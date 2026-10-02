use std::{
    collections::{hash_map::Entry, HashMap, HashSet},
    env, fs,
    io::{self, IoSlice, IoSliceMut},
    net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket},
    os::fd::AsRawFd,
    path::PathBuf,
    sync::{mpsc, Arc, Mutex, RwLock},
    thread,
    time::{Duration, Instant},
};

use mousevpn_admin_api::{
    AdminSettings, AdminToken, DeviceAuthorization, DeviceTrafficCounter, SeedDevice,
    SharedDeviceRegistry, TrafficStore,
};
use mousevpn_config::{
    decode_public_key, encode_public_key, ValidatedServerConfig, DEFAULT_TUN_MTU, MAX_SAFE_TUN_MTU,
};
use mousevpn_crypto::{
    derive_morph_key, derive_speedy_key, ProtocolContext, PublicKey, ServerHandshake,
};
use mousevpn_data_plane::{
    looks_like_protocol_datagram, Decoded, Ipv4Packet, PacketDevice, TunnelDataPlane,
    TunnelReceiver, TunnelSender, TUNNEL_OVERHEAD,
};
use mousevpn_linux_platform::{LinuxTun, LinuxTunConfig, DEFAULT_TX_QUEUE_LEN};
use mousevpn_morph::{
    accepted_epochs, current_epoch, routing_tag_at, DecodedFrame, Direction, MorphCodec, MorphKey,
    Profile, SAFE_TUN_MTU,
};
use mousevpn_speedy::{Direction as SpeedyDirection, SpeedyCodec, SpeedyKey};

#[cfg(test)]
mod speedy_tests;
use mousevpn_protocol::{Datagram, Header, PacketKind, SessionParameters};
use nix::poll::{poll, PollFd, PollFlags};
use nix::sys::socket::{
    recvmmsg, sendmmsg, setsockopt, sockopt::RxqOvfl, ControlMessageOwned, MsgFlags, MultiHeaders,
    SockaddrStorage,
};
use socket2::SockRef;

use crate::{rate_limit::HandshakeLimiter, ServerDaemonError};

const DATAGRAM_BUFFER_LEN: usize = 65_535;
const UDP_BATCH_SIZE: usize = 32;
const SOCKET_BUFFER_LEN: usize = 8 * 1024 * 1024;
const PEER_LOG_INTERVAL: Duration = Duration::from_secs(10);
const UDP_DROP_LOG_INTERVAL: Duration = Duration::from_secs(30);
const WORKER_HEALTH_POLL: Duration = Duration::from_secs(1);
/// Outer IPv4 and UDP headers carried around every tunnel datagram.
const IPV4_UDP_OVERHEAD: usize = 28;

struct RuntimeSession {
    client_address: Ipv4Addr,
    authorization: DeviceAuthorization,
    traffic: Arc<DeviceTrafficCounter>,
    /// Current client endpoint, replaced only after a packet authenticates.
    peer: RwLock<SocketAddr>,
    /// Client-to-server direction, driven by the UDP loop alone.
    inbound: Mutex<TunnelReceiver>,
    /// Server-to-client direction, driven by the TUN worker alone.
    outbound: Mutex<TunnelSender>,
    wire: WireMode,
    last_peer_log: Mutex<Option<Instant>>,
    last_authenticated: Mutex<Instant>,
}

impl RuntimeSession {
    fn peer(&self) -> Option<SocketAddr> {
        self.peer.read().ok().map(|peer| *peer)
    }

    /// Adopts a new client endpoint after the packet has been authenticated.
    ///
    /// Clients behind NAT change source port on rebinding and change address
    /// entirely when roaming between networks. Without this the session stalls
    /// until the client's own idle timeout forces a fresh handshake.
    fn adopt_peer(&self, peer: SocketAddr) {
        if let Ok(mut seen) = self.last_authenticated.lock() {
            *seen = Instant::now();
        }
        if self.peer() == Some(peer) {
            return;
        }
        let previous = {
            let Ok(mut current) = self.peer.write() else {
                return;
            };
            if *current == peer {
                return;
            }
            let previous = *current;
            *current = peer;
            previous
        };
        let should_log = self.last_peer_log.lock().is_ok_and(|mut last| {
            if last.is_some_and(|last| last.elapsed() < PEER_LOG_INTERVAL) {
                return false;
            }
            *last = Some(Instant::now());
            true
        });
        if should_log {
            eprintln!(
                "session for {} moved from {previous} to {peer}",
                self.client_address
            );
        }
    }
}

/// Session lookup indexed for both hot paths.
///
/// The UDP loop looks sessions up by ID, the TUN worker by tunnel address; a
/// linear scan of either would cost O(sessions) on every single packet.
#[derive(Default)]
struct Sessions {
    by_id: HashMap<u64, Arc<RuntimeSession>>,
    by_address: HashMap<Ipv4Addr, Arc<RuntimeSession>>,
}

impl Sessions {
    fn online_devices(&self) -> u32 {
        // One tunnel address per device; reconnects replace the old session.
        u32::try_from(
            self.by_address
                .values()
                .filter(|session| {
                    session.authorization.is_active()
                        && session
                            .last_authenticated
                            .lock()
                            .is_ok_and(|seen| seen.elapsed() <= Duration::from_secs(90))
                })
                .count(),
        )
        .unwrap_or(u32::MAX)
    }
}

type SessionMap = Arc<RwLock<Sessions>>;

struct ReceivedDatagram {
    index: usize,
    length: usize,
    peer: SocketAddr,
    rx_overflow: Option<u32>,
}

/// Last handshake seen from a device, so duplicates stay harmless.
///
/// A `HandshakeInit` is replayable by design in Noise IK, and the client
/// retransmits it on a lossy link. Building a second session for a byte
/// identical message would silently strand the client on keys it never
/// derived, so an exact repeat is answered with the exact same response.
struct CachedHandshake {
    request: Vec<u8>,
    /// Complete legacy response datagram; `MouseMorph` is freshly applied for
    /// every retransmission so nonces and padding do not repeat.
    response: Vec<u8>,
}

struct KeepaliveBuffers {
    plaintext: Vec<u8>,
    response: Vec<u8>,
    wire_response: Vec<u8>,
}

#[derive(Clone, Debug)]
enum WireMode {
    Legacy,
    Speedy {
        client_public_key: PublicKey,
        codec: SpeedyCodec,
    },
    Morph {
        client_public_key: PublicKey,
        codec: MorphCodec,
    },
}

impl WireMode {
    fn encode_server(&self, inner: &[u8], output: &mut Vec<u8>) -> Result<(), ()> {
        match self {
            Self::Legacy => {
                output.clear();
                output.extend_from_slice(inner);
                Ok(())
            }
            Self::Morph { codec, .. } => codec
                .encode_payload(inner, Direction::ServerToClient, output)
                .map_err(|_| ()),
            Self::Speedy { codec, .. } => codec
                .encode(inner, SpeedyDirection::ServerToClient, output)
                .map_err(|_| ()),
        }
    }

    fn allows_client(&self, public_key: &PublicKey) -> bool {
        match self {
            Self::Legacy => true,
            Self::Morph {
                client_public_key, ..
            }
            | Self::Speedy {
                client_public_key, ..
            } => client_public_key == public_key,
        }
    }

    fn matches(&self, incoming: &Self) -> bool {
        match (self, incoming) {
            (Self::Legacy, Self::Legacy) => true,
            (
                Self::Speedy {
                    client_public_key: expected,
                    ..
                },
                Self::Speedy {
                    client_public_key: actual,
                    ..
                },
            ) => expected == actual,
            (
                Self::Morph {
                    client_public_key: expected,
                    codec: expected_codec,
                },
                Self::Morph {
                    client_public_key: actual,
                    codec: actual_codec,
                },
            ) => expected == actual && expected_codec.profile() == actual_codec.profile(),
            _ => false,
        }
    }

    fn session_mtu(&self, configured: u16) -> u16 {
        match self {
            Self::Legacy => configured,
            Self::Speedy { .. } => configured.min(mousevpn_speedy::SAFE_TUN_MTU),
            Self::Morph { .. } => configured.min(SAFE_TUN_MTU),
        }
    }
}

#[derive(Clone)]
struct MorphRoute {
    public_key: PublicKey,
    key: MorphKey,
    profile: Profile,
}

#[derive(Default)]
struct MorphRouter {
    epoch: Option<u64>,
    // The static shared key does not change when routing tags rotate. Avoid
    // repeating X25519 for every device in the receive loop once per second.
    keys: HashMap<PublicKey, MorphKey>,
    speedy_codecs: HashMap<PublicKey, SpeedyCodec>,
    speedy_routes: HashMap<[u8; 8], (PublicKey, SpeedyCodec)>,
    routes: HashMap<[u8; 8], MorphRoute>,
    ambiguous: HashSet<[u8; 8]>,
}

impl MorphRouter {
    fn resolve(
        &mut self,
        input: &[u8],
        config: &ValidatedServerConfig,
        authorized: &SharedDeviceRegistry,
    ) -> Option<MorphRoute> {
        let tag: [u8; 8] = input.get(..8)?.try_into().ok()?;
        let epoch = current_epoch(Profile::Paranoid).ok()?;
        if self.epoch != Some(epoch) && self.refresh(epoch, config, authorized).is_err() {
            return None;
        }
        self.routes.get(&tag).cloned()
    }

    fn refresh(
        &mut self,
        epoch: u64,
        config: &ValidatedServerConfig,
        authorized: &SharedDeviceRegistry,
    ) -> Result<(), ()> {
        let devices: HashSet<_> = authorized
            .list()
            .map_err(|_| ())?
            .iter()
            .filter_map(|device| decode_public_key(&device.public_key).ok())
            .collect();
        self.keys
            .retain(|public_key, _| devices.contains(public_key));
        self.speedy_codecs
            .retain(|public_key, _| devices.contains(public_key));
        self.speedy_routes.clear();
        self.routes.clear();
        self.ambiguous.clear();
        for public_key in devices {
            let key = match self.keys.entry(public_key) {
                Entry::Occupied(entry) => entry.into_mut(),
                Entry::Vacant(entry) => {
                    let Ok(key) = derive_morph_key(
                        &config.server_private_key,
                        &public_key,
                        &config.server_public_key,
                        &public_key,
                    ) else {
                        continue;
                    };
                    entry.insert(MorphKey::from_bytes(key))
                }
            };
            for profile in [Profile::Quiet, Profile::Balanced, Profile::Paranoid] {
                let Ok(profile_epoch) = current_epoch(profile) else {
                    continue;
                };
                let route = MorphRoute {
                    public_key,
                    key: key.clone(),
                    profile,
                };
                for accepted in accepted_epochs(profile_epoch) {
                    let tag =
                        routing_tag_at(&route.key, profile, Direction::ClientToServer, accepted);
                    if self.ambiguous.contains(&tag) {
                        continue;
                    }
                    if self.speedy_routes.remove(&tag).is_some() {
                        self.ambiguous.insert(tag);
                        continue;
                    }
                    match self.routes.entry(tag) {
                        Entry::Vacant(entry) => {
                            entry.insert(route.clone());
                        }
                        Entry::Occupied(entry) => {
                            entry.remove();
                            self.ambiguous.insert(tag);
                        }
                    }
                }
            }
            self.add_speedy_routes(public_key, config)?;
        }
        self.epoch = Some(epoch);
        Ok(())
    }

    fn add_speedy_routes(
        &mut self,
        public_key: PublicKey,
        config: &ValidatedServerConfig,
    ) -> Result<(), ()> {
        let codec = match self.speedy_codecs.entry(public_key) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                let key = derive_speedy_key(
                    &config.server_private_key,
                    &public_key,
                    &config.server_public_key,
                    &public_key,
                )
                .map_err(|_| ())?;
                entry.insert(SpeedyCodec::new(SpeedyKey::from_bytes(key)))
            }
        };
        for epoch in
            mousevpn_speedy::accepted_epochs(mousevpn_speedy::current_epoch().map_err(|_| ())?)
        {
            let tag = codec.routing_tag_at(SpeedyDirection::ClientToServer, epoch);
            if self.ambiguous.contains(&tag) {
                continue;
            }
            if self.routes.remove(&tag).is_some() || self.speedy_routes.remove(&tag).is_some() {
                self.ambiguous.insert(tag);
                continue;
            }
            self.speedy_routes.insert(tag, (public_key, codec.clone()));
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct HandshakeServices<'a> {
    config: &'a ValidatedServerConfig,
    authorized: &'a SharedDeviceRegistry,
    traffic: &'a TrafficStore,
    sessions: &'a SessionMap,
}

/// Creates the server TUN/UDP endpoints and runs until a fatal I/O error.
///
/// # Errors
///
/// Returns an error when TUN creation, UDP binding or packet reception fails.
pub fn run(config: &ValidatedServerConfig) -> Result<(), ServerDaemonError> {
    warn_about_fragmenting_mtu(config.tun.mtu);
    let tun = Arc::new(LinuxTun::create(&LinuxTunConfig {
        name: config.tun.name.clone(),
        address: config.tun.address,
        prefix_len: config.tun.prefix_len,
        mtu: config.tun.mtu,
        tx_queue_len: DEFAULT_TX_QUEUE_LEN,
    })?);
    tun.set_nonblocking(true)?;
    let socket = UdpSocket::bind(config.listen)?;
    configure_socket_buffers(&socket)?;
    socket.set_read_timeout(Some(WORKER_HEALTH_POLL))?;
    setsockopt(&socket, RxqOvfl, &1).map_err(io::Error::from)?;
    let sessions: SessionMap = Arc::new(RwLock::new(Sessions::default()));
    let authorized = open_device_registry(config)?;
    let mut morph_router = MorphRouter::default();
    let traffic = open_traffic_store()?;
    traffic.spawn_flusher(Duration::from_secs(10));
    start_admin_if_configured(config, &authorized, &traffic)?;
    let observed_sessions = Arc::clone(&sessions);
    crate::controller::start(
        &authorized,
        &encode_public_key(&config.server_public_key),
        move || observed_sessions.read().ok().map(|s| s.online_devices()),
    )?;
    let mut handshake_limiter = HandshakeLimiter::new(50, Duration::from_secs(60));
    let mut handshake_cache: HashMap<PublicKey, CachedHandshake> = HashMap::new();

    let tun_worker = start_tun_worker(Arc::clone(&tun), socket.try_clone()?, Arc::clone(&sessions));
    let mut buffers: Vec<Vec<u8>> = (0..UDP_BATCH_SIZE)
        .map(|_| vec![0_u8; DATAGRAM_BUFFER_LEN])
        .collect();
    let mut headers =
        MultiHeaders::<SockaddrStorage>::preallocate(UDP_BATCH_SIZE, Some(nix::cmsg_space!(u32)));
    let mut received = Vec::with_capacity(UDP_BATCH_SIZE);
    let mut last_rx_overflow = 0_u32;
    // Reused across packets so the steady-state receive path never allocates.
    let mut plaintext = Vec::with_capacity(DATAGRAM_BUFFER_LEN);
    let mut keepalive = KeepaliveBuffers {
        plaintext: Vec::with_capacity(128),
        response: Vec::with_capacity(128),
        wire_response: Vec::with_capacity(256),
    };
    let mut morph_payload = Vec::with_capacity(DATAGRAM_BUFFER_LEN);
    loop {
        check_tun_worker(&tun_worker)?;
        match receive_batch(&socket, &mut buffers, &mut headers, &mut received) {
            Ok(()) => {}
            Err(error) if is_recoverable(&error) => {
                check_tun_worker(&tun_worker)?;
                continue;
            }
            Err(error) => return Err(error.into()),
        }
        for received in received.drain(..) {
            let ReceivedDatagram {
                index,
                length,
                peer,
                rx_overflow,
            } = received;
            record_rx_overflow(rx_overflow, &mut last_rx_overflow);
            let buffer = &buffers[index][..length];
            let Some(wire) = decode_wire_into(
                buffer,
                config,
                &authorized,
                &mut morph_router,
                &mut morph_payload,
            ) else {
                continue;
            };
            if !looks_like_protocol_datagram(&morph_payload) {
                continue;
            }
            let Ok(datagram) = Datagram::decode(&morph_payload) else {
                continue;
            };
            match datagram.header.kind {
                PacketKind::HandshakeInit if handshake_limiter.allow(peer.ip()) => {
                    handle_handshake(
                        &socket,
                        peer,
                        datagram,
                        HandshakeServices {
                            config,
                            authorized: &authorized,
                            traffic: &traffic,
                            sessions: &sessions,
                        },
                        &wire,
                        &mut handshake_cache,
                    );
                }
                PacketKind::Data => {
                    handle_client_data(peer, datagram, &wire, &sessions, &tun, &mut plaintext);
                }
                PacketKind::Keepalive => {
                    handle_keepalive(&socket, peer, datagram, &wire, &sessions, &mut keepalive);
                }
                _ => {}
            }
        }
    }
}

fn record_rx_overflow(observed: Option<u32>, previous: &mut u32) {
    let Some(observed) = observed.filter(|observed| observed > previous) else {
        return;
    };
    eprintln!(
        "MouseVPN UDP receive queue dropped {} datagrams (total {observed})",
        observed - *previous
    );
    *previous = observed;
}

fn decode_wire_into(
    input: &[u8],
    config: &ValidatedServerConfig,
    authorized: &SharedDeviceRegistry,
    router: &mut MorphRouter,
    output: &mut Vec<u8>,
) -> Option<WireMode> {
    let Some(route) = router.resolve(input, config, authorized) else {
        if let Some(tag) = input
            .get(..8)
            .and_then(|bytes| <[u8; 8]>::try_from(bytes).ok())
        {
            if router.ambiguous.contains(&tag) {
                return None;
            }
            if let Some((public_key, codec)) = router.speedy_routes.get(&tag) {
                codec
                    .decode(input, SpeedyDirection::ClientToServer, output)
                    .ok()?;
                return Some(WireMode::Speedy {
                    client_public_key: *public_key,
                    codec: codec.clone(),
                });
            }
        }
        output.clear();
        output.extend_from_slice(input);
        return Some(WireMode::Legacy);
    };
    let codec = MorphCodec::new(route.key.clone(), route.profile);
    let Ok(frame) = codec.decode(input, Direction::ClientToServer, output) else {
        return None;
    };
    let DecodedFrame::Payload { profile } = frame else {
        return None;
    };
    Some(WireMode::Morph {
        client_public_key: route.public_key,
        codec: MorphCodec::new(route.key, profile),
    })
}

fn receive_batch(
    socket: &UdpSocket,
    buffers: &mut [Vec<u8>],
    headers: &mut MultiHeaders<SockaddrStorage>,
    received: &mut Vec<ReceivedDatagram>,
) -> io::Result<()> {
    let mut slices: Vec<_> = buffers
        .iter_mut()
        .map(|buffer| [IoSliceMut::new(buffer)])
        .collect();
    let messages = recvmmsg(
        socket.as_raw_fd(),
        headers,
        slices.iter_mut(),
        MsgFlags::MSG_WAITFORONE,
        None,
    )
    .map_err(io::Error::from)?;
    received.clear();
    for (index, message) in messages.enumerate() {
        let Some(address) = message.address.and_then(socket_address) else {
            continue;
        };
        let overflow = message.cmsgs().ok().and_then(|mut messages| {
            messages.find_map(|message| match message {
                ControlMessageOwned::RxqOvfl(value) => Some(value),
                _ => None,
            })
        });
        received.push(ReceivedDatagram {
            index,
            length: message.bytes,
            peer: address,
            rx_overflow: overflow,
        });
    }
    Ok(())
}

fn socket_address(address: SockaddrStorage) -> Option<SocketAddr> {
    address
        .as_sockaddr_in()
        .copied()
        .map(SocketAddr::from)
        .or_else(|| address.as_sockaddr_in6().copied().map(SocketAddr::from))
}

/// Warns when the configured tunnel MTU cannot fit a 1500-byte path.
///
/// The symptom is not a clean failure: small packets work, large ones are
/// fragmented or silently dropped by middleboxes, and the tunnel looks merely
/// "slow" or "flaky" while TLS and video stall.
fn warn_about_fragmenting_mtu(mtu: u16) {
    if mtu > MAX_SAFE_TUN_MTU {
        eprintln!(
            "MouseVPN warning: tun.mtu = {mtu} produces {} byte datagrams on a \
             1500 byte path, which will be fragmented. Use {DEFAULT_TUN_MTU} \
             unless every path is known to carry more.",
            usize::from(mtu) + IPV4_UDP_OVERHEAD + TUNNEL_OVERHEAD
        );
    }
}

/// Transient receive errors that must not take the whole daemon down.
fn is_recoverable(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::Interrupted
            | io::ErrorKind::WouldBlock
            | io::ErrorKind::TimedOut
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionReset
    ) || matches!(
        error.raw_os_error(),
        Some(nix::libc::ENOBUFS | nix::libc::ENOMEM)
    )
}

fn check_tun_worker(worker: &mpsc::Receiver<io::Error>) -> Result<(), ServerDaemonError> {
    match worker.try_recv() {
        Ok(error) => Err(error.into()),
        Err(mpsc::TryRecvError::Empty) => Ok(()),
        Err(mpsc::TryRecvError::Disconnected) => Err(ServerDaemonError::WorkerStopped),
    }
}

fn configure_socket_buffers(socket: &UdpSocket) -> std::io::Result<()> {
    let socket = SockRef::from(socket);
    socket.set_recv_buffer_size(SOCKET_BUFFER_LEN)?;
    socket.set_send_buffer_size(SOCKET_BUFFER_LEN)?;
    let received = socket.recv_buffer_size()?;
    let sent = socket.send_buffer_size()?;
    eprintln!("MouseVPN UDP buffers: receive={received} send={sent} requested={SOCKET_BUFFER_LEN}");
    Ok(())
}

fn handle_keepalive(
    socket: &UdpSocket,
    peer: SocketAddr,
    datagram: Datagram<'_>,
    wire: &WireMode,
    sessions: &SessionMap,
    buffers: &mut KeepaliveBuffers,
) {
    let Some(session) = find_session_by_id(sessions, datagram.header.session_id) else {
        return;
    };
    if !session.authorization.is_active() {
        return;
    }
    if !session.wire.matches(wire) {
        return;
    }
    {
        let Ok(mut inbound) = session.inbound.lock() else {
            return;
        };
        if !matches!(
            inbound.decode_into(datagram, &mut buffers.plaintext),
            Ok(Decoded::Keepalive)
        ) {
            return;
        }
    }
    session.adopt_peer(peer);
    {
        let Ok(mut outbound) = session.outbound.lock() else {
            return;
        };
        if outbound
            .encode_keepalive_into(&mut buffers.response)
            .is_err()
        {
            return;
        }
    }
    if session
        .wire
        .encode_server(&buffers.response, &mut buffers.wire_response)
        .is_err()
    {
        return;
    }
    let _ = socket.send_to(&buffers.wire_response, peer);
}

fn handle_handshake(
    socket: &UdpSocket,
    peer: SocketAddr,
    datagram: Datagram<'_>,
    services: HandshakeServices<'_>,
    wire: &WireMode,
    cache: &mut HashMap<PublicKey, CachedHandshake>,
) {
    let context = if matches!(wire, WireMode::Speedy { .. }) {
        ProtocolContext::for_speedy_server(&services.config.server_public_key)
    } else {
        services.config.context
    };
    let Ok(mut handshake) = ServerHandshake::new(&services.config.server_private_key, &context)
    else {
        return;
    };
    if handshake.read_initial(datagram.payload).is_err() {
        return;
    }
    let Some(public_key) = handshake.peer_static_key() else {
        return;
    };
    if !wire.allows_client(&public_key) {
        return;
    }
    let Some(client) = services.authorized.authorize(&public_key) else {
        return;
    };

    // A repeat of the exact same request is a retransmission or a duplicate in
    // the network, never a new session. Answering it again keeps the client's
    // existing session alive instead of replacing it with unusable keys.
    if let Some(cached) = cache.get(&public_key) {
        if cached.request == datagram.payload {
            let mut wire_response = Vec::with_capacity(cached.response.len() + 128);
            if wire
                .encode_server(&cached.response, &mut wire_response)
                .is_ok()
            {
                let _ = socket.send_to(&wire_response, peer);
            }
            return;
        }
    }

    let session_mtu = wire.session_mtu(services.config.tun.mtu);
    let parameters = SessionParameters {
        client_address: client.address,
        prefix_len: services.config.tun.prefix_len,
        mtu: session_mtu,
        dns: services.config.tun.dns,
    };
    let Ok((crypto, response)) = handshake.finish(&parameters.encode()) else {
        return;
    };
    let (sender, receiver) =
        TunnelDataPlane::new(datagram.header.session_id, usize::from(session_mtu), crypto).split();
    let session = Arc::new(RuntimeSession {
        client_address: client.address,
        authorization: client.authorization,
        traffic: services
            .traffic
            .counter(&encode_public_key(&client.public_key), &client.name),
        peer: RwLock::new(peer),
        inbound: Mutex::new(receiver),
        outbound: Mutex::new(sender),
        wire: wire.clone(),
        last_peer_log: Mutex::new(None),
        last_authenticated: Mutex::new(Instant::now()),
    });

    let Ok(mut guard) = services.sessions.write() else {
        return;
    };
    if !guard.replace_client(datagram.header.session_id, session) {
        return;
    }
    drop(guard);

    let header = Header {
        kind: PacketKind::HandshakeResponse,
        flags: 0,
        session_id: datagram.header.session_id,
        sequence: 0,
    };
    let encoded = Datagram::new(header, &response).encode();
    let mut wire_encoded = Vec::with_capacity(encoded.len() + 128);
    if wire.encode_server(&encoded, &mut wire_encoded).is_err() {
        return;
    }
    let _ = socket.send_to(&wire_encoded, peer);
    cache.insert(
        public_key,
        CachedHandshake {
            request: datagram.payload.to_vec(),
            response: encoded,
        },
    );
    eprintln!("session established for {} from {peer}", client.name);
}

fn handle_client_data(
    peer: SocketAddr,
    datagram: Datagram<'_>,
    wire: &WireMode,
    sessions: &SessionMap,
    tun: &LinuxTun,
    plaintext: &mut Vec<u8>,
) {
    let Some(session) = find_session_by_id(sessions, datagram.header.session_id) else {
        return;
    };
    if !session.authorization.is_active() {
        return;
    }
    if !session.wire.matches(wire) {
        return;
    }
    let packet = {
        let Ok(mut inbound) = session.inbound.lock() else {
            return;
        };
        let Ok(Decoded::Ip(packet)) = inbound.decode_into(datagram, plaintext) else {
            return;
        };
        packet
    };
    let Ok(ip) = Ipv4Packet::parse(packet) else {
        return;
    };
    if ip.source() != session.client_address {
        return;
    }
    if tun.send(packet).is_ok() {
        session.traffic.add_upload(packet.len() as u64);
        session.adopt_peer(peer);
    }
}

fn start_tun_worker(
    tun: Arc<LinuxTun>,
    socket: UdpSocket,
    sessions: SessionMap,
) -> mpsc::Receiver<io::Error> {
    let (failure, failures) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let error = run_tun_worker(&tun, &socket, &sessions)
            .err()
            .unwrap_or_else(|| io::Error::other("TUN worker stopped unexpectedly"));
        let _ = failure.send(error);
    });
    failures
}

fn run_tun_worker(tun: &LinuxTun, socket: &UdpSocket, sessions: &SessionMap) -> io::Result<()> {
    let mut packets: Vec<Vec<u8>> = (0..UDP_BATCH_SIZE)
        .map(|_| vec![0_u8; DATAGRAM_BUFFER_LEN])
        .collect();
    let mut datagrams: Vec<Vec<u8>> = (0..UDP_BATCH_SIZE)
        .map(|_| Vec::with_capacity(DATAGRAM_BUFFER_LEN))
        .collect();
    let mut wire_datagrams: Vec<Vec<u8>> = (0..UDP_BATCH_SIZE)
        .map(|_| Vec::with_capacity(DATAGRAM_BUFFER_LEN))
        .collect();
    let mut packet_lengths = [0_usize; UDP_BATCH_SIZE];
    let mut peers = Vec::with_capacity(UDP_BATCH_SIZE);
    let mut traffic = Vec::with_capacity(UDP_BATCH_SIZE);
    let mut payload_lengths = Vec::with_capacity(UDP_BATCH_SIZE);
    let mut send_headers = MultiHeaders::preallocate(UDP_BATCH_SIZE, None);
    let mut dropped_datagrams = 0_u64;
    let mut last_drop_report = None;
    loop {
        let mut descriptor = [PollFd::new(tun.as_fd(), PollFlags::POLLIN)];
        if let Err(error) = poll(&mut descriptor, None::<u16>) {
            if error == nix::errno::Errno::EINTR {
                continue;
            }
            return Err(io::Error::from(error));
        }
        let mut packet_count = 0;
        while packet_count < UDP_BATCH_SIZE {
            match tun.receive(&mut packets[packet_count]) {
                Ok(length) => {
                    packet_lengths[packet_count] = length;
                    packet_count += 1;
                }
                Err(error) if is_recoverable(&error) => break,
                Err(error) => return Err(error),
            }
        }

        peers.clear();
        traffic.clear();
        payload_lengths.clear();
        let mut datagram_count = 0;
        for index in 0..packet_count {
            let packet = &packets[index][..packet_lengths[index]];
            let Ok(ip) = Ipv4Packet::parse(packet) else {
                continue;
            };
            let Some(session) = find_session_by_address(sessions, ip.destination()) else {
                continue;
            };
            if !session.authorization.is_active() {
                continue;
            }
            let Some(peer) = session.peer() else {
                continue;
            };
            {
                let Ok(mut outbound) = session.outbound.lock() else {
                    continue;
                };
                if outbound
                    .encode_ip_into(ip.as_bytes(), &mut datagrams[datagram_count])
                    .is_err()
                {
                    continue;
                }
            }
            if session
                .wire
                .encode_server(
                    &datagrams[datagram_count],
                    &mut wire_datagrams[datagram_count],
                )
                .is_err()
            {
                continue;
            }
            peers.push(peer);
            traffic.push(Arc::clone(&session.traffic));
            payload_lengths.push(ip.as_bytes().len() as u64);
            datagram_count += 1;
        }
        if datagram_count == 0 {
            continue;
        }

        let sent = send_server_batch(
            socket,
            &mut send_headers,
            &wire_datagrams,
            &peers,
            datagram_count,
        )?;
        record_downloads(sent, &traffic, &payload_lengths);
        note_server_drops(
            &mut dropped_datagrams,
            &mut last_drop_report,
            datagram_count.saturating_sub(sent),
        );
    }
}

fn send_server_batch(
    socket: &UdpSocket,
    headers: &mut MultiHeaders<SockaddrStorage>,
    datagrams: &[Vec<u8>],
    peers: &[SocketAddr],
    count: usize,
) -> io::Result<usize> {
    let slices: [[IoSlice<'_>; 1]; UDP_BATCH_SIZE] = std::array::from_fn(|index| {
        [IoSlice::new(
            datagrams.get(index).map_or(&[], Vec::as_slice),
        )]
    });
    let addresses: [Option<SockaddrStorage>; UDP_BATCH_SIZE] =
        std::array::from_fn(|index| peers.get(index).copied().map(SockaddrStorage::from));
    match sendmmsg(
        socket.as_raw_fd(),
        headers,
        &slices[..count],
        &addresses[..count],
        [],
        MsgFlags::empty(),
    ) {
        Ok(results) => Ok(results.count()),
        Err(error) if is_recoverable(&io::Error::from(error)) => Ok(0),
        Err(error) => Err(io::Error::from(error)),
    }
}

fn note_server_drops(total: &mut u64, last_report: &mut Option<Instant>, dropped: usize) {
    if dropped == 0 {
        return;
    }
    *total = total.saturating_add(dropped as u64);
    let now = Instant::now();
    if last_report.is_none_or(|last| now.duration_since(last) >= UDP_DROP_LOG_INTERVAL) {
        eprintln!("MouseVPN UDP send queue dropped {total} datagrams");
        *last_report = Some(now);
    }
}

fn record_downloads(sent: usize, traffic: &[Arc<DeviceTrafficCounter>], payload_lengths: &[u64]) {
    for index in 0..sent {
        traffic[index].add_download(payload_lengths[index]);
    }
}

fn open_device_registry(
    config: &ValidatedServerConfig,
) -> Result<SharedDeviceRegistry, ServerDaemonError> {
    let path = env::var_os("RELAY_DEVICE_STORE")
        .or_else(|| env::var_os("MOUSEVPN_DEVICE_STORE"))
        .map_or_else(
            || PathBuf::from("/var/lib/mousevpn/devices.toml"),
            PathBuf::from,
        );
    let seeds = config
        .clients
        .iter()
        .map(|client| SeedDevice {
            name: client.name.clone(),
            public_key: client.public_key,
            address: client.address,
        })
        .collect();
    SharedDeviceRegistry::open(path, seeds, config.tun.address, config.tun.prefix_len)
        .map_err(|error| ServerDaemonError::Configuration(error.to_string()))
}

fn open_traffic_store() -> Result<TrafficStore, ServerDaemonError> {
    let path = env::var_os("RELAY_TRAFFIC_STORE")
        .or_else(|| env::var_os("MOUSEVPN_TRAFFIC_STORE"))
        .map_or_else(
            || PathBuf::from("/var/lib/mousevpn/traffic.sqlite"),
            PathBuf::from,
        );
    TrafficStore::open(path).map_err(|error| ServerDaemonError::Configuration(error.to_string()))
}

fn start_admin_if_configured(
    config: &ValidatedServerConfig,
    registry: &SharedDeviceRegistry,
    traffic: &TrafficStore,
) -> Result<(), ServerDaemonError> {
    let Some(raw_token) = load_admin_token()? else {
        eprintln!("MouseVPN admin disabled: /etc/mousevpn/admin.token does not exist");
        return Ok(());
    };
    let token = AdminToken::new(raw_token.into_bytes())
        .map_err(|error| ServerDaemonError::Configuration(error.to_string()))?;
    let listen = env::var("MOUSEVPN_ADMIN_LISTEN")
        .unwrap_or_else(|_| format!("{}:9797", config.tun.address))
        .parse::<SocketAddr>()
        .map_err(|error| ServerDaemonError::Configuration(error.to_string()))?;
    let allow_public = env::var("MOUSEVPN_ADMIN_ALLOW_PUBLIC")
        .is_ok_and(|value| matches!(value.as_str(), "1" | "true" | "yes"));
    if !admin_listener_allowed(listen.ip(), config.tun.address, allow_public) {
        return Err(ServerDaemonError::Configuration(
            "admin listener must use the tunnel address or loopback unless MOUSEVPN_ADMIN_ALLOW_PUBLIC=1"
                .to_owned(),
        ));
    }
    let public_endpoint = config
        .public_endpoint
        .or_else(|| {
            env::var("MOUSEVPN_PUBLIC_ENDPOINT")
                .ok()
                .and_then(|value| value.parse().ok())
        })
        .ok_or_else(|| {
            ServerDaemonError::Configuration(
                "public_endpoint is required when admin is enabled".to_owned(),
            )
        })?;
    if public_endpoint.ip().is_unspecified() || public_endpoint.port() == 0 {
        return Err(ServerDaemonError::Configuration(
            "public_endpoint must contain a usable IP and port".to_owned(),
        ));
    }
    let settings = AdminSettings {
        public_endpoint,
        server_public_key: encode_public_key(&config.server_public_key),
        tun_name: config.tun.name.clone(),
    };
    mousevpn_admin_api::spawn(listen, registry.clone(), traffic.clone(), token, settings)?;
    Ok(())
}

fn admin_listener_allowed(listen: IpAddr, tunnel: Ipv4Addr, allow_public: bool) -> bool {
    listen.is_loopback() || listen == IpAddr::V4(tunnel) || allow_public
}

fn load_admin_token() -> Result<Option<String>, ServerDaemonError> {
    if let Ok(token) = env::var("MOUSEVPN_ADMIN_TOKEN") {
        return Ok(Some(token));
    }
    let path = env::var_os("RELAY_ADMIN_TOKEN_FILE")
        .or_else(|| env::var_os("MOUSEVPN_ADMIN_TOKEN_FILE"))
        .map_or_else(|| PathBuf::from("/etc/mousevpn/admin.token"), PathBuf::from);
    if !path.exists() {
        return Ok(None);
    }
    ensure_private_token_file(&path)?;
    let token = fs::read_to_string(path)?.trim().to_owned();
    Ok(Some(token))
}

#[cfg(unix)]
fn ensure_private_token_file(path: &std::path::Path) -> Result<(), ServerDaemonError> {
    use std::os::unix::fs::PermissionsExt;

    let mode = fs::metadata(path)?.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(ServerDaemonError::Configuration(format!(
            "admin token permissions are insecure: {mode:o}"
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_private_token_file(_path: &std::path::Path) -> Result<(), ServerDaemonError> {
    Ok(())
}

fn find_session_by_id(sessions: &SessionMap, session_id: u64) -> Option<Arc<RuntimeSession>> {
    sessions.read().ok()?.by_id.get(&session_id).cloned()
}

fn find_session_by_address(
    sessions: &SessionMap,
    address: Ipv4Addr,
) -> Option<Arc<RuntimeSession>> {
    sessions.read().ok()?.by_address.get(&address).cloned()
}

impl Sessions {
    /// Installs a session, replacing any previous one for the same device.
    fn replace_client(&mut self, session_id: u64, session: Arc<RuntimeSession>) -> bool {
        let address = session.client_address;
        // The session ID is chosen by the client, not an authorization token.
        // Reject collisions before changing either index, including the
        // reconnecting device's own previous session.
        if self
            .by_id
            .get(&session_id)
            .is_some_and(|existing| existing.client_address != address)
        {
            return false;
        }
        if let Some(previous) = self.by_address.insert(address, Arc::clone(&session)) {
            self.by_id
                .retain(|_, existing| !Arc::ptr_eq(existing, &previous));
        }
        self.by_id.insert(session_id, session);
        true
    }
}

#[cfg(test)]
mod session_isolation_tests {
    use std::{
        collections::HashMap,
        net::UdpSocket,
        sync::{Arc, RwLock},
    };

    use mousevpn_admin_api::{SeedDevice, SharedDeviceRegistry, TrafficStore};
    use mousevpn_config::{ServerTunConfig, ValidatedServerConfig};
    use mousevpn_crypto::{ClientHandshake, KeyPair, ProtocolContext};
    use mousevpn_protocol::{Datagram, Header, PacketKind};

    use super::{handle_handshake, HandshakeServices, Sessions, WireMode};

    #[test]
    fn a_device_cannot_replace_another_devices_session_id() {
        let directory = tempfile::tempdir().unwrap();
        let server = KeyPair::generate().unwrap();
        let clients = [KeyPair::generate().unwrap(), KeyPair::generate().unwrap()];
        let config = ValidatedServerConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            public_endpoint: None,
            server_public_key: server.public,
            context: ProtocolContext::for_server(&server.public),
            server_private_key: server.secret,
            tun: ServerTunConfig {
                name: "mousevpn0".to_owned(),
                address: "10.77.0.1".parse().unwrap(),
                prefix_len: 24,
                mtu: 1280,
                dns: "1.1.1.1".parse().unwrap(),
            },
            clients: Vec::new(),
        };
        let addresses = ["10.77.0.2".parse().unwrap(), "10.77.0.3".parse().unwrap()];
        let registry = SharedDeviceRegistry::open(
            directory.path().join("devices.toml"),
            clients
                .iter()
                .zip(addresses)
                .enumerate()
                .map(|(index, (key, address))| SeedDevice {
                    name: format!("device-{index}"),
                    public_key: key.public,
                    address,
                })
                .collect(),
            config.tun.address,
            config.tun.prefix_len,
        )
        .unwrap();
        let traffic = TrafficStore::open(directory.path().join("traffic.sqlite")).unwrap();
        let sessions = Arc::new(RwLock::new(Sessions::default()));
        let socket = UdpSocket::bind(config.listen).unwrap();
        let peer = UdpSocket::bind(config.listen)
            .unwrap()
            .local_addr()
            .unwrap();
        let mut cache = HashMap::new();
        let mut connect = |client: usize, session_id: u64| {
            let mut handshake = ClientHandshake::new(
                &clients[client].secret,
                &config.server_public_key,
                &config.context,
            )
            .unwrap();
            let initial = handshake.write_initial(&[]).unwrap();
            handle_handshake(
                &socket,
                peer,
                Datagram::new(
                    Header {
                        kind: PacketKind::HandshakeInit,
                        flags: 0,
                        session_id,
                        sequence: 0,
                    },
                    &initial,
                ),
                HandshakeServices {
                    config: &config,
                    authorized: &registry,
                    traffic: &traffic,
                    sessions: &sessions,
                },
                &WireMode::Legacy,
                &mut cache,
            );
        };
        connect(0, 11);
        connect(1, 22);
        let victim = Arc::clone(&sessions.read().unwrap().by_id[&11]);
        let other = Arc::clone(&sessions.read().unwrap().by_id[&22]);
        connect(1, 11);
        {
            let guard = sessions.read().unwrap();
            assert!(Arc::ptr_eq(&guard.by_id[&11], &victim));
            assert!(Arc::ptr_eq(&guard.by_id[&22], &other));
            assert!(Arc::ptr_eq(&guard.by_address[&addresses[0]], &victim));
            assert!(Arc::ptr_eq(&guard.by_address[&addresses[1]], &other));
        }
        // A normal reconnect still replaces only this device's previous session.
        connect(1, 33);
        let guard = sessions.read().unwrap();
        assert!(!guard.by_id.contains_key(&22));
        assert!(guard.by_id.contains_key(&33));
        assert!(Arc::ptr_eq(&guard.by_id[&11], &victim));
        assert_eq!(guard.by_id.len(), 2);
        assert_eq!(guard.by_address.len(), 2);
        assert_eq!(guard.online_devices(), 2);
        *victim.last_authenticated.lock().unwrap() =
            std::time::Instant::now() - std::time::Duration::from_secs(91);
        assert_eq!(guard.online_devices(), 1);
        victim.adopt_peer(peer);
        assert_eq!(guard.online_devices(), 2);
        registry
            .revoke(&mousevpn_config::encode_public_key(&clients[0].public))
            .unwrap();
        assert_eq!(guard.online_devices(), 1);
    }
}

#[cfg(test)]
mod admin_listener_tests {
    use std::{
        io,
        net::{IpAddr, Ipv4Addr},
        sync::mpsc,
    };

    use mousevpn_admin_api::{SeedDevice, SharedDeviceRegistry};
    use mousevpn_config::{ServerTunConfig, ValidatedAuthorizedClient, ValidatedServerConfig};
    use mousevpn_crypto::{derive_morph_key, KeyPair, ProtocolContext};
    use mousevpn_morph::{DecodedFrame, Direction, MorphCodec, MorphKey, Profile};

    use super::{
        admin_listener_allowed, check_tun_worker, decode_wire_into, is_recoverable, MorphRouter,
        WireMode,
    };

    #[test]
    fn public_admin_listener_requires_explicit_opt_in() {
        let tunnel = Ipv4Addr::new(10, 77, 0, 1);
        assert!(admin_listener_allowed(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            tunnel,
            false
        ));
        assert!(admin_listener_allowed(IpAddr::V4(tunnel), tunnel, false));
        assert!(!admin_listener_allowed(
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            tunnel,
            false
        ));
        assert!(admin_listener_allowed(
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            tunnel,
            true
        ));
    }

    #[test]
    fn udp_queue_pressure_does_not_stop_the_server() {
        assert!(is_recoverable(&io::Error::from_raw_os_error(
            nix::libc::ENOBUFS
        )));
        assert!(is_recoverable(&io::Error::from_raw_os_error(
            nix::libc::ENOMEM
        )));
    }

    #[test]
    fn reports_worker_errors_and_disconnects() {
        let (sender, receiver) = mpsc::sync_channel(1);
        assert!(check_tun_worker(&receiver).is_ok());
        sender
            .send(io::Error::other("TUN worker failed"))
            .expect("send worker failure");
        assert!(check_tun_worker(&receiver).is_err());

        let (sender, receiver) = mpsc::sync_channel(1);
        drop(sender);
        assert!(check_tun_worker(&receiver).is_err());
    }

    #[test]
    fn router_resolves_every_profile_without_a_global_marker() {
        let server = KeyPair::generate().expect("server keys");
        let client = KeyPair::generate().expect("client keys");
        let server_public = server.public;
        let client_public = client.public;
        let config = ValidatedServerConfig {
            listen: "127.0.0.1:51820".parse().expect("listen"),
            public_endpoint: None,
            server_public_key: server_public,
            server_private_key: server.secret,
            context: ProtocolContext::for_server(&server_public),
            tun: ServerTunConfig {
                name: "mousevpn0".to_owned(),
                address: Ipv4Addr::new(10, 77, 0, 1),
                prefix_len: 24,
                mtu: 1_420,
                dns: Ipv4Addr::new(1, 1, 1, 1),
            },
            clients: vec![ValidatedAuthorizedClient {
                name: "owner".to_owned(),
                public_key: client_public,
                address: Ipv4Addr::new(10, 77, 0, 2),
            }],
        };
        let directory = tempfile::tempdir().expect("temporary directory");
        let registry = SharedDeviceRegistry::open(
            directory.path().join("devices.toml"),
            vec![SeedDevice {
                name: "owner".to_owned(),
                public_key: client_public,
                address: Ipv4Addr::new(10, 77, 0, 2),
            }],
            config.tun.address,
            config.tun.prefix_len,
        )
        .expect("registry");
        let key = derive_morph_key(
            &client.secret,
            &server_public,
            &server_public,
            &client_public,
        )
        .expect("client morph key");
        let mut router = MorphRouter::default();

        for profile in [Profile::Quiet, Profile::Balanced, Profile::Paranoid] {
            let codec = MorphCodec::new(MorphKey::from_bytes(key), profile);
            let mut encoded = Vec::new();
            codec
                .encode_payload(b"legacy packet", Direction::ClientToServer, &mut encoded)
                .expect("encode");
            let route = router.resolve(&encoded, &config, &registry).expect("route");
            assert_eq!(route.public_key, client_public);
            assert_eq!(route.profile, profile);
            let codec = MorphCodec::new(route.key, route.profile);
            let mut plaintext = Vec::new();
            assert_eq!(
                codec
                    .decode(&encoded, Direction::ClientToServer, &mut plaintext)
                    .expect("decode"),
                DecodedFrame::Payload { profile }
            );
            assert_eq!(plaintext, b"legacy packet");
        }
        assert!(router
            .resolve(
                b"legacy datagram without a matching tag",
                &config,
                &registry
            )
            .is_none());

        let legacy = b"legacy datagram without a matching tag";
        let mut decoded = Vec::new();
        assert!(matches!(
            decode_wire_into(legacy, &config, &registry, &mut router, &mut decoded),
            Some(WireMode::Legacy)
        ));
        assert_eq!(decoded, legacy);

        // Rotating tags must keep working with cached keys, and revocation
        // must remove both the routing tags and their cached secret material.
        let codec = MorphCodec::new(MorphKey::from_bytes(key), Profile::Quiet);
        let mut frame = Vec::new();
        codec
            .encode_payload(b"probe", Direction::ClientToServer, &mut frame)
            .unwrap();
        router.refresh(0, &config, &registry).unwrap();
        assert!(router.resolve(&frame, &config, &registry).is_some());
        registry
            .provision("replacement", mousevpn_admin_api::DevicePlatform::Android)
            .unwrap();
        registry
            .revoke(&mousevpn_config::encode_public_key(&client_public))
            .unwrap();
        router.refresh(0, &config, &registry).unwrap();
        assert!(router.resolve(&frame, &config, &registry).is_none());
        assert!(!router.keys.contains_key(&client_public));
    }
}
