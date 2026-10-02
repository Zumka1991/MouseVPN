#![doc = "Runs a per-application tunnel that needs no adapter and no routes."]

use std::{
    net::{IpAddr, Ipv4Addr},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc, Mutex, RwLock,
    },
    thread,
    time::Instant,
};

use mousevpn_client_wire::{ClientWire, MAX_WIRE_DATAGRAM_LEN};
use mousevpn_config::ValidatedClientConfig;
use mousevpn_data_plane::{DataPlaneError, Decoded, TunnelReceiver, TunnelSender};
use mousevpn_protocol::Datagram;
use mousevpn_transport::{DatagramTransport, UdpTransport};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;

use crate::{
    diagnostics::{Diagnostics, SendCounters},
    handshake::connect,
    liveness::{Action, Liveness},
    netcfg, network,
    packet_loop::{is_peer_unavailable, is_transient_io, UDP_POLL},
    platform::ensure_supported_runtime,
    windivert::{
        divert::{prepare_inbound, Diverter, Translation},
        flow::{FlowTable, FlowWatcher},
        Address, Library,
    },
    AppRoutingPolicy, ClientError,
};

const DATAGRAM_BUFFER_LEN: usize = 65_535;

/// Tunnels only the applications the policy selects, leaving the rest of the
/// machine on its physical link.
///
/// Nothing here touches the routing table, creates an adapter, or installs
/// firewall filters. Traffic reaches the tunnel because `WinDivert` lifts it out
/// of the stack, not because a route sent it somewhere. That is what keeps
/// excluded applications working exactly as they did before `MouseVPN` started:
/// their packets are handed straight back, unmodified.
///
/// The tunnel address exists only on the wire. Every packet is translated in
/// both directions, so applications continue to see the physical address they
/// bound to.
///
/// # Errors
///
/// Returns [`ClientError`] when elevation, the handshake, `WinDivert`, or packet
/// processing fails.
pub fn run_split_tunnel(
    config: &ValidatedClientConfig,
    stopping: &Arc<AtomicBool>,
    app_routing: &AppRoutingPolicy,
) -> Result<(), ClientError> {
    ensure_supported_runtime()?;
    let _runtime_lock = network::RuntimeLock::acquire()?;

    let wire = ClientWire::from_config(config)?;
    let (incoming, plane, parameters) = connect(config, &wire)?;
    incoming.set_read_timeout(Some(UDP_POLL))?;
    let outgoing = incoming.try_clone()?;

    // Shared rather than copied: a reconnect can change the tunnel address,
    // the MTU, and, if the machine moved networks, the physical address too.
    let route = netcfg::default_ipv4_route(None)?;
    let translation = Arc::new(RwLock::new(Translation::new(
        IpAddr::V4(network::physical_addresses()?.ipv4),
        IpAddr::V4(parameters.client_address),
        IpAddr::V4(parameters.dns),
        parameters.mtu,
    )));
    // Installed before capture starts: a query sent to the old resolver in the
    // gap would go out untunnelled.
    let _dns = DnsGuard::install(route.interface_luid, parameters.dns)?;

    let library = Library::load()?;
    // The watcher must be running before the diverter captures anything:
    // packets of a flow it has not classified yet pass through untranslated.
    let watcher = FlowWatcher::start(&library, app_routing)?;
    let table = watcher.table();
    let diverter = Arc::new(Diverter::open(
        &library,
        Arc::clone(&table),
        Arc::clone(&translation),
        config.server,
    )?);

    let (sender, receiver) = plane.split();
    let sender = Arc::new(Mutex::new(sender));
    let (transport_tx, transport_rx) = mpsc::sync_channel(1);
    let counters = Arc::new(SendCounters::default());

    eprintln!("MOUSEVPN_STATE=connected");
    eprintln!("MOUSEVPN_MODE=split_tunnel");

    let outbound = spawn_outbound(
        &diverter,
        &sender,
        stopping,
        wire.clone(),
        outgoing,
        transport_rx,
        &counters,
    )?;

    let result = ReceiveLoop {
        config,
        wire: &wire,
        transport: incoming,
        receiver,
        sender: &sender,
        translation: &translation,
        table: &table,
        diverter: &diverter,
        counters: &counters,
        outbound_transport: &transport_tx,
        inbound: Address::for_inbound(netcfg::default_ipv4_route(None)?.interface_index, 0),
    }
    .run(stopping);

    // The outbound worker parks inside `WinDivert`, so it only notices the stop
    // flag once the handle is shut down.
    stopping.store(true, Ordering::Release);
    diverter.stop();
    match outbound.join() {
        Ok(worker) => worker?,
        Err(_) => eprintln!("MOUSEVPN_SPLIT_WARNING=the split tunnel sender panicked"),
    }
    result
}

/// Encrypts captured packets and sends them to the server.
fn spawn_outbound(
    diverter: &Arc<Diverter>,
    sender: &Arc<Mutex<TunnelSender>>,
    stopping: &Arc<AtomicBool>,
    wire: ClientWire,
    mut transport: UdpTransport,
    replacements: mpsc::Receiver<UdpTransport>,
    counters: &Arc<SendCounters>,
) -> Result<thread::JoinHandle<Result<(), ClientError>>, ClientError> {
    let diverter = Arc::clone(diverter);
    let sender = Arc::clone(sender);
    let stopping = Arc::clone(stopping);
    let counters = Arc::clone(counters);
    thread::Builder::new()
        .name("mousevpn-split-outbound".to_owned())
        .spawn(move || {
            let mut encrypted = Vec::with_capacity(DATAGRAM_BUFFER_LEN);
            let mut datagram = Vec::with_capacity(MAX_WIRE_DATAGRAM_LEN);
            let mut oversized = 0_u64;
            diverter.run(&stopping, |packet| {
                // A reconnect hands over a replacement socket; the old one is
                // already closed and would fail every send.
                while let Ok(replacement) = replacements.try_recv() {
                    transport = replacement;
                }
                let encoded = sender
                    .lock()
                    .map_err(|_| poisoned())
                    .and_then(|mut sender| {
                        sender
                            .encode_ip_into(packet, &mut encrypted)
                            .map_err(|error| match error {
                                // An application may emit a packet larger than
                                // the tunnel can carry. Dropping one packet is
                                // recoverable; stopping is not.
                                DataPlaneError::PacketExceedsMtu { .. } | DataPlaneError::Ip(_) => {
                                    Skip
                                }
                                error => Fatal(error.into()),
                            })
                    });
                match encoded {
                    Ok(()) => {}
                    Err(Skip) => {
                        counters.failed();
                        // Clamping the segment size keeps TCP within the
                        // tunnel, so anything still arriving oversized is a
                        // datagram protocol probing upwards. Counting it is
                        // what turns a silent black hole into evidence.
                        oversized = oversized.saturating_add(1);
                        if oversized.is_power_of_two() {
                            // Naming the protocol and size separates a
                            // datagram protocol probing for a larger path,
                            // which corrects itself, from a stream the segment
                            // clamp failed to hold down, which does not.
                            let protocol = packet.get(9).copied().unwrap_or(0);
                            eprintln!(
                                "MOUSEVPN_SPLIT_WARNING=dropped {oversized} packet(s) larger \
                                 than the tunnel MTU; last was protocol {protocol}, {} bytes",
                                packet.len()
                            );
                        }
                        return;
                    }
                    Err(Fatal(error)) => {
                        counters.failed();
                        eprintln!("MOUSEVPN_SPLIT_WARNING={error}");
                        return;
                    }
                }
                match wire
                    .encode(&encrypted, &mut datagram)
                    .map_err(ClientError::from)
                    .and_then(|()| transport.send(&datagram).map_err(ClientError::from))
                {
                    Ok(()) => counters.sent(datagram.len()),
                    // The receive loop notices the same silence and rebuilds
                    // the session; reporting every packet would drown it out.
                    Err(ClientError::Io(error))
                        if is_peer_unavailable(&error) || is_transient_io(&error) =>
                    {
                        counters.failed();
                    }
                    Err(error) => {
                        counters.failed();
                        eprintln!("MOUSEVPN_SPLIT_WARNING={error}");
                    }
                }
            })
        })
        .map_err(|error| {
            ClientError::Platform(format!("failed to start the split tunnel sender: {error}"))
        })
}

/// Translates packets arriving from the server and keeps the session alive.
struct ReceiveLoop<'a> {
    config: &'a ValidatedClientConfig,
    wire: &'a ClientWire,
    transport: UdpTransport,
    receiver: TunnelReceiver,
    sender: &'a Arc<Mutex<TunnelSender>>,
    translation: &'a Arc<RwLock<Translation>>,
    table: &'a Arc<FlowTable>,
    diverter: &'a Diverter,
    counters: &'a Arc<SendCounters>,
    outbound_transport: &'a mpsc::SyncSender<UdpTransport>,
    inbound: Address,
}

/// The scratch space one session reuses for every packet.
///
/// Sized once when the loop starts, so the receive path allocates nothing
/// afterwards. Kept together because passing six buffers individually says
/// nothing that "the buffers" does not.
struct Buffers {
    encrypted: Vec<u8>,
    payload: Vec<u8>,
    plaintext: Vec<u8>,
    /// Injection rewrites the packet, and the decoded one is borrowed from
    /// `plaintext`. One buffer for that copy is what keeps the inbound path
    /// from allocating per packet.
    injectable: Vec<u8>,
    keepalive: Vec<u8>,
    wire_keepalive: Vec<u8>,
}

impl Buffers {
    fn new() -> Self {
        Self {
            encrypted: vec![0_u8; MAX_WIRE_DATAGRAM_LEN],
            payload: Vec::with_capacity(DATAGRAM_BUFFER_LEN),
            plaintext: Vec::with_capacity(DATAGRAM_BUFFER_LEN),
            injectable: Vec::with_capacity(DATAGRAM_BUFFER_LEN),
            keepalive: Vec::with_capacity(128),
            wire_keepalive: Vec::with_capacity(MAX_WIRE_DATAGRAM_LEN),
        }
    }
}

impl ReceiveLoop<'_> {
    fn run(&mut self, stopping: &AtomicBool) -> Result<(), ClientError> {
        let mut buffers = Buffers::new();
        let mut liveness = Liveness::new(Instant::now());
        let mut diagnostics = Diagnostics::start();

        while !stopping.load(Ordering::Acquire) {
            match self.transport.receive(&mut buffers.encrypted) {
                Ok(length) => {
                    // Timed because this is the only stretch where the socket
                    // is unattended. How long it lasts decides whether the
                    // datagrams missing from the sequence were dropped here or
                    // never arrived. Read the clock only when something will
                    // read the answer.
                    let started = diagnostics.enabled().then(Instant::now);
                    self.deliver(length, &mut buffers, &mut liveness, &mut diagnostics);
                    if let Some(started) = started {
                        diagnostics.processed(started.elapsed());
                    }
                }
                Err(error) if is_transient_io(&error) => {}
                Err(error) if is_peer_unavailable(&error) => {
                    liveness.connection_lost(Instant::now());
                }
                Err(error) => return Err(error.into()),
            }
            self.maintain(&mut liveness, &mut buffers, &mut diagnostics)?;
            // The receive timeout bounds how long this can be deferred, so a
            // silent tunnel still reports its silence on schedule.
            diagnostics.report(self.counters);
        }
        Ok(())
    }

    /// Decodes one datagram and injects it if it belongs to this session.
    fn deliver(
        &mut self,
        length: usize,
        buffers: &mut Buffers,
        liveness: &mut Liveness,
        diagnostics: &mut Diagnostics,
    ) {
        let framed = self
            .wire
            .decode(&buffers.encrypted[..length], &mut buffers.payload)
            .ok()
            .filter(|decoded| *decoded)
            .and_then(|_| Datagram::decode(&buffers.payload).ok());
        let Some(datagram) = framed else {
            diagnostics.rejected();
            return;
        };
        // Read before the datagram is consumed: the header numbers every
        // datagram the server sends, which is the only way from here to tell
        // a packet the network dropped from one that was never sent.
        let sequence = datagram.header.sequence;
        let packet = match self.receiver.decode_into(datagram, &mut buffers.plaintext) {
            Ok(Decoded::Ip(packet)) => {
                diagnostics.received(sequence, length);
                packet
            }
            // A keepalive proves the peer is there, which is its entire job.
            // It is also the reply to a probe we timed, and so the session's
            // round-trip time.
            Ok(Decoded::Keepalive) => {
                let now = Instant::now();
                diagnostics.received(sequence, length);
                diagnostics.probe_answered(now);
                liveness.packet_received(now);
                return;
            }
            Err(_) => {
                diagnostics.rejected();
                return;
            }
        };
        liveness.packet_received(Instant::now());

        let Ok(translation) = self.translation.read().map(|guard| *guard) else {
            return;
        };
        buffers.injectable.clear();
        buffers.injectable.extend_from_slice(packet);
        // A packet addressed to anything but the tunnel address is not ours to
        // deliver, and injecting it could hand an application traffic it never
        // asked for.
        if prepare_inbound(&mut buffers.injectable, translation) {
            self.diverter
                .inject_inbound(&mut buffers.injectable, self.inbound);
        }
    }

    fn maintain(
        &mut self,
        liveness: &mut Liveness,
        buffers: &mut Buffers,
        diagnostics: &mut Diagnostics,
    ) -> Result<(), ClientError> {
        let now = Instant::now();
        match liveness.action(now) {
            Action::None => Ok(()),
            Action::Keepalive => {
                let mut sender = self.sender.lock().map_err(|_| {
                    ClientError::Platform("the split tunnel sender lock was poisoned".to_owned())
                })?;
                sender.encode_keepalive_into(&mut buffers.keepalive)?;
                self.wire
                    .encode(&buffers.keepalive, &mut buffers.wire_keepalive)?;
                match self.transport.send(&buffers.wire_keepalive) {
                    Ok(()) => {
                        liveness.keepalive_sent(now);
                        // The server answers a keepalive with a keepalive, so
                        // this is the outbound half of a real round trip and
                        // not an estimate derived from anything else.
                        diagnostics.probe_sent(now);
                    }
                    Err(error) if is_peer_unavailable(&error) => liveness.connection_lost(now),
                    Err(error) => return Err(error.into()),
                }
                Ok(())
            }
            Action::Reconnect => {
                liveness.reconnect_attempted(now);
                eprintln!("MOUSEVPN_STATE=reconnecting");
                match self.establish() {
                    Ok(()) => {
                        liveness.reconnected(Instant::now());
                        // The new session numbers its datagrams from zero, so
                        // anything measured against the old one is now noise.
                        diagnostics.session_restarted();
                        eprintln!("MOUSEVPN_STATE=reconnected");
                    }
                    Err(error) => eprintln!("MOUSEVPN_RECONNECT_ERROR={error}"),
                }
                Ok(())
            }
        }
    }

    /// Rebuilds the session, following the machine wherever it has moved.
    fn establish(&mut self) -> Result<(), ClientError> {
        // Sleeping, a docking station or a hop between Wi-Fi networks can all
        // change which interface carries traffic, so none of this is reread
        // from what the session started with.
        let physical = IpAddr::V4(network::physical_addresses()?.ipv4);
        let route = netcfg::default_ipv4_route(None)?;
        let (transport, plane, parameters) = connect(self.config, self.wire)?;
        transport.set_read_timeout(Some(UDP_POLL))?;
        let outgoing = transport.try_clone()?;

        let replacement = Translation::new(
            physical,
            IpAddr::V4(parameters.client_address),
            IpAddr::V4(parameters.dns),
            parameters.mtu,
        );
        {
            let mut translation = self.translation.write().map_err(|_| {
                ClientError::Platform("the split tunnel translation lock was poisoned".to_owned())
            })?;
            // Every flow key carries the physical local address. If that
            // changed, the recorded classifications can never match again, and
            // leaving them would route new flows by a decision made for an
            // address the machine no longer holds.
            if translation.physical != replacement.physical {
                self.table.clear();
                eprintln!("MOUSEVPN_STATE=physical_address_changed");
            }
            *translation = replacement;
        }

        let (sender, receiver) = plane.split();
        *self.sender.lock().map_err(|_| {
            ClientError::Platform("the split tunnel sender lock was poisoned".to_owned())
        })? = sender;
        self.receiver = receiver;
        self.outbound_transport
            .send(outgoing)
            .map_err(|_| ClientError::Platform("the split tunnel sender stopped".to_owned()))?;
        self.transport = transport;
        // Injected replies claim to arrive on the interface an application
        // would have used, which may not be the one the session started on.
        self.inbound = Address::for_inbound(route.interface_index, 0);
        Ok(())
    }
}

/// Points the physical interface at the session's resolver for the duration.
///
/// A full tunnel gives its adapter the resolver and Windows follows. There is
/// no adapter here, so the physical interface has to carry it, and the packets
/// it produces are recognised by destination and sent through the tunnel.
///
/// Without this the machine keeps whatever resolver its network offers. That is
/// usually fine and sometimes fatal: a router that does not answer at all
/// leaves every application unable to resolve a name, while a browser with its
/// own encrypted resolver carries on and hides the fault.
struct DnsGuard {
    alias: String,
}

impl DnsGuard {
    /// # Errors
    ///
    /// Returns an error when the interface cannot be named or netsh refuses.
    fn install(interface: NET_LUID_LH, resolver: Ipv4Addr) -> Result<Self, ClientError> {
        let alias = netcfg::interface_alias(interface)?;
        netcfg::set_tunnel_dns(&alias, resolver)?;
        eprintln!("MOUSEVPN_STATE=dns_configured");
        Ok(Self { alias })
    }
}

impl Drop for DnsGuard {
    fn drop(&mut self) {
        // Leaving a resolver behind that only existed inside the tunnel would
        // break name resolution on a machine that is no longer connected, so a
        // failure here is worth reporting loudly.
        if let Err(error) = netcfg::reset_tunnel_dns(&self.alias) {
            eprintln!(
                "MOUSEVPN_RUNTIME_WARNING=failed to restore DNS on {}: {error}",
                self.alias
            );
        }
    }
}

/// Distinguishes a packet worth dropping from a failure worth reporting.
enum SendFailure {
    Skip,
    Fatal(ClientError),
}
use SendFailure::{Fatal, Skip};

fn poisoned() -> SendFailure {
    Fatal(ClientError::Platform(
        "the split tunnel sender lock was poisoned".to_owned(),
    ))
}
