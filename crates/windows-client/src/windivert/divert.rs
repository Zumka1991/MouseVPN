#![doc = "Moves selected applications' packets between the stack and the tunnel."]

use std::{
    fmt::Write as _,
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, RwLock,
    },
    time::{Duration, Instant},
};

use super::{
    flow::{Disposition, FlowKey, FlowTable},
    packet::{Packet, PROTOCOL_TCP, PROTOCOL_UDP},
    Address, Handle, Library, BATCH_MAX, LAYER_NETWORK, MTU_MAX,
};
use crate::ClientError;

const DNS_PORT: u16 = 53;

/// The staging buffer for one batch, in bytes.
///
/// Wide enough for a full batch of ordinary frames, and on its own wide enough
/// for the largest packet `WinDivert` will ever hand over, so a segment-offload
/// giant cannot wedge the loop by never fitting.
const CAPTURE_BUFFER: usize = 512 * 1024;
const _: () = assert!(CAPTURE_BUFFER > MTU_MAX);

/// Staging for packets that stay on the physical link.
///
/// Excluded applications are the majority of what the capture loop sees, and
/// every one of their packets has to be handed back untouched. Handing them
/// back individually costs a kernel transition each, charged to applications
/// the user asked the tunnel to leave alone. Copying them into one buffer and
/// injecting the lot costs a memory copy each instead, which is roughly two
/// orders of magnitude cheaper.
struct Reinject {
    packets: Vec<u8>,
    addresses: Vec<Address>,
    /// Where the boundaries between the staged packets fall.
    ///
    /// Only needed when a batch is refused and has to be retried one packet at
    /// a time, which is exactly when the boundaries are no longer recoverable
    /// from anything else.
    lengths: Vec<usize>,
}

impl Reinject {
    fn new() -> Self {
        Self {
            packets: Vec::with_capacity(CAPTURE_BUFFER),
            addresses: Vec::with_capacity(BATCH_MAX),
            lengths: Vec::with_capacity(BATCH_MAX),
        }
    }

    /// Reports whether one more packet of `length` bytes would overrun either
    /// limit `WinDivert` places on a batch.
    fn is_full(&self, length: usize) -> bool {
        self.addresses.len() >= BATCH_MAX
            || self.packets.len().saturating_add(length) > CAPTURE_BUFFER
    }

    fn push(&mut self, packet: &[u8], address: Address) {
        self.packets.extend_from_slice(packet);
        self.addresses.push(address);
        self.lengths.push(packet.len());
    }

    /// Hands the staged packets back to the stack, reporting drops without
    /// stopping.
    ///
    /// Losing packets here is survivable — TCP and QUIC both recover — whereas
    /// returning an error would take down the tunnel. Losing a whole batch is
    /// a different matter: `WinDivert` refuses a batch as a unit, so a single
    /// packet it objects to would cost up to two hundred and fifty-four
    /// innocent ones belonging to applications the user excluded from the
    /// tunnel entirely. The retry below narrows that back down to the packet
    /// actually at fault.
    fn flush(&mut self, handle: &Handle) {
        if self.addresses.is_empty() {
            return;
        }
        if handle.send_batch(&self.packets, &self.addresses).is_err() {
            self.flush_individually(handle);
        }
        self.packets.clear();
        self.addresses.clear();
        self.lengths.clear();
    }

    /// Reinjects the staged packets one at a time after a batch was refused.
    fn flush_individually(&self, handle: &Handle) {
        let mut offset = 0_usize;
        let mut refused = 0_u64;
        for (length, address) in self.lengths.iter().zip(&self.addresses) {
            let end = offset.saturating_add(*length).min(self.packets.len());
            if handle.send(&self.packets[offset..end], address).is_err() {
                refused = refused.saturating_add(1);
            }
            offset = end;
        }
        eprintln!(
            "MOUSEVPN_DIVERT_WARNING=WinDivert refused a batch of {} packet(s); resent them \
             individually and lost {refused}",
            self.addresses.len()
        );
    }
}

/// How often the capture loop reports what it has been doing.
const STATS_INTERVAL: Duration = Duration::from_secs(10);

/// Running totals for the capture loop.
///
/// A split tunnel fails in ways that look identical from outside: an
/// application left on the physical link and one whose packets vanish both
/// present as "it does not work". These counts tell them apart.
struct Stats {
    tunnelled: u64,
    passed: u64,
    discarded: u64,
    batches: u64,
    reported: Instant,
}

impl Stats {
    fn new() -> Self {
        Self {
            tunnelled: 0,
            passed: 0,
            discarded: 0,
            batches: 0,
            reported: Instant::now(),
        }
    }

    fn report(&mut self) {
        if self.reported.elapsed() < STATS_INTERVAL {
            return;
        }
        self.reported = Instant::now();
        // Packets per batch is the number to watch. A figure near one means
        // the loop is keeping up and every packet costs a kernel transition;
        // a figure in the tens or hundreds means the queue is filling faster
        // than user mode drains it, which is what precedes packet loss.
        let handled = self
            .tunnelled
            .saturating_add(self.passed)
            .saturating_add(self.discarded);
        // Tenths, in integers: the ratio is only ever read by eye, and a float
        // here would be the one lossy cast in the packet path.
        let tenths = handled.saturating_mul(10) / self.batches.max(1);
        eprintln!(
            "MOUSEVPN_DIVERT_STATS=tunnelled={} passed={} discarded={} batches={} \
             packets_per_batch={}.{}",
            self.tunnelled,
            self.passed,
            self.discarded,
            self.batches,
            tenths / 10,
            tenths % 10
        );
    }
}

/// What to do with a captured outbound packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Outcome {
    /// The packet belongs to a routed application: it has been rewritten to
    /// carry the tunnel's source address and must go to the data plane.
    Tunnel,
    /// The packet belongs to an application that stays on the physical link.
    /// It has not been touched and must be reinjected exactly as captured.
    PassThrough,
    /// The packet belongs to a routed application but cannot be tunnelled.
    /// It must be discarded rather than handed back, because reinjecting it
    /// would send traffic the user asked to protect out in the clear.
    Discard,
}

/// How the split tunnel translates between the two ends of a session.
///
/// Applications only ever see `physical`, because every packet is translated
/// before it reaches them. `tunnel` exists solely on the wire to the server.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Translation {
    pub(crate) physical: IpAddr,
    pub(crate) tunnel: IpAddr,
    /// The resolver the session provides. Traffic to it always takes the
    /// tunnel, whichever process sent it.
    pub(crate) resolver: IpAddr,
    /// The largest TCP segment the tunnel can carry, clamped into the
    /// handshake of every routed connection.
    pub(crate) max_segment_size: u16,
}

impl Translation {
    /// Derives the segment limit from the tunnel's MTU.
    ///
    /// A full-tunnel session hands this MTU to the Wintun adapter and the stack
    /// sizes everything accordingly. There is no adapter here, so the limit has
    /// to be imposed on the connections themselves.
    pub(crate) fn new(physical: IpAddr, tunnel: IpAddr, resolver: IpAddr, tunnel_mtu: u16) -> Self {
        // IPv4 and TCP headers, twenty bytes each, come off the top.
        const HEADERS: u16 = 40;
        Self {
            physical,
            tunnel,
            resolver,
            max_segment_size: tunnel_mtu.saturating_sub(HEADERS),
        }
    }
}

/// Builds the capture filter.
///
/// Two exclusions are load-bearing. Our own tunnel datagrams must never be
/// captured, or every packet we send would come straight back to us and the
/// client would wedge itself. Loopback is excluded because local traffic has no
/// business crossing a VPN and capturing it only costs latency.
/// Compiles the built-in filter plus any extras, reporting each verdict.
///
/// Exposed for the `filter_check` example: a filter the driver rejects is
/// otherwise only visible as `ERROR_INVALID_PARAMETER` at connection time.
///
/// # Errors
///
/// Returns [`ClientError::Platform`] when `WinDivert.dll` cannot be loaded.
pub fn check_capture_filters(extra: &[String]) -> Result<String, ClientError> {
    let library = Library::load()?;
    let server: SocketAddr = "203.0.113.10:51820".parse().unwrap_or_else(|_| {
        unreachable!("the sample endpoint is a literal");
    });
    let mut report = String::new();
    let built_in = filter(server);
    for candidate in std::iter::once(&built_in).chain(extra) {
        let verdict = match library.check_filter(candidate, LAYER_NETWORK) {
            Ok(()) => "OK  ".to_owned(),
            Err(error) => format!("FAIL {error}\n     "),
        };
        let _ = writeln!(report, "{verdict}{candidate}");
    }
    Ok(report)
}

/// The exclusion is written as a disjunction rather than the more obvious
/// `not (udp and dst == server and port == p)`. `WinDivert` applies negation to
/// a single test, not to a parenthesised group, and rejects the latter with a
/// parse error that surfaces only as `ERROR_INVALID_PARAMETER` when the handle
/// is opened. De Morgan's law gives the same meaning in a form it accepts.
fn filter(server: SocketAddr) -> String {
    let family = if server.is_ipv4() { "ip" } else { "ipv6" };
    format!(
        "outbound and !loopback and {family} and \
         (tcp or (udp and ({family}.DstAddr != {} or udp.DstPort != {})))",
        server.ip(),
        server.port()
    )
}

/// Rewrites a captured outbound packet when it belongs in the tunnel.
///
/// Returns [`Outcome::PassThrough`] for anything not positively identified as
/// routed: unparseable packets, protocols without ports, and flows the watcher
/// has not classified. Defaulting to "leave it alone" means an unknown packet
/// keeps working over the physical link instead of vanishing into a tunnel
/// that may not expect it.
pub(crate) fn prepare_outbound(
    bytes: &mut [u8],
    table: &FlowTable,
    translation: Translation,
) -> Outcome {
    let Some(mut packet) = Packet::parse(bytes) else {
        return Outcome::PassThrough;
    };
    if !matches!(packet.protocol(), PROTOCOL_TCP | PROTOCOL_UDP) {
        return Outcome::PassThrough;
    }
    let Some((source_port, destination_port)) = packet.ports() else {
        return Outcome::PassThrough;
    };
    let key = FlowKey {
        protocol: packet.protocol(),
        local: packet.source(),
        local_port: source_port,
        remote: packet.destination(),
        remote_port: destination_port,
    };
    // Name resolution is the one thing that cannot follow the per-application
    // policy. Windows resolves through a shared service, so a query carries no
    // trace of which application wanted the name, and the session's resolver
    // only exists at the far end of the tunnel: sent any other way the query
    // would be routed at an address that does not answer. Every application
    // therefore resolves through the tunnel, including excluded ones.
    let resolving = packet.destination() == translation.resolver && destination_port == DNS_PORT;
    if !resolving && table.lookup(&key) != Some(Disposition::Tunnel) {
        return Outcome::PassThrough;
    }
    // The application bound to the physical address, but the server only
    // recognises the tunnel one. Anything else would come back to the wrong
    // place, if it came back at all.
    //
    // This fails when the flow is IPv6, because the session only assigns an
    // IPv4 address. Handing such a packet back would put traffic the policy
    // routes through the tunnel onto the physical link instead, so it is
    // dropped: the application sees the address family fail and falls back.
    if !packet.set_source(translation.tunnel) {
        return Outcome::Discard;
    }
    packet.clamp_mss(translation.max_segment_size);
    Outcome::Tunnel
}

/// Restores the physical destination on a packet arriving from the tunnel.
///
/// Returns `false` when the packet is not addressed to the tunnel address, so
/// traffic meant for something else is never redirected at an application.
pub(crate) fn prepare_inbound(bytes: &mut [u8], translation: Translation) -> bool {
    let Some(mut packet) = Packet::parse(bytes) else {
        return false;
    };
    if packet.destination() != translation.tunnel {
        return false;
    }
    if !packet.set_destination(translation.physical) {
        return false;
    }
    // Clamping only the outbound handshake limits what the peer sends us, not
    // what we send it: our segment size comes from the option in its reply.
    // Leaving that alone lets the stack build packets too large for the tunnel,
    // so downloads work while anything we upload disappears.
    packet.clamp_mss(translation.max_segment_size);
    true
}

/// Captures outbound packets and feeds the routed ones to the tunnel.
///
/// The translation is shared rather than copied because a reconnect can change
/// it: the server may assign a different tunnel address or MTU, and moving
/// between networks changes the physical address too.
pub(crate) struct Diverter {
    handle: Arc<Handle>,
    table: Arc<FlowTable>,
    translation: Arc<RwLock<Translation>>,
}

impl Diverter {
    /// Opens the network-layer handle used for capture and injection.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Platform`] when the handle cannot be opened,
    /// which includes a filter the driver rejects.
    pub(crate) fn open(
        library: &Arc<Library>,
        table: Arc<FlowTable>,
        translation: Arc<RwLock<Translation>>,
        server: SocketAddr,
    ) -> Result<Self, ClientError> {
        // Priority 0 keeps MouseVPN below tools that deliberately sit high,
        // and nothing here depends on winning against another filter.
        let handle = Arc::new(library.open(&filter(server), LAYER_NETWORK, 0, 0)?);
        // This handle carries every packet the machine sends, not only the
        // tunnelled ones, so it is the one that overflows first.
        handle.tune_queues();
        Ok(Self {
            handle,
            table,
            translation,
        })
    }

    /// Runs the capture loop until [`Diverter::stop`] is called.
    ///
    /// `sink` receives every packet bound for the tunnel, already rewritten.
    /// Packets that stay on the physical link are reinjected before `sink` is
    /// consulted for any of them, so a slow data plane cannot stall unrelated
    /// traffic.
    ///
    /// Packets are drained a batch at a time rather than one by one. With
    /// seven applications routed and the rest direct, the great majority of
    /// what this loop sees is traffic it will hand straight back, and the cost
    /// of handing it back is what excluded applications feel as the tunnel
    /// slowing them down. One kernel transition per batch instead of two per
    /// packet is the difference between that cost scaling with the machine's
    /// packet rate and scaling with how often the loop runs.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Platform`] when the capture fails. A shutdown is
    /// not a failure and returns `Ok(())`.
    pub(crate) fn run(
        &self,
        stopping: &AtomicBool,
        mut sink: impl FnMut(&[u8]),
    ) -> Result<(), ClientError> {
        let mut buffer = vec![0_u8; CAPTURE_BUFFER];
        let mut addresses = vec![Address::zeroed(); BATCH_MAX];
        let mut reinject = Reinject::new();
        // Where each tunnelled packet ended up in `buffer`, so the whole batch
        // can be reinjected before any of it is encrypted. Recording ranges
        // rather than copying keeps that ordering free.
        let mut tunnelled: Vec<(usize, usize)> = Vec::with_capacity(BATCH_MAX);
        let mut discarded = 0_u64;
        let mut unsplittable = 0_u64;
        let mut stats = Stats::new();
        while !stopping.load(Ordering::Acquire) {
            stats.report();
            let Some((bytes, count)) = self.handle.recv_batch(&mut buffer, &mut addresses)? else {
                return Ok(());
            };
            stats.batches = stats.batches.saturating_add(1);
            // Read once per batch: a reconnect may have replaced the addresses
            // since the last one arrived, but it cannot do so mid-batch.
            let Ok(translation) = self.translation.read().map(|guard| *guard) else {
                return Err(ClientError::Platform(
                    "the split tunnel translation lock was poisoned".to_owned(),
                ));
            };
            let mut offset = 0_usize;
            for address in addresses.iter().take(count) {
                if offset >= bytes {
                    break;
                }
                // A batch has no framing of its own, so a packet whose bounds
                // cannot be found takes every packet behind it with it. The
                // alternative — guessing — would corrupt them instead.
                let Some(length) = self.handle.first_packet_len(&buffer[offset..bytes]) else {
                    unsplittable = unsplittable.saturating_add(1);
                    if unsplittable.is_power_of_two() {
                        eprintln!(
                            "MOUSEVPN_DIVERT_WARNING=abandoned {unsplittable} batch(es) after a \
                             packet WinDivert could not parse"
                        );
                    }
                    break;
                };
                let start = offset;
                let end = offset.saturating_add(length).min(bytes);
                let packet = &mut buffer[start..end];
                offset = end;
                match prepare_outbound(packet, &self.table, translation) {
                    Outcome::PassThrough => {
                        stats.passed = stats.passed.saturating_add(1);
                        // Captured but unmodified, so the checksums the stack
                        // computed are still correct and reinjection is a
                        // straight handback.
                        if reinject.is_full(packet.len()) {
                            reinject.flush(&self.handle);
                        }
                        reinject.push(packet, *address);
                    }
                    Outcome::Discard => {
                        stats.discarded = stats.discarded.saturating_add(1);
                        discarded = discarded.saturating_add(1);
                        if discarded.is_power_of_two() {
                            eprintln!(
                                "MOUSEVPN_DIVERT_WARNING=discarded {discarded} packet(s) of \
                                 routed applications that this session cannot carry, usually IPv6"
                            );
                        }
                    }
                    Outcome::Tunnel => {
                        stats.tunnelled = stats.tunnelled.saturating_add(1);
                        // The source address changed, which invalidates the IP
                        // and transport checksums the stack had already filled
                        // in.
                        let mut owned = *address;
                        if let Err(error) = self.handle.calc_checksums(packet, &mut owned) {
                            eprintln!("MOUSEVPN_DIVERT_WARNING={error}");
                            continue;
                        }
                        tunnelled.push((start, end));
                    }
                }
            }
            // Before a single packet is encrypted: `sink` encrypts and sends
            // on the wire, and an application the user excluded from the
            // tunnel must not wait behind the tunnel's own round trip.
            reinject.flush(&self.handle);
            for (start, end) in tunnelled.drain(..) {
                sink(&buffer[start..end]);
            }
        }
        Ok(())
    }

    /// Delivers a translated packet from the tunnel to the local stack.
    ///
    /// The destination address changed on the way in, so the checksums the
    /// server computed no longer hold and are recomputed before injection.
    /// Failures are reported and dropped for the same reason as
    /// [`Diverter::reinject`]: one lost packet is recoverable, a torn-down
    /// tunnel is not.
    pub(crate) fn inject_inbound(&self, packet: &mut [u8], address: Address) {
        let mut address = address;
        if let Err(error) = self.handle.calc_checksums(packet, &mut address) {
            eprintln!("MOUSEVPN_DIVERT_WARNING={error}");
            return;
        }
        if let Err(error) = self.handle.send(packet, &address) {
            eprintln!("MOUSEVPN_DIVERT_WARNING={error}");
        }
    }

    /// Unblocks the capture loop.
    pub(crate) fn stop(&self) {
        self.handle.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::{filter, prepare_inbound, prepare_outbound, Address, Outcome, Translation};
    use crate::windivert::{
        flow::{Disposition, FlowKey, FlowTable},
        packet::PROTOCOL_UDP,
    };
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    const PHYSICAL: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 0, 189));
    const TUNNEL: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 77, 0, 22));
    const REMOTE: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
    const RESOLVER: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 77, 0, 1));

    fn addresses() -> Translation {
        Translation::new(PHYSICAL, TUNNEL, RESOLVER, 1280)
    }

    fn udp_packet(source: IpAddr, destination: IpAddr) -> Vec<u8> {
        let (IpAddr::V4(source), IpAddr::V4(destination)) = (source, destination) else {
            unreachable!("tests use IPv4")
        };
        let mut packet = vec![0_u8; 28];
        packet[0] = 0x45;
        packet[9] = PROTOCOL_UDP;
        packet[12..16].copy_from_slice(&source.octets());
        packet[16..20].copy_from_slice(&destination.octets());
        packet[20..22].copy_from_slice(&54_518_u16.to_be_bytes());
        packet[22..24].copy_from_slice(&53_u16.to_be_bytes());
        packet
    }

    fn table_with(disposition: Disposition) -> FlowTable {
        let table = FlowTable::default();
        table.insert_for_test(
            FlowKey {
                protocol: PROTOCOL_UDP,
                local: PHYSICAL,
                local_port: 54_518,
                remote: REMOTE,
                remote_port: 53,
            },
            disposition,
        );
        table
    }

    #[test]
    fn stages_pass_through_packets_end_to_end() {
        // The batch carries no framing, so the packets must land in the buffer
        // back to back and in the order they were captured. Anything else and
        // WinDivert injects the wrong bytes against the wrong address.
        let mut reinject = super::Reinject::new();
        reinject.push(&[1, 2, 3], Address::zeroed());
        reinject.push(&[4, 5], Address::zeroed());
        assert_eq!(reinject.packets, [1, 2, 3, 4, 5]);
        assert_eq!(reinject.addresses.len(), 2);
    }

    #[test]
    fn refuses_more_than_windivert_accepts_in_one_batch() {
        // Exceeding either limit is not a partial send: WinDivert rejects the
        // whole call, which would drop a full batch of excluded traffic.
        let mut reinject = super::Reinject::new();
        for _ in 0..super::BATCH_MAX {
            assert!(!reinject.is_full(64));
            reinject.push(&[0; 64], Address::zeroed());
        }
        assert!(reinject.is_full(64));
    }

    #[test]
    fn refuses_a_packet_that_would_overrun_the_staging_buffer() {
        let mut reinject = super::Reinject::new();
        reinject.push(&vec![0; super::CAPTURE_BUFFER - 8], Address::zeroed());
        assert!(reinject.is_full(9));
        assert!(!reinject.is_full(8));
    }

    #[test]
    fn rewrites_a_routed_packet_onto_the_tunnel_address() {
        let mut packet = udp_packet(PHYSICAL, REMOTE);
        let table = table_with(Disposition::Tunnel);
        assert_eq!(
            prepare_outbound(&mut packet, &table, addresses()),
            Outcome::Tunnel
        );
        assert_eq!(&packet[12..16], &[10, 77, 0, 22]);
        // The destination and ports must survive untouched.
        assert_eq!(&packet[16..20], &[1, 1, 1, 1]);
        assert_eq!(&packet[20..24], &[0xd4, 0xf6, 0x00, 0x35]);
    }

    #[test]
    fn leaves_an_excluded_packet_byte_for_byte_alone() {
        let mut packet = udp_packet(PHYSICAL, REMOTE);
        let original = packet.clone();
        let table = table_with(Disposition::Direct);
        assert_eq!(
            prepare_outbound(&mut packet, &table, addresses()),
            Outcome::PassThrough
        );
        assert_eq!(packet, original);
    }

    #[test]
    fn passes_through_a_flow_the_watcher_has_not_classified() {
        // Racing the flow layer must not swallow traffic: an unknown packet
        // keeps working on the physical link.
        let mut packet = udp_packet(PHYSICAL, REMOTE);
        let original = packet.clone();
        assert_eq!(
            prepare_outbound(&mut packet, &FlowTable::default(), addresses()),
            Outcome::PassThrough
        );
        assert_eq!(packet, original);
    }

    #[test]
    fn restores_the_physical_address_on_the_way_back() {
        let mut packet = udp_packet(REMOTE, TUNNEL);
        assert!(prepare_inbound(&mut packet, addresses()));
        assert_eq!(&packet[16..20], &[192, 168, 0, 189]);
    }

    /// A SYN-ACK arriving from the tunnel, offering a segment size sized for a
    /// physical link.
    fn inbound_syn_ack(mss: u16) -> Vec<u8> {
        let (IpAddr::V4(remote), IpAddr::V4(tunnel)) = (REMOTE, TUNNEL) else {
            unreachable!("tests use IPv4")
        };
        let mut packet = vec![0_u8; 20 + 24];
        packet[0] = 0x45;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&remote.octets());
        packet[16..20].copy_from_slice(&tunnel.octets());
        packet[20..22].copy_from_slice(&443_u16.to_be_bytes());
        packet[22..24].copy_from_slice(&51_000_u16.to_be_bytes());
        // Six words of header, SYN and ACK set.
        packet[32] = 6 << 4;
        packet[33] = 0x12;
        packet[40] = 2;
        packet[41] = 4;
        packet[42..44].copy_from_slice(&mss.to_be_bytes());
        packet
    }

    #[test]
    fn clamps_the_segment_size_the_peer_offers_us() {
        // Without this the peer's own limit governs what we send, and every
        // upload larger than the tunnel's MTU vanishes while downloads work.
        let mut packet = inbound_syn_ack(1460);
        assert!(prepare_inbound(&mut packet, addresses()));
        assert_eq!(u16::from_be_bytes([packet[42], packet[43]]), 1240);
        assert_eq!(&packet[16..20], &[192, 168, 0, 189]);
    }

    #[test]
    fn refuses_inbound_packets_addressed_elsewhere() {
        let mut packet = udp_packet(REMOTE, PHYSICAL);
        let original = packet.clone();
        assert!(!prepare_inbound(&mut packet, addresses()));
        assert_eq!(packet, original);
    }

    #[test]
    fn excludes_our_own_tunnel_datagrams_from_capture() {
        let server: SocketAddr = "203.0.113.10:51820".parse().expect("address");
        let filter = filter(server);
        // Without this exclusion every datagram we send would be recaptured.
        assert!(filter.contains("203.0.113.10"));
        assert!(filter.contains("51820"));
        assert!(filter.contains("outbound"));
        assert!(filter.contains("!loopback"));
    }

    #[test]
    fn derives_the_segment_limit_from_the_tunnel_mtu() {
        // 1280 less twenty bytes of IPv4 header and twenty of TCP.
        assert_eq!(addresses().max_segment_size, 1240);
        // A nonsensically small MTU must not wrap around into a huge limit.
        assert_eq!(
            Translation::new(PHYSICAL, TUNNEL, RESOLVER, 8).max_segment_size,
            0
        );
    }

    #[test]
    fn tunnels_name_resolution_whatever_the_policy_says() {
        // Windows resolves through a shared service, so the query carries no
        // trace of which application wanted the name. An unclassified flow to
        // the session's resolver still has to take the tunnel: the resolver
        // exists nowhere else.
        let mut packet = udp_packet(PHYSICAL, RESOLVER);
        packet[22..24].copy_from_slice(&53_u16.to_be_bytes());
        assert_eq!(
            prepare_outbound(&mut packet, &FlowTable::default(), addresses()),
            Outcome::Tunnel
        );
        assert_eq!(&packet[12..16], &[10, 77, 0, 22]);
    }

    #[test]
    fn leaves_other_traffic_to_the_resolver_alone() {
        // Only port 53 is name resolution. The resolver may run other services
        // and an unclassified flow to one of them is not ours to redirect.
        let mut packet = udp_packet(PHYSICAL, RESOLVER);
        packet[22..24].copy_from_slice(&443_u16.to_be_bytes());
        assert_eq!(
            prepare_outbound(&mut packet, &FlowTable::default(), addresses()),
            Outcome::PassThrough
        );
    }

    #[test]
    fn discards_a_routed_flow_it_cannot_translate() {
        // An IPv6 flow of a routed application has no tunnel address to take.
        // Handing it back would put protected traffic on the physical link.
        let mut packet = vec![0_u8; 60];
        packet[0] = 0x60;
        packet[6] = PROTOCOL_UDP;
        packet[8..24].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        packet[24..40].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        packet[40..42].copy_from_slice(&54_518_u16.to_be_bytes());
        packet[42..44].copy_from_slice(&53_u16.to_be_bytes());

        let table = FlowTable::default();
        table.insert_for_test(
            FlowKey {
                protocol: PROTOCOL_UDP,
                local: IpAddr::V6(Ipv6Addr::LOCALHOST),
                local_port: 54_518,
                remote: IpAddr::V6(Ipv6Addr::LOCALHOST),
                remote_port: 53,
            },
            Disposition::Tunnel,
        );
        assert_eq!(
            prepare_outbound(&mut packet, &table, addresses()),
            Outcome::Discard
        );
    }

    #[test]
    fn never_negates_a_parenthesised_group() {
        // WinDivert negates a single test, not a group, and reports the
        // difference only as ERROR_INVALID_PARAMETER from WinDivertOpen. Both
        // spellings of negation are checked so neither creeps back in.
        for server in ["203.0.113.10:51820", "[2001:db8::1]:51820"] {
            let filter = filter(server.parse().expect("address"));
            assert!(!filter.contains("not ("), "{filter}");
            assert!(!filter.contains("!("), "{filter}");
        }
    }

    #[test]
    fn keeps_the_tunnel_exclusion_scoped_to_udp() {
        // Hoisting the address test out of the udp branch would exclude TCP to
        // the server as well, and silently stop tunnelling it.
        let server: SocketAddr = "203.0.113.10:51820".parse().expect("address");
        let filter = filter(server);
        let udp_branch = filter.split("tcp or ").nth(1).expect("udp branch");
        assert!(udp_branch.contains("203.0.113.10"));
    }
}
