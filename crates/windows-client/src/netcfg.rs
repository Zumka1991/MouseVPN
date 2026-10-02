#![doc = "Native Windows interface, address and route configuration."]

use std::{
    ffi::c_void,
    mem,
    net::{Ipv4Addr, Ipv6Addr},
    os::windows::process::CommandExt,
    process::Command,
    ptr, thread,
    time::{Duration, Instant},
};

use windows_sys::Win32::{
    NetworkManagement::{
        IpHelper::{
            ConvertInterfaceAliasToLuid, ConvertInterfaceLuidToAlias, ConvertInterfaceLuidToIndex,
            CreateIpForwardEntry2, CreateUnicastIpAddressEntry, DeleteIpForwardEntry2,
            DeleteUnicastIpAddressEntry, FreeMibTable, GetBestRoute2, GetIpForwardTable2,
            GetIpInterfaceEntry, GetUnicastIpAddressTable, InitializeIpForwardEntry,
            InitializeUnicastIpAddressEntry, SetIpInterfaceEntry, MIB_IPFORWARD_ROW2,
            MIB_IPFORWARD_TABLE2, MIB_IPINTERFACE_ROW, MIB_UNICASTIPADDRESS_ROW,
            MIB_UNICASTIPADDRESS_TABLE,
        },
        Ndis::NET_LUID_LH,
    },
    Networking::WinSock::{
        IpDadStatePreferred, AF_INET, AF_INET6, IN6_ADDR, IN6_ADDR_0, IN_ADDR, IN_ADDR_0,
        MIB_IPPROTO_NETMGMT, SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_IN6_0, SOCKADDR_INET,
    },
};

use crate::ClientError;

const ERROR_SUCCESS: u32 = 0;
const ERROR_FILE_NOT_FOUND: u32 = 2;
const ERROR_NOT_FOUND: u32 = 1168;
const ERROR_OBJECT_ALREADY_EXISTS: u32 = 5010;
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// How long to let Windows attach IPv4 to a newly created tunnel interface.
const INTERFACE_READY_TIMEOUT: Duration = Duration::from_secs(5);
const INTERFACE_READY_POLL: Duration = Duration::from_millis(25);

/// Reports whether a delete already had nothing to delete.
const fn already_gone(status: u32) -> bool {
    status == ERROR_NOT_FOUND || status == ERROR_FILE_NOT_FOUND
}

/// Route metric shared by every route `MouseVPN` installs, so cleanup can
/// recognise its own routes without consulting a journal.
pub(crate) const ROUTE_METRIC: u32 = 4242;
/// Interface metric for the tunnel. It has to beat every physical interface so
/// the two half-default routes win against the physical default route.
const TUNNEL_INTERFACE_METRIC: u32 = 1;

/// The physical addresses the split-tunnel WFP callouts bind excluded
/// applications to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PhysicalAddresses {
    pub(crate) ipv4: Ipv4Addr,
    pub(crate) ipv6: Option<Ipv6Addr>,
}

/// The physical IPv4 default route the tunnel endpoint has to keep using.
#[derive(Clone, Copy)]
pub(crate) struct DefaultRoute {
    pub(crate) interface_luid: NET_LUID_LH,
    pub(crate) interface_index: u32,
    pub(crate) next_hop: Ipv4Addr,
}

/// One IPv4 route `MouseVPN` owns, for verification and cleanup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OwnedRoute {
    pub(crate) destination: Ipv4Addr,
    pub(crate) prefix_len: u8,
    pub(crate) interface_index: u32,
    pub(crate) next_hop: Ipv4Addr,
}

/// Resolves an interface alias to its LUID.
///
/// # Errors
///
/// Returns an error when Windows has no interface with that alias.
pub(crate) fn interface_luid(alias: &str) -> Result<NET_LUID_LH, ClientError> {
    let alias = alias
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut luid: NET_LUID_LH = unsafe { mem::zeroed() };
    let status = unsafe { ConvertInterfaceAliasToLuid(alias.as_ptr(), &raw mut luid) };
    if status == ERROR_SUCCESS {
        Ok(luid)
    } else {
        Err(win32_error("resolve the MouseVPN interface", status))
    }
}

/// Reports whether an interface with this alias currently exists.
pub(crate) fn interface_exists(alias: &str) -> bool {
    interface_luid(alias).is_ok()
}

/// Resolves a LUID to the interface index Windows uses in route entries.
///
/// # Errors
///
/// Returns an error when the interface has disappeared.
pub(crate) fn interface_index(luid: NET_LUID_LH) -> Result<u32, ClientError> {
    let mut index = 0_u32;
    let status = unsafe { ConvertInterfaceLuidToIndex(&raw const luid, &raw mut index) };
    if status == ERROR_SUCCESS {
        Ok(index)
    } else {
        Err(win32_error("resolve the MouseVPN interface index", status))
    }
}

/// Resolves a LUID to the interface name `netsh` expects.
///
/// # Errors
///
/// Returns an error when the interface has disappeared or its name does not
/// fit the buffer Windows documents as sufficient.
pub(crate) fn interface_alias(luid: NET_LUID_LH) -> Result<String, ClientError> {
    // NDIS_IF_MAX_STRING_SIZE plus the terminator, which Windows documents as
    // enough for any interface alias.
    let mut buffer = [0_u16; 257];
    let status =
        unsafe { ConvertInterfaceLuidToAlias(&raw const luid, buffer.as_mut_ptr(), buffer.len()) };
    if status != ERROR_SUCCESS {
        return Err(win32_error("resolve the interface name", status));
    }
    let length = buffer.iter().position(|value| *value == 0).unwrap_or(0);
    Ok(String::from_utf16_lossy(&buffer[..length]))
}

/// Finds the physical IPv4 default route the tunnel must not displace.
///
/// This mirrors what the old PowerShell pipeline selected: the lowest-metric
/// `0.0.0.0/0` route with a real next hop that does not live on the tunnel.
///
/// # Errors
///
/// Returns an error when the route table cannot be read or the machine has no
/// usable physical default route.
pub(crate) fn default_ipv4_route(tunnel: Option<NET_LUID_LH>) -> Result<DefaultRoute, ClientError> {
    let tunnel = tunnel.map(luid_value);
    let mut table: *mut MIB_IPFORWARD_TABLE2 = ptr::null_mut();
    let status = unsafe { GetIpForwardTable2(AF_INET, &raw mut table) };
    if status != ERROR_SUCCESS {
        return Err(win32_error("read the Windows IPv4 route table", status));
    }
    let mut best: Option<(u32, DefaultRoute)> = None;
    for row in unsafe { forward_rows(table) } {
        if row.DestinationPrefix.PrefixLength != 0 {
            continue;
        }
        let next_hop = unsafe { ipv4_from_sockaddr(&row.NextHop) };
        if next_hop.is_unspecified() || tunnel == Some(luid_value(row.InterfaceLuid)) {
            continue;
        }
        let better = match &best {
            Some((metric, _)) => row.Metric < *metric,
            None => true,
        };
        if better {
            best = Some((
                row.Metric,
                DefaultRoute {
                    interface_luid: row.InterfaceLuid,
                    interface_index: row.InterfaceIndex,
                    next_hop,
                },
            ));
        }
    }
    unsafe {
        FreeMibTable(table.cast::<c_void>());
    }
    best.map(|(_, route)| route).ok_or_else(|| {
        ClientError::Platform("No active physical IPv4 default route found".to_owned())
    })
}

/// Reports the source addresses Windows would pick for traffic that bypasses
/// the tunnel.
///
/// # Errors
///
/// Returns an error when there is no physical default route or no preferred
/// source address on it.
pub(crate) fn physical_addresses(
    tunnel: Option<NET_LUID_LH>,
) -> Result<PhysicalAddresses, ClientError> {
    let route = default_ipv4_route(tunnel)?;
    let ipv4 = best_source_address_v4(route.interface_luid, route.next_hop).ok_or_else(|| {
        ClientError::Platform("No preferred physical IPv4 address found".to_owned())
    })?;
    Ok(PhysicalAddresses {
        ipv4,
        ipv6: best_source_address_v6(tunnel.map(luid_value)),
    })
}

fn best_source_address_v4(luid: NET_LUID_LH, destination: Ipv4Addr) -> Option<Ipv4Addr> {
    let destination = sockaddr_v4(destination);
    let mut route: MIB_IPFORWARD_ROW2 = unsafe { mem::zeroed() };
    let mut source: SOCKADDR_INET = unsafe { mem::zeroed() };
    let status = unsafe {
        GetBestRoute2(
            &raw const luid,
            0,
            ptr::null(),
            &raw const destination,
            0,
            &raw mut route,
            &raw mut source,
        )
    };
    if status != ERROR_SUCCESS {
        return None;
    }
    let address = unsafe { ipv4_from_sockaddr(&source) };
    (!address.is_unspecified()).then_some(address)
}

fn best_source_address_v6(tunnel: Option<u64>) -> Option<Ipv6Addr> {
    // Any global unicast destination is enough to make Windows run its own
    // source address selection over the physical IPv6 default route.
    let destination = sockaddr_v6(Ipv6Addr::new(0x2000, 0, 0, 0, 0, 0, 0, 0));
    let mut route: MIB_IPFORWARD_ROW2 = unsafe { mem::zeroed() };
    let mut source: SOCKADDR_INET = unsafe { mem::zeroed() };
    let status = unsafe {
        GetBestRoute2(
            ptr::null(),
            0,
            ptr::null(),
            &raw const destination,
            0,
            &raw mut route,
            &raw mut source,
        )
    };
    if status != ERROR_SUCCESS {
        return None;
    }
    if tunnel == Some(luid_value(route.InterfaceLuid)) {
        return None;
    }
    let address = unsafe { ipv6_from_sockaddr(&source) };
    if address.is_unspecified() || is_link_local_v6(address) {
        return None;
    }
    Some(address)
}

fn is_link_local_v6(address: Ipv6Addr) -> bool {
    let octets = address.octets();
    octets[0] == 0xfe && octets[1] & 0xc0 == 0x80
}

/// Replaces every IPv4 address on the tunnel with the negotiated one.
///
/// Duplicate address detection is skipped: the address comes from the server's
/// own pool, and waiting for DAD adds a visible stall to every connection.
///
/// # Errors
///
/// Returns an error when Windows rejects the address change.
pub(crate) fn set_tunnel_address(
    luid: NET_LUID_LH,
    address: Ipv4Addr,
    prefix_len: u8,
) -> Result<(), ClientError> {
    clear_addresses(luid)?;
    let mut row: MIB_UNICASTIPADDRESS_ROW = unsafe { mem::zeroed() };
    unsafe {
        InitializeUnicastIpAddressEntry(&raw mut row);
    }
    row.InterfaceLuid = luid;
    row.Address = sockaddr_v4(address);
    row.OnLinkPrefixLength = prefix_len;
    row.DadState = IpDadStatePreferred;
    let status = unsafe { CreateUnicastIpAddressEntry(&raw const row) };
    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(win32_error("assign the MouseVPN tunnel address", status))
    }
}

/// Removes every IPv4 address currently bound to the interface.
///
/// # Errors
///
/// Returns the first removal failure after attempting all of them.
pub(crate) fn clear_addresses(luid: NET_LUID_LH) -> Result<(), ClientError> {
    let mut table: *mut MIB_UNICASTIPADDRESS_TABLE = ptr::null_mut();
    let status = unsafe { GetUnicastIpAddressTable(AF_INET, &raw mut table) };
    if status != ERROR_SUCCESS {
        return Err(win32_error("read the Windows IPv4 address table", status));
    }
    let mut failure = None;
    for row in unsafe { unicast_rows(table) } {
        if !same_luid(luid, row.InterfaceLuid) {
            continue;
        }
        let status = unsafe { DeleteUnicastIpAddressEntry(ptr::from_ref(row)) };
        if status != ERROR_SUCCESS && !already_gone(status) && failure.is_none() {
            failure = Some(win32_error("remove a stale MouseVPN address", status));
        }
    }
    unsafe {
        FreeMibTable(table.cast::<c_void>());
    }
    failure.map_or(Ok(()), Err)
}

/// Reports whether the IPv4 stack is currently bound to this interface.
///
/// Windows unbinds IPv4 before the device itself disappears, so an interface
/// can still be present by alias while none of its IPv4 settings exist any
/// more. Cleanup uses this to tell "already undone" apart from a real failure.
pub(crate) fn has_ipv4_binding(luid: NET_LUID_LH) -> bool {
    let mut row: MIB_IPINTERFACE_ROW = unsafe { mem::zeroed() };
    row.Family = AF_INET;
    row.InterfaceLuid = luid;
    unsafe { GetIpInterfaceEntry(&raw mut row) == ERROR_SUCCESS }
}

/// Waits for Windows to finish binding IPv4 to a freshly created interface.
///
/// Wintun hands back the adapter before the IP stack has attached to it, and
/// every address, metric and route call below fails with `ERROR_NOT_FOUND`
/// until it has. In the normal case the first poll already succeeds.
///
/// # Errors
///
/// Returns an error when the binding does not appear within
/// [`INTERFACE_READY_TIMEOUT`], or when Windows reports anything other than a
/// missing interface.
pub(crate) fn wait_for_ipv4_interface(luid: NET_LUID_LH) -> Result<(), ClientError> {
    let deadline = Instant::now() + INTERFACE_READY_TIMEOUT;
    loop {
        let mut row: MIB_IPINTERFACE_ROW = unsafe { mem::zeroed() };
        row.Family = AF_INET;
        row.InterfaceLuid = luid;
        let status = unsafe { GetIpInterfaceEntry(&raw mut row) };
        if status == ERROR_SUCCESS {
            return Ok(());
        }
        if status != ERROR_NOT_FOUND || Instant::now() >= deadline {
            return Err(win32_error(
                "wait for the MouseVPN interface to accept IPv4",
                status,
            ));
        }
        thread::sleep(INTERFACE_READY_POLL);
    }
}

/// Pins the tunnel interface metric so its half-default routes win.
///
/// # Errors
///
/// Returns an error when Windows rejects the interface write.
pub(crate) fn set_tunnel_metric(luid: NET_LUID_LH) -> Result<(), ClientError> {
    update_interface(luid, |row| {
        row.UseAutomaticMetric = false;
        row.Metric = TUNNEL_INTERFACE_METRIC;
    })
}

/// Hands the interface metric back to Windows.
///
/// # Errors
///
/// Returns an error when Windows rejects the interface write.
pub(crate) fn reset_tunnel_metric(luid: NET_LUID_LH) -> Result<(), ClientError> {
    update_interface(luid, |row| {
        row.UseAutomaticMetric = true;
    })
}

fn update_interface(
    luid: NET_LUID_LH,
    edit: impl FnOnce(&mut MIB_IPINTERFACE_ROW),
) -> Result<(), ClientError> {
    let mut row: MIB_IPINTERFACE_ROW = unsafe { mem::zeroed() };
    row.Family = AF_INET;
    row.InterfaceLuid = luid;
    let status = unsafe { GetIpInterfaceEntry(&raw mut row) };
    if status != ERROR_SUCCESS {
        return Err(win32_error("read the MouseVPN interface entry", status));
    }
    edit(&mut row);
    // Windows rejects an IPv4 interface write that still carries a site prefix.
    row.SitePrefixLength = 0;
    let status = unsafe { SetIpInterfaceEntry(&raw mut row) };
    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(win32_error("update the MouseVPN interface entry", status))
    }
}

/// Adds one `MouseVPN` IPv4 route.
///
/// # Errors
///
/// Returns an error when Windows rejects the route.
pub(crate) fn add_route(
    luid: NET_LUID_LH,
    destination: Ipv4Addr,
    prefix_len: u8,
    next_hop: Ipv4Addr,
) -> Result<(), ClientError> {
    let mut row: MIB_IPFORWARD_ROW2 = unsafe { mem::zeroed() };
    unsafe {
        InitializeIpForwardEntry(&raw mut row);
    }
    row.InterfaceLuid = luid;
    row.DestinationPrefix.Prefix = sockaddr_v4(destination);
    row.DestinationPrefix.PrefixLength = prefix_len;
    row.NextHop = sockaddr_v4(next_hop);
    row.Metric = ROUTE_METRIC;
    row.Protocol = MIB_IPPROTO_NETMGMT;
    let status = unsafe { CreateIpForwardEntry2(&raw const row) };
    // An identical route already being present is the outcome we wanted. This
    // happens when a previous cleanup could not finish.
    if status == ERROR_SUCCESS || status == ERROR_OBJECT_ALREADY_EXISTS {
        Ok(())
    } else {
        Err(win32_error(
            &format!("add the {destination}/{prefix_len} route"),
            status,
        ))
    }
}

/// Lists every IPv4 route carrying the `MouseVPN` metric and protocol.
///
/// # Errors
///
/// Returns an error when the route table cannot be read.
pub(crate) fn owned_routes() -> Result<Vec<OwnedRoute>, ClientError> {
    let mut table: *mut MIB_IPFORWARD_TABLE2 = ptr::null_mut();
    let status = unsafe { GetIpForwardTable2(AF_INET, &raw mut table) };
    if status != ERROR_SUCCESS {
        return Err(win32_error("read the Windows IPv4 route table", status));
    }
    let routes = unsafe { forward_rows(table) }
        .iter()
        .filter(|row| row.Metric == ROUTE_METRIC && row.Protocol == MIB_IPPROTO_NETMGMT)
        .map(|row| unsafe { owned_route(row) })
        .collect();
    unsafe {
        FreeMibTable(table.cast::<c_void>());
    }
    Ok(routes)
}

/// Removes every `MouseVPN` IPv4 route the predicate selects.
///
/// # Errors
///
/// Returns the first removal failure after attempting all of them.
pub(crate) fn remove_owned_routes(
    selected: impl Fn(&OwnedRoute) -> bool,
) -> Result<(), ClientError> {
    let mut table: *mut MIB_IPFORWARD_TABLE2 = ptr::null_mut();
    let status = unsafe { GetIpForwardTable2(AF_INET, &raw mut table) };
    if status != ERROR_SUCCESS {
        return Err(win32_error("read the Windows IPv4 route table", status));
    }
    let mut failure = None;
    for row in unsafe { forward_rows(table) } {
        if row.Metric != ROUTE_METRIC || row.Protocol != MIB_IPPROTO_NETMGMT {
            continue;
        }
        let owned = unsafe { owned_route(row) };
        if !selected(&owned) {
            continue;
        }
        let status = unsafe { DeleteIpForwardEntry2(ptr::from_ref(row)) };
        if status != ERROR_SUCCESS && !already_gone(status) && failure.is_none() {
            failure = Some(win32_error("remove a MouseVPN route", status));
        }
    }
    unsafe {
        FreeMibTable(table.cast::<c_void>());
    }
    failure.map_or(Ok(()), Err)
}

/// Points the tunnel interface at the server-provided resolver.
///
/// `netsh` is used rather than `SetInterfaceDnsSettings` so the client keeps
/// working on Windows builds older than 10 2004. It is a native binary and
/// costs about a tenth of a second, unlike the DNS client PowerShell module.
/// `validate=no` matters: without it netsh probes the resolver before applying
/// the change, which blocks until the tunnel it is configuring already works.
///
/// # Errors
///
/// Returns an error when netsh rejects the change.
pub(crate) fn set_tunnel_dns(alias: &str, server: Ipv4Addr) -> Result<(), ClientError> {
    run_netsh(
        &[
            "interface",
            "ipv4",
            "set",
            "dnsservers",
            &format!("name={alias}"),
            "source=static",
            &format!("address={server}"),
            "register=none",
            "validate=no",
        ],
        "set the MouseVPN DNS server",
    )
}

/// Hands DNS on the tunnel interface back to DHCP.
///
/// # Errors
///
/// Returns an error when netsh rejects the change.
pub(crate) fn reset_tunnel_dns(alias: &str) -> Result<(), ClientError> {
    run_netsh(
        &[
            "interface",
            "ipv4",
            "set",
            "dnsservers",
            &format!("name={alias}"),
            "source=dhcp",
            "register=none",
            "validate=no",
        ],
        "restore the DNS configuration",
    )
}

fn run_netsh(arguments: &[&str], operation: &str) -> Result<(), ClientError> {
    let mut command = Command::new("netsh.exe");
    command.creation_flags(CREATE_NO_WINDOW);
    let output = command.args(arguments).output()?;
    if output.status.success() {
        return Ok(());
    }
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    let details = if stderr.is_empty() { stdout } else { stderr };
    Err(ClientError::Platform(format!(
        "failed to {operation}: {details}"
    )))
}

unsafe fn owned_route(row: &MIB_IPFORWARD_ROW2) -> OwnedRoute {
    OwnedRoute {
        destination: unsafe { ipv4_from_sockaddr(&row.DestinationPrefix.Prefix) },
        prefix_len: row.DestinationPrefix.PrefixLength,
        interface_index: row.InterfaceIndex,
        next_hop: unsafe { ipv4_from_sockaddr(&row.NextHop) },
    }
}

unsafe fn forward_rows<'table>(table: *const MIB_IPFORWARD_TABLE2) -> &'table [MIB_IPFORWARD_ROW2] {
    if table.is_null() {
        return &[];
    }
    unsafe {
        std::slice::from_raw_parts(
            (*table).Table.as_ptr(),
            usize::try_from((*table).NumEntries).unwrap_or(0),
        )
    }
}

unsafe fn unicast_rows<'table>(
    table: *const MIB_UNICASTIPADDRESS_TABLE,
) -> &'table [MIB_UNICASTIPADDRESS_ROW] {
    if table.is_null() {
        return &[];
    }
    unsafe {
        std::slice::from_raw_parts(
            (*table).Table.as_ptr(),
            usize::try_from((*table).NumEntries).unwrap_or(0),
        )
    }
}

fn luid_value(luid: NET_LUID_LH) -> u64 {
    unsafe { luid.Value }
}

fn same_luid(left: NET_LUID_LH, right: NET_LUID_LH) -> bool {
    luid_value(left) == luid_value(right)
}

fn sockaddr_v4(address: Ipv4Addr) -> SOCKADDR_INET {
    let mut value: SOCKADDR_INET = unsafe { mem::zeroed() };
    value.Ipv4 = SOCKADDR_IN {
        sin_family: AF_INET,
        sin_port: 0,
        sin_addr: IN_ADDR {
            S_un: IN_ADDR_0 {
                S_addr: u32::from_ne_bytes(address.octets()),
            },
        },
        sin_zero: [0; 8],
    };
    value
}

fn sockaddr_v6(address: Ipv6Addr) -> SOCKADDR_INET {
    let mut value: SOCKADDR_INET = unsafe { mem::zeroed() };
    value.Ipv6 = SOCKADDR_IN6 {
        sin6_family: AF_INET6,
        sin6_port: 0,
        sin6_flowinfo: 0,
        sin6_addr: IN6_ADDR {
            u: IN6_ADDR_0 {
                Byte: address.octets(),
            },
        },
        Anonymous: SOCKADDR_IN6_0 { sin6_scope_id: 0 },
    };
    value
}

unsafe fn ipv4_from_sockaddr(value: &SOCKADDR_INET) -> Ipv4Addr {
    Ipv4Addr::from(unsafe { value.Ipv4.sin_addr.S_un.S_addr }.to_ne_bytes())
}

unsafe fn ipv6_from_sockaddr(value: &SOCKADDR_INET) -> Ipv6Addr {
    Ipv6Addr::from(unsafe { value.Ipv6.sin6_addr.u.Byte })
}

fn win32_error(operation: &str, code: u32) -> ClientError {
    ClientError::Platform(format!("failed to {operation}: Windows error {code}"))
}

#[cfg(test)]
mod tests {
    use super::{
        ipv4_from_sockaddr, ipv6_from_sockaddr, is_link_local_v6, sockaddr_v4, sockaddr_v6,
    };
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn round_trips_an_ipv4_sockaddr() {
        let address = Ipv4Addr::new(10, 8, 0, 7);
        assert_eq!(
            unsafe { ipv4_from_sockaddr(&sockaddr_v4(address)) },
            address
        );
    }

    #[test]
    fn round_trips_an_ipv6_sockaddr() {
        let address: Ipv6Addr = "2001:db8::1".parse().expect("address");
        assert_eq!(
            unsafe { ipv6_from_sockaddr(&sockaddr_v6(address)) },
            address
        );
    }

    #[test]
    fn recognizes_link_local_ipv6_addresses() {
        assert!(is_link_local_v6("fe80::1".parse().expect("address")));
        assert!(!is_link_local_v6("2001:db8::1".parse().expect("address")));
    }
}
