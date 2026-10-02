use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    net::Ipv4Addr,
    os::windows::process::CommandExt,
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, Mutex},
};

use fs2::FileExt;
use mousevpn_protocol::SessionParameters;
use serde::{Deserialize, Serialize};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;

use crate::{
    app_bypass::{AppBypassGuard, AppBypassRefresher},
    killswitch::KillSwitch,
    netcfg::{self, OwnedRoute},
    AppRoutingMode, AppRoutingPolicy, ClientError,
};

pub(crate) use crate::netcfg::PhysicalAddresses;

pub(crate) const ADAPTER_NAME: &str = "MouseVPN";
/// Fixed device GUID for the Wintun interface.
///
/// Wintun deletes the adapter when the last handle closes, so every connection
/// creates it again. Reusing one GUID makes Windows reuse the same device
/// instance and its cached network profile instead of classifying a brand new
/// "Network N" each time, which both speeds the interface up and stops the
/// profile list from growing without bound.
pub(crate) const ADAPTER_GUID: u128 = 0x53a1_e2c4_7b90_4d6e_9f31_08c5_a4b7_d260;
const FIREWALL_GROUP: &str = "MouseVPN Kill Switch";
const STATE_FILE: &str = "network-state.toml";
/// Records that the tunnel's network profile has already been marked Public.
/// It holds the adapter GUID it was applied to, so changing [`ADAPTER_GUID`]
/// re-applies the category to the new profile.
const CATEGORY_MARKER: &str = "network-category.marker";
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// The two halves of the default route the tunnel installs. Two `/1` routes
/// beat a physical `0.0.0.0/0` on prefix length without replacing it, so the
/// original default route survives for the tunnel endpoint itself.
const TUNNEL_HALVES: [Ipv4Addr; 2] = [Ipv4Addr::UNSPECIFIED, Ipv4Addr::new(128, 0, 0, 0)];

pub(crate) struct RuntimeLock {
    _file: File,
}

impl RuntimeLock {
    pub(crate) fn acquire() -> Result<Self, ClientError> {
        let directory = runtime_dir()?;
        fs::create_dir_all(&directory)?;
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(directory.join("runtime.lock"))?;
        file.try_lock_exclusive().map_err(|error| {
            if error.kind() == io::ErrorKind::WouldBlock {
                ClientError::Platform(
                    "another MouseVPN Windows helper is already running".to_owned(),
                )
            } else {
                error.into()
            }
        })?;
        Ok(Self { _file: file })
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct RecoveryState {
    server_ip: Ipv4Addr,
    /// Whether this session created Windows Firewall rules. The full tunnel
    /// keeps its kill switch in WFP, where it disappears with the process, so
    /// recovery can skip the firewall cleanup entirely. Defaults to true so a
    /// journal written by an older build is still cleaned up properly.
    #[serde(default = "yes")]
    firewall_rules: bool,
}

const fn yes() -> bool {
    true
}

pub(crate) struct NetworkGuard {
    state: RecoveryState,
    state_path: PathBuf,
    refresh_lock: Arc<Mutex<()>>,
    app_routing: AppRoutingPolicy,
    app_bypass: Option<AppBypassGuard>,
    /// Present for the full tunnel, where the kill switch lives in WFP. The
    /// allowlist edition still needs per-application Windows Firewall rules,
    /// and leaves this empty.
    kill_switch: Option<KillSwitch>,
    parameters: SessionParameters,
}

#[derive(Clone)]
pub(crate) struct NetworkRefresher {
    server_ip: Ipv4Addr,
    refresh_lock: Arc<Mutex<()>>,
    app_routing: AppRoutingPolicy,
    app_bypass: Option<AppBypassRefresher>,
    /// WFP filters live for as long as the session handle, so there is nothing
    /// for a refresh to re-create.
    kill_switch_is_dynamic: bool,
}

impl NetworkGuard {
    pub(crate) fn install(
        server_ip: Ipv4Addr,
        server_port: u16,
        parameters: SessionParameters,
        app_routing: &AppRoutingPolicy,
        app_bypass: Option<AppBypassGuard>,
    ) -> Result<Self, ClientError> {
        let state_path = state_path()?;
        // Journal first, and pessimistically: if the machine loses power midway
        // through the install, recovery has to assume firewall rules exist.
        let mut state = RecoveryState {
            server_ip,
            firewall_rules: true,
        };
        write_state(&state_path, &state)?;
        let kill_switch = match install_policy(server_ip, parameters, app_routing) {
            Ok(kill_switch) => kill_switch,
            Err(error) => {
                if cleanup(true).is_ok() {
                    let _ = fs::remove_file(&state_path);
                }
                return Err(error);
            }
        };
        state.firewall_rules = kill_switch.is_none();
        write_state(&state_path, &state)?;
        eprintln!("MOUSEVPN_POLICY=installed for {server_ip}:{server_port}");
        harden_network_category();
        Ok(Self {
            state,
            state_path,
            refresh_lock: Arc::new(Mutex::new(())),
            app_routing: app_routing.clone(),
            app_bypass,
            kill_switch,
            parameters,
        })
    }

    pub(crate) fn update_parameters(
        &mut self,
        parameters: SessionParameters,
    ) -> Result<(), ClientError> {
        if parameters == self.parameters {
            return Ok(());
        }
        let _guard = self.refresh_lock.lock().map_err(|_| {
            ClientError::Platform("Windows network policy refresh lock was poisoned".to_owned())
        })?;
        let tunnel = netcfg::interface_luid(ADAPTER_NAME)?;
        let previous = self.parameters;
        if let Err(error) = apply_parameters(tunnel, parameters) {
            // Fall back to what the tunnel was already using so the interface
            // never sits without an address, then report the original failure.
            apply_parameters(tunnel, previous)?;
            return Err(ClientError::Platform(format!(
                "updating MouseVPN session parameters failed: {error}"
            )));
        }
        self.parameters = parameters;
        Ok(())
    }

    pub(crate) fn refresh(&self) -> Result<(), ClientError> {
        self.refresher().refresh()
    }

    pub(crate) fn refresher(&self) -> NetworkRefresher {
        NetworkRefresher {
            server_ip: self.state.server_ip,
            refresh_lock: Arc::clone(&self.refresh_lock),
            app_routing: self.app_routing.clone(),
            app_bypass: self.app_bypass.as_ref().map(AppBypassGuard::refresher),
            kill_switch_is_dynamic: self.kill_switch.is_some(),
        }
    }
}

impl NetworkRefresher {
    pub(crate) fn refresh(&self) -> Result<(), ClientError> {
        let _guard = self.refresh_lock.lock().map_err(|_| {
            ClientError::Platform("Windows network policy refresh lock was poisoned".to_owned())
        })?;
        let tunnel = netcfg::interface_luid(ADAPTER_NAME)?;
        repair_routes(tunnel, self.server_ip)?;
        if !self.kill_switch_is_dynamic {
            run_powershell(
                &refresh_script(self.server_ip, &self.app_routing),
                "refresh the Windows network policy",
            )?;
        }
        if let Some(app_bypass) = &self.app_bypass {
            app_bypass.refresh()?;
        }
        Ok(())
    }
}

fn install_policy(
    server_ip: Ipv4Addr,
    parameters: SessionParameters,
    app_routing: &AppRoutingPolicy,
) -> Result<Option<KillSwitch>, ClientError> {
    let tunnel = netcfg::interface_luid(ADAPTER_NAME)?;
    // Wintun returns the adapter before Windows has attached IPv4 to it, and
    // every address, metric and route call below needs that binding.
    netcfg::wait_for_ipv4_interface(tunnel)?;
    // The kill switch has to be in place before the default route moves, or
    // traffic leaks over the physical interface during the switchover.
    let kill_switch = match app_routing.mode {
        AppRoutingMode::Exclude => match KillSwitch::install(server_ip, tunnel) {
            Ok(kill_switch) => Some(kill_switch),
            Err(error) => {
                // Never trade the kill switch for speed. If this machine's WFP
                // stack will not take the filters, fall back to the Windows
                // Firewall rules: slower to install, but the tunnel is still
                // fenced in.
                eprintln!(
                    "MOUSEVPN_POLICY_WARNING=WFP kill switch unavailable, using Windows Firewall instead: {error}"
                );
                run_powershell(
                    &install_script(server_ip, app_routing),
                    "install the Windows kill switch",
                )?;
                None
            }
        },
        // The allowlist edition blocks per application and per service rather
        // than globally, which Windows Firewall can express and a single WFP
        // interface condition cannot.
        AppRoutingMode::Include => {
            run_powershell(
                &install_script(server_ip, app_routing),
                "install the Windows kill switch",
            )?;
            None
        }
    };
    let default = netcfg::default_ipv4_route(Some(tunnel))?;
    apply_parameters(tunnel, parameters)?;
    netcfg::set_tunnel_metric(tunnel)?;
    netcfg::add_route(default.interface_luid, server_ip, 32, default.next_hop)?;
    for destination in TUNNEL_HALVES {
        netcfg::add_route(tunnel, destination, 1, Ipv4Addr::UNSPECIFIED)?;
    }
    Ok(kill_switch)
}

/// Marks the tunnel as a Public network so Windows applies its stricter
/// built-in inbound rules to it.
///
/// This runs detached: it needs the Network Location Awareness service to have
/// classified the brand new interface, which it has usually not done yet, and
/// nothing about the tunnel depends on the outcome.
///
/// It also runs at most once per machine. Windows remembers the category
/// against the network profile, and the tunnel now uses a fixed device GUID, so
/// the same profile comes back on every connection. Re-applying it would put a
/// PowerShell start-up — and the console window that flashes with it — on a
/// connection path that otherwise has none.
fn harden_network_category() {
    let Ok(marker) = runtime_dir().map(|directory| directory.join(CATEGORY_MARKER)) else {
        return;
    };
    let applied = format!("{ADAPTER_GUID:032x}");
    if fs::read_to_string(&marker).is_ok_and(|contents| contents.trim() == applied) {
        return;
    }
    std::thread::spawn(move || {
        let script = format!(
            "$vpn=Get-NetAdapter -Name '{ADAPTER_NAME}' -ErrorAction SilentlyContinue; \
             if ($vpn) {{ \
               $profile=Get-NetConnectionProfile -InterfaceIndex $vpn.ifIndex -ErrorAction SilentlyContinue; \
               if ($profile -and $profile.NetworkCategory -ne 'Public') {{ \
                 Set-NetConnectionProfile -InterfaceIndex $vpn.ifIndex -NetworkCategory Public -ErrorAction SilentlyContinue \
               }} \
             }}; \
             exit 0"
        );
        match run_powershell(&script, "mark MouseVPN as a Public network") {
            Ok(()) => {
                let _ = fs::write(&marker, applied);
            }
            Err(error) => eprintln!("MOUSEVPN_POLICY_WARNING={error}"),
        }
    });
}

fn apply_parameters(tunnel: NET_LUID_LH, parameters: SessionParameters) -> Result<(), ClientError> {
    netcfg::set_tunnel_address(tunnel, parameters.client_address, parameters.prefix_len)?;
    netcfg::set_tunnel_dns(ADAPTER_NAME, parameters.dns)
}

/// Restores any route the tunnel owns that roaming or another VPN removed.
fn repair_routes(tunnel: NET_LUID_LH, server_ip: Ipv4Addr) -> Result<(), ClientError> {
    let tunnel_index = netcfg::interface_index(tunnel)?;
    let default = netcfg::default_ipv4_route(Some(tunnel))?;
    let routes = netcfg::owned_routes()?;

    if server_route_is_stale(
        &routes,
        server_ip,
        default.interface_index,
        default.next_hop,
    ) {
        netcfg::remove_owned_routes(|route| is_server_route(route, server_ip))?;
        netcfg::add_route(default.interface_luid, server_ip, 32, default.next_hop)?;
    }

    for destination in TUNNEL_HALVES {
        let present = routes.iter().any(|route| {
            route.destination == destination
                && route.prefix_len == 1
                && route.interface_index == tunnel_index
        });
        if !present {
            netcfg::add_route(tunnel, destination, 1, Ipv4Addr::UNSPECIFIED)?;
        }
    }
    Ok(())
}

fn is_server_route(route: &OwnedRoute, server_ip: Ipv4Addr) -> bool {
    route.destination == server_ip && route.prefix_len == 32
}

/// Reports whether the endpoint route needs replacing.
///
/// It is stale when it is missing, duplicated, or points somewhere other than
/// the current physical default gateway — which is exactly what happens when
/// the machine roams to another network.
fn server_route_is_stale(
    routes: &[OwnedRoute],
    server_ip: Ipv4Addr,
    interface_index: u32,
    next_hop: Ipv4Addr,
) -> bool {
    let mut total = 0_usize;
    let mut matching = 0_usize;
    for route in routes
        .iter()
        .filter(|route| is_server_route(route, server_ip))
    {
        total += 1;
        if route.interface_index == interface_index && route.next_hop == next_hop {
            matching += 1;
        }
    }
    total != 1 || matching != 1
}

impl Drop for NetworkGuard {
    fn drop(&mut self) {
        // The WFP kill switch stays up for the whole of cleanup and only falls
        // away with this guard, so the machine is never briefly unprotected
        // while the routes are being taken down.
        if cleanup(self.state.firewall_rules).is_ok() {
            let _ = fs::remove_file(&self.state_path);
        }
    }
}

pub(crate) fn recover_stale_state() -> Result<(), ClientError> {
    let path = state_path()?;
    if let Some(state) = read_state(&path) {
        cleanup(state.firewall_rules)?;
        fs::remove_file(path)?;
        return Ok(());
    }
    if path.exists() {
        // A journal that will not parse says nothing about what was installed,
        // so assume the worst and sweep everything.
        cleanup(true)?;
        fs::remove_file(path)?;
        return Ok(());
    }
    // Policy is only ever written after the journal exists, so a missing
    // journal and a missing interface together mean the machine is clean.
    if !netcfg::interface_exists(ADAPTER_NAME) {
        return Ok(());
    }
    // The adapter usually outlives the session by a few seconds: Windows
    // removes the device well after the helper that owned it exited. The
    // journal is written before any firewall rule is created and removed only
    // after a cleanup that succeeded, so its absence proves there are no rules
    // of ours to sweep, and the firewall search can be skipped.
    cleanup(false)
}

pub(crate) fn repair() -> Result<(), ClientError> {
    // An explicit repair makes no assumptions: sweep the firewall too, so rules
    // left by a build that predates the WFP kill switch are collected.
    cleanup(true)?;
    match fs::remove_file(state_path()?) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn read_state(path: &Path) -> Option<RecoveryState> {
    toml::from_str(&fs::read_to_string(path).ok()?).ok()
}

pub(crate) fn report() -> Result<String, ClientError> {
    let script = format!(
        "$vpn=Get-NetAdapter -Name '{ADAPTER_NAME}' -ErrorAction SilentlyContinue; \
         $routes=@(); $dns=@(); $category=$null; $metric=$null; $bindings=@(); $otherDns=@(); \
         if ($vpn) {{ \
           $routes=@(Get-NetRoute -InterfaceIndex $vpn.ifIndex -ErrorAction SilentlyContinue | Where-Object {{$_.DestinationPrefix -in '0.0.0.0/1','128.0.0.0/1'}} | Select-Object DestinationPrefix,InterfaceIndex,RouteMetric); \
           $dns=@((Get-DnsClientServerAddress -InterfaceIndex $vpn.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses); \
           $metric=(Get-NetIPInterface -InterfaceIndex $vpn.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).InterfaceMetric; \
           $category=(Get-NetConnectionProfile -InterfaceIndex $vpn.ifIndex -ErrorAction SilentlyContinue).NetworkCategory; \
           $bindings=@(Get-NetAdapterBinding -Name '{ADAPTER_NAME}' -ErrorAction SilentlyContinue | Where-Object {{$_.Enabled -and $_.ComponentID -in 'nt_ndisrd','nt_ndiswgc'}} | Select-Object -ExpandProperty ComponentID); \
           $otherDns=@(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {{$_.ifIndex -ne $vpn.ifIndex -and $_.Status -eq 'Up'}} | ForEach-Object {{ \
             $adapter=$_; $ip=Get-NetIPInterface -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue; $servers=@((Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses); \
             if ($servers.Count -gt 0) {{[pscustomobject]@{{interfaceAlias=$adapter.Name; interfaceMetric=$ip.InterfaceMetric; dnsServers=$servers}}}} \
           }}) \
         }}; \
         [ordered]@{{ adapterUp=[bool]($vpn -and $vpn.Status -eq 'Up'); routeCount=$routes.Count; firewallRuleCount=@(Get-NetFirewallRule -Group '{FIREWALL_GROUP}' -Enabled True -ErrorAction SilentlyContinue).Count; dnsServers=$dns; interfaceMetric=$metric; networkCategory=$category; incompatibleBindings=$bindings; otherDnsAdapters=$otherDns; stateJournal=Test-Path '{}'; ipv6DefaultRoutes=@(Get-NetRoute -AddressFamily IPv6 -DestinationPrefix '::/0' -ErrorAction SilentlyContinue).Count }} | ConvertTo-Json -Depth 4 -Compress",
        powershell_path(&state_path()?)
    );
    run_powershell_output(&script, "collect the Windows network report")
}

pub(crate) fn physical_addresses() -> Result<PhysicalAddresses, ClientError> {
    netcfg::physical_addresses(netcfg::interface_luid(ADAPTER_NAME).ok())
}

fn write_state(path: &Path, state: &RecoveryState) -> Result<(), ClientError> {
    let contents = toml::to_string(state).map_err(|error| {
        ClientError::Platform(format!("failed to encode recovery state: {error}"))
    })?;
    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&temporary)?;
        file.write_all(contents.as_bytes())?;
        file.sync_all()?;
        if path.exists() {
            fs::remove_file(path)?;
        }
        fs::rename(&temporary, path)?;
        Ok::<(), io::Error>(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result.map_err(Into::into)
}

/// Undoes every network change `MouseVPN` can make.
///
/// Route removal does not depend on the recovery journal: routes are recognised
/// by the metric and protocol the client always stamps on them, so a session
/// whose journal was lost still cleans up completely.
///
/// `firewall_rules` says whether Windows Firewall is worth searching. The full
/// tunnel keeps its kill switch in a dynamic WFP session that Windows tears down
/// with the process, so skipping the search keeps a six-second PowerShell start
/// out of every disconnect.
fn cleanup(firewall_rules: bool) -> Result<(), ClientError> {
    let mut failures = Vec::new();
    // Windows unbinds IPv4 before it removes the device, so between a
    // disconnect and the adapter actually disappearing the interface still
    // resolves by alias while none of its IPv4 settings exist. There is
    // nothing left to undo in that window, and treating it as a failure used
    // to block the next connection until Windows finished the removal.
    if let Ok(tunnel) = netcfg::interface_luid(ADAPTER_NAME) {
        if netcfg::has_ipv4_binding(tunnel) {
            collect(&mut failures, netcfg::reset_tunnel_dns(ADAPTER_NAME));
            collect(&mut failures, netcfg::reset_tunnel_metric(tunnel));
            collect(&mut failures, netcfg::clear_addresses(tunnel));
        }
    }
    collect(&mut failures, netcfg::remove_owned_routes(|_| true));
    if firewall_rules {
        collect(
            &mut failures,
            run_powershell(
                &format!(
                    "$rules=@(Get-NetFirewallRule -Group '{FIREWALL_GROUP}' -ErrorAction SilentlyContinue); \
                     if ($rules.Count -gt 0) {{ $rules | Remove-NetFirewallRule -ErrorAction Stop }}; \
                     exit 0"
                ),
                "remove the Windows kill switch",
            ),
        );
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(ClientError::Platform(failures.join("; ")))
    }
}

fn collect(failures: &mut Vec<String>, result: Result<(), ClientError>) {
    if let Err(error) = result {
        failures.push(error.to_string());
    }
}

fn install_script(server_ip: Ipv4Addr, app_routing: &AppRoutingPolicy) -> String {
    let prefixes = blocked_ipv4_prefixes(server_ip).join("','");
    let firewall = firewall_script(app_routing, false);
    format!(
        "$ErrorActionPreference='Stop'; \
         $blocked=@('{prefixes}'); \
         $physical=Get-NetAdapter | Where-Object {{$_.Name -ne '{ADAPTER_NAME}' -and $_.InterfaceDescription -notmatch 'Loopback'}}; \
         {firewall}"
    )
}

fn refresh_script(server_ip: Ipv4Addr, app_routing: &AppRoutingPolicy) -> String {
    let prefixes = blocked_ipv4_prefixes(server_ip).join("','");
    let firewall = firewall_script(app_routing, true);
    format!(
        "$ErrorActionPreference='Stop'; \
         $vpn=Get-NetAdapter -Name '{ADAPTER_NAME}' -ErrorAction Stop; \
         try {{ \
           $profile=Get-NetConnectionProfile -InterfaceIndex $vpn.ifIndex -ErrorAction SilentlyContinue; \
           if ($profile -and $profile.NetworkCategory -ne 'Public') {{Set-NetConnectionProfile -InterfaceIndex $vpn.ifIndex -NetworkCategory Public -ErrorAction Stop}} \
         }} catch {{Write-Warning ('Could not mark MouseVPN as a Public network: '+$_.Exception.Message)}}; \
         $blocked=@('{prefixes}'); \
         $physical=Get-NetAdapter | Where-Object {{$_.Name -ne '{ADAPTER_NAME}' -and $_.InterfaceDescription -notmatch 'Loopback'}}; \
         {firewall}"
    )
}

fn firewall_script(policy: &AppRoutingPolicy, only_missing: bool) -> String {
    match policy.mode {
        AppRoutingMode::Exclude => {
            let create_v4 = "try { New-NetFirewallRule -Name ('MouseVPN-KS-v4-'+$adapter.ifIndex) -DisplayName ('MouseVPN kill switch IPv4 '+$adapter.Name) -Group 'MouseVPN Kill Switch' -Direction Outbound -Action Block -Enabled True -Profile Any -InterfaceAlias $adapter.Name -RemoteAddress $blocked | Out-Null } catch { throw ('IPv4 firewall rule failed on adapter '+$adapter.Name+': '+$_.Exception.Message) }";
            let create_v6 = "try { New-NetFirewallRule -Name ('MouseVPN-KS-v6-'+$adapter.ifIndex) -DisplayName ('MouseVPN kill switch IPv6 '+$adapter.Name) -Group 'MouseVPN Kill Switch' -Direction Outbound -Action Block -Enabled True -Profile Any -InterfaceAlias $adapter.Name -RemoteAddress 'Internet6' | Out-Null } catch { throw ('IPv6 firewall rule failed on adapter '+$adapter.Name+': '+$_.Exception.Message) }";
            if only_missing {
                format!(
                    "foreach ($adapter in $physical) {{ if (-not (Get-NetFirewallRule -Name ('MouseVPN-KS-v4-'+$adapter.ifIndex) -ErrorAction SilentlyContinue)) {{ {create_v4} }}; if (-not (Get-NetFirewallRule -Name ('MouseVPN-KS-v6-'+$adapter.ifIndex) -ErrorAction SilentlyContinue)) {{ {create_v6} }} }}"
                )
            } else {
                format!("foreach ($adapter in $physical) {{ {create_v4}; {create_v6} }}")
            }
        }
        AppRoutingMode::Include => {
            let apps = policy
                .apps
                .iter()
                .map(|path| format!("'{}'", powershell_path(path)))
                .collect::<Vec<_>>()
                .join(",");
            let packages = policy
                .package_sids
                .iter()
                .map(|sid| format!("'{}'", sid.replace('\'', "''")))
                .collect::<Vec<_>>()
                .join(",");
            let guard = if only_missing {
                "if (-not (Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue))"
            } else {
                "if ($true)"
            };
            format!(
                "$vpnApps=@({apps}); $vpnPackages=@({packages}); foreach ($adapter in $physical) {{ $name=('MouseVPN-KS-v4-'+$adapter.ifIndex+'-dnscache'); {guard} {{ try {{ New-NetFirewallRule -Name $name -DisplayName ('MouseVPN DNS Client kill switch IPv4 '+$adapter.Name) -Group '{FIREWALL_GROUP}' -Direction Outbound -Action Block -Enabled True -Profile Any -InterfaceAlias $adapter.Name -Service Dnscache -RemoteAddress $blocked | Out-Null }} catch {{ throw ('DNS Client IPv4 firewall rule failed: '+$_.Exception.Message) }} }}; $name=('MouseVPN-KS-v6-'+$adapter.ifIndex+'-dnscache'); {guard} {{ try {{ New-NetFirewallRule -Name $name -DisplayName ('MouseVPN DNS Client kill switch IPv6 '+$adapter.Name) -Group '{FIREWALL_GROUP}' -Direction Outbound -Action Block -Enabled True -Profile Any -InterfaceAlias $adapter.Name -Service Dnscache -RemoteAddress 'Internet6' | Out-Null }} catch {{ throw ('DNS Client IPv6 firewall rule failed: '+$_.Exception.Message) }} }}; $i=0; foreach ($app in $vpnApps) {{ $name=('MouseVPN-KS-v4-'+$adapter.ifIndex+'-'+$i); {guard} {{ try {{ New-NetFirewallRule -Name $name -DisplayName ('MouseVPN selected app kill switch IPv4 '+$adapter.Name) -Group '{FIREWALL_GROUP}' -Direction Outbound -Action Block -Enabled True -Profile Any -InterfaceAlias $adapter.Name -Program $app -RemoteAddress $blocked | Out-Null }} catch {{ throw ('Selected-app IPv4 firewall rule failed for '+$app+': '+$_.Exception.Message) }} }}; $name=('MouseVPN-KS-v6-'+$adapter.ifIndex+'-'+$i); {guard} {{ try {{ New-NetFirewallRule -Name $name -DisplayName ('MouseVPN selected app kill switch IPv6 '+$adapter.Name) -Group '{FIREWALL_GROUP}' -Direction Outbound -Action Block -Enabled True -Profile Any -InterfaceAlias $adapter.Name -Program $app -RemoteAddress 'Internet6' | Out-Null }} catch {{ throw ('Selected-app IPv6 firewall rule failed for '+$app+': '+$_.Exception.Message) }} }}; $i++ }}; foreach ($package in $vpnPackages) {{ $name=('MouseVPN-KS-v4-'+$adapter.ifIndex+'-package-'+$i); {guard} {{ try {{ New-NetFirewallRule -Name $name -DisplayName ('MouseVPN selected package kill switch IPv4 '+$adapter.Name) -Group '{FIREWALL_GROUP}' -Direction Outbound -Action Block -Enabled True -Profile Any -InterfaceAlias $adapter.Name -Package $package -RemoteAddress $blocked | Out-Null }} catch {{ throw ('Selected-package IPv4 firewall rule failed for '+$package+': '+$_.Exception.Message) }} }}; $name=('MouseVPN-KS-v6-'+$adapter.ifIndex+'-package-'+$i); {guard} {{ try {{ New-NetFirewallRule -Name $name -DisplayName ('MouseVPN selected package kill switch IPv6 '+$adapter.Name) -Group '{FIREWALL_GROUP}' -Direction Outbound -Action Block -Enabled True -Profile Any -InterfaceAlias $adapter.Name -Package $package -RemoteAddress 'Internet6' | Out-Null }} catch {{ throw ('Selected-package IPv6 firewall rule failed for '+$package+': '+$_.Exception.Message) }} }}; $i++ }} }}"
            )
        }
    }
}

fn blocked_ipv4_prefixes(server_ip: Ipv4Addr) -> Vec<String> {
    let server = u32::from(server_ip);
    let mut server_network = 0_u32;
    let mut prefixes = Vec::with_capacity(32);

    for prefix_len in 1..=32 {
        let bit = 1_u32 << (32 - prefix_len);
        let sibling_network = if server & bit == 0 {
            server_network | bit
        } else {
            let sibling = server_network;
            server_network |= bit;
            sibling
        };
        prefixes.push(format!(
            "{}/{}",
            Ipv4Addr::from(sibling_network),
            prefix_len
        ));
    }

    prefixes
}

fn state_path() -> Result<PathBuf, ClientError> {
    Ok(runtime_dir()?.join(STATE_FILE))
}

pub(crate) fn runtime_dir() -> Result<PathBuf, ClientError> {
    let base = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .ok_or_else(|| ClientError::Platform("LOCALAPPDATA is unavailable".to_owned()))?;
    Ok(base.join("MouseVPN").join("runtime"))
}

fn powershell_path(path: &Path) -> String {
    crate::normalize_windows_path(path)
        .display()
        .to_string()
        .replace('\'', "''")
}

pub(crate) fn run_powershell(script: &str, operation: &str) -> Result<(), ClientError> {
    run_powershell_output(script, operation).map(|_| ())
}

fn run_powershell_output(script: &str, operation: &str) -> Result<String, ClientError> {
    let script = format!(
        "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; \
         $OutputEncoding=[Console]::OutputEncoding; \
         {script}"
    );
    let mut command = Command::new("powershell.exe");
    command.creation_flags(CREATE_NO_WINDOW);
    let output = command
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &script,
        ])
        .output()?;
    if output.status.success() {
        return Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let details = if !stderr.is_empty() {
        stderr
    } else if !stdout.is_empty() {
        stdout
    } else {
        format!("PowerShell exited with status {}", output.status)
    };
    Err(ClientError::Platform(format!(
        "failed to {operation}: {details}"
    )))
}

#[cfg(test)]
mod tests {
    use super::{
        blocked_ipv4_prefixes, firewall_script, install_script, server_route_is_stale, OwnedRoute,
    };
    use crate::{AppRoutingMode, AppRoutingPolicy};
    use std::net::Ipv4Addr;
    use std::path::PathBuf;

    const SERVER: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 10);
    const GATEWAY: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 1);

    fn server_route(interface_index: u32, next_hop: Ipv4Addr) -> OwnedRoute {
        OwnedRoute {
            destination: SERVER,
            prefix_len: 32,
            interface_index,
            next_hop,
        }
    }

    #[test]
    fn emits_valid_cidr_prefixes_that_exclude_the_server() {
        let prefixes = blocked_ipv4_prefixes(SERVER);
        assert_eq!(prefixes.len(), 32);
        assert!(prefixes.iter().all(|prefix| !contains(prefix, SERVER)));
        assert!(contains_any(&prefixes, Ipv4Addr::UNSPECIFIED));
        assert!(contains_any(&prefixes, Ipv4Addr::BROADCAST));
        assert!(contains_any(&prefixes, Ipv4Addr::new(203, 0, 113, 9)));
        assert!(contains_any(&prefixes, Ipv4Addr::new(203, 0, 113, 11)));
    }

    #[test]
    fn handles_ipv4_boundaries() {
        for server in [Ipv4Addr::UNSPECIFIED, Ipv4Addr::BROADCAST] {
            let prefixes = blocked_ipv4_prefixes(server);
            assert_eq!(prefixes.len(), 32);
            assert!(prefixes.iter().all(|prefix| !contains(prefix, server)));
        }
    }

    #[test]
    fn keeps_a_matching_endpoint_route() {
        assert!(!server_route_is_stale(
            &[server_route(7, GATEWAY)],
            SERVER,
            7,
            GATEWAY
        ));
    }

    #[test]
    fn replaces_an_endpoint_route_left_on_the_previous_network() {
        assert!(server_route_is_stale(
            &[server_route(7, Ipv4Addr::new(10, 0, 0, 1))],
            SERVER,
            7,
            GATEWAY
        ));
        assert!(server_route_is_stale(
            &[server_route(9, GATEWAY)],
            SERVER,
            7,
            GATEWAY
        ));
    }

    #[test]
    fn replaces_a_missing_or_duplicated_endpoint_route() {
        assert!(server_route_is_stale(&[], SERVER, 7, GATEWAY));
        assert!(server_route_is_stale(
            &[server_route(7, GATEWAY), server_route(9, GATEWAY)],
            SERVER,
            7,
            GATEWAY
        ));
    }

    #[test]
    fn install_only_configures_the_kill_switch() {
        let script = install_script(SERVER, &AppRoutingPolicy::default());
        assert!(script.contains("MouseVPN-KS-v4-"));
        // Addresses, DNS, the interface metric and routes are applied through
        // iphlpapi now, so none of them may reappear in the script.
        assert!(!script.contains("New-NetIPAddress"));
        assert!(!script.contains("New-NetRoute"));
        assert!(!script.contains("Set-DnsClientServerAddress"));
        assert!(!script.contains("Set-NetIPInterface"));
    }

    #[test]
    fn allowlist_firewall_targets_only_selected_programs() {
        let script = firewall_script(
            &AppRoutingPolicy {
                mode: AppRoutingMode::Include,
                apps: vec![PathBuf::from(r"C:\Apps\Mouse's Browser.exe")],
                package_sids: Vec::new(),
            },
            false,
        );
        assert!(script.contains("-Program $app"));
        assert!(script.contains("Mouse''s Browser.exe"));
    }

    #[test]
    fn allowlist_firewall_keeps_dns_client_on_the_tunnel() {
        let script = firewall_script(
            &AppRoutingPolicy {
                mode: AppRoutingMode::Include,
                apps: Vec::new(),
                package_sids: Vec::new(),
            },
            false,
        );
        assert!(script.contains("-Service Dnscache"));
        assert!(script.contains("-dnscache"));
        assert!(!script.contains("-Program 'C:\\Windows\\System32\\svchost.exe'"));
    }

    #[test]
    fn allowlist_firewall_uses_regular_windows_paths() {
        let script = firewall_script(
            &AppRoutingPolicy {
                mode: AppRoutingMode::Include,
                apps: vec![PathBuf::from(r"\\?\C:\Program Files\Browser\browser.exe")],
                package_sids: Vec::new(),
            },
            false,
        );
        assert!(script.contains(r"'C:\Program Files\Browser\browser.exe'"));
        assert!(!script.contains(r"\\?\"));
    }

    #[test]
    fn denylist_firewall_remains_global() {
        let script = firewall_script(&AppRoutingPolicy::default(), false);
        assert!(!script.contains("-Program"));
        assert!(script.contains("MouseVPN-KS-v4-"));
    }

    #[test]
    fn allowlist_firewall_targets_selected_store_packages() {
        let script = firewall_script(
            &AppRoutingPolicy {
                mode: AppRoutingMode::Include,
                apps: Vec::new(),
                package_sids: vec!["S-1-15-2-123".to_owned()],
            },
            false,
        );
        assert!(script.contains("-Package $package"));
        assert!(script.contains("'S-1-15-2-123'"));
    }

    fn contains_any(prefixes: &[String], address: Ipv4Addr) -> bool {
        prefixes.iter().any(|prefix| contains(prefix, address))
    }

    fn contains(prefix: &str, address: Ipv4Addr) -> bool {
        let (network, length) = prefix.split_once('/').expect("CIDR prefix");
        let network = u32::from(network.parse::<Ipv4Addr>().expect("IPv4 network"));
        let length = length.parse::<u32>().expect("prefix length");
        let mask = u32::MAX << (32 - length);
        u32::from(address) & mask == network
    }
}
