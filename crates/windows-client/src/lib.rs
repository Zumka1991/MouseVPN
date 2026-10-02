#![doc = "Windows `MouseVPN` client runtime."]

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[cfg(windows)]
mod app_bypass;
#[cfg(not(windows))]
#[path = "app_bypass_stub.rs"]
mod app_bypass;
// Temporary: see the module documentation for what removing it involves.
mod diagnostics;
mod error;
mod handshake;
#[cfg(windows)]
mod killswitch;
mod liveness;
#[cfg(windows)]
mod netcfg;
#[cfg(windows)]
mod network;
#[cfg(windows)]
mod network_events;
#[cfg(windows)]
mod packet_loop;
#[cfg(windows)]
mod platform;
mod secure_store;

#[cfg(not(windows))]
mod platform_stub;
#[cfg(windows)]
mod runtime;
#[cfg(windows)]
mod split_tunnel;
#[cfg(windows)]
mod windivert;

pub use error::ClientError;
pub use secure_store::{protect_account, unprotect_account};

/// Performs only the authenticated UDP handshake without creating `Wintun`,
/// routes, DNS policy or firewall state.
///
/// # Errors
///
/// Returns an error when key derivation, UDP transport or the handshake fails.
pub fn probe(
    config: &mousevpn_config::ValidatedClientConfig,
) -> Result<mousevpn_protocol::SessionParameters, ClientError> {
    let wire = mousevpn_client_wire::ClientWire::from_config(config)?;
    let (_, _, parameters) = handshake::connect(config, &wire)?;
    Ok(parameters)
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AppRoutingMode {
    #[default]
    Exclude,
    Include,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AppRoutingPolicy {
    pub mode: AppRoutingMode,
    pub apps: Vec<PathBuf>,
    pub package_sids: Vec<String>,
}

impl AppRoutingPolicy {
    /// Reports whether this policy asks for per-application routing.
    ///
    /// Excluding nothing is the same as tunnelling everything, so an empty
    /// denylist runs as a plain full tunnel: no capture, no translation, and
    /// the kill switch and routes that come with it. An include list is always
    /// per-application, even when empty, because "tunnel only these" with
    /// nothing chosen still means the rest of the machine stays direct.
    #[must_use]
    pub fn is_per_application(&self) -> bool {
        matches!(self.mode, AppRoutingMode::Include)
            || !self.apps.is_empty()
            || !self.package_sids.is_empty()
    }
}

#[cfg(windows)]
/// Derives the `AppContainer` SID string used by WFP and Windows Firewall.
///
/// # Errors
///
/// Returns [`ClientError::Platform`] when Windows cannot derive or format the
/// package identity.
pub fn app_container_sid_string(package_family_name: &str) -> Result<String, ClientError> {
    use std::ptr;

    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::{
            Authorization::ConvertSidToStringSidW, FreeSid,
            Isolation::DeriveAppContainerSidFromAppContainerName, PSID,
        },
    };

    let package_family_name = package_family_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut sid: PSID = ptr::null_mut();
    let result = unsafe {
        DeriveAppContainerSidFromAppContainerName(package_family_name.as_ptr(), &raw mut sid)
    };
    if result < 0 || sid.is_null() {
        return Err(ClientError::Platform(format!(
            "failed to derive the package SID (HRESULT 0x{:08X})",
            u32::from_ne_bytes(result.to_ne_bytes())
        )));
    }

    let mut sid_string = ptr::null_mut();
    let converted = unsafe { ConvertSidToStringSidW(sid, &raw mut sid_string) };
    if converted == 0 || sid_string.is_null() {
        unsafe {
            FreeSid(sid);
        }
        return Err(ClientError::Platform(format!(
            "failed to format the package SID: {}",
            std::io::Error::last_os_error()
        )));
    }
    let Some(length) = (0..256).find(|&index| unsafe { *sid_string.add(index) == 0 }) else {
        unsafe {
            LocalFree(sid_string.cast());
            FreeSid(sid);
        }
        return Err(ClientError::Platform(
            "Windows returned an invalid package SID string".to_owned(),
        ));
    };
    let value = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(sid_string, length) });
    unsafe {
        LocalFree(sid_string.cast());
        FreeSid(sid);
    }
    Ok(value)
}

#[cfg(not(windows))]
/// Reports that `AppContainer` identities are unavailable outside Windows.
///
/// # Errors
///
/// Always returns [`ClientError::Platform`] outside Windows.
pub fn app_container_sid_string(_package_family_name: &str) -> Result<String, ClientError> {
    Err(ClientError::Platform(
        "Windows application package identities are unavailable on this platform".to_owned(),
    ))
}

/// Converts Rust's extended-length canonical Windows paths into the regular
/// DOS/UNC form expected by Windows Firewall and WFP application APIs.
#[must_use]
pub fn normalize_windows_path(path: &Path) -> PathBuf {
    let value = path.to_string_lossy().replace('/', "\\");
    if let Some(value) = value.strip_prefix(r"\\?\UNC\") {
        PathBuf::from(format!(r"\\{value}"))
    } else if let Some(value) = value.strip_prefix(r"\\?\") {
        PathBuf::from(value)
    } else {
        PathBuf::from(value)
    }
}

#[cfg(not(windows))]
pub use platform_stub::{
    diagnose, network_report, repair_network, run_with_stop, RuntimeDiagnostics,
};
#[cfg(windows)]
pub use runtime::{diagnose, network_report, repair_network, run_with_stop, RuntimeDiagnostics};

#[cfg(windows)]
pub use split_tunnel::run_split_tunnel;

#[cfg(windows)]
pub use windivert::divert::check_capture_filters;

#[cfg(windows)]
pub use windivert::flow::probe as probe_split_tunnel_flows;

#[cfg(test)]
mod tests {
    use super::normalize_windows_path;
    use std::path::Path;

    #[test]
    fn removes_extended_drive_path_prefix() {
        assert_eq!(
            normalize_windows_path(Path::new(r"\\?\C:\Apps\Browser.exe")),
            Path::new(r"C:\Apps\Browser.exe")
        );
    }

    #[test]
    fn converts_extended_unc_path() {
        assert_eq!(
            normalize_windows_path(Path::new(r"\\?\UNC\server\share\Browser.exe")),
            Path::new(r"\\server\share\Browser.exe")
        );
    }

    #[cfg(windows)]
    #[test]
    fn derives_an_app_container_sid_from_a_package_family() {
        let sid = super::app_container_sid_string("OpenAI.Codex_2p2nqsd0c76g0").unwrap();
        assert!(sid.starts_with("S-1-15-2-"));
    }
}
