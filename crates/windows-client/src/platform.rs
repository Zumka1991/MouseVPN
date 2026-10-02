use std::{fs, path::PathBuf, ptr};

use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE},
    Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY},
    System::{
        LibraryLoader::{GetModuleHandleA, GetProcAddress},
        Threading::{GetCurrentProcess, OpenProcessToken},
    },
};

use crate::{network, ClientError};

const WINTUN_DLL: &[u8] = include_bytes!("../vendor/wintun/wintun.dll");
pub(crate) const WINTUN_VERSION: &str = "0.14.1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeDiagnostics {
    pub platform: &'static str,
    pub running_under_wine: bool,
    pub wintun_available: bool,
    pub elevated: bool,
    pub message: String,
}

#[must_use]
pub fn diagnose() -> RuntimeDiagnostics {
    let running_under_wine = is_wine();
    let elevated = is_elevated();
    let message = match (running_under_wine, elevated) {
        (true, _) => {
            "Wine detected: headless checks are supported, but the Wintun driver is unavailable"
                .to_owned()
        }
        (false, true) => format!("Windows runtime is ready (embedded Wintun {WINTUN_VERSION})"),
        (false, false) => "MouseVPN must be started as Administrator".to_owned(),
    };
    RuntimeDiagnostics {
        platform: "windows",
        running_under_wine,
        wintun_available: !running_under_wine,
        elevated,
        message,
    }
}

pub(crate) fn ensure_supported_runtime() -> Result<(), ClientError> {
    if is_wine() {
        return Err(ClientError::Platform(
            "Wintun cannot run under Wine; use Windows or a Windows VM for tunnel tests".to_owned(),
        ));
    }
    if !is_elevated() {
        return Err(ClientError::Platform(
            "MouseVPN must be started as Administrator".to_owned(),
        ));
    }
    Ok(())
}

pub(crate) fn materialize_wintun() -> Result<PathBuf, ClientError> {
    let directory = network::runtime_dir()?;
    fs::create_dir_all(&directory)?;
    let destination = directory.join(format!("wintun-{WINTUN_VERSION}.dll"));
    // Comparing the length first keeps the common warm-start path from reading
    // the whole embedded library back off disk on every connection.
    if fs::metadata(&destination).is_ok_and(|metadata| metadata.len() == WINTUN_DLL.len() as u64)
        && fs::read(&destination).is_ok_and(|contents| contents == WINTUN_DLL)
    {
        return Ok(destination);
    }
    let temporary = directory.join(format!(
        "wintun-{WINTUN_VERSION}.tmp-{}",
        std::process::id()
    ));
    fs::write(&temporary, WINTUN_DLL)?;
    if destination.exists() {
        fs::remove_file(&destination)?;
    }
    if let Err(error) = fs::rename(&temporary, &destination) {
        let _ = fs::remove_file(&temporary);
        return Err(error.into());
    }
    Ok(destination)
}

/// Reports whether the current process token carries an elevated administrator
/// identity.
///
/// This deliberately avoids `net session`: that command depends on the
/// `LanmanServer` service, so it reports "not elevated" on machines where the
/// Server service is disabled, and it costs a process spawn on every check.
fn is_elevated() -> bool {
    let mut token: HANDLE = ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) } == 0 {
        return false;
    }
    let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut returned = 0_u32;
    let queried = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            (&raw mut elevation).cast(),
            u32::try_from(size_of::<TOKEN_ELEVATION>()).unwrap_or(0),
            &raw mut returned,
        )
    };
    unsafe {
        CloseHandle(token);
    }
    queried != 0 && elevation.TokenIsElevated != 0
}

/// Detects Wine by looking for its `ntdll` extension export instead of shelling
/// out to `reg.exe`.
fn is_wine() -> bool {
    let module = unsafe { GetModuleHandleA(c"ntdll.dll".as_ptr().cast()) };
    if module.is_null() {
        return false;
    }
    unsafe { GetProcAddress(module, c"wine_get_version".as_ptr().cast()) }.is_some()
}
