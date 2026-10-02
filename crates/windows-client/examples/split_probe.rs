//! Runs one split tunnel session against an explicit policy.
//!
//! The policy is given on the command line rather than read from the saved
//! settings, so trying this out cannot disturb the configuration the installed
//! client uses.
//!
//! Requires Administrator, no other `MouseVPN` session running, and
//! `WinDivert.dll` and `WinDivert64.sys` beside this executable.
//!
//! ```text
//! split_probe.exe --config <profile.toml> --include C:\Windows\System32\curl.exe
//! split_probe.exe --config <profile.toml> --exclude C:\Windows\System32\curl.exe
//! ```

fn main() {
    #[cfg(windows)]
    {
        if let Err(error) = windows::run() {
            eprintln!("split probe failed: {error}");
            std::process::exit(1);
        }
    }

    #[cfg(not(windows))]
    eprintln!("the split probe only runs on Windows");
}

#[cfg(windows)]
mod windows {
    use std::{
        path::PathBuf,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
    };

    use mousevpn_config::{load_toml, ClientConfig};
    use mousevpn_windows_client::{AppRoutingMode, AppRoutingPolicy};

    pub(super) fn run() -> Result<(), String> {
        let (config_path, mode, apps) = arguments()?;
        let config: ClientConfig = load_toml(&config_path).map_err(|error| error.to_string())?;
        let config = config.validate().map_err(|error| error.to_string())?;
        let policy = AppRoutingPolicy {
            mode,
            apps,
            package_sids: Vec::new(),
        };

        println!("mode: {mode:?}");
        for app in &policy.apps {
            println!("app : {}", app.display());
        }
        println!("connecting; press Ctrl+C to stop\n");

        let stopping = Arc::new(AtomicBool::new(false));
        stop_on_enter(&stopping);

        mousevpn_windows_client::run_split_tunnel(&config, &stopping, &policy)
            .map_err(|error| error.to_string())
    }

    /// Reads `--config` plus exactly one of `--include` or `--exclude`.
    fn arguments() -> Result<(PathBuf, AppRoutingMode, Vec<PathBuf>), String> {
        let values: Vec<String> = std::env::args().skip(1).collect();
        let mut config = None;
        let mut mode = None;
        let mut apps = Vec::new();
        let mut index = 0;
        while index + 1 < values.len() {
            let value = PathBuf::from(&values[index + 1]);
            match values[index].as_str() {
                "--config" => config = Some(value),
                "--include" => {
                    mode = Some(AppRoutingMode::Include);
                    apps.push(value);
                }
                "--exclude" => {
                    mode = Some(AppRoutingMode::Exclude);
                    apps.push(value);
                }
                other => return Err(format!("unexpected argument {other}")),
            }
            index += 2;
        }
        let config = config.ok_or_else(usage)?;
        let mode = mode.ok_or_else(usage)?;
        if apps.iter().any(|app| !app.is_file()) {
            return Err("every application path must name an existing file".to_owned());
        }
        Ok((config, mode, apps))
    }

    fn usage() -> String {
        "usage: split_probe --config <profile.toml> (--include | --exclude) <app.exe> ..."
            .to_owned()
    }

    /// Stops the session when a line arrives on standard input.
    ///
    /// Pressing Enter unwinds the session properly, closing the `WinDivert`
    /// handles on the way out. Ctrl+C also works, just less tidily: Windows
    /// reclaims the handles when the process dies, so the driver stops
    /// diverting either way.
    fn stop_on_enter(stopping: &Arc<AtomicBool>) {
        let stopping = Arc::clone(stopping);
        std::thread::spawn(move || {
            let mut line = String::new();
            let _ = std::io::stdin().read_line(&mut line);
            stopping.store(true, Ordering::Release);
        });
    }
}
