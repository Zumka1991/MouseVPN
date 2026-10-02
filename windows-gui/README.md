# MouseVPN for Windows

Native Windows desktop client built with Tauri 2 and the shared MouseVPN Rust
protocol implementation.

## Current development slice

- imports and stores encrypted `MV1.…` profiles under `%APPDATA%\\MouseVPN`;
- performs the MouseVPN UDP/Noise handshake;
- creates a layer-3 adapter through `wintun.dll`;
- configures an IPv4 full tunnel and tunnel DNS with PowerShell;
- gives the tunnel interface metric `1` so its DNS path wins over lower-priority
  virtual adapters without modifying those third-party adapters;
- marks the dedicated tunnel as a Public network for Store/UWP network
  isolation compatibility;
- installs per-interface Windows Firewall kill-switch rules for IPv4 and IPv6;
- supports application denylist/allowlist routing through the bundled WFP
  callout driver;
- supports a `full-tunnel-only` family build that omits the test driver, hides
  application routing, and ignores split-tunnel settings left by another
  edition;
- discovers Start-menu and Microsoft Store applications for multi-select and
  refreshes versioned `WindowsApps` executable paths after package updates;
- matches Microsoft Store applications by both executable path and package SID
  so MSIX network processes follow the selected split-tunnel policy;
- keeps the Windows DNS Client service on the tunnel in application allowlist
  mode, with service-specific leak protection that does not capture unrelated
  `svchost.exe` services;
- reauthorizes and blocks pre-existing selected-application flows that still
  use a physical local address, so applications started before MouseVPN fail
  closed and retry through the tunnel;
- groups Squirrel desktop applications such as Claude with their versioned
  `app-*` executable and refreshes that path automatically after updates;
- groups the Microsoft Store Claude client with its separately updated
  `%APPDATA%\Claude\claude-code\<version>\claude.exe` network helper and
  refreshes that helper path automatically after updates;
- journals every network mutation before applying it and repairs stale state on
  the next launch;
- reconnects timed-out sessions with bounded exponential backoff while leaving
  the kill switch active;
- coalesces duplicate Windows resume and address-change notifications after a
  successful reconnect so waking from sleep does not start a second handshake;
- preserves a fail-closed network policy and restarts the complete Wintun
  runtime after an unexpected fatal packet-path error;
- keeps running in the Windows notification area when its main window is
  closed, with show, connect/disconnect and quit actions;
- prevents duplicate GUI processes and reveals the existing window when the
  application is launched a second time;
- can register an elevated Task Scheduler logon task and start minimized in
  the notification area without showing a UAC prompt on every launch;
- starts the tunnel helper and Windows networking commands without visible
  console windows;
- keeps a rotated helper diagnostic log under
  `%LOCALAPPDATA%\\MouseVPN\\logs` without profile secrets;
- reports known third-party NDIS bindings from WireSock/WinpkFilter without
  modifying them;
- restores firewall rules, routes, the tunnel address and DNS on disconnect;
- provides a non-Windows diagnostic stub so the workspace remains testable on
  Linux and the executable UI can be smoke-tested with Wine.

The Windows networking backend is still an early MVP. Existing adapters are
protected when the tunnel starts; a background policy worker rechecks every 30
seconds and reconnects refresh the physical server route and WFP policy.
Application routing requires a properly signed `MouseVpnSplitTunnel.sys`; see
`../windows-driver/README.md`. Do not treat the client as leak-safe until the
real Windows test matrix in `WINDOWS-TESTING.md` passes.

## Development requirements

- Windows 10 or 11 x64;
- Rust 1.85 or newer with the MSVC target;
- Visual Studio Build Tools with the Desktop C++ workload;
- Windows SDK/WDK and either a test- or release-signing setup for the
  split-tunnel driver;
- WebView2 Runtime;
- the official signed x64 Wintun library is embedded into the application;
- an Administrator terminal for tunnel tests.

Run the development application from the repository root:

```powershell
cargo tauri dev --config windows-gui/src-tauri/tauri.conf.json
```

Cross-build a release EXE on Linux with:

```sh
./windows-gui/build-windows.sh
```

The versioned artifact is written to `windows-gui/dist`.

Release builds contain a `requireAdministrator` application manifest. The
NSIS/MSI configuration downloads the Microsoft WebView2 bootstrapper when the
runtime is missing.

## Friends test installer

The locally test-signed split-tunnel package is intentionally separate from a
release build. Build it on Windows with:

```powershell
.\windows-gui\build-installer.ps1 -UseTestSignedDriver
```

The resulting `MouseVPN_<version>_x64-friends-test-setup.exe` contains the WFP
driver and the public test certificate. Its installer requires administrator
rights, displays an explicit consent page, refuses to continue while Secure
Boot is enabled, imports the certificate, enables `TESTSIGNING`, and requests
a reboot. Silent or passive installation is refused unless the caller also
passes `/ALLOWTESTMODE`.

On uninstall, the package stops and removes the driver and deletes its test
certificate. It disables `TESTSIGNING` only when the installer recorded that
it was previously off. Secure Boot is never changed automatically. This build
is suitable only for trusted test machines; public distribution requires a
Microsoft dashboard-signed driver and a publicly trusted installer signature.

For a headless Wine smoke test that does not initialize WebView2:

```sh
wine mousevpn-windows-gui.exe --diagnose
```

The repeatable wrapper is `./windows-gui/test-wine.sh [path-to-exe]`. Set
`WINE_BIN` when Wine is installed outside `PATH`.

Real Windows build and verification steps are in `WINDOWS-TESTING.md`. The
non-destructive test command is:

```powershell
.\windows-gui\test-windows.ps1
```

Add `-TestCrashRecovery` only in a disposable VM or after saving work. If a
test is interrupted while the kill switch is active, run the EXE with
`--repair-network` from Administrator PowerShell.

Wintun is not available under Wine, and current WebView2 installers are not
reliably compatible with Wine. The supported Wine test is therefore the
headless runtime diagnostic; GUI, tunnel, route, DNS and leak tests require
Windows or a Windows VM.

The bundled Wintun 0.14.1 archive was downloaded from `wintun.net` and checked
against the publisher's SHA-256 value
`07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51`.
Its redistribution license is kept at
`crates/windows-client/vendor/wintun/LICENSE.txt`.

## Windows 0.2.1 installer from Linux

The Windows build embeds the same compact interface as Linux 0.2.1. Its default
window is 960×680 (minimum 720×560); Windows autostart and application routing
remain in Settings. Account and support screens, live ticket updates and
connection cancellation use the shared frontend.

To cross-build the x64 **NSIS installer**, use `./windows-gui/build-linux-installer.sh`.
This requires the Rust `x86_64-pc-windows-gnu` target, MinGW toolchain, Tauri CLI
(`tauri` on PATH, or `TAURI_CLI`), Node.js and NSIS. For a relocated MinGW SDK,
set Cargo's target linker and the target-specific CC/AR environment variables.
`MOUSEVPN_ACCOUNT_URL` defaults to `https://mousevpn.space/vpn`.

The output is `windows-gui/dist/MouseVPN-0.2.1-windows-setup.exe`, with SHA-256
beside it. It includes WebView2Loader, the unmodified vendored WinDivert DLL and
driver, license and upstream source notice. The Microsoft WebView2 runtime is
installed by the bootstrapper when missing. It does not ship the locally
signed test driver or enable Windows test-signing mode.

This installer is unsigned. Cross-build, NSIS integrity/content checks, DLL
imports and browser UI checks passed. Native Windows installation, networking,
driver loading and system autostart still require the Windows test checklist;
the browser fixture does not validate those operating-system integrations.
