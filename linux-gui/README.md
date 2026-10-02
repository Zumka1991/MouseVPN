# MouseVPN for Linux

Desktop client built with Tauri 2 and the existing MouseVPN Rust runtime.

## Account and subscription (0.2.0)

- Sign in with the same email and password as Android. The app uses
  `https://mousevpn.space/vpn`, with the existing fallback service for sign-in.
- View subscription expiry and the shared two-device limit; revoke an old
  device and register this computer without creating a new key on each login.
- Assigned servers update automatically; removing access or expiring the
  subscription stops an active managed connection. Server-side leases enforce
  access independently of the desktop UI.
- Select one protocol mode for all subscription servers. Imported legacy keys
  retain their own mode and are preserved on sign-in and sign-out.
- Create support tickets and read administration messages, including after
  expiry. An open conversation refreshes every three seconds; drafts and loaded
  older messages remain in place. The account and unread badge refresh every
  thirty seconds while the app is running. These are foreground updates, not
  push notifications when the application is closed.
- Account session and device identities are stored under
  `$XDG_CONFIG_HOME/mousevpn` (normally `~/.config/mousevpn`), in private `0600`
  files and `0700` directories. The password is not stored. Unlike the Windows
  DPAPI store, these files are protected by Unix file permissions, not an OS
  keyring. Sign-out removes subscription profiles and the session, retaining
  the device identity for a subsequent login.

## VPN features

- supports the optional **Speedy** protocol with minimal header masking,
  no padding or handshake cover traffic, and separate reliability history;
  requires a server built with [Speedy support](../docs/SPEEDY.md). Existing
  profiles keep their selected protocol, with Legacy as the default;

- imports encrypted `MV1.…` profiles with their password;
- stores one private TOML file per profile under
  `$XDG_CONFIG_HOME/mousevpn/profiles` (or `~/.config/mousevpn/profiles`) with
  mode `0600`;
- selects and deletes profiles;
- connects through a short-lived privileged helper started by PolicyKit;
- disconnects gracefully so the runtime removes its routes, DNS settings and
  isolated nftables table;
- treats temporary Wi-Fi and gateway failures as reconnectable conditions and
  refreshes the server host route without removing TUN, DNS or firewall state;
- refreshes the physical server route periodically, retries a corrupt handshake
  within the original timeout and safely applies changed tunnel IP, MTU or DNS
  parameters during reconnect;
- rejects global IPv6 instead of dropping it, so dual-stack applications fail
  over to IPv4 at once rather than stalling on a connect timeout, while
  link-local and link-scoped multicast IPv6 stay available for neighbour
  discovery;
- keeps IPv4 DHCP renewal working while connected, so a lease expiring mid
  session no longer takes the tunnel down with it;
- allows direct access to the VPN server's IPv4 address on all ports, so websites
  and other services on that address remain reachable while connected. This
  traffic bypasses the tunnel; other destinations remain subject to the kill
  switch;
- starts a privileged watchdog that removes only MouseVPN's nftables table and
  marked server route if the tunnel helper is killed before Rust cleanup runs;
- shows reconnect progress in the GUI and keeps a rotated helper log under
  `$XDG_DATA_HOME/MouseVPN/logs` (normally
  `~/.local/share/MouseVPN/logs`);
- passively records per-profile reliability for every protocol mode: missed
  keepalive replies, RTT, reconnects, recovery failures, migrations, packet
  counts and send drops. It reuses the normal ten-second keepalive, adds no
  probe traffic, and recommends a mode only after at least five minutes and 20
  keepalives have been observed in two modes. History is stored locally under
  `$XDG_DATA_HOME/MouseVPN/diagnostics`;
- keeps running in the system tray when the main window is closed, with tray
  actions to reopen, disconnect or quit;
- publishes the tray through the freedesktop/KDE StatusNotifier D-Bus protocol,
  so it does not require `libappindicator` at runtime;
- keeps the Tauri webview and profile management unprivileged;
- ships a small standalone privileged helper in the AppImage and copies it to
  the user's private cache before PolicyKit starts it; root never needs to
  execute a binary through the user's FUSE mount.

The helper mode is part of the same executable. The GUI invokes it as:

```text
pkexec mousevpn-linux-gui --helper --config <profile.toml>
```

No password or private key is passed on the command line. PolicyKit elevation
is requested only when the user connects.

## Development build

Tauri uses the system WebKitGTK. On Arch/CachyOS install:

```sh
sudo pacman -S --needed webkit2gtk-4.1 gtk3 base-devel
```

Debian/Ubuntu development packages use the names `libwebkit2gtk-4.1-dev` and
`libgtk-3-dev`. Then build or run from the repository root:

```sh
cargo build -p mousevpn-linux-gui
cargo run -p mousevpn-linux-gui
```

To produce a `.deb` and AppImage compatible with Ubuntu 22.04 and newer from
any Docker host, run:

```sh
./linux-gui/build-ubuntu22.sh
```

If the host VPN prevents Docker bridge networking from reaching package
repositories, the build can use the host network without changing VPN rules:

```sh
MOUSEVPN_BUILD_NETWORK=host MOUSEVPN_RUN_NETWORK=host ./linux-gui/build-ubuntu22.sh
```

The container's Cargo build defaults to four jobs; override `CARGO_BUILD_JOBS`
to adjust memory use. Artifact names follow the version in `tauri.conf.json`.

For native packaging on a configured Ubuntu/Zorin x64 build host with the
Tauri CLI, `curl`, `dpkg-deb`, `pkg-config` and Python 3 installed, run
`./linux-gui/build-native.sh`. It produces `.deb` and AppImage in `linux-gui/dist`,
adds the standalone helper and records the host glibc minimum in the `.deb`.
The published 0.2.0 native build was built and launched on Zorin OS 18.1
(Ubuntu 24.04, glibc 2.39); it is not an Ubuntu 22.04 build. Use the Docker
workflow above to produce a separate older-baseline build.

The artifacts are written to `linux-gui/dist`. The build deliberately leaves
Wayland client libraries out of the AppImage: they must match the host's EGL
graphics driver. Bundling the Ubuntu copies can make WebKit abort with
`EGL_BAD_PARAMETER` and display a blank window on rolling distributions such
as Arch/CachyOS. It also repacks with the current AppImage runtime, which uses
FUSE 3 and does not require the legacy `libfuse.so.2` compatibility package.

## Runtime support

The current networking backend requires:

- Linux with TUN support;
- `nftables` and `iproute2`;
- `systemd-resolved` with `resolvectl`;
- PolicyKit with `pkexec`;
- WebKitGTK 4.1.

This covers current Arch/CachyOS, Fedora, openSUSE and Debian/Ubuntu systems
configured with `systemd-resolved`. Supporting NetworkManager DNS directly and
non-systemd resolvers is a separate backend task; the GUI must not claim those
systems work until that implementation is tested.

The desktop panel must expose a StatusNotifier host. KDE Plasma, Ubuntu with
its AppIndicator extension, Noctalia and Waybar with the `tray` module provide
one.
