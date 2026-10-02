#!/usr/bin/env bash
# Build the Windows x64 NSIS installer on Linux using MinGW and Tauri CLI.
set -euo pipefail
repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
target=x86_64-pc-windows-gnu
target_dir="${CARGO_TARGET_DIR:-$repo_root/target}"
tauri_cli="${TAURI_CLI:-tauri}"
version=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["version"])' "$repo_root/windows-gui/src-tauri/tauri.conf.json")
export MOUSEVPN_ACCOUNT_URL="${MOUSEVPN_ACCOUNT_URL:-https://mousevpn.space/vpn}"
command -v "$tauri_cli" >/dev/null || { echo 'Tauri CLI is required on PATH (or set TAURI_CLI).' >&2; exit 1; }
cd "$repo_root"
cargo build -p mousevpn-windows-gui --target "$target" --release --features custom-protocol
cd "$repo_root/windows-gui/src-tauri"
"$tauri_cli" bundle --target "$target" --bundles nsis --config tauri.windivert.conf.json
dist="$repo_root/windows-gui/dist"
mkdir -p "$dist"
name="MouseVPN-${version}-windows-setup.exe"
cp "$target_dir/$target/release/bundle/nsis/MouseVPN_${version}_x64-setup.exe" "$dist/$name"
(cd "$dist"; sha256sum "$name" > "$name.sha256")
printf 'Installer: %s\n' "$dist/$name"
