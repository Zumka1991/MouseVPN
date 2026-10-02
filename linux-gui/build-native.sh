#!/usr/bin/env bash
# Native x64 Linux packaging. Compatibility starts at the build host's glibc.
set -euo pipefail
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd -- "$script_dir/.." && pwd)"
target_dir="${CARGO_TARGET_DIR:-$repo_dir/target}"
version="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["version"])' "$script_dir/src-tauri/tauri.conf.json")"
export APPIMAGE_EXTRACT_AND_RUN=1
# Multiarch Ubuntu/Zorin has /usr/lib64 but stores GTK typelibs elsewhere.
export LD_GTK_LIBRARY_PATH="${LD_GTK_LIBRARY_PATH:-$(pkg-config --variable=libdir gtk+-3.0)}"
if [[ "${MOUSEVPN_SKIP_BUILD:-0}" != 1 ]]; then
  (cd "$script_dir/src-tauri"; cargo build --release --bin mousevpn-helper; cargo tauri build --bundles deb,appimage)
fi
appdir="$target_dir/release/bundle/appimage/MouseVPN.AppDir"
for library in client cursor egl server; do
  rm -f "$appdir/usr/lib/libwayland-$library.so.0" "$appdir/usr/lib/libwayland-$library.so.1"
done
install -D -m 0755 "$target_dir/release/mousevpn-helper" "$appdir/usr/lib/mousevpn/mousevpn-helper"
tool="$target_dir/.tools/appimagetool-modern-x86_64.AppImage"
mkdir -p "$(dirname "$tool")" "$script_dir/dist"
if [[ ! -x "$tool" ]]; then
  curl -fL --retry 2 https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage -o "$tool.tmp"
  chmod 0755 "$tool.tmp"
  mv "$tool.tmp" "$tool"
fi
ARCH=x86_64 "$tool" "$appdir" "$script_dir/dist/MouseVPN_${version}_linux_amd64.AppImage"
# Tauri lists GTK dependencies but does not constrain the build's libc ABI.
package_dir="$(mktemp -d)"
trap 'rm -rf -- "$package_dir"' EXIT
dpkg-deb --raw-extract "$target_dir/release/bundle/deb/MouseVPN_${version}_amd64.deb" "$package_dir"
minimum_glibc="$(getconf GNU_LIBC_VERSION | cut -d ' ' -f 2)"
python3 - "$package_dir/DEBIAN/control" "$minimum_glibc" <<'PY'
import sys
from pathlib import Path
path=Path(sys.argv[1]);lines=path.read_text().splitlines()
for i,line in enumerate(lines):
    if line.startswith('Depends:'):
        lines[i]=line+', xdg-utils, libc6 (>= '+sys.argv[2]+')'
        break
else:
    raise SystemExit('Missing package dependency metadata')
path.write_text('\n'.join(lines)+'\n')
PY
dpkg-deb --root-owner-group --build "$package_dir" "$script_dir/dist/MouseVPN_${version}_linux_amd64.deb"
(cd "$script_dir/dist"; sha256sum "MouseVPN_${version}_linux_amd64.deb" "MouseVPN_${version}_linux_amd64.AppImage" > SHA256SUMS)
