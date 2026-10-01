#!/usr/bin/env bash
# Cross-builds the snare Windows Host-plane test with cargo-xwin and runs it in a Parallels Windows
# VM, which must share the Mac home folder (Parallels maps it to \\Mac\Home). Scoped to the
# `win_host` test target so the unix-only integration tests are not part of the Windows build.
#
#   scripts/test-windows-host.sh [target]    default: aarch64-pc-windows-msvc
#   SNARE_WINDOWS_VM="Windows 11"            VM name as `prlctl list` shows it
set -euo pipefail

vm="${SNARE_WINDOWS_VM:-Windows 11}"
root="$(cd "$(dirname "$0")/.." && pwd)"
target="${1:-aarch64-pc-windows-msvc}"

case "$root" in
    "$HOME"/*) ;;
    *) echo "workspace must be under $HOME to be visible in the VM" >&2; exit 1 ;;
esac

status="$(prlctl status "$vm")"
case "$status" in
    *running*) ;;
    *suspended* | *paused*) prlctl resume "$vm" >/dev/null ;;
    *) prlctl start "$vm" >/dev/null ;;
esac

echo "== $target"
exe=$(cd "$root" && cargo xwin test -p snare --no-run --test win_host --target "$target" --message-format json 2>/dev/null \
    | sed -n 's/.*"executable":"\([^"]*\)".*/\1/p')
windows_path="\\\\Mac\\Home\\${exe#"$HOME"/}"
windows_path="${windows_path//\//\\}"
echo "-- $(basename "$exe")"
prlctl exec "$vm" --current-user cmd /c "$windows_path"
