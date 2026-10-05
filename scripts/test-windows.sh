#!/usr/bin/env bash
# Cross-builds the workspace's tests with cargo-xwin and runs them in a Parallels Windows VM,
# which must share the Mac home folder (Parallels maps it to \\Mac\Home).
#
#   scripts/test-windows.sh [target...]    default: aarch64-pc-windows-msvc x86_64-pc-windows-msvc
#   SNARE_WINDOWS_VM="Windows 11"          VM name as `prlctl list` shows it
set -euo pipefail

vm="${SNARE_WINDOWS_VM:-Windows 11}"
root="$(cd "$(dirname "$0")/.." && pwd)"
targets=("$@")
[ ${#targets[@]} -eq 0 ] && targets=(aarch64-pc-windows-msvc x86_64-pc-windows-msvc)

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

failed=0
for target in "${targets[@]}"; do
    echo "== $target"
    # Build the whole workspace so cdylib test fixtures exist beside the test binaries.
    (cd "$root" && cargo xwin build --workspace --target "$target" >/dev/null 2>&1)
    executables=$(cd "$root" && cargo xwin test --no-run --target "$target" --message-format json 2>/dev/null \
        | sed -n 's/.*"executable":"\([^"]*\)".*/\1/p')
    for exe in $executables; do
        windows_path="\\\\Mac\\Home\\${exe#"$HOME"/}"
        windows_path="${windows_path//\//\\}"
        echo "-- $(basename "$exe")"
        prlctl exec "$vm" --current-user cmd /c "$windows_path" || failed=1
    done
done
exit $failed
