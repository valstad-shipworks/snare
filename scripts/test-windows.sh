#!/usr/bin/env bash
# Cross-builds the workspace's tests with cargo-xwin and runs them in a Parallels Windows VM. The
# test binaries are staged under a folder the VM can see, laid out as the workspace is, with the
# interpose-probe cdylib beside their deps directory (the module-loading test loads it from there)
# and the golden files under crates/snare/tests/golden; the stage is removed afterwards.
#
# Parallels maps the Mac home folder to \\Mac\Home whether it shares all of it or, with only "Share
# Mac user folders" on, just Desktop, Documents and Downloads, so the stage must be under $HOME and,
# in the second case, under one of those three.
#
# Like the Windows CI step, each binary runs at NORMAL priority class, and on Server 2025 skips
# unread_stream_fill_matches_real_os (OPEN_BUGS.md).
#
# C code is compiled with clang rather than cargo-xwin's default clang-cl: ring (the quinn tests'
# crypto) compiles for aarch64 Windows with clang only, which rejects clang-cl's flags.
#
#   scripts/test-windows.sh [target...]       default: aarch64-pc-windows-msvc x86_64-pc-windows-msvc
#   SNARE_WINDOWS_VM="Windows 11 (1)"         VM name as `prlctl list -a` shows it
#   SNARE_WINDOWS_STAGE=~/Downloads/snare-windows-stage
#   SNARE_WINDOWS_FILTER=regex                run only test targets whose name matches
#   SNARE_PERF_SCALE=n                        passed on to the tests when set
set -euo pipefail

vm="${SNARE_WINDOWS_VM:-Windows 11 (1)}"
root="$(cd "$(dirname "$0")/.." && pwd)"
stage="${SNARE_WINDOWS_STAGE:-$HOME/Downloads/snare-windows-stage}"
filter="${SNARE_WINDOWS_FILTER:-}"
targets=("$@")
[ ${#targets[@]} -eq 0 ] && targets=(aarch64-pc-windows-msvc x86_64-pc-windows-msvc)

mkdir -p "$stage"
stage="$(cd "$stage" && pwd)"
case "$stage" in
    "$HOME"/*) ;;
    *) echo "SNARE_WINDOWS_STAGE must be under $HOME to be visible in the VM" >&2; exit 1 ;;
esac
run="$(mktemp -d "$stage/run.XXXXXX")"
log="$(mktemp -t snare-windows)"
trap 'rm -rf "$run" "$log"; rmdir "$stage" 2>/dev/null || true' EXIT

status="$(prlctl status "$vm")"
case "$status" in
    *running*) ;;
    *suspended* | *paused*) prlctl resume "$vm" >/dev/null ;;
    *) prlctl start "$vm" >/dev/null ;;
esac

perf=""
[ -n "${SNARE_PERF_SCALE:-}" ] && perf="\$env:SNARE_PERF_SCALE = '$SNARE_PERF_SCALE'; "
server2025="if ((Get-CimInstance Win32_OperatingSystem).Caption -match 'Server 2025') { \$skip = '--skip', 'unread_stream_fill_matches_real_os' }"

failed=0
summary=()
for target in "${targets[@]}"; do
    echo "== $target"
    (cd "$root" && cargo xwin build --quiet --cross-compiler clang -p interpose-probe --target "$target")
    executables=$(cd "$root" && cargo xwin test --quiet --cross-compiler clang --workspace --no-run --target "$target" --message-format json \
        | jq -r --arg filter "$filter" \
            'select(.reason == "compiler-artifact" and .profile.test and .executable != null
                    and (.target.name | test($filter))) | .executable')

    debug="$run/target/$target/debug"
    mkdir -p "$debug/deps" "$run/crates/snare/tests"
    cp "$root/target/$target/debug/interpose_probe.dll" "$debug/"
    cp -R "$root/crates/snare/tests/golden" "$run/crates/snare/tests/"
    for exe in $executables; do
        cp "$exe" "$debug/deps/"
    done

    for exe in $executables; do
        name="$(basename "$exe")"
        windows_path="\\\\Mac\\Home\\${debug#"$HOME"/}/deps/$name"
        windows_path="${windows_path//\//\\}"
        echo "-- $name"
        # prlctl exec now and then fails to start the job or collect its result, printing only a
        # PrlJob_* error; the binary has then produced no output, so it is run again.
        for _ in 1 2 3; do
            code=0
            prlctl exec "$vm" --current-user powershell -NoProfile -Command \
                "(Get-Process -Id \$PID).PriorityClass = 'Normal'; ${perf}\$skip = @(); $server2025; & '$windows_path' @skip; exit \$LASTEXITCODE" \
                2>&1 | tee "$log" || code=$?
            [ "$code" -ne 0 ] && ! grep -qv '^PrlJob_' "$log" || break
        done
        [ "$code" -eq 0 ] || failed=1
        counts=$(sed -n 's/^test result: [A-Za-z]*\. \([0-9]*\) passed; \([0-9]*\) failed; \([0-9]*\) ignored.*/\1 \2 \3/p' "$log" \
            | awk '{ p += $1; f += $2; i += $3 } END { printf "%d passed, %d failed, %d ignored", p, f, i }')
        summary+=("$target $name: $counts, exit $code")
        while read -r test; do
            summary+=("    FAILED $test")
        done < <(sed -n 's/^test \(.*\) \.\.\. FAILED$/\1/p' "$log")
    done
    rm -rf "${run:?}/target"
done

echo "== summary"
printf '%s\n' "${summary[@]}"
exit $failed
