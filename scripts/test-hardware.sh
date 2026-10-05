#!/usr/bin/env bash
# Runs snare's hardware truth tests (crates/snare/tests/hw_*.rs) on this Linux machine and writes
# a report of what passed, failed and was skipped (with the reason) and what was noted. The tests
# run with `--include-ignored hw_`, one at a time. Builds as the invoking user; with --sudo only
# the test binaries run as root.
#
#   scripts/test-hardware.sh [options]
#     --iface IF          the NIC under test (SNARE_HW_IFACE; default: auto-detected by the tests)
#     --ptp DEV           its PTP clock, e.g. /dev/ptp0 (SNARE_HW_PTP; default: the NIC's PHC)
#     --peer IP[:PORT]    a second machine running the reflector (SNARE_HW_PEER)
#     --mutate            let tests change NIC, timestamping and qdisc settings; each is restored
#                         (SNARE_HW_MUTATE=1). Without it nothing on the machine is changed.
#     --sudo              run the test binaries under sudo (root: CAP_NET_ADMIN, CAP_SYS_NICE, ...)
#     --report FILE       where the report goes (default target/hardware-report.txt)
#     --dry-run           print what was found and what would be touched, run nothing
#     --reflector         instead of testing, serve as the peer: echo UDP until idle or `quit`
#     --port N --secs N   the reflector's port (default 47000) and idle limit (default 600 s)
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
report="$root/target/hardware-report.txt"
iface="" ptp="" peer="" mutate=0 sudo="" dry=0 reflector=0 port=47000 secs=600

while [ $# -gt 0 ]; do
    case "$1" in
        --iface) iface="$2"; shift ;;
        --ptp) ptp="$2"; shift ;;
        --peer) peer="$2"; shift ;;
        --mutate) mutate=1 ;;
        --sudo) sudo="sudo" ;;
        --report) report="$2"; shift ;;
        --dry-run) dry=1 ;;
        --reflector) reflector=1 ;;
        --port) port="$2"; shift ;;
        --secs) secs="$2"; shift ;;
        -h | --help) sed -n '2,20p' "$0"; exit 0 ;;
        *) echo "unknown option $1" >&2; exit 2 ;;
    esac
    shift
done

[ "$(uname -s)" = Linux ] || { echo "the Linux hardware tests run on Linux; use scripts/test-hardware.ps1 on Windows" >&2; exit 2; }

# The test executables of the hw_* targets, built as the invoking user.
build() {
    [ $# -gt 0 ] || set -- --test 'hw_*'
    (cd "$root" && cargo test -p snare --no-run --message-format json "$@" 2>/dev/null) \
        | grep '"kind":\["test"\]' | grep '"name":"hw_' \
        | sed -n 's/.*"executable":"\([^"]*\)".*/\1/p'
}

if [ "$reflector" = 1 ]; then
    exe=$(build --test hw_peer_reflector)
    [ -n "$exe" ] || { echo "could not build hw_peer_reflector" >&2; exit 1; }
    echo "reflecting UDP on port $port until $secs s pass without traffic; stop the tests' machine's side with a 'quit' datagram or Ctrl-C"
    SNARE_HW_REFLECT=1 SNARE_HW_REFLECT_PORT="$port" SNARE_HW_REFLECT_SECS="$secs" \
        "$exe" --include-ignored hw_peer_reflector --nocapture
    exit $?
fi

cap_eff=$(sed -n 's/^CapEff:\s*//p' /proc/self/status)
[ -n "$sudo" ] && cap_eff="(root under sudo)"
echo "== machine"
echo "kernel:   $(uname -r) $(uname -v)"
echo "realtime: $(cat /sys/kernel/realtime 2>/dev/null || echo 'no /sys/kernel/realtime')"
echo "user:     $(id -un) uid $(id -u), CapEff $cap_eff"
echo "NICs:"
for dir in /sys/class/net/*; do
    name=$(basename "$dir")
    [ -e "$dir/device" ] || continue
    driver=$(basename "$(readlink -f "$dir/device/driver" 2>/dev/null)" 2>/dev/null || true)
    printf '  %-12s driver %-10s operstate %s\n' "$name" "${driver:-?}" "$(cat "$dir/operstate" 2>/dev/null)"
done
echo "PTP clocks: $(ls /dev/ptp* 2>/dev/null | tr '\n' ' ' || true)"
echo
echo "== settings"
echo "SNARE_HW_IFACE=${iface:-(auto)} SNARE_HW_PTP=${ptp:-(auto)} SNARE_HW_PEER=${peer:-(none)} SNARE_HW_MUTATE=$mutate"
if [ "$mutate" = 1 ]; then
    target="${iface:-the auto-detected NIC}"
    echo "WILL CHANGE, then restore, on $target:"
    echo "  ethtool ring sizes, coalescing, channels, flow control and EEE (hw_ethtool_truth)"
    echo "  the hardware timestamping configuration, SIOCSHWTSTAMP (hw_timestamping_truth)"
    echo "  the root qdisc: mq with etf children, then the kernel default again (hw_txtime_truth)"
    echo "  some drivers reset the port for ring and channel changes: expect a short link drop"
else
    echo "read-only: no NIC, timestamping or qdisc setting is changed (pass --mutate to test changes)"
fi
[ -n "$peer" ] && echo "sends UDP to the reflector at $peer"
[ "$dry" = 1 ] && exit 0

executables=$(build)
[ -n "$executables" ] || { echo "no hw_* test executables were built" >&2; exit 1; }

mkdir -p "$(dirname "$report")"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
log="${report%.txt}.log"
: > "$log"
skips="$work/skips.txt"
: > "$skips"
chmod a+rw "$skips" "$work"

envs=(SNARE_HW_REPORT="$skips")
[ -n "$iface" ] && envs+=(SNARE_HW_IFACE="$iface")
[ -n "$ptp" ] && envs+=(SNARE_HW_PTP="$ptp")
[ -n "$peer" ] && envs+=(SNARE_HW_PEER="$peer")
[ "$mutate" = 1 ] && envs+=(SNARE_HW_MUTATE=1)

for exe in $executables; do
    echo "== $(basename "$exe")" | tee -a "$log"
    $sudo env "${envs[@]}" "$exe" --include-ignored hw_ --test-threads=1 2>&1 | tee -a "$log" \
        | grep -E '^test .* \.\.\. ' || true
done

passed=() failed=() skipped=() notes=()
while IFS= read -r line; do
    name=$(echo "$line" | sed -n 's/^test \([^ ]*\) \.\.\. .*/\1/p')
    [ -n "$name" ] || continue
    case "$line" in
        *"... ok")
            reason=$(awk -F'\t' -v n="$name" '$1 == "SKIP" && $2 == n { print $3; exit }' "$skips")
            if [ -n "$reason" ]; then skipped+=("$name: $reason"); else passed+=("$name"); fi ;;
        *"... FAILED") failed+=("$name") ;;
    esac
done < <(grep -E '^test [^ ]+ \.\.\. (ok|FAILED)$' "$log")
while IFS=$'\t' read -r kind name text; do
    [ "$kind" = NOTE ] && notes+=("$name: $text")
done < "$skips"

{
    echo "snare hardware truth tests, $(date -u +%Y-%m-%dT%H:%M:%SZ) on $(hostname)"
    echo "kernel $(uname -r) $(uname -v)"
    echo "SNARE_HW_IFACE=${iface:-(auto)} SNARE_HW_PTP=${ptp:-(auto)} SNARE_HW_PEER=${peer:-(none)} SNARE_HW_MUTATE=$mutate sudo=${sudo:-no}"
    echo
    echo "PASSED (${#passed[@]})"
    for t in "${passed[@]}"; do echo "  $t"; done
    echo "FAILED (${#failed[@]}) - details in $log"
    for t in "${failed[@]}"; do
        echo "  $t"
        awk -v n="$t" '$0 ~ "^thread '\''" n "'\''" { show = 1 } show && /^note: run with/ { show = 0 } show { print "    " $0 }' "$log" | head -40
    done
    echo "SKIPPED (${#skipped[@]})"
    for t in "${skipped[@]}"; do echo "  $t"; done
    echo "NOTES (${#notes[@]})"
    for t in "${notes[@]}"; do echo "  $t"; done
} > "$report"

echo
cat "$report"
[ ${#failed[@]} -eq 0 ]
