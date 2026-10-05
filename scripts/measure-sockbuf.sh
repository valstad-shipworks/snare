#!/usr/bin/env bash
# Measures a real kernel's UDP socket-buffer accounting on x86_64 and arm64, for the Linux model
# in crates/snare/src/limits.rs. A container's kernel is the Docker VM's (on an arm64 Mac, arm64
# even for `--platform linux/amd64`), so this boots Debian's stock kernel of each architecture
# under QEMU (TCG) with scripts/sockbuf-probe.c, built static, as the initramfs's /init, and
# prints what it measured. With TESTS it also builds those snare integration tests for each
# architecture and runs them in the VM after the probe, so `*_os_truth` tests compare the sim with
# that kernel.
#
#   scripts/measure-sockbuf.sh [max-len]    default 17000; output also in target/sockbuf-<suite>-<arch>.txt
#   ARCHES="amd64"                          the Debian architectures to boot (default amd64 arm64)
#   KERNEL_SUITE=sid                        the Debian suite to take the kernel from (default trixie)
#   TESTS="socket_limits os_parity"         snare test targets to run in the VM (default none);
#                                           built in docker volumes snare-measure-target-<arch>
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
max="${1:-17000}"
mkdir -p "$root/target"

for arch in ${ARCHES:-amd64 arm64}; do
    out="$root/target/vm-tests-$arch"
    rm -rf "$out"
    mkdir -p "$out"
    [ -z "${TESTS:-}" ] && continue
    targets=$(printf -- '--test %s ' $TESTS)
    docker run --rm --platform "linux/$arch" -v "$root":/work:ro -w /work \
        -v "snare-measure-target-$arch":/tmp/target -e CARGO_TARGET_DIR=/tmp/target \
        -v "$out":/out rust:latest bash -c "
            set -euo pipefail
            cargo test -p snare --no-run --message-format=json $targets 2>/dev/null \
                | grep -o '\"executable\":\"[^\"]*\"' | cut -d'\"' -f4 > /tmp/exes
            mkdir -p /out/tests
            for exe in \$(cat /tmp/exes); do
                cp \"\$exe\" /out/tests/
                ldd \"\$exe\" | grep -o '/[^ ]*' | xargs -I{} cp -L --parents {} /out/
            done"
done

docker run --rm -i -e ARCHES -e KERNEL_SUITE -v "$root/scripts":/scripts:ro -v "$root/target":/out \
    debian:trixie bash -s "$max" <<'EOF'
set -euo pipefail
max="$1"
dpkg --add-architecture amd64
dpkg --add-architecture arm64
suite="${KERNEL_SUITE:-trixie}"
echo "deb http://deb.debian.org/debian $suite main" > /etc/apt/sources.list.d/kernel.list
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq qemu-system-x86 qemu-system-arm cpio gcc \
    gcc-x86-64-linux-gnu libc6-dev-amd64-cross gcc-aarch64-linux-gnu libc6-dev-arm64-cross \
    >/dev/null 2>&1
cd /tmp
native=$(dpkg --print-architecture)
for arch in ${ARCHES:-amd64 arm64}; do
    apt-get download "linux-image-$arch:$arch/$suite" >/dev/null 2>&1
    meta=$(ls linux-image-${arch}_*.deb)
    image=$(dpkg-deb -f "$meta" Depends | tr ',' '\n' | grep -o 'linux-image-[0-9][^ ]*' | head -1)
    apt-get download "$image:$arch/$suite" >/dev/null 2>&1
    mkdir -p "k-$arch" && dpkg-deb -x "$image"_*.deb "k-$arch"
    # Debian 7.x kernels moved vmlinuz into a linux-binary-<version> package.
    binary=$(dpkg-deb -f "$image"_*.deb Depends | tr ',' '\n' | grep -o 'linux-binary-[0-9][^ ]*' | head -1 || true)
    if [ -n "$binary" ]; then
        apt-get download "$binary:$arch/$suite" >/dev/null 2>&1
        dpkg-deb -x "$binary"_*.deb "k-$arch"
    fi
    case $arch in
        "$native") cc=gcc ;;
        amd64) cc=x86_64-linux-gnu-gcc ;;
        arm64) cc=aarch64-linux-gnu-gcc ;;
    esac
    mkdir -p "rd-$arch"
    $cc -O2 -static -o "rd-$arch/init" /scripts/sockbuf-probe.c
    mkdir -p "rd-$arch/proc" "rd-$arch/dev" "rd-$arch/tmp"
    cp -a "/out/vm-tests-$arch/." "rd-$arch/"
    (cd "rd-$arch" && find . | cpio -o -H newc 2>/dev/null) > "initrd-$arch"
    kernel=$(find "k-$arch" -type f -name 'vmlinuz*' | head -1)
    case $arch in
        amd64) qemu=(qemu-system-x86_64 -M pc -cpu max -append "console=ttyS0 quiet panic=-1 -- $max") ;;
        arm64) qemu=(qemu-system-aarch64 -M virt -cpu max -append "console=ttyAMA0 quiet panic=-1 -- $max") ;;
    esac
    "${qemu[@]}" -m 4096 -smp 1 -nographic -no-reboot -kernel "$kernel" -initrd "initrd-$arch" \
        | tr -d '\r' \
        | grep -aoE '(== .*|/proc/sys.*|udp default.*|tcp default.*|set -?[0-9]+ ->.*|meminfo.*|overflow rcvbuf.*|truesize .*|test .*|thread .*|  left.*|  right.*)' \
        | { echo "== package $image"; cat; } | tee "/out/sockbuf-$suite-$arch.txt"
done
EOF
