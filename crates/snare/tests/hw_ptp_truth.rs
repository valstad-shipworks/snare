#![cfg(target_os = "linux")]

//! A real PTP hardware clock against the `SimHost`'s `/dev/ptp<N>` model: the same calls on the
//! real character device and on the sim's must succeed or fail alike and fill the same slots in
//! the same order. Covered: `PTP_CLOCK_GETCAPS`, `PTP_SYS_OFFSET` (including a sample count past
//! `PTP_MAX_SAMPLES`), `PTP_SYS_OFFSET_PRECISE`, `PTP_SYS_OFFSET_EXTENDED`, and
//! `clock_gettime`/`clock_getres` on the dynamic clock id of the open device.
//!
//! Request numbers and layouts are include/uapi/linux/ptp_clock.h (`_IOR`/`_IOW`/`_IOWR` of
//! include/uapi/asm-generic/ioctl.h); the checks are drivers/ptp/ptp_chardev.c `ptp_ioctl`; the
//! dynamic clock id is `FD_TO_CLOCKID` of Documentation/driver-api/ptp.rst and
//! include/linux/posix-timers.h (`(~fd << 3) | CLOCKFD`, `CLOCKFD` 3).

#[path = "support/hw.rs"]
mod hw;

use std::ffi::CString;
use std::path::Path;

use hw::need;
use snare::{HostProfile, Privileges, PtpCaps, Sim};

const PTP_MAX_SAMPLES: u32 = 25;

/// `_IOC(dir, '=', nr, size)`: direction in bits 30..32 (1 write, 2 read), size in 16..30.
const fn ioc(dir: u64, nr: u64, size: u64) -> u64 {
    (dir << 30) | (size << 16) | ((b'=' as u64) << 8) | nr
}
/// `struct ptp_clock_caps`: 20 ints.
const PTP_CLOCK_GETCAPS: u64 = ioc(2, 1, 80);
/// `struct ptp_sys_offset`: `n_samples`, `rsv[3]`, `ts[2 * PTP_MAX_SAMPLES + 1]` of 16 bytes.
const PTP_SYS_OFFSET: u64 = ioc(1, 5, 16 + (2 * 25 + 1) * 16);
/// `struct ptp_sys_offset_precise`: three `ptp_clock_time`s and `rsv[4]`.
const PTP_SYS_OFFSET_PRECISE: u64 = ioc(3, 8, 64);
/// `struct ptp_sys_offset_extended`: `n_samples`, `clockid`, `rsv[2]`, `ts[PTP_MAX_SAMPLES][3]`.
const PTP_SYS_OFFSET_EXTENDED: u64 = ioc(3, 9, 16 + 25 * 3 * 16);

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn ptp_index(path: &Path) -> Option<u32> {
    path.to_str()?.strip_prefix("/dev/ptp")?.parse().ok()
}

/// A `ptp_clock_time` at `at`: (sec, nsec).
fn clock_time(b: &[u8], at: usize) -> (i64, u32) {
    (
        i64::from_ne_bytes(b[at..at + 8].try_into().unwrap()),
        u32::from_ne_bytes(b[at + 8..at + 12].try_into().unwrap()),
    )
}

fn nanos((s, ns): (i64, u32)) -> i128 {
    i128::from(s) * 1_000_000_000 + i128::from(ns)
}

/// What one call left: its errno, which of its timestamps are non-zero, whether the system
/// readings it brackets the device with are in order, and whether every device reading sits
/// within a day of its system reading (the shape, not the values: a PHC may keep TAI).
#[derive(Debug, PartialEq, Eq)]
struct Shape {
    rc: Result<(), i32>,
    filled: Vec<bool>,
    ordered: bool,
    near: bool,
}

fn ioctl(fd: i32, request: u64, buf: &mut [u8]) -> Result<(), i32> {
    let rc = unsafe { libc::ioctl(fd, request as _, buf.as_mut_ptr()) };
    if rc == 0 { Ok(()) } else { Err(errno()) }
}

fn sys_offset(fd: i32, n: u32) -> Shape {
    let mut buf = vec![0u8; 16 + 51 * 16];
    buf[..4].copy_from_slice(&n.to_ne_bytes());
    let rc = ioctl(fd, PTP_SYS_OFFSET, &mut buf);
    let n = n.min(PTP_MAX_SAMPLES) as usize;
    let ts: Vec<(i64, u32)> = (0..2 * n + 1)
        .map(|i| clock_time(&buf, 16 + 16 * i))
        .collect();
    let sys: Vec<i128> = ts.iter().step_by(2).map(|&t| nanos(t)).collect();
    Shape {
        rc,
        filled: ts.iter().map(|&t| t != (0, 0)).collect(),
        ordered: sys.windows(2).all(|w| w[0] <= w[1]),
        near: (0..n)
            .all(|i| (nanos(ts[2 * i + 1]) - nanos(ts[2 * i])).abs() < 1_000_000_000 * 3600 * 24),
    }
}

fn precise(fd: i32) -> Shape {
    let mut buf = vec![0u8; 64];
    let rc = ioctl(fd, PTP_SYS_OFFSET_PRECISE, &mut buf);
    let ts: Vec<(i64, u32)> = (0..3).map(|i| clock_time(&buf, 16 * i)).collect();
    Shape {
        rc,
        filled: ts.iter().map(|&t| t != (0, 0)).collect(),
        ordered: true,
        near: rc.is_err() || (nanos(ts[0]) - nanos(ts[1])).abs() < 1_000_000_000 * 3600 * 24,
    }
}

fn extended(fd: i32, n: u32) -> Shape {
    let mut buf = vec![0u8; 16 + 25 * 48];
    buf[..4].copy_from_slice(&n.to_ne_bytes());
    let rc = ioctl(fd, PTP_SYS_OFFSET_EXTENDED, &mut buf);
    let n = n.min(PTP_MAX_SAMPLES) as usize;
    let ts: Vec<[(i64, u32); 3]> = (0..n)
        .map(|i| std::array::from_fn(|j| clock_time(&buf, 16 + 48 * i + 16 * j)))
        .collect();
    Shape {
        rc,
        filled: ts.iter().flatten().map(|&t| t != (0, 0)).collect(),
        ordered: ts.iter().all(|s| nanos(s[0]) <= nanos(s[2])),
        near: true,
    }
}

/// `PTP_CLOCK_GETCAPS`: its errno, and the capability words (`max_adj` and the reserved words
/// excepted, which no model is asked to match).
fn caps(fd: i32) -> (Result<(), i32>, Vec<i32>) {
    let mut buf = vec![0u8; 80];
    let rc = ioctl(fd, PTP_CLOCK_GETCAPS, &mut buf);
    let words = (1..9)
        .map(|i| i32::from_ne_bytes(buf[4 * i..4 * i + 4].try_into().unwrap()))
        .collect();
    (rc, words)
}

fn open(path: &Path, flags: i32) -> Result<i32, i32> {
    let c = CString::new(path.to_str().unwrap()).unwrap();
    let fd = unsafe { libc::open(c.as_ptr(), flags | libc::O_CLOEXEC) };
    if fd >= 0 { Ok(fd) } else { Err(errno()) }
}

/// A sim exposing `/dev/ptp<index>` with the capabilities the real clock reports
/// (`PTP_CLOCK_GETCAPS`; the defaults when it cannot be read).
fn sim(index: u32) -> Sim {
    let path = std::path::PathBuf::from(format!("/dev/ptp{index}"));
    let caps = snare::real(|| {
        let fd = open(&path, libc::O_RDONLY).ok()?;
        let mut buf = vec![0u8; 80];
        let rc = ioctl(fd, PTP_CLOCK_GETCAPS, &mut buf);
        unsafe { libc::close(fd) };
        rc.ok()?;
        let words: [i32; 9] =
            std::array::from_fn(|i| i32::from_ne_bytes(buf[4 * i..4 * i + 4].try_into().unwrap()));
        Some(PtpCaps::from_words(words))
    })
    .unwrap_or_default();
    let host = HostProfile::new().ptp_clock_caps(index, caps).build();
    Sim::builder()
        .host(host)
        .privileges(Privileges::from_real_process().unwrap())
        .build()
}

fn usable_ptp() -> Option<(std::path::PathBuf, u32)> {
    let path = hw::hw().ptp.clone()?;
    let index = ptp_index(&path)?;
    snare::real(|| open(&path, libc::O_RDONLY).map(|fd| unsafe { libc::close(fd) }))
        .ok()
        .map(|_| (path, index))
}

const NEEDS_PTP: &str =
    "needs a readable PTP clock (set SNARE_HW_PTP=/dev/ptpN; /dev/ptp* is usually root-only)";

#[test]
#[ignore = "hardware: needs a PTP hardware clock"]
fn hw_ptp_offset_ioctls_match() {
    let (path, index) = need!(usable_ptp(), "{NEEDS_PTP}");
    let probe = || {
        let fd = open(&path, libc::O_RDONLY).unwrap();
        let out = (
            sys_offset(fd, 5),
            sys_offset(fd, PTP_MAX_SAMPLES),
            sys_offset(fd, PTP_MAX_SAMPLES + 1).rc,
            sys_offset(fd, 0),
            precise(fd),
            extended(fd, 5),
            extended(fd, PTP_MAX_SAMPLES + 1).rc,
        );
        unsafe { libc::close(fd) };
        out
    };
    let real = snare::real(probe);
    let simulated = sim(index).run(probe);
    eprintln!("{path:?}: real {real:#?}");
    assert_eq!(simulated.0, real.0, "PTP_SYS_OFFSET n_samples 5");
    assert_eq!(
        simulated.1, real.1,
        "PTP_SYS_OFFSET n_samples PTP_MAX_SAMPLES"
    );
    assert_eq!(simulated.2, real.2, "PTP_SYS_OFFSET past PTP_MAX_SAMPLES");
    assert_eq!(simulated.3, real.3, "PTP_SYS_OFFSET n_samples 0");
    assert_eq!(
        simulated.4, real.4,
        "PTP_SYS_OFFSET_PRECISE (cross timestamping)"
    );
    assert_eq!(simulated.5, real.5, "PTP_SYS_OFFSET_EXTENDED n_samples 5");
    assert_eq!(
        simulated.6, real.6,
        "PTP_SYS_OFFSET_EXTENDED past PTP_MAX_SAMPLES"
    );
}

#[test]
#[ignore = "hardware: needs a PTP hardware clock"]
fn hw_ptp_caps_match() {
    let (path, index) = need!(usable_ptp(), "{NEEDS_PTP}");
    let probe = || {
        let fd = open(&path, libc::O_RDONLY).unwrap();
        let out = caps(fd);
        unsafe { libc::close(fd) };
        out
    };
    let real = snare::real(probe);
    let simulated = sim(index).run(probe);
    assert_eq!(
        simulated.0, real.0,
        "PTP_CLOCK_GETCAPS (real caps: n_alarm, n_ext_ts, n_per_out, pps, n_pins, cross_timestamping, adjust_phase, max_phase_adj = {:?})",
        real.1
    );
}

/// `FD_TO_CLOCKID`.
fn clockid(fd: i32) -> libc::clockid_t {
    ((!fd) << 3) | 3
}

/// `clock_gettime` and `clock_getres` on the open device's dynamic clock id, on a closed fd's,
/// and whether the PHC reads within a day of `CLOCK_REALTIME` (a PHC keeps TAI or UTC).
fn dynamic_probe(path: &Path) -> Vec<Result<bool, i32>> {
    let mut out = Vec::new();
    for flags in [libc::O_RDONLY, libc::O_RDWR] {
        let fd = match open(path, flags) {
            Ok(fd) => fd,
            Err(e) => {
                out.push(Err(e));
                continue;
            }
        };
        let mut phc = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let mut real = phc;
        let rc = unsafe { libc::clock_gettime(clockid(fd), &mut phc) };
        unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut real) };
        out.push(if rc == 0 {
            Ok((phc.tv_sec - real.tv_sec).abs() < 86_400)
        } else {
            Err(errno())
        });
        let mut res = phc;
        let rc = unsafe { libc::clock_getres(clockid(fd), &mut res) };
        out.push(if rc == 0 {
            Ok(res.tv_sec == 0 && res.tv_nsec > 0)
        } else {
            Err(errno())
        });
        unsafe { libc::close(fd) };
        let rc = unsafe { libc::clock_gettime(clockid(fd), &mut phc) };
        out.push(if rc == 0 { Ok(true) } else { Err(errno()) });
    }
    out.push(
        open(Path::new("/dev/ptp4095"), libc::O_RDONLY).map(|fd| unsafe { libc::close(fd) } == 0),
    );
    out
}

#[test]
#[ignore = "hardware: needs a PTP hardware clock"]
fn hw_ptp_dynamic_clock_matches() {
    let (path, index) = need!(usable_ptp(), "{NEEDS_PTP}");
    let real = snare::real(|| dynamic_probe(&path));
    let simulated = sim(index).run(|| dynamic_probe(&path));
    assert_eq!(
        simulated, real,
        "[gettime, getres, gettime-after-close] for O_RDONLY then O_RDWR, then opening a missing clock"
    );
}
