#![cfg(target_os = "linux")]

use snare::{HostProfile, PtpCaps, Sim};

const fn ioc(dir: u64, ty: u8, nr: u64, size: usize) -> libc::c_ulong {
    ((dir << 30) | ((ty as u64) << 8) | nr | ((size as u64) << 16)) as libc::c_ulong
}

const PTP_MAGIC: u8 = b'=';
// struct ptp_sys_offset_precise is 64 bytes; struct ptp_sys_offset is 832 bytes.
const PTP_SYS_OFFSET_PRECISE: libc::c_ulong = ioc(3, PTP_MAGIC, 8, 64);
const PTP_SYS_OFFSET: libc::c_ulong = ioc(1, PTP_MAGIC, 5, 832);
// struct ptp_clock_caps is 80 bytes, struct ptp_sys_offset_extended 1216, struct ptp_extts_request
// 16; the *2 requests (nr + 9) share the layouts.
const PTP_CLOCK_GETCAPS: libc::c_ulong = ioc(2, PTP_MAGIC, 1, 80);
const PTP_EXTTS_REQUEST: libc::c_ulong = ioc(1, PTP_MAGIC, 2, 16);
const PTP_SYS_OFFSET_EXTENDED: libc::c_ulong = ioc(3, PTP_MAGIC, 9, 1216);
const PTP_SYS_OFFSET2: libc::c_ulong = ioc(1, PTP_MAGIC, 14, 832);
const PTP_SYS_OFFSET_PRECISE_CYCLES: libc::c_ulong = ioc(3, PTP_MAGIC, 21, 64);
const PTP_MAX_SAMPLES: u32 = 25;

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn ioctl(fd: i32, request: libc::c_ulong, buf: &mut [u8]) -> Result<(), i32> {
    let rc = unsafe { libc::ioctl(fd, request, buf.as_mut_ptr()) };
    if rc == 0 { Ok(()) } else { Err(errno()) }
}

fn open_ptp(path: &std::ffi::CStr, flags: i32) -> i32 {
    let fd = unsafe { libc::open(path.as_ptr(), flags) };
    assert!(fd >= 0, "opening {path:?}");
    fd
}

fn read_ptp_time(buf: &[u8], off: usize) -> u64 {
    let sec = i64::from_ne_bytes(buf[off..off + 8].try_into().unwrap());
    let nsec = u32::from_ne_bytes(buf[off + 8..off + 12].try_into().unwrap());
    sec as u64 * 1_000_000_000 + nsec as u64
}

#[test]
fn sys_offset_precise_reports_a_deterministic_phc_offset() {
    let caps = PtpCaps {
        cross_timestamping: true,
        ..PtpCaps::default()
    };
    let host = HostProfile::new()
        .ptp_clock_offset(0, 500)
        .ptp_clock_caps(0, caps)
        .build();
    Sim::builder().host(host).build().run(|| {
        let fd = unsafe { libc::open(c"/dev/ptp0".as_ptr(), libc::O_RDWR) };
        assert!(fd >= 0, "opening /dev/ptp0");

        let mut buf = [0u8; 64];
        let rc = unsafe { libc::ioctl(fd, PTP_SYS_OFFSET_PRECISE, buf.as_mut_ptr()) };
        assert_eq!(rc, 0, "PTP_SYS_OFFSET_PRECISE");

        let device = read_ptp_time(&buf, 0);
        let realtime = read_ptp_time(&buf, 16);
        let monoraw = read_ptp_time(&buf, 32);

        assert_eq!(
            device.wrapping_sub(realtime),
            500,
            "PHC leads realtime by the offset"
        );
        assert!(
            realtime > 1_700_000_000 * 1_000_000_000,
            "realtime near the fixed epoch"
        );
        assert!(
            monoraw < realtime,
            "monotonic-raw starts at zero, realtime at the epoch"
        );

        unsafe { libc::close(fd) };
    });
}

#[test]
fn sys_offset_interleaves_system_and_phc_samples() {
    let host = HostProfile::new().ptp_clock_offset(1, -250).build();
    Sim::builder().host(host).build().run(|| {
        let fd = unsafe { libc::open(c"/dev/ptp1".as_ptr(), libc::O_RDWR) };
        assert!(fd >= 0);

        let mut buf = [0u8; 832];
        buf[0..4].copy_from_slice(&1u32.to_ne_bytes()); // n_samples = 1
        let rc = unsafe { libc::ioctl(fd, PTP_SYS_OFFSET, buf.as_mut_ptr()) };
        assert_eq!(rc, 0, "PTP_SYS_OFFSET");

        // ts[] starts at offset 16: ts[0]=system, ts[1]=phc, ts[2]=system.
        let sys_before = read_ptp_time(&buf, 16);
        let phc = read_ptp_time(&buf, 32);
        assert_eq!(
            phc.wrapping_sub(sys_before),
            (-250i64) as u64,
            "PHC trails realtime by 250ns"
        );

        unsafe { libc::close(fd) };
    });
}

#[test]
fn an_unconfigured_ptp_index_is_enoent() {
    let host = HostProfile::new().ptp_clock(0).build();
    Sim::builder().host(host).build().run(|| {
        let fd = unsafe { libc::open(c"/dev/ptp7".as_ptr(), libc::O_RDWR) };
        assert!(fd < 0, "only configured clocks exist");
    });
}

/// drivers/ptp/ptp_chardev.c `ptp_sys_offset_precise`: a clock without `getcrosststamp` (igb's
/// I210, the default) is `EOPNOTSUPP`, and so are the `_CYCLES` variants on a clock without
/// cycles.
#[test]
fn precise_offsets_need_a_cross_timestamping_clock() {
    let host = HostProfile::new().ptp_clock(0).build();
    Sim::builder().host(host).build().run(|| {
        let fd = open_ptp(c"/dev/ptp0", libc::O_RDONLY);
        let mut buf = [0u8; 64];
        assert_eq!(
            ioctl(fd, PTP_SYS_OFFSET_PRECISE, &mut buf),
            Err(libc::EOPNOTSUPP)
        );
        assert_eq!(buf, [0; 64], "nothing written");
        assert_eq!(
            ioctl(fd, PTP_SYS_OFFSET_PRECISE_CYCLES, &mut buf),
            Err(libc::EOPNOTSUPP)
        );
        unsafe { libc::close(fd) };
    });
}

/// `ptp_clock_getcaps` copies the driver's `ptp_clock_info` counts; `max_phase_adj` only with
/// `adjust_phase`.
#[test]
fn getcaps_reports_the_clock_capabilities() {
    let caps = PtpCaps {
        max_adj: 62_499_999,
        n_ext_ts: 2,
        n_per_out: 2,
        pps: true,
        n_pins: 4,
        ..PtpCaps::default()
    };
    let host = HostProfile::new().ptp_clock_caps(3, caps).build();
    Sim::builder().host(host).build().run(|| {
        let fd = open_ptp(c"/dev/ptp3", libc::O_RDONLY);
        let mut buf = [0xffu8; 80];
        assert_eq!(ioctl(fd, PTP_CLOCK_GETCAPS, &mut buf), Ok(()));
        let words: Vec<i32> = buf
            .chunks(4)
            .map(|w| i32::from_ne_bytes(w.try_into().unwrap()))
            .collect();
        assert_eq!(&words[..9], &[62_499_999, 0, 2, 2, 1, 4, 0, 0, 0]);
        assert!(words[9..].iter().all(|&w| w == 0), "reserved words zeroed");
        unsafe { libc::close(fd) };
    });
}

/// `ptp_sys_offset`: `n_samples` past `PTP_MAX_SAMPLES` is `EINVAL`, not clamped; 0 samples
/// still reads the system clock once; `PTP_SYS_OFFSET2` is the same request.
#[test]
fn sys_offset_refuses_more_than_max_samples() {
    let host = HostProfile::new().ptp_clock(0).build();
    Sim::builder().host(host).build().run(|| {
        let fd = open_ptp(c"/dev/ptp0", libc::O_RDONLY);
        let mut buf = [0u8; 832];
        buf[..4].copy_from_slice(&(PTP_MAX_SAMPLES + 1).to_ne_bytes());
        assert_eq!(ioctl(fd, PTP_SYS_OFFSET, &mut buf), Err(libc::EINVAL));
        assert!(buf[16..].iter().all(|&b| b == 0), "nothing written");
        buf[..4].copy_from_slice(&PTP_MAX_SAMPLES.to_ne_bytes());
        assert_eq!(ioctl(fd, PTP_SYS_OFFSET2, &mut buf), Ok(()));
        assert_ne!(
            read_ptp_time(&buf, 16 + 50 * 16),
            0,
            "the closing system reading"
        );
        let mut zero = [0u8; 832];
        assert_eq!(ioctl(fd, PTP_SYS_OFFSET, &mut zero), Ok(()));
        assert_ne!(
            read_ptp_time(&zero, 16),
            0,
            "one system reading for no samples"
        );
        assert_eq!(read_ptp_time(&zero, 32), 0);
        unsafe { libc::close(fd) };
    });
}

/// `ptp_sys_offset_extended`: each sample is (system, PHC, system) on the requested clock;
/// `EINVAL` past `PTP_MAX_SAMPLES`, with reserved words set, or for a clock other than
/// `CLOCK_REALTIME`, `CLOCK_MONOTONIC` and `CLOCK_MONOTONIC_RAW`; `EOPNOTSUPP` without
/// `gettimex64`.
#[test]
fn sys_offset_extended_brackets_each_phc_reading() {
    let host = HostProfile::new()
        .ptp_clock_offset(0, 1_000)
        .ptp_clock_caps(
            1,
            PtpCaps {
                extended: false,
                ..PtpCaps::default()
            },
        )
        .build();
    Sim::builder().host(host).build().run(|| {
        let fd = open_ptp(c"/dev/ptp0", libc::O_RDONLY);
        let request = |n: u32, clockid: i32, rsv: u32| {
            let mut buf = vec![0u8; 1216];
            buf[..4].copy_from_slice(&n.to_ne_bytes());
            buf[4..8].copy_from_slice(&clockid.to_ne_bytes());
            buf[8..12].copy_from_slice(&rsv.to_ne_bytes());
            (ioctl(fd, PTP_SYS_OFFSET_EXTENDED, &mut buf), buf)
        };
        let (rc, buf) = request(3, libc::CLOCK_REALTIME, 0);
        assert_eq!(rc, Ok(()));
        for i in 0..3 {
            let at = 16 + i * 48;
            let (pre, phc, post) = (
                read_ptp_time(&buf, at),
                read_ptp_time(&buf, at + 16),
                read_ptp_time(&buf, at + 32),
            );
            assert!(pre <= post);
            assert_eq!(phc.wrapping_sub(pre), 1_000, "sample {i}: the PHC's offset");
        }
        assert_eq!(read_ptp_time(&buf, 16 + 3 * 48), 0, "no fourth sample");
        let (rc, buf) = request(1, libc::CLOCK_MONOTONIC_RAW, 0);
        assert_eq!(rc, Ok(()));
        assert!(
            read_ptp_time(&buf, 16) < 1_000_000_000_000,
            "monotonic counts from zero"
        );
        assert_eq!(request(PTP_MAX_SAMPLES + 1, 0, 0).0, Err(libc::EINVAL));
        assert_eq!(request(1, libc::CLOCK_TAI, 0).0, Err(libc::EINVAL));
        assert_eq!(request(1, 0, 1).0, Err(libc::EINVAL));
        unsafe { libc::close(fd) };
        let fd = open_ptp(c"/dev/ptp1", libc::O_RDONLY);
        let mut buf = vec![0u8; 1216];
        buf[..4].copy_from_slice(&1u32.to_ne_bytes());
        assert_eq!(
            ioctl(fd, PTP_SYS_OFFSET_EXTENDED, &mut buf),
            Err(libc::EOPNOTSUPP)
        );
        unsafe { libc::close(fd) };
    });
}

/// `ptp_ioctl`: the requests that change the clock need an fd open for writing (`EACCES`), then
/// a channel the clock has (`EINVAL`); an unknown request is `ENOTTY`.
#[test]
fn changing_requests_need_a_writable_fd_and_a_channel() {
    let caps = PtpCaps {
        n_ext_ts: 1,
        ..PtpCaps::default()
    };
    let host = HostProfile::new().ptp_clock_caps(0, caps).build();
    Sim::builder().host(host).build().run(|| {
        let extts = |fd: i32, index: u32| {
            let mut buf = [0u8; 16];
            buf[..4].copy_from_slice(&index.to_ne_bytes());
            buf[4..8].copy_from_slice(&1u32.to_ne_bytes());
            ioctl(fd, PTP_EXTTS_REQUEST, &mut buf)
        };
        let ro = open_ptp(c"/dev/ptp0", libc::O_RDONLY);
        assert_eq!(extts(ro, 0), Err(libc::EACCES));
        let rw = open_ptp(c"/dev/ptp0", libc::O_RDWR);
        assert_eq!(extts(rw, 0), Ok(()));
        assert_eq!(extts(rw, 1), Err(libc::EINVAL), "one channel");
        let mut buf = [0u8; 64];
        assert_eq!(
            ioctl(rw, ioc(3, PTP_MAGIC, 99, 64), &mut buf),
            Err(libc::ENOTTY)
        );
        unsafe {
            libc::close(ro);
            libc::close(rw);
        }
    });
}
