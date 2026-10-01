#![cfg(target_os = "linux")]

use snare::{HostProfile, Sim};

const fn ioc(dir: u64, ty: u8, nr: u64, size: usize) -> libc::c_ulong {
    ((dir << 30) | ((ty as u64) << 8) | nr | ((size as u64) << 16)) as libc::c_ulong
}

const PTP_MAGIC: u8 = b'=';
// struct ptp_sys_offset_precise is 64 bytes; struct ptp_sys_offset is 832 bytes.
const PTP_SYS_OFFSET_PRECISE: libc::c_ulong = ioc(3, PTP_MAGIC, 8, 64);
const PTP_SYS_OFFSET: libc::c_ulong = ioc(1, PTP_MAGIC, 5, 832);

fn read_ptp_time(buf: &[u8], off: usize) -> u64 {
    let sec = i64::from_ne_bytes(buf[off..off + 8].try_into().unwrap());
    let nsec = u32::from_ne_bytes(buf[off + 8..off + 12].try_into().unwrap());
    sec as u64 * 1_000_000_000 + nsec as u64
}

#[test]
fn sys_offset_precise_reports_a_deterministic_phc_offset() {
    let host = HostProfile::new().ptp_clock_offset(0, 500).build();
    Sim::builder().host(host).build().run(|| {
        let fd = unsafe { libc::open(c"/dev/ptp0".as_ptr(), libc::O_RDWR) };
        assert!(fd >= 0, "opening /dev/ptp0");

        let mut buf = [0u8; 64];
        let rc = unsafe { libc::ioctl(fd, PTP_SYS_OFFSET_PRECISE, buf.as_mut_ptr()) };
        assert_eq!(rc, 0, "PTP_SYS_OFFSET_PRECISE");

        let device = read_ptp_time(&buf, 0);
        let realtime = read_ptp_time(&buf, 16);
        let monoraw = read_ptp_time(&buf, 32);

        assert_eq!(device.wrapping_sub(realtime), 500, "PHC leads realtime by the offset");
        assert!(realtime > 1_700_000_000 * 1_000_000_000, "realtime near the fixed epoch");
        assert!(monoraw < realtime, "monotonic-raw starts at zero, realtime at the epoch");

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
        assert_eq!(phc.wrapping_sub(sys_before), (-250i64) as u64, "PHC trails realtime by 250ns");

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
