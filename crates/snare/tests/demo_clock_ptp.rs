#![cfg(target_os = "linux")]

//! PTP hardware clock cross-timestamps via `PTP_SYS_OFFSET_PRECISE` on `/dev/ptp<N>`. One ioctl
//! returns the PHC time, CLOCK_REALTIME and CLOCK_MONOTONIC_RAW captured at a single instant, so a
//! caller derives a consistent PHC-to-system offset. Only a clock whose driver cross-timestamps
//! (`PtpCaps::cross_timestamping`) answers it. The ioctl numbers and the `ptp_sys_offset_*`
//! struct layouts are in <linux/ptp_clock.h>.

use snare::{HostProfile, Nic, PtpCaps, Sim};

const CROSS: PtpCaps = PtpCaps {
    cross_timestamping: true,
    max_adj: 0,
    n_alarm: 0,
    n_ext_ts: 0,
    n_per_out: 0,
    pps: false,
    n_pins: 0,
    adjust_phase: false,
    max_phase_adj: 0,
    extended: true,
};

const fn ioc(dir: u64, ty: u8, nr: u64, size: usize) -> libc::c_ulong {
    ((dir << 30) | ((ty as u64) << 8) | nr | ((size as u64) << 16)) as libc::c_ulong
}

// struct ptp_sys_offset_precise is 64 bytes; _IOWR('=', 8, ...).
const PTP_SYS_OFFSET_PRECISE: libc::c_ulong = ioc(3, b'=', 8, 64);

fn read_time(buf: &[u8], off: usize) -> i128 {
    let sec = i64::from_ne_bytes(buf[off..off + 8].try_into().unwrap());
    let nsec = u32::from_ne_bytes(buf[off + 8..off + 12].try_into().unwrap());
    sec as i128 * 1_000_000_000 + nsec as i128
}

fn sample(path: &std::ffi::CStr) -> [i128; 3] {
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR) };
    assert!(fd >= 0, "opening {path:?}");
    let mut buf = [0u8; 64];
    let rc = unsafe { libc::ioctl(fd, PTP_SYS_OFFSET_PRECISE, buf.as_mut_ptr()) };
    assert_eq!(rc, 0, "PTP_SYS_OFFSET_PRECISE on {path:?}");
    unsafe { libc::close(fd) };
    // struct ptp_sys_offset_precise: device @0, sys_realtime @16, sys_monoraw @32 (each a
    // ptp_clock_time of {sec: i64, nsec: u32, reserved: u32} = 16 bytes).
    [read_time(&buf, 0), read_time(&buf, 16), read_time(&buf, 32)]
}

#[test]
fn a_zero_offset_phc_tracks_realtime_exactly() {
    let host = HostProfile::new().ptp_clock_caps(0, CROSS).build();
    Sim::builder().host(host).fixed_epoch().build().run(|| {
        let [device, realtime, _] = sample(c"/dev/ptp0");
        assert_eq!(
            device, realtime,
            "a 0-offset PHC reads identically to CLOCK_REALTIME"
        );
    });
}

#[test]
fn a_positive_offset_phc_leads_realtime() {
    let host = HostProfile::new()
        .ptp_clock_offset(2, 12_000)
        .ptp_clock_caps(2, CROSS)
        .build();
    Sim::builder().host(host).fixed_epoch().build().run(|| {
        let [device, realtime, _] = sample(c"/dev/ptp2");
        assert_eq!(
            device - realtime,
            12_000,
            "PHC leads realtime by the configured offset"
        );
    });
}

#[test]
fn a_negative_offset_phc_trails_realtime() {
    let host = HostProfile::new()
        .ptp_clock_offset(0, -9_000)
        .ptp_clock_caps(0, CROSS)
        .build();
    Sim::builder().host(host).fixed_epoch().build().run(|| {
        let [device, realtime, _] = sample(c"/dev/ptp0");
        assert_eq!(
            device - realtime,
            -9_000,
            "PHC trails realtime by the configured offset"
        );
    });
}

#[test]
fn monotonic_raw_is_the_monotonic_raw_clock() {
    let host = HostProfile::new().ptp_clock_caps(0, CROSS).build();
    Sim::builder().host(host).fixed_epoch().build().run(|| {
        let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC_RAW, &mut ts) };
        let before = ts.tv_sec as i128 * 1_000_000_000 + ts.tv_nsec as i128;
        let [_, realtime, monoraw] = sample(c"/dev/ptp0");
        assert!(
            monoraw < realtime,
            "monoraw counts from zero, realtime from the epoch"
        );
        assert!(monoraw < 1_000_000_000, "monoraw is still near its origin");
        assert!(
            (before..before + 1_000_000).contains(&monoraw),
            "the sample's monoraw is CLOCK_MONOTONIC_RAW at that instant ({before} -> {monoraw})"
        );
    });
}

#[test]
fn realtime_in_the_sample_sits_at_the_virtual_epoch() {
    let host = HostProfile::new().ptp_clock_caps(0, CROSS).build();
    Sim::builder().host(host).fixed_epoch().build().run(|| {
        let [_, realtime, _] = sample(c"/dev/ptp0");
        assert_eq!(
            realtime / 1_000_000_000,
            1_700_000_000,
            "cross-timestamp realtime is the epoch"
        );
    });
}

#[test]
fn two_phcs_carry_independent_offsets() {
    let host = HostProfile::new()
        .ptp_clock_offset(0, 1_000)
        .ptp_clock_offset(1, -1_000)
        .ptp_clock_caps(0, CROSS)
        .ptp_clock_caps(1, CROSS)
        .build();
    Sim::builder().host(host).fixed_epoch().build().run(|| {
        let [d0, r0, _] = sample(c"/dev/ptp0");
        let [d1, r1, _] = sample(c"/dev/ptp1");
        assert_eq!(d0 - r0, 1_000, "ptp0 leads by 1µs");
        assert_eq!(d1 - r1, -1_000, "ptp1 trails by 1µs");
    });
}

#[test]
fn a_nic_ptp_index_exposes_its_phc() {
    // A NIC that advertises a PHC index makes /dev/ptp<index> appear, tracking realtime exactly.
    let nic = Nic::new("eth0", 2).ptp_index(4);
    let host = HostProfile::new().nic(nic).ptp_clock_caps(4, CROSS).build();
    Sim::builder().host(host).fixed_epoch().build().run(|| {
        let [device, realtime, _] = sample(c"/dev/ptp4");
        assert_eq!(
            device, realtime,
            "the NIC's PHC tracks realtime with no configured offset"
        );
    });
}

#[test]
fn an_unconfigured_ptp_node_does_not_exist() {
    let host = HostProfile::new().ptp_clock_caps(0, CROSS).build();
    Sim::builder().host(host).fixed_epoch().build().run(|| {
        let fd = unsafe { libc::open(c"/dev/ptp9".as_ptr(), libc::O_RDWR) };
        assert!(fd < 0, "only configured PHCs are present");
    });
}
