#![cfg(target_os = "macos")]

use snare::{HostProfile, LinkStats, Nic, Sim};

const CTL_NET: libc::c_int = 4;
const PF_ROUTE: libc::c_int = 17;
const NET_RT_IFLIST2: libc::c_int = 6;
const RTM_IFINFO2: u8 = 0x12;
const IF_MSGHDR2_LEN: usize = 168;

fn read_u64(buf: &[u8], off: usize) -> u64 {
    u64::from_ne_bytes(buf[off..off + 8].try_into().unwrap())
}

#[test]
fn net_rt_iflist2_reports_configured_link_stats() {
    let host = HostProfile::new()
        .nic(Nic::new("en5", 9).operstate("up").link_stats(LinkStats {
            rx_packets: 7,
            tx_packets: 11,
            rx_bytes: 111,
            tx_bytes: 222,
            ..Default::default()
        }))
        .build();
    Sim::builder().host(host).build().run(|| {
        let mut mib: [libc::c_int; 6] = [CTL_NET, PF_ROUTE, 0, 0, NET_RT_IFLIST2, 0];

        // Size query first (oldp = null), as a real caller does.
        let mut needed: usize = 0;
        let rc = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as u32,
                std::ptr::null_mut(),
                &mut needed,
                std::ptr::null_mut(),
                0,
            )
        };
        assert_eq!(rc, 0, "size query");
        assert_eq!(needed, 2 * IF_MSGHDR2_LEN, "loopback's and en5's messages");

        let mut buf = vec![0u8; needed];
        let mut len = needed;
        let rc = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as u32,
                buf.as_mut_ptr() as *mut libc::c_void,
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        assert_eq!(rc, 0, "data fetch");
        assert_eq!(len, 2 * IF_MSGHDR2_LEN);
        assert_eq!(
            u16::from_ne_bytes([buf[12], buf[13]]),
            1,
            "lo0 first, by index"
        );
        let buf = &buf[IF_MSGHDR2_LEN..];
        let msglen = u16::from_ne_bytes([buf[0], buf[1]]) as usize;
        assert_eq!(msglen, IF_MSGHDR2_LEN);
        assert_eq!(buf[3], RTM_IFINFO2, "ifm_type");
        let ifindex = u16::from_ne_bytes([buf[12], buf[13]]);
        assert_eq!(ifindex, 9, "ifm_index");

        let d = 32; // struct if_data64
        assert_eq!(read_u64(buf, d + 24), 7, "ifi_ipackets");
        assert_eq!(read_u64(buf, d + 40), 11, "ifi_opackets");
        assert_eq!(read_u64(buf, d + 64), 111, "ifi_ibytes");
        assert_eq!(read_u64(buf, d + 72), 222, "ifi_obytes");
    });
}

#[test]
fn too_small_a_buffer_is_enomem() {
    let host = HostProfile::new().nic(Nic::new("en5", 9)).build();
    Sim::builder().host(host).build().run(|| {
        let mut mib: [libc::c_int; 6] = [CTL_NET, PF_ROUTE, 0, 0, NET_RT_IFLIST2, 0];
        let mut buf = [0u8; 8];
        let mut len = buf.len();
        let rc = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as u32,
                buf.as_mut_ptr() as *mut libc::c_void,
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        assert_eq!(rc, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ENOMEM)
        );
    });
}

/// `sysctlbyname(name)` as an `int`, or the errno.
fn hw_int(name: &std::ffi::CStr) -> Result<i32, i32> {
    let mut value: i32 = 0;
    let mut len = size_of::<i32>();
    let rc = unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            (&raw mut value).cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error().raw_os_error().unwrap());
    }
    assert_eq!(len, size_of::<i32>());
    Ok(value)
}

#[test]
fn hw_cpu_counts_follow_the_profile() {
    let host = HostProfile::new().cpus(6).online([0, 1, 2, 3]).build();
    Sim::builder().host(host).build().run(|| {
        assert_eq!(hw_int(c"hw.ncpu"), Ok(6));
        assert_eq!(hw_int(c"hw.logicalcpu_max"), Ok(6));
        assert_eq!(hw_int(c"hw.physicalcpu_max"), Ok(6));
        assert_eq!(hw_int(c"hw.activecpu"), Ok(4));
        assert_eq!(hw_int(c"hw.logicalcpu"), Ok(4));
        assert_eq!(hw_int(c"hw.physicalcpu"), Ok(4));
        if cfg!(target_arch = "aarch64") {
            assert_eq!(hw_int(c"hw.nperflevels"), Ok(1));
            assert_eq!(hw_int(c"hw.perflevel0.logicalcpu_max"), Ok(6));
            assert_eq!(hw_int(c"hw.perflevel0.physicalcpu"), Ok(4));
            assert_eq!(hw_int(c"hw.perflevel1.logicalcpu"), Err(libc::ENOENT));
            let mut mib = [0 as libc::c_int; 4];
            let mut len = mib.len();
            let rc = unsafe {
                libc::sysctlnametomib(c"hw.perflevel1.name".as_ptr(), mib.as_mut_ptr(), &mut len)
            };
            assert_eq!(rc, -1);
            let mut name = [0u8; 32];
            let mut len = name.len();
            let rc = unsafe {
                libc::sysctlbyname(
                    c"hw.perflevel0.name".as_ptr(),
                    name.as_mut_ptr().cast(),
                    &mut len,
                    std::ptr::null_mut(),
                    0,
                )
            };
            assert_eq!(rc, 0);
            assert_eq!(&name[..len], b"Performance\0");
        }
    });
}

#[test]
fn hw_cpu_counts_by_mib() {
    let host = HostProfile::new().cpus(3).build();
    Sim::builder().host(host).build().run(|| {
        let read = |mib: &mut [libc::c_int]| {
            let mut value: i32 = 0;
            let mut len = size_of::<i32>();
            let rc = unsafe {
                libc::sysctl(
                    mib.as_mut_ptr(),
                    mib.len() as u32,
                    (&raw mut value).cast(),
                    &mut len,
                    std::ptr::null_mut(),
                    0,
                )
            };
            assert_eq!(rc, 0);
            value
        };
        assert_eq!(read(&mut [libc::CTL_HW, libc::HW_NCPU]), 3);
        let mut mib = [0 as libc::c_int; 4];
        let mut len = mib.len();
        let rc = unsafe {
            libc::sysctlnametomib(c"hw.physicalcpu".as_ptr(), mib.as_mut_ptr(), &mut len)
        };
        assert_eq!(rc, 0);
        assert_eq!(read(&mut mib[..len]), 3);
    });
}

/// The calling conventions of a read-only `int` node, as `(rc, errno, len)` for: a size query, a
/// short buffer, a long buffer, a write, and a null length pointer.
fn hw_ncpu_conventions() -> Vec<(i32, i32, usize)> {
    let name = c"hw.ncpu".as_ptr();
    let errno = || std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    let mut out = Vec::new();
    unsafe {
        let mut len = 0usize;
        let rc = libc::sysctlbyname(
            name,
            std::ptr::null_mut(),
            &mut len,
            std::ptr::null_mut(),
            0,
        );
        out.push((rc, if rc == 0 { 0 } else { errno() }, len));
        let mut short = [0u8; 2];
        let mut len = short.len();
        let rc = libc::sysctlbyname(
            name,
            short.as_mut_ptr().cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        );
        out.push((rc, if rc == 0 { 0 } else { errno() }, len));
        let mut long = [0u8; 8];
        let mut len = long.len();
        let rc = libc::sysctlbyname(
            name,
            long.as_mut_ptr().cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        );
        out.push((rc, if rc == 0 { 0 } else { errno() }, len));
        let mut value: i32 = 2;
        let rc = libc::sysctlbyname(
            name,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            (&raw mut value).cast(),
            4,
        );
        out.push((rc, if rc == 0 { 0 } else { errno() }, 0));
        let rc = libc::sysctlbyname(
            name,
            long.as_mut_ptr().cast(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
        );
        out.push((rc, if rc == 0 { 0 } else { errno() }, 0));
    }
    out
}

#[test]
fn hw_ncpu_conventions_os_truth() {
    let real = hw_ncpu_conventions();
    let host = HostProfile::new().cpus(3).build();
    let sim = Sim::builder().host(host).build().run(hw_ncpu_conventions);
    assert_eq!(sim, real);
}
