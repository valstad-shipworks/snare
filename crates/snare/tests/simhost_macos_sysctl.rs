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
        .nic(
            Nic::new("en5", 9)
                .operstate("up")
                .link_stats(LinkStats {
                    rx_packets: 7,
                    tx_packets: 11,
                    rx_bytes: 111,
                    tx_bytes: 222,
                    ..Default::default()
                }),
        )
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
        assert_eq!(needed, IF_MSGHDR2_LEN, "one interface's worth of bytes");

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
        assert_eq!(len, IF_MSGHDR2_LEN);

        // Parse the single if_msghdr2.
        let msglen = u16::from_ne_bytes([buf[0], buf[1]]) as usize;
        assert_eq!(msglen, IF_MSGHDR2_LEN);
        assert_eq!(buf[3], RTM_IFINFO2, "ifm_type");
        let ifindex = u16::from_ne_bytes([buf[12], buf[13]]);
        assert_eq!(ifindex, 9, "ifm_index");

        let d = 32; // struct if_data64
        assert_eq!(read_u64(&buf, d + 24), 7, "ifi_ipackets");
        assert_eq!(read_u64(&buf, d + 40), 11, "ifi_opackets");
        assert_eq!(read_u64(&buf, d + 64), 111, "ifi_ibytes");
        assert_eq!(read_u64(&buf, d + 72), 222, "ifi_obytes");
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
        assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::ENOMEM));
    });
}
