//! Enumerate the simulated host's interfaces over rtnetlink, exactly as a real program would.
//!
//! Builds a Sim with two NICs, opens an AF_NETLINK/NETLINK_ROUTE socket inside it, issues an
//! RTM_GETLINK dump, and prints each interface with its IFLA_STATS64 rx/tx packet counts.
//!
//! Protocol reference: man 7 rtnetlink (RTM_GETLINK / RTM_NEWLINK, IFLA_*); struct
//! rtnl_link_stats64 is from <linux/if_link.h>. Run with:
//!     cargo run -p snare --example netlink_getlink

#[cfg(target_os = "linux")]
fn main() {
    use snare::{HostProfile, LinkStats, Nic, Sim};

    const NETLINK_ROUTE: i32 = 0;
    const RTM_GETLINK: u16 = 18;
    const RTM_NEWLINK: u16 = 16;
    const NLMSG_DONE: u16 = 3;
    const NLM_F_REQUEST: u16 = 1;
    const NLM_F_DUMP: u16 = 0x300;
    const IFLA_IFNAME: u16 = 3;
    const IFLA_STATS64: u16 = 23;

    fn align4(n: usize) -> usize {
        (n + 3) & !3
    }
    fn u16at(b: &[u8], o: usize) -> u16 {
        u16::from_ne_bytes([b[o], b[o + 1]])
    }
    fn u32at(b: &[u8], o: usize) -> u32 {
        u32::from_ne_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
    }
    fn u64at(b: &[u8], o: usize) -> u64 {
        u64::from_ne_bytes(b[o..o + 8].try_into().unwrap())
    }

    let host = HostProfile::new()
        .nic(Nic::new("eth0", 2).link_stats(LinkStats {
            rx_packets: 1_000,
            tx_packets: 900,
            ..Default::default()
        }))
        .nic(Nic::new("eth1", 3).link_stats(LinkStats {
            rx_packets: 5,
            tx_packets: 7,
            ..Default::default()
        }))
        .build();

    Sim::builder().host(host).build().run(|| {
        let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, NETLINK_ROUTE) };
        assert!(fd >= 0, "open netlink socket");

        // 16-byte nlmsghdr + 16-byte ifinfomsg RTM_GETLINK dump request.
        let mut req = [0u8; 32];
        req[0..4].copy_from_slice(&32u32.to_ne_bytes());
        req[4..6].copy_from_slice(&RTM_GETLINK.to_ne_bytes());
        req[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
        req[8..12].copy_from_slice(&1u32.to_ne_bytes());
        let sent = unsafe { libc::send(fd, req.as_ptr() as *const libc::c_void, 32, 0) };
        assert_eq!(sent, 32);

        let mut buf = vec![0u8; 65536];
        let got = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        assert!(got > 0);
        buf.truncate(got as usize);
        unsafe { libc::close(fd) };

        let mut off = 0;
        while off + 16 <= buf.len() {
            let msg_len = u32at(&buf, off) as usize;
            let msg_type = u16at(&buf, off + 4);
            if msg_len < 16 || off + msg_len > buf.len() || msg_type == NLMSG_DONE {
                break;
            }
            if msg_type == RTM_NEWLINK {
                let mut name = String::new();
                let (mut rx, mut tx) = (0u64, 0u64);
                let mut a = off + 32;
                let end = off + msg_len;
                while a + 4 <= end {
                    let rta_len = u16at(&buf, a) as usize;
                    let rta_type = u16at(&buf, a + 2);
                    if rta_len < 4 || a + rta_len > end {
                        break;
                    }
                    let p = &buf[a + 4..a + rta_len];
                    match rta_type {
                        IFLA_IFNAME => {
                            let s = p.split(|&c| c == 0).next().unwrap_or(&[]);
                            name = String::from_utf8_lossy(s).into_owned();
                        }
                        IFLA_STATS64 => {
                            rx = u64at(p, 0);
                            tx = u64at(p, 8);
                        }
                        _ => {}
                    }
                    a += align4(rta_len);
                }
                println!("link {name}: rx_packets={rx} tx_packets={tx}");
            }
            off += align4(msg_len);
        }
    });
}

#[cfg(not(target_os = "linux"))]
fn main() {
    // rtnetlink is a Linux facility; there is nothing to demonstrate on other platforms.
    println!("netlink_getlink: rtnetlink is Linux-only; nothing to run on this platform");
}
