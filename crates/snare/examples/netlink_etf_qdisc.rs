//! Read the root qdisc of the simulated host over rtnetlink and print its etf pacing parameters.
//!
//! Builds a Sim whose NIC has an `etf` root qdisc, opens NETLINK_ROUTE, issues RTM_GETQDISC, and
//! decodes TCA_KIND plus the nested TCA_OPTIONS/TCA_ETF_PARMS (struct tc_etf_qopt).
//!
//! Protocol reference: man 7 rtnetlink (RTM_GETQDISC / RTM_NEWQDISC, TCA_*); the etf qdisc and
//! struct tc_etf_qopt are from <linux/pkt_sched.h>, described in man 8 tc-etf. Run with:
//!     cargo run -p snare --example netlink_etf_qdisc

#[cfg(target_os = "linux")]
fn main() {
    use snare::{HostProfile, Nic, Sim};

    const NETLINK_ROUTE: i32 = 0;
    const RTM_GETQDISC: u16 = 38;
    const NLM_F_REQUEST: u16 = 1;
    const NLM_F_DUMP: u16 = 0x300;
    const TCA_KIND: u16 = 1;
    const TCA_OPTIONS: u16 = 2;
    const TCA_ETF_PARMS: u16 = 1;

    fn u16at(b: &[u8], o: usize) -> u16 {
        u16::from_ne_bytes([b[o], b[o + 1]])
    }
    fn u32at(b: &[u8], o: usize) -> u32 {
        u32::from_ne_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
    }
    fn i32at(b: &[u8], o: usize) -> i32 {
        i32::from_ne_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
    }
    fn find_attr(attrs: &[u8], want: u16) -> Option<&[u8]> {
        let mut pos = 0;
        while pos + 4 <= attrs.len() {
            let len = u16at(attrs, pos) as usize;
            let ty = u16at(attrs, pos + 2);
            if len < 4 || pos + len > attrs.len() {
                break;
            }
            if ty == want {
                return Some(&attrs[pos + 4..pos + len]);
            }
            pos += len.next_multiple_of(4);
        }
        None
    }

    let host = HostProfile::new()
        .nic(Nic::new("eth0", 2))
        .etf_qdisc(300_000, libc::CLOCK_TAI, 0)
        .build();

    Sim::builder().host(host).build().run(|| {
        let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, NETLINK_ROUTE) };
        assert!(fd >= 0);

        let mut req = Vec::new();
        req.extend_from_slice(&36u32.to_ne_bytes()); // 16-byte nlmsghdr + 20-byte tcmsg
        req.extend_from_slice(&RTM_GETQDISC.to_ne_bytes());
        req.extend_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
        req.extend_from_slice(&1u32.to_ne_bytes());
        req.extend_from_slice(&0u32.to_ne_bytes());
        req.extend_from_slice(&[0u8; 20]);
        unsafe { libc::send(fd, req.as_ptr() as *const libc::c_void, req.len(), 0) };

        let mut reply = vec![0u8; 4096];
        let got =
            unsafe { libc::recv(fd, reply.as_mut_ptr() as *mut libc::c_void, reply.len(), 0) };
        assert!(got > 0);
        reply.truncate(got as usize);
        unsafe { libc::close(fd) };

        let msglen = u32at(&reply, 0) as usize;
        let attrs = &reply[36..msglen];
        let kind = find_attr(attrs, TCA_KIND).unwrap();
        let end = kind.iter().position(|&b| b == 0).unwrap_or(kind.len());
        let kind = String::from_utf8_lossy(&kind[..end]);
        print!("root qdisc: {kind}");
        if let Some(parms) = find_attr(attrs, TCA_OPTIONS).and_then(|o| find_attr(o, TCA_ETF_PARMS))
        {
            let delta = i32at(parms, 0);
            let clockid = i32at(parms, 4);
            print!(" delta={delta}ns clockid={clockid}");
        }
        println!();
    });
}

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("netlink_etf_qdisc: rtnetlink is Linux-only; nothing to run on this platform");
}
