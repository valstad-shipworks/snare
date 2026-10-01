#![cfg(target_os = "linux")]

use snare::{HostProfile, Nic, Sim};

const NETLINK_ROUTE: i32 = 0;
const NETLINK_GENERIC: i32 = 16;
const GENL_ID_CTRL: u16 = 16;
const NLM_F_REQUEST: u16 = 1;
const NLM_F_DUMP: u16 = 0x300;

fn nl_message(ty: u16, flags: u16, seq: u32, body: &[u8]) -> Vec<u8> {
    let len = (16 + body.len()) as u32;
    let mut out = Vec::new();
    out.extend_from_slice(&len.to_ne_bytes());
    out.extend_from_slice(&ty.to_ne_bytes());
    out.extend_from_slice(&flags.to_ne_bytes());
    out.extend_from_slice(&seq.to_ne_bytes());
    out.extend_from_slice(&0u32.to_ne_bytes());
    out.extend_from_slice(body);
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
    out
}

fn push_attr(out: &mut Vec<u8>, ty: u16, payload: &[u8]) {
    let len = (4 + payload.len()) as u16;
    out.extend_from_slice(&len.to_ne_bytes());
    out.extend_from_slice(&ty.to_ne_bytes());
    out.extend_from_slice(payload);
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
}

fn find_attr(attrs: &[u8], want: u16) -> Option<&[u8]> {
    let mut pos = 0;
    while pos + 4 <= attrs.len() {
        let len = u16::from_ne_bytes([attrs[pos], attrs[pos + 1]]) as usize;
        let ty = u16::from_ne_bytes([attrs[pos + 2], attrs[pos + 3]]);
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

fn round_trip(fd: i32, request: &[u8]) -> Vec<u8> {
    let sent = unsafe {
        libc::send(fd, request.as_ptr() as *const libc::c_void, request.len(), 0)
    };
    assert_eq!(sent, request.len() as isize, "send request");
    let mut reply = vec![0u8; 4096];
    let got = unsafe { libc::recv(fd, reply.as_mut_ptr() as *mut libc::c_void, reply.len(), 0) };
    assert!(got > 0, "recv reply");
    reply.truncate(got as usize);
    reply
}

#[test]
fn genetlink_resolves_the_netdev_family_id() {
    let host = HostProfile::new().nic(Nic::new("eth0", 2)).build();
    Sim::builder().host(host).build().run(|| {
        let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, NETLINK_GENERIC) };
        assert!(fd >= 0);

        let mut body = vec![3u8, 1, 0, 0]; // genlmsghdr: CTRL_CMD_GETFAMILY, version 1
        push_attr(&mut body, 2, b"netdev\0"); // CTRL_ATTR_FAMILY_NAME
        let request = nl_message(GENL_ID_CTRL, NLM_F_REQUEST, 1, &body);
        let reply = round_trip(fd, &request);

        let ty = u16::from_ne_bytes([reply[4], reply[5]]);
        assert_eq!(ty, GENL_ID_CTRL, "controller reply");
        assert_eq!(reply[16], 1, "genl cmd CTRL_CMD_NEWFAMILY");

        let family_id = find_attr(&reply[20..], 1).expect("CTRL_ATTR_FAMILY_ID present");
        assert_eq!(u16::from_ne_bytes([family_id[0], family_id[1]]), 24, "netdev family id");

        unsafe { libc::close(fd) };
    });
}

#[test]
fn genetlink_rejects_an_unknown_family() {
    let host = HostProfile::new().build();
    Sim::builder().host(host).build().run(|| {
        let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, NETLINK_GENERIC) };
        let mut body = vec![3u8, 1, 0, 0];
        push_attr(&mut body, 2, b"nosuch\0");
        let request = nl_message(GENL_ID_CTRL, NLM_F_REQUEST, 2, &body);
        let reply = round_trip(fd, &request);

        let ty = u16::from_ne_bytes([reply[4], reply[5]]);
        assert_eq!(ty, 2, "NLMSG_ERROR");
        let errno = i32::from_ne_bytes([reply[16], reply[17], reply[18], reply[19]]);
        assert_eq!(errno, -libc::ENODEV, "unknown family -> ENODEV");
        unsafe { libc::close(fd) };
    });
}

#[test]
fn rtm_getqdisc_reports_the_etf_root_qdisc() {
    let host = HostProfile::new()
        .nic(Nic::new("eth0", 2))
        .etf_qdisc(300_000, libc::CLOCK_TAI, 0)
        .build();
    Sim::builder().host(host).build().run(|| {
        let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, NETLINK_ROUTE) };
        assert!(fd >= 0);

        let tcmsg = [0u8; 20];
        let request = nl_message(38, NLM_F_REQUEST | NLM_F_DUMP, 3, &tcmsg);
        let reply = round_trip(fd, &request);

        let msglen = u32::from_ne_bytes([reply[0], reply[1], reply[2], reply[3]]) as usize;
        let ty = u16::from_ne_bytes([reply[4], reply[5]]);
        assert_eq!(ty, 36, "RTM_NEWQDISC");

        // Attributes follow the 16-byte nlmsghdr and the 20-byte tcmsg.
        let attrs = &reply[36..msglen];
        let kind = find_attr(attrs, 1).expect("TCA_KIND present");
        let end = kind.iter().position(|&b| b == 0).unwrap_or(kind.len());
        assert_eq!(&kind[..end], b"etf", "root qdisc kind");

        let opts = find_attr(attrs, 2).expect("TCA_OPTIONS present");
        let parms = find_attr(opts, 1).expect("TCA_ETF_PARMS present");
        let delta = i32::from_ne_bytes([parms[0], parms[1], parms[2], parms[3]]);
        let clockid = i32::from_ne_bytes([parms[4], parms[5], parms[6], parms[7]]);
        assert_eq!(delta, 300_000, "etf delta");
        assert_eq!(clockid, libc::CLOCK_TAI, "etf clockid");

        unsafe { libc::close(fd) };
    });
}
