#![cfg(target_os = "linux")]

//! Generic netlink (genetlink) controller lookups against the SimHost backend.
//!
//! Protocol reference: man 7 netlink (framing) and the genetlink controller protocol in
//! <linux/genetlink.h> — a CTRL_CMD_GETFAMILY request carrying CTRL_ATTR_FAMILY_NAME resolves a
//! named family to its dynamically allocated numeric id (CTRL_ATTR_FAMILY_ID). Background:
//! Documentation/userspace-api/netlink/intro.rst. The "netdev" family is the one ethtool's
//! netlink interface and modern NIC tooling query.

use snare::{HostProfile, Nic, Sim};

const NETLINK_GENERIC: i32 = 16;
const GENL_ID_CTRL: u16 = 16;
const NLMSG_ERROR: u16 = 2;
const NLM_F_REQUEST: u16 = 1;
const CTRL_CMD_NEWFAMILY: u8 = 1;
const CTRL_CMD_GETFAMILY: u8 = 3;
const CTRL_ATTR_FAMILY_ID: u16 = 1;
const CTRL_ATTR_FAMILY_NAME: u16 = 2;
const NETDEV_FAMILY_ID: u16 = 24;

fn u16at(b: &[u8], o: usize) -> u16 {
    u16::from_ne_bytes([b[o], b[o + 1]])
}
fn i32at(b: &[u8], o: usize) -> i32 {
    i32::from_ne_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

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

/// Send a CTRL_CMD_GETFAMILY for `family` and return the raw controller reply.
fn getfamily(fd: i32, family: &[u8], seq: u32) -> Vec<u8> {
    // genlmsghdr: cmd u8, version u8, reserved u16.
    let mut body = vec![CTRL_CMD_GETFAMILY, 1, 0, 0];
    let mut nul = family.to_vec();
    nul.push(0);
    push_attr(&mut body, CTRL_ATTR_FAMILY_NAME, &nul);
    let request = nl_message(GENL_ID_CTRL, NLM_F_REQUEST, seq, &body);
    let sent = unsafe {
        libc::send(
            fd,
            request.as_ptr() as *const libc::c_void,
            request.len(),
            0,
        )
    };
    assert_eq!(sent, request.len() as isize);
    let mut reply = vec![0u8; 4096];
    let got = unsafe { libc::recv(fd, reply.as_mut_ptr() as *mut libc::c_void, reply.len(), 0) };
    assert!(got > 0, "recv controller reply");
    reply.truncate(got as usize);
    reply
}

fn generic_socket() -> i32 {
    let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, NETLINK_GENERIC) };
    assert!(fd >= 0, "AF_NETLINK/NETLINK_GENERIC socket");
    fd
}

#[test]
fn netdev_family_resolves_to_its_id() {
    let host = HostProfile::new().nic(Nic::new("eth0", 2)).build();
    Sim::builder().host(host).build().run(|| {
        let fd = generic_socket();
        let reply = getfamily(fd, b"netdev", 1);
        unsafe { libc::close(fd) };

        assert_eq!(
            u16at(&reply, 4),
            GENL_ID_CTRL,
            "reply comes from the controller"
        );
        assert_eq!(reply[16], CTRL_CMD_NEWFAMILY, "cmd is CTRL_CMD_NEWFAMILY");
        let id = find_attr(&reply[20..], CTRL_ATTR_FAMILY_ID).expect("CTRL_ATTR_FAMILY_ID present");
        assert_eq!(u16at(id, 0), NETDEV_FAMILY_ID);
    });
}

#[test]
fn family_reply_echoes_the_name_and_seq() {
    let host = HostProfile::new().build();
    Sim::builder().host(host).build().run(|| {
        let fd = generic_socket();
        let reply = getfamily(fd, b"netdev", 77);
        unsafe { libc::close(fd) };
        let name = find_attr(&reply[20..], CTRL_ATTR_FAMILY_NAME).expect("family name present");
        let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
        assert_eq!(&name[..end], b"netdev");
        assert_eq!(
            u16::from_ne_bytes([reply[8], reply[9]]) as u32,
            77,
            "seq echoed"
        );
    });
}

#[test]
fn unknown_family_is_enodev() {
    let host = HostProfile::new().build();
    Sim::builder().host(host).build().run(|| {
        let fd = generic_socket();
        let reply = getfamily(fd, b"nosuchfam", 2);
        unsafe { libc::close(fd) };
        assert_eq!(u16at(&reply, 4), NLMSG_ERROR, "reply is NLMSG_ERROR");
        // NLMSG_ERROR's payload leads with the negated errno (man 7 netlink).
        assert_eq!(
            i32at(&reply, 16),
            -libc::ENODEV,
            "unknown family -> -ENODEV"
        );
    });
}

#[test]
fn empty_family_name_is_enodev() {
    let host = HostProfile::new().build();
    Sim::builder().host(host).build().run(|| {
        let fd = generic_socket();
        let reply = getfamily(fd, b"", 3);
        unsafe { libc::close(fd) };
        assert_eq!(u16at(&reply, 4), NLMSG_ERROR);
        assert_eq!(i32at(&reply, 16), -libc::ENODEV);
    });
}

#[test]
fn non_getfamily_command_is_enodev() {
    // A controller command other than CTRL_CMD_GETFAMILY is not modelled and errors out.
    const CTRL_CMD_GETOPS: u8 = 6;
    let host = HostProfile::new().build();
    Sim::builder().host(host).build().run(|| {
        let fd = generic_socket();
        let mut body = vec![CTRL_CMD_GETOPS, 1, 0, 0];
        push_attr(&mut body, CTRL_ATTR_FAMILY_NAME, b"netdev\0");
        let request = nl_message(GENL_ID_CTRL, NLM_F_REQUEST, 4, &body);
        unsafe {
            libc::send(
                fd,
                request.as_ptr() as *const libc::c_void,
                request.len(),
                0,
            )
        };
        let mut reply = vec![0u8; 4096];
        let got =
            unsafe { libc::recv(fd, reply.as_mut_ptr() as *mut libc::c_void, reply.len(), 0) };
        reply.truncate(got as usize);
        unsafe { libc::close(fd) };
        assert_eq!(u16at(&reply, 4), NLMSG_ERROR);
        assert_eq!(i32at(&reply, 16), -libc::ENODEV);
    });
}

#[test]
fn family_id_is_stable_across_lookups() {
    let host = HostProfile::new().build();
    Sim::builder().host(host).build().run(|| {
        let fd = generic_socket();
        let a = getfamily(fd, b"netdev", 1);
        let b = getfamily(fd, b"netdev", 2);
        unsafe { libc::close(fd) };
        let id = |r: &[u8]| u16at(find_attr(&r[20..], CTRL_ATTR_FAMILY_ID).unwrap(), 0);
        assert_eq!(
            id(&a),
            id(&b),
            "the family id does not drift between queries"
        );
    });
}
