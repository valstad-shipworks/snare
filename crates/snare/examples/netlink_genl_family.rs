//! Resolve a generic-netlink family id by name through the genetlink controller.
//!
//! Opens AF_NETLINK/NETLINK_GENERIC inside a Sim and sends CTRL_CMD_GETFAMILY for "netdev",
//! then prints the numeric family id from CTRL_ATTR_FAMILY_ID.
//!
//! Protocol reference: the genetlink controller protocol in <linux/genetlink.h>
//! (CTRL_CMD_GETFAMILY, CTRL_ATTR_FAMILY_NAME/ID); framing per man 7 netlink. Run with:
//!     cargo run -p snare --example netlink_genl_family

#[cfg(target_os = "linux")]
fn main() {
    use snare::{HostProfile, Nic, Sim};

    const NETLINK_GENERIC: i32 = 16;
    const GENL_ID_CTRL: u16 = 16;
    const NLM_F_REQUEST: u16 = 1;
    const CTRL_CMD_GETFAMILY: u8 = 3;
    const CTRL_ATTR_FAMILY_ID: u16 = 1;
    const CTRL_ATTR_FAMILY_NAME: u16 = 2;

    fn u16at(b: &[u8], o: usize) -> u16 {
        u16::from_ne_bytes([b[o], b[o + 1]])
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

    let host = HostProfile::new().nic(Nic::new("eth0", 2)).build();
    Sim::builder().host(host).build().run(|| {
        let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, NETLINK_GENERIC) };
        assert!(fd >= 0);

        // genlmsghdr (cmd, version, reserved u16) + CTRL_ATTR_FAMILY_NAME "netdev".
        let mut body = vec![CTRL_CMD_GETFAMILY, 1, 0, 0];
        let name = b"netdev\0";
        let attr_len = (4 + name.len()) as u16;
        body.extend_from_slice(&attr_len.to_ne_bytes());
        body.extend_from_slice(&CTRL_ATTR_FAMILY_NAME.to_ne_bytes());
        body.extend_from_slice(name);
        while !body.len().is_multiple_of(4) {
            body.push(0);
        }

        let mut req = Vec::new();
        req.extend_from_slice(&((16 + body.len()) as u32).to_ne_bytes());
        req.extend_from_slice(&GENL_ID_CTRL.to_ne_bytes());
        req.extend_from_slice(&NLM_F_REQUEST.to_ne_bytes());
        req.extend_from_slice(&1u32.to_ne_bytes());
        req.extend_from_slice(&0u32.to_ne_bytes());
        req.extend_from_slice(&body);
        unsafe { libc::send(fd, req.as_ptr() as *const libc::c_void, req.len(), 0) };

        let mut reply = vec![0u8; 4096];
        let got =
            unsafe { libc::recv(fd, reply.as_mut_ptr() as *mut libc::c_void, reply.len(), 0) };
        assert!(got > 0);
        reply.truncate(got as usize);
        unsafe { libc::close(fd) };

        // Controller reply body starts after the 16-byte nlmsghdr + 4-byte genlmsghdr.
        let id = find_attr(&reply[20..], CTRL_ATTR_FAMILY_ID).expect("family id");
        println!("genetlink family \"netdev\" -> id {}", u16at(id, 0));
    });
}

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("netlink_genl_family: generic netlink is Linux-only; nothing to run on this platform");
}
