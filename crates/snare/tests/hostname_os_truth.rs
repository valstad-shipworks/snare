//! A host that copies the machine's `uname` answers `gethostname`, `sethostname` and, on macOS,
//! the `kern.*` sysctls `uname` is built from exactly as the machine does: the same return, errno
//! and bytes for every buffer size.
#![cfg(unix)]

use libc::c_int;
use snare::{HostProfile, Sim};

type Outcome = (c_int, c_int, Vec<u8>);

fn errno() -> c_int {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn machine_host() -> HostProfile {
    let root = unsafe { libc::geteuid() } == 0;
    HostProfile::new().real_uname().unwrap().root(root)
}

fn nodename() -> Vec<u8> {
    let mut u: libc::utsname = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::uname(&mut u) }, 0);
    unsafe { std::ffi::CStr::from_ptr(u.nodename.as_ptr()) }
        .to_bytes()
        .to_vec()
}

fn gethostname_at(len: usize) -> Outcome {
    let mut buf = [b'#'; 320];
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), len) };
    (rc, if rc == 0 { 0 } else { errno() }, buf.to_vec())
}

/// Every buffer length around the name's own and the libc limits. A zero length is left out on
/// macOS, whose `gethostname` then writes the byte before the buffer.
fn gethostname_outcomes() -> Vec<(usize, Outcome)> {
    let n = nodename().len();
    let mut lens = vec![1, 2, 4, n - 1, n, n + 1, n + 2, 64, 65, 255, 256, 257, 300];
    if cfg!(target_os = "linux") {
        lens.push(0);
    }
    lens.into_iter()
        .map(|len| (len, gethostname_at(len)))
        .collect()
}

#[test]
fn gethostname_matches_the_machine() {
    let real = gethostname_outcomes();
    let sim = Sim::builder()
        .host(machine_host().build())
        .build()
        .run(gethostname_outcomes);
    assert_eq!(sim, real);
    if cfg!(target_os = "linux") {
        let (_, short) = &real[1];
        assert_eq!((short.0, short.1), (-1, libc::ENAMETOOLONG));
    } else {
        let (_, short) = &real[1];
        assert_eq!((short.0, short.1, short.2[1]), (0, 0, 0));
    }
}

/// `sethostname` to the name the host already has, so a privileged run renames nothing.
fn sethostname_same() -> (c_int, c_int) {
    let name = nodename();
    let rc = unsafe { libc::sethostname(name.as_ptr().cast(), name.len() as _) };
    (rc, if rc == 0 { 0 } else { errno() })
}

#[test]
fn sethostname_matches_the_machine() {
    let real = sethostname_same();
    if cfg!(target_os = "linux") && real.0 == 0 {
        // The machine grants CAP_SYS_ADMIN, which the sim's privileges do not model.
        return;
    }
    let sim = Sim::builder()
        .host(machine_host().build())
        .build()
        .run(sethostname_same);
    assert_eq!(sim, real);
}

#[cfg(target_os = "macos")]
mod kern {
    use super::*;

    const NODES: [(&std::ffi::CStr, c_int); 4] = [
        (c"kern.ostype", libc::KERN_OSTYPE),
        (c"kern.osrelease", libc::KERN_OSRELEASE),
        (c"kern.version", libc::KERN_VERSION),
        (c"kern.hostname", libc::KERN_HOSTNAME),
    ];

    /// One `sysctl` or `sysctlbyname` call, through the MIB or the name.
    unsafe fn call(
        node: (&std::ffi::CStr, c_int),
        by_name: bool,
        oldp: *mut u8,
        oldlenp: *mut usize,
        newp: *const u8,
        newlen: usize,
    ) -> c_int {
        let mut mib = [libc::CTL_KERN, node.1];
        unsafe {
            if by_name {
                libc::sysctlbyname(node.0.as_ptr(), oldp.cast(), oldlenp, newp as _, newlen)
            } else {
                libc::sysctl(mib.as_mut_ptr(), 2, oldp.cast(), oldlenp, newp as _, newlen)
            }
        }
    }

    /// For each node, by MIB and by name: a size query, buffers of 0, 1, 4 and 300 bytes, a null
    /// length pointer, a call with neither buffer, and a write of the node's own value.
    fn outcomes() -> Vec<(usize, Outcome)> {
        let mut out = Vec::new();
        for node in NODES {
            for by_name in [false, true] {
                let mut len = 0usize;
                let null = std::ptr::null_mut();
                let rc = unsafe { call(node, by_name, null, &mut len, null, 0) };
                out.push((len, (rc, if rc == 0 { 0 } else { errno() }, Vec::new())));
                for room in [0usize, 1, 4, 300] {
                    let mut buf = [b'#'; 320];
                    let mut len = room;
                    let rc = unsafe { call(node, by_name, buf.as_mut_ptr(), &mut len, null, 0) };
                    out.push((len, (rc, if rc == 0 { 0 } else { errno() }, buf.to_vec())));
                }
                let mut buf = [b'#'; 320];
                let rc = unsafe {
                    call(
                        node,
                        by_name,
                        buf.as_mut_ptr(),
                        std::ptr::null_mut(),
                        null,
                        0,
                    )
                };
                out.push((0, (rc, if rc == 0 { 0 } else { errno() }, Vec::new())));
                let rc = unsafe { call(node, by_name, null, std::ptr::null_mut(), null, 0) };
                out.push((0, (rc, if rc == 0 { 0 } else { errno() }, Vec::new())));
                let mut value = [0u8; 320];
                let mut len = value.len();
                let rc = unsafe { call(node, by_name, value.as_mut_ptr(), &mut len, null, 0) };
                assert_eq!(rc, 0);
                let rc = unsafe {
                    call(
                        node,
                        by_name,
                        null,
                        std::ptr::null_mut(),
                        value.as_ptr(),
                        len - 1,
                    )
                };
                out.push((0, (rc, if rc == 0 { 0 } else { errno() }, Vec::new())));
            }
        }
        out
    }

    #[test]
    fn kern_identity_sysctls_match_the_machine() {
        let real = outcomes();
        let sim = Sim::builder()
            .host(machine_host().build())
            .build()
            .run(outcomes);
        assert_eq!(sim, real);
    }
}
