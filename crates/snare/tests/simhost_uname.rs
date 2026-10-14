//! `uname` reports the simulated host's kernel identity, and `HostProfile::real_uname` copies the
//! machine's own.
#![cfg(unix)]

use snare::{HostProfile, Sim};

#[derive(Debug, PartialEq, Eq)]
struct Uts {
    sysname: String,
    nodename: String,
    release: String,
    version: String,
    machine: String,
}

fn field(f: &[libc::c_char]) -> String {
    unsafe { std::ffi::CStr::from_ptr(f.as_ptr()) }
        .to_string_lossy()
        .into_owned()
}

fn from_utsname(u: &libc::utsname) -> Uts {
    Uts {
        sysname: field(&u.sysname),
        nodename: field(&u.nodename),
        release: field(&u.release),
        version: field(&u.version),
        machine: field(&u.machine),
    }
}

fn uname() -> Uts {
    let mut u: libc::utsname = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::uname(&mut u) }, 0);
    from_utsname(&u)
}

fn in_sim(profile: HostProfile) -> Uts {
    Sim::builder().host(profile.build()).build().run(uname)
}

#[test]
fn default_profile_reports_a_fixed_kernel() {
    let uts = in_sim(HostProfile::new());
    assert_eq!(uts.nodename, "snare");
    if cfg!(target_os = "linux") {
        assert_eq!(uts.sysname, "Linux");
        assert_eq!(uts.release, "6.12.0");
        assert_eq!(uts.version, "#1 SMP PREEMPT_DYNAMIC");
        assert_eq!(uts.machine, std::env::consts::ARCH);
    } else {
        assert_eq!(uts.sysname, "Darwin");
        assert_eq!(uts.release, "25.0.0");
        assert!(uts.version.starts_with("Darwin Kernel Version 25.0.0"));
        let arch = if cfg!(target_arch = "aarch64") {
            "arm64"
        } else {
            "x86_64"
        };
        assert_eq!(uts.machine, arch);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn preempt_rt_shows_in_the_version() {
    let uts = in_sim(HostProfile::new().preempt_rt(true));
    assert!(uts.version.contains("PREEMPT_RT"), "{uts:?}");
    let pinned = in_sim(HostProfile::new().preempt_rt(true).kernel_version("#7 SMP"));
    assert_eq!(pinned.version, "#7 SMP");
}

#[test]
fn configured_fields_are_reported_and_truncated_to_fit() {
    let long = "x".repeat(400);
    let uts = in_sim(
        HostProfile::new()
            .sysname("Plan9")
            .nodename(long.as_str())
            .kernel_release("6.6.30-rt30")
            .kernel_version("#1 SMP PREEMPT_RT Fri Jan 3 00:00:00 UTC 2025")
            .machine("riscv64"),
    );
    let capacity = unsafe { std::mem::zeroed::<libc::utsname>() }
        .nodename
        .len()
        - 1;
    assert_eq!(uts.sysname, "Plan9");
    assert_eq!(uts.nodename, long[..capacity]);
    assert_eq!(uts.release, "6.6.30-rt30");
    assert_eq!(uts.version, "#1 SMP PREEMPT_RT Fri Jan 3 00:00:00 UTC 2025");
    assert_eq!(uts.machine, "riscv64");
}

#[test]
fn real_uname_matches_the_machine() {
    let real = uname();
    let profile = HostProfile::new().real_uname().unwrap();
    assert_eq!(in_sim(profile), real);
}

#[test]
fn real_uname_inside_a_sim_reads_the_machine() {
    let real = uname();
    let copied = Sim::builder()
        .host(HostProfile::new().build())
        .build()
        .run(|| HostProfile::new().real_uname().unwrap());
    assert_eq!(in_sim(copied), real);
}

#[test]
fn without_a_host_uname_is_the_machines() {
    let real = uname();
    assert_eq!(Sim::new().run(uname), real);
}

#[cfg(target_os = "linux")]
#[test]
fn raw_syscall_is_served_too() {
    let uts = Sim::builder()
        .host(HostProfile::new().kernel_release("5.15.0").build())
        .build()
        .run(|| {
            let mut u: libc::utsname = unsafe { std::mem::zeroed() };
            assert_eq!(unsafe { libc::syscall(libc::SYS_uname, &mut u) }, 0);
            from_utsname(&u)
        });
    assert_eq!(uts.release, "5.15.0");
}

fn errno() -> Option<i32> {
    std::io::Error::last_os_error().raw_os_error()
}

fn gethostname(len: usize) -> (libc::c_int, Vec<u8>) {
    let mut buf = vec![b'#'; len];
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), len) };
    (rc, buf)
}

fn hostname() -> String {
    let (rc, buf) = gethostname(300);
    assert_eq!(rc, 0);
    let end = buf.iter().position(|&b| b == 0).unwrap();
    String::from_utf8(buf[..end].to_vec()).unwrap()
}

fn in_sim_hostname(profile: HostProfile) -> String {
    Sim::builder().host(profile.build()).build().run(hostname)
}

#[test]
fn gethostname_reports_the_nodename() {
    let names = Sim::builder()
        .host(HostProfile::new().nodename("rig-7").build())
        .build()
        .run(|| (hostname(), uname().nodename));
    assert_eq!(names, ("rig-7".to_string(), "rig-7".to_string()));
    assert_eq!(in_sim_hostname(HostProfile::new()), "snare");
}

#[test]
fn gethostname_cuts_a_long_nodename_as_uname_does() {
    let long = "y".repeat(400);
    let uts = in_sim(HostProfile::new().nodename(long.as_str()));
    let name = in_sim_hostname(HostProfile::new().nodename(long.as_str()));
    assert_eq!(name, uts.nodename);
}

#[test]
fn gethostname_short_buffers_follow_the_libc() {
    let (rc, errno, buf) = Sim::builder()
        .host(HostProfile::new().nodename("rig-7").build())
        .build()
        .run(|| {
            let (rc, buf) = gethostname(4);
            (rc, errno(), buf)
        });
    if cfg!(target_os = "linux") {
        assert_eq!(
            (rc, errno, buf),
            (-1, Some(libc::ENAMETOOLONG), b"rig-".to_vec())
        );
    } else {
        assert_eq!((rc, buf), (0, b"rig\0".to_vec()));
    }
}

#[cfg(target_os = "linux")]
#[test]
fn fortified_gethostname_is_served_too() {
    unsafe extern "C" {
        fn __gethostname_chk(name: *mut libc::c_char, len: usize, real: usize) -> libc::c_int;
    }
    let out = Sim::builder()
        .host(HostProfile::new().nodename("rig-7").build())
        .build()
        .run(|| {
            let mut buf = [b'#'; 16];
            let rc = unsafe { __gethostname_chk(buf.as_mut_ptr().cast(), 16, 16) };
            let mut short = [b'#'; 4];
            let short_rc = unsafe { __gethostname_chk(short.as_mut_ptr().cast(), 4, 4) };
            (rc, buf, short_rc, errno(), short)
        });
    assert_eq!(
        out,
        (
            0,
            *b"rig-7\0##########",
            -1,
            Some(libc::ENAMETOOLONG),
            *b"rig-"
        )
    );
}

#[test]
fn without_a_host_gethostname_is_the_machines() {
    let real = hostname();
    assert_eq!(Sim::new().run(hostname), real);
}

#[test]
fn an_unprivileged_sethostname_is_refused() {
    let (rc, errno, uts) = Sim::builder()
        .host(HostProfile::new().nodename("rig-7").build())
        .build()
        .run(|| {
            let rc = unsafe { libc::sethostname(c"other".as_ptr(), 5) };
            (rc, errno(), uname())
        });
    assert_eq!((rc, errno), (-1, Some(libc::EPERM)));
    assert_eq!(uts.nodename, "rig-7");
}

#[cfg(target_os = "linux")]
#[test]
fn linux_sethostname_needs_cap_sys_admin_even_as_root() {
    let out = Sim::builder()
        .host(HostProfile::new().root(true).build())
        .build()
        .run(|| {
            let named = unsafe { libc::sethostname(c"other".as_ptr(), 5) };
            let named_errno = errno();
            let raw = unsafe { libc::syscall(libc::SYS_sethostname, c"other".as_ptr(), 5) };
            (named, named_errno, raw, errno(), hostname())
        });
    assert_eq!(
        out,
        (
            -1,
            Some(libc::EPERM),
            -1,
            Some(libc::EPERM),
            "snare".to_string()
        )
    );
}

#[cfg(target_os = "linux")]
#[test]
fn proc_sys_kernel_reports_the_identity() {
    let read = |name: &str| std::fs::read_to_string(format!("/proc/sys/kernel/{name}")).unwrap();
    let out = Sim::builder()
        .host(
            HostProfile::new()
                .nodename("rig-7")
                .kernel_release("6.6.30-rt30")
                .build(),
        )
        .build()
        .run(|| ["hostname", "domainname", "ostype", "osrelease", "version"].map(read));
    assert_eq!(
        out,
        [
            "rig-7\n",
            "(none)\n",
            "Linux\n",
            "6.6.30-rt30\n",
            "#1 SMP PREEMPT_DYNAMIC\n"
        ]
    );
}

#[cfg(target_os = "macos")]
fn kern_string(name: &std::ffi::CStr) -> Result<String, i32> {
    let mut buf = [0u8; 300];
    let mut len = buf.len();
    let rc = unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            buf.as_mut_ptr().cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return Err(errno().unwrap());
    }
    Ok(String::from_utf8(buf[..len - 1].to_vec()).unwrap())
}

#[cfg(target_os = "macos")]
fn kern_by_mib(node: libc::c_int) -> String {
    let mut mib = [libc::CTL_KERN, node];
    let mut buf = [0u8; 300];
    let mut len = buf.len();
    let rc = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            2,
            buf.as_mut_ptr().cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    assert_eq!(rc, 0);
    String::from_utf8(buf[..len - 1].to_vec()).unwrap()
}

#[cfg(target_os = "macos")]
#[test]
fn kern_sysctls_follow_the_profile() {
    let profile = HostProfile::new()
        .nodename("rig-7")
        .kernel_release("24.1.0")
        .kernel_version("Darwin Kernel Version 24.1.0: test");
    let (by_name, by_mib) = Sim::builder().host(profile.build()).build().run(|| {
        let names = [
            c"kern.ostype",
            c"kern.osrelease",
            c"kern.version",
            c"kern.hostname",
        ];
        let mibs = [
            libc::KERN_OSTYPE,
            libc::KERN_OSRELEASE,
            libc::KERN_VERSION,
            libc::KERN_HOSTNAME,
        ];
        (names.map(kern_string), mibs.map(kern_by_mib))
    });
    let expected = [
        "Darwin",
        "24.1.0",
        "Darwin Kernel Version 24.1.0: test",
        "rig-7",
    ];
    assert_eq!(by_name, expected.map(|s| Ok(s.to_string())));
    assert_eq!(by_mib, expected.map(str::to_string));
}

#[cfg(target_os = "macos")]
#[test]
fn root_renames_the_sim_host_and_never_the_machine() {
    let machine = hostname();
    let renamed = Sim::builder()
        .host(HostProfile::new().root(true).build())
        .build()
        .run(|| {
            let state = || (hostname(), uname().nodename, kern_string(c"kern.hostname"));
            let mut out = Vec::new();
            let rc = unsafe { libc::sethostname(c"bench".as_ptr(), 5) };
            out.push((rc, None, state()));
            let long = [b'z'; 256];
            let rc = unsafe { libc::sethostname(long.as_ptr().cast(), 256) };
            out.push((rc, errno(), state()));
            let rc = unsafe { libc::sethostname(b"ab\0cd".as_ptr().cast(), 5) };
            out.push((rc, None, state()));
            let rc = unsafe {
                libc::sysctlbyname(
                    c"kern.hostname".as_ptr(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    c"by-sysctl".as_ptr() as *mut _,
                    9,
                )
            };
            out.push((rc, None, state()));
            out
        });
    let named = |v: &str| (v.to_string(), v.to_string(), Ok(v.to_string()));
    assert_eq!(
        renamed,
        [
            (0, None, named("bench")),
            (-1, Some(libc::EINVAL), named("bench")),
            (0, None, named("ab")),
            (0, None, named("by-sysctl")),
        ]
    );
    assert_eq!(hostname(), machine);
}
