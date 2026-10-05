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
