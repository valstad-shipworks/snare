//! A `SimHost`'s CPU count is what the code under test counts: `sysconf(_SC_NPROCESSORS_CONF)`
//! is every CPU and `_SC_NPROCESSORS_ONLN` the online ones (man 3 sysconf), and
//! `std::thread::available_parallelism` follows (from `sched_getaffinity` on Linux, `sysconf` on
//! macOS). Without a host, the counts are the machine's.
#![cfg(unix)]

use snare::{HostProfile, Sim};

fn counts() -> (libc::c_long, libc::c_long, usize) {
    (
        unsafe { libc::sysconf(libc::_SC_NPROCESSORS_CONF) },
        unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) },
        std::thread::available_parallelism().unwrap().get(),
    )
}

#[test]
fn the_profiles_cpus_are_counted() {
    let host = HostProfile::new().cpus(3).build();
    assert_eq!(Sim::builder().host(host).build().run(counts), (3, 3, 3));
}

#[test]
fn offline_cpus_are_configured_but_not_online() {
    let host = HostProfile::new().cpus(4).online([0, 2]).build();
    let (conf, online, _) = Sim::builder().host(host).build().run(counts);
    assert_eq!((conf, online), (4, 2));
}

#[test]
fn each_sim_counts_its_own_cpus() {
    let a = Sim::builder()
        .host(HostProfile::new().cpus(3).build())
        .build()
        .run(|| std::thread::spawn(counts).join().unwrap());
    let b = Sim::builder()
        .host(HostProfile::new().cpus(5).build())
        .build()
        .run(counts);
    assert_eq!((a, b), ((3, 3, 3), (5, 5, 5)));
}

#[test]
fn without_a_host_the_machines_counts_apply() {
    let outside = counts();
    assert_eq!(Sim::builder().build().run(counts), outside);
}

#[test]
fn other_sysconf_names_reach_libc() {
    let outside = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    let host = HostProfile::new().cpus(3).build();
    let inside = Sim::builder()
        .host(host)
        .build()
        .run(|| unsafe { libc::sysconf(libc::_SC_PAGESIZE) });
    assert_eq!(inside, outside);
}
