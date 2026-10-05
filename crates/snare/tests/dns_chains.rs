#![cfg(unix)]

//! Joined `getaddrinfo` lists hand every piece back to the OS when freed, on any thread and after
//! the sim is gone. A test binary of its own, so the process-wide count of joined lists is this
//! test's alone.

use std::ffi::{CStr, CString};
use std::net::IpAddr;
use std::{mem, ptr};

use snare::Sim;
use snare_interpose::joined_lists;

fn lookup_raw(name: &str) -> usize {
    let name = CString::new(name).unwrap();
    let mut hints: libc::addrinfo = unsafe { mem::zeroed() };
    hints.ai_flags = libc::AI_CANONNAME;
    let mut list = ptr::null_mut();
    assert_eq!(
        unsafe { libc::getaddrinfo(name.as_ptr(), ptr::null(), &hints, &mut list) },
        0
    );
    let canon = unsafe { CStr::from_ptr((*list).ai_canonname) };
    assert_eq!(canon.to_str().unwrap(), "Multi.local");
    list as usize
}

fn free_raw(list: usize) {
    unsafe { libc::freeaddrinfo(list as *mut libc::addrinfo) };
}

#[test]
fn freeaddrinfo_releases_chains() {
    let addrs: [IpAddr; 3] = [
        "127.0.0.50".parse().unwrap(),
        "fd00::50".parse().unwrap(),
        "127.0.0.51".parse().unwrap(),
    ];
    let sim = Sim::builder().add_host("Multi.local", addrs).build();
    let leftover = sim.run(|| {
        for _ in 0..10_000 {
            free_raw(lookup_raw("multi.local"));
        }
        assert_eq!(joined_lists(), 0);

        let lists: Vec<usize> = (0..1000).map(|_| lookup_raw("multi.local")).collect();
        assert_eq!(joined_lists(), 1000);
        std::thread::spawn(move || lists.into_iter().for_each(free_raw))
            .join()
            .unwrap();
        assert_eq!(joined_lists(), 0);

        let real = snare::real(|| {
            let mut list = ptr::null_mut();
            let rc = unsafe {
                libc::getaddrinfo(c"127.0.0.1".as_ptr(), ptr::null(), ptr::null(), &mut list)
            };
            assert_eq!(rc, 0);
            list as usize
        });
        assert_eq!(joined_lists(), 0);
        free_raw(real);

        (0..1000)
            .map(|_| lookup_raw("multi.local"))
            .collect::<Vec<_>>()
    });
    drop(sim);
    assert_eq!(joined_lists(), 1000);
    std::thread::spawn(move || leftover.into_iter().for_each(free_raw))
        .join()
        .unwrap();
    assert_eq!(joined_lists(), 0);
}
