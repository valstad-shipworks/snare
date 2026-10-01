#![cfg(target_os = "linux")]

//! Datagram socket options: set/get round-trips, defaults, and the errno path. The sim stores an
//! option's bytes under `(level, name)` and reads them back, modelling getsockopt(2)/setsockopt(2)
//! for the options a timestamping/pacing test needs (SO_PRIORITY, SO_TIMESTAMPING, SO_TXTIME).
//! Option names and levels are from socket(7) / asm-generic/socket.h.

use snare::{HostProfile, Sim};

const SO_TIMESTAMPING: i32 = 37;
const SOF_TIMESTAMPING_RX_SOFTWARE: u32 = 1 << 3;
const SOF_TIMESTAMPING_SOFTWARE: u32 = 1 << 4;

fn udp_socket() -> i32 {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    assert!(fd >= 0);
    fd
}

fn set_i32(fd: i32, name: i32, val: i32) -> i32 {
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            name,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of::<i32>() as u32,
        )
    }
}

fn get_i32(fd: i32, name: i32) -> (i32, i32, u32) {
    let mut got: i32 = 0;
    let mut len = std::mem::size_of::<i32>() as u32;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            name,
            &mut got as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    (rc, got, len)
}

fn errno() -> i32 {
    unsafe { *libc::__errno_location() }
}

#[test]
fn so_priority_round_trips() {
    // SO_PRIORITY sets the packet priority used for qdisc classing (socket(7)).
    Sim::builder().host(HostProfile::new().build()).build().run(|| {
        let fd = udp_socket();
        assert_eq!(set_i32(fd, libc::SO_PRIORITY, 6), 0);
        let (rc, got, len) = get_i32(fd, libc::SO_PRIORITY);
        assert_eq!(rc, 0);
        assert_eq!(got, 6);
        assert_eq!(len, std::mem::size_of::<i32>() as u32);
        unsafe { libc::close(fd) };
    });
}

#[test]
fn so_priority_accepts_boundary_values() {
    // The classic Linux band range is 0..=6; the highest, TC_PRIO_CONTROL-ish traffic, is what an
    // RT sender sets. The store is exact for each value.
    Sim::builder().host(HostProfile::new().build()).build().run(|| {
        for want in [0, 1, 6, 7] {
            let fd = udp_socket();
            assert_eq!(set_i32(fd, libc::SO_PRIORITY, want), 0);
            let (rc, got, _) = get_i32(fd, libc::SO_PRIORITY);
            assert_eq!(rc, 0);
            assert_eq!(got, want, "SO_PRIORITY {want} stored exactly");
            unsafe { libc::close(fd) };
        }
    });
}

#[test]
fn an_unset_option_reads_back_as_zero() {
    // getsockopt(2): a never-set integer option reads a modelled default of zero (it does not fail).
    Sim::builder().host(HostProfile::new().build()).build().run(|| {
        let fd = udp_socket();
        let (rc, got, len) = get_i32(fd, libc::SO_PRIORITY);
        assert_eq!(rc, 0);
        assert_eq!(got, 0);
        assert!(len <= std::mem::size_of::<i32>() as u32);
        unsafe { libc::close(fd) };
    });
}

#[test]
fn getsockopt_with_null_value_is_efault() {
    // getsockopt(2): a NULL optval pointer is EFAULT.
    Sim::builder().host(HostProfile::new().build()).build().run(|| {
        let fd = udp_socket();
        let mut len = std::mem::size_of::<i32>() as u32;
        let rc = unsafe {
            libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_PRIORITY, std::ptr::null_mut(), &mut len)
        };
        assert_eq!(rc, -1);
        assert_eq!(errno(), libc::EFAULT);
        unsafe { libc::close(fd) };
    });
}

#[test]
fn distinct_options_are_stored_independently() {
    Sim::builder().host(HostProfile::new().build()).build().run(|| {
        let fd = udp_socket();
        assert_eq!(set_i32(fd, libc::SO_PRIORITY, 3), 0);
        assert_eq!(set_i32(fd, libc::SO_RCVBUF, 65536), 0);
        let (_, prio, _) = get_i32(fd, libc::SO_PRIORITY);
        let (_, rcvbuf, _) = get_i32(fd, libc::SO_RCVBUF);
        assert_eq!(prio, 3);
        assert_eq!(rcvbuf, 65536, "a second option does not clobber the first");
        unsafe { libc::close(fd) };
    });
}

#[test]
fn the_last_write_of_an_option_wins() {
    Sim::builder().host(HostProfile::new().build()).build().run(|| {
        let fd = udp_socket();
        assert_eq!(set_i32(fd, libc::SO_PRIORITY, 2), 0);
        assert_eq!(set_i32(fd, libc::SO_PRIORITY, 5), 0);
        let (_, got, _) = get_i32(fd, libc::SO_PRIORITY);
        assert_eq!(got, 5);
        unsafe { libc::close(fd) };
    });
}

#[test]
fn timestamping_flags_survive_a_priority_write() {
    // Setting SO_PRIORITY must not disturb the SO_TIMESTAMPING generation mask (they are separate
    // options); a later recvmsg still gets its rx stamp.
    Sim::builder().host(HostProfile::new().build()).build().run(|| {
        let fd = udp_socket();
        let flags = SOF_TIMESTAMPING_SOFTWARE | SOF_TIMESTAMPING_RX_SOFTWARE;
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                SO_TIMESTAMPING,
                &flags as *const _ as *const libc::c_void,
                std::mem::size_of::<u32>() as u32,
            )
        };
        assert_eq!(rc, 0);
        assert_eq!(set_i32(fd, libc::SO_PRIORITY, 4), 0);

        let mut got: u32 = 0;
        let mut len = std::mem::size_of::<u32>() as u32;
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                SO_TIMESTAMPING,
                &mut got as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        assert_eq!(rc, 0);
        assert_eq!(got, flags, "timestamping mask untouched by the SO_PRIORITY write");
        unsafe { libc::close(fd) };
    });
}
