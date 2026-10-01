#![cfg(target_os = "linux")]

//! `/dev/cpu_dma_latency` is the PM QoS interface a latency-sensitive program holds open to cap
//! CPU idle-state exit latency: it opens the device, writes a little-endian 32-bit microsecond
//! target, and keeps the fd open for the lifetime of the constraint (closing it drops the request).
//! See Documentation/admin-guide/pm/cpuidle.rst and Documentation/power/pm_qos_interface.rst. The
//! sim serves the whole lifecycle in-process, so a test needs neither the real device nor root.

use snare::{HostProfile, Sim};

fn open_latency() -> libc::c_int {
    let fd = unsafe { libc::open(c"/dev/cpu_dma_latency".as_ptr(), libc::O_WRONLY) };
    assert!(fd >= 0, "the sim exposes /dev/cpu_dma_latency without root");
    fd
}

#[test]
fn opens_without_privilege() {
    let host = HostProfile::new().build();
    Sim::builder().host(host).build().run(|| {
        let fd = open_latency();
        unsafe { libc::close(fd) };
    });
}

#[test]
fn writing_a_target_latency_succeeds() {
    let host = HostProfile::new().build();
    Sim::builder().host(host).build().run(|| {
        let fd = open_latency();
        // Zero microseconds: the strongest request, pinning the CPU out of deep idle states.
        let target: i32 = 0;
        let n = unsafe {
            libc::write(fd, (&target as *const i32).cast(), std::mem::size_of::<i32>())
        };
        assert_eq!(n, 4, "a 4-byte PM QoS target is accepted");
        unsafe { libc::close(fd) };
    });
}

#[test]
fn a_nonzero_cap_is_accepted() {
    let host = HostProfile::new().build();
    Sim::builder().host(host).build().run(|| {
        let fd = open_latency();
        let target: i32 = 5; // 5µs, a typical real-time cap
        let n = unsafe {
            libc::write(fd, (&target as *const i32).cast(), std::mem::size_of::<i32>())
        };
        assert_eq!(n, 4);
        unsafe { libc::close(fd) };
    });
}

#[test]
fn the_constraint_can_be_held_then_released_and_reacquired() {
    let host = HostProfile::new().build();
    Sim::builder().host(host).build().run(|| {
        // Hold, drop, and reacquire: the kernel resets the cap when the last writer closes the fd,
        // and a fresh open must work again.
        let fd = open_latency();
        let target: i32 = 10;
        unsafe {
            libc::write(fd, (&target as *const i32).cast(), std::mem::size_of::<i32>());
            libc::close(fd);
        }
        let fd2 = open_latency();
        assert!(fd2 >= 0, "reopening after release works");
        unsafe { libc::close(fd2) };
    });
}

#[test]
fn two_writers_can_hold_the_device_at_once() {
    let host = HostProfile::new().build();
    Sim::builder().host(host).build().run(|| {
        // Each open gets its own fd; PM QoS aggregates concurrent constraints.
        let a = open_latency();
        let b = open_latency();
        assert!(a >= 0 && b >= 0 && a != b, "independent descriptors");
        unsafe {
            libc::close(a);
            libc::close(b);
        }
    });
}

#[test]
fn a_short_write_is_tolerated() {
    let host = HostProfile::new().build();
    Sim::builder().host(host).build().run(|| {
        // A write shorter than the 4-byte target does not update the cap but still reports its
        // byte count rather than erroring.
        let fd = open_latency();
        let two = [0u8; 2];
        let n = unsafe { libc::write(fd, two.as_ptr().cast(), two.len()) };
        assert_eq!(n, 2, "a partial write returns its length");
        unsafe { libc::close(fd) };
    });
}
