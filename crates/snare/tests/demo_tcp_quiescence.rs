#![cfg(target_os = "linux")]
//! Quiescence: when every managed thread is parked in a sim wait and nothing can post, the run is
//! deadlocked, so the blocking wait gives up (EAGAIN) instead of hanging the test forever. The
//! readiness-backed waits — a blocking `eventfd` read (man 2 eventfd) among them — are the ones
//! that detect this. A test returning at all is the assertion that it did not hang.

use std::time::Duration;

fn eventfd(initval: u32) -> i32 {
    let fd = unsafe { libc::eventfd(initval, 0) };
    assert!(fd >= 0, "eventfd");
    fd
}

fn blocking_read_u64(fd: i32) -> isize {
    let mut buf = [0u8; 8];
    unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, 8) }
}

#[test]
fn lone_blocked_reader_gives_up() {
    snare::Sim::new().run(|| {
        // man 2 eventfd: reading a counter of 0 blocks. This is the only managed thread, so no
        // write can ever arrive — the classic self-deadlock, resolved by giving up.
        let efd = eventfd(0);
        assert_eq!(blocking_read_u64(efd), -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EAGAIN)
        );
        unsafe { libc::close(efd) };
    });
}

#[test]
fn reader_wakes_when_a_peer_thread_posts() {
    snare::Sim::new().run(|| {
        let efd = eventfd(0);
        let writer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(5));
            let one: u64 = 1;
            let w = unsafe { libc::write(efd, &one as *const _ as *const libc::c_void, 8) };
            assert_eq!(w, 8);
        });

        let mut buf = [0u8; 8];
        let n = unsafe { libc::read(efd, buf.as_mut_ptr() as *mut libc::c_void, 8) };
        assert_eq!(n, 8, "the writer satisfies the read; it is progress, not a deadlock");
        assert_eq!(u64::from_ne_bytes(buf), 1);
        writer.join().unwrap();
        unsafe { libc::close(efd) };
    });
}

#[test]
fn every_thread_blocked_on_its_own_fd_gives_up() {
    snare::Sim::new().run(|| {
        // Two managed threads, each parked on a counter nothing will post to. Quiescence needs
        // *all* live managed threads parked at once, so both must give up — including this one.
        let mine = eventfd(0);
        let reader = std::thread::spawn(move || {
            let theirs = eventfd(0);
            let n = blocking_read_u64(theirs);
            let e = std::io::Error::last_os_error().raw_os_error();
            unsafe { libc::close(theirs) };
            (n, e)
        });

        let n = blocking_read_u64(mine);
        assert_eq!(n, -1);
        assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::EAGAIN));
        assert_eq!(reader.join().unwrap(), (-1, Some(libc::EAGAIN)));
        unsafe { libc::close(mine) };
    });
}

#[test]
fn a_posted_eventfd_reads_without_blocking() {
    snare::Sim::new().run(|| {
        // Seeded non-zero, so the very first read succeeds and quiescence never comes into play.
        let efd = eventfd(7);
        let mut buf = [0u8; 8];
        let n = unsafe { libc::read(efd, buf.as_mut_ptr() as *mut libc::c_void, 8) };
        assert_eq!(n, 8);
        assert_eq!(u64::from_ne_bytes(buf), 7);
        unsafe { libc::close(efd) };
    });
}

#[test]
fn tcp_blocking_recv_with_no_peer_should_give_up() {
    // A blocking TCP `recv` on a connection whose peer never sends is the sole managed thread, so
    // the quiescence-aware readiness wait it parks on detects the deadlock and gives up rather than
    // hanging. The read returns an error instead of blocking forever.
    use std::io::Read;
    use std::net::TcpStream;
    use snare::{Line, Sim, connect_tester};

    Sim::new().run(|| {
        let _peer = connect_tester::<Line>("127.0.0.2:9440");
        let mut stream = TcpStream::connect("127.0.0.2:9440").unwrap();
        let mut buf = [0u8; 8];
        assert!(stream.read(&mut buf).is_err());
    });
}
