#![cfg(target_os = "linux")]

use snare::Sim;

/// A blocking read that nothing can ever satisfy used to hang forever. With quiescence detection,
/// once every managed thread is parked in a sim wait the run is deadlocked, so the wait gives up
/// (EAGAIN) instead. This test returning at all is the assertion that it no longer hangs.
#[test]
fn blocking_read_with_no_writer_gives_up_instead_of_hanging() {
    Sim::new().run(|| {
        // A blocking eventfd (counter 0). This is the only managed thread, so nothing will ever
        // post to it — the classic self-deadlock.
        let efd = unsafe { libc::eventfd(0, 0) };
        assert!(efd >= 0, "eventfd");

        let mut buf = [0u8; 8];
        let n = unsafe { libc::read(efd, buf.as_mut_ptr() as *mut libc::c_void, 8) };
        assert_eq!(
            n, -1,
            "the deadlocked read returns rather than blocking forever"
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EAGAIN)
        );
        unsafe { libc::close(efd) };
    });
}

/// A second managed thread that eventually posts keeps the first from being declared quiescent —
/// the read blocks, then succeeds when the writer runs. (Progress, not deadlock.)
#[test]
fn blocking_read_wakes_when_another_thread_posts() {
    Sim::new().run(|| {
        let efd = unsafe { libc::eventfd(0, 0) };
        assert!(efd >= 0);

        let writer = std::thread::spawn(move || {
            // A real sleep is virtualized (AFAP), so this returns at once but leaves the reader
            // parked < live until the write lands.
            std::thread::sleep(std::time::Duration::from_millis(5));
            let one: u64 = 1;
            let w = unsafe { libc::write(efd, &one as *const _ as *const libc::c_void, 8) };
            assert_eq!(w, 8);
        });

        let mut buf = [0u8; 8];
        let n = unsafe { libc::read(efd, buf.as_mut_ptr() as *mut libc::c_void, 8) };
        assert_eq!(
            n, 8,
            "the read is satisfied by the writer, not declared a deadlock"
        );
        assert_eq!(u64::from_ne_bytes(buf), 1);
        writer.join().unwrap();
        unsafe { libc::close(efd) };
    });
}
