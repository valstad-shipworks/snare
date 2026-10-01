#![cfg(windows)]

//! Quiescence on Windows: when every managed thread is parked in a sim wait and nothing can post,
//! the run is deadlocked, so the blocking wait gives up (`WouldBlock`) instead of hanging. A thread
//! that gives up first and then joins a still-parked peer must itself count as parked — std's
//! `JoinHandle::join` is `WaitForSingleObject` on the thread handle, hooked to mark quiescence — or
//! the peer would never reach the quiescence threshold and both would hang. The Berkeley-sockets
//! counterpart is `tests/demo_tcp_quiescence.rs`.

use std::net::UdpSocket;

use snare::Sim;

#[test]
fn lone_blocked_reader_gives_up() {
    Sim::new().run(|| {
        // The only managed thread, parked on a datagram nothing will ever send: a self-deadlock
        // resolved by giving up rather than blocking forever.
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut buf = [0u8; 8];
        assert!(sock.recv_from(&mut buf).is_err());
    });
}

#[test]
fn every_thread_blocked_gives_up_including_the_joiner() {
    Sim::new().run(|| {
        // Two managed threads, each parked on a socket nothing will post to. Quiescence needs
        // *all* live managed threads parked at once. Whichever gives up first then blocks in
        // `join` on the other; that join must count, or the still-parked peer never reaches the
        // threshold and the test hangs.
        let mine = UdpSocket::bind("127.0.0.1:0").unwrap();
        let reader = std::thread::spawn(|| {
            let theirs = UdpSocket::bind("127.0.0.1:0").unwrap();
            let mut buf = [0u8; 8];
            theirs.recv_from(&mut buf).is_err()
        });

        let mut buf = [0u8; 8];
        assert!(mine.recv_from(&mut buf).is_err());
        assert!(reader.join().unwrap(), "the peer also gave up rather than hang");
    });
}

#[test]
fn a_condvar_wait_counts_toward_quiescence() {
    // std's Condvar blocks in `WaitOnAddress` on Windows 8+. The waiter can only be released by
    // main, which is parked on a socket nothing will send to: main's receive must see both threads
    // blocked and give up, which needs the condvar wait counted as parked.
    use std::sync::{Arc, Condvar, Mutex};
    Sim::new().run(|| {
        let pair = Arc::new((Mutex::new(false), Condvar::new()));
        let theirs = pair.clone();
        let waiter = std::thread::spawn(move || {
            let (flag, cv) = &*theirs;
            let mut set = flag.lock().unwrap();
            while !*set {
                set = cv.wait(set).unwrap();
            }
        });

        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut buf = [0u8; 8];
        assert!(sock.recv_from(&mut buf).is_err(), "the deadlocked receive gave up");

        let (flag, cv) = &*pair;
        *flag.lock().unwrap() = true;
        cv.notify_one();
        waiter.join().unwrap();
    });
}

#[test]
fn a_contended_mutex_counts_toward_quiescence() {
    // The holder keeps a lock while parked on a socket nothing will send to; main blocks on that
    // lock (`WaitOnAddress`). Only with main counted does the holder's receive see the deadlock,
    // give up and release the lock.
    use std::sync::{Arc, Mutex, mpsc};
    Sim::new().run(|| {
        let lock = Arc::new(Mutex::new(()));
        let held = lock.clone();
        let (locked_tx, locked_rx) = mpsc::channel();
        let holder = std::thread::spawn(move || {
            let _guard = held.lock().unwrap();
            locked_tx.send(()).unwrap();
            let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
            let mut buf = [0u8; 8];
            sock.recv_from(&mut buf).is_err()
        });
        locked_rx.recv().unwrap();
        drop(lock.lock().unwrap());
        assert!(holder.join().unwrap(), "the holder's receive gave up");
    });
}
