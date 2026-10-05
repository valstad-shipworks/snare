#![cfg(target_os = "macos")]

//! The fabric's `kqueue`/`kevent` model, exercised directly with raw libc (no mio), to pin down
//! readiness and user-event (waker) behavior independent of any event-loop crate.

use std::net::UdpSocket;
use std::time::Duration;

use snare::Sim;

fn kev(ident: usize, filter: i16, flags: u16, fflags: u32, udata: u64) -> libc::kevent {
    libc::kevent {
        ident,
        filter,
        flags,
        fflags,
        data: 0,
        udata: udata as *mut libc::c_void,
    }
}

#[test]
fn udp_readable_fires_on_kqueue() {
    Sim::new().run(|| {
        let a = UdpSocket::bind("127.0.0.1:0").unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").unwrap();
        let b_fd = {
            use std::os::fd::AsRawFd;
            b.as_raw_fd()
        };

        let kq = unsafe { libc::kqueue() };
        assert!(kq >= 0, "kqueue()");

        // Register read interest on b.
        let ch = kev(b_fd as usize, libc::EVFILT_READ, libc::EV_ADD, 0, 0xB);
        let r = unsafe { libc::kevent(kq, &ch, 1, std::ptr::null_mut(), 0, std::ptr::null()) };
        assert_eq!(r, 0, "register");

        // Nothing sent yet: a zero-timeout poll reports no events.
        let mut out = [kev(0, 0, 0, 0, 0); 4];
        let ts0 = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let n = unsafe { libc::kevent(kq, std::ptr::null(), 0, out.as_mut_ptr(), 4, &ts0) };
        assert_eq!(n, 0, "no events before send");

        // Send to b, then poll (blocking) — b becomes readable, udata echoed back.
        a.send_to(b"x", b.local_addr().unwrap()).unwrap();
        let n = unsafe {
            libc::kevent(
                kq,
                std::ptr::null(),
                0,
                out.as_mut_ptr(),
                4,
                std::ptr::null(),
            )
        };
        assert_eq!(n, 1, "one ready event");
        assert_eq!({ out[0].filter }, libc::EVFILT_READ);
        assert_eq!({ out[0].udata } as u64, 0xB);
    });
}

#[test]
fn user_event_triggers_like_a_waker() {
    Sim::new().run(|| {
        let kq = unsafe { libc::kqueue() };
        assert!(kq >= 0);
        // Register a user event (EV_CLEAR = one-shot, as mio's waker uses).
        let ch = kev(7, libc::EVFILT_USER, libc::EV_ADD | libc::EV_CLEAR, 0, 0x77);
        assert_eq!(
            unsafe { libc::kevent(kq, &ch, 1, std::ptr::null_mut(), 0, std::ptr::null()) },
            0
        );

        // Not triggered yet.
        let mut out = [kev(0, 0, 0, 0, 0); 2];
        let ts0 = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        assert_eq!(
            unsafe { libc::kevent(kq, std::ptr::null(), 0, out.as_mut_ptr(), 2, &ts0) },
            0
        );

        // Trigger it from another thread, then a blocking poll returns it once.
        let t = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(10));
            let trig = kev(7, libc::EVFILT_USER, 0, libc::NOTE_TRIGGER, 0x77);
            unsafe { libc::kevent(kq, &trig, 1, std::ptr::null_mut(), 0, std::ptr::null()) };
        });
        let n = unsafe {
            libc::kevent(
                kq,
                std::ptr::null(),
                0,
                out.as_mut_ptr(),
                2,
                std::ptr::null(),
            )
        };
        assert_eq!(n, 1, "user event delivered");
        assert_eq!({ out[0].filter }, libc::EVFILT_USER);
        t.join().unwrap();
    });
}

/// What each zero-timeout `kevent` reports, as sorted `udata`s, through a scripted sequence:
/// three UDP sockets registered `EVFILT_READ` level-triggered (1), `EV_CLEAR` (2) and
/// `EV_ONESHOT` (3), plus user events with `EV_CLEAR` (4) and without (5).
fn trigger_modes_sequence() -> Vec<Vec<u64>> {
    use std::os::fd::AsRawFd;
    let kq = unsafe { libc::kqueue() };
    let socks: Vec<UdpSocket> = (0..3)
        .map(|_| UdpSocket::bind("127.0.0.1:0").unwrap())
        .collect();
    let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
    let send_all = || {
        for s in &socks {
            tx.send_to(b"x", s.local_addr().unwrap()).unwrap();
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let apply = |changes: &[libc::kevent]| {
        let n = unsafe {
            libc::kevent(
                kq,
                changes.as_ptr(),
                changes.len() as i32,
                std::ptr::null_mut(),
                0,
                std::ptr::null(),
            )
        };
        assert_eq!(n, 0, "kevent changes: {}", std::io::Error::last_os_error());
    };
    let read = |i: usize, flags: u16| {
        kev(
            socks[i].as_raw_fd() as usize,
            libc::EVFILT_READ,
            libc::EV_ADD | flags,
            0,
            i as u64 + 1,
        )
    };
    apply(&[
        read(0, 0),
        read(1, libc::EV_CLEAR),
        read(2, libc::EV_ONESHOT),
        kev(4, libc::EVFILT_USER, libc::EV_ADD | libc::EV_CLEAR, 0, 4),
        kev(5, libc::EVFILT_USER, libc::EV_ADD, 0, 5),
    ]);
    let poll = || {
        let mut out = [kev(0, 0, 0, 0, 0); 8];
        let ts0 = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let n = unsafe { libc::kevent(kq, std::ptr::null(), 0, out.as_mut_ptr(), 8, &ts0) };
        assert!(n >= 0);
        let mut got: Vec<u64> = out[..n as usize].iter().map(|e| e.udata as u64).collect();
        got.sort_unstable();
        got
    };
    let mut seen = vec![poll()];
    send_all();
    seen.push(poll());
    seen.push(poll());
    send_all();
    seen.push(poll());
    seen.push(poll());
    apply(&[
        kev(4, libc::EVFILT_USER, 0, libc::NOTE_TRIGGER, 4),
        kev(5, libc::EVFILT_USER, 0, libc::NOTE_TRIGGER, 5),
    ]);
    seen.push(poll());
    seen.push(poll());
    apply(&[read(1, libc::EV_CLEAR)]);
    seen.push(poll());
    seen.push(poll());
    seen
}

fn trigger_modes_expected() -> Vec<Vec<u64>> {
    vec![
        vec![],
        vec![1, 2, 3],
        vec![1],
        vec![1, 2],
        vec![1],
        vec![1, 4, 5],
        vec![1, 5],
        vec![1, 2, 5],
        vec![1, 5],
    ]
}

#[test]
fn clear_and_oneshot_trigger_modes() {
    assert_eq!(
        Sim::new().run(trigger_modes_sequence),
        trigger_modes_expected()
    );
}

#[test]
fn clear_and_oneshot_trigger_modes_os_truth() {
    assert_eq!(trigger_modes_sequence(), trigger_modes_expected());
}
