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
        let r = unsafe {
            libc::kevent(kq, &ch, 1, std::ptr::null_mut(), 0, std::ptr::null())
        };
        assert_eq!(r, 0, "register");

        // Nothing sent yet: a zero-timeout poll reports no events.
        let mut out = [kev(0, 0, 0, 0, 0); 4];
        let ts0 = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        let n = unsafe { libc::kevent(kq, std::ptr::null(), 0, out.as_mut_ptr(), 4, &ts0) };
        assert_eq!(n, 0, "no events before send");

        // Send to b, then poll (blocking) — b becomes readable, udata echoed back.
        a.send_to(b"x", b.local_addr().unwrap()).unwrap();
        let n = unsafe { libc::kevent(kq, std::ptr::null(), 0, out.as_mut_ptr(), 4, std::ptr::null()) };
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
        let ts0 = libc::timespec { tv_sec: 0, tv_nsec: 0 };
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
        let n = unsafe { libc::kevent(kq, std::ptr::null(), 0, out.as_mut_ptr(), 2, std::ptr::null()) };
        assert_eq!(n, 1, "user event delivered");
        assert_eq!({ out[0].filter }, libc::EVFILT_USER);
        t.join().unwrap();
    });
}
