//! Where the clock stands when a timed wait gives up, and that a timed wait the clock crawls past
//! wakes there rather than at whatever the sim next skips to.

use std::net::UdpSocket;
use std::sync::mpsc;
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

use snare::Sim;

const TIMEOUT: Duration = Duration::from_millis(20);

fn sims() -> [(&'static str, Sim); 2] {
    [
        ("discrete", Sim::new()),
        (
            "deterministic",
            Sim::builder().deterministic().seed(1).build(),
        ),
    ]
}

/// Runs `wait`, which gives up after [`TIMEOUT`], in each kind of sim and checks the code under
/// test reads the clock strictly past the deadline afterwards, as after a real timer: a reading
/// equal to it would send a `now < deadline` loop round again with nothing left to wait.
fn lands_past_the_deadline(what: &str, wait: fn()) {
    for (kind, sim) in sims() {
        sim.run(move || {
            let start = Instant::now();
            wait();
            let waited = start.elapsed();
            assert!(
                waited > TIMEOUT,
                "{what} in a {kind} sim: read {waited:?} after a {TIMEOUT:?} timeout"
            );
        });
    }
}

#[test]
fn a_sleep_ends_past_its_deadline() {
    lands_past_the_deadline("sleep", || std::thread::sleep(TIMEOUT));
}

#[test]
fn a_timed_out_channel_receive_ends_past_its_deadline() {
    lands_past_the_deadline("recv_timeout", || {
        let (_tx, rx) = mpsc::channel::<()>();
        assert!(rx.recv_timeout(TIMEOUT).is_err());
    });
}

#[test]
fn a_timed_out_condvar_wait_ends_past_its_deadline() {
    lands_past_the_deadline("wait_timeout", || {
        let lock = Mutex::new(());
        let cv = Condvar::new();
        let (_guard, result) = cv
            .wait_timeout_while(lock.lock().unwrap(), TIMEOUT, |()| true)
            .unwrap();
        assert!(result.timed_out());
    });
}

#[test]
fn a_timed_out_socket_receive_ends_past_its_deadline() {
    lands_past_the_deadline("recv_from", || {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_read_timeout(Some(TIMEOUT)).unwrap();
        assert!(socket.recv_from(&mut [0; 8]).is_err());
    });
}

#[test]
fn a_timed_out_mio_poll_ends_past_its_deadline() {
    lands_past_the_deadline("mio poll", || {
        let mut socket = mio::net::UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let mut poll = mio::Poll::new().unwrap();
        poll.registry()
            .register(&mut socket, mio::Token(0), mio::Interest::READABLE)
            .unwrap();
        let mut events = mio::Events::with_capacity(4);
        poll.poll(&mut events, Some(TIMEOUT)).unwrap();
        assert!(events.is_empty());
    });
}

/// Two threads released by one time skip each make a non-blocking call, charged a microsecond,
/// that carries the clock past a third thread's sleep while the other is still waiting for its
/// turn; then both wait long. The sleeper wakes at its own deadline, not at the next one the sim
/// skips to.
#[cfg(windows)]
#[test]
fn a_sleep_the_clock_crawls_past_wakes_at_its_deadline() {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{
        CreateWaitableTimerExW, INFINITE, SetWaitableTimer, TIMER_ALL_ACCESS, WaitForSingleObject,
    };

    const RELEASE: Duration = Duration::from_millis(4);
    const LONG: Duration = Duration::from_millis(20);
    Sim::builder().deterministic().seed(1).build().run(|| {
        let crawlers: Vec<_> = (0..2)
            .map(|_| {
                let timer = unsafe {
                    CreateWaitableTimerExW(std::ptr::null(), std::ptr::null(), 0, TIMER_ALL_ACCESS)
                };
                assert!(!timer.is_null());
                let handle = timer as usize;
                let thread = std::thread::spawn(move || {
                    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
                    socket.set_nonblocking(true).unwrap();
                    assert_eq!(unsafe { WaitForSingleObject(handle as _, INFINITE) }, 0);
                    assert!(socket.recv_from(&mut [0; 8]).is_err());
                    std::thread::sleep(LONG);
                });
                (timer, thread)
            })
            .collect();
        std::thread::sleep(Duration::from_millis(1));

        let due = -i64::try_from(RELEASE.as_nanos() / 100).unwrap();
        for (timer, _) in &crawlers {
            assert_eq!(
                unsafe { SetWaitableTimer(*timer, &due, 0, None, std::ptr::null(), 0) },
                1
            );
        }
        let start = Instant::now();
        let sleep = RELEASE + Duration::from_nanos(500);
        std::thread::sleep(sleep);
        let late = start.elapsed().saturating_sub(sleep);
        assert!(
            late < Duration::from_micros(100),
            "the sleep woke {late:?} after its deadline"
        );
        for (timer, thread) in crawlers {
            thread.join().unwrap();
            assert_eq!(unsafe { CloseHandle(timer) }, 1);
        }
    });
}
