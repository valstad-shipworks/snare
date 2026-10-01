use std::net::UdpSocket;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use snare_interpose::{ClockKind, Domain, Flow, Layer, SleepRequest, Unmodelled};

/// Models time and sleeps, and remembers what it was told went unmodelled.
#[derive(Default)]
struct Clock {
    seen: Mutex<Vec<Unmodelled>>,
}

impl Layer for Clock {
    fn now(&self, _clock: ClockKind) -> Flow<Duration> {
        Flow::Done(Duration::from_secs(1))
    }

    fn sleep(&self, _request: SleepRequest) -> Flow<()> {
        Flow::Done(())
    }

    fn unmodelled(&self, call: Unmodelled) {
        self.seen.lock().unwrap().push(call);
    }
}

fn domain() -> (Arc<Clock>, Domain) {
    let clock = Arc::new(Clock::default());
    let domain = Domain::new([clock.clone() as Arc<dyn Layer>]);
    (clock, domain)
}

fn functions(domain: &Domain) -> Vec<&'static str> {
    domain
        .unmodelled()
        .iter()
        .map(|(call, _)| call.function)
        .collect()
}

const SOCKET: &str = if cfg!(windows) {
    "WSASocketW"
} else {
    "socket"
};

#[test]
fn modelled_work_leaves_no_unmodelled_calls() {
    let (_clock, domain) = domain();
    domain.run(|| {
        let start = std::time::Instant::now();
        std::thread::sleep(Duration::from_secs(10));
        let _ = start.elapsed();
    });
    assert_eq!(domain.unmodelled(), []);
}

#[test]
fn sockets_on_managed_threads_are_reported() {
    let (clock, domain) = domain();
    domain.run(|| {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.send_to(b"x", socket.local_addr().unwrap()).unwrap();
    });
    let functions = functions(&domain);
    for expected in [SOCKET, "bind", "sendto"] {
        assert!(
            functions.contains(&expected),
            "{expected} missing from {functions:?}"
        );
    }
    let seen = clock.seen.lock().unwrap();
    assert!(seen.iter().any(|c| c.function == SOCKET));
}

#[test]
fn unmanaged_threads_are_not_reported() {
    let (_clock, domain) = domain();
    let _socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    assert!(!functions(&domain).contains(&SOCKET));
}

#[test]
fn children_of_managed_threads_are_reported() {
    let (_clock, domain) = domain();
    domain.run(|| {
        std::thread::spawn(|| UdpSocket::bind("127.0.0.1:0").unwrap())
            .join()
            .unwrap()
    });
    assert!(functions(&domain).contains(&SOCKET));
}

#[test]
fn clear_forgets_earlier_calls() {
    let (_clock, domain) = domain();
    domain.run(|| UdpSocket::bind("127.0.0.1:0").unwrap());
    domain.clear_unmodelled();
    assert_eq!(domain.unmodelled(), []);
}

#[cfg(target_os = "linux")]
#[test]
fn raw_syscalls_are_reported_with_their_number() {
    let (_clock, domain) = domain();
    // SAFETY: getpid takes no arguments and cannot fail.
    domain.run(|| unsafe { libc::syscall(libc::SYS_getpid) });
    let expected = Unmodelled {
        function: "syscall",
        detail: Some(libc::SYS_getpid),
    };
    assert!(
        domain
            .unmodelled()
            .iter()
            .any(|(call, _)| *call == expected)
    );
}

/// io_uring bypasses per-operation syscalls, but the ring is created with `io_uring_setup`, which
/// the io-uring crate issues through libc `syscall` (its `direct-syscall` feature aside). The
/// syscall hook records it, so the harness can refuse a run that reaches for io_uring rather than
/// let its ring traffic escape observation.
#[cfg(target_os = "linux")]
#[test]
fn io_uring_setup_is_observed() {
    let (_clock, domain) = domain();
    domain.run(|| {
        let mut params = [0u8; 120];
        // SAFETY: io_uring_setup(entries, params); an unsupported or disabled ring just returns an
        // error, and the call is recorded either way.
        unsafe { libc::syscall(libc::SYS_io_uring_setup, 8, params.as_mut_ptr()) };
    });
    let calls = domain.unmodelled();
    assert!(
        calls
            .iter()
            .any(|(c, _)| c.function == "syscall" && c.detail == Some(libc::SYS_io_uring_setup)),
        "io_uring_setup not observed: {calls:?}",
    );
}

#[test]
fn report_separates_modelled_observed_and_other_imports() {
    let report = snare_interpose::install();
    assert!(report.patched(SOCKET), "{report:#?}");
    for image in &report.images {
        for name in &image.other_imports {
            assert!(!image.modelled.contains(&name.as_str()));
            assert!(!image.observed.contains(&name.as_str()));
        }
    }
    assert!(report.images.iter().any(|i| !i.other_imports.is_empty()));
}
