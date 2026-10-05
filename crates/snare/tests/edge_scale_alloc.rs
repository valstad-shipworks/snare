//! Perf budget: heap allocations per hooked call, counted by a global allocator in this test
//! binary, so the performance pass can see and tighten what each call allocates. Only the calling
//! thread's allocations are counted (a thread-local counter), so the sim's helper threads and
//! other tests in the binary do not disturb the count; each figure is the mean over 2 000 calls
//! after 200 to warm up, rounded up. The spawn/join budget measures allocations above a native
//! spawn/join in the same binary: libtest output capture installs allocating thread-spawn hooks.
//!
//! Each budget is today's measured value plus slack — a quarter more, plus one — taken on macOS
//! and Linux alike; the measured values are in the table at [`BUDGETS`]. A
//! failure here means a change made a call allocate more; when the pass makes one allocate less,
//! lower its budget to the new value plus the same slack.

#![cfg(unix)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use snare::Sim;

struct Counting;

thread_local! {
    static ALLOCATIONS: Cell<u64> = const { Cell::new(0) };
}

fn count() {
    let _ = ALLOCATIONS.try_with(|c| c.set(c.get() + 1));
}

// SAFETY: every call is forwarded to the system allocator unchanged; counting touches only a
// const-initialised thread-local with no destructor, which never allocates.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        count();
        // SAFETY: forwarded as given.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        count();
        // SAFETY: forwarded as given.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        count();
        // SAFETY: forwarded as given.
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: forwarded as given.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

fn allocations() -> u64 {
    ALLOCATIONS.with(Cell::get)
}

const WARMUP: u64 = 200;
const CALLS: u64 = 2_000;

/// Allocations of `CALLS` invocations on this thread after warming up.
fn total_allocations(mut call: impl FnMut()) -> u64 {
    for _ in 0..WARMUP {
        call();
    }
    let before = allocations();
    for _ in 0..CALLS {
        call();
    }
    allocations() - before
}

fn per_call(call: impl FnMut()) -> u64 {
    total_allocations(call).div_ceil(CALLS)
}

/// One budget: the call, today's measured allocations per call, and the budget.
struct Budget {
    call: &'static str,
    measured: u64,
    budget: u64,
}

const fn budget(call: &'static str, measured: u64) -> Budget {
    Budget {
        call,
        measured,
        budget: measured + measured / 4 + 1,
    }
}

/// Warmed caller-thread allocation counts on macOS 26 and Linux in Docker (arm64).
const BUDGETS: &[Budget] = &[
    budget("clock read outside a sim", 0),
    budget("clock read", 0),
    budget("sched_yield", 0),
    budget("empty nonblocking recv", 0),
    budget("poll(0)", 3),
    #[cfg(target_os = "macos")]
    budget("udp send+recv", 1),
    #[cfg(not(target_os = "macos"))]
    budget("udp send+recv", 13),
    budget("tcp write+read 1 KiB", 0),
    budget("uncontended mutex", 0),
    budget("1 ms sleep (one time skip)", 0),
    budget("thread spawn+join overhead", 2),
];

thread_local! {
    static RESULTS: std::cell::RefCell<Vec<(&'static str, u64)>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

fn check(call: &'static str, got: u64) {
    RESULTS.with(|r| r.borrow_mut().push((call, got)));
}

#[test]
fn perf_budget_allocations_per_hooked_call() {
    Sim::new().run(|| {});
    let native_spawn = total_allocations(|| std::thread::spawn(|| ()).join().unwrap());
    check(
        "clock read outside a sim",
        per_call(|| {
            std::hint::black_box(Instant::now());
        }),
    );

    Sim::new().run(|| {
        let reads = per_call(|| {
            for _ in 0..50 {
                std::hint::black_box(Instant::now());
            }
            std::thread::yield_now();
        });
        check("clock read", reads.div_ceil(50));
        check("sched_yield", per_call(std::thread::yield_now));

        let a = UdpSocket::bind("127.0.0.1:9000").unwrap();
        let b = UdpSocket::bind("127.0.0.1:9001").unwrap();
        a.set_nonblocking(true).unwrap();
        check(
            "empty nonblocking recv",
            per_call(|| drop(a.recv(&mut [0u8; 8]))),
        );
        check("poll(0)", per_call(|| poll_zero(&a)));
        check(
            "udp send+recv",
            per_call(|| {
                b.send_to(b"ping", "127.0.0.1:9000").unwrap();
                a.recv(&mut [0u8; 8]).unwrap();
            }),
        );

        let listener = TcpListener::bind("127.0.0.1:9002").unwrap();
        let mut client = TcpStream::connect("127.0.0.1:9002").unwrap();
        let (mut server, _) = listener.accept().unwrap();
        let chunk = [7u8; 1024];
        let mut buf = [0u8; 1024];
        check(
            "tcp write+read 1 KiB",
            per_call(|| {
                client.write_all(&chunk).unwrap();
                server.read_exact(&mut buf).unwrap();
            }),
        );

        let m = Mutex::new(0u64);
        check("uncontended mutex", per_call(|| *m.lock().unwrap() += 1));
        check(
            "1 ms sleep (one time skip)",
            per_call(|| std::thread::sleep(Duration::from_millis(1))),
        );
        check(
            "thread spawn+join overhead",
            total_allocations(|| std::thread::spawn(|| ()).join().unwrap())
                .saturating_sub(native_spawn)
                .div_ceil(CALLS),
        );
    });

    let results = RESULTS.with(|r| r.take());
    assert_eq!(results.len(), BUDGETS.len());
    let mut over = Vec::new();
    for (call, got) in results {
        let b = BUDGETS.iter().find(|b| b.call == call).unwrap();
        eprintln!(
            "{call}: {got} allocations per call (measured {}, budget {})",
            b.measured, b.budget
        );
        if got > b.budget {
            over.push(format!("{call}: {got} > {}", b.budget));
        }
    }
    assert!(over.is_empty(), "over budget: {over:?}");
}

#[cfg(target_os = "macos")]
#[test]
fn thirty_two_active_udp_sockets_transfer_inline_payloads_without_allocating() {
    for deterministic in [false, true] {
        for connected in [false, true] {
            let mut builder = Sim::builder();
            if deterministic {
                builder = builder.deterministic();
            }
            builder.build().run(|| {
                let sockets: Vec<_> = (0..32)
                    .map(|_| UdpSocket::bind("127.0.0.1:0").unwrap())
                    .collect();
                let addresses: Vec<_> = sockets
                    .iter()
                    .map(|socket| socket.local_addr().unwrap())
                    .collect();
                if connected {
                    for (index, socket) in sockets.iter().enumerate() {
                        socket.connect(addresses[index ^ 1]).unwrap();
                    }
                }
                let payload = [7u8; 128];
                let mut received = [0u8; 128];
                let total = total_allocations(|| {
                    for (index, socket) in sockets.iter().enumerate() {
                        let sent = if connected {
                            socket.send(&payload)
                        } else {
                            socket.send_to(&payload, addresses[index ^ 1])
                        }
                        .unwrap();
                        assert_eq!(sent, payload.len());
                    }
                    for socket in &sockets {
                        assert_eq!(socket.recv(&mut received).unwrap(), payload.len());
                        assert_eq!(received, payload);
                    }
                });
                assert_eq!(
                    total, 0,
                    "deterministic={deterministic}, connected={connected}"
                );
            });
        }
    }
}

fn poll_zero(sock: &UdpSocket) {
    use std::os::fd::AsRawFd;
    let mut fds = [libc::pollfd {
        fd: sock.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    }];
    // SAFETY: `fds` is a live array of one pollfd.
    unsafe { libc::poll(fds.as_mut_ptr(), 1, 0) };
}
