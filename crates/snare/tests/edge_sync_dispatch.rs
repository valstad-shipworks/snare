//! Where a hooked call lands, pinned for the performance pass: a managed thread's call goes to its
//! sim; under `snare::real` (nested or not), on a thread spawned under it, on a thread outside every
//! sim, inside a layer's own callback and in a thread's TLS destructors it goes to the OS. `dlsym`
//! hands out the hook (outside passthrough, even off a sim) and the real address under `real`; a
//! pointer resolved to the real function stays real inside a sim, while one resolved to the hook
//! is simulated wherever a managed thread calls it. `fork` reaches the OS and is counted as an
//! unmodelled call.
//!
//! The probe is `CLOCK_REALTIME`: a sim's realtime clock starts at 2023-11-14T22:13:20Z and moves
//! only by virtual time, while the machine's is years past it.
#![cfg(unix)]

use std::cell::RefCell;
use std::ffi::CStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use snare::Sim;
use snare_interpose::{ClockKind, Domain, Flow, Layer};

/// The sim's realtime epoch, in Unix seconds.
const SIM_EPOCH: u64 = 1_700_000_000;

/// Whether `CLOCK_REALTIME` read through std reads a sim's clock.
fn reads_sim_clock() -> bool {
    sim_seconds(SystemTime::now().duration_since(UNIX_EPOCH).unwrap())
}

fn sim_seconds(since_epoch: Duration) -> bool {
    since_epoch.as_secs() < SIM_EPOCH + 30 * 24 * 3600
}

type ClockGettime = unsafe extern "C" fn(libc::clockid_t, *mut libc::timespec) -> libc::c_int;

/// Reads `CLOCK_REALTIME` through `f` and says whether it was a sim's clock.
fn reads_sim_clock_through(f: ClockGettime) -> bool {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `f` is clock_gettime or its hook; `ts` is a valid out-pointer.
    assert_eq!(unsafe { f(libc::CLOCK_REALTIME, &mut ts) }, 0);
    sim_seconds(Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32))
}

/// `dlsym(RTLD_DEFAULT, name)` as the calling thread sees it.
fn lookup(name: &CStr) -> usize {
    // SAFETY: RTLD_DEFAULT and a C string are valid arguments.
    unsafe { libc::dlsym(libc::RTLD_DEFAULT, name.as_ptr()) as usize }
}

fn as_clock_gettime(address: usize) -> ClockGettime {
    assert_ne!(address, 0);
    // SAFETY: the address came from dlsym("clock_gettime"), the real function or its hook.
    unsafe { std::mem::transmute::<usize, ClockGettime>(address) }
}

#[test]
fn a_managed_thread_reads_the_sim_and_real_reads_the_os() {
    let seen = Sim::new().run(|| {
        vec![
            reads_sim_clock(),
            snare::real(reads_sim_clock),
            reads_sim_clock(),
        ]
    });
    assert_eq!(seen, [true, false, true]);
    assert!(!reads_sim_clock(), "the thread left the sim");
}

#[test]
fn nested_real_scopes_restore_the_outer_mode_on_each_exit() {
    let seen = Sim::new().run(|| {
        let mut seen = vec![(snare_interpose::in_passthrough(), reads_sim_clock())];
        snare::real(|| {
            seen.push((snare_interpose::in_passthrough(), reads_sim_clock()));
            snare::real(|| {
                seen.push((snare_interpose::in_passthrough(), reads_sim_clock()));
            });
            seen.push((snare_interpose::in_passthrough(), reads_sim_clock()));
        });
        seen.push((snare_interpose::in_passthrough(), reads_sim_clock()));
        seen
    });
    assert_eq!(
        seen,
        [
            (false, true),
            (true, false),
            (true, false),
            (true, false),
            (false, true)
        ]
    );
}

#[test]
fn a_panic_inside_real_restores_simulation() {
    let seen = Sim::new().run(|| {
        let caught = std::panic::catch_unwind(|| snare::real(|| panic!("inside real")));
        assert!(caught.is_err());
        (snare_interpose::in_passthrough(), reads_sim_clock())
    });
    assert_eq!(seen, (false, true));
}

#[test]
fn real_keeps_the_thread_in_its_sim() {
    let sim = Sim::new();
    let id = sim.id();
    let seen = sim.run(|| {
        snare::real(|| {
            (
                snare::sched::in_sim(),
                snare::sched::current_sim() == Some(id),
                Domain::current().is_some(),
            )
        })
    });
    assert_eq!(seen, (true, true, true));
}

#[test]
fn a_thread_spawned_under_real_is_unmanaged_and_so_are_its_children() {
    let seen = Sim::new().run(|| {
        snare::real(|| {
            std::thread::spawn(|| {
                let child = std::thread::spawn(|| (snare::sched::in_sim(), reads_sim_clock()))
                    .join()
                    .unwrap();
                ((snare::sched::in_sim(), reads_sim_clock()), child)
            })
            .join()
            .unwrap()
        })
    });
    assert_eq!(seen, ((false, false), (false, false)));
}

#[test]
fn a_thread_outside_every_sim_reads_the_os_while_a_sim_runs() {
    let sim = Sim::new();
    let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
    let (seen_tx, seen_rx) = std::sync::mpsc::channel();
    let outsider = std::thread::spawn(move || {
        go_rx.recv().unwrap();
        seen_tx
            .send((snare::sched::in_sim(), reads_sim_clock()))
            .unwrap();
    });
    let inside = sim.run(|| {
        snare::real(|| go_tx.send(()).unwrap());
        let seen = snare::real(|| seen_rx.recv().unwrap());
        (seen, reads_sim_clock())
    });
    outsider.join().unwrap();
    assert_eq!(inside, ((false, false), true));
}

#[test]
fn dlsym_hands_out_the_hook_outside_passthrough_and_the_os_function_under_real() {
    let name = c"clock_gettime";
    let (managed, under_real) = Sim::new().run(|| (lookup(name), snare::real(|| lookup(name))));
    let unmanaged = std::thread::spawn(move || lookup(name)).join().unwrap();
    assert_ne!(managed, under_real, "the hook is not the OS function");
    assert_eq!(
        unmanaged, managed,
        "a thread outside every sim is not in passthrough, so it is handed the hook too"
    );
    let plain = c"strlen";
    let (managed, under_real) = Sim::new().run(|| (lookup(plain), snare::real(|| lookup(plain))));
    assert_eq!(managed, under_real, "an unhooked symbol resolves to itself");
}

#[test]
fn a_resolved_pointer_keeps_its_target_whoever_calls_it() {
    let name = c"clock_gettime";
    let sim = Sim::new();
    let (hook, os) = sim.run(|| (lookup(name), snare::real(|| lookup(name))));
    let (hook, os) = (as_clock_gettime(hook), as_clock_gettime(os));
    let in_sim = sim.run(|| {
        (
            reads_sim_clock_through(hook),
            reads_sim_clock_through(os),
            snare::real(|| reads_sim_clock_through(hook)),
        )
    });
    assert_eq!(
        in_sim,
        (true, false, false),
        "the hook simulates a managed caller; the cached OS function never does"
    );
    let outside = (reads_sim_clock_through(hook), reads_sim_clock_through(os));
    assert_eq!(outside, (false, false));
}

#[test]
fn an_import_address_taken_on_a_managed_thread_is_the_hook() {
    let sim = Sim::new();
    let (taken, looked_up, os) = sim.run(|| {
        (
            libc::clock_gettime as ClockGettime as usize,
            lookup(c"clock_gettime"),
            snare::real(|| lookup(c"clock_gettime")),
        )
    });
    assert_eq!(taken, looked_up);
    assert_ne!(taken, os);
    let seen = sim.run(|| reads_sim_clock_through(as_clock_gettime(taken)));
    assert!(seen);
}

/// A clock layer whose callbacks read the clock themselves and record what they saw.
struct Reentrant {
    seen: Mutex<Vec<(bool, bool)>>,
    depth: AtomicUsize,
}

impl Layer for Reentrant {
    fn now(&self, clock: ClockKind) -> Flow<Duration> {
        if clock != ClockKind::Realtime {
            return Flow::Pass;
        }
        let depth = self.depth.fetch_add(1, Ordering::SeqCst);
        let inner = reads_sim_clock();
        self.seen
            .lock()
            .unwrap()
            .push((snare_interpose::in_passthrough(), inner));
        self.depth.fetch_sub(1, Ordering::SeqCst);
        assert_eq!(depth, 0, "a layer's own clock read reentered it");
        Flow::Done(Duration::from_secs(SIM_EPOCH))
    }
}

#[test]
fn a_layer_calling_a_hooked_function_reaches_the_os_without_reentering() {
    let layer = Arc::new(Reentrant {
        seen: Mutex::new(Vec::new()),
        depth: AtomicUsize::new(0),
    });
    let domain = Domain::new([layer.clone() as Arc<dyn Layer>]);
    let outer = domain.run(|| {
        let first = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let second = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        (first, second, snare_interpose::in_passthrough())
    });
    assert_eq!(
        outer,
        (
            Duration::from_secs(SIM_EPOCH),
            Duration::from_secs(SIM_EPOCH),
            false
        )
    );
    assert_eq!(*layer.seen.lock().unwrap(), [(true, false), (true, false)]);
}

static TEARDOWN: Mutex<Vec<(&'static str, bool)>> = Mutex::new(Vec::new());

struct ReadsOnDrop(&'static str);

impl Drop for ReadsOnDrop {
    fn drop(&mut self) {
        let sim = reads_sim_clock();
        TEARDOWN.lock().unwrap().push((self.0, sim));
    }
}

thread_local! {
    static ON_EXIT: RefCell<Option<ReadsOnDrop>> = const { RefCell::new(None) };
}

#[test]
fn tls_destructors_of_a_managed_thread_reach_the_os() {
    let body = Sim::new().run(|| {
        std::thread::spawn(|| {
            ON_EXIT.with(|slot| *slot.borrow_mut() = Some(ReadsOnDrop("spawned")));
            reads_sim_clock()
        })
        .join()
        .unwrap()
    });
    assert!(body, "the thread body read the sim");
    let seen: Vec<_> = TEARDOWN
        .lock()
        .unwrap()
        .iter()
        .filter(|(who, _)| *who == "spawned")
        .copied()
        .collect();
    assert_eq!(
        seen,
        [("spawned", false)],
        "the destructor ran after the thread left its sim"
    );
}

#[test]
fn a_hook_after_the_run_returns_reaches_the_os() {
    let sim = Sim::new();
    sim.run(|| assert!(reads_sim_clock()));
    assert!(!reads_sim_clock());
    assert!(!snare::sched::in_sim());
    drop(sim);
    assert!(!reads_sim_clock());
}

#[test]
fn fork_reaches_the_os_and_is_counted_unmodelled() {
    let (status, counted, counted_under_real) = Sim::new().run(|| {
        let domain = Domain::current().unwrap();
        // SAFETY: the child only calls _exit, which is async-signal-safe.
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            // SAFETY: leaving the forked child at once.
            unsafe { libc::_exit(7) };
        }
        assert!(pid > 0, "fork failed: {}", std::io::Error::last_os_error());
        let mut status = 0;
        // SAFETY: `pid` is our child; `status` is a valid out-pointer.
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        let count = |domain: &Domain| {
            domain
                .unmodelled()
                .iter()
                .filter(|(call, _)| call.function == "fork")
                .map(|(_, n)| *n)
                .sum::<u64>()
        };
        let counted = count(&domain);
        snare::real(|| {
            // SAFETY: as above.
            let pid = unsafe { libc::fork() };
            if pid == 0 {
                // SAFETY: as above.
                unsafe { libc::_exit(0) };
            }
            let mut ignored = 0;
            // SAFETY: as above.
            unsafe { libc::waitpid(pid, &mut ignored, 0) };
        });
        (status, counted, count(&domain))
    });
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 7);
    assert_eq!(counted, 1);
    assert_eq!(counted_under_real, 1, "a fork under real is not counted");
}
