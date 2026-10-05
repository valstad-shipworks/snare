//! What an executive reports about a sim beyond its quiescence: which leases hold it busy and of
//! what kind, and how often something outside the sim woke one of its participants.

use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use snare::Sim;
use snare::sched::{
    self, BlockerKind, Executive, ExecutiveConfig, Grant, LeaseInfo, LeaseKind, PState, Quiescence,
};

fn real_now() -> Instant {
    snare::real(Instant::now)
}

fn real_since(start: Instant) -> Duration {
    snare::real(|| start.elapsed())
}

fn sims() -> [(&'static str, Sim); 2] {
    [
        ("plain", Sim::new()),
        (
            "deterministic",
            Sim::builder().deterministic().seed(3).build(),
        ),
    ]
}

fn attach_frozen() -> Executive {
    sched::mark_driver_thread();
    let exec = sched::attach(ExecutiveConfig::default()).unwrap();
    exec.grant(Grant {
        anchor_v: Duration::ZERO,
        anchor_wall: real_now(),
        rate: 0.0,
        horizon: Duration::ZERO,
    });
    exec
}

/// Waits until the sim is quiescent with a participant blocked.
fn settle(exec: &Executive) -> Quiescence {
    let start = real_now();
    loop {
        let q = exec.quiescence();
        if q.quiescent && q.blocked > 0 {
            return q;
        }
        assert!(
            real_since(start) < Duration::from_secs(20),
            "the sim never went quiescent: {q:?}"
        );
        thread::yield_now();
    }
}

#[test]
fn setup_and_busy_leases_are_told_apart() {
    Sim::new().run(|| {
        let exec = attach_frozen();
        let me = sched::thread_name();
        let setup = sched::setup_scope("boot");
        assert_eq!(
            exec.held_leases(),
            vec![LeaseInfo {
                label: "boot",
                kind: LeaseKind::Setup,
                holder: me.clone(),
            }]
        );
        let q = exec.quiescence();
        assert!(!q.quiescent);
        assert_eq!(q.blocker, Some((BlockerKind::Setup, Arc::from("boot"))));

        let busy = sched::busy("crunch");
        assert_eq!(busy.kind(), Some(LeaseKind::Busy));
        assert_eq!(
            exec.quiescence().blocker,
            Some((BlockerKind::Lease, Arc::from("crunch"))),
            "a busy lease is named before a setup lease"
        );
        let kinds: Vec<(&str, LeaseKind)> = sched::held_leases()
            .iter()
            .map(|lease| (lease.label, lease.kind))
            .collect();
        assert_eq!(
            kinds,
            vec![("boot", LeaseKind::Setup), ("crunch", LeaseKind::Busy)]
        );
        let rows = exec.participants();
        let lease_rows: Vec<(&str, Option<LeaseKind>)> = rows
            .iter()
            .filter_map(|row| match row.state {
                PState::Busy(label) => Some((label, row.lease_kind)),
                _ => None,
            })
            .collect();
        assert_eq!(
            lease_rows,
            vec![
                ("boot", Some(LeaseKind::Setup)),
                ("crunch", Some(LeaseKind::Busy))
            ]
        );
        assert!(
            rows.iter()
                .filter(|row| !matches!(row.state, PState::Busy(_)))
                .all(|row| row.lease_kind.is_none())
        );

        drop(busy);
        assert_eq!(
            exec.quiescence().blocker,
            Some((BlockerKind::Setup, Arc::from("boot")))
        );
        drop(setup);
        assert!(exec.held_leases().is_empty());
        assert!(exec.quiescence().quiescent);
    });
}

#[test]
fn a_lease_taken_off_a_sim_is_inert() {
    assert!(!sched::in_sim());
    assert_eq!(sched::current_sim(), None);
    let lease = sched::busy("outside");
    assert!(!lease.is_held());
    assert_eq!(lease.kind(), None);
    let scope = sched::setup_scope("outside");
    assert!(sched::held_leases().is_empty());
    let shown = format!("{lease:?} {scope:?}");
    assert!(shown.contains("BusyLease"), "{shown}");
    assert!(shown.contains("SetupScope"), "{shown}");
    drop((lease, scope));

    let sim = Sim::new();
    let lease = sim.busy("from outside the run");
    assert!(lease.is_held());
    assert_eq!(lease.kind(), Some(LeaseKind::Busy));
    let shown = format!("{lease:?}");
    assert!(shown.contains("from outside the run"), "{shown}");
    assert_eq!(sim.held_leases()[0].holder, None);
    drop(lease);
    assert!(sim.held_leases().is_empty());
}

/// A participant waits on a condition variable; the flag is set and the condition signalled by
/// `notify`, then the participant is let run to its end. Returns the executive's outside wakes
/// before and after.
fn condvar_wake(sim: &Sim, notify: impl FnOnce(Arc<(Mutex<bool>, Condvar)>)) -> (u64, u64) {
    sim.run(|| {
        let exec = attach_frozen();
        let pair = Arc::new((Mutex::new(false), Condvar::new()));
        let waiter = {
            let pair = pair.clone();
            thread::Builder::new()
                .name("waiter".into())
                .spawn(move || {
                    let (flag, cond) = &*pair;
                    let mut set = flag.lock().unwrap();
                    while !*set {
                        set = cond.wait(set).unwrap();
                    }
                })
                .unwrap()
        };
        settle(&exec);
        let before = exec.outside_wakes();
        notify(pair);
        waiter.join().unwrap();
        (before, exec.outside_wakes())
    })
}

#[test]
fn a_wake_from_outside_the_sim_is_counted_without_an_audit() {
    for (kind, sim) in sims() {
        let (before, after) = condvar_wake(&sim, |pair| {
            snare::real(|| {
                thread::spawn(move || {
                    let (flag, cond) = &*pair;
                    *flag.lock().unwrap() = true;
                    cond.notify_all();
                })
                .join()
                .unwrap();
            });
        });
        assert_eq!(before, 0, "{kind}");
        assert_eq!(
            after, 1,
            "{kind}: the unmanaged thread's wake is an outside wake"
        );
    }
}

#[test]
fn a_wake_from_the_sims_own_threads_is_not_an_outside_wake() {
    for (kind, sim) in sims() {
        let (before, after) = condvar_wake(&sim, |pair| {
            let (flag, cond) = &*pair;
            *flag.lock().unwrap() = true;
            cond.notify_all();
        });
        assert_eq!((before, after), (0, 0), "{kind}: the driver's own wake");
    }
}
