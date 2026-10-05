//! The thread census and "am I in a sim": every OS thread of the process held against the sims'
//! thread registries, told apart as this sim's (by class), another sim's, snare's own, or no sim's.

use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use snare::Sim;
use snare::sched::{self, ExecutiveConfig, Grant, ThreadCensus, ThreadClass, ThreadOwner};

fn real_now() -> Instant {
    snare::real(Instant::now)
}

/// Whether a thread's name is `name`, as far as the OS keeps it: Linux keeps 15 bytes (man 3
/// pthread_setname_np).
fn is_named(name: Option<&str>, wanted: &str) -> bool {
    name.is_some_and(|name| wanted.starts_with(name) && name.len() >= wanted.len().min(15))
}

/// The census entry for the thread named `name`, waiting for it to show up as `owner`: a thread
/// just spawned registers with its sim from its own first line.
fn owner_of(take: impl Fn() -> ThreadCensus, name: &str, owner: ThreadOwner) -> ThreadCensus {
    let start = real_now();
    loop {
        let census = take();
        if census
            .threads
            .iter()
            .any(|t| is_named(t.name.as_deref(), name) && t.owner == owner)
        {
            return census;
        }
        assert!(
            snare::real(|| start.elapsed()) < Duration::from_secs(10),
            "{name} never showed as {owner:?}: {census:#?}"
        );
        snare::real(|| thread::sleep(Duration::from_millis(1)));
    }
}

#[test]
fn the_census_tells_this_sims_threads_from_other_sims_and_unmanaged_ones() {
    let (stop_stranger, stranger_stop) = mpsc::channel::<()>();
    let stranger = thread::Builder::new()
        .name("census-stranger".into())
        .spawn(move || {
            let _ = stranger_stop.recv();
        })
        .unwrap();

    let other = Sim::new();
    let other_id = other.id();
    let (stop_other, other_stop) = mpsc::channel::<()>();
    let (other_ready, other_started) = mpsc::channel::<()>();
    let other_run = thread::spawn(move || {
        other.run(|| {
            let neighbour = thread::Builder::new()
                .name("census-neighbor".into())
                .spawn(move || {
                    other_ready.send(()).unwrap();
                    let _ = other_stop.recv();
                })
                .unwrap();
            neighbour.join().unwrap();
        });
    });
    other_started.recv().unwrap();

    let sim = Sim::new();
    assert_ne!(sim.id(), other_id);
    sim.run(|| {
        assert!(sched::in_sim());
        let here = sched::current_sim().expect("in a sim");
        let (stop_worker, worker_stop) = mpsc::channel::<()>();
        let worker = thread::Builder::new()
            .name("census-worker".into())
            .spawn(move || {
                assert_eq!(sched::current_sim(), Some(here));
                let _ = worker_stop.recv();
            })
            .unwrap();
        let (stop_sampler, sampler_stop) = mpsc::channel::<()>();
        let sampler = thread::Builder::new()
            .name("census-sampler".into())
            .spawn(move || {
                sched::mark_background("sampler");
                let _ = sampler_stop.recv();
            })
            .unwrap();
        let census = owner_of(
            || sched::thread_census().expect("this OS lists its threads"),
            "census-worker",
            ThreadOwner::ThisSim(ThreadClass::Participant),
        );
        assert_eq!(census.sim, Some(here));
        let census = owner_of(
            || sched::thread_census().unwrap(),
            "census-sampler",
            ThreadOwner::ThisSim(ThreadClass::Background),
        );
        let named = |name: &str| {
            census
                .threads
                .iter()
                .find(|t| is_named(t.name.as_deref(), name))
                .unwrap_or_else(|| panic!("no {name}: {census:#?}"))
                .owner
        };
        assert_eq!(
            named("census-neighbor"),
            ThreadOwner::OtherSim(other_id, ThreadClass::Participant)
        );
        assert_eq!(named("census-stranger"), ThreadOwner::Unmanaged);
        assert!(
            census
                .unmanaged()
                .any(|t| is_named(t.name.as_deref(), "census-stranger"))
        );
        assert!(
            census
                .this_sim()
                .any(|t| is_named(t.name.as_deref(), "census-worker"))
        );
        assert!(
            census
                .other_sims()
                .any(|t| is_named(t.name.as_deref(), "census-neighbor"))
        );
        assert!(
            census
                .this_sim()
                .any(|t| t.owner == ThreadOwner::ThisSim(ThreadClass::Participant)),
            "the calling thread is this sim's"
        );
        let mut ids: Vec<u64> = census.threads.iter().map(|t| t.os_id).collect();
        ids.dedup();
        assert_eq!(ids.len(), census.threads.len(), "one entry per thread");

        stop_worker.send(()).unwrap();
        stop_sampler.send(()).unwrap();
        worker.join().unwrap();
        sampler.join().unwrap();
        let census = sched::thread_census().unwrap();
        assert!(
            !census
                .this_sim()
                .any(|t| is_named(t.name.as_deref(), "census-worker")),
            "a joined thread is no longer the sim's: {census:#?}"
        );
    });

    let outside = snare::sched::thread_census().unwrap();
    assert_eq!(outside.sim, None);
    assert!(
        outside
            .threads
            .iter()
            .any(|t| is_named(t.name.as_deref(), "census-neighbor")
                && t.owner == ThreadOwner::OtherSim(other_id, ThreadClass::Participant))
    );
    stop_other.send(()).unwrap();
    other_run.join().unwrap();
    stop_stranger.send(()).unwrap();
    stranger.join().unwrap();
}

#[test]
fn snares_own_service_threads_are_listed_as_snares() {
    let sim = Sim::new();
    sim.run(|| {
        sched::mark_driver_thread();
        let exec = sched::attach(ExecutiveConfig::default()).unwrap();
        exec.grant(Grant {
            anchor_v: Duration::ZERO,
            anchor_wall: real_now(),
            rate: 1.0,
            horizon: Duration::from_secs(3600),
        });
        let census = owner_of(
            || exec.thread_census().unwrap(),
            "snare-executive-flow",
            ThreadOwner::Snare,
        );
        assert_eq!(census.sim, Some(exec.sim_id()));
        assert!(
            census
                .this_sim()
                .any(|t| t.owner == ThreadOwner::ThisSim(ThreadClass::Driver)),
            "the executive's thread is this sim's driver: {census:#?}"
        );
    });
}

#[test]
fn a_sim_takes_a_census_from_outside_its_run() {
    let sim = Sim::new();
    let id = sim.id();
    let (stop, stopped) = mpsc::channel::<()>();
    let (ready, started) = mpsc::channel::<()>();
    thread::scope(|s| {
        let sim = &sim;
        let run = s.spawn(move || {
            sim.run(|| {
                assert_eq!(sched::current_sim(), Some(id));
                ready.send(()).unwrap();
                let _ = stopped.recv();
            });
        });
        started.recv().unwrap();
        let census = sim.thread_census().unwrap();
        assert_eq!(census.sim, Some(id));
        assert!(
            census
                .this_sim()
                .any(|t| t.owner == ThreadOwner::ThisSim(ThreadClass::Participant)),
            "{census:#?}"
        );
        assert!(!sched::in_sim(), "the test's own thread is in no sim");
        stop.send(()).unwrap();
        run.join().unwrap();
    });
}
