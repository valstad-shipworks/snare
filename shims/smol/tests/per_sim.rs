//! `smol::spawn` inside snare sims: each sim has its own global executor and "smol-N" threads,
//! so concurrent sims never poll each other's tasks, and the threads exit with their sim.

#![cfg(snare)]

use std::sync::mpsc;
use std::time::{Duration, Instant};

use snare::Sim;

fn sim(deterministic: bool) -> Sim {
    let builder = Sim::builder().stuck_after(Duration::from_secs(10));
    if deterministic {
        builder.deterministic().build()
    } else {
        builder.build()
    }
}

fn exercise(deterministic: bool) {
    let (elapsed, me, task_sim) = sim(deterministic).run(|| {
        let start = Instant::now();
        let task = smol::spawn(async {
            smol::Timer::after(Duration::from_millis(50)).await;
            std::thread::sleep(Duration::from_millis(10));
            snare::sched::current_sim()
        });
        let task_sim = smol::block_on(task);
        (start.elapsed(), snare::sched::current_sim(), task_sim)
    });
    assert_eq!(task_sim, me, "the task ran in another sim");
    assert!(
        (Duration::from_millis(60)..Duration::from_millis(70)).contains(&elapsed),
        "a 50 ms timer and a 10 ms sleep took {:?} of sim time",
        elapsed
    );
}

#[test]
fn sequential_sims() {
    for deterministic in [false, true, false, true] {
        exercise(deterministic);
    }
}

#[test]
fn concurrent_sims() {
    let workers: Vec<_> = (0..4)
        .map(|i| std::thread::spawn(move || (0..3).for_each(|_| exercise(i % 2 == 0))))
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
}

#[test]
fn the_executor_thread_exits_with_its_sim() {
    let sim = sim(false);
    let thread = sim.run(|| {
        smol::block_on(smol::spawn(async {}));
        let census = snare::sched::thread_census().unwrap();
        census
            .threads
            .iter()
            .find(|t| {
                matches!(t.owner, snare_interpose::ThreadOwner::ThisSim(_))
                    && t.name.as_deref() == Some("smol-1")
            })
            .map(|t| t.os_id)
            .unwrap_or_else(|| panic!("no smol-1 thread in {:?}", census))
    });
    drop(sim);
    let gone = (0..100).any(|_| {
        let census = snare_interpose::census(None).unwrap();
        if census.threads.iter().all(|t| t.os_id != thread) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
        false
    });
    assert!(gone, "the smol-1 thread outlived its sim");
}

#[test]
fn unfinished_tasks_are_dropped_with_their_sim() {
    struct Dropped(mpsc::Sender<()>);
    impl Drop for Dropped {
        fn drop(&mut self) {
            let _ = self.0.send(());
        }
    }

    let (tx, rx) = mpsc::channel();
    let sim = sim(false);
    sim.run(|| {
        smol::spawn(async move {
            let _guard = Dropped(tx);
            std::future::pending::<()>().await;
        })
        .detach();
        smol::block_on(smol::Timer::after(Duration::from_millis(5)));
    });
    assert!(rx.try_recv().is_err());
    drop(sim);
    assert!(rx.recv_timeout(Duration::from_secs(5)).is_ok());
}

#[test]
fn outside_a_sim_the_executor_is_the_process_one() {
    assert_eq!(smol::block_on(smol::spawn(async { 3 })), 3);
    exercise(false);
    assert_eq!(smol::block_on(smol::spawn(async { 4 })), 4);
}
