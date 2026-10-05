//! Managed threads, pinned for the performance pass: lineage ids follow the spawn tree exactly
//! (SplitMix64's finaliser over parent and birth order; a run's root is 0 on the sim's first entry
//! and a salted id on each later one) through spawn storms, scoped threads, grandchildren and
//! `Builder` names; each thread's seeded random stream follows from its lineage alone; joining a
//! thread that already exited returns its value; a detached thread outlives its run inside the
//! sim; and a panic in a managed thread poisons, unwinds and leaves the sim usable.
#![cfg(unix)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use snare::Sim;
use snare_interpose::{Domain, thread_lineage};

/// `domain.rs`'s `mix_lineage`.
fn mix(parent: u64, order: u64) -> u64 {
    let mut z = parent ^ order.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// `domain.rs`'s `ROOT_SALT`.
const ROOT_SALT: u64 = 0x524f_4f54_454e_5452;

struct SplitMix64(u64);

impl SplitMix64 {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}

/// The first `n` bytes a fresh thread of lineage `lineage` draws in a sim seeded `seed`.
fn expected_stream(seed: u64, lineage: u64, n: usize) -> Vec<u8> {
    let mut origin = SplitMix64(seed ^ lineage.rotate_left(32));
    let mut rng = SplitMix64(origin.next());
    let mut out = Vec::new();
    while out.len() < n {
        out.extend_from_slice(&rng.next().to_le_bytes());
    }
    out.truncate(n);
    out
}

/// 16 bytes of OS entropy as the calling thread sees it.
fn entropy() -> [u8; 16] {
    let mut buf = [0u8; 16];
    // SAFETY: `buf` is 16 writable bytes, under getentropy's 256-byte limit.
    assert_eq!(
        unsafe { libc::getentropy(buf.as_mut_ptr().cast(), buf.len()) },
        0
    );
    buf
}

fn sims() -> Vec<(&'static str, Sim)> {
    vec![
        ("plain", Sim::builder().seed(42).build()),
        (
            "deterministic",
            Sim::builder().seed(42).deterministic().build(),
        ),
    ]
}

#[test]
fn a_storm_of_a_thousand_threads_gets_exact_lineages_and_streams() {
    for (what, sim) in sims() {
        let seen = sim.run(|| {
            let root = thread_lineage();
            let handles: Vec<_> = (0..1000)
                .map(|_| std::thread::spawn(|| (thread_lineage(), entropy())))
                .collect();
            let children: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
            (root, children)
        });
        assert_eq!(seen.0, 0, "{what}: the first entry's root");
        for (i, (lineage, bytes)) in seen.1.iter().enumerate() {
            let expected = mix(0, i as u64 + 1);
            assert_eq!(*lineage, expected, "{what}: child {i}");
            assert_eq!(
                bytes.as_slice(),
                expected_stream(42, expected, 16),
                "{what}: child {i}'s stream"
            );
        }
        let distinct: std::collections::HashSet<_> = seen.1.iter().map(|(l, _)| *l).collect();
        assert_eq!(distinct.len(), 1000, "{what}");
    }
}

#[test]
fn grandchildren_and_scoped_threads_follow_the_spawn_tree() {
    let seen = Sim::new().run(|| {
        let first = std::thread::spawn(|| {
            let mine = thread_lineage();
            let grandchildren: Vec<_> = (0..3)
                .map(|_| std::thread::spawn(thread_lineage).join().unwrap())
                .collect();
            (mine, grandchildren)
        })
        .join()
        .unwrap();
        let scoped: Vec<u64> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..2).map(|_| scope.spawn(thread_lineage)).collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        let named = std::thread::Builder::new()
            .name("named-worker".into())
            .spawn(thread_lineage)
            .unwrap()
            .join()
            .unwrap();
        (first, scoped, named)
    });
    let child = mix(0, 1);
    assert_eq!(
        seen.0,
        (child, vec![mix(child, 1), mix(child, 2), mix(child, 3)])
    );
    assert_eq!(seen.1, [mix(0, 2), mix(0, 3)]);
    assert_eq!(seen.2, mix(0, 4));
}

#[test]
fn each_later_entry_gets_a_salted_root_and_its_children_restart_birth_order() {
    let sim = Sim::new();
    let runs: Vec<(u64, u64)> = (0..4)
        .map(|_| {
            sim.run(|| {
                (
                    thread_lineage(),
                    std::thread::spawn(thread_lineage).join().unwrap(),
                )
            })
        })
        .collect();
    let roots = [0, mix(ROOT_SALT, 1), mix(ROOT_SALT, 2), mix(ROOT_SALT, 3)];
    let expected: Vec<_> = roots.iter().map(|&r| (r, mix(r, 1))).collect();
    assert_eq!(runs, expected);
    assert_eq!(thread_lineage(), 0, "off a sim the lineage reads 0");
}

#[test]
fn a_thread_restarts_its_stream_on_each_entry() {
    let sim = Sim::builder().seed(9).build();
    let first = sim.run(entropy);
    let second = sim.run(entropy);
    assert_eq!(first.as_slice(), expected_stream(9, 0, 16));
    assert_eq!(second.as_slice(), expected_stream(9, mix(ROOT_SALT, 1), 16));
    let fresh = Sim::builder()
        .seed(9)
        .build()
        .run(|| (entropy(), entropy()));
    let both = expected_stream(9, 0, 32);
    assert_eq!(fresh.0.as_slice(), &both[..16]);
    assert_eq!(
        fresh.1.as_slice(),
        &both[16..],
        "a stream continues within an entry"
    );
}

#[test]
fn builder_names_are_the_threads_sim_names() {
    let names = Sim::new().run(|| {
        let named = std::thread::Builder::new()
            .name("io-7".into())
            .spawn(|| snare::sched::thread_name().map(|n| n.to_string()))
            .unwrap()
            .join()
            .unwrap();
        let unnamed = std::thread::spawn(|| snare::sched::thread_name().map(|n| n.to_string()))
            .join()
            .unwrap();
        let long = std::thread::Builder::new()
            .name("a-name-longer-than-fifteen-bytes".into())
            .spawn(|| snare::sched::thread_name().map(|n| n.to_string()))
            .unwrap()
            .join()
            .unwrap();
        (
            named,
            unnamed,
            long,
            snare::sched::thread_name().map(|n| n.to_string()),
        )
    });
    assert_eq!(names.0.as_deref(), Some("io-7"));
    let long = if cfg!(target_os = "linux") {
        "a-name-longer-t"
    } else {
        "a-name-longer-than-fifteen-bytes"
    };
    assert_eq!(names.2.as_deref(), Some(long));
    let current = std::thread::current();
    let root = current.name().map(|n| {
        if cfg!(target_os = "linux") {
            &n[..n.len().min(15)]
        } else {
            n
        }
    });
    assert_eq!(
        names.3.as_deref(),
        root,
        "the root carries the OS name it entered with, as the OS keeps it"
    );
    let unnamed = if cfg!(target_os = "linux") {
        root
    } else {
        None
    };
    assert_eq!(
        names.1.as_deref(),
        unnamed,
        "an unnamed thread reads the name the OS gave it: its creator's on Linux, none on macOS"
    );
    assert_eq!(snare::sched::thread_name(), None, "off a sim");
}

#[test]
fn joining_a_thread_that_already_exited_returns_its_value_at_once() {
    let sim = Sim::builder().deterministic().build();
    let (value, waited) = sim.run(|| {
        let (tx, rx) = mpsc::channel();
        let handle = std::thread::spawn(move || {
            tx.send(()).unwrap();
            17u32
        });
        rx.recv().unwrap();
        std::thread::sleep(Duration::from_millis(10));
        let before = Instant::now();
        let value = handle.join().unwrap();
        (value, before.elapsed())
    });
    assert_eq!(value, 17);
    assert!(
        waited < Duration::from_millis(1),
        "joined at once: {waited:?}"
    );
}

#[test]
fn a_detached_thread_stays_in_its_sim_after_the_run_and_returns_to_the_next() {
    let sim = Sim::new();
    let id = sim.id();
    let (ask_tx, ask_rx) = mpsc::channel::<()>();
    let (seen_tx, seen_rx) = mpsc::channel();
    sim.run(|| {
        std::thread::spawn(move || {
            while ask_rx.recv().is_ok() {
                let domain = Domain::current();
                seen_tx
                    .send((
                        snare::sched::current_sim() == Some(id),
                        domain.is_some_and(|d| d.is_dormant()),
                    ))
                    .unwrap();
            }
        });
    });
    ask_tx.send(()).unwrap();
    assert_eq!(seen_rx.recv().unwrap(), (true, true), "between runs");
    let during = sim.run(|| {
        snare::real(|| ask_tx.send(()).unwrap());
        snare::real(|| seen_rx.recv().unwrap())
    });
    assert_eq!(during, (true, false), "during the next run");
    drop(sim);
    ask_tx.send(()).unwrap();
    assert_eq!(seen_rx.recv().unwrap(), (true, true), "after the drop");
    drop(ask_tx);
}

#[test]
fn a_panicking_managed_thread_unwinds_poisons_and_releases_quiescence() {
    for (what, sim) in sims() {
        let (joined, poisoned, slept) = sim.run(|| {
            let lock = Arc::new(Mutex::new(0u32));
            let held = lock.clone();
            let handle = std::thread::spawn(move || {
                let _guard = held.lock().unwrap();
                panic!("managed panic");
            });
            let joined = handle
                .join()
                .unwrap_err()
                .downcast_ref::<&str>()
                .map(|s| s.to_string());
            let poisoned = lock.lock().is_err();
            let start = Instant::now();
            std::thread::sleep(Duration::from_secs(5));
            (joined, poisoned, start.elapsed())
        });
        assert_eq!(joined.as_deref(), Some("managed panic"), "{what}");
        assert!(poisoned, "{what}");
        assert!(slept >= Duration::from_secs(5), "{what}: {slept:?}");
    }
}

#[test]
fn a_panic_in_the_run_reaches_the_caller_and_the_sim_runs_again() {
    for (what, sim) in sims() {
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            sim.run(|| -> () { panic!("root panic") })
        }));
        let payload = caught.unwrap_err();
        assert_eq!(
            payload.downcast_ref::<&str>(),
            Some(&"root panic"),
            "{what}"
        );
        assert!(!snare::sched::in_sim(), "{what}: the panic left the sim");
        let again = sim.run(|| {
            let start = Instant::now();
            std::thread::spawn(|| std::thread::sleep(Duration::from_secs(1)))
                .join()
                .unwrap();
            (
                snare::sched::in_sim(),
                start.elapsed() >= Duration::from_secs(1),
            )
        });
        assert_eq!(again, (true, true), "{what}");
    }
}

#[test]
fn a_thread_spawned_by_a_panicking_parent_lives_on() {
    let sim = Sim::new();
    let done = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::channel();
    let flag = done.clone();
    let parent = sim.run(move || {
        std::thread::spawn(move || {
            let child = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(50));
                flag.store(true, Ordering::SeqCst);
                thread_lineage()
            });
            tx.send(child).unwrap();
            panic!("parent panics");
        })
        .join()
    });
    assert!(parent.is_err());
    let child = rx.recv().unwrap();
    assert_eq!(child.join().unwrap(), mix(mix(0, 1), 1));
    assert!(done.load(Ordering::SeqCst));
}
