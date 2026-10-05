//! Thread classes, leases and the epoch (`snare::sched`): which threads hold up quiescence and the
//! deterministic schedule, and what holds time still.

use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use snare::Sim;
use snare::sched::{self, ThreadClass};

fn real_now() -> Instant {
    snare::real(Instant::now)
}

fn real_since(start: Instant) -> Duration {
    snare::real(|| start.elapsed())
}

fn dsim(seed: u64) -> Sim {
    Sim::builder().deterministic().seed(seed).build()
}

#[test]
fn background_thread_does_not_block_quiescence() {
    Sim::new().run(|| {
        let stop = Arc::new(AtomicBool::new(false));
        let spins = Arc::new(AtomicU64::new(0));
        let (spinning, started) = mpsc::channel();
        let spinner = {
            let (stop, spins) = (stop.clone(), spins.clone());
            thread::spawn(move || {
                sched::mark_background("spinner");
                let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
                sock.set_nonblocking(true).unwrap();
                let mut buf = [0u8; 8];
                while !stop.load(Ordering::Acquire) {
                    assert!(sock.recv_from(&mut buf).is_err());
                    if spins.fetch_add(1, Ordering::Relaxed) == 0 {
                        spinning.send(()).unwrap();
                    }
                }
            })
        };
        started.recv().unwrap();
        let real = real_now();
        let start = Instant::now();
        thread::sleep(Duration::from_secs(10));
        assert!(start.elapsed() >= Duration::from_secs(10));
        assert!(
            real_since(real) < Duration::from_secs(5),
            "the sleep skipped although the spinner never blocked: {:?}",
            real_since(real)
        );
        stop.store(true, Ordering::Release);
        spinner.join().unwrap();
    });
}

#[test]
fn background_timers_do_not_steer_skips() {
    Sim::new().run(|| {
        let stop = Arc::new(AtomicBool::new(false));
        let ticks = Arc::new(AtomicU64::new(0));
        let ticker = {
            let (stop, ticks) = (stop.clone(), ticks.clone());
            let _class = sched::spawn_as(ThreadClass::Background, "ticker");
            thread::spawn(move || {
                while !stop.load(Ordering::Acquire) {
                    thread::sleep(Duration::from_millis(1));
                    ticks.fetch_add(1, Ordering::Relaxed);
                }
            })
        };
        let real = real_now();
        while ticks.load(Ordering::Relaxed) == 0 {
            assert!(
                real_since(real) < Duration::from_secs(60),
                "the ticker's sleeps complete as time passes"
            );
            thread::sleep(Duration::from_millis(1));
        }
        let start = Instant::now();
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut buf = [0u8; 8];
        assert!(
            sock.recv_from(&mut buf).is_err(),
            "a lone participant waiting on nothing gives up"
        );
        assert_eq!(
            start.elapsed(),
            Duration::ZERO,
            "time never skipped to the ticker's timers"
        );
        stop.store(true, Ordering::Release);
        ticker.join().unwrap();
    });
}

#[test]
fn driver_thread_reads_real_time() {
    Sim::new().run(|| {
        let frozen = sched::now();
        sched::mark_driver_thread();
        assert_eq!(sched::thread_class(), ThreadClass::Driver);
        assert!(!sched::is_participant());
        let start = Instant::now();
        thread::sleep(Duration::from_millis(30));
        assert!(start.elapsed() >= Duration::from_millis(30));
        assert!(start.elapsed() < Duration::from_secs(30));
        assert_eq!(sched::now(), frozen, "nothing moved the sim's clock");
    });
}

#[test]
fn a_lease_blocks_the_auto_time_skip() {
    Sim::new().run(|| {
        let lease = sched::busy("warmup");
        let held = sched::held_leases();
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].label, "warmup");
        assert_eq!(held[0].kind, sched::LeaseKind::Busy);
        assert_eq!(
            held[0].holder,
            sched::thread_name().or(Some(Arc::from("thread-0")))
        );
        let real = real_now();
        let sleeper = thread::spawn(move || {
            thread::sleep(Duration::from_secs(10));
            (sched::now(), real_since(real))
        });
        let releaser = snare::real(|| {
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(300));
                drop(lease);
            })
        });
        let (woke_at, woke_after) = sleeper.join().unwrap();
        snare::real(|| releaser.join().unwrap());
        assert!(woke_at >= Duration::from_secs(10));
        assert!(
            woke_after >= Duration::from_millis(250),
            "the sleeper woke {woke_after:?} in, before the lease was dropped"
        );
        assert!(sched::held_leases().is_empty());
    });
}

#[test]
fn setup_scope_holds_time_still_in_a_plain_discrete_sim() {
    Sim::new().run(|| {
        let done = Arc::new(AtomicBool::new(false));
        let sleeper = {
            let _setup = sched::setup_scope("boot");
            let sleeper = {
                let done = done.clone();
                thread::spawn(move || {
                    thread::sleep(Duration::from_secs(1));
                    done.store(true, Ordering::Release);
                })
            };
            let (tx, rx) = mpsc::channel();
            let notifier = snare::real(|| {
                thread::spawn(move || {
                    thread::sleep(Duration::from_millis(200));
                    tx.send(()).unwrap();
                })
            });
            rx.recv().unwrap();
            snare::real(|| notifier.join().unwrap());
            assert!(!done.load(Ordering::Acquire), "time skipped during setup");
            assert!(sched::now() < Duration::from_secs(1));
            sleeper
        };
        sleeper.join().unwrap();
        assert!(done.load(Ordering::Acquire));
        assert!(sched::now() >= Duration::from_secs(1));
    });
}

#[test]
fn spawn_as_background_children_start_background_and_later_children_are_participants() {
    Sim::new().run(|| {
        let probe = || (sched::thread_class(), sched::is_participant());
        let background = {
            let _class = sched::spawn_as(ThreadClass::Background, "pool");
            thread::spawn(move || {
                let grandchild = thread::spawn(probe).join().unwrap();
                (probe(), grandchild)
            })
        };
        let participant = thread::spawn(probe);
        let (me, grandchild) = background.join().unwrap();
        assert_eq!(me, (ThreadClass::Background, false));
        assert_eq!(grandchild, (ThreadClass::Participant, true));
        assert_eq!(
            participant.join().unwrap(),
            (ThreadClass::Participant, true)
        );
    });
}

#[test]
fn participate_restores_previous_class() {
    Sim::new().run(|| {
        let worker = thread::spawn(|| {
            sched::mark_background("worker");
            let name = sched::thread_name();
            assert_eq!(sched::thread_class(), ThreadClass::Background);
            assert!(!sched::is_participant());
            {
                let _turn = sched::participate("phase-1");
                assert!(sched::is_participant());
                assert_eq!(sched::thread_name().as_deref(), Some("phase-1"));
                thread::sleep(Duration::from_millis(5));
            }
            assert_eq!(sched::thread_name(), name);
            sched::thread_class()
        });
        assert_eq!(worker.join().unwrap(), ThreadClass::Background);
    });
    let _outside = sched::participate("nobody");
    assert!(!sched::is_participant());
}

#[test]
fn arm_fires_on_epoch_change_once() {
    let domain = snare_interpose::Domain::new([]);
    let fired = Arc::new(AtomicUsize::new(0));
    let callback = || {
        let fired = fired.clone();
        Arc::new(move || {
            fired.fetch_add(1, Ordering::SeqCst);
        }) as Arc<dyn Fn() + Send + Sync>
    };
    let seen = domain.epoch();
    domain.arm(seen, callback());
    assert_eq!(fired.load(Ordering::SeqCst), 0);
    let lease = domain.take_lease("x");
    assert_eq!(fired.load(Ordering::SeqCst), 1);
    domain.release_lease(lease);
    assert_eq!(fired.load(Ordering::SeqCst), 1, "fires once");
    domain.run(|| sched::hint_starving("rx", 0.5));
    assert_eq!(domain.take_hints(), vec![(Arc::from("rx"), 0.5)]);
    assert!(domain.take_hints().is_empty());
    domain.arm(seen, callback());
    assert_eq!(
        fired.load(Ordering::SeqCst),
        2,
        "an epoch already past fires at once"
    );

    domain.run(|| {
        domain.arm(domain.epoch(), callback());
        drop(snare_interpose::mark_waiting(true));
        drop(snare_interpose::mark_waiting(false));
    });
    assert_eq!(
        fired.load(Ordering::SeqCst),
        3,
        "a participant parking moves the epoch"
    );

    let other = thread::spawn({
        let domain = domain.clone();
        let callback = callback();
        move || {
            let seen = domain.epoch();
            domain.arm(seen, callback);
            seen
        }
    })
    .join()
    .unwrap();
    domain.run(|| {
        assert_eq!(domain.epoch(), other);
        snare_interpose::set_thread_class(ThreadClass::Background, Some("bg"));
    });
    assert_eq!(
        fired.load(Ordering::SeqCst),
        4,
        "a class change moves the epoch"
    );
}

#[test]
fn thread_names_recorded_via_std_builder_name() {
    Sim::new().run(|| {
        let named = thread::Builder::new()
            .name("sampler-7".into())
            .spawn(sched::thread_name)
            .unwrap();
        assert_eq!(named.join().unwrap().as_deref(), Some("sampler-7"));

        let leases = thread::Builder::new()
            .name("loader".into())
            .spawn(|| {
                let _lease = sched::busy("load");
                sched::held_leases()
            })
            .unwrap()
            .join()
            .unwrap();
        assert_eq!(leases.len(), 1);
        assert_eq!(leases[0].label, "load");
        assert_eq!(leases[0].holder.as_deref(), Some("loader"));
    });
}

fn name_self(name: &std::ffi::CStr) {
    #[cfg(target_os = "linux")]
    assert_eq!(
        unsafe { libc::pthread_setname_np(libc::pthread_self(), name.as_ptr()) },
        0
    );
    #[cfg(target_os = "macos")]
    assert_eq!(unsafe { libc::pthread_setname_np(name.as_ptr()) }, 0);
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::Threading::{GetCurrentThread, SetThreadDescription};
        let wide: Vec<u16> = name
            .to_str()
            .unwrap()
            .encode_utf16()
            .chain(Some(0))
            .collect();
        assert!(unsafe { SetThreadDescription(GetCurrentThread(), wide.as_ptr()) } >= 0);
    }
}

#[test]
fn a_thread_naming_itself_renames_its_row_through_the_hook() {
    Sim::new().run(|| {
        let names = thread::spawn(|| {
            let _turn = sched::participate("p");
            let before = sched::thread_name();
            name_self(c"viahook");
            (before, sched::thread_name())
        })
        .join()
        .unwrap();
        assert_eq!(
            names,
            (Some(Arc::from("p")), Some(Arc::from("viahook"))),
            "only the naming hook can replace a name the OS never held"
        );
    });
}

#[cfg(target_os = "linux")]
#[test]
fn a_linux_thread_named_by_another_renames_its_row_through_the_hook() {
    use std::os::unix::thread::JoinHandleExt;
    Sim::new().run(|| {
        let (ready, is_ready) = mpsc::channel();
        let (go, wait) = mpsc::channel::<()>();
        let child = thread::spawn(move || {
            let _turn = sched::participate("p");
            ready.send(()).unwrap();
            wait.recv().unwrap();
            sched::thread_name()
        });
        is_ready.recv().unwrap();
        let named = unsafe { libc::pthread_setname_np(child.as_pthread_t(), c"byparent".as_ptr()) };
        assert_eq!(named, 0);
        go.send(()).unwrap();
        assert_eq!(child.join().unwrap().as_deref(), Some("byparent"));
    });
}

#[cfg(target_os = "linux")]
#[test]
fn a_linux_name_too_long_fails_as_the_os_does() {
    let long = c"sixteen-chars-xx";
    let short = c"fifteen-chars-x";
    let set = |name: &std::ffi::CStr| unsafe {
        libc::pthread_setname_np(libc::pthread_self(), name.as_ptr())
    };
    let real = snare::real(|| {
        thread::spawn(move || (set(long), set(short)))
            .join()
            .unwrap()
    });
    Sim::new().run(|| {
        let simulated = thread::spawn(move || {
            let before = sched::thread_name();
            let too_long = set(long);
            let unchanged = sched::thread_name() == before;
            let fits = set(short);
            (too_long, unchanged, fits, sched::thread_name())
        })
        .join()
        .unwrap();
        assert_eq!(real, (libc::ERANGE, 0));
        assert_eq!(
            simulated,
            (libc::ERANGE, true, 0, Some(Arc::from("fifteen-chars-x")))
        );
    });
}

#[test]
fn a_background_spinner_runs_outside_the_baton_and_does_not_starve_participants() {
    let run = || {
        dsim(3).run(|| {
            let stop = Arc::new(AtomicBool::new(false));
            let spins = Arc::new(AtomicU64::new(0));
            let (spinning, started) = mpsc::channel();
            let spinner = {
                let (stop, spins) = (stop.clone(), spins.clone());
                let _class = sched::spawn_as(ThreadClass::Background, "spinner");
                thread::spawn(move || {
                    while !stop.load(Ordering::Acquire) {
                        if spins.fetch_add(1, Ordering::Relaxed) == 0 {
                            spinning.send(()).unwrap();
                        }
                        std::hint::spin_loop();
                    }
                })
            };
            started.recv().unwrap();
            let log = Arc::new(Mutex::new(Vec::new()));
            let workers: Vec<_> = (0..3u64)
                .map(|i| {
                    let log = log.clone();
                    thread::spawn(move || {
                        for j in 0..3 {
                            thread::sleep(Duration::from_millis(1 + i));
                            log.lock().unwrap().push((i, j, Instant::now()));
                        }
                    })
                })
                .collect();
            for worker in workers {
                worker.join().unwrap();
            }
            stop.store(true, Ordering::Release);
            spinner.join().unwrap();
            let start = log.lock().unwrap()[0].2;
            let log = log.lock().unwrap();
            log.iter()
                .map(|&(i, j, at)| (i, j, at.duration_since(start)))
                .collect::<Vec<_>>()
        })
    };
    let first = run();
    assert_eq!(first.len(), 9);
    assert_eq!(
        first,
        run(),
        "the participants replay with a spinner beside them"
    );
}

#[test]
fn lease_under_det_idles_then_kick_resumes() {
    let run = || {
        dsim(4).run(|| {
            let lease = sched::busy("warmup");
            let real = real_now();
            let sleepers: Vec<_> = (0..3u64)
                .map(|i| {
                    thread::spawn(move || {
                        thread::sleep(Duration::from_secs(3 - i));
                        (i, sched::now(), real_since(real))
                    })
                })
                .collect();
            let releaser = snare::real(|| {
                thread::spawn(move || {
                    thread::sleep(Duration::from_millis(150));
                    drop(lease);
                })
            });
            let woke: Vec<_> = sleepers.into_iter().map(|s| s.join().unwrap()).collect();
            snare::real(|| releaser.join().unwrap());
            for (_, _, after) in &woke {
                assert!(
                    *after >= Duration::from_millis(100),
                    "a sleeper woke {after:?} in, while the lease was held"
                );
            }
            woke.into_iter()
                .map(|(i, at, _)| (i, at))
                .collect::<Vec<_>>()
        })
    };
    let first = run();
    assert!(
        first
            .iter()
            .all(|&(i, at)| at >= Duration::from_secs(3 - i))
    );
    assert_eq!(first, run(), "released in the same order on every run");
}

#[test]
fn a_background_timed_wait_completes_as_a_participant_skip_passes_it() {
    Sim::new().run(|| {
        let (receiving, started) = mpsc::channel();
        let waiter = {
            let _class = sched::spawn_as(ThreadClass::Background, "poller");
            thread::spawn(move || {
                let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
                sock.set_read_timeout(Some(Duration::from_millis(100)))
                    .unwrap();
                receiving.send(()).unwrap();
                let mut buf = [0u8; 8];
                assert!(sock.recv_from(&mut buf).is_err());
                sched::now()
            })
        };
        started.recv().unwrap();
        let real = real_now();
        while !waiter.is_finished() {
            assert!(
                real_since(real) < Duration::from_secs(30),
                "the background receive timed out as the participant moved time past it"
            );
            thread::sleep(Duration::from_secs(1));
        }
        assert!(waiter.join().unwrap() >= Duration::from_millis(100));
    });
}

#[test]
fn a_driver_socket_timeout_runs_in_real_time() {
    Sim::new().run(|| {
        sched::mark_driver_thread();
        let lease = sched::busy("drive");
        let target = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = target.local_addr().unwrap();
        let participant = {
            let _class = sched::spawn_as(ThreadClass::Participant, "rx");
            thread::spawn(move || {
                let mut buf = [0u8; 8];
                target.recv_from(&mut buf).map(|(n, _)| n).ok()
            })
        };
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        let frozen = sched::now();
        let start = Instant::now();
        let mut buf = [0u8; 8];
        assert!(sock.recv_from(&mut buf).is_err());
        let waited = start.elapsed();
        assert!(waited >= Duration::from_millis(50), "{waited:?}");
        assert!(
            waited < Duration::from_secs(3),
            "the driver's receive timeout waited {waited:?} for virtual time"
        );
        assert_eq!(sched::now(), frozen);
        sock.send_to(b"go", addr).unwrap();
        drop(lease);
        assert_eq!(participant.join().unwrap(), Some(2));
    });
}

#[test]
fn arm_fires_when_a_participant_parks_in_a_sim_wait() {
    Sim::new().run(|| {
        let domain = snare_interpose::Domain::current().unwrap();
        sched::mark_background("observer");
        let lease = sched::busy("hold");
        let target = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = target.local_addr().unwrap();
        let returned = Arc::new(AtomicBool::new(false));
        let (fired, on_fire) = mpsc::channel();
        domain.arm(
            domain.epoch(),
            Arc::new({
                let returned = returned.clone();
                move || {
                    let _ = fired.send(returned.load(Ordering::SeqCst));
                }
            }),
        );
        let receiver = {
            let returned = returned.clone();
            let _class = sched::spawn_as(ThreadClass::Participant, "rx");
            thread::spawn(move || {
                let mut buf = [0u8; 8];
                let got = target.recv_from(&mut buf).map(|(n, _)| n).ok();
                returned.store(true, Ordering::SeqCst);
                got
            })
        };
        let returned_when_fired = snare::real(|| on_fire.recv_timeout(Duration::from_secs(3)))
            .expect("parking in the receive moved the epoch");
        assert!(!returned_when_fired, "fired while the receiver was parked");
        UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .send_to(b"wake", addr)
            .unwrap();
        drop(lease);
        assert_eq!(receiver.join().unwrap(), Some(4));
    });
}

#[test]
fn mark_background_in_a_joined_child_under_det_hands_the_schedule_on() {
    let run = || {
        dsim(5).run(|| {
            let quick = thread::spawn(|| {
                sched::mark_background("bg");
                7
            });
            assert_eq!(quick.join().unwrap(), 7);

            let slow = thread::spawn(|| {
                thread::sleep(Duration::from_millis(10));
                sched::mark_background("bg");
                sched::now()
            });
            thread::sleep(Duration::from_secs(1));
            let main_woke = sched::now();
            let bg_woke = slow.join().unwrap();
            assert!(bg_woke >= Duration::from_millis(10));
            main_woke
        })
    };
    let first = run();
    assert!(first >= Duration::from_secs(1));
    assert_eq!(first, run());
}

#[test]
fn participate_drop_under_det_while_the_parent_joins() {
    let run = || {
        dsim(6).run(|| {
            let worker = {
                let _class = sched::spawn_as(ThreadClass::Background, "worker");
                thread::spawn(|| {
                    let at = {
                        let _turn = sched::participate("p");
                        thread::sleep(Duration::from_millis(5));
                        sched::now()
                    };
                    (at, sched::thread_class())
                })
            };
            let (at, class) = worker.join().unwrap();
            assert_eq!(class, ThreadClass::Background);
            at
        })
    };
    let first = run();
    assert!(first >= Duration::from_millis(5));
    assert_eq!(first, run());
}

fn within<R: Send + 'static>(what: &str, f: impl FnOnce() -> R + Send + 'static) -> R {
    snare::real(|| {
        let (done, result) = mpsc::channel();
        thread::spawn(move || done.send(f()).unwrap());
        result
            .recv_timeout(Duration::from_secs(60))
            .unwrap_or_else(|_| panic!("{what} hung"))
    })
}

fn stop_and_join_a_background_sampler(sim: Sim) -> Duration {
    sim.run(|| {
        let stop = Arc::new(AtomicBool::new(false));
        let (sampling, started) = mpsc::channel();
        let sampler = {
            let stop = stop.clone();
            let _class = sched::spawn_as(ThreadClass::Background, "sampler");
            thread::spawn(move || {
                sampling.send(()).unwrap();
                while !stop.load(Ordering::Acquire) {
                    thread::sleep(Duration::from_millis(10));
                }
            })
        };
        started.recv().unwrap();
        thread::sleep(Duration::from_millis(100));
        stop.store(true, Ordering::Release);
        sampler.join().unwrap();
        sched::now()
    })
}

#[test]
fn stopping_and_joining_a_background_sampler_returns() {
    for round in 0..20 {
        let at = within("the join on the stopped sampler", || {
            stop_and_join_a_background_sampler(Sim::new())
        });
        assert!(at >= Duration::from_millis(100), "round {round}: {at:?}");
    }
}

#[test]
fn stopping_and_joining_a_background_sampler_returns_under_det() {
    for round in 0..10 {
        let at = within("the join on the stopped sampler", move || {
            stop_and_join_a_background_sampler(dsim(20 + round))
        });
        assert!(at >= Duration::from_millis(100), "round {round}: {at:?}");
    }
}

fn join_a_background_sleeper_after_a_give_up(sim: Sim) -> Duration {
    sim.run(|| {
        let sleeper = {
            let _class = sched::spawn_as(ThreadClass::Background, "sleeper");
            thread::spawn(|| {
                for _ in 0..3 {
                    thread::sleep(Duration::from_millis(1));
                }
                sched::now()
            })
        };
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut buf = [0u8; 8];
        assert!(sock.recv_from(&mut buf).is_err());
        thread::sleep(Duration::from_millis(5));
        sleeper.join().unwrap()
    })
}

#[test]
fn a_join_on_a_background_sleeper_returns_after_a_participant_gives_up() {
    for round in 0..10 {
        let done = within("the join on the sleeper", || {
            join_a_background_sleeper_after_a_give_up(Sim::new())
        });
        assert!(done >= Duration::from_millis(3), "round {round}: {done:?}");
        let done = within("the join on the sleeper under det", move || {
            join_a_background_sleeper_after_a_give_up(dsim(40 + round))
        });
        assert!(done >= Duration::from_millis(3), "round {round}: {done:?}");
    }
}

fn wait_for_a_background_sender(sim: Sim) -> Duration {
    sim.run(|| {
        let (tx, rx) = mpsc::channel();
        let sender = {
            let _class = sched::spawn_as(ThreadClass::Background, "sender");
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(250));
                tx.send(sched::now()).unwrap();
            })
        };
        let sent = rx.recv().unwrap();
        sender.join().unwrap();
        sent
    })
}

#[test]
fn a_participant_waiting_on_a_background_sender_is_released_as_its_sleep_passes() {
    for round in 0..10 {
        let sent = within("the receive from the background sender", || {
            wait_for_a_background_sender(Sim::new())
        });
        assert!(
            sent >= Duration::from_millis(250),
            "round {round}: {sent:?}"
        );
        let sent = within("the receive under det", move || {
            wait_for_a_background_sender(dsim(60 + round))
        });
        assert!(
            sent >= Duration::from_millis(250),
            "round {round}: {sent:?}"
        );
    }
}

#[cfg(windows)]
#[test]
fn a_background_timer_armed_after_native_quiescence_releases_the_participant() {
    within("the timer armed after native quiescence", || {
        Sim::new().run(|| {
            let (tx, rx) = mpsc::channel();
            let sender = {
                let _class = sched::spawn_as(ThreadClass::Background, "sender");
                thread::spawn(move || {
                    let domain = snare_interpose::Domain::current().unwrap();
                    let start = real_now();
                    while !domain.quiescent(false) {
                        assert!(real_since(start) < Duration::from_secs(5));
                        snare::real(|| thread::sleep(Duration::from_millis(1)));
                    }
                    thread::sleep(Duration::from_millis(250));
                    tx.send(sched::now()).unwrap();
                })
            };
            assert!(rx.recv().unwrap() >= Duration::from_millis(250));
            sender.join().unwrap();
        });
    });
}

#[test]
fn time_stays_put_once_a_busy_lease_taken_from_outside_returns() {
    let sim = Sim::new();
    let stop = AtomicBool::new(false);
    thread::scope(|scope| {
        scope.spawn(|| {
            sim.run(|| {
                while !stop.load(Ordering::Acquire) {
                    thread::sleep(Duration::from_micros(10));
                }
            })
        });
        while sim.time_value() == Duration::ZERO {
            thread::sleep(Duration::from_millis(1));
        }
        for round in 0..100 {
            let lease = sim.busy("outside");
            let at = sim.time_value();
            thread::sleep(Duration::from_millis(2));
            assert_eq!(
                sim.time_value(),
                at,
                "round {round}: time moved under the lease"
            );
            drop(lease);
            thread::sleep(Duration::from_micros(500));
        }
        stop.store(true, Ordering::Release);
    });
}
