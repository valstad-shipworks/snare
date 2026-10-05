#![cfg(windows)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use snare::Sim;
use snare::sched::ExecutiveConfig;
use windows_sys::Win32::System::Threading::{WaitOnAddress, WakeByAddressSingle};

#[test]
fn an_already_changed_address_does_not_count_as_an_outside_wake() {
    for deterministic in [false, true] {
        let sim = if deterministic {
            Sim::builder().deterministic().build()
        } else {
            Sim::new()
        };
        let exec = sim.executive(ExecutiveConfig::default()).unwrap();
        let word = AtomicU32::new(2);
        let expected = 1_u32;
        sim.run(|| {
            assert_ne!(
                unsafe {
                    WaitOnAddress(
                        word.as_ptr().cast(),
                        (&expected as *const u32).cast(),
                        std::mem::size_of::<u32>(),
                        u32::MAX,
                    )
                },
                0
            );
        });
        assert_eq!(exec.outside_wakes(), 0, "deterministic={deterministic}");
    }
}

fn take_turn(word: &AtomicU32, turn: u32) {
    let other = 1 - turn;
    while word.load(Ordering::Acquire) != turn {
        assert_ne!(
            unsafe {
                WaitOnAddress(
                    word.as_ptr().cast(),
                    (&other as *const u32).cast(),
                    std::mem::size_of::<u32>(),
                    u32::MAX,
                )
            },
            0
        );
    }
    word.store(other, Ordering::Release);
    unsafe { WakeByAddressSingle(word.as_ptr().cast()) };
}

#[test]
fn the_sims_address_wakes_remain_owned_across_wait_registration() {
    for deterministic in [false, true] {
        let sim = if deterministic {
            Sim::builder().deterministic().build()
        } else {
            Sim::new()
        };
        let exec = sim.executive(ExecutiveConfig::default()).unwrap();
        let word = Arc::new(AtomicU32::new(0));
        sim.run(|| {
            let worker = {
                let word = word.clone();
                std::thread::spawn(move || {
                    for _ in 0..2000 {
                        take_turn(&word, 1);
                    }
                })
            };
            for _ in 0..2000 {
                take_turn(&word, 0);
            }
            worker.join().unwrap();
        });
        assert_eq!(exec.outside_wakes(), 0, "deterministic={deterministic}");
    }
}
