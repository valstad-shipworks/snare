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

/// Another word of `words` that shares `target`'s slot in snare-interpose's table of watched
/// addresses, which files an address under the top bits of this Fibonacci hash of its word index.
fn sharing_slot(words: &[AtomicU32], target: &AtomicU32) -> usize {
    let slot = |addr: usize| ((addr as u64) >> 2).wrapping_mul(0x9e37_79b9_7f4a_7c15) >> 48;
    let target = target.as_ptr() as usize;
    words
        .iter()
        .map(|word| word.as_ptr() as usize)
        .find(|&addr| addr != target && slot(addr) == slot(target))
        .expect("a word sharing the target's slot")
}

/// `RtlWakeAddressSingle` (ntdll), which `WakeByAddressSingle` forwards to. A wake made there
/// passes no hook, so the wait it ends returns `TRUE` with the comparand still in place and no
/// `WakeByAddress*` made on its address: to the hooks, a spurious return.
fn unhooked_wake() -> unsafe extern "system" fn(*const std::ffi::c_void) {
    use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
    let ntdll = unsafe { GetModuleHandleA(c"ntdll.dll".as_ptr().cast()) };
    let wake = unsafe { GetProcAddress(ntdll, c"RtlWakeAddressSingle".as_ptr().cast()) }
        .expect("RtlWakeAddressSingle");
    unsafe {
        std::mem::transmute::<
            unsafe extern "system" fn() -> isize,
            unsafe extern "system" fn(*const std::ffi::c_void),
        >(wake)
    }
}

#[test]
fn a_spurious_return_outlasts_a_wake_of_an_address_sharing_its_slot() {
    use windows_sys::Win32::Foundation::{ERROR_TIMEOUT, GetLastError};
    use windows_sys::Win32::System::Threading::WakeByAddressAll;

    let spurious = unhooked_wake();
    let words: Vec<AtomicU32> = (0..1 << 18).map(|_| AtomicU32::new(0)).collect();
    let target = &words[0];
    let other = sharing_slot(&words, target);
    let pause = std::time::Duration::from_millis(100);
    for timed in [true, false] {
        target.store(0, Ordering::Release);
        let sim = Sim::new();
        sim.pause_time();
        let time = sim.time();
        let (woke, error, value, waited) = std::thread::scope(|scope| {
            scope.spawn(|| {
                std::thread::sleep(pause);
                unsafe {
                    WakeByAddressAll(other as *const _);
                    spurious(target.as_ptr().cast());
                }
                std::thread::sleep(pause);
                if !timed {
                    target.store(1, Ordering::Release);
                    unsafe { WakeByAddressAll(target.as_ptr().cast()) };
                }
                time.resume();
            });
            sim.run(|| {
                let start = std::time::Instant::now();
                let expected = 0_u32;
                let woke = unsafe {
                    WaitOnAddress(
                        target.as_ptr().cast(),
                        (&expected as *const u32).cast(),
                        std::mem::size_of::<u32>(),
                        if timed { 1000 } else { u32::MAX },
                    )
                };
                let error = unsafe { GetLastError() };
                (woke, error, target.load(Ordering::Acquire), start.elapsed())
            })
        });
        if timed {
            assert_eq!((woke, error), (0, ERROR_TIMEOUT), "waited {waited:?}");
            assert!(waited >= std::time::Duration::from_secs(1), "{waited:?}");
        } else {
            assert_ne!(woke, 0);
            assert_eq!(value, 1, "returned before the wake, after {waited:?}");
        }
    }
}
