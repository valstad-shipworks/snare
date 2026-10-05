use std::sync::OnceLock;
use std::time::Duration;

use crate::SleepRequest;
use crate::detour::{self, Threads, Transaction, TypedDetour};
use crate::domain;

static SLEEP: OnceLock<TypedDetour<fn(Duration)>> = OnceLock::new();

pub(crate) fn install() {
    // SAFETY: Transparent tail branches preserve the complete Rust Duration calling convention.
    let target = unsafe { detour::resolve_tail_target(std::thread::sleep as fn(Duration)) }
        .unwrap_or_else(|error| panic!("cannot resolve std::thread::sleep body: {error}"));
    // SAFETY: Both functions have the same Rust ABI and consume the complete Duration argument.
    let hook = unsafe { TypedDetour::<fn(Duration)>::new(target, sleep as fn(Duration)) }
        .unwrap_or_else(|error| panic!("cannot prepare std::thread::sleep interposition: {error}"));
    hook.validate_suspended_install()
        .unwrap_or_else(|error| panic!("cannot safely patch std::thread::sleep: {error}"));
    assert!(
        SLEEP.set(hook).is_ok(),
        "std::thread::sleep is already installed"
    );
    let hook = SLEEP.get().expect("published sleep trampoline");
    let mut transaction = Transaction::new();
    transaction.enable(hook);
    // SAFETY: The trampoline is published before code changes and other threads are suspended.
    unsafe { transaction.commit(Threads::All) }
        .unwrap_or_else(|error| panic!("cannot enable std::thread::sleep interposition: {error}"));
}

#[inline(never)]
fn sleep(duration: Duration) {
    if duration.as_nanos() / 100 > i64::MAX as u128
        && domain::dispatch(|layer| layer.sleep(SleepRequest::For(duration))).is_some()
    {
        return;
    }
    SLEEP
        .get()
        .expect("published sleep trampoline")
        .original()
        .call(duration);
}
