use std::sync::atomic::Ordering;

use super::participant::AUDITING;
use super::slot::try_with_slot;

/// Record a snare-visible effect (`op`) by the calling thread for the audit
/// log: a blocked participant, or an unknown thread holding no lease, is a
/// quiescence violation.
pub(crate) fn note_effect(op: &'static str) {
    if super::classified().is_some() {
        super::participant::class_effect(op);
        return;
    }
    if AUDITING.load(Ordering::Acquire) == 0 || super::is_driver_thread() {
        return;
    }
    try_with_slot(|slot| {
        let reg = slot.reg();
        if reg.is_auditing() {
            let mut g = reg.lock();
            let _ = reg.account_caller(&mut g, op, false);
        }
    });
}

/// Whether `SNARE_SCHED_AUDIT` is set to anything but `0` or empty.
pub(crate) fn audit_env() -> bool {
    std::env::var("SNARE_SCHED_AUDIT").is_ok_and(|v| !v.is_empty() && v != "0")
}

/// Whether operations that would escape the sim are refused: audit mode is
/// on through [`audit_env`] or an attached driver.
pub(crate) fn strict() -> bool {
    AUDITING.load(Ordering::Acquire) > 0 || audit_env()
}

/// Record a fatal violation `op` by the calling thread in the audit log of
/// its slot's driver, if one audits.
pub(crate) fn fatal_violation(op: &'static str) {
    try_with_slot(|slot| {
        let reg = slot.reg();
        if reg.is_auditing() {
            reg.fatal_violation(op);
        }
    });
}
