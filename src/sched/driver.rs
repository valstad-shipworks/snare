use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use super::participant::{self, Registry};
use super::slot::{SchedSlot, duration_ns, set_driver_time};
use super::timer::wall_ns_of;
use super::{
    AttachError, AuditReport, DRIVEN_ORIGIN, DRIVEN_WALL_EPOCH, DriverConfig, Grant, NotQuiescent,
    ParticipantInfo, Quiescence, TimerInfo,
};

/// Exclusive owner of a state slot's clock. Dropping it returns the clock to
/// scaled mode, frozen at its current value, and ends participant accounting.
pub struct Driver {
    slot: Arc<SchedSlot>,
    cfg: DriverConfig,
}

/// Take ownership of the calling thread's state-slot clock. The clock moves
/// forward to [`DRIVEN_ORIGIN`] (or, if already past it, the next whole
/// second) and is frozen there until the first [`Driver::grant`]; that
/// instant reads as [`DRIVEN_WALL_EPOCH`] through the virtual `SystemTime`.
///
/// Audit mode is on if `cfg.audit` is set or the `SNARE_SCHED_AUDIT`
/// environment variable is set to anything but `0` or the empty string.
pub fn attach_driver(cfg: DriverConfig) -> Result<Driver, AttachError> {
    let slot = crate::state::try_sched_slot().ok_or(AttachError::NotGlobal)?;
    if slot.driver.swap(true, Ordering::AcqRel) {
        return Err(AttachError::AlreadyAttached);
    }
    let audit = cfg.audit || super::audit_env();
    crate::state::seed_rng(cfg.seed);
    slot.reg().attach(cfg.accounting, audit);
    slot.clock().set_driven();
    let origin = origin_after(slot.clock().now());
    slot.clock().jump(origin);
    slot.set_wall_base_ns(duration_ns(DRIVEN_WALL_EPOCH) - origin);
    slot.timers().notify();
    Ok(Driver { slot, cfg })
}

fn origin_after(now: u64) -> u64 {
    const SEC: u64 = 1_000_000_000;
    now.div_ceil(SEC)
        .saturating_mul(SEC)
        .max(duration_ns(DRIVEN_ORIGIN))
}

impl Driver {
    fn reg(&self) -> &Arc<Registry> {
        self.slot.reg()
    }

    /// Current virtual time, the same value [`crate::time_value`] reports on
    /// threads without a driver-time override.
    pub fn now(&self) -> Duration {
        Duration::from_nanos(self.slot.clock().now())
    }

    pub fn config(&self) -> &DriverConfig {
        &self.cfg
    }

    /// Install a new flow line. The anchor never moves time backwards: if
    /// `g.anchor_v` is behind the clock, the line is anchored at the current
    /// value and wall time instead.
    pub fn grant(&self, g: Grant) {
        self.slot.clock().grant(
            duration_ns(g.anchor_v),
            wall_ns_of(g.anchor_wall),
            g.rate,
            duration_ns(g.horizon),
        );
        self.slot.timers().notify();
    }

    /// Stop the clock where it is: horizon = now, rate 0.
    pub fn freeze(&self) {
        self.slot.clock().freeze();
        self.slot.timers().notify_if_reachable();
    }

    /// Earliest pending timer deadline in this slot.
    pub fn next_deadline(&self) -> Option<Duration> {
        self.slot.timers().next_deadline().map(Duration::from_nanos)
    }

    /// Jump the clock to `t` if the domain is still quiescent, checked under
    /// the registry lock. If a timer is due before `t` the clock lands on
    /// that deadline instead, so one jump fires exactly one timer group.
    /// Returns how many timers fired. The clock is left frozen where it
    /// landed.
    pub fn jump_to(&self, t: Duration) -> Result<u32, NotQuiescent> {
        let due = self.reg().jump(duration_ns(t))?;
        let fired = super::as_driver(|| self.slot.timers().fire_taken(due));
        self.slot.timers().notify_if_reachable();
        Ok(fired)
    }

    /// Start running the internal timestamp `t` on the calling thread: the
    /// clock moves to `t - 1ns` and holds there, the calling thread reads
    /// exactly `t` from every snare clock, and the wakes it causes are
    /// deferred until [`leave_timestamp`](Self::leave_timestamp). Marks the
    /// calling thread as a driver thread.
    pub fn enter_timestamp(&self, t: Duration) {
        let t = duration_ns(t);
        self.slot.clock().jump(t.saturating_sub(1));
        super::mark_driver_thread();
        set_driver_time(Some(t));
        participant::set_defer(Some(Arc::clone(self.reg())));
        self.slot.timers().notify_if_reachable();
    }

    /// [`enter_timestamp`](Self::enter_timestamp), but only if the domain is
    /// quiescent and no timer is due before `t`, checked under the scheduler
    /// lock together with the clock move. On `Err` nothing changed except
    /// that the calling thread is marked as a driver thread.
    pub fn enter_timestamp_checked(&self, t: Duration) -> Result<(), NotQuiescent> {
        let t = duration_ns(t);
        super::mark_driver_thread();
        self.reg().enter_checked(t)?;
        set_driver_time(Some(t));
        participant::set_defer(Some(Arc::clone(self.reg())));
        self.slot.timers().notify_if_reachable();
        Ok(())
    }

    /// Finish timestamp `t`: the clock moves to `t` (frozen until the next
    /// grant), the deferred wakes are delivered and every timer due at `t`
    /// fires. Returns how many timers fired.
    pub fn leave_timestamp(&self, t: Duration) -> u32 {
        set_driver_time(None);
        participant::set_defer(None);
        self.slot.clock().jump(duration_ns(t));
        let fired = super::as_driver(|| {
            self.reg().flush_deferred();
            self.slot.timers().fire_due()
        });
        self.slot.timers().notify_if_reachable();
        fired
    }

    /// The quiescence predicate and its inputs, read under the registry lock.
    pub fn quiescence(&self) -> Quiescence {
        self.reg().quiescence()
    }

    /// Call `f` once, the next time the quiescence epoch moves past
    /// `seen_epoch` (at once if it already has). Replaces any earlier
    /// arming. `f` runs on whichever thread changed the state, with no snare
    /// lock held; keep it short.
    pub fn arm_notify(&self, seen_epoch: u64, f: Arc<dyn Fn() + Send + Sync>) {
        self.reg().arm(seen_epoch, f);
    }

    /// Every registered participant thread, then every busy lease.
    pub fn participants(&self) -> Vec<ParticipantInfo> {
        self.reg().participants()
    }

    /// The `n` earliest pending timers.
    pub fn timers(&self, n: usize) -> Vec<TimerInfo> {
        self.reg().timers(n)
    }

    /// Take the starvation hints raised since the last call.
    pub fn drain_hints(&self) -> Vec<(Arc<str>, f32)> {
        self.reg().drain_hints()
    }

    /// Stray wakes, recorded quiescence violations, class effects and the
    /// unknown threads every [`thread_census`](super::thread_census) so far
    /// has found.
    pub fn audit(&self) -> AuditReport {
        AuditReport {
            unknown_threads: crate::census::unknown(),
            ..self.reg().audit_report()
        }
    }

    /// Every busy lease held, with the name of the participant whose thread
    /// took it (`None` when the holder is no participant).
    pub fn held_leases(&self) -> Vec<(&'static str, Option<Arc<str>>)> {
        self.reg().held_leases()
    }

    /// Release the clock: the same as dropping the driver.
    pub fn detach(self) {}
}

impl Drop for Driver {
    fn drop(&mut self) {
        self.reg().detach();
        self.slot.clock().set_scaled();
        self.slot.driver.store(false, Ordering::Release);
        self.slot.timers().notify();
    }
}

impl std::fmt::Debug for Driver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Driver")
            .field("now", &self.now())
            .field("cfg", &self.cfg)
            .finish()
    }
}
