use std::convert::Infallible;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use super::timer::{TimeSource, Timers, wall_now_ns};
use super::{
    AttachError, AuditReport, DriverConfig, Grant, NotQuiescent, ParticipantInfo, Quiescence,
    TimerInfo,
};

/// Wall-clock time source for builds without `shim`.
pub(crate) struct Source;

impl TimeSource for Source {
    fn now_ns(&self) -> u64 {
        wall_now_ns()
    }

    fn wall_at(&self, v: u64) -> Option<u64> {
        Some(v)
    }
}

static TIMERS: LazyLock<Arc<Timers<Source>>> = LazyLock::new(|| Timers::new(Source));

pub(crate) fn timers() -> Arc<Timers<Source>> {
    Arc::clone(&TIMERS)
}

/// Cannot be constructed without the `shim` feature; [`attach_driver`]
/// always fails.
pub struct Driver {
    never: Infallible,
}

/// Always `Err(AttachError::ShimDisabled)` without the `shim` feature.
pub fn attach_driver(cfg: DriverConfig) -> Result<Driver, AttachError> {
    let _ = cfg;
    Err(AttachError::ShimDisabled)
}

impl Driver {
    pub fn now(&self) -> Duration {
        match self.never {}
    }

    pub fn config(&self) -> &DriverConfig {
        match self.never {}
    }

    pub fn grant(&self, g: Grant) {
        let _ = g;
        match self.never {}
    }

    pub fn freeze(&self) {
        match self.never {}
    }

    pub fn next_deadline(&self) -> Option<Duration> {
        match self.never {}
    }

    pub fn jump_to(&self, t: Duration) -> Result<u32, NotQuiescent> {
        let _ = t;
        match self.never {}
    }

    pub fn enter_timestamp(&self, t: Duration) {
        let _ = t;
        match self.never {}
    }

    pub fn enter_timestamp_checked(&self, t: Duration) -> Result<(), NotQuiescent> {
        let _ = t;
        match self.never {}
    }

    pub fn leave_timestamp(&self, t: Duration) -> u32 {
        let _ = t;
        match self.never {}
    }

    pub fn quiescence(&self) -> Quiescence {
        match self.never {}
    }

    pub fn arm_notify(&self, seen_epoch: u64, f: Arc<dyn Fn() + Send + Sync>) {
        let _ = (seen_epoch, f);
        match self.never {}
    }

    pub fn participants(&self) -> Vec<ParticipantInfo> {
        match self.never {}
    }

    pub fn timers(&self, n: usize) -> Vec<TimerInfo> {
        let _ = n;
        match self.never {}
    }

    pub fn drain_hints(&self) -> Vec<(Arc<str>, f32)> {
        match self.never {}
    }

    pub fn audit(&self) -> AuditReport {
        match self.never {}
    }

    pub fn held_leases(&self) -> Vec<(&'static str, Option<Arc<str>>)> {
        match self.never {}
    }

    pub fn detach(self) {
        match self.never {}
    }
}

impl std::fmt::Debug for Driver {
    fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.never {}
    }
}
