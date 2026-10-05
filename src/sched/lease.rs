use std::fmt;
#[cfg(feature = "shim")]
use std::sync::Arc;

#[cfg(feature = "shim")]
use super::participant::Registry;

/// Keeps the domain from counting as quiescent until dropped. `Send`, so a
/// lease can follow work to another thread; the thread that took it is the
/// holder the audit checks against.
#[must_use = "the lease ends when it is dropped"]
pub struct BusyLease {
    #[cfg(feature = "shim")]
    inner: Option<(Arc<Registry>, u64, u64)>,
    label: &'static str,
}

/// Take a busy lease labelled `label`. A no-op unless a
/// [`Driver`](super::Driver) owns the calling thread's clock.
pub fn busy(label: &'static str) -> BusyLease {
    #[cfg(feature = "shim")]
    let inner = super::participant::any_attached()
        .then(super::slot::try_slot)
        .flatten()
        .and_then(|s| {
            let reg = Arc::clone(s.reg());
            reg.lease(label)
                .map(|(generation, id)| (reg, generation, id))
        });
    BusyLease {
        #[cfg(feature = "shim")]
        inner,
        label,
    }
}

impl BusyLease {
    /// A lease already taken from `reg`, to be held by whoever ends up with
    /// this value.
    #[cfg(all(feature = "shim", feature = "fast-talker-core"))]
    pub(super) fn taken(reg: &Arc<Registry>, label: &'static str) -> Option<Self> {
        let (generation, id) = reg.lease(label)?;
        Some(BusyLease {
            inner: Some((Arc::clone(reg), generation, id)),
            label,
        })
    }
}

impl Drop for BusyLease {
    fn drop(&mut self) {
        #[cfg(feature = "shim")]
        if let Some((reg, generation, id)) = self.inner.take() {
            reg.release(generation, id);
        }
    }
}

impl fmt::Debug for BusyLease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BusyLease")
            .field("label", &self.label)
            .finish()
    }
}

/// Tell the driver that `source` is starved for simulated time; `severity`
/// in `[0, 1]`. Collected by [`Driver::drain_hints`](super::Driver::drain_hints).
pub fn hint_starving(source: &str, severity: f32) {
    #[cfg(feature = "shim")]
    if let Some(s) = super::participant::any_attached()
        .then(super::slot::try_slot)
        .flatten()
    {
        s.reg().hint(source, severity);
    }
    #[cfg(not(feature = "shim"))]
    let _ = (source, severity);
}
