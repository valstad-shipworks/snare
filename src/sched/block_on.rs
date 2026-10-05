use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use super::park::park_as;
use super::timer::{TimeSource, TimerTarget, Timers};
use super::{ParkResult, park_cell};
use super::{Source, timers};

/// Drive `f` to completion on the calling thread, parking between polls.
/// The waker is the thread's [`Unparker`](super::Unparker), so under an
/// accounting driver the thread counts as blocked while the future is
/// pending and as running from the moment it is woken.
pub fn block_on<F: Future>(f: F) -> F::Output {
    let waker = Waker::from(park_cell());
    let mut cx = Context::from_waker(&waker);
    let mut f = std::pin::pin!(f);
    loop {
        if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return v;
        }
        park_as(None, "block_on");
    }
}

/// Drive `f` like [`block_on`], giving up at `deadline` (virtual under
/// `shim`, wall time otherwise). `None` means no deadline. When the deadline
/// passes, `f` is polled once more before `None` is returned, so an output
/// that became ready at the deadline instant is not lost.
///
/// Under an accounting driver the caller is blocked (snare-visible) while
/// `f` is pending, with the deadline as its timer: the driver can jump the
/// clock straight to it once the domain is quiescent.
pub fn block_on_until<F: Future>(
    f: F,
    deadline: Option<crate::time::Instant>,
) -> Option<F::Output> {
    let waker = Waker::from(park_cell());
    let mut cx = Context::from_waker(&waker);
    let mut f = std::pin::pin!(f);
    loop {
        if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return Some(v);
        }
        if park_as(deadline, "block_on") == ParkResult::TimedOut {
            return match f.as_mut().poll(&mut cx) {
                Poll::Ready(v) => Some(v),
                Poll::Pending => None,
            };
        }
    }
}

/// [`block_on_until`] with a deadline `timeout` from now on the snare clock.
/// A timeout that overflows the clock (e.g. `Duration::MAX`) means no
/// deadline.
pub fn block_on_timeout<F: Future>(f: F, timeout: Duration) -> Option<F::Output> {
    block_on_until(f, crate::time::Instant::now().checked_add(timeout))
}

/// Future that completes once the clock reaches its deadline. Dropping it
/// removes its timer entry.
pub struct Sleep {
    timers: Arc<Timers<Source>>,
    deadline: u64,
    id: Option<u64>,
}

impl Sleep {
    /// Whether the deadline has been reached.
    pub fn is_elapsed(&self) -> bool {
        self.timers.source().now_ns() >= self.deadline
    }
}

impl Future for Sleep {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = &mut *self;
        if this.is_elapsed() {
            if let Some(id) = this.id.take() {
                this.timers.cancel(id);
            }
            return Poll::Ready(());
        }
        let registered = this
            .id
            .is_some_and(|id| this.timers.set_waker(id, cx.waker()));
        if !registered {
            #[cfg(feature = "shim")]
            let foreign = {
                super::participant::class_effect("sleep");
                super::participant::foreign_here()
            };
            #[cfg(not(feature = "shim"))]
            let foreign = false;
            this.id = Some(this.timers.insert_as(
                this.deadline,
                TimerTarget::Waker(cx.waker().clone()),
                foreign,
            ));
            #[cfg(feature = "shim")]
            if !foreign {
                super::participant::foreign_timer_added();
            }
        }
        Poll::Pending
    }
}

impl Drop for Sleep {
    fn drop(&mut self) {
        if let Some(id) = self.id.take() {
            self.timers.cancel(id);
        }
    }
}

impl fmt::Debug for Sleep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sleep")
            .field("deadline_ns", &self.deadline)
            .field("registered", &self.id.is_some())
            .finish()
    }
}

/// A [`Sleep`] that completes at `deadline` (virtual under `shim`).
pub fn sleep_until(deadline: crate::time::Instant) -> Sleep {
    #[cfg(feature = "shim")]
    let deadline = super::slot::instant_ns(deadline);
    #[cfg(not(feature = "shim"))]
    let deadline = super::timer::wall_ns_of(deadline);
    Sleep {
        timers: timers(),
        deadline,
        id: None,
    }
}
