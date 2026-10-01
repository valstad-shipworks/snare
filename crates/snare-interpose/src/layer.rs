use std::fmt;
use std::time::Duration;

/// A layer's answer to one operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flow<T> {
    /// The layer handled the operation; later layers and the OS never see it.
    Done(T),
    /// Offer the operation to the next layer, and finally to the OS.
    Pass,
}

/// Which clock a time reading or an absolute deadline refers to.
///
/// Each OS clock that std, `libc` or `windows-sys` code can read maps onto one of these. CPU-time
/// clocks are not virtualized and always reach the OS. The POSIX clock ids are in `clock_gettime(2)`
/// (`<time.h>`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ClockKind {
    /// Time since an arbitrary fixed origin, never going backwards. `CLOCK_MONOTONIC`.
    Monotonic,
    /// Time since the Unix epoch. `CLOCK_REALTIME`.
    Realtime,
    /// International Atomic Time: `CLOCK_TAI`, which leads `Realtime` by the TAI–UTC offset (37 s
    /// today). Real-time networking uses it for hardware transmit scheduling.
    ///
    /// Unlike UTC, TAI has no leap seconds, so the offset only steps when a leap second is
    /// inserted; the kernel holds it as `timex.tai`, set through `adjtimex(2)`. `SO_TXTIME` launch
    /// times are expressed on this clock (`Documentation/networking/timestamping.rst`).
    Tai,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SleepRequest {
    For(Duration),
    /// Sleep until `clock` reads the given time.
    Until(ClockKind, Duration),
}

/// One stage of a managed thread's OS.
///
/// Every method defaults to [`Flow::Pass`], so a layer implements only what it models. Methods
/// run on the calling thread with redirection switched off: anything a layer does itself goes
/// straight to the OS.
pub trait Layer: Send + Sync + 'static {
    fn now(&self, clock: ClockKind) -> Flow<Duration> {
        let _ = clock;
        Flow::Pass
    }

    /// Blocks the calling thread. `Done` means the layer has carried out the whole sleep.
    fn sleep(&self, request: SleepRequest) -> Flow<()> {
        let _ = request;
        Flow::Pass
    }

    /// Fills `buffer` with random bytes, in place of the OS entropy source.
    ///
    /// Stands in for `getrandom(2)`/`getentropy(3)` on Linux and `ProcessPrng`/`BCryptGenRandom`
    /// on Windows. Seeded randomness makes std's `HashMap` iteration order, among others,
    /// repeatable.
    fn random(&self, buffer: &mut [u8]) -> Flow<()> {
        let _ = buffer;
        Flow::Pass
    }

    /// A managed thread made an OS call that no layer can model; it goes to the OS after this
    /// returns. The domain also counts it, see [`Domain::unmodelled`](crate::Domain::unmodelled).
    fn unmodelled(&self, call: Unmodelled) {
        let _ = call;
    }

    /// Called when the domain is quiescent (every managed thread is blocked in an in-memory wait)
    /// to give a clock layer the chance to jump virtual time forward to its next pending timer.
    /// `true` means time advanced, so a blocked wait can make progress rather than deadlock.
    fn try_time_skip(&self) -> bool {
        false
    }

    /// Records a timed wait (a socket/readiness wait with a timeout `after` from now) as a pending
    /// virtual timer, so [`try_time_skip`](Self::try_time_skip) can jump to it when the domain is
    /// quiescent — otherwise a timeout that nothing else can satisfy reads as a deadlock. A clock
    /// layer returns the absolute deadline it registered, to be handed back to
    /// [`unregister_timer`](Self::unregister_timer) if the wait returns before the timeout fires;
    /// `None` means this layer did not register one.
    fn register_timer(&self, _after: Duration) -> Option<u64> {
        None
    }

    /// Drops a pending timer registered by [`register_timer`](Self::register_timer) whose wait ended
    /// early, so virtual time is not later advanced to a deadline no thread is waiting for.
    fn unregister_timer(&self, _key: u64) {}

    /// Advances a discrete virtual clock by `latency`, the cost of a call that returned without
    /// blocking, and reports whether that carried time onto or past any pending timer (so its
    /// waiter needs waking). Leaves any other clock untouched and returns `false`.
    fn charge_latency(&self, _latency: Duration) -> bool {
        false
    }

    /// The current time on this layer's clock if it is a discrete virtual clock — one that holds
    /// still until the sim moves it — read without advancing it. `None` for every other clock.
    fn discrete_now(&self) -> Option<Duration> {
        None
    }

    /// Wakes the backend's blocked waiters so they re-check quiescence and their deadlines at once,
    /// instead of at their next poll — called after a time skip or when a native wait (a futex, a
    /// condvar) completes quiescence outside the backend's own wait loop.
    fn wake_waiters(&self) {}

    /// Whether a waiter the backend woke has yet to run. While one has, the domain may only look
    /// quiescent — the woken thread still counts as parked — so no time skip may happen.
    fn settling(&self) -> bool {
        false
    }

    /// Runs on a managed thread's child before any of the child's own code.
    fn thread_started(&self) {}

    /// Runs on a managed thread created by another managed thread, after its entry function
    /// returns.
    fn thread_exiting(&self) {}
}

/// An OS call a managed thread made that went to the OS because nothing models it yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Unmodelled {
    /// The C or Win32 function called.
    pub function: &'static str,
    /// The syscall number for `syscall`, the request for `ioctl`.
    pub detail: Option<i64>,
}

impl fmt::Display for Unmodelled {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.detail {
            Some(detail) => write!(f, "{}({detail:#x})", self.function),
            None => f.write_str(self.function),
        }
    }
}
