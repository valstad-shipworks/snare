//! The [`Layer`] trait a domain's stages implement, and the small types its operations carry.
//!
//! A hook turns a managed thread's OS call into one of these operations and offers it to the
//! domain's layers front to back; the first [`Flow::Done`] wins, and if every layer passes the
//! hook makes the real call. Layers run under passthrough (see `crate::state`), so they may use
//! the real OS freely.

use std::fmt;
use std::task::Waker;
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
    /// since 2017-01-01, IERS Bulletin C). Real-time networking uses it for hardware transmit
    /// scheduling. Linux only: clock id 11 in `include/uapi/linux/time.h`; Darwin has no such clock.
    ///
    /// Unlike UTC, TAI has no leap seconds, so the offset only steps when a leap second is
    /// inserted; the kernel holds it as `timex.tai`, set through `adjtimex(2)`. `SO_TXTIME` launch
    /// times are on the clock named in `struct sock_txtime` (`include/uapi/linux/net_tstamp.h`),
    /// which must match the etf qdisc's `clockid`; tc-etf(8)'s example uses `CLOCK_TAI`.
    Tai,
}

/// What a sleep asks for, as the hooked sleep call expressed it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SleepRequest {
    /// Sleep for a span measured from now (`nanosleep`, `usleep`, `Sleep`, a relative
    /// `clock_nanosleep`).
    For(Duration),
    /// Sleep until `clock` reads the given time (`clock_nanosleep` with `TIMER_ABSTIME`).
    Until(ClockKind, Duration),
}

/// What one step of a clock spin did to a layer's clock (see [`Layer::spin_step`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpinStep {
    /// The clock moved forward; `fired` says it reached a pending timer, whose waiter needs
    /// waking.
    Moved {
        /// Whether the step carried time onto or past a pending timer.
        fired: bool,
    },
    /// The clock is held (paused, or owned by an executive): only a writer moves it, so the
    /// spinner waits on time no spinning can make pass.
    Held,
    /// The clock has reached a timer whose waiter has yet to run: the spinner waits for it before
    /// time moves on.
    Waking,
    /// The clock moves without the spinner's help (scaled to real time, ticking on each read), or
    /// this layer has no clock: nothing to do.
    Runs,
}

/// One stage of a managed thread's OS.
///
/// Every method defaults to [`Flow::Pass`], so a layer implements only what it models. Methods
/// run on the calling thread with redirection switched off: anything a layer does itself goes
/// straight to the OS.
pub trait Layer: Send + Sync + 'static {
    /// Reads `clock`. `Done` is the reading as a span since the clock's origin; each hook converts
    /// it into its own API's units (a `timespec`, Mach ticks, 100 ns `FILETIME` intervals).
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
    /// Stands in for `getrandom(2)`/`getentropy(3)` on Linux, `getentropy`,
    /// `CCRandomGenerateBytes` and `arc4random` on macOS, and `ProcessPrng`/`BCryptGenRandom` on
    /// Windows. Seeded randomness makes std's `HashMap` iteration order, among others,
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

    /// As [`try_time_skip`](Self::try_time_skip), to the earliest pending timer of any thread,
    /// participant or not: called when every participant waits on something only a thread of
    /// another class can do, so that thread's timers are what moves the domain on.
    fn try_foreign_time_skip(&self) -> bool {
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

    /// Records something that happens on its own `after` from now — a datagram arriving after its
    /// link latency — as a pending virtual timer. Unlike [`register_timer`](Self::register_timer),
    /// which files a thread's own wait under its class, this is an event every thread may wait for,
    /// so a time skip may land on it whichever thread registered it.
    fn register_event_timer(&self, after: Duration) -> Option<u64> {
        self.register_timer(after)
    }

    /// Whether this layer supplies clock-driven callbacks through [`register_wake`](Self::register_wake)
    /// for native wait objects. A clock that implements only `sleep` leaves this false.
    fn supports_timer_wakes(&self) -> bool {
        false
    }

    /// Wakes `waker` once this layer's clock reaches monotonic time `at`: a pending timer filed under
    /// the calling thread's class, as [`register_timer`](Self::register_timer) files a wait, that a
    /// time skip, a scaled clock reaching it or a writer moving the clock fires. Returns the key for
    /// [`cancel_wake`](Self::cancel_wake); `None` means this layer did not register it.
    fn register_wake(&self, at: Duration, waker: Waker) -> Option<u64> {
        let _ = (at, waker);
        None
    }

    /// Registers a timer for its original thread class when rearmed from an unmanaged callback.
    fn register_owned_wake(&self, at: Duration, waker: Waker, _foreign: bool) -> Option<u64> {
        self.register_wake(at, waker)
    }

    /// Drops a waker from [`register_wake`](Self::register_wake) that has not fired.
    fn cancel_wake(&self, key: u64) {
        let _ = key;
    }

    /// Whether this layer woke wakers from [`register_wake`](Self::register_wake) since last asked.
    /// It wakes them from inside the sim's own code, where their wakes reach the OS unhooked, so a
    /// deterministic schedule re-polls the threads it holds on native wait objects.
    fn take_timer_wakes(&self) -> bool {
        false
    }

    /// Every participant of `domain` may now be blocked, the last having entered a native wait
    /// that never gives up or left the participants, so none may run a time skip of its own. A
    /// layer holding wakers a skip could land on arranges for
    /// [`Domain::skip_idle`](crate::Domain::skip_idle) to run from outside the domain.
    fn native_quiescence(&self, domain: &crate::Domain) {
        let _ = domain;
    }

    /// Drops a pending timer registered by [`register_timer`](Self::register_timer) whose wait ended
    /// early, so virtual time is not later advanced to a deadline no thread is waiting for.
    fn unregister_timer(&self, _key: u64) {}

    /// Drops an event from [`register_event_timer`](Self::register_event_timer) that will no
    /// longer happen, so virtual time is not later advanced to it.
    fn unregister_event_timer(&self, _key: u64) {}

    /// A timed wait timed out at `deadline` on this layer's clock while the clock ticks on each
    /// read — it ran out in real time, or was held by a paused clock that has since resumed. A
    /// clock layer carries its clock to the deadline, as it would carry a sleep.
    fn expire_timer(&self, _deadline: Duration) {}

    /// Advances a discrete virtual clock by `latency`, the cost of a call that returned without
    /// blocking, and reports whether that carried time onto or past any pending timer (so its
    /// waiter needs waking). Leaves any other clock untouched and returns `false`.
    fn charge_latency(&self, _latency: Duration) -> bool {
        false
    }

    /// Moves a discrete virtual clock up to `step` on for a participant caught in a clock spin
    /// (reading the clock or yielding over and over with no other hooked call), never past a
    /// pending timer in one step; see `domain::clock_spin`. The default has no clock to move.
    fn spin_step(&self, _step: Duration) -> SpinStep {
        SpinStep::Runs
    }

    /// The current time on this layer's clock if it is a virtual clock that moves only as the sim
    /// moves it — discrete, scaled to real time, or paused — read without advancing it. `None` for
    /// every other clock, including one that ticks on each read.
    fn virtual_now(&self) -> Option<Duration> {
        None
    }

    /// How much real time `span` of this layer's virtual time takes to pass on its own: `Some`
    /// only while the clock runs scaled to real time.
    fn real_span(&self, _span: Duration) -> Option<Duration> {
        None
    }

    /// Whether this layer's clock is held — paused, or waiting to be moved from outside the sim —
    /// or will reach a pending timer on its own, and if so how long to wait in real time before
    /// checking it again. While it is `Some`, a domain with every thread blocked is waiting on
    /// time, not deadlocked.
    fn idle_wait(&self) -> Option<Duration> {
        None
    }

    /// Wakes the backend's blocked waiters so they re-check quiescence and their deadlines at once,
    /// instead of at their next poll — called after a time skip or when a native wait (a futex, a
    /// condvar) completes quiescence outside the backend's own wait loop. `domain` is the
    /// [`Domain::key`](crate::Domain::key) of the domain asking: a backend shared between domains
    /// wakes only that domain's waiters.
    fn wake_waiters(&self, _domain: usize) {}

    /// Wakes this layer's waiters after a full readiness broadcast for `domain`. Layers sharing
    /// that readiness board may omit its publication; other layers retain their own wakeup.
    fn wake_waiters_after_readiness(&self, domain: usize) {
        self.wake_waiters(domain);
    }

    /// Wakes the backend's blocked waiters of the domain with key `domain` that run outside a
    /// deterministic schedule, after the schedule moved virtual time; the waiters inside it are
    /// woken by the schedule itself.
    fn wake_unscheduled(&self, _domain: usize) {}

    /// Whether a waiter of the domain with key `domain` (see [`Domain::key`](crate::Domain::key))
    /// that the backend woke has yet to run. While one has, that domain may only look quiescent —
    /// the woken thread still counts as parked — so no time skip may happen. Waiters of other
    /// domains sharing the backend never count.
    fn settling(&self, _domain: usize) -> bool {
        false
    }

    /// Whether this layer's clock has reached a participant's timed wait that the waiting thread
    /// has yet to take, outside a deterministic schedule. The thread still counts as parked until
    /// it notices — a native timed wait does only between real-time slices — so the domain may only
    /// look quiescent, and a time skip then would carry the clock past that wait's deadline before
    /// it returns.
    fn wait_due(&self) -> bool {
        false
    }

    /// The domain's runs began (`false`: a thread entered it with [`Domain::enter`](crate::Domain::enter)
    /// while no other was inside) or all ended (`true`: the last such thread left). While dormant,
    /// the threads still managed by it are left over from a finished run: nothing waits on them,
    /// so a clock moves for their timed waits no faster than real time, and they block rather
    /// than give up when nothing is left to wait for. Called under the domain's run lock, with no
    /// other lock held.
    fn dormant(&self, _dormant: bool) {}

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
    /// The syscall number for `syscall` (the arch's `SYS_*`, `<sys/syscall.h>`), the request for
    /// `ioctl`; `None` for every other function.
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
