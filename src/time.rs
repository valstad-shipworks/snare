//! Drop-in shim for [`std::time`].
//!
//! With the `shim` feature on, `Instant` and `SystemTime` read from a virtual
//! per-test clock instead of the OS clock. The clock resolves through the same
//! thread-chain hierarchy as `snare::net` — every thread the test owns sees one
//! shared clock — and honours `--cfg snare_global`. Control it from the test
//! with [`set_time_rate`](crate::set_time_rate), [`pause_time`](crate::pause_time),
//! [`advance_time`](crate::advance_time), and [`set_time_value`](crate::set_time_value):
//! set the rate to `0` to pause, `>1` to run fast. `Duration` is unchanged — it
//! re-exports `std::time::Duration`.
//!
//! When the `shim` feature is off this module is a transparent re-export of
//! `std::time` — nothing extra runs, so the same SUT code that uses
//! `snare::time::Instant` compiles to the real thing in release builds.
//!
//! [`snare::thread::sleep`](crate::thread::sleep) also honours this clock: it
//! blocks until virtual time has advanced by its duration, so a paused clock
//! parks the sleeper until it's advanced and a fast clock wakes it sooner. Use
//! [`snare::thread::real_sleep`](crate::thread::real_sleep) to wait in real wall
//! time. The tester loop itself still runs in real time.

#[cfg(not(feature = "shim"))]
pub use std::time::*;

#[cfg(feature = "shim")]
pub use std::time::{Duration, TryFromFloatSecsError};

#[cfg(feature = "shim")]
pub use shimmed::{Instant, SystemTime, SystemTimeError, UNIX_EPOCH};

#[cfg(feature = "shim")]
mod shimmed {
    use std::error::Error;
    use std::fmt;
    use std::ops::{Add, AddAssign, Sub, SubAssign};
    use std::time::Duration;

    use crate::state;

    /// Virtual monotonic clock reading, stored as a [`Duration`] since the
    /// clock's virtual epoch. Drop-in replacement for [`std::time::Instant`].
    #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct Instant(Duration);

    impl Instant {
        pub fn now() -> Instant {
            Instant(state::clock_mono_now())
        }

        pub fn duration_since(&self, earlier: Instant) -> Duration {
            self.0.saturating_sub(earlier.0)
        }

        pub fn saturating_duration_since(&self, earlier: Instant) -> Duration {
            self.0.saturating_sub(earlier.0)
        }

        pub fn checked_duration_since(&self, earlier: Instant) -> Option<Duration> {
            self.0.checked_sub(earlier.0)
        }

        pub fn elapsed(&self) -> Duration {
            Instant::now().0.saturating_sub(self.0)
        }

        pub fn checked_add(&self, duration: Duration) -> Option<Instant> {
            self.0.checked_add(duration).map(Instant)
        }

        pub fn checked_sub(&self, duration: Duration) -> Option<Instant> {
            self.0.checked_sub(duration).map(Instant)
        }
    }

    impl Add<Duration> for Instant {
        type Output = Instant;
        fn add(self, rhs: Duration) -> Instant {
            self.checked_add(rhs)
                .expect("overflow when adding duration to instant")
        }
    }

    impl AddAssign<Duration> for Instant {
        fn add_assign(&mut self, rhs: Duration) {
            *self = *self + rhs;
        }
    }

    impl Sub<Duration> for Instant {
        type Output = Instant;
        fn sub(self, rhs: Duration) -> Instant {
            self.checked_sub(rhs)
                .expect("overflow when subtracting duration from instant")
        }
    }

    impl SubAssign<Duration> for Instant {
        fn sub_assign(&mut self, rhs: Duration) {
            *self = *self - rhs;
        }
    }

    impl Sub<Instant> for Instant {
        type Output = Duration;
        fn sub(self, rhs: Instant) -> Duration {
            self.duration_since(rhs)
        }
    }

    impl fmt::Debug for Instant {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_tuple("Instant").field(&self.0).finish()
        }
    }

    /// Virtual wall clock reading, stored as a [`Duration`] since
    /// [`UNIX_EPOCH`]. Drop-in replacement for [`std::time::SystemTime`].
    #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct SystemTime(Duration);

    /// An anchor in time equal to `1970-01-01 00:00:00 UTC` on the virtual
    /// clock. Mirrors [`std::time::UNIX_EPOCH`].
    pub const UNIX_EPOCH: SystemTime = SystemTime(Duration::ZERO);

    impl SystemTime {
        pub const UNIX_EPOCH: SystemTime = UNIX_EPOCH;

        pub fn now() -> SystemTime {
            SystemTime(state::clock_wall_now())
        }

        pub fn duration_since(&self, earlier: SystemTime) -> Result<Duration, SystemTimeError> {
            if self.0 >= earlier.0 {
                Ok(self.0 - earlier.0)
            } else {
                Err(SystemTimeError(earlier.0 - self.0))
            }
        }

        pub fn elapsed(&self) -> Result<Duration, SystemTimeError> {
            SystemTime::now().duration_since(*self)
        }

        pub fn checked_add(&self, duration: Duration) -> Option<SystemTime> {
            self.0.checked_add(duration).map(SystemTime)
        }

        pub fn checked_sub(&self, duration: Duration) -> Option<SystemTime> {
            self.0.checked_sub(duration).map(SystemTime)
        }
    }

    impl Add<Duration> for SystemTime {
        type Output = SystemTime;
        fn add(self, rhs: Duration) -> SystemTime {
            self.checked_add(rhs)
                .expect("overflow when adding duration to system time")
        }
    }

    impl AddAssign<Duration> for SystemTime {
        fn add_assign(&mut self, rhs: Duration) {
            *self = *self + rhs;
        }
    }

    impl Sub<Duration> for SystemTime {
        type Output = SystemTime;
        fn sub(self, rhs: Duration) -> SystemTime {
            self.checked_sub(rhs)
                .expect("overflow when subtracting duration from system time")
        }
    }

    impl SubAssign<Duration> for SystemTime {
        fn sub_assign(&mut self, rhs: Duration) {
            *self = *self - rhs;
        }
    }

    impl fmt::Debug for SystemTime {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_tuple("SystemTime").field(&self.0).finish()
        }
    }

    /// Error returned from [`SystemTime::duration_since`] and
    /// [`SystemTime::elapsed`] when the second time is later than `self`.
    /// Mirrors [`std::time::SystemTimeError`].
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct SystemTimeError(Duration);

    impl SystemTimeError {
        /// The positive duration by which the other time exceeds `self`.
        pub fn duration(&self) -> Duration {
            self.0
        }
    }

    impl fmt::Display for SystemTimeError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "second time provided was later than self")
        }
    }

    impl Error for SystemTimeError {}
}
