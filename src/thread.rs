//! Drop-in shim for [`std::thread`].
//!
//! Re-exports every `std::thread` type and free function unchanged, but the
//! [`spawn`] free function and [`Builder::spawn`] method are wrapped so the
//! newly-created thread auto-registers itself as a child of the spawning
//! thread before running any user code. Use this in place of `std::thread`
//! and you can drop every manual `.register_as_child()` / `register_thread_child_of`
//! call in your tests.
//!
//! [`sleep`] blocks on snare's virtual clock rather than real time (see
//! [`snare::time`](crate::time)); reach for [`real_sleep`] when a test needs to
//! wait in real wall-clock time regardless of the clock's rate. [`park`] and
//! [`park_timeout`] are snare waits too, woken through the [`Thread`] handle
//! [`current`] returns.
//!
//! When the `shim` feature is off, this module is a transparent re-export of
//! `std::thread` — nothing extra runs, and [`real_sleep`] aliases
//! [`std::thread::sleep`].

#[cfg(not(feature = "shim"))]
pub use std::thread::sleep as real_sleep;
#[cfg(not(feature = "shim"))]
pub use std::thread::*;

/// Block until `deadline` in wall time. Returns at once if it has passed.
#[cfg(not(feature = "shim"))]
pub fn sleep_until(deadline: std::time::Instant) {
    let now = std::time::Instant::now();
    if deadline > now {
        std::thread::sleep(deadline - now);
    }
}

#[cfg(feature = "shim")]
pub use std::thread::{
    AccessError, LocalKey, Scope, ThreadId, available_parallelism, panicking, yield_now,
};

#[cfg(feature = "shim")]
pub use std::thread::Result;

#[cfg(feature = "shim")]
mod shimmed {
    use std::future::Future;
    use std::io;
    use std::ops::Deref;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::task::{Context, Poll};
    use std::time::Duration;

    use crate::sched::WakerSet;
    use crate::sched::timer::ParkCell;

    /// Set by the spawned thread once its closure has returned or unwound.
    #[derive(Default)]
    struct Exit {
        done: AtomicBool,
        waiters: WakerSet,
    }

    impl Exit {
        fn wait(&self) {
            crate::sched::block_on(ExitWait(self));
        }
    }

    struct ExitWait<'a>(&'a Exit);

    impl Future for ExitWait<'_> {
        type Output = ();

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            if self.0.done.load(Ordering::Acquire) {
                return Poll::Ready(());
            }
            self.0.waiters.register(cx.waker());
            if self.0.done.load(Ordering::Acquire) {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        }
    }

    struct SignalExit(Arc<Exit>);

    impl Drop for SignalExit {
        fn drop(&mut self) {
            self.0.done.store(true, Ordering::Release);
            self.0.waiters.wake_all();
        }
    }

    /// An owned permission to join a thread, like [`std::thread::JoinHandle`],
    /// whose [`join`](Self::join) is a snare wait: the joining participant
    /// counts as blocked until the thread's closure has returned.
    pub struct JoinHandle<T> {
        inner: std::thread::JoinHandle<T>,
        exit: Arc<Exit>,
    }

    impl<T> JoinHandle<T> {
        /// Wait for the thread to finish, as [`std::thread::JoinHandle::join`].
        pub fn join(self) -> Result<T> {
            self.exit.wait();
            self.inner.join()
        }

        /// The std handle of the underlying thread.
        pub fn thread(&self) -> &std::thread::Thread {
            self.inner.thread()
        }

        /// Whether the thread has finished running its closure, as
        /// [`std::thread::JoinHandle::is_finished`].
        pub fn is_finished(&self) -> bool {
            self.inner.is_finished()
        }

        /// The std handle, whose `join` snare cannot see.
        pub fn into_std(self) -> std::thread::JoinHandle<T> {
            self.inner
        }
    }

    impl<T> std::fmt::Debug for JoinHandle<T> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("JoinHandle").finish_non_exhaustive()
        }
    }

    #[cfg(unix)]
    impl<T> std::os::unix::thread::JoinHandleExt for JoinHandle<T> {
        fn as_pthread_t(&self) -> std::os::unix::thread::RawPthread {
            self.inner.as_pthread_t()
        }

        fn into_pthread_t(self) -> std::os::unix::thread::RawPthread {
            self.inner.into_pthread_t()
        }
    }

    /// A scoped thread's join handle, like [`std::thread::ScopedJoinHandle`],
    /// whose [`join`](Self::join) is a snare wait.
    pub struct ScopedJoinHandle<'scope, T> {
        inner: std::thread::ScopedJoinHandle<'scope, T>,
        exit: Arc<Exit>,
    }

    impl<T> ScopedJoinHandle<'_, T> {
        /// Wait for the thread to finish, as
        /// [`std::thread::ScopedJoinHandle::join`].
        pub fn join(self) -> Result<T> {
            self.exit.wait();
            self.inner.join()
        }

        pub fn thread(&self) -> &std::thread::Thread {
            self.inner.thread()
        }

        pub fn is_finished(&self) -> bool {
            self.inner.is_finished()
        }
    }

    impl<T> std::fmt::Debug for ScopedJoinHandle<'_, T> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("ScopedJoinHandle").finish_non_exhaustive()
        }
    }

    /// The body of every thread snare spawns: registers it with its parent's
    /// state slot and participant handoff, then runs `f` and signals `exit`
    /// however `f` ends.
    fn run_child<T>(
        parent: std::thread::ThreadId,
        handoff: Option<crate::sched::participant::Handoff>,
        exit: Arc<Exit>,
        f: impl FnOnce() -> T,
    ) -> T {
        crate::register_thread_child_of(parent);
        if let Some(h) = handoff {
            h.install();
        }
        let _registered = crate::threads::enter();
        let _exit = SignalExit(exit);
        f()
    }

    /// A handle to a thread, like [`std::thread::Thread`], whose
    /// [`unpark`](Self::unpark) wakes the virtual [`park`] and
    /// [`park_timeout`]. Derefs to the std handle.
    ///
    /// [`JoinHandle::thread`](std::thread::JoinHandle::thread) and
    /// [`Scope`](std::thread::Scope) still hand out std handles, since
    /// replacing them would mean replacing std's whole thread API; convert
    /// one with [`Thread::from`] before unparking. A std `unpark` does not
    /// reach a thread parked in [`park`].
    #[derive(Clone)]
    pub struct Thread {
        inner: std::thread::Thread,
        token: Arc<ParkCell>,
    }

    impl Thread {
        /// Makes the thread's token available, waking it if it is parked in
        /// [`park`] or [`park_timeout`] (or in `std::thread::park`).
        pub fn unpark(&self) {
            self.token.unpark();
            self.inner.unpark();
        }
    }

    impl std::fmt::Debug for Thread {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            self.inner.fmt(f)
        }
    }

    impl Deref for Thread {
        type Target = std::thread::Thread;

        fn deref(&self) -> &std::thread::Thread {
            &self.inner
        }
    }

    impl From<std::thread::Thread> for Thread {
        fn from(inner: std::thread::Thread) -> Thread {
            let token = crate::sched::thread_token(inner.id());
            Thread { inner, token }
        }
    }

    impl From<Thread> for std::thread::Thread {
        fn from(t: Thread) -> std::thread::Thread {
            t.inner
        }
    }

    /// The calling thread's handle. Mirrors [`std::thread::current`].
    pub fn current() -> Thread {
        Thread::from(std::thread::current())
    }

    /// Drop-in for [`std::thread::park`] on snare's scheduler: blocks until
    /// the thread's token is made available by [`Thread::unpark`], consuming
    /// it. A parked participant counts as blocked, so the virtual clock can
    /// move on. Like std's, it may return spuriously.
    pub fn park() {
        crate::sched::park_thread(None, "thread park");
    }

    /// Drop-in for [`std::thread::park_timeout`] on snare's virtual clock:
    /// [`park`], returning after at most `dur` of virtual time.
    pub fn park_timeout(dur: Duration) {
        let deadline = crate::time::Instant::now().checked_add(dur);
        crate::sched::park_thread(deadline, "thread park_timeout");
    }

    /// Drop-in for [`std::thread::sleep`] that blocks on snare's virtual clock
    /// instead of real wall time. A paused clock (`rate == 0`) suspends the
    /// thread until another thread advances the clock; a fast clock returns
    /// after proportionally less real time. Use [`real_sleep`] to block in real
    /// wall time regardless of the clock. A zero duration returns immediately.
    pub fn sleep(dur: Duration) {
        crate::sched::sleep_for(dur);
    }

    /// Block until snare's virtual clock reaches `deadline`. Returns at once
    /// if it already has. Pairs with [`sleep`] for drift-free fixed-period
    /// loops: `next += period; sleep_until(next)`.
    pub fn sleep_until(deadline: crate::time::Instant) {
        crate::sched::sleep_until_virtual(deadline);
    }

    /// Sleep in real wall-clock time, bypassing the virtual clock — a direct
    /// alias for [`std::thread::sleep`]. For test code that must wait on
    /// something outside the shim (real I/O, an OS-driven background thread)
    /// no matter what rate the virtual clock runs at.
    pub fn real_sleep(dur: Duration) {
        std::thread::sleep(dur);
    }

    /// Spawn a new thread that auto-registers itself as a child of the calling
    /// thread (via [`register_thread_child_of`](crate::register_thread_child_of))
    /// before running `f`. Otherwise identical to [`std::thread::spawn`],
    /// except that the returned [`JoinHandle`]'s `join` is a snare wait.
    ///
    /// Under an accounting [`sched::Driver`](crate::sched::Driver) the child
    /// is registered as a running participant here, before the OS thread
    /// exists, so the domain cannot look quiescent while it starts up.
    pub fn spawn<F, T>(f: F) -> JoinHandle<T>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        Builder::new().spawn(f).expect("failed to spawn thread")
    }

    /// Spawn a snare-internal thread named `name` that is marked background
    /// before it runs, so it is never a participant, not even while it
    /// starts. Registered in the state slot's thread registry like any
    /// [`spawn`]ed thread.
    #[cfg_attr(any(not(test), snare_global), allow(dead_code))]
    pub(crate) fn spawn_background<F, T>(
        name: &'static str,
        f: F,
    ) -> io::Result<std::thread::JoinHandle<T>>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        let parent = std::thread::current().id();
        std::thread::Builder::new()
            .name(name.to_string())
            .spawn(move || {
                crate::register_thread_child_of(parent);
                crate::sched::mark_background(name);
                let _registered = crate::threads::enter();
                f()
            })
    }

    /// Drop-in wrapper around [`std::thread::Builder`] whose [`spawn`](Self::spawn)
    /// method auto-registers the spawned thread as a child of the calling thread
    /// before running `f`.
    pub struct Builder {
        inner: std::thread::Builder,
        name: Option<String>,
    }

    impl Builder {
        /// Equivalent to [`std::thread::Builder::new`].
        pub fn new() -> Self {
            Self {
                inner: std::thread::Builder::new(),
                name: None,
            }
        }

        /// Equivalent to [`std::thread::Builder::name`].
        pub fn name(mut self, name: String) -> Self {
            self.inner = self.inner.name(name.clone());
            self.name = Some(name);
            self
        }

        /// Equivalent to [`std::thread::Builder::stack_size`].
        pub fn stack_size(mut self, size: usize) -> Self {
            self.inner = self.inner.stack_size(size);
            self
        }

        /// Spawn the thread, auto-registering it as a child of the calling
        /// thread before `f` runs, with the same participant handoff as
        /// [`spawn`]. Returns snare's [`JoinHandle`], whose `join` is a
        /// snare wait.
        pub fn spawn<F, T>(self, f: F) -> io::Result<JoinHandle<T>>
        where
            F: FnOnce() -> T + Send + 'static,
            T: Send + 'static,
        {
            let parent = std::thread::current().id();
            let handoff = crate::sched::handoff(self.name.as_deref());
            let exit = Arc::<Exit>::default();
            let child_exit = Arc::clone(&exit);
            let inner = self
                .inner
                .spawn(move || run_child(parent, handoff, child_exit, f))?;
            Ok(JoinHandle { inner, exit })
        }

        /// Spawn the thread inside `scope`, auto-registering it as a child of
        /// the calling thread before `f` runs. Returns snare's
        /// [`ScopedJoinHandle`], whose `join` is a snare wait.
        pub fn spawn_scoped<'scope, 'env, F, T>(
            self,
            scope: &'scope std::thread::Scope<'scope, 'env>,
            f: F,
        ) -> io::Result<ScopedJoinHandle<'scope, T>>
        where
            F: FnOnce() -> T + Send + 'scope,
            T: Send + 'scope,
        {
            let parent = std::thread::current().id();
            let handoff = crate::sched::handoff(self.name.as_deref());
            let exit = Arc::<Exit>::default();
            let child_exit = Arc::clone(&exit);
            let inner = self
                .inner
                .spawn_scoped(scope, move || run_child(parent, handoff, child_exit, f))?;
            Ok(ScopedJoinHandle { inner, exit })
        }
    }

    impl Default for Builder {
        fn default() -> Self {
            Self::new()
        }
    }
}

#[cfg(feature = "shim")]
#[cfg_attr(any(not(test), snare_global), allow(unused_imports))]
pub(crate) use shimmed::spawn_background;
#[cfg(feature = "shim")]
pub use shimmed::{
    Builder, JoinHandle, ScopedJoinHandle, Thread, current, park, park_timeout, real_sleep, sleep,
    sleep_until, spawn,
};

// `std::thread::scope` is re-exported as-is. Wrapping it would force callers
// to thread an extra lifetime through every closure body (the wrapper would
// have to live for the full `'scope`, but it can only be created inside the
// scope-closure body — outliving its own borrow). Since scoped threads are
// borrowed-data-only and rarely used in tests, callers should attach them
// manually with `t.thread().id().register_as_child()` after `s.spawn(...)`.
#[cfg(feature = "shim")]
pub use std::thread::scope;
