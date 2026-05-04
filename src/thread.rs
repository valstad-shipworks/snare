//! Drop-in shim for [`std::thread`].
//!
//! Re-exports every `std::thread` type and free function unchanged, but the
//! [`spawn`] free function and [`Builder::spawn`] method are wrapped so the
//! newly-created thread auto-registers itself as a child of the spawning
//! thread before running any user code. Use this in place of `std::thread`
//! and you can drop every manual `.register_as_child()` / `register_thread_child_of`
//! call in your tests.
//!
//! When the `shim` feature is off, this module is a transparent re-export of
//! `std::thread` — nothing extra runs.

#[cfg(not(feature = "shim"))]
pub use std::thread::*;

#[cfg(feature = "shim")]
pub use std::thread::{
    AccessError, JoinHandle, LocalKey, Scope, ScopedJoinHandle, Thread, ThreadId,
    available_parallelism, current, panicking, park, park_timeout, sleep, yield_now,
};

#[cfg(feature = "shim")]
pub use std::thread::Result;

#[cfg(feature = "shim")]
mod shimmed {
    use std::io;

    /// Spawn a new thread that auto-registers itself as a child of the calling
    /// thread (via [`register_thread_child_of`](crate::register_thread_child_of))
    /// before running `f`. Otherwise identical to [`std::thread::spawn`].
    pub fn spawn<F, T>(f: F) -> std::thread::JoinHandle<T>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        let parent = std::thread::current().id();
        std::thread::spawn(move || {
            crate::register_thread_child_of(parent);
            f()
        })
    }

    /// Drop-in wrapper around [`std::thread::Builder`] whose [`spawn`](Self::spawn)
    /// method auto-registers the spawned thread as a child of the calling thread
    /// before running `f`.
    pub struct Builder {
        inner: std::thread::Builder,
    }

    impl Builder {
        /// Equivalent to [`std::thread::Builder::new`].
        pub fn new() -> Self {
            Self {
                inner: std::thread::Builder::new(),
            }
        }

        /// Equivalent to [`std::thread::Builder::name`].
        pub fn name(mut self, name: String) -> Self {
            self.inner = self.inner.name(name);
            self
        }

        /// Equivalent to [`std::thread::Builder::stack_size`].
        pub fn stack_size(mut self, size: usize) -> Self {
            self.inner = self.inner.stack_size(size);
            self
        }

        /// Spawn the thread, auto-registering it as a child of the calling
        /// thread before `f` runs. Same return type as
        /// [`std::thread::Builder::spawn`].
        pub fn spawn<F, T>(self, f: F) -> io::Result<std::thread::JoinHandle<T>>
        where
            F: FnOnce() -> T + Send + 'static,
            T: Send + 'static,
        {
            let parent = std::thread::current().id();
            self.inner.spawn(move || {
                crate::register_thread_child_of(parent);
                f()
            })
        }

        /// Spawn the thread inside `scope`, auto-registering it as a child of
        /// the calling thread before `f` runs. Same return type as
        /// [`std::thread::Builder::spawn_scoped`].
        pub fn spawn_scoped<'scope, 'env, F, T>(
            self,
            scope: &'scope std::thread::Scope<'scope, 'env>,
            f: F,
        ) -> io::Result<std::thread::ScopedJoinHandle<'scope, T>>
        where
            F: FnOnce() -> T + Send + 'scope,
            T: Send + 'scope,
        {
            let parent = std::thread::current().id();
            self.inner.spawn_scoped(scope, move || {
                crate::register_thread_child_of(parent);
                f()
            })
        }
    }

    impl Default for Builder {
        fn default() -> Self {
            Self::new()
        }
    }
}

#[cfg(feature = "shim")]
pub use shimmed::{Builder, spawn};

// `std::thread::scope` is re-exported as-is. Wrapping it would force callers
// to thread an extra lifetime through every closure body (the wrapper would
// have to live for the full `'scope`, but it can only be created inside the
// scope-closure body — outliving its own borrow). Since scoped threads are
// borrowed-data-only and rarely used in tests, callers should attach them
// manually with `t.thread().id().register_as_child()` after `s.spawn(...)`.
#[cfg(feature = "shim")]
pub use std::thread::scope;
