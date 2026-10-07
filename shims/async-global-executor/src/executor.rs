use crate::Task;
use async_executor::{Executor, LocalExecutor};
use async_channel::{Receiver, Sender};
use async_lock::Mutex;
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

/// An executor shared by the threads of one pool, and the pool's bookkeeping.
pub(crate) struct Pool {
    pub(crate) executor: Executor<'static>,
    /// The current number of threads (some might be shutting down and not in the pool anymore).
    pub(crate) threads_number: Mutex<usize>,
    /// The expected number of threads (excluding the ones that are shutting down).
    pub(crate) expected_threads_number: Mutex<usize>,
    started: AtomicBool,
    /// Closed when the sim that owns the pool ends; its threads then exit.
    closing: (Sender<()>, Receiver<()>),
}

/// A sim's pool, as kept in the sim; dropped as the sim ends.
struct SimPool(Arc<Pool>);

impl Drop for SimPool {
    fn drop(&mut self) {
        self.0.closing.0.close();
    }
}

impl Pool {
    /// The calling thread's pool: under a snare sim, the sim's own, kept as a
    /// [`snare_interpose::sim_local`] and shut down with the sim; elsewhere the process-wide one.
    pub(crate) fn get() -> Arc<Pool> {
        static GLOBAL: OnceLock<Arc<Pool>> = OnceLock::new();
        match snare_interpose::sim_local(|| SimPool(Arc::new(Pool::new()))) {
            Some(local) => local.0.clone(),
            None => GLOBAL.get_or_init(|| Arc::new(Pool::new())).clone(),
        }
    }

    fn new() -> Pool {
        Pool {
            executor: Executor::new(),
            threads_number: Mutex::new(0),
            expected_threads_number: Mutex::new(0),
            started: AtomicBool::new(false),
            closing: async_channel::bounded(1),
        }
    }

    /// Whether this call is the first to start the pool's threads.
    pub(crate) fn start(&self) -> bool {
        !self.started.swap(true, Ordering::SeqCst)
    }

    /// Completes once the pool's sim has ended.
    pub(crate) fn closed(&self) -> impl Future<Output = ()> + 'static {
        let closing = self.closing.1.clone();
        async move {
            let _ = closing.recv().await;
        }
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.closing.0.is_closed()
    }
}

thread_local! {
    pub(crate) static LOCAL_EXECUTOR: LocalExecutor<'static> = const { LocalExecutor::new() };
}

/// Runs the global and the local executor on the current thread
///
/// Note: this calls `async_io::block_on` underneath.
///
/// # Examples
///
/// ```
/// let task = async_global_executor::spawn(async {
///     1 + 2
/// });
/// async_global_executor::block_on(async {
///     assert_eq!(task.await, 3);
/// });
/// ```
pub fn block_on<F: Future<Output = T>, T>(future: F) -> T {
    LOCAL_EXECUTOR.with(|executor| crate::reactor::block_on(executor.run(future)))
}

/// Spawns a task onto the multi-threaded global executor.
///
/// # Examples
///
/// ```
/// # use futures_lite::future;
///
/// let task1 = async_global_executor::spawn(async {
///     1 + 2
/// });
/// let task2 = async_global_executor::spawn(async {
///     3 + 4
/// });
/// let task = future::zip(task1, task2);
///
/// async_global_executor::block_on(async {
///     assert_eq!(task.await, (3, 7));
/// });
/// ```
pub fn spawn<F: Future<Output = T> + Send + 'static, T: Send + 'static>(future: F) -> Task<T> {
    crate::init();
    Pool::get().executor.spawn(future)
}

/// Spawns a task onto the local executor.
///
///
/// The task does not need to be `Send` as it will be spawned on the same thread.
///
/// # Examples
///
/// ```
/// # use futures_lite::future;
///
/// let task1 = async_global_executor::spawn_local(async {
///     1 + 2
/// });
/// let task2 = async_global_executor::spawn_local(async {
///     3 + 4
/// });
/// let task = future::zip(task1, task2);
///
/// async_global_executor::block_on(async {
///     assert_eq!(task.await, (3, 7));
/// });
/// ```
pub fn spawn_local<F: Future<Output = T> + 'static, T: 'static>(future: F) -> Task<T> {
    LOCAL_EXECUTOR.with(|executor| executor.spawn(future))
}

/// Runs blocking code on a thread pool.
///
/// # Examples
///
/// Read the contents of a file:
///
/// ```no_run
/// # async_global_executor::block_on(async {
/// let contents = async_global_executor::spawn_blocking(|| std::fs::read_to_string("file.txt")).await?;
/// # std::io::Result::Ok(()) });
/// ```
///
/// Spawn a process:
///
/// ```no_run
/// use std::process::Command;
///
/// # async_global_executor::block_on(async {
/// let out = async_global_executor::spawn_blocking(|| Command::new("dir").output()).await?;
/// # std::io::Result::Ok(()) });
/// ```
pub fn spawn_blocking<F: FnOnce() -> T + Send + 'static, T: Send + 'static>(f: F) -> Task<T> {
    blocking::unblock(f)
}
