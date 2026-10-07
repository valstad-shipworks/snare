use std::future::Future;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;
use std::thread;

use async_executor::{Executor, Task};
use async_io::block_on;
use async_lock::OnceCell;
use futures_lite::future;

/// Spawns a task onto the global executor (single-threaded by default).
///
/// There is a global executor that gets lazily initialized on first use. It is included in this
/// library for convenience when writing unit tests and small programs, but it is otherwise
/// more advisable to create your own [`Executor`].
///
/// By default, the global executor is run by a single background thread, but you can also
/// configure the number of threads by setting the `SMOL_THREADS` environment variable.
///
/// Since the executor is kept around forever, `drop` is not called for tasks when the program
/// exits.
///
/// Under a snare sim the global executor and its threads are the sim's own, kept as a
/// [`snare_interpose::sim_local`]: its threads exit and its unfinished tasks are dropped when the
/// sim ends.
///
/// # Examples
///
/// ```
/// let task = smol::spawn(async {
///     1 + 2
/// });
///
/// smol::block_on(async {
///     assert_eq!(task.await, 3);
/// });
/// ```
pub fn spawn<T: Send + 'static>(future: impl Future<Output = T> + Send + 'static) -> Task<T> {
    static GLOBAL: OnceCell<Executor<'_>> = OnceCell::new();

    fn global() -> &'static Executor<'static> {
        GLOBAL.get_or_init_blocking(|| {
            let num_threads = {
                // Parse SMOL_THREADS or default to 1.
                std::env::var("SMOL_THREADS")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(1)
            };

            for n in 1..=num_threads {
                thread::Builder::new()
                    .name(format!("smol-{}", n))
                    .spawn(|| loop {
                        catch_unwind(|| block_on(global().run(future::pending::<()>()))).ok();
                    })
                    .expect("cannot spawn executor thread");
            }

            // Prevent spawning another thread by running the process driver on this thread.
            let ex = Executor::new();
            #[cfg(not(target_os = "espidf"))]
            ex.spawn(async_process::driver()).detach();
            ex
        })
    }

    match snare_interpose::sim_local(SimExecutor::start) {
        Some(local) => local.executor.spawn(future),
        None => global().spawn(future),
    }
}

/// A sim's global executor and the sender whose drop, as the sim ends, stops its threads.
struct SimExecutor {
    executor: Arc<Executor<'static>>,
    _stop: async_channel::Sender<()>,
}

impl SimExecutor {
    fn start() -> SimExecutor {
        let num_threads = std::env::var("SMOL_THREADS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1);
        let executor = Arc::new(Executor::new());
        let (stop, stopped) = async_channel::bounded::<()>(1);

        for n in 1..=num_threads {
            let executor = executor.clone();
            let stopped = stopped.clone();
            thread::Builder::new()
                .name(format!("smol-{}", n))
                .spawn(move || {
                    while catch_unwind(AssertUnwindSafe(|| block_on(executor.run(stopped.recv()))))
                        .is_err()
                    {}
                })
                .expect("cannot spawn executor thread");
        }

        // No `async_process::driver()` here: the child reaper it drives is process-wide, so one
        // sim's executor would carry it for every sim, and stall them all once that sim ends.
        // Without a driver, async-process reaps on a thread of its own.
        SimExecutor {
            executor,
            _stop: stop,
        }
    }
}
