use std::cell::{Cell, RefCell};
use std::future::Future;
use std::pin::pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use parking::Parker;

use crate::reactor::Reactor;

/// The main loop for the "async-io" thread, until its reactor's sim ends.
pub(crate) fn main_loop(reactor: Arc<Reactor>, parker: parking::Parker) {
    let _exited = CallOnDrop(|| reactor.driver_exited());

    #[cfg(feature = "tracing")]
    let span = tracing::trace_span!("async_io::main_loop");
    #[cfg(feature = "tracing")]
    let _enter = span.enter();

    // The last observed reactor tick.
    let mut last_tick = 0;
    // Number of sleeps since this thread has called `react()`.
    let mut sleeps = 0u64;

    loop {
        if reactor.is_shut_down() {
            return;
        }

        let tick = reactor.ticker();

        if last_tick == tick {
            let reactor_lock = if sleeps >= 10 {
                // If no new ticks have occurred for a while, stop sleeping and spinning in
                // this loop and just block on the reactor lock.
                Some(reactor.lock())
            } else {
                reactor.try_lock()
            };

            if let Some(mut reactor_lock) = reactor_lock {
                if reactor.is_shut_down() {
                    return;
                }

                #[cfg(feature = "tracing")]
                tracing::trace!("waiting on I/O");
                reactor_lock.react(None).ok();
                last_tick = reactor.ticker();
                sleeps = 0;
            }
        } else {
            last_tick = tick;
        }

        if reactor.block_on_count.load(Ordering::SeqCst) > 0 {
            // Exponential backoff from 50us to 10ms.
            let delay_us = [50, 75, 100, 250, 500, 750, 1000, 2500, 5000]
                .get(sleeps as usize)
                .unwrap_or(&10_000);

            #[cfg(feature = "tracing")]
            tracing::trace!("sleeping for {} us", delay_us);
            if parker.park_timeout(Duration::from_micros(*delay_us)) {
                #[cfg(feature = "tracing")]
                tracing::trace!("notified");

                // If notified before timeout, reset the last tick and the sleep counter.
                last_tick = reactor.ticker();
                sleeps = 0;
            } else {
                sleeps += 1;
            }
        }
    }
}

/// Blocks the current thread on a future, processing I/O events when idle.
///
/// # Examples
///
/// ```
/// use async_io::Timer;
/// use std::time::Duration;
///
/// async_io::block_on(async {
///     // This timer will likely be processed by the current
///     // thread rather than the fallback "async-io" thread.
///     Timer::after(Duration::from_millis(1)).await;
/// });
/// ```
pub fn block_on<T>(future: impl Future<Output = T>) -> T {
    #[cfg(feature = "tracing")]
    let span = tracing::trace_span!("async_io::block_on");
    #[cfg(feature = "tracing")]
    let _enter = span.enter();

    let reactor = Reactor::get();

    // Increment the block-on count so that the "async-io" thread becomes less aggressive.
    reactor.block_on_count.fetch_add(1, Ordering::SeqCst);

    // Make sure to decrement the block-on count at the end and wake the "async-io" thread.
    let _guard = CallOnDrop(|| {
        reactor.block_on_count.fetch_sub(1, Ordering::SeqCst);
        reactor.unparker().unpark();
    });

    // Creates a parker and an associated waker that unparks it.
    fn parker_and_waker(reactor: Arc<Reactor>) -> (Parker, Waker, Arc<AtomicBool>, Arc<Reactor>) {
        // Parker and unparker for notifying the current thread.
        let (p, u) = parking::pair();

        // This boolean is set to `true` when the current thread is blocked on I/O.
        let io_blocked = Arc::new(AtomicBool::new(false));

        // Prepare the waker.
        let waker = BlockOnWaker::create(io_blocked.clone(), u, reactor.clone());

        (p, waker, io_blocked, reactor)
    }

    type Cached = Option<(Parker, Waker, Arc<AtomicBool>, Arc<Reactor>)>;

    thread_local! {
        // Cached parker and waker for efficiency, rebuilt when the thread's reactor changes.
        static CACHE: RefCell<Cached> = const { RefCell::new(None) };

        // Indicates that the current thread is polling I/O, but not necessarily blocked on it.
        static IO_POLLING: Cell<bool> = const { Cell::new(false) };
    }

    struct BlockOnWaker {
        io_blocked: Arc<AtomicBool>,
        unparker: parking::Unparker,
        reactor: Arc<Reactor>,
    }

    impl BlockOnWaker {
        fn create(
            io_blocked: Arc<AtomicBool>,
            unparker: parking::Unparker,
            reactor: Arc<Reactor>,
        ) -> Waker {
            Waker::from(Arc::new(BlockOnWaker {
                io_blocked,
                unparker,
                reactor,
            }))
        }
    }

    impl std::task::Wake for BlockOnWaker {
        fn wake_by_ref(self: &Arc<Self>) {
            if self.unparker.unpark() {
                // Check if waking from another thread and if currently blocked on I/O.
                if !IO_POLLING.with(Cell::get) && self.io_blocked.load(Ordering::SeqCst) {
                    self.reactor.notify();
                }
            }
        }

        fn wake(self: Arc<Self>) {
            self.wake_by_ref()
        }
    }

    CACHE.with(|cache| {
        // Try grabbing the cached parker and waker.
        let tmp_cached;
        let tmp_fresh;
        let (p, waker, io_blocked, _) = match cache.try_borrow_mut() {
            Ok(mut cache) => {
                // Use the cached parker and waker.
                if !matches!(&*cache, Some((.., cached)) if Arc::ptr_eq(cached, &reactor)) {
                    *cache = Some(parker_and_waker(reactor.clone()));
                }
                tmp_cached = cache;
                tmp_cached.as_ref().unwrap()
            }
            Err(_) => {
                // Looks like this is a recursive `block_on()` call.
                // Create a fresh parker and waker.
                tmp_fresh = parker_and_waker(reactor.clone());
                &tmp_fresh
            }
        };

        let mut future = pin!(future);

        let cx = &mut Context::from_waker(waker);

        loop {
            // Poll the future.
            if let Poll::Ready(t) = future.as_mut().poll(cx) {
                // Ensure the cached parker is reset to the unnotified state for future block_on calls,
                // in case this future called wake and then immediately returned Poll::Ready.
                p.park_timeout(Duration::from_secs(0));
                #[cfg(feature = "tracing")]
                tracing::trace!("completed");
                return t;
            }

            // Check if a notification was received.
            if p.park_timeout(Duration::from_secs(0)) {
                #[cfg(feature = "tracing")]
                tracing::trace!("notified");

                // Try grabbing a lock on the reactor to process I/O events.
                if let Some(mut reactor_lock) = reactor.try_lock() {
                    // First let wakers know this parker is processing I/O events.
                    IO_POLLING.with(|io| io.set(true));
                    let _guard = CallOnDrop(|| {
                        IO_POLLING.with(|io| io.set(false));
                    });

                    // Process available I/O events.
                    reactor_lock.react(Some(Duration::from_secs(0))).ok();
                }
                continue;
            }

            // Try grabbing a lock on the reactor to wait on I/O.
            if let Some(mut reactor_lock) = reactor.try_lock() {
                // Record the instant at which the lock was grabbed.
                let start = Instant::now();

                loop {
                    // First let wakers know this parker is blocked on I/O.
                    IO_POLLING.with(|io| io.set(true));
                    io_blocked.store(true, Ordering::SeqCst);
                    let _guard = CallOnDrop(|| {
                        IO_POLLING.with(|io| io.set(false));
                        io_blocked.store(false, Ordering::SeqCst);
                    });

                    // Check if a notification has been received before `io_blocked` was updated
                    // because in that case the reactor won't receive a wakeup.
                    if p.park_timeout(Duration::from_secs(0)) {
                        #[cfg(feature = "tracing")]
                        tracing::trace!("notified");
                        break;
                    }

                    // Wait for I/O events.
                    #[cfg(feature = "tracing")]
                    tracing::trace!("waiting on I/O");
                    reactor_lock.react(None).ok();

                    // Check if a notification has been received.
                    if p.park_timeout(Duration::from_secs(0)) {
                        #[cfg(feature = "tracing")]
                        tracing::trace!("notified");
                        break;
                    }

                    // Check if this thread been handling I/O events for a long time.
                    if start.elapsed() > Duration::from_micros(500) {
                        #[cfg(feature = "tracing")]
                        tracing::trace!("stops hogging the reactor");

                        // This thread is clearly processing I/O events for some other threads
                        // because it didn't get a notification yet. It's best to stop hogging the
                        // reactor and give other threads a chance to process I/O events for
                        // themselves.
                        drop(reactor_lock);

                        // Unpark the "async-io" thread in case no other thread is ready to start
                        // processing I/O events. This way we prevent a potential latency spike.
                        reactor.unparker().unpark();

                        // Wait for a notification.
                        p.park();
                        break;
                    }
                }
            } else {
                // Wait for an actual notification.
                #[cfg(feature = "tracing")]
                tracing::trace!("sleep until notification");
                p.park();
            }
        }
    })
}

/// Runs a closure when dropped.
struct CallOnDrop<F: Fn()>(F);

impl<F: Fn()> Drop for CallOnDrop<F> {
    fn drop(&mut self) {
        (self.0)();
    }
}
