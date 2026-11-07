# Determinism, threads and the sim lifecycle

## Determinism and quiescence

Time is virtual, so a test that "waits a second" finishes instantly and every run sees the same
sim times (and the same absolute timestamps under `deterministic()` or `fixed_epoch()`); randomness
is seeded (`SimBuilder::seed`), per thread, so `HashMap` order, random ids and link faults replay
(std draws a thread's hash keys once, at its first `HashMap`, so a thread that made one before its
sim keeps the keys it drew then; see [OPEN_BUGS.md](../OPEN_BUGS.md)). When every thread is blocked with no timer left to fire, the run is deadlocked and
the blocked simulated wait gives up (`EAGAIN`) rather than hanging the test. A thread blocked on a
word in static data (Linux futex, Windows `WaitOnAddress`; std's stdout and stderr locks, a
`static` mutex) is the exception: a thread outside the sim, such as another test's, may hold it, so
the run waits in real time for it to be let go instead of reading as deadlocked.
Timers due at one instant all fire there: a time skip lands just past the earliest deadline (1 ns;
on Windows 100 ns, or one `QueryPerformanceCounter` tick where that is longer, so `Instant` reads
past it), and the
next skip waits until every timed wait it reached has returned, so a park, condvar or channel timeout —
which notices its deadline only between real-time slices of at most 2 ms — wakes at its deadline even
when a sleeper on another thread is due at the same instant and would otherwise skip straight on.
Likewise a thread woken from a native wait — a futex, condition variable or semaphore wake, or the
exit of the thread it joins — holds off every time skip until it has run.
A thread blocked on a lock that no thread of its sim holds — one held by another test running in
parallel, an unmanaged thread, or std's own process-wide locks such as the one every thread start
and exit takes — waits on the world outside, not on the sim, so it holds off time skips too until
it gets the lock. The pthread mutex hooks record which mutexes each of a sim's threads holds, so a
contended pthread mutex (std's `Mutex` on macOS) is judged exactly; a futex word names no holder, so
on Linux a lock wait on a word in static data (std's own statics) first waits up to 1 ms of real
time uncounted, which an outside holder in a short critical section lets go within, and a lock in
heap memory held outside the sim is still counted as a wait in it.

Thread *interleaving* is deterministic too with `Sim::builder().deterministic()`: one thread runs at a
time, and control passes only where a thread waits — a socket, sleep, mutex, condition variable,
channel, park, join or yield — to the next thread in a fixed order. Those waits are emulated rather than
handed to the kernel, so the waker always moves its waiters to the run queue itself and nothing is woken
behind the scheduler's back; locks shared with threads outside the simulation (another test running in
parallel) are waited out without letting their timing reorder this one, for up to 50 ms of real time
each, after which the waiter passes the baton on and waits in the schedule for the holder's unlock (a
pool's worker left over from an earlier sim may hold its queue's lock for as long as it waits for its
next job). A wake made from outside the schedule (another sim's thread, a thread no sim manages) on
a condition variable, futex, semaphore or address a participant waits on reaches it in the schedule,
however busy the schedule keeps itself. With the same seed, a run replays exactly. What it cannot see it cannot order: a thread spinning on an atomic without ever
yielding keeps the baton, and a call that blocks in the OS outside snare's hooks blocks every thread.
A yield with no other thread able to run time-skips to the next pending timer, as a free-running
yield does once every other thread is parked, so a yield loop waiting on a sleeper (crossbeam's
`Backoff::snooze`, rayon's idle workers) gets there.

The sim's own code often runs on a participant from inside its hooked wait — the deterministic
schedule's dispatch and the time skips in it, or an idle skip as a native wait begins — where std may
already have parked the thread on its thread parker. std's parker tracks one park at a time, so a std
wait there that parks the same thread again (a channel; on macOS also a contended `OnceLock`, `Once`
or `RwLock`) would leave neither park able to be woken. snare's own process-wide singletons therefore
never wait to be initialised, and the parker's blocking calls (`dispatch_semaphore_wait`, Linux
`futex`, `WaitOnAddress`) treat a wait nested in another on the same object as a 1 ms real-time
slice that returns as a spurious wakeup, and wake the outer park to re-check, so a layer that blocks
in std there still makes progress.

### Clock spins

Reading the clock never moves a discrete clock, so a thread waiting on time by polling it —
`while Instant::now() < deadline {}`, with or without `yield_now`, spin_sleep's final spin, a loop
that checks an unhooked channel between reads — would wait forever. snare catches such a *clock
spin* and moves time for it:

- A participant's clock reads and `sched_yield`/`SwitchToThread` calls count toward a spin; any other
  hooked call (a socket call, a sleep, a wait, a thread spawn, a lock that contends, a signal) ends
  it — a wait as it begins, whether it then blocks or finds what it waits for already there, while
  one whose timeout is zero or already past is a poll and leaves the spin running — and so does each
  of the sim's own waits, such as a tester waiting for its next message or tick:
  the clock reads of a tester's loop and handlers never add up to a spin. After 64 in a row the spin is caught: isolated reads, a few back-to-back reads, or reads with
  other hooked calls between them never get there and keep holding still. A loop polling a socket
  is not a clock spin: each non-blocking call is charged its microsecond instead.
- Work the sim cannot see — computing, uncontended locks and atomics, allocation — can read the
  clock 64 times in a row too: an `Instant::now()` per item of a loop, a cache stamping each
  insert, an allocator reading its decay clock every so often. That is caught as a spin as well,
  so a spin's first steps cost what calls that do not block cost: each of its first 65,536 reads
  moves time 1 µs (a loop of 10,000 timestamped items takes 10 ms of virtual time, and 20,000
  allocations under jemalloc about 18 ms). A spin that yields between its reads is waiting
  outright and skips this stretch.
- After those, each read moves time 1/64 of the virtual time since the spin was caught, up to one
  second. The steps grow geometrically, so a spin on a deadline a second or an hour away takes
  about 66,000 or 70,000 reads (about 1,000 or 4,500 when it yields between them), a fraction of a second of real time, and a spin overshoots its own
  deadline by at most 1/64 of its length or 1 µs (one more read before any other hooked call
  moves it one more step). A step never jumps a pending timer: one that would reach the earliest
  timer lands 1 ns short of it, so a spinner whose deadline comes first sees it first, and the
  next lands just past it, as a time skip does, waking its waiter.
- Time moves only while every other participant is parked or spinning itself, no woken waiter has
  yet to run and no lease is held, so other threads' work at the current instant comes first and
  timers fire in order. A free-running spin waits for a waiter its step reached to take its
  deadline (up to 5 ms of real time) before stepping on. Under `deterministic()` each step is a
  scheduling point: the spinner hands the baton to any runnable thread that is not spinning, and
  after a step lets the threads it released run before the next. Runs replay exactly.
- A yield loop that does not read the clock waits on another thread, not on a deadline of its own,
  and keeps the full time skip to the next timer; it gets none while a clock spinner is about,
  since that would jump past the spinner's deadline. A thread that read the clock since its last
  yield is polling, and its yields only hand others a turn.
- A paused clock, or one an executive drives, is never moved by a spin: the spinner keeps reading
  the held instant, yielding the CPU, until something outside the sim moves or resumes the clock;
  `stuck_after` reports it. A spin that moves time is progress to the watchdog. A scaled or
  as-fast-as-possible clock moves on its own and a `wall_clock()` sim reads real time, so neither is
  touched. Only participants' spins count; a background or driver thread spinning on the clock is
  left alone.

## Thread classes and leases

Every thread created inside `Sim::run` is simulated — its sockets, clock, files and environment are
the sim's — and by default it is a *participant*: time skips only once every participant is blocked, a
blocked wait gives up only when they all are, and `deterministic()` runs participants one at a time. A
thread the run should not wait on changes its class with `snare::sched`:

| Class | Set with | Effect |
|---|---|---|
| `Participant` | the default; `participate(name)` for a scope | Counts toward quiescence and runs in the deterministic schedule. |
| `Background` / `Helper` | `mark_background(label)` / `mark_helper()` | Still simulated, but never holds up quiescence or the schedule. Its sleeps and timeouts are satisfied as the clock passes them rather than steering a time skip, and its non-blocking calls cost no time. |
| `Driver` | `mark_driver_thread()` | As `Background`, and its clock reads, sleeps and timeouts (socket, poll and condition-variable timeouts alike) are real; `sched::now()` reads the sim's clock. |

`spawn_as(class, label)` makes the threads the caller creates while the guard lives start in `class`
(for a pool or library that spawns its own threads); later children, and a background thread's own
children, are participants again. Sim waits (a receive, a poll, an accept) still give up when every
participant is blocked with no participant timer left, however many background timers are pending.
Once no participant can give up — each is in a join, a lock, a condition variable or a channel
receive, waiting on what only a background thread can do, as when the test stops a sampler and joins
it — time skips to the background threads' timers instead, so the join returns. Under
`deterministic()` a thread that leaves the schedule (`mark_background` on a running participant, or a
`participate` guard dropping) hands the baton on as it goes, and a thread of another class runs
beside the schedule: whatever it wakes — a channel send, a condvar signal, a socket write — still
reaches the schedule, but when it runs relative to the participants depends on the OS, so its effects
on them only replay if they wait for it. The same holds for a background thread entering the schedule
through `participate`: the point where it joins depends on real time, so the run replays only if the
participants wait for it there (for a message it sends from inside the guard, say).

`busy(label)` (`Send`; also `Sim::busy`) and `setup_scope(label)` are leases: while one is held the sim
is never quiescent, so time does not skip and no blocked wait gives up, even on the discrete clock; a
deterministic schedule idles until the lease is dropped. Taking one waits out a time skip already in
flight, so from any thread, inside the sim or not, no skip lands once `busy` returns. A lease has a
kind: `busy` takes a `LeaseKind::Busy` one, for work the sim cannot see that lasts about as long as a
reaction, and `setup_scope` a `LeaseKind::Setup` one, which may last as long as setup takes without
anything being stuck. `held_leases()` lists them as `LeaseInfo { label, kind, holder }`, the holder
being the name of the thread that took it. Off a sim both return an inert lease (`is_held()` is
`false`) rather than panicking, so code shared with a real deployment can take them unconditionally;
`sched::in_sim()` says whether the calling thread runs in a sim at all, and `sched::current_sim()`
which one (a `SimId`, also `Sim::id`). A thread's name is whatever it set through `pthread_setname_np` or
`SetThreadDescription` (std's `Builder::name`), which go to the OS unchanged — a Linux name over 15
bytes still fails with `ERANGE` — or `thread-<lineage>` otherwise.

### Stuck runs

A participant that runs without making a hooked call — spinning on an atomic, or computing — keeps
the sim from going quiescent, so the discrete clock cannot move and every sleeper it may be waiting
for waits for good: the test hangs. `SimBuilder::stuck_after(d)` (off by default) turns that into a
failure. A watchdog thread outside the sim samples it every eighth of `d` (between 1 ms and 250 ms)
and fires once, for `d` of real time, a participant has been running while none of the sim's
progress has happened: no participant blocked or woke, no lease was taken or given back, virtual
time did not move (a time skip, a clock write, a scaled or granted clock flowing, the microsecond
each non-blocking call is charged, a [clock spin](#clock-spins)'s step), and under `deterministic()` no participant began a wait in the
schedule, and the participants running have used `d` of CPU time meanwhile, so one the OS has not
let run on a loaded machine is not taken for a spin. One blocked in a call snare does not hook (a
real pipe made outside the sim that nobody writes, a `pthread_rwlock_t` held for good) uses no CPU time either, and fails the run once it has
gone ten times `d`, and at least 5 s, of real time without progress. It never fires while every participant is blocked — on a paused clock, on an executive, on
locks only a thread outside the sim can release — since the design waits for those, nor while a
lease is held or an executive's timestamp is open, nor on a `wall_clock()` sim, whose time moves on
its own. A participant that legitimately runs longer than
`d` with no hooked call (a long computation, work inside `real`) holds `busy()` across it. Off by default because that work looks exactly like a spin.

A stuck thread cannot be made to panic from outside, and the test would never finish, so the
watchdog attempts its report on the process's stderr — past the test harness's output capture —
with a 2 s reporting budget, then aborts the test process. Locked or blocked stderr may leave
the report incomplete, and OS scheduling may delay detection and termination. The report names
every participant: running (and, under `deterministic()`, which one holds the baton), or what it
waits in and until when, what it last
waited in, and the leases it holds.

The same listing explains a deterministic schedule that has idled for a second with every
participant blocked — on a held clock, on a lease, or on locks only something outside the sim can
release: that is waiting rather than stuck, so it is a one-time warning on stderr and the schedule
carries on.

## Sim lifecycle

A `Sim` is *running* while at least one thread is inside `Sim::run`, and *dormant* between runs and
after it is dropped. Threads spawned inside a run that are still alive when it returns — a
background loop the test never stopped, a pool's idle workers — stay in the sim: their clock,
sockets and files are still its own, and the sim's state lives as long as any of them does, even
past the `Sim`'s drop. But nothing waits on them any more, so while the sim is dormant:

- **Time moves for them at real time's pace.** A time skip lands no further past the reading the
  run ended at than real time has moved since, so a leftover thread sleeping in a loop sleeps in
  real time (a near-idle CPU) instead of racing the virtual clock ahead at full speed. An
  as-fast-as-possible clock holds still between such skips too. With no leftover thread waiting on
  a timer the clock does not move at all, so a sim without leftovers starts its next run where the
  last one ended. A paused clock, or one an executive still drives, stays held.
- **A wait with nothing left to wait for blocks** instead of giving up as a deadlock: a receive no
  thread will ever answer stays blocked (polling a few times a second) rather than failing with
  `EAGAIN`, so a leftover loop that retries on errors does not spin.
- **They no longer count anywhere else**: not toward another sim's quiescence (each sim's woken
  waiters are its own, however many sims run in parallel), not toward the `stuck_after` watchdog
  (a leftover thread spinning on an atomic is the test's own business once the run has ended), and
  a deterministic schedule has already let them go to run freely.
- **They can still be stopped and joined from outside**: set the flag they poll and join them;
  their sleeps end in real time.

The next `Sim::run` on the same sim takes its leftovers back: they are its participants again, and
time skips go back to virtual time at once (monotonic time never goes backwards across the switch).
A test that wants none of this stops its threads before the run returns.

**Process-wide pools.** A pool kept in a static — rayon's global registry, a `LazyLock` of a
`futures` `ThreadPool`, a `threadpool`, a static tokio runtime's workers and blocking pool — starts
its threads under whichever sim touches it first, and they park on condition variables, futexes and
semaphores between jobs. A later sim that hands one of them work wakes it, and the work is that
sim's: a participant of a dormant sim woken by a thread of a sim whose run is in progress follows
the waker into its sim, as a thread it had spawned, before it runs another line. It runs on the
later sim's clock, in its schedule, and counts toward its quiescence, so time does not skip while it
computes for it. Its place there is made ready at the wake, before the OS wakes it, and counted
live, so the later sim cannot read as quiescent in between; a wake the OS may give to any of several
waiters (`notify_one` on a shared queue) makes as many places as it can wake, each for whichever
dormant waiter returns first. A place nobody takes within 200 ms of real time — the OS woke a
thread the census never saw — is given back. Under `deterministic()` the place joins the schedule
where the wake was made, as a spawn does, so runs replay. To leave no worker still spinning
between jobs (rayon's yield 32 times before they park), a run's end waits, a bounded real time,
until its leftover participants have all come to rest in a wait. An attached
[`Executive`](time-and-executive.md#controlling-time) counts as a run in progress until it is dropped: a harness that
drives the sim from outside enters it only to spawn its threads, and the sim is live all the same.
Threads of a sim whose run is in progress never move, nor do background, helper or driver threads;
a pool two sims share while both are running still serves both from one world (see
`OPEN_BUGS.md`), which the parallel-only shims lift for the pools they cover.

**A new sim continues the process's time.** Each plain sim's clocks start where the furthest
clock of every sim built before it had got to (see [Controlling time](time-and-executive.md#controlling-time)), so a
process static that remembers a timestamp from an earlier sim — a static tokio runtime's timer
wheel, a global memo or DNS cache — still sees its deadlines ahead and its entries age. A
`deterministic()` or `fixed_epoch()` sim starts at the fixed epoch instead, where such a static
stays stale: a cache entry from a sim that ran further may never expire in it.

**Process-wide reactors.** An epoll set, a kqueue, an eventfd or a timerfd belongs to the process,
not to a network, and a library may create one once per process: async-io keeps its poller and
the "async-io" thread that waits on it in statics, made under whichever sim touches it first.
When a running sim reaches such a descriptor of a dormant (or dropped) sim, it takes over every
one that sim holds, and the leftover threads blocked on them join it, as threads it had spawned:
they run on its clock, in its schedule, and count toward its quiescence. A timerfd keeps the time
it had left. One closed outside every sim is gone, and its number is the OS's to reuse for a real
file. Network sockets never move: a world has no instance of another world's connection, so
another sim's socket (or one gone with its sim) is a connection that is gone there, as a
connection pool kept in a static (ureq's agent, reqwest's client) must find it: its first read or
write reports `ECONNRESET`, later reads end of stream and later writes `EPIPE`, `poll`, epoll and
kqueue show the hang-up and the error, and `getpeername` is `ENOTCONN`. A registration of such a
socket in an epoll set or kqueue that moves to another sim stays, and reports the same. Closing it,
from any sim or from a thread outside every sim, closes it in the sim that made it, whose peer
sees the connection end, and gives its number back to the OS, so std's I/O-safety check never
sees a close fail. A `socketpair` end has no network in it either, but it carries bytes, so
instead of moving it is mirrored: each sim that reaches one another sim made (tokio keeps its
signal self-pipe in a static and every runtime with I/O dups it) gets an instance of the pair of
its own under the same numbers, both ends open, and bytes written in one world are never read in
another. Its numbers are the ends of a real socketpair, the outside world's instance, so a thread
outside every sim (a runtime built after the sims) uses a working pair. Every other descriptor of
a sim's network (a socket, an epoll set, a kqueue, an eventfd, a timerfd) is a `dup` of a
placeholder that fails loudly when a call no hook serves reaches it: the read end of a pipe whose
writer has gone, so a write fails with `EBADF` and a read is at end of file. A
wake of another running sim's reactor (an eventfd write, a kqueue `EVFILT_USER`
trigger) is delivered to it as a wake from outside its world. Two sims running at the same time
cannot otherwise share one such object: a sim that
reaches a descriptor another running sim holds waits until that run ends, but one that only
touches the library's memory (a timer queued while the reactor's notifier is already pending)
gives snare nothing to wait at, so tests that share a process-wide reactor must take turns (a
static `Mutex` held across the test, or `--test-threads=1`). `cargo snare test --parallel
<smol|async-std|rayon|futures-timer|all>` patches in shims that give each sim its own reactor,
executor, thread pool and timer thread and lift this for async-io, smol, async-std, rayon's global
pool and futures-timer (see [Shims](harness.md#shims-shims)).
