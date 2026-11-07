# Time, the executive and cooperative primitives

## Controlling time

The clock every `Sim` runs on can be driven from the test, through `Sim` methods or a `TimeHandle`
(`sim.time()`, or `snare::time()` from any thread running inside the sim):

| Call | Effect |
|---|---|
| `set_time_rate(r)` / `SimBuilder::time_rate(r)` | `r` in (0, 1e6]: virtual time runs at `r` times real time (larger values clamp). `0.0` pauses. `f64::INFINITY` returns to virtual time — discrete-event, or as-fast-as-possible for a `SimHost` or Windows sim built with `wall_clock()` — keeping the reading. Negative or NaN panics. |
| `time_rate()` | `0.0` while paused, the rate while scaled, `f64::INFINITY` on virtual time. |
| `pause_time()` / `resume_time()` | Pausing holds the clock: reads return the same instant, and every sleep, socket timeout, poll timeout and condition-variable or futex timeout blocks until time moves, as `nanosleep(2)` and `Sleep` wait out their whole interval. Resuming restores the mode and rate in force before the pause. |
| `advance_time(d)` | Moves the clock forward by `d`, paused or not, waking what it reaches. |
| `set_time_value(v)` / `time_value()` | Sets sim time — how far the clock has moved since the sim was built — to `v`, `CLOCK_MONOTONIC` and the realtime clocks moving with it; forward only (setting it back panics and leaves the clock alone). `time_value()` reads without ticking. |

Monotonic time never goes backwards, whatever moves the clock: every monotonic source is
non-decreasing on each thread and across threads that synchronize, every mode switch re-anchors at
the last reading handed out, and a request to move the clock back is refused. Realtime moves with
monotonic time, a fixed boot time apart.

**Where a sim's clock starts.** A plain sim's clock continues the process's time:
`CLOCK_MONOTONIC` (and `CLOCK_BOOTTIME`, `Instant`, `mach_absolute_time`,
`QueryPerformanceCounter`, `GetTickCount64`) starts at the highest reading any sim's clock in the
process has handed out — every sim built before it, the ones still running included — plus at
least a second, on a whole second (sim time only: no real time passes), and `CLOCK_REALTIME` (`SystemTime`, `FILETIME`, `CLOCK_TAI` with it) no earlier
than the highest realtime reading. So a library that keeps a timestamp in a static — tokio's timer
wheel in a static runtime, a memo or cache expiry, a time-zone cache, a UUIDv7 counter, a coarse
clock's "recent" value — never sees time go backwards from one sim to the next. A sim already
running when another starts keeps its own timeline: only its readings up to then count. A
`deterministic()` sim, or one built with `SimBuilder::fixed_epoch()`, starts at the fixed epoch
instead: monotonic zero and realtime 2023-11-14T22:13:20Z (Unix time 1 700 000 000 s, a snare
choice), so a replay reads the same absolute values; a static timestamp from an earlier sim may
then be ahead of its clocks. Sim time — `time_value`, `set_time_value`, recorded events, the socket
table, an `Executive`'s times — counts from the clock's start either way, so it reads the same in
any order. Realtime minus monotonic, the sim's boot time, never changes within a sim. A
`SimHost`'s clock is placed once, by the first sim built on it, and later sims on the host
continue it. An `Instant` taken outside every sim, or in a `wall_clock()` sim, is on the real
timeline and may look ahead of one taken inside. A driver thread is the one exception by design:
it reads real time, and an executive's timestamp time while it acts at one.

A paused clock is moved by something outside the simulation — the test thread before or after `run`,
or a thread it starts under `snare::real` — so a sim where every thread waits on a paused clock is
waiting, not deadlocked; it says so on stderr after a second. Once resumed, a wait nothing can
satisfy gives up as before. On an as-fast-as-possible clock, a timed wait that is still held when
the clock resumes times out then, the clock jumping to its deadline as a sleep's does; one already
running when the clock is paused or scaled keeps the time it had left and holds with the clock. Under
`deterministic()` the clock can be paused, advanced and set; a write made while every simulated
thread is blocked on the paused clock releases the waiters in the schedule's fixed order, but one
made while a simulated thread runs lands wherever real time puts it in that thread's work, so the run
only replays if outside writes wait for the sim to block; an [Executive](#executive)'s `jump_to` and
`enter_timestamp_checked` act only while the schedule is idle, so they always do. A real-time rate is refused, since nothing
in a deterministic run may depend on real time. A plain unix `Sim` built with `wall_clock()` runs on the
real clock and has none of these controls; `time_rate(1.0)` gives a controllable clock that tracks
real time. With a `SimHost`, rate, value and pause apply to its timestamps, PHC samples and
`SO_TXTIME` alike. Scaled time follows real time, so it is not reproducible run to run.

On Windows, Rust sleep durations that exceed its signed 100 ns timer range reach the
simulated clock before conversion, including `std::thread::sleep(Duration::MAX)`. They
saturate at the clock's finite limit. Ordinary Rust sleeps retain the Windows timer grid;
native `Sleep(INFINITE)` and non-alertable `SleepEx(INFINITE)` still wait indefinitely.
This uses a typed hook on the linked Rust sleep implementation, following transparent entry
tail jumps. Entirely inlined implementations and separately linked std copies need their own
instrumentation. Hook installation errors are reported immediately.

## Executive

A simulation that drives the code under test from outside — sham inside theater — owns the sim's
clock through an `Executive`, in the same process: `sim.executive(ExecutiveConfig::default())` from any
thread, or `snare::sched::attach(cfg)` from a thread inside the run. Attaching fails with
`AlreadyAttached`, `NotInSim` (the free function off a sim's thread) or `WallClock` (a plain unix sim
on the real clock, which has no clock to own). From then until the executive drops, only it moves
time: there is no time skip on quiescence and no deadlock give-up — a wait nothing can satisfy waits
for the executive, and a deterministic schedule idles — and `pause_time`, `resume_time`,
`advance_time`, `set_time_rate`, `set_time_value` and their `TimeHandle` forms panic with "this
Sim's clock is owned by an Executive". The clock is frozen at its reading until the first grant.

| Call | Effect |
|---|---|
| `grant(Grant { anchor_v, anchor_wall, rate, horizon })` | Time runs from `anchor_v` at the real instant `anchor_wall`, `rate` virtual seconds per real second (in `[0, 1e6]`, NaN as 0), never past `horizon`. An anchor behind the clock anchors at the clock's reading, now. Timers the clock flows past fire as real time reaches them. |
| `freeze()` | Holds the clock where it is (horizon at the reading, rate 0). |
| `next_deadline()` | The earliest participant timer after the reading. Background timers are never jump targets; they fire as the clock passes them. |
| `jump_to(t)` | If the sim is quiescent — checked under the sim's locks in the same step as the move, so no participant starts running in between — moves the clock to `t` or to the earliest participant timer before it, exactly onto that deadline, and returns how many waits and events were due there; `Err(NotQuiescent)` changes nothing. The horizon rises to reach just past the landing — 1 ns, or on Windows 100 ns or one `QueryPerformanceCounter` tick where that is longer — so a wait that recomputes a zero timeout at its deadline can creep over it on the latency its call is charged; the rate stays the grant's. A charge that carries the clock onto a participant timer at the horizon raises it just past that timer the same way, so a creep that ends on another thread's deadline does not hold its waiter at it. Code that runs after the landing may therefore read up to that much past it. |
| `enter_timestamp(t)` / `leave_timestamp(t)` | The calling thread becomes the driver and acts at `t`: it reads exactly `t` from every clock and the code under test reads at least `t`, while the clock itself stands just before `t`, so timers at `t` are still pending. Participants released meanwhile — by what the driver sends, or by timers before `t` — wait at a gate, still counted blocked, until `leave_timestamp(t)` moves the clock to `t` (its horizon just past `t`, as for `jump_to`), fires what is due there (returning the count) and opens the gate. It wakes only waiters something reached: a timestamp at which nothing was sent and nothing came due leaves a quiescent sim quiescent. |
| `enter_timestamp_checked(t)` | As `enter_timestamp`, only if the sim is quiescent and no participant timer falls before `t`, checked in the same step; on `Err` nothing changes but the calling thread becoming the driver. |
| `with_driver_time(t, f)` | On a driver thread (a pool worker doing the executive's work), runs `f` reading `t` as the sim's time; its sends are held at the gate like the executive's own. |
| `quiescence()` | `quiescent`, the epoch, runnable/blocked participants, leases, `next_deadline`, and the first `blocker`: `Runnable` (a running participant, by name) > `Settling` (a woken waiter, a participant a futex, condition-variable, semaphore or `WaitOnAddress` wake released, one waiting for a pthread mutex that is now free, a joiner whose thread exited, or a participant the gate let go at the end of a timestamp, yet to run) > `Lease` (a busy lease) > `Setup` (only setup leases) > `Deferred` (held at the gate) > `TimerDue` (a timer at or before the reading its waiter has yet to take). |
| `arm_notify(epoch, f)` / `epoch()` | Calls `f` once the epoch moves past `epoch` — a change that can make the sim quiescent or end its quiescence: the last running participant parking or the first waking (any participant's park or wake under `deterministic()`), the last woken waiter re-checking and waiting on, a lease taken or given back, a class change, a thread exiting, a deterministic schedule going idle — on the thread that moved it, with no lock of the sim held. A participant parking or waking while another runs throughout moves no epoch. `epoch()` reads it without a lock. |
| `participants()` / `timers(n)` / `timer_count()` / `held_leases()` / `drain_hints()` | Every participant (lineage, name, running or blocked, for how long in sim and real time, what it waits in, its deadline, what it last waited in, the leases it holds) then one row per lease, with its `lease_kind`; the earliest timers, participants' before the others', with their owners' names; how many timers `timers` would list, without listing them; the leases with their kinds; the `hint_starving` hints since the last drain. |
| `outside_wakes()` | Unmatched returns from participants' native waits since the executive attached: nothing snare observed since quiescence explains the return. Always counted, with or without an audit. Spurious OS returns, such as those allowed by [WaitOnAddress](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitonaddress), can contribute; this is not proof that an unmanaged thread released the waiter. A run requiring every wake to be accounted for asserts it stays 0. |
| `audit()` | With `ExecutiveConfig { audit: true }` (or `SNARE_SCHED_AUDIT` set to anything but empty or `0`): background and helper threads' sim-visible effects (sends, connects, closes, futex/condvar/semaphore/address wakes, sleeps, `busy`), counted apart inside a `setup_scope`; the outside wakes; and every call the sim cannot model, as a violation. |
| `thread_census()` / `sim_id()` | Every OS thread of the process and whose it is (see [Thread census](#thread-census)); the sim's id. |

Dropping the executive (or `detach`) returns the clock to its base mode at its reading — never
backwards, and past an open timestamp's time — opens the gate, and time skips and deadlock give-ups
resume with the OS's own errors.

The gate holds participants leaving a sim wait (a socket, poll or sleep), a futex, a semaphore, a
`WaitOnAddress`, a condition variable or a join. A condition-variable wait woken inside a timestamp
lets go of its mutex while it waits at the gate and takes it back after, which the caller sees as an
ordinary wakeup. A contended mutex returns holding the code under test's lock, so it passes the gate
rather than risk blocking the executive's own threads on that lock. A participant already running when an unchecked `enter_timestamp` begins can see what the
driver does at `t` early, as can background threads, which the gate never holds. Under
`deterministic()` a timestamp also holds the schedule's baton: `enter_timestamp` waits for every
participant to block, `enter_timestamp_checked` takes it only if the schedule is idle, and
`leave_timestamp` hands it to the participants in the schedule's own order, whatever order the data
arrived in. A grant's rate runs as 0 there, with a one-time warning, so a deterministic run driven by
jumps and checked timestamps replays exactly; a flowing grant follows real time by design.

Outside `deterministic()`, a participant released by another thread's wake counts as `Settling` from
the wake until it runs: the futex, condition-variable, semaphore and `WaitOnAddress` hooks count,
before the OS wakes anyone, how many participants were parked on that address (up to the wake's
count), and an exit counts its joiners. A pthread mutex is judged by who holds it instead: the lock,
trylock and unlock hooks track the holder of every mutex a participant waits for, so a participant in
a contended lock is `Settling` only while that mutex is free or held outside the sim, and one woken
from a condition variable only while its mutex is free or its own. A holder that
re-takes the lock before the woken waiter runs, or that notifies and then sleeps holding the lock,
leaves the waiter blocked and the domain quiescent. A wake the OS hands to a thread that is not a
participant (a background thread waiting on the same address) leaves the parked participant counted
`Settling` until it next wakes, and a wake or unlock from a thread outside the sim is not seen at
all.

Whatever makes a participant runnable keeps the sim from being quiescent until that participant has
run: a datagram, bytes or a connection delivered to a socket it waits on (and any other readiness
change) marks every waiter woken as `Settling` until it has taken the lock again and re-checked — a
waiter that let go of the lock for a moment on its way back to sleep counts as asleep meanwhile, so a
wake landing then marks it too; an `Unparker::unpark` is such a readiness change; a futex,
condition-variable, semaphore or address wake counts as above; and a participant the gate held stays
counted until it has left its wait, so the next `enter_timestamp_checked` cannot slip in between the
gate opening and the participant running. A datagram still in flight is a timer at its arrival, not
a pending wake. A readiness change wakes only the waiters of the sim it belongs to (and threads
outside every sim): sims driven side by side by executives of their own never wake each other's
waiters, so none reads `Settling` because of a neighbour, and a jump made right after reading
quiescent goes through however busy the sims beside it are.

A driver time (`enter_timestamp`, `with_driver_time`) lapses on every thread when the executive is
dropped: the driver reads real time again.

Migrating sham and theater: sham and theater are the simulator and are never interposed. Theater
builds the `Sim` (seed from `SimBuilder::seed`) and hands it to sham's `SnareDomain::new(&sim, cfg)`,
which owns the clock through `sim.executive(cfg)` in place of the old `attach_driver`, before the code
under test starts. The code under test (conductor) runs inside `sim.run`; everything theater does
with sham, and every thread sham starts, runs under `snare::real`, so none of it joins the sim and
nothing marks thread classes or uses driver time. Theater talks to the code under test only through
the `Sim` API: its network (testers, or emulator threads woken from outside), faults and time.
There is no global slot or `register_test`, and no environment handshake; the thread census is
`sched::thread_census()` (below).

### Thread census

`sched::thread_census()` (also `Sim::thread_census`, `Executive::thread_census`) lists every OS
thread of the process — read from `/proc/self/task` on Linux, `task_threads` on macOS and a Toolhelp
thread snapshot on Windows — as a `CensusThread { os_id, name, owner }`, where `owner` is
`ThisSim(class)` for the calling thread's (or that) sim, `OtherSim(id, class)` for another sim's,
`Snare` for snare's own service threads (the link-delay and timer wakers, an executive's flow thread,
a stuck watchdog, the signal forwarder) and `Unmanaged` for everything else: the test harness, a
thread started outside every sim or under `snare::real`, one a runtime started for itself.
`ThreadCensus::unmanaged()`, `this_sim()` and `other_sims()` filter it. A thread counts as a sim's
from its own first line in the sim until it leaves, so one being created or exiting can read as
unmanaged for that moment; a run that fails on unknown threads should want one found unmanaged in
two censuses in a row, as theater's tracker did with snare v1.

## Cooperative primitives

`snare::sched` has the blocking and future primitives a simulation's own runtime (sham's
participants) is written against. In a sim they run on its clock and its schedule; off one, on real
time.

| Call | Effect |
|------|--------|
| `park(deadline)` / `current_unparker()` | Blocks until the thread's `Unparker` fires or the deadline passes (`ParkResult::Unparked` / `TimedOut`). An unpark that came first is consumed and returns at once. In a sim the park is a sim wait: it counts toward quiescence, its deadline (an `Instant`, read on the sim's clock) is a timer a time skip or an executive's jump lands on, a wake during an executive's timestamp is held at the gate, and under `deterministic()` it waits in the schedule. A participant parked with no deadline while nothing in the sim can move keeps waiting, as a join does. `Unparker::unpark` and `Unparker::waker()` work from any thread. |
| `block_on(f)` / `block_on_until(f, deadline)` / `block_on_timeout(f, d)` | Polls `f`, parking between polls with the thread's `Unparker` as the waker. Past the deadline `f` is polled once more, so an output ready at the deadline is not lost; a timeout past the end of the clock is no deadline. |
| `sleep_until(instant)` → `Sleep` | A future that completes when the clock reaches the instant: on its first pending poll its waker becomes a timer of the calling thread's class (a participant's steers time skips, a background thread's fires as the clock passes it or, once every participant waits on what only such a thread can do, steers them too), which the discrete time skip, `Executive::jump_to`, a flowing grant, a scaled clock reaching it (a real-time waker set for the real arrival) or a clock writer fires. Later polls replace the waker; dropping it, or completing, removes the timer. `is_elapsed()` checks the clock. On an as-fast-as-possible clock waiting on it jumps the clock to the instant, as a sleep does. Any waker works, not only `block_on`'s: a hand-rolled executor blocking in a channel receive or a condition variable between polls is woken at the instant, under `deterministic()` too. The clock runs the wakers it fires on a thread of its own, outside the sim. |
| `WakerSet` | The wakers of every task waiting on one piece of state: `register` before checking the state, `wake_all` after changing it. |
| `is_driven()` | The calling thread is a participant and the sim's clock is virtual (discrete, scaled, paused or owned by an executive). |

A driver thread outside an executive's timestamp reads real `Instant`s, so its `Sleep`s and park
deadlines are on real time; such threads should time their waits with real-time timers, or under
`with_driver_time`.
