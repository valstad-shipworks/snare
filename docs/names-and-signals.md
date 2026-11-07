# Names and signals

## Names

Inside a `Sim`, name resolution never leaves the process. `getaddrinfo`, `getnameinfo` and
`gethostbyname` — and on Windows `GetAddrInfoW`, `GetNameInfoW` — answer from the sim's host table
and a built-in `localhost` (`::1`, `127.0.0.1`; on Windows `""` too). Any other name fails as the
host OS fails an unknown name: `EAI_NONAME` (std's "failed to lookup address information"),
`HOST_NOT_FOUND`, `WSAHOST_NOT_FOUND` (11001), at once and without a packet.

```rust
let sim = Sim::builder().add_host("robot1.local", ["127.0.0.20".parse().unwrap()]).build();
sim.run(|| {
    let robot = connect_tester::<Line>("robot1.local:9000");   // testers and policies take names
    set_dns_policy("robot1.local", |p| p.latency = Duration::from_millis(30));
    // TcpStream::connect("ROBOT1.local.:9000") reaches the tester after 30 ms of virtual time
});
```

| Call | Effect |
|---|---|
| `add_host(name, addrs)` / `remove_host(name)` | Resolves `name` (case-insensitive, one trailing dot ignored) to `addrs` in table order. Also on `SimBuilder` and `Sim`. A name with no address of the asked family fails with `EAI_NONAME` (glibc, macOS) or `WSANO_DATA` (Windows). |
| `set_dns_policy(name, ..)` / `set_default_dns_policy(..)` | `DnsPolicy { latency, failure, failure_rate }`: the lookup waits `latency` on the sim's clock (virtual, so it time-skips and orders under `deterministic()`), then fails with `failure` — or, with a `failure_rate`, fails that often (`TryAgain` unless `failure` says otherwise), drawn from the sim's seed. Failures are logged as `Fault::Dns`. |
| `SimBuilder::resolve_real(name)` | Looks `name` up on the real resolver when the sim is built and keeps the answer; panics if it fails. |
| `SimBuilder::real_dns()` | Sends unknown names to the real resolver, counted as unmodelled calls. Panics in `build()` with `deterministic()`, since a real lookup blocks outside the schedule. |

Numeric hosts, a null node and service names go to the real libc / ws2_32, so hints semantics and
error precedence are the host's own; Windows reads a shorthand such as `127.1` as numeric only with
`AI_NUMERICHOST`, and otherwise as a name. A known name is answered by asking the OS for each of its
addresses as a numeric host with the caller's hints and joining the lists it returns; `freeaddrinfo`
takes such a list apart again on any thread, even after the sim is gone. `AI_ADDRCONFIG` is
ignored. `getnameinfo` reverses an address to the first table name holding it (and loopback to
`localhost` on Linux and macOS), otherwise numerically, or `EAI_NONAME` / `WSAHOST_NOT_FOUND` with
`NI_NAMEREQD`. The asynchronous resolvers (`getaddrinfo_a`, `GetAddrInfoEx`, `DNSServiceGetAddrInfo`,
`DnsQuery_W`, `res_query`) are not modelled and are reported as unmodelled calls.

## Signals

Each `Sim` keeps its own signal dispositions. The code under test installs its handlers with the
OS's own calls, so `ctrlc` and `signal-hook` run unchanged, and the real process's
handlers are never touched; two sims in one test binary each see only their own.

```rust
let sim = Sim::new();
let signals = sim.signals();                      // Clone + Send, usable from any thread
sim.run(|| {
    let (tx, rx) = std::sync::mpsc::channel();
    ctrlc::set_handler(move || tx.send(()).unwrap()).unwrap();
    assert_eq!(signals.raise(Signal::Interrupt), SignalDelivery::Handled);
    rx.recv().unwrap();
    let pending = signals.raise_after(Signal::Terminate, Duration::from_secs(30)); // a virtual timer
    pending.wait();
});
```

| Platform | What is simulated |
|---|---|
| unix | `sigaction`, `signal` (BSD semantics), `raise`, `kill` of the own process (`getpid()`, 0, `-getpgrp()`; `kill(-1)` skips the caller, as on the host, so it goes to the OS), `pthread_kill`, `pause`, `sigsuspend`, `pthread_sigmask`, `sigprocmask`, `sigpending` and `sigwait` (Linux also `sigwaitinfo`, `sigtimedwait` with its timeout on the sim's clock, and `signalfd`, a descriptor `read`, `poll`, `epoll` and `select` serve) for `SIGINT`, `SIGTERM`, `SIGHUP` and `SIGCHLD`. Every other signal, and other pids, go to the OS; the real process's mask never changes for these four. A sim's table starts from the process's dispositions, so an inherited `SIG_IGN` reads back, and a thread entering a sim starts with its real mask, a thread it creates with its own. A blocked signal stays pending (one ignored is discarded as it is sent on macOS, and on Linux unless blocked) until the mask lets it through, when the handlers of all that are pending run highest number first, as the kernel stacks their frames, each with its `sa_mask` blocked; or until `sigwait` or a `signalfd` read takes it. A signal sent to the process goes to a thread waiting for it in `sigwait`, else to a thread that does not block it: a root thread of the sim blocked in a call it interrupts, as the kernel prefers the main thread, else the sending thread synchronously, as POSIX requires of a signal a process sends itself, else, when every root blocks it, another thread blocked in such a call or any other; one every thread blocks stays pending for the process (on macOS for the first root, as XNU keeps it for the main thread). `SA_SIGINFO` handlers and `sigwaitinfo` get a `siginfo_t` with `si_code` `SI_USER` (Linux: `SI_TKILL` for `raise`/`pthread_kill`, folded into `SI_USER` by `sigwaitinfo` as glibc does) and `si_pid` the parent for the test's signals; `SA_RESETHAND` and `SA_NODEFER` behave as on the host. `pthread_kill` to another thread of the sim runs the handler there at its next hooked call, or at once if it is blocked in a call the handler interrupts. A handler that interrupts a blocked call fails it with `EINTR` or, under `SA_RESTART`, restarts it, call by call as on the host (man 7 signal; Linux never restarts a socket call with a timeout, macOS never a `sem_wait`): socket `recv`/`accept`/`send`/`connect` (macOS never restarts a `connect`), `poll`, `select`, `epoll_wait`, `kevent`, the sleeps (`nanosleep` reports the time left), `flock`/`F_SETLKW`/`F_OFD_SETLKW` on a `VirtualFs` file, `pause`, `sigsuspend`, `sigwaitinfo`/`sigtimedwait` (never restarted), a `close` lingering under `SO_LINGER` (on macOS it fails, with `EBADF` under `SA_RESTART`; Linux's returns 0), a blocking `read`, `readv`, `write` or `writev` of a pipe the sim made, a `read` of a `signalfd`, the waits for a child's end (`wait`, `waitpid`, `wait4`, `waitid`), and `sem_wait` (Linux also `sem_timedwait` and `sem_clockwait`, never restarted). |
| Windows | `SetConsoleCtrlHandler` (a list per sim, plus the ignore-CTRL+C flag), `GenerateConsoleCtrlEvent` for this process (group 0 or its own id; asynchronous, as on Windows; CTRL+C to a nonzero group succeeds and reaches no one, as Windows documents) and the CRT's `signal`/`raise` for `SIGINT`, `SIGBREAK`, `SIGTERM`. Each event is handled on a new thread, last registered handler first, until one returns `TRUE`. A close event's handlers get 5 s and a logoff or shutdown's 20 s of sim time before the delivery reports `HandledThenExit`. |
| both | `Sim::raise_signal` / `SignalHandle::raise` returns `Handled`, `HandledThenExit`, `DefaultAction` (never carried out), `Ignored`, `Pending` (every thread blocks it), `Accepted` (a `sigwait` took it), or `Unavailable` for a signal the host OS lacks (`Break`/`Close`/`Logoff`/`Shutdown` on unix, `Terminate`/`Hangup`/`Child` on Windows). From a thread outside the sim it is delivered on a new thread of the sim, joined before it returns, unless a root thread of the sim blocked in a call takes it; inside an executive's timestamp its effects wait for the timestamp to end like any other wake. |

The waits those libraries' threads block on are simulated: POSIX semaphores (`sem_wait`,
`sem_timedwait`, `sem_clockwait`, `sem_trywait`, `sem_post`; named semaphores on macOS), Windows
semaphore handles in `WaitForSingleObject` / `ReleaseSemaphore`, and `socketpair(AF_UNIX,
SOCK_STREAM | SOCK_DGRAM)`, served by the fabric like any socket (`poll`, `epoll`, `kqueue`, EOF,
`EPIPE`; an unnamed address as the host reports it). `pipe`/`pipe2` stay real, so a child process
can inherit them, but a `poll`, `select`, `epoll_wait` or `kevent` that waits on one (or on another
real descriptor, a child's pidfd) beside the sim's own blocks on it too: it ends when the descriptor
becomes ready, at the sim time a write or close by a thread of the sim made it so. While a process
a thread of the sim spawned runs, or a thread waits on a pipe such a process may hold, the sim's
clock moves no faster than real time, so a timeout cannot pass before the child has had that long;
when the child ends the sim delivers `SIGCHLD` once, on a thread of its own, with the `siginfo_t`
the kernel fills (`si_pid`, `si_code` `CLD_EXITED`/`CLD_KILLED`/`CLD_DUMPED`, `si_status`), and
drops the kernel's own `SIGCHLD` for it, which would land on whichever thread of the process the
kernel picked; `tokio::process` waits for it on macOS. A sim that ignores `SIGCHLD` or sets
`SA_NOCLDWAIT` has its children reaped at their exit. Until a sim's code sets `SIGCHLD` itself,
it gets the handler the code under test last installed in any sim, then the process's own. Under
`deterministic()`, once every root thread of a run has left and nothing can run, the schedule lets
leftover daemon threads (the `ctrlc` thread) go; they wait outside it until the sim runs again.

A library that installs its dispatcher once per process and remembers that in a static
(signal-hook-registry, and so `tokio::signal`, `signal-hook`, `async-signal`) calls `sigaction`
only in the first sim whose code registers with it. `SimBuilder::process_signal_handlers()` lets a
signal the sim's own code never set an action for reach the handler the code under test last
installed in any sim of the process, so such a library works in every sim; tokio delivers a signal
to the listeners of every runtime, as one process would.

`SimBuilder::forward_real_signals()` opts a sim in to the real `SIGINT`/`SIGTERM`/`SIGHUP` (a console
control handler on Windows): while any sim forwards, a process-wide forwarder delivers each real
signal into every forwarding sim, and one that no sim handled or ignored is raised for real against
the process's own disposition. The last forwarding sim to drop restores the originals. `SIGALRM`, kqueue's `EVFILT_SIGNAL` and
the real-time signals are not modelled, nor `EINTR` for a call that blocks in the OS itself (a read
of a real descriptor that is not a pipe the sim made; see [OPEN_BUGS.md](../OPEN_BUGS.md)).
