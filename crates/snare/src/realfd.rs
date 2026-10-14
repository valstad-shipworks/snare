//! Real descriptors in the sim's readiness waits.
//!
//! A pipe stays a real descriptor in a sim, so that a child process can inherit it, and a
//! `poll`, `epoll_wait` or `kevent` may wait on it, or on another real descriptor, beside the
//! sim's own. A [`Watch`] holds such descriptors in a probe set of the OS's (an epoll set on
//! Linux, a kqueue on macOS), each edge-triggered, so the probe turns readable when one of them
//! changes and stays so until it is drained. A simulated epoll set or kqueue keeps one for the
//! real descriptors registered in it, whose drained edges are theirs; a `poll` makes one for the
//! time it blocks. While a thread blocks on a watch ([`Waiting`]), three things read its probe:
//!
//! - the `snare-real-fds` thread, which blocks on the probes of waits outside a deterministic
//!   schedule and wakes their waiters, whatever wrote the descriptor;
//! - a sim about to move time or give up its waits as deadlocked, which first wakes every waiter
//!   whose probe is readable ([`settling`], and [`real_ready`] for a deterministic schedule), so
//!   a write by one of its own threads is seen at the sim time it happened, and in a deterministic
//!   run at a point of the schedule that replays;
//! - the waiter itself, which drains its probe before it looks at its descriptors.
//!
//! [`Pipes`] records the pipes a sim makes. One of them is the sim's own until a child process may
//! hold it (an end named by a `posix_spawn` file action, or any of them at a `fork`): from then on
//! something outside the sim may write it, and while a thread waits on such a pipe, until its
//! other side hangs up, the sim's clock moves no faster than real time
//! ([`Clock::hold_outside`](crate::clock::Clock::hold_outside)), so a timeout cannot pass before
//! the child has had that long to answer, and a quiescent sim waits for the child rather than
//! giving up. Any other real descriptor (one made outside the sim) wakes its waiter when it
//! becomes ready but holds no time back. A child process a thread of the sim spawned holds the
//! clock the same way while it runs, and its end is the sim's `SIGCHLD` ([`watch_child`]).
//!
//! Lock order: [`WATCHES`] is a leaf, taken under a deterministic schedule's lock by
//! [`real_ready`]; nothing bumps readiness or takes a schedule's lock under it. A watch's own
//! locks are leaves too.

use std::ffi::c_int;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};

use snare_interpose::RaceCell;

use crate::readiness::{WakeKey, WakeKeys, readiness};
use crate::scope::SimShared;
use crate::{HashMap, HashSet};

/// The pipes a sim made, by the identity of each of their ends.
#[derive(Default)]
pub(crate) struct Pipes {
    state: Mutex<PipeState>,
}

#[derive(Default)]
struct PipeState {
    /// Each end's `(st_dev, st_ino)`, and the pipe it belongs to. macOS gives the two ends of a
    /// pipe inodes of their own, Linux one inode for both.
    ends: HashMap<(u64, u64), u64>,
    /// The pipes a child process may hold.
    lent: HashSet<u64>,
    next: u64,
}

impl Pipes {
    fn state(&self) -> MutexGuard<'_, PipeState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Records a pipe the sim made.
    pub(crate) fn add(&self, fds: [c_int; 2]) {
        let ends = fds.map(identity);
        let mut state = self.state();
        state.next += 1;
        let pipe = state.next;
        for end in ends.into_iter().flatten() {
            state.ends.insert(end, pipe);
        }
    }

    /// A child process may hold `fd`; with `None`, any of the sim's pipes.
    pub(crate) fn lend(&self, fd: Option<c_int>) {
        let end = fd.map(identity);
        let mut state = self.state();
        let state = &mut *state;
        match end {
            Some(end) => {
                if let Some(&pipe) = end.and_then(|end| state.ends.get(&end)) {
                    state.lent.insert(pipe);
                }
            }
            None => state.lent.extend(state.ends.values().copied()),
        }
    }

    /// Whether `fd` is an end of a pipe the sim made, and if so whether a child process may hold
    /// that pipe.
    pub(crate) fn lent(&self, fd: c_int) -> Option<bool> {
        if self.state().ends.is_empty() {
            return None;
        }
        let end = identity(fd)?;
        let state = self.state();
        let pipe = state.ends.get(&end)?;
        Some(state.lent.contains(pipe))
    }
}

/// The identity of the open file `fd` names, `None` for a closed descriptor.
// `st_dev` and `st_ino` are `u64` on Linux; `st_dev` is `i32` on macOS.
#[allow(clippy::unnecessary_cast)]
fn identity(fd: c_int) -> Option<(u64, u64)> {
    snare_interpose::real(|| {
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: `stat` has room for the result.
        if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
            return None;
        }
        // SAFETY: fstat filled it.
        let stat = unsafe { stat.assume_init() };
        Some((stat.st_dev as u64, stat.st_ino as u64))
    })
}

/// A watch, as the registry and the watcher thread see it.
struct Entry {
    id: u64,
    /// The [`Domain::key`](snare_interpose::Domain::key) of the sim its waiter runs in.
    domain: usize,
    probe: c_int,
    /// A thread blocks on it.
    waiting: bool,
    /// The watcher thread is to wake the waiter: set while it waits outside a deterministic
    /// schedule and has looked since the last wake.
    armed: bool,
    /// Its waiter waits on a descriptor a child process may write.
    outside: bool,
    /// For a child process of a sim rather than a wait: its pid, and the sim. The probe turns
    /// readable when it exits.
    child: Option<(libc::pid_t, Weak<SimShared>)>,
}

static WATCHES: Mutex<Vec<Entry>> = Mutex::new(Vec::new());

/// The next [`Entry::id`].
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// How many entries [`WATCHES`] holds, so a sim with none skips its lock.
static WATCH_COUNT: AtomicUsize = AtomicUsize::new(0);

fn watches() -> MutexGuard<'static, Vec<Entry>> {
    WATCHES.lock().unwrap_or_else(|e| e.into_inner())
}

/// Runs `f` on the registry's entry for watch `id`, if it is there.
fn with_entry<R>(id: u64, f: impl FnOnce(&mut Entry) -> R) -> Option<R> {
    snare_interpose::real(|| watches().iter_mut().find(|e| e.id == id).map(f))
}

/// How long a quiescent sim with no virtual clock waits in real time between looks while one of
/// its threads waits on what a child process may write. A snare choice: the watcher thread wakes
/// the waiter as soon as the child writes, so this only bounds how long the sim takes to notice
/// a wait that ended otherwise.
pub(crate) const OUTSIDE_POLL: std::time::Duration = std::time::Duration::from_millis(200);

/// Real descriptors held edge-triggered in a probe set (see the module documentation).
pub(crate) struct Watch {
    id: u64,
    probe: c_int,
    /// The descriptors in the probe, with the `poll` events each is watched for.
    fds: Mutex<Vec<(c_int, i16)>>,
    /// The edges the probe has reported for each descriptor: (read, write).
    edges: Mutex<HashMap<c_int, (u64, u64)>>,
}

impl Watch {
    /// A watch on `fds`, each with its `poll` events. `None` when the OS gives no probe set.
    pub(crate) fn new(fds: &[(c_int, i16)]) -> Option<Arc<Watch>> {
        let probe = snare_interpose::real(probe_set);
        if probe < 0 {
            return None;
        }
        let watch = Arc::new(Watch {
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            probe,
            fds: Mutex::new(Vec::new()),
            edges: Mutex::new(HashMap::default()),
        });
        watch.set(fds);
        snare_interpose::real(|| {
            watches().push(Entry {
                id: watch.id,
                domain: 0,
                probe,
                waiting: false,
                armed: false,
                outside: false,
                child: None,
            });
        });
        WATCH_COUNT.fetch_add(1, Ordering::SeqCst);
        Some(watch)
    }

    /// The readiness key the watch wakes its waiter on.
    pub(crate) fn key(&self) -> WakeKey {
        WakeKey::Real(self.id)
    }

    /// Watches `fds` from now on, in place of what it watched.
    pub(crate) fn set(&self, fds: &[(c_int, i16)]) {
        let mut wanted: Vec<(c_int, i16)> = Vec::with_capacity(fds.len());
        for &(fd, events) in fds {
            match wanted.iter_mut().find(|(f, _)| *f == fd) {
                Some(entry) => entry.1 |= events,
                None => wanted.push((fd, events)),
            }
        }
        let mut held = self.fds.lock().unwrap_or_else(|e| e.into_inner());
        if *held == wanted {
            return;
        }
        snare_interpose::real(|| {
            for &(fd, _) in held
                .iter()
                .filter(|(fd, _)| !wanted.iter().any(|w| w.0 == *fd))
            {
                unwatch(self.probe, fd);
            }
            for &(fd, events) in &wanted {
                if !held.contains(&(fd, events)) {
                    watch(self.probe, fd, events);
                }
            }
        });
        let mut edges = self.edges.lock().unwrap_or_else(|e| e.into_inner());
        edges.retain(|fd, _| wanted.iter().any(|w| w.0 == *fd));
        *held = wanted;
    }

    /// Takes what the probe has seen, counting each descriptor's edges, so it turns readable
    /// again only on the next change.
    pub(crate) fn drain(&self) {
        let mut edges = self.edges.lock().unwrap_or_else(|e| e.into_inner());
        snare_interpose::real(|| {
            drain(self.probe, &mut |fd, read, write| {
                let counts = edges.entry(fd).or_default();
                counts.0 += u64::from(read);
                counts.1 += u64::from(write);
            });
        });
    }

    /// The read and write edges the probe has reported for `fd` so far.
    pub(crate) fn edges(&self, fd: c_int) -> (u64, u64) {
        let edges = self.edges.lock().unwrap_or_else(|e| e.into_inner());
        edges.get(&fd).copied().unwrap_or_default()
    }

    /// Marks a thread of `shared`'s sim blocking on the watch until the returned guard drops.
    pub(crate) fn wait(self: &Arc<Self>, shared: &Arc<SimShared>) -> Waiting {
        let domain = shared.domain_key();
        with_entry(self.id, |entry| {
            entry.domain = domain;
            entry.waiting = true;
        });
        let waiting = Waiting {
            watch: self.clone(),
            shared: shared.clone(),
            outside: AtomicBool::new(false),
        };
        waiting.arm();
        waiting
    }
}

impl Drop for Watch {
    /// Closes the probe at once, so its number is free again as it would be without the sim. The
    /// watcher thread may still be blocked on it: it looks again, and a number reused meanwhile
    /// costs it only a spurious look.
    fn drop(&mut self) {
        let armed = snare_interpose::real(|| {
            let mut watches = watches();
            let at = watches.iter().position(|e| e.id == self.id)?;
            let entry = watches.swap_remove(at);
            // SAFETY: the probe is this watch's own.
            unsafe { libc::close(entry.probe) };
            Some(entry.armed)
        });
        if let Some(armed) = armed {
            WATCH_COUNT.fetch_sub(1, Ordering::SeqCst);
            if armed {
                watcher().poke();
            }
        }
    }
}

/// A thread blocking on a [`Watch`]: subscribed to its [`key`](Watch::key), it calls
/// [`look`](Self::look) each time before it checks its descriptors.
pub(crate) struct Waiting {
    watch: Arc<Watch>,
    shared: Arc<SimShared>,
    /// Holding the sim's clock to real time: a child process may write one of the descriptors.
    outside: AtomicBool,
}

impl Waiting {
    /// The watch blocked on.
    pub(crate) fn watch(&self) -> &Arc<Watch> {
        &self.watch
    }

    /// Drains the probe, then [`arm`](Self::arm)s it.
    pub(crate) fn look(&self) {
        self.watch.drain();
        self.arm();
    }

    /// Has the watcher thread wake the waiter on the probe's next change when it waits outside a
    /// deterministic schedule, and settles whether a child process may write one of the
    /// descriptors.
    fn arm(&self) {
        if !snare_interpose::det_active() {
            let rearmed = with_entry(self.watch.id, |entry| {
                !std::mem::replace(&mut entry.armed, true)
            });
            if rearmed == Some(true) {
                watcher().poke();
            }
        }
        let outside = {
            let fds = self.watch.fds.lock().unwrap_or_else(|e| e.into_inner());
            fds.iter()
                .any(|&(fd, _)| self.shared.pipes.lent(fd) == Some(true) && !hung_up(fd))
        };
        if self.outside.swap(outside, Ordering::AcqRel) != outside {
            if let Some(clock) = &self.shared.clock {
                clock.hold_outside(outside);
            }
            with_entry(self.watch.id, |entry| entry.outside = outside);
        }
    }
}

impl Drop for Waiting {
    fn drop(&mut self) {
        if self.outside.load(Ordering::Acquire)
            && let Some(clock) = &self.shared.clock
        {
            clock.hold_outside(false);
        }
        with_entry(self.watch.id, |entry| {
            entry.waiting = false;
            entry.armed = false;
            entry.outside = false;
        });
    }
}

/// Whether `fd`'s other side has gone: a read end whose writers have all closed, a write end
/// whose readers have, or a descriptor closed meanwhile. Nothing can make it ready again.
fn hung_up(fd: c_int) -> bool {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN | libc::POLLOUT,
        revents: 0,
    };
    // SAFETY: one pollfd.
    let polled = snare_interpose::real(|| unsafe { libc::poll(&mut pfd, 1, 0) });
    polled < 0 || pfd.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0
}

/// Whether `probe` has seen a change not yet drained.
fn probe_ready(probe: c_int) -> bool {
    let mut pfd = libc::pollfd {
        fd: probe,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one pollfd.
    let polled = snare_interpose::real(|| unsafe { libc::poll(&mut pfd, 1, 0) });
    polled > 0 && pfd.revents & libc::POLLIN != 0
}

#[cfg(target_os = "linux")]
fn probe_set() -> c_int {
    // SAFETY: no pointers.
    unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) }
}

#[cfg(target_os = "macos")]
fn probe_set() -> c_int {
    // SAFETY: no pointers.
    let kq = unsafe { libc::kqueue() };
    if kq >= 0 {
        // SAFETY: no pointers.
        unsafe { libc::fcntl(kq, libc::F_SETFD, libc::FD_CLOEXEC) };
    }
    kq
}

/// Adds `fd` to `probe` edge-triggered for `events`. A descriptor the OS cannot watch (a regular
/// file, `/dev/null`) is left out: it is always ready, so its waiter never blocks on it.
#[cfg(target_os = "linux")]
fn watch(probe: c_int, fd: c_int, events: i16) {
    let mask = (events as u16 as u32)
        & (libc::EPOLLIN | libc::EPOLLOUT | libc::EPOLLPRI | libc::EPOLLRDHUP) as u32;
    let mut event = libc::epoll_event {
        events: mask | libc::EPOLLET as u32,
        u64: fd as u64,
    };
    // SAFETY: `event` is a valid epoll_event.
    unsafe {
        if libc::epoll_ctl(probe, libc::EPOLL_CTL_ADD, fd, &mut event) != 0 {
            libc::epoll_ctl(probe, libc::EPOLL_CTL_MOD, fd, &mut event);
        }
    }
}

#[cfg(target_os = "linux")]
fn unwatch(probe: c_int, fd: c_int) {
    // SAFETY: a null event is allowed for EPOLL_CTL_DEL (man 2 epoll_ctl, BUGS).
    unsafe { libc::epoll_ctl(probe, libc::EPOLL_CTL_DEL, fd, std::ptr::null_mut()) };
}

/// Empties `probe`'s ready list, passing `edge` each event's descriptor and whether it was a read
/// or a write edge (a hang-up or an error is both).
#[cfg(target_os = "linux")]
fn drain(probe: c_int, edge: &mut dyn FnMut(c_int, bool, bool)) {
    let mut events = [libc::epoll_event { events: 0, u64: 0 }; 16];
    loop {
        // SAFETY: `events` has room for 16.
        let n = unsafe { libc::epoll_wait(probe, events.as_mut_ptr(), 16, 0) };
        for event in &events[..n.max(0) as usize] {
            let (bits, fd) = (event.events, event.u64 as c_int);
            let broken = bits & (libc::EPOLLHUP | libc::EPOLLERR) as u32 != 0;
            let read = bits & (libc::EPOLLIN | libc::EPOLLPRI | libc::EPOLLRDHUP) as u32 != 0;
            edge(
                fd,
                read || broken,
                bits & libc::EPOLLOUT as u32 != 0 || broken,
            );
        }
        if n < 16 {
            break;
        }
    }
}

#[cfg(target_os = "macos")]
fn kevent_filters(events: i16) -> impl Iterator<Item = i16> {
    [
        (
            libc::POLLIN | libc::POLLPRI | libc::POLLRDNORM,
            libc::EVFILT_READ,
        ),
        (libc::POLLOUT | libc::POLLWRNORM, libc::EVFILT_WRITE),
    ]
    .into_iter()
    .filter(move |(bits, _)| events & bits != 0)
    .map(|(_, filter)| filter)
}

#[cfg(target_os = "macos")]
fn change(probe: c_int, fd: c_int, events: i16, flags: u16) {
    for filter in kevent_filters(events) {
        let change = libc::kevent {
            ident: fd as usize,
            filter,
            flags: flags | libc::EV_RECEIPT,
            fflags: 0,
            data: 0,
            udata: std::ptr::null_mut(),
        };
        // SAFETY: zeroed kevents are valid.
        let mut receipt: libc::kevent = unsafe { std::mem::zeroed() };
        // SAFETY: one change and room for its receipt.
        unsafe { libc::kevent(probe, &change, 1, &mut receipt, 1, std::ptr::null()) };
    }
}

#[cfg(target_os = "macos")]
fn watch(probe: c_int, fd: c_int, events: i16) {
    change(probe, fd, events, libc::EV_ADD | libc::EV_CLEAR);
}

#[cfg(target_os = "macos")]
fn unwatch(probe: c_int, fd: c_int) {
    change(probe, fd, libc::POLLIN | libc::POLLOUT, libc::EV_DELETE);
}

#[cfg(target_os = "macos")]
fn drain(probe: c_int, edge: &mut dyn FnMut(c_int, bool, bool)) {
    // SAFETY: zeroed kevents are valid.
    let mut events: [libc::kevent; 16] = unsafe { std::mem::zeroed() };
    let zero = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    loop {
        // SAFETY: `events` has room for 16.
        let n = unsafe { libc::kevent(probe, std::ptr::null(), 0, events.as_mut_ptr(), 16, &zero) };
        for event in &events[..n.max(0) as usize] {
            let fd = event.ident as c_int;
            edge(
                fd,
                event.filter == libc::EVFILT_READ,
                event.filter == libc::EVFILT_WRITE,
            );
        }
        if n < 16 {
            break;
        }
    }
}

/// Watches child process `pid` of `shared`'s sim: once it ends, the sim delivers `SIGCHLD` for it
/// ([`child_exited`]), and the child stops holding the sim's clock (see
/// [`Clock::hold_child`](crate::clock::Clock::hold_child)). The kernel's own `SIGCHLD` for it
/// reaches no handler ([`snare_interpose::adopt_child`]): it lands on whichever thread of the
/// process the kernel picks, often one outside every sim, where what a handler writes to the
/// sim's descriptors (tokio's signal pipe) reaches none, and the code under test would see the
/// child end twice.
pub(crate) fn watch_child(shared: &Arc<SimShared>, pid: libc::pid_t) {
    snare_interpose::real(|| snare_interpose::adopt_child(pid));
    let probe = snare_interpose::real(|| child_probe(pid));
    if probe < 0 {
        child_exited(shared, pid, None);
        return;
    }
    snare_interpose::real(|| {
        watches().push(Entry {
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            domain: shared.domain_key(),
            probe,
            waiting: false,
            armed: false,
            outside: false,
            child: Some((pid, Arc::downgrade(shared))),
        });
    });
    WATCH_COUNT.fetch_add(1, Ordering::SeqCst);
    watcher().poke();
}

/// A descriptor that turns readable once child process `pid` exits: a pidfd (man 2 pidfd_open,
/// Linux 5.3). -1 when the kernel has none, or the child is gone.
#[cfg(target_os = "linux")]
pub(crate) fn child_probe(pid: libc::pid_t) -> c_int {
    // SAFETY: no pointers.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as c_int;
    if fd >= 0 {
        // SAFETY: no pointers.
        unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
    }
    fd
}

/// A kqueue that turns readable once child process `pid` exits (`EVFILT_PROC` with `NOTE_EXIT`,
/// and `NOTE_EXITSTATUS` for the wait(2) status in the event's `data`, man 2 kevent). -1 when the
/// child is gone.
#[cfg(target_os = "macos")]
pub(crate) fn child_probe(pid: libc::pid_t) -> c_int {
    let kq = probe_set();
    if kq < 0 {
        return kq;
    }
    let change = libc::kevent {
        ident: pid as usize,
        filter: libc::EVFILT_PROC,
        flags: libc::EV_ADD | libc::EV_ONESHOT,
        fflags: libc::NOTE_EXIT | libc::NOTE_EXITSTATUS,
        data: 0,
        udata: std::ptr::null_mut(),
    };
    // SAFETY: one change, no events.
    if unsafe { libc::kevent(kq, &change, 1, std::ptr::null_mut(), 0, std::ptr::null()) } != 0 {
        // SAFETY: the kqueue made above.
        unsafe { libc::close(kq) };
        return -1;
    }
    kq
}

/// The wait(2) status of the child whose exit made `probe` readable, when the probe says it: the
/// `NOTE_EXITSTATUS` event's `data` on macOS. A pidfd says nothing of it.
#[cfg(target_os = "linux")]
fn child_status(_probe: c_int) -> Option<c_int> {
    None
}

#[cfg(target_os = "macos")]
fn child_status(probe: c_int) -> Option<c_int> {
    // SAFETY: a zeroed kevent is valid; room for one event, and a zero timeout.
    let mut event: libc::kevent = unsafe { std::mem::zeroed() };
    let zero = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: as above.
    let n = unsafe { libc::kevent(probe, std::ptr::null(), 0, &mut event, 1, &zero) };
    (n == 1 && event.filter == libc::EVFILT_PROC && event.fflags & libc::NOTE_EXIT != 0)
        .then_some(event.data as c_int)
}

/// How long a delivery of `SIGCHLD` waits for a child's end to be known when the child was reaped
/// before it looked, for the reaping wait to note it (see [`child_exit`]). A snare choice: the
/// note follows the reap within microseconds.
const REAP_NOTE_GRACE: std::time::Duration = std::time::Duration::from_millis(100);

/// Child process `pid` of `shared`'s sim has ended, its wait(2) `status` known when the probe told
/// it: lets the child's hold on the clock go, and delivers `SIGCHLD` for it into the sim on a
/// thread of the sim (see [`snare_interpose::deliver_child_exit`]) when the sim handles it. A sim
/// that ignores it, or set `SA_NOCLDWAIT`, has the child reaped, as the kernel would have it reaped
/// at its exit (man 2 sigaction, `SA_NOCLDWAIT`; man 2 wait, NOTES: with `SIGCHLD` ignored "the
/// children of the calling process will not be transformed into zombies"). Linux still sends
/// `SIGCHLD` to a handler installed with `SA_NOCLDWAIT`, which POSIX leaves open.
fn child_exited(shared: &Arc<SimShared>, pid: libc::pid_t, status: Option<c_int>) {
    let action = snare_interpose::real(|| shared.signals.child_action());
    if action.sa_sigaction == libc::SIG_IGN || action.sa_flags & libc::SA_NOCLDWAIT != 0 {
        // SAFETY: no pointers but a null status; WNOHANG returns at once.
        snare_interpose::real(|| unsafe {
            libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG)
        });
    }
    let handled = action.sa_sigaction != libc::SIG_DFL && action.sa_sigaction != libc::SIG_IGN;
    if let Some(domain) = shared.domain.get().and_then(|d| d.upgrade())
        && (handled || (held_by_default(&action) && domain.holds_signal(libc::SIGCHLD)))
    {
        let _ = domain.spawn_injected("snare-sigchld", move || {
            // SAFETY: getuid has no preconditions; on a thread of the sim it is the sim's.
            let uid = unsafe { libc::getuid() };
            let exit = snare_interpose::real(|| child_exit(pid, uid, status));
            snare_interpose::deliver_child_exit(exit);
        });
    }
    if let Some(clock) = &shared.clock {
        clock.release_child(pid);
    }
}

/// Whether the kernel still sends `SIGCHLD` under `action` though no handler is installed, for a
/// thread to take with `sigwait` or a `signalfd` while every thread blocks it: Linux sends it
/// under `SIG_DFL` and keeps it pending while blocked (kernel/signal.c `do_notify_parent` sends
/// it unless the action is `SIG_IGN`, and `sig_ignored` keeps a blocked signal); XNU discards it
/// as it is sent, its default action being to ignore it (bsd/kern/kern_sig.c `psignal_internal`
/// checks `p_sigignore`, which `setsigvec` fills for a default-ignored signal). Pinned against
/// both hosts by tests/signal_masks.rs.
fn held_by_default(action: &libc::sigaction) -> bool {
    cfg!(target_os = "linux") && action.sa_sigaction == libc::SIG_DFL
}

/// How child `pid` of user `uid` ended, measured against the host: the status its exit probe
/// gave; else waitid(2) of the child not yet reaped (`WNOWAIT`), which fills a `siginfo_t` as the
/// kernel's `SIGCHLD` does; else what the kernel's `SIGCHLD` or a wait that reaped it noted
/// ([`snare_interpose::child_exit_of`]), waited for up to [`REAP_NOTE_GRACE`]. A child whose end
/// none of these saw (reaped by a call snare does not see) is reported as having exited with 0.
fn child_exit(
    pid: libc::pid_t,
    uid: libc::uid_t,
    status: Option<c_int>,
) -> snare_interpose::ChildExit {
    if let Some(exit) =
        status.and_then(|status| snare_interpose::ChildExit::from_wait_status(pid, uid, status))
    {
        return exit;
    }
    // SAFETY: zeroed is a valid siginfo_t, which waitid fills.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: as above; WNOWAIT leaves the child to be reaped.
    let waited = unsafe {
        libc::waitid(
            libc::P_PID,
            pid as libc::id_t,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    // SAFETY: waitid filled `info`.
    if waited == 0 && unsafe { info.si_pid() } == pid {
        return snare_interpose::ChildExit {
            pid,
            uid,
            code: info.si_code,
            // SAFETY: as above.
            status: unsafe { info.si_status() },
        };
    }
    let since = std::time::Instant::now();
    loop {
        if let Some(exit) = snare_interpose::child_exit_of(pid, uid) {
            return exit;
        }
        if since.elapsed() >= REAP_NOTE_GRACE {
            return snare_interpose::ChildExit {
                pid,
                uid,
                code: libc::CLD_EXITED,
                status: 0,
            };
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}

/// Wakes the waiters of the domain with key `domain` whose probes are readable and who wait
/// outside a deterministic schedule, returning whether there was one: until they have looked the
/// sim only looks quiescent, so no time may skip.
pub(crate) fn settling(domain: usize) -> bool {
    if WATCH_COUNT.load(Ordering::SeqCst) == 0 {
        return false;
    }
    let mut woken = WakeKeys::default();
    snare_interpose::real(|| {
        for entry in watches().iter() {
            if entry.domain == domain && entry.waiting && probe_ready(entry.probe) {
                woken.push(WakeKey::Real(entry.id));
            }
        }
    });
    if woken.as_slice().is_empty() {
        return false;
    }
    readiness().bump_keys_unscheduled(domain, woken.as_slice());
    true
}

/// Has every wait of the domain with key `domain` on real descriptors look again: a child
/// process may now hold one of them.
pub(crate) fn recheck(domain: usize) {
    if WATCH_COUNT.load(Ordering::SeqCst) == 0 {
        return;
    }
    let mut keys = WakeKeys::default();
    snare_interpose::real(|| {
        for entry in watches().iter() {
            if entry.domain == domain && entry.waiting {
                keys.push(WakeKey::Real(entry.id));
            }
        }
    });
    if !keys.as_slice().is_empty() {
        readiness().bump_keys(domain, keys.as_slice());
    }
}

/// Whether a thread of the domain with key `domain` waits on a descriptor a child process may
/// write.
pub(crate) fn outside(domain: usize) -> bool {
    WATCH_COUNT.load(Ordering::SeqCst) > 0
        && snare_interpose::real(|| {
            watches()
                .iter()
                .any(|e| e.domain == domain && e.waiting && e.outside)
        })
}

/// Passes `ready` the key of each wait of the domain with key `domain` whose probe is readable
/// (see `Layer::real_ready`). Runs under a deterministic schedule's lock, so it allocates nothing.
pub(crate) fn real_ready(domain: usize, ready: &mut dyn FnMut(WakeKey)) {
    if WATCH_COUNT.load(Ordering::SeqCst) == 0 {
        return;
    }
    snare_interpose::real(|| {
        for entry in watches().iter() {
            if entry.domain == domain && entry.waiting && probe_ready(entry.probe) {
                ready(WakeKey::Real(entry.id));
            }
        }
    });
}

/// The `snare-real-fds` thread, which blocks on the probes of armed waits and wakes their
/// waiters. Started unmanaged on first use.
struct Watcher {
    /// A pipe whose read end is in every set the thread blocks on: a byte written to it makes the
    /// thread look at the registry again.
    wake: [c_int; 2],
}

static WATCHER: RaceCell<Watcher> = RaceCell::new();

fn watcher() -> &'static Watcher {
    let (instance, started) = WATCHER.get_or_init(|| {
        let mut wake = [-1; 2];
        snare_interpose::real(|| {
            // SAFETY: `wake` has room for two descriptors.
            if unsafe { libc::pipe(wake.as_mut_ptr()) } == 0 {
                for fd in wake {
                    // SAFETY: no pointers.
                    unsafe {
                        libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
                        libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK);
                    }
                }
            }
        });
        Watcher { wake }
    });
    if started {
        snare_interpose::real(|| {
            std::thread::Builder::new()
                .name("snare-real-fds".into())
                .spawn(|| {
                    let _service = snare_interpose::service_thread();
                    watcher().run();
                })
                .expect("start the real-descriptor watcher");
        });
    }
    instance
}

impl Watcher {
    fn poke(&self) {
        if self.wake[1] >= 0 {
            // SAFETY: one byte from a static.
            snare_interpose::real(|| unsafe { libc::write(self.wake[1], b"w".as_ptr().cast(), 1) });
        }
    }

    fn run(&self) {
        // The process's signals are the code under test's: none lands on this thread.
        // SAFETY: a full set, applied to the calling thread only.
        unsafe {
            let mut all: libc::sigset_t = std::mem::zeroed();
            libc::sigfillset(&mut all);
            libc::pthread_sigmask(libc::SIG_BLOCK, &all, std::ptr::null_mut());
        }
        let mut set: Vec<libc::pollfd> = Vec::new();
        let mut ids: Vec<u64> = Vec::new();
        let mut woken: Vec<(usize, WakeKey)> = Vec::new();
        let mut exited: Vec<(libc::pid_t, Weak<SimShared>, Option<c_int>)> = Vec::new();
        loop {
            set.clear();
            ids.clear();
            set.push(libc::pollfd {
                fd: self.wake[0],
                events: libc::POLLIN,
                revents: 0,
            });
            {
                let watches = watches();
                for entry in watches.iter() {
                    if entry.child.is_some() || entry.armed && entry.waiting {
                        set.push(libc::pollfd {
                            fd: entry.probe,
                            events: libc::POLLIN,
                            revents: 0,
                        });
                        ids.push(entry.id);
                    }
                }
            }
            // SAFETY: `set` holds `set.len()` pollfds.
            let polled = unsafe { libc::poll(set.as_mut_ptr(), set.len() as _, -1) };
            if polled < 0
                && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted
            {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            let mut byte = [0u8; 64];
            // SAFETY: `byte` has room for 64.
            while unsafe { libc::read(self.wake[0], byte.as_mut_ptr().cast(), 64) } > 0 {}
            {
                let mut watches = watches();
                for (pfd, id) in set[1..].iter().zip(&ids) {
                    if pfd.revents == 0 {
                        continue;
                    }
                    let Some(at) = watches.iter().position(|e| e.id == *id) else {
                        continue;
                    };
                    if watches[at].child.is_some() {
                        let entry = watches.swap_remove(at);
                        let status = child_status(entry.probe);
                        // SAFETY: the child's probe, which only this registry holds.
                        unsafe { libc::close(entry.probe) };
                        WATCH_COUNT.fetch_sub(1, Ordering::SeqCst);
                        exited.extend(entry.child.map(|(pid, shared)| (pid, shared, status)));
                    } else {
                        watches[at].armed = false;
                        woken.push((watches[at].domain, WakeKey::Real(*id)));
                    }
                }
            }
            for (domain, key) in woken.drain(..) {
                readiness().bump_keys_unscheduled(domain, &[key]);
            }
            for (pid, shared, status) in exited.drain(..) {
                if let Some(shared) = shared.upgrade() {
                    child_exited(&shared, pid, status);
                }
            }
        }
    }
}
