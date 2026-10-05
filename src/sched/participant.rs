//! Participant registry: which threads count toward quiescence, whether each
//! is running or blocked in a snare wait, busy leases, deferred wakes and the
//! audit log.
//!
//! Every Blocked→Running move happens under the registry lock *before* the
//! OS-level wake, and only a running participant or a driver-class thread can
//! cause it, so `runnable` never reads 0 while a wake is in flight. The park
//! cell's wake flag is set under the same lock; only the condvar notify runs
//! after it is released, and a late notify is harmless because a waiter
//! always re-checks its flags.

use std::cell::RefCell;
use std::collections::{BTreeMap, VecDeque};
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant as WallInstant};

use parking_lot::{Mutex, MutexGuard};

use super::clock::Clock;
use super::slot::try_with_slot;
use super::timer::{ParkCell, ParkWake, TimerTarget, Timers};
use super::{
    AuditReport, BlockerKind, ClassEffect, NotQuiescent, PState, ParkResult, ParticipantInfo,
    Quiescence, QuiescenceViolation, ThreadClass, TimerInfo, classified, is_driver_thread,
};

/// Registries with accounting on, process-wide. Zero keeps every hot path
/// free of registry work.
static ACCOUNTING: AtomicUsize = AtomicUsize::new(0);
/// Registries with audit on, process-wide.
pub(super) static AUDITING: AtomicUsize = AtomicUsize::new(0);
/// Registries with a driver attached, process-wide.
static ATTACHED: AtomicUsize = AtomicUsize::new(0);

/// Whether any state slot in the process has a driver attached.
pub(super) fn any_attached() -> bool {
    ATTACHED.load(Ordering::Acquire) != 0
}

const MAX_HINTS: usize = 1024;
const MAX_VIOLATIONS: usize = 1024;
const MAX_CLASS_EFFECTS: usize = 256;

type Notify = Arc<dyn Fn() + Send + Sync>;

thread_local! {
    static MEMBER: RefCell<Option<Member>> = const { RefCell::new(None) };
    static DEFER: RefCell<Option<Arc<Registry>>> = const { RefCell::new(None) };
}

/// A park cell's tie to the participant that waits on it.
#[derive(Clone)]
pub(crate) struct Link {
    pub(crate) reg: Arc<Registry>,
    generation: u64,
    pid: u64,
}

impl Link {
    fn same(&self, other: &Link) -> bool {
        self.generation == other.generation
            && self.pid == other.pid
            && Arc::ptr_eq(&self.reg, &other.reg)
    }
}

/// What holds the domain back from quiescence.
enum Block<'a> {
    Untracked,
    Running(&'a Participant),
    Lease(&'static str),
    Deferred,
    TimerDue,
}

impl Block<'_> {
    fn describe(&self) -> (BlockerKind, Arc<str>) {
        match self {
            Block::Untracked => (BlockerKind::Untracked, Arc::from("accounting disabled")),
            Block::Running(p) if p.origin == Origin::Stray => (BlockerKind::Stray, p.name.clone()),
            Block::Running(p) => (BlockerKind::Runnable, p.name.clone()),
            Block::Lease(label) => (BlockerKind::Lease, Arc::from(*label)),
            Block::Deferred => (BlockerKind::Deferred, Arc::from("deferred wakes")),
            Block::TimerDue => (BlockerKind::TimerDue, Arc::from("timer due")),
        }
    }
}

pub(crate) enum WakeKind {
    Unpark,
    Fire(u64),
}

#[derive(Copy, Clone, PartialEq, Eq)]
enum Origin {
    Spawned,
    FirstTouch,
    Stray,
    Explicit,
}

#[derive(Copy, Clone)]
enum State {
    Running,
    Blocked {
        deadline: Option<u64>,
        wait: &'static str,
        cell: usize,
        timer: u64,
    },
}

struct Participant {
    name: Arc<str>,
    origin: Origin,
    state: State,
    thread: Option<std::thread::ThreadId>,
    last_wait: Option<&'static str>,
    since_v: u64,
    since_w: WallInstant,
}

struct Lease {
    label: &'static str,
    holder: std::thread::ThreadId,
    since_v: u64,
    since_w: WallInstant,
}

#[derive(Default)]
pub(crate) struct Inner {
    generation: u64,
    parts: BTreeMap<u64, Participant>,
    leases: BTreeMap<u64, Lease>,
    next_id: u64,
    runnable: u32,
    blocked: u32,
    epoch: u64,
    deferred: Vec<Arc<ParkCell>>,
    stray_wakes: u64,
    strays: Vec<Arc<str>>,
    hints: VecDeque<(Arc<str>, f32)>,
    violations: VecDeque<QuiescenceViolation>,
    violation_count: u64,
    class_effects: VecDeque<ClassEffect>,
    class_effect_count: u64,
    setup_effect_count: u64,
    armed: Option<Notify>,
    fire: Option<Notify>,
}

impl Inner {
    fn bump(&mut self) {
        self.epoch = self.epoch.wrapping_add(1);
        if let Some(f) = self.armed.take() {
            self.fire = Some(f);
        }
    }

    fn add(&mut self, name: Arc<str>, origin: Origin, now_v: u64) -> u64 {
        self.next_id += 1;
        let pid = self.next_id;
        let thread = (origin != Origin::Spawned).then(|| std::thread::current().id());
        self.parts.insert(
            pid,
            Participant {
                name,
                origin,
                state: State::Running,
                thread,
                last_wait: None,
                since_v: now_v,
                since_w: WallInstant::now(),
            },
        );
        self.runnable += 1;
        self.bump();
        pid
    }

    fn remove(&mut self, pid: u64) {
        if let Some(p) = self.parts.remove(&pid) {
            match p.state {
                State::Running => self.runnable -= 1,
                State::Blocked { .. } => self.blocked -= 1,
            }
            self.bump();
        }
    }

    fn set_state(&mut self, pid: u64, state: State, now_v: u64) {
        let Some(p) = self.parts.get_mut(&pid) else {
            return;
        };
        match (p.state, state) {
            (State::Running, State::Blocked { .. }) => {
                self.runnable -= 1;
                self.blocked += 1;
            }
            (State::Blocked { wait, .. }, State::Running) => {
                self.blocked -= 1;
                self.runnable += 1;
                p.last_wait = Some(wait);
            }
            _ => {}
        }
        p.state = state;
        p.since_v = now_v;
        p.since_w = WallInstant::now();
        self.bump();
    }

    fn blocked_on(&self, pid: u64, cell: usize, kind: &WakeKind) -> bool {
        self.parts.get(&pid).is_some_and(|p| match p.state {
            State::Blocked { cell: c, timer, .. } => {
                c == cell
                    && match kind {
                        WakeKind::Unpark => true,
                        WakeKind::Fire(t) => *t == timer,
                    }
            }
            State::Running => false,
        })
    }

    fn holds_lease(&self, t: std::thread::ThreadId) -> bool {
        self.leases.values().any(|l| l.holder == t)
    }

    fn violation(&mut self, thread: Arc<str>, op: &'static str, blocked: bool, now_v: u64) {
        self.push_violation(QuiescenceViolation {
            thread,
            op,
            blocked,
            fatal: false,
            at: Duration::from_nanos(now_v),
        });
    }

    fn push_violation(&mut self, v: QuiescenceViolation) {
        self.violation_count += 1;
        if self.violations.len() == MAX_VIOLATIONS {
            self.violations.pop_front();
        }
        self.violations.push_back(v);
    }

    fn class_effect(&mut self, class: ThreadClass, op: &'static str, now_v: u64) {
        if super::in_setup() {
            self.setup_effect_count += 1;
            return;
        }
        self.class_effect_count += 1;
        if self.class_effects.len() == MAX_CLASS_EFFECTS {
            self.class_effects.pop_front();
        }
        let thread = match super::class_label() {
            Some(l) => Arc::from(l),
            None => thread_name(&std::thread::current()),
        };
        self.class_effects.push_back(ClassEffect {
            thread,
            class,
            op,
            at: Duration::from_nanos(now_v),
        });
    }

    fn part_by_thread(&self, t: std::thread::ThreadId) -> Option<&Participant> {
        self.parts.values().find(|p| p.thread == Some(t))
    }
}

/// Holds the registry lock; runs a pending activity notification after the
/// lock is released.
pub(crate) struct RegGuard<'a> {
    guard: Option<MutexGuard<'a, Inner>>,
}

impl Deref for RegGuard<'_> {
    type Target = Inner;
    fn deref(&self) -> &Inner {
        self.guard.as_ref().expect("registry guard")
    }
}

impl DerefMut for RegGuard<'_> {
    fn deref_mut(&mut self) -> &mut Inner {
        self.guard.as_mut().expect("registry guard")
    }
}

impl Drop for RegGuard<'_> {
    fn drop(&mut self) {
        let notify = self.guard.as_mut().and_then(|g| g.fire.take());
        self.guard = None;
        if let Some(f) = notify {
            f();
        }
    }
}

pub(crate) struct Registry {
    inner: Mutex<Inner>,
    timers: Arc<Timers<Clock>>,
    generation: AtomicU64,
    accounting: AtomicBool,
    audit: AtomicBool,
    attached: AtomicBool,
}

impl Registry {
    pub(crate) fn new(timers: Arc<Timers<Clock>>) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Inner::default()),
            timers,
            generation: AtomicU64::new(0),
            accounting: AtomicBool::new(false),
            audit: AtomicBool::new(false),
            attached: AtomicBool::new(false),
        })
    }

    pub(crate) fn lock(&self) -> RegGuard<'_> {
        super::note_lock();
        RegGuard {
            guard: Some(self.inner.lock()),
        }
    }

    fn now(&self) -> u64 {
        self.timers.source().now()
    }

    fn accounting(&self) -> bool {
        self.accounting.load(Ordering::Acquire)
    }

    pub(crate) fn attach(&self, accounting: bool, audit: bool) {
        let mut g = self.lock();
        let generation = g.generation + 1;
        *g = Inner {
            generation,
            epoch: g.epoch.wrapping_add(1),
            next_id: g.next_id,
            ..Inner::default()
        };
        self.generation.store(generation, Ordering::Release);
        if accounting && !self.accounting.swap(true, Ordering::AcqRel) {
            ACCOUNTING.fetch_add(1, Ordering::AcqRel);
        }
        if audit && !self.audit.swap(true, Ordering::AcqRel) {
            AUDITING.fetch_add(1, Ordering::AcqRel);
        }
        if !self.attached.swap(true, Ordering::AcqRel) {
            ATTACHED.fetch_add(1, Ordering::AcqRel);
        }
    }

    pub(crate) fn detach(&self) {
        let cells = {
            let mut g = self.lock();
            if self.accounting.swap(false, Ordering::AcqRel) {
                ACCOUNTING.fetch_sub(1, Ordering::AcqRel);
            }
            if self.audit.swap(false, Ordering::AcqRel) {
                AUDITING.fetch_sub(1, Ordering::AcqRel);
            }
            if self.attached.swap(false, Ordering::AcqRel) {
                ATTACHED.fetch_sub(1, Ordering::AcqRel);
            }
            g.generation += 1;
            self.generation.store(g.generation, Ordering::Release);
            g.parts.clear();
            g.leases.clear();
            g.runnable = 0;
            g.blocked = 0;
            g.hints.clear();
            g.armed = None;
            g.bump();
            g.fire = None;
            std::mem::take(&mut g.deferred)
        };
        for cell in cells {
            cell.raw_unpark();
        }
    }

    fn register(self: &Arc<Self>, name: Arc<str>, origin: Origin) -> Option<Member> {
        let now = self.now();
        let mut g = self.lock();
        if !self.accounting() {
            return None;
        }
        let pid = g.add(name, origin, now);
        Some(Member {
            reg: Arc::clone(self),
            generation: g.generation,
            pid,
        })
    }

    fn exit(&self, generation: u64, pid: u64) {
        let mut g = self.lock();
        if g.generation == generation {
            g.remove(pid);
        }
    }

    fn rename(&self, generation: u64, pid: u64, name: Option<Arc<str>>, origin: Option<Origin>) {
        let mut g = self.lock();
        if g.generation != generation {
            return;
        }
        if let Some(p) = g.parts.get_mut(&pid) {
            if let Some(n) = name {
                p.name = n;
            }
            if let Some(o) = origin {
                p.origin = o;
            }
            p.thread = Some(std::thread::current().id());
        }
    }

    /// Park the participant `link` on `cell` until it is woken or `deadline`
    /// (virtual ns) passes.
    pub(crate) fn park(
        self: &Arc<Self>,
        link: &Link,
        cell: &Arc<ParkCell>,
        deadline: Option<u64>,
        wait: &'static str,
        consume_woken: bool,
    ) -> ParkResult {
        let ptr = cell_ptr(cell);
        let id = {
            let now = self.now();
            let mut g = self.lock();
            if g.generation != link.generation || !g.parts.contains_key(&link.pid) {
                drop(g);
                return super::park::wait_plain(cell, deadline, consume_woken);
            }
            {
                let mut s = cell.lock_state();
                if !s.link.as_ref().is_some_and(|l| l.same(link)) {
                    s.link = Some(link.clone());
                }
                s.running = false;
                if consume_woken && std::mem::take(&mut s.woken) {
                    return ParkResult::Unparked;
                }
            }
            if deadline.is_some_and(|d| now >= d) {
                return ParkResult::TimedOut;
            }
            let id = deadline
                .map(|d| self.timers.insert(d, TimerTarget::Park(Arc::clone(cell))))
                .unwrap_or(0);
            let state = State::Blocked {
                deadline,
                wait,
                cell: ptr,
                timer: id,
            };
            g.set_state(link.pid, state, now);
            id
        };
        let (wake, running) = cell.wait_participant(id);
        let result = match wake {
            ParkWake::Fired => ParkResult::TimedOut,
            ParkWake::Unparked => {
                if id != 0 {
                    self.timers.cancel(id);
                }
                ParkResult::Unparked
            }
        };
        if !running {
            let mut g = self.lock();
            if g.generation == link.generation && g.blocked_on(link.pid, ptr, &WakeKind::Unpark) {
                let now = self.now();
                g.set_state(link.pid, State::Running, now);
            }
        }
        result
    }

    /// Move the participant of `link` to running if it is blocked on `cell`
    /// for `kind`. Returns whether it moved.
    fn transfer(&self, g: &mut Inner, link: &Link, cell: &ParkCell, kind: &WakeKind) -> bool {
        let moved = g.generation == link.generation && g.blocked_on(link.pid, cell_ptr(cell), kind);
        if moved {
            g.set_state(link.pid, State::Running, self.now());
        }
        moved
    }

    /// Wake `cell` (tied to `link`), moving its participant to runnable first.
    pub(crate) fn wake(self: &Arc<Self>, link: &Link, cell: &ParkCell, kind: WakeKind) {
        let installed = {
            let mut g = self.lock();
            let installed = match kind {
                WakeKind::Unpark => self.account_caller(&mut g, "unpark", true),
                WakeKind::Fire(_) => None,
            };
            let moved = self.transfer(&mut g, link, cell, &kind);
            match kind {
                WakeKind::Unpark => cell.mark_unparked(moved),
                WakeKind::Fire(t) => cell.mark_fired(t, moved),
            }
            installed
        };
        cell.notify();
        if let Some(m) = installed {
            install_member(m);
        }
    }

    /// Check the calling thread before a snare-visible effect. Records an
    /// audit violation for a blocked participant or an unknown thread with no
    /// lease; with `register`, an unknown thread is also registered as a
    /// running stray participant, returned for installing once the lock is
    /// released.
    pub(super) fn account_caller(
        self: &Arc<Self>,
        g: &mut Inner,
        op: &'static str,
        register: bool,
    ) -> Option<Member> {
        if !self.attached.load(Ordering::Acquire) || is_driver_thread() {
            return None;
        }
        let audit = self.audit.load(Ordering::Acquire);
        let accounting = self.accounting();
        if !audit && !accounting {
            return None;
        }
        let now = self.now();
        if let Some(class) = classified() {
            if accounting {
                g.class_effect(class, op, now);
            }
            return None;
        }
        let me = std::thread::current();
        if let Some(pid) = current_pid(self, g.generation) {
            let blocked = g
                .parts
                .get(&pid)
                .is_some_and(|p| matches!(p.state, State::Blocked { .. }));
            if audit && blocked {
                let name = g.parts[&pid].name.clone();
                g.violation(name, op, true, now);
            }
            return None;
        }
        if g.holds_lease(me.id()) {
            return None;
        }
        let name = thread_name(&me);
        if audit {
            g.violation(name.clone(), op, false, now);
        }
        if !(register && accounting) {
            return None;
        }
        g.stray_wakes += 1;
        if !g.strays.contains(&name) {
            g.strays.push(name.clone());
        }
        let pid = g.add(name, Origin::Stray, now);
        Some(Member {
            reg: Arc::clone(self),
            generation: g.generation,
            pid,
        })
    }

    /// Every timer taken off the heap has been delivered, which can make the
    /// domain quiescent without any participant changing state.
    pub(crate) fn timers_settled(&self) {
        if self.attached.load(Ordering::Acquire) {
            self.lock().bump();
        }
    }

    fn defer(&self, cell: &Arc<ParkCell>) -> bool {
        if !self.attached.load(Ordering::Acquire) {
            return false;
        }
        let mut g = self.lock();
        g.deferred.push(Arc::clone(cell));
        g.bump();
        true
    }

    /// Deliver every wake deferred during a timestamp.
    pub(crate) fn flush_deferred(self: &Arc<Self>) {
        let mut foreign = Vec::new();
        let mut woken = Vec::new();
        {
            let mut g = self.lock();
            let cells = std::mem::take(&mut g.deferred);
            if !cells.is_empty() {
                g.bump();
            }
            for cell in cells {
                {
                    let mut s = cell.lock_state();
                    let moved = match &s.link {
                        Some(l) if Arc::ptr_eq(&l.reg, self) => {
                            self.transfer(&mut g, l, &cell, &WakeKind::Unpark)
                        }
                        Some(_) => {
                            drop(s);
                            foreign.push(cell);
                            continue;
                        }
                        None => false,
                    };
                    s.woken = true;
                    s.running |= moved;
                }
                woken.push(cell);
            }
        }
        for cell in woken {
            cell.notify();
        }
        for cell in foreign {
            cell.unpark();
        }
    }

    /// What holds the domain back, and the earliest pending deadline.
    fn block_locked<'a>(&self, g: &'a Inner) -> (Option<Block<'a>>, Option<u64>) {
        let now = self.now();
        let (next, firing) = self.timers.next_deadline_and_firing();
        let due = firing || next.is_some_and(|d| d <= now);
        let running = (g.runnable != 0)
            .then(|| g.parts.values().find(|p| matches!(p.state, State::Running)))
            .flatten();
        let block = if !self.accounting() {
            Some(Block::Untracked)
        } else if let Some(p) = running {
            Some(Block::Running(p))
        } else if let Some(l) = g.leases.values().next() {
            Some(Block::Lease(l.label))
        } else if !g.deferred.is_empty() {
            Some(Block::Deferred)
        } else if due {
            Some(Block::TimerDue)
        } else {
            None
        };
        (block, next)
    }

    fn quiescence_locked(&self, g: &Inner) -> Quiescence {
        let (block, next) = self.block_locked(g);
        Quiescence {
            quiescent: block.is_none(),
            epoch: g.epoch,
            runnable: g.runnable,
            busy: g.leases.len() as u32,
            blocked: g.blocked,
            next_deadline: next.map(Duration::from_nanos),
            blocker: block.as_ref().map(Block::describe),
        }
    }

    pub(crate) fn quiescence(&self) -> Quiescence {
        let g = self.lock();
        self.quiescence_locked(&g)
    }

    /// Move the clock to `t - 1ns` iff the domain is quiescent and no timer
    /// is due before `t`, checked under the lock.
    pub(crate) fn enter_checked(&self, t: u64) -> Result<(), NotQuiescent> {
        let g = self.lock();
        let (block, next) = self.block_locked(&g);
        if block.is_some() || next.is_some_and(|d| d < t) {
            return Err(NotQuiescent);
        }
        self.timers.source().jump(t.saturating_sub(1));
        Ok(())
    }

    /// Move the clock to `t`, or to the earliest pending deadline if that
    /// comes first, iff the domain is quiescent under the lock.
    pub(crate) fn jump(&self, t: u64) -> Result<Vec<(u64, TimerTarget)>, NotQuiescent> {
        let g = self.lock();
        let (block, next) = self.block_locked(&g);
        if block.is_some() {
            return Err(NotQuiescent);
        }
        let landing = next.map_or(t, |d| t.min(d));
        let src = self.timers.source();
        Ok(self.timers.advance_and_take(|| src.jump(landing)).1)
    }

    pub(crate) fn arm(&self, seen_epoch: u64, f: Notify) {
        let mut g = self.lock();
        if g.epoch != seen_epoch {
            g.fire = Some(f);
        } else {
            g.armed = Some(f);
        }
    }

    pub(crate) fn lease(self: &Arc<Self>, label: &'static str) -> Option<(u64, u64)> {
        if !self.attached.load(Ordering::Acquire) {
            return None;
        }
        let now = self.now();
        let mut g = self.lock();
        if let Some(class) = classified()
            && self.accounting()
        {
            g.class_effect(class, "busy", now);
        }
        g.next_id += 1;
        let id = g.next_id;
        g.leases.insert(
            id,
            Lease {
                label,
                holder: std::thread::current().id(),
                since_v: now,
                since_w: WallInstant::now(),
            },
        );
        g.bump();
        Some((g.generation, id))
    }

    pub(crate) fn release(&self, generation: u64, id: u64) {
        let mut g = self.lock();
        if g.generation == generation && g.leases.remove(&id).is_some() {
            g.bump();
        }
    }

    pub(crate) fn hint(&self, source: &str, severity: f32) {
        if !self.attached.load(Ordering::Acquire) {
            return;
        }
        let mut g = self.lock();
        if g.hints.len() == MAX_HINTS {
            g.hints.pop_front();
        }
        g.hints.push_back((Arc::from(source), severity));
    }

    pub(crate) fn drain_hints(&self) -> Vec<(Arc<str>, f32)> {
        self.lock().hints.drain(..).collect()
    }

    pub(crate) fn participants(&self) -> Vec<ParticipantInfo> {
        let g = self.lock();
        let now = self.now();
        let since = |v: u64| Duration::from_nanos(now.saturating_sub(v));
        let leases_of = |t: Option<std::thread::ThreadId>| -> Vec<&'static str> {
            t.map(|t| {
                g.leases
                    .values()
                    .filter(|l| l.holder == t)
                    .map(|l| l.label)
                    .collect()
            })
            .unwrap_or_default()
        };
        let threads = g.parts.iter().map(|(&id, p)| {
            let (state, deadline, wait) = match p.state {
                State::Running => (PState::Running, None, None),
                State::Blocked { deadline, wait, .. } => (
                    PState::Blocked,
                    deadline.map(Duration::from_nanos),
                    Some(wait),
                ),
            };
            ParticipantInfo {
                id,
                name: p.name.clone(),
                state,
                stray: p.origin == Origin::Stray,
                since_virtual: since(p.since_v),
                since_wall: p.since_w.elapsed(),
                deadline,
                wait,
                last_wait: p.last_wait,
                leases: leases_of(p.thread),
            }
        });
        let leases = g.leases.iter().map(|(&id, l)| ParticipantInfo {
            id,
            name: Arc::from(l.label),
            state: PState::Busy(l.label),
            stray: false,
            since_virtual: since(l.since_v),
            since_wall: l.since_w.elapsed(),
            deadline: None,
            wait: None,
            last_wait: None,
            leases: Vec::new(),
        });
        threads.chain(leases).collect()
    }

    /// Whether the thread `t` is currently a participant.
    pub(crate) fn has_thread(&self, t: std::thread::ThreadId) -> bool {
        self.lock().part_by_thread(t).is_some()
    }

    pub(crate) fn held_leases(&self) -> Vec<(&'static str, Option<Arc<str>>)> {
        let g = self.lock();
        g.leases
            .values()
            .map(|l| (l.label, g.part_by_thread(l.holder).map(|p| p.name.clone())))
            .collect()
    }

    /// Record a snare effect by a background or helper thread.
    fn note_class(&self, class: ThreadClass, op: &'static str) {
        if !self.attached.load(Ordering::Acquire) || !self.accounting() {
            return;
        }
        let now = self.now();
        self.lock().class_effect(class, op, now);
    }

    pub(crate) fn timers(&self, n: usize) -> Vec<TimerInfo> {
        let entries = self.timers.snapshot(n);
        let owners: Vec<Option<Link>> = entries
            .iter()
            .map(|(_, cell)| cell.as_ref().and_then(|c| c.lock_state().link.clone()))
            .collect();
        let g = self.lock();
        entries
            .into_iter()
            .zip(owners)
            .map(|((deadline, _), link)| TimerInfo {
                deadline: Duration::from_nanos(deadline),
                owner: link
                    .filter(|l| l.generation == g.generation)
                    .and_then(|l| g.parts.get(&l.pid).map(|p| p.name.clone())),
            })
            .collect()
    }

    pub(crate) fn audit_report(&self) -> AuditReport {
        let g = self.lock();
        AuditReport {
            stray_wakes: g.stray_wakes,
            strays: g.strays.clone(),
            violations: g.violations.iter().cloned().collect(),
            total_violations: g.violation_count,
            class_effects: g.class_effects.iter().cloned().collect(),
            total_class_effects: g.class_effect_count,
            total_setup_effects: g.setup_effect_count,
            unknown_threads: Vec::new(),
        }
    }

    /// Record a fatal violation `op` by the calling thread.
    pub(super) fn fatal_violation(&self, op: &'static str) {
        let at = Duration::from_nanos(self.now());
        let thread = thread_name(&std::thread::current());
        self.lock().push_violation(QuiescenceViolation {
            thread,
            op,
            blocked: false,
            fatal: true,
            at,
        });
    }

    pub(super) fn is_auditing(&self) -> bool {
        self.audit.load(Ordering::Acquire)
    }
}

/// The calling thread's membership in one registry. Dropping it (thread
/// exit, guard drop, driver-thread marking) removes the participant.
pub(crate) struct Member {
    reg: Arc<Registry>,
    generation: u64,
    pid: u64,
}

impl Member {
    fn link(&self) -> Link {
        Link {
            reg: Arc::clone(&self.reg),
            generation: self.generation,
            pid: self.pid,
        }
    }
}

impl Drop for Member {
    fn drop(&mut self) {
        self.reg.exit(self.generation, self.pid);
    }
}

/// A participant registered by a spawning thread for the child it is about
/// to start. Dropped without [`Handoff::install`] (a failed spawn), the
/// participant is removed again.
pub(crate) struct Handoff(Member);

impl Handoff {
    pub(crate) fn install(self) {
        let me = std::thread::current();
        let name = me.name().is_some().then(|| thread_name(&me));
        self.0.reg.rename(self.0.generation, self.0.pid, name, None);
        install_member(self.0);
    }
}

fn cell_ptr(cell: &ParkCell) -> usize {
    cell as *const ParkCell as usize
}

fn thread_name(t: &std::thread::Thread) -> Arc<str> {
    match t.name() {
        Some(n) => Arc::from(n),
        None => Arc::from(format!("{:?}", t.id())),
    }
}

fn install_member(m: Member) {
    let old = MEMBER.try_with(|c| c.borrow_mut().replace(m));
    drop(old);
    crate::threads::register_current();
}

fn current_pid(reg: &Arc<Registry>, generation: u64) -> Option<u64> {
    MEMBER
        .try_with(|c| {
            c.borrow()
                .as_ref()
                .filter(|m| Arc::ptr_eq(&m.reg, reg) && m.generation == generation)
                .map(|m| m.pid)
        })
        .ok()
        .flatten()
}

fn accounting_reg() -> Option<Arc<Registry>> {
    if is_driver_thread() || classified().is_some() {
        return None;
    }
    slot_accounting_reg()
}

/// Whether an accounting driver owns the calling thread's clock.
pub(crate) fn accounting_here() -> bool {
    with_accounting_reg(|_| ()).is_some()
}

/// Whether a deadline the calling thread waits on belongs in the foreign
/// heap: an accounting driver owns the thread's clock and the thread is
/// outside the simulation, so its timers must never decide where virtual
/// time goes.
pub(crate) fn foreign_here() -> bool {
    !is_driver_thread() && classified().is_some() && accounting_here()
}

/// A thread that is not a participant added a domain timer. Nothing else
/// would tell a driver waiting for activity that its next deadline moved,
/// so bump the epoch.
pub(crate) fn foreign_timer_added() {
    if is_driver_thread() || is_participant() {
        return;
    }
    if let Some(reg) = slot_accounting_reg() {
        reg.timers_settled();
    }
}

/// Record a snare effect (`op`) by the calling thread if it is a background
/// or helper thread under an accounting driver.
pub(crate) fn class_effect(op: &'static str) {
    let Some(class) = classified() else {
        return;
    };
    if let Some(reg) = slot_accounting_reg() {
        reg.note_class(class, op);
    }
}

fn slot_accounting_reg() -> Option<Arc<Registry>> {
    with_accounting_reg(Arc::clone)
}

/// Run `f` on the calling thread's slot registry if an accounting driver
/// owns it.
fn with_accounting_reg<R>(f: impl FnOnce(&Arc<Registry>) -> R) -> Option<R> {
    if ACCOUNTING.load(Ordering::Acquire) == 0 {
        return None;
    }
    try_with_slot(|s| s.reg().accounting().then(|| f(s.reg()))).flatten()
}

/// The calling thread's participant link, registering it (first blocking
/// touch) if accounting is on and it is not yet a participant. `None` when
/// the thread is not accounted.
pub(crate) fn member_link() -> Option<Link> {
    if is_driver_thread() || classified().is_some() {
        return None;
    }
    let existing = with_accounting_reg(|reg| {
        let generation = reg.generation.load(Ordering::Acquire);
        MEMBER
            .try_with(|c| {
                c.borrow()
                    .as_ref()
                    .filter(|m| Arc::ptr_eq(&m.reg, reg) && m.generation == generation)
                    .map(Member::link)
            })
            .ok()
            .flatten()
    })?;
    if existing.is_some() {
        return existing;
    }
    let reg = slot_accounting_reg()?;
    let member = reg.register(thread_name(&std::thread::current()), Origin::FirstTouch)?;
    let link = member.link();
    install_member(member);
    Some(link)
}

/// Register the calling thread explicitly. Returns the participant id, or 0
/// if accounting is off.
pub(crate) fn participate(name: &str) -> u64 {
    let Some(reg) = accounting_reg() else {
        return 0;
    };
    let generation = reg.generation.load(Ordering::Acquire);
    if let Some(pid) = current_pid(&reg, generation) {
        reg.rename(
            generation,
            pid,
            Some(Arc::from(name)),
            Some(Origin::Explicit),
        );
        return pid;
    }
    match reg.register(Arc::from(name), Origin::Explicit) {
        Some(m) => {
            let pid = m.pid;
            install_member(m);
            pid
        }
        None => 0,
    }
}

/// End the calling thread's participation if its participant id is `pid`.
pub(crate) fn leave(pid: u64) {
    let old = MEMBER.try_with(|c| {
        let mut c = c.borrow_mut();
        if c.as_ref().is_some_and(|m| m.pid == pid) {
            c.take()
        } else {
            None
        }
    });
    drop(old);
}

/// End the calling thread's participation, whatever it is.
pub(crate) fn leave_current() {
    let old = MEMBER.try_with(|c| c.borrow_mut().take());
    drop(old);
}

pub(crate) fn is_participant() -> bool {
    MEMBER
        .try_with(|c| {
            c.borrow()
                .as_ref()
                .is_some_and(|m| m.generation == m.reg.generation.load(Ordering::Acquire))
        })
        .unwrap_or(false)
}

/// Register the child of a spawn as running before the OS thread exists.
pub(crate) fn handoff(name: Option<&str>) -> Option<Handoff> {
    let reg = slot_accounting_reg()?;
    let name: Arc<str> = Arc::from(name.unwrap_or("thread"));
    reg.register(name, Origin::Spawned).map(Handoff)
}

/// Queue `cell`'s wake if the calling thread is inside a driver timestamp.
pub(crate) fn defer_wake(cell: &Arc<ParkCell>) -> bool {
    let reg = DEFER.try_with(|d| d.borrow().clone()).ok().flatten();
    reg.is_some_and(|r| r.defer(cell))
}

pub(crate) fn set_defer(reg: Option<Arc<Registry>>) -> Option<Arc<Registry>> {
    DEFER
        .try_with(|d| std::mem::replace(&mut *d.borrow_mut(), reg))
        .ok()
        .flatten()
}
