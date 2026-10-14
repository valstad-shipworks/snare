//! The child processes the domains' threads make, and the process's real `SIGCHLD`.
//!
//! A domain delivers `SIGCHLD` for a child its threads made itself ([`crate::deliver_child_exit`]),
//! on a thread of its own, so the kernel's `SIGCHLD` for that child must reach no handler: it
//! lands on whichever thread of the process the kernel picks, often one outside every domain,
//! and would run the handler a second time. Once any domain has made a child, or the code under
//! test in one has installed a `SIGCHLD` handler, the process's real action is [`on_sigchld`]
//! whenever a handler is due: it notes the end of a domain's child (its `si_code` and
//! `si_status`) and drops the signal, and hands any other child's to the process's own action,
//! which a `sigaction` made outside every domain sets in its place ([`outside_sigaction`]). With
//! that action at `SIG_DFL` it hands it to the handler the code under test last installed in a
//! domain instead: a library that installs its dispatcher once per process (signal-hook-registry,
//! and so `tokio::process`) does it in whichever domain first needs it, and the process's own
//! children still reach it.
//!
//! The domains' children are kept in a fixed table the handler reads without locking (man 7
//! signal-safety): a slot per child, its pid and, once known, how it ended.

use std::ffi::c_int;
use std::sync::Mutex;
use std::sync::atomic::{AtomicI32, AtomicU64, AtomicUsize, Ordering};

use crate::signals::ChildExit;
use crate::state::Passthrough;

/// How many children of the domains the table follows at once; a child past that is not followed,
/// so the kernel's `SIGCHLD` for it is not dropped. A snare choice.
const SLOTS: usize = 512;

/// A child of a domain: its pid (0 for a free slot) and its end, packed by [`pack`] (0 until
/// known).
struct Slot {
    pid: AtomicI32,
    exit: AtomicU64,
}

static TABLE: [Slot; SLOTS] = [const {
    Slot {
        pid: AtomicI32::new(0),
        exit: AtomicU64::new(0),
    }
}; SLOTS];

/// How many slots are taken: lets the wait hooks skip the table while no domain has a child.
static TAKEN: AtomicUsize = AtomicUsize::new(0);

/// The process's own `SIGCHLD` action as the code outside every domain set it, once
/// [`on_sigchld`] may stand in for it; `None` before.
static OWN: Mutex<Option<libc::sigaction>> = Mutex::new(None);
/// `OWN`'s handler word and flags, for [`on_sigchld`] to read without locking.
static OWN_HANDLER: AtomicUsize = AtomicUsize::new(libc::SIG_DFL);
static OWN_FLAGS: AtomicI32 = AtomicI32::new(0);
/// The `SIGCHLD` handler the code under test last installed in any domain (`SIG_DFL` for none),
/// and its flags and mask.
static DOMAINS: Mutex<Option<libc::sigaction>> = Mutex::new(None);
static DOMAINS_HANDLER: AtomicUsize = AtomicUsize::new(libc::SIG_DFL);
static DOMAINS_FLAGS: AtomicI32 = AtomicI32::new(0);

/// A child's end as a slot holds it: a set top bit, `si_code` in bits 32..40, `si_status` below.
fn pack(code: c_int, status: c_int) -> u64 {
    1 << 63 | u64::from(code as u8) << 32 | u64::from(status as u32)
}

fn unpack(word: u64) -> Option<(c_int, c_int)> {
    (word >> 63 == 1).then_some((((word >> 32) & 0xff) as c_int, word as u32 as c_int))
}

fn slot_of(pid: libc::pid_t) -> Option<&'static Slot> {
    if pid <= 0 || TAKEN.load(Ordering::Acquire) == 0 {
        return None;
    }
    TABLE.iter().find(|slot| slot.pid.load(Ordering::Acquire) == pid)
}

fn is_handler(handler: usize) -> bool {
    handler != libc::SIG_DFL && handler != libc::SIG_IGN
}

/// Follows `pid`, a child a thread of a domain made: the kernel's `SIGCHLD` for it is dropped from
/// now on, its end noted for [`exit_of`]. A slot is let go once its child has been reaped, when a
/// later child is adopted: by then the kernel's `SIGCHLD` for it has long been handled.
pub fn adopt(pid: libc::pid_t) {
    sweep();
    if let Some(slot) = slot_of(pid) {
        slot.exit.store(0, Ordering::Release);
    } else if let Some(slot) = TABLE.iter().find(|slot| {
        slot.pid
            .compare_exchange(0, pid, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
    }) {
        slot.exit.store(0, Ordering::Release);
        TAKEN.fetch_add(1, Ordering::AcqRel);
    }
    stand_in();
}

/// Whether `pid` is a child of a domain's the table follows.
pub(crate) fn followed(pid: libc::pid_t) -> bool {
    slot_of(pid).is_some()
}

/// Lets go of the slots of children already reaped.
fn sweep() {
    if TAKEN.load(Ordering::Acquire) == 0 {
        return;
    }
    let _passthrough = Passthrough::enter();
    for slot in &TABLE {
        let pid = slot.pid.load(Ordering::Acquire);
        if pid != 0
            && !exists(pid)
            && slot
                .pid
                .compare_exchange(pid, 0, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
        {
            TAKEN.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

/// Whether `pid` is still a child of the process, running or not yet reaped (man 2 waitid:
/// `WNOWAIT` leaves it to be reaped, `WNOHANG` returns at once for one still running).
fn exists(pid: libc::pid_t) -> bool {
    // SAFETY: zeroed is a valid siginfo_t, which waitid fills.
    unsafe {
        let mut info: libc::siginfo_t = std::mem::zeroed();
        libc::waitid(
            libc::P_PID,
            pid as libc::id_t,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        ) == 0
    }
}

/// The process's children of the kind `idtype` and `id` name, as waitid(2) names them, running or
/// not yet reaped: all of them (`P_ALL`), one (`P_PID`), or a process group's (`P_PGID`). Empty
/// where the OS does not list them.
pub(crate) fn of_process(idtype: libc::idtype_t, id: libc::id_t) -> Vec<libc::pid_t> {
    let mut children = listed();
    children.retain(|&pid| match idtype {
        libc::P_ALL => true,
        libc::P_PID => pid as libc::id_t == id,
        // SAFETY: no pointers.
        _ => (unsafe { libc::getpgid(pid) }) as libc::id_t == id,
    });
    children
}

/// Every child of the process: Linux lists each thread's in /proc/self/task/<tid>/children
/// (man 5 proc_pid_task; a kernel built with `CONFIG_PROC_CHILDREN`).
#[cfg(target_os = "linux")]
fn listed() -> Vec<libc::pid_t> {
    let Ok(tasks) = std::fs::read_dir("/proc/self/task") else {
        return Vec::new();
    };
    let mut children = Vec::new();
    for task in tasks.flatten() {
        if let Ok(text) = std::fs::read_to_string(task.path().join("children")) {
            children.extend(text.split_ascii_whitespace().filter_map(|pid| pid.parse::<libc::pid_t>().ok()));
        }
    }
    children
}

/// Every child of the process, as libproc's `proc_listchildpids` lists them, by count.
#[cfg(target_os = "macos")]
fn listed() -> Vec<libc::pid_t> {
    let mut children: Vec<libc::pid_t> = vec![0; 64];
    loop {
        let room = (children.len() * size_of::<libc::pid_t>()) as c_int;
        // SAFETY: `children` has room for `room` bytes; getpid has no preconditions.
        let n = unsafe {
            libc::proc_listchildpids(libc::getpid(), children.as_mut_ptr().cast(), room)
        };
        if n < 0 {
            return Vec::new();
        }
        if (n as usize) < children.len() {
            children.truncate(n as usize);
            return children;
        }
        children.resize(children.len() * 2, 0);
    }
}

/// Whether a wait for the children `idtype` and `id` name returns at once: one of them has exited
/// (waitid(2) with `WNOWAIT` leaves it to be reaped), or none is left (`ECHILD`).
pub(crate) fn reapable(idtype: libc::idtype_t, id: libc::id_t) -> bool {
    // SAFETY: zeroed is a valid siginfo_t, which waitid fills.
    unsafe {
        let mut info: libc::siginfo_t = std::mem::zeroed();
        libc::waitid(
            idtype,
            id,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        ) != 0
            || info.si_pid() != 0
    }
}

/// The end of followed child `pid` as the kernel's `SIGCHLD` or a reaping wait reported it, if
/// either has yet.
pub fn exit_of(pid: libc::pid_t, uid: libc::uid_t) -> Option<ChildExit> {
    let (code, status) = unpack(slot_of(pid)?.exit.load(Ordering::Acquire))?;
    Some(ChildExit {
        pid,
        uid,
        code,
        status,
    })
}

/// Notes the end of `pid`, if it is a followed child, as a wait reaped it: `status` as wait(2)
/// reports it.
pub(crate) fn reaped(pid: libc::pid_t, status: c_int) {
    if let Some(slot) = slot_of(pid)
        && let Some(exit) = ChildExit::from_wait_status(pid, 0, status)
    {
        slot.exit.store(pack(exit.code, exit.status), Ordering::Release);
    }
}

/// Notes the end of `pid`, if it is a followed child, as waitid(2) reaped it.
pub(crate) fn reaped_info(pid: libc::pid_t, code: c_int, status: c_int) {
    if matches!(code, libc::CLD_EXITED | libc::CLD_KILLED | libc::CLD_DUMPED)
        && let Some(slot) = slot_of(pid)
    {
        slot.exit.store(pack(code, status), Ordering::Release);
    }
}

/// The process's own `SIGCHLD` action: the one outside code set, even while [`on_sigchld`]
/// stands in for it.
pub fn process_action() -> libc::sigaction {
    let _passthrough = Passthrough::enter();
    if let Some(mut own) = *OWN.lock().unwrap_or_else(|e| e.into_inner()) {
        own.sa_sigaction = OWN_HANDLER.load(Ordering::Acquire);
        return own;
    }
    // SAFETY: a query only fills `old` (man 2 sigaction).
    unsafe {
        let mut old: libc::sigaction = std::mem::zeroed();
        libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut old);
        old
    }
}

/// Records `action` as the `SIGCHLD` handler the code under test last installed in a domain
/// (`SIG_DFL` or `SIG_IGN` for none), for the process's own children while its own action is
/// `SIG_DFL`.
pub fn set_domains_action(action: &libc::sigaction) {
    {
        let _passthrough = Passthrough::enter();
        let mut domains = DOMAINS.lock().unwrap_or_else(|e| e.into_inner());
        *domains = Some(*action);
        DOMAINS_FLAGS.store(action.sa_flags, Ordering::Release);
        DOMAINS_HANDLER.store(action.sa_sigaction, Ordering::Release);
    }
    stand_in();
}

/// `sigaction(SIGCHLD, act, old)` made outside every domain once [`on_sigchld`] may stand in for
/// the process's action: sets the process's own action instead of the real one. `None` before.
pub(crate) fn outside_sigaction(
    act: Option<&libc::sigaction>,
    old: Option<&mut libc::sigaction>,
) -> Option<()> {
    let _passthrough = Passthrough::enter();
    let mut own = OWN.lock().unwrap_or_else(|e| e.into_inner());
    let current = own.as_mut()?;
    current.sa_sigaction = OWN_HANDLER.load(Ordering::Acquire);
    if let Some(old) = old {
        *old = *current;
    }
    if let Some(act) = act {
        *current = *act;
        OWN_FLAGS.store(act.sa_flags, Ordering::Release);
        OWN_HANDLER.store(act.sa_sigaction, Ordering::Release);
        apply(current);
    }
    Some(())
}

/// Lets [`on_sigchld`] stand in for the process's `SIGCHLD` action from now on, taking the action
/// in force as the process's own the first time.
fn stand_in() {
    let _passthrough = Passthrough::enter();
    let mut own = OWN.lock().unwrap_or_else(|e| e.into_inner());
    let current = own.get_or_insert_with(|| {
        // SAFETY: a query only fills `old` (man 2 sigaction).
        let current = unsafe {
            let mut old: libc::sigaction = std::mem::zeroed();
            libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut old);
            old
        };
        OWN_FLAGS.store(current.sa_flags, Ordering::Release);
        OWN_HANDLER.store(current.sa_sigaction, Ordering::Release);
        current
    });
    current.sa_sigaction = OWN_HANDLER.load(Ordering::Acquire);
    apply(current);
}

/// Sets the process's real `SIGCHLD` action from its own, `own`: [`on_sigchld`] when a handler
/// is due (its own, or the domains' while its own is `SIG_DFL`), with that handler's mask and
/// flags, `SA_SIGINFO` added for the child's pid and `SA_RESETHAND` left for [`on_sigchld`] to
/// apply; `own` itself otherwise, so an ignored `SIGCHLD` still has the kernel reap children
/// (man 2 sigaction, `SA_NOCLDWAIT`; man 2 wait, NOTES). Called with `OWN` held, in passthrough.
fn apply(own: &libc::sigaction) {
    let domains = *DOMAINS.lock().unwrap_or_else(|e| e.into_inner());
    let due = if is_handler(own.sa_sigaction) {
        Some(*own)
    } else if own.sa_sigaction == libc::SIG_DFL {
        domains.filter(|domains| is_handler(domains.sa_sigaction))
    } else {
        None
    };
    let real = match due {
        Some(mut due) => {
            due.sa_sigaction = on_sigchld as *const () as libc::sighandler_t;
            due.sa_flags = (due.sa_flags | libc::SA_SIGINFO) & !libc::SA_RESETHAND;
            due
        }
        None => *own,
    };
    // SAFETY: installs a valid action; the old one is not wanted.
    unsafe { libc::sigaction(libc::SIGCHLD, &real, std::ptr::null_mut()) };
}

/// The kernel's `SIGCHLD`s for children no domain followed yet that ended while a spawn was under
/// way: a child can end before the call that made it has returned and been followed ([`adopt`]),
/// so its end waits here for the spawn to finish, then goes to its slot or, a child of no domain
/// after all, to the process's handler ([`Spawning`]). The size is a snare choice; past it, an end
/// goes to the process's handler at once.
static EARLY: [Slot; 16] = [const {
    Slot {
        pid: AtomicI32::new(0),
        exit: AtomicU64::new(0),
    }
}; 16];

/// How many spawns are under way (see [`EARLY`]).
static SPAWNS: AtomicUsize = AtomicUsize::new(0);

/// A spawn under way: `fork`, `posix_spawn` or `posix_spawnp` from the call until the child it
/// made is followed, if a domain's thread made it. Dropping it settles [`EARLY`].
pub(crate) struct Spawning(());

/// Counts a spawn under way until the guard drops.
pub(crate) fn spawning() -> Spawning {
    SPAWNS.fetch_add(1, Ordering::AcqRel);
    Spawning(())
}

impl Drop for Spawning {
    /// Hands each end [`EARLY`] holds to its child's slot, or, once no spawn is under way, to the
    /// process's handler, as the kernel would have, late.
    fn drop(&mut self) {
        let last = SPAWNS.fetch_sub(1, Ordering::AcqRel) == 1;
        for early in &EARLY {
            let pid = early.pid.load(Ordering::Acquire);
            if pid == 0 {
                continue;
            }
            let exit = early.exit.load(Ordering::Acquire);
            let slot = slot_of(pid);
            if (slot.is_none() && !last)
                || early
                    .pid
                    .compare_exchange(pid, 0, Ordering::AcqRel, Ordering::Relaxed)
                    .is_err()
            {
                continue;
            }
            match (slot, unpack(exit)) {
                (Some(slot), _) => slot.exit.store(exit, Ordering::Release),
                (None, Some((code, status))) => {
                    // SAFETY: zeroed is a valid siginfo_t.
                    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
                    // SAFETY: getuid has no preconditions.
                    let uid = unsafe { libc::getuid() };
                    crate::signals::fill_siginfo(&mut info, libc::SIGCHLD, code, pid, uid, status);
                    hand_on(libc::SIGCHLD, &mut info, std::ptr::null_mut());
                }
                (None, None) => {}
            }
        }
    }
}

/// The process's real `SIGCHLD` handler while it stands in (see the module docs). Only
/// async-signal-safe work: atomics, and the handler it hands the signal to, which is itself a
/// signal handler.
extern "C" fn on_sigchld(sig: c_int, info: *mut libc::siginfo_t, context: *mut libc::c_void) {
    if !info.is_null() {
        // SAFETY: the kernel's siginfo for this SIGCHLD.
        let (pid, code, status) =
            unsafe { ((*info).si_pid(), (*info).si_code, (*info).si_status()) };
        let ended = matches!(code, libc::CLD_EXITED | libc::CLD_KILLED | libc::CLD_DUMPED);
        if let Some(slot) = slot_of(pid) {
            if ended {
                slot.exit.store(pack(code, status), Ordering::Release);
            }
            return;
        }
        if ended
            && SPAWNS.load(Ordering::Acquire) > 0
            && let Some(early) = EARLY.iter().find(|early| {
                early
                    .pid
                    .compare_exchange(0, pid, Ordering::AcqRel, Ordering::Relaxed)
                    .is_ok()
            })
        {
            early.exit.store(pack(code, status), Ordering::Release);
            return;
        }
    }
    hand_on(sig, info, context);
}

/// Hands a `SIGCHLD` for a child of no domain to the process's own handler, or with that at
/// `SIG_DFL` to the domains' (see the module docs). The handler runs in passthrough: a child of
/// no domain is no domain's business, whichever thread the kernel picked.
fn hand_on(sig: c_int, info: *mut libc::siginfo_t, context: *mut libc::c_void) {
    let own = OWN_HANDLER.load(Ordering::Acquire);
    let (handler, flags) = if own == libc::SIG_DFL {
        (
            DOMAINS_HANDLER.load(Ordering::Acquire),
            DOMAINS_FLAGS.load(Ordering::Acquire),
        )
    } else {
        (own, OWN_FLAGS.load(Ordering::Acquire))
    };
    if !is_handler(handler) {
        return;
    }
    if own != libc::SIG_DFL && flags & libc::SA_RESETHAND != 0 {
        OWN_HANDLER.store(libc::SIG_DFL, Ordering::Release);
    }
    let _passthrough = Passthrough::enter();
    if flags & libc::SA_SIGINFO != 0 {
        // SAFETY: a handler installed with SA_SIGINFO takes these three arguments.
        let handler: extern "C" fn(c_int, *mut libc::siginfo_t, *mut libc::c_void) =
            unsafe { std::mem::transmute(handler) };
        handler(sig, info, context);
    } else {
        // SAFETY: a handler installed without SA_SIGINFO takes the signal number.
        let handler: extern "C" fn(c_int) = unsafe { std::mem::transmute(handler) };
        handler(sig);
    }
}
