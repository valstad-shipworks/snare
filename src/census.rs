//! The thread census: every OS thread of the process held against the
//! state slot's thread registry.
//!
//! A thread is accounted for when it is registered (spawned through
//! [`crate::thread`], marked with a class, or a participant), matched by a
//! [`classify_background_by_name`](crate::sched::classify_background_by_name)
//! rule, or a system thread the OS created for itself (see
//! [`crate::host_threads::is_system`]). Anything else is unregistered. A
//! thread just starting is unregistered until its first line runs, so a
//! live thread only counts as unknown once two censuses in a row found it
//! unregistered; a thread that started and exited without ever registering
//! (seen where starts are tracked) is unknown at once. Unknown threads stay
//! on record for the life of the state slot.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

use parking_lot::Mutex;

use crate::host_threads;
use crate::sched::{CensusThread, HostThreadKind, ThreadCensus, UnknownThread};

#[derive(Default)]
pub(crate) struct CensusState {
    runs: u64,
    suspects: HashMap<u64, Option<Arc<str>>>,
    unknown: BTreeMap<u64, UnknownThread>,
}

type NameRule = fn(&str) -> bool;

static NAME_RULES: Mutex<Vec<NameRule>> = Mutex::new(Vec::new());

pub(crate) fn add_name_rule(matches: NameRule) {
    NAME_RULES.lock().push(matches);
}

fn adoptable(name: &str) -> bool {
    NAME_RULES.lock().iter().any(|matches| matches(name))
}

/// Every unknown thread any census of the calling thread's state slot has
/// found, in id order.
pub(crate) fn unknown() -> Vec<UnknownThread> {
    crate::state::thread_registry()
        .census
        .lock()
        .unknown
        .values()
        .cloned()
        .collect()
}

pub(crate) fn run() -> Option<ThreadCensus> {
    crate::sched::try_slot()?;
    let started = host_threads::unregistered_starts();
    let os = host_threads::enumerate()?;
    let registry = crate::state::thread_registry();
    let mut known: HashMap<u64, crate::sched::ThreadClass> = crate::threads::all()
        .into_iter()
        .filter(|t| !t.kernel)
        .filter_map(|t| Some((t.host_tid?, t.class)))
        .collect();
    for h in &os {
        if known.contains_key(&h.tid) || h.system || host_threads::is_system(h.tid) {
            continue;
        }
        if let Some(name) = h.name.as_deref().filter(|n| adoptable(n)) {
            crate::threads::adopt_background(h.tid, name);
            known.insert(h.tid, crate::sched::ThreadClass::Background);
        }
    }

    let mut state = registry.census.lock();
    state.runs += 1;
    let mut suspects = HashMap::new();
    let mut threads = Vec::with_capacity(os.len());
    for h in os {
        let name: Option<Arc<str>> = h.name.as_deref().map(Arc::from);
        let kind = if let Some(&class) = known.get(&h.tid) {
            HostThreadKind::Known(class)
        } else if h.system || host_threads::is_system(h.tid) {
            HostThreadKind::System
        } else {
            if state.suspects.contains_key(&h.tid) {
                state.unknown.entry(h.tid).or_insert_with(|| UnknownThread {
                    host_tid: h.tid,
                    name: name.clone(),
                    exited: false,
                });
            }
            suspects.insert(h.tid, name.clone());
            HostThreadKind::Unregistered
        };
        threads.push(CensusThread {
            host_tid: h.tid,
            name,
            kind,
        });
    }
    let live: HashSet<u64> = threads.iter().map(|t| t.host_tid).collect();
    for tid in started.into_iter().flatten() {
        if live.contains(&tid) || known.contains_key(&tid) {
            continue;
        }
        let name = state.suspects.get(&tid).cloned().flatten();
        state
            .unknown
            .entry(tid)
            .and_modify(|u| u.exited = true)
            .or_insert(UnknownThread {
                host_tid: tid,
                name,
                exited: true,
            });
        host_threads::forget_start(tid);
    }
    for (tid, u) in state.unknown.iter_mut() {
        if !live.contains(tid) {
            u.exited = true;
        }
    }
    state.suspects = suspects;
    Some(ThreadCensus {
        threads,
        unknown: state.unknown.values().cloned().collect(),
        creation_tracked: host_threads::creation_tracked(),
    })
}
