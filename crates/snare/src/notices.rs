//! Change notices for poll sets. An epoll set, a kqueue or a completion port subscribes each of
//! its registrations to the readiness keys of the sources behind it (a socket's record, a
//! descriptor), and every readiness bump naming one of those keys marks it on the set's
//! [`ReadyList`] and reaches the set's own key as well. A scan of the set then looks only at the
//! registrations marked since its last scan, those that fired at it and those whose readiness
//! moves with time ([`PollSet`]), and a wait on the set listens to the set's key alone, whatever
//! the set holds.
//!
//! A bump that names no source makes every set look at all of its registrations at its next scan.
//!
//! Lock order: a board shard, then a list's marks. Both are leaves, taken under a backend's socket
//! table or the readiness lock; nothing bumps readiness or takes another lock under them.

#![cfg_attr(windows, allow(dead_code))]

use std::hash::Hash;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use snare_interpose::RaceCell;

use crate::readiness::{WakeKey, WakeKeys};
use crate::{HashMap, HashSet};

const SHARDS: usize = 64;

type Shard = Mutex<HashMap<WakeKey, Vec<Arc<ReadyList>>>>;

/// The lists subscribed to each key, sharded by key.
struct Board {
    shards: [Shard; SHARDS],
}

/// How many (key, list) subscriptions the board holds, so a bump with none skips it.
static SUBSCRIPTIONS: AtomicUsize = AtomicUsize::new(0);

/// Bumps that named no source so far.
static BROADCASTS: AtomicU64 = AtomicU64::new(0);

fn board() -> &'static Board {
    static BOARD: RaceCell<Board> = RaceCell::new();
    BOARD
        .get_or_init(|| Board {
            shards: std::array::from_fn(|_| Mutex::default()),
        })
        .0
}

fn shard(key: WakeKey) -> &'static Shard {
    let (kind, id) = match key {
        WakeKey::Socket(id) => (1u64, id),
        #[cfg(unix)]
        WakeKey::Descriptor(id) => (2, id),
        #[cfg(windows)]
        WakeKey::CompletionPort(id) => (2, id),
        WakeKey::Thread(id) => (3, id),
        #[cfg(unix)]
        WakeKey::Real(id) => (4, id),
    };
    let mixed = (id ^ kind.rotate_right(8)).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    &board().shards[(mixed >> 58) as usize % SHARDS]
}

/// What a bump of `domain` (0 for every domain) with `event` reaches once notices are posted:
/// the event itself, or for keys some set is subscribed to, those keys and the subscribed sets'
/// own, gathered in `reached`. Marks the keys on those sets' lists; a bump naming no source
/// makes every set look at everything.
pub(crate) fn post<'a>(
    domain: usize,
    event: snare_interpose::ReadinessWake<'a>,
    reached: &'a mut WakeKeys,
) -> snare_interpose::ReadinessWake<'a> {
    use snare_interpose::ReadinessWake;
    match event {
        ReadinessWake::All => {
            BROADCASTS.fetch_add(1, Ordering::AcqRel);
            event
        }
        ReadinessWake::Keys(keys) if SUBSCRIPTIONS.load(Ordering::Acquire) > 0 => {
            let mut any = false;
            for &key in keys {
                any |= mark(domain, key, |list| {
                    if !any {
                        any = true;
                        keys.iter().for_each(|&key| reached.push(key));
                    }
                    reached.push(list);
                });
            }
            if any {
                ReadinessWake::Keys(reached.as_slice())
            } else {
                event
            }
        }
        _ => event,
    }
}

/// Marks `key` on the lists subscribed to it in `domain` (0 for every domain) without waking
/// anything: for a change whose bump comes later, which a scan before it must already see.
pub(crate) fn notice(domain: usize, key: WakeKey) {
    if SUBSCRIPTIONS.load(Ordering::Acquire) > 0 {
        mark(domain, key, |_| {});
    }
}

/// Marks `key` on its subscribed lists in `domain`, handing `reached` each one's own key.
/// `true` if any list was marked.
fn mark(domain: usize, key: WakeKey, mut reached: impl FnMut(WakeKey)) -> bool {
    let shard = shard(key).lock().unwrap_or_else(|e| e.into_inner());
    let Some(lists) = shard.get(&key) else {
        return false;
    };
    let mut marked = false;
    for list in lists {
        let theirs = list.domain.load(Ordering::Acquire);
        if domain != 0 && theirs != 0 && theirs != domain {
            continue;
        }
        list.marks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(key);
        reached(list.key());
        marked = true;
    }
    marked
}

/// A poll set's inbox: the keys of its registrations' sources that changed since it last looked.
pub(crate) struct ReadyList {
    /// The identity behind the set's own key: its open description (Unix) or its completion
    /// port (Windows).
    id: AtomicU64,
    /// The [`Domain::key`](snare_interpose::Domain::key) of the sim the set belongs to, whose
    /// bumps reach it; 0 for every sim's.
    domain: AtomicUsize,
    marks: Mutex<HashSet<WakeKey>>,
}

impl ReadyList {
    /// The key a wait on the set listens on, which every notice to the set reaches.
    pub(crate) fn key(&self) -> WakeKey {
        let id = self.id.load(Ordering::Acquire);
        #[cfg(unix)]
        return WakeKey::Descriptor(id);
        #[cfg(windows)]
        return WakeKey::CompletionPort(id);
    }

    /// Names the set by `id` (see [`key`](Self::key)) in the sim with domain key `domain`.
    pub(crate) fn place(&self, id: u64, domain: usize) {
        self.id.store(id, Ordering::Release);
        self.domain.store(domain, Ordering::Release);
    }

    fn subscribe(self: &Arc<Self>, key: WakeKey) {
        shard(key)
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(key)
            .or_default()
            .push(self.clone());
        SUBSCRIPTIONS.fetch_add(1, Ordering::AcqRel);
    }

    fn unsubscribe(self: &Arc<Self>, key: WakeKey) {
        let mut shard = shard(key).lock().unwrap_or_else(|e| e.into_inner());
        let Some(lists) = shard.get_mut(&key) else {
            return;
        };
        let Some(at) = lists.iter().position(|list| Arc::ptr_eq(list, self)) else {
            return;
        };
        lists.swap_remove(at);
        if lists.is_empty() {
            shard.remove(&key);
        }
        SUBSCRIPTIONS.fetch_sub(1, Ordering::AcqRel);
    }

    fn take(&self, mut marked: impl FnMut(WakeKey)) {
        let mut marks = self.marks.lock().unwrap_or_else(|e| e.into_inner());
        if !marks.is_empty() {
            marks.drain().for_each(&mut marked);
        }
    }
}

/// The keys of one registration's sources: at most two (an open description and its socket's
/// record).
#[derive(Clone, Copy, Default, PartialEq)]
pub(crate) struct Keys([Option<WakeKey>; 2]);

impl Keys {
    pub(crate) fn of(first: Option<WakeKey>, second: Option<WakeKey>) -> Self {
        if first == second {
            Keys([first, None])
        } else {
            Keys([first, second])
        }
    }

    pub(crate) fn iter(self) -> impl Iterator<Item = WakeKey> {
        self.0.into_iter().flatten()
    }
}

/// How a scan left a registration.
#[derive(Clone, Copy, PartialEq)]
pub(crate) enum Settled {
    /// Neither ready nor waiting on time: only a notice can change it.
    Idle,
    /// Fired, or something only a fresh look can tell may change it (a real descriptor, a
    /// descriptor not served by the sim, one the scan did not reach): looked at again next scan.
    Due,
    /// Its readiness moves with the clock (a delayed arrival, a pending connect, an armed timer):
    /// looked at again every scan, and a wait on the set wakes on clock moves.
    Timed,
}

/// A scan's handle on one registration of a [`PollSet`], from [`PollSet::due`].
#[derive(Clone, Copy)]
pub(crate) struct Ticket {
    slot: u32,
    generation: u32,
}

struct Slot<R, T> {
    held: Option<(R, T)>,
    keys: Keys,
    /// Moves on each time the registration is listed by anything but a notice, or replaced, so a
    /// scan that let go of the set's lock meanwhile leaves it listed.
    generation: u32,
    /// In [`PollSet::due`]'s list.
    listed: bool,
    timed: bool,
    /// The scan that last handed it out, so that a scan hands it out once.
    scanned: u64,
}

/// A poll set's registrations, each a value under its identity `R`, with the source keys it is
/// subscribed under and whether a scan must look at it. Lookups by identity hash; a scan reaches
/// the registrations it looks at by slot.
pub(crate) struct PollSet<R: Copy + Eq + Hash, T> {
    list: Arc<ReadyList>,
    slots: Vec<Slot<R, T>>,
    free: Vec<u32>,
    index: HashMap<R, u32>,
    /// The slots each subscribed key reaches.
    watched: HashMap<WakeKey, Vec<u32>>,
    /// The slots the next scan looks at, with stale entries until it compacts them.
    due: Vec<u32>,
    /// How many registrations are settled [`Settled::Timed`].
    timed: usize,
    scans: u64,
    /// [`BROADCASTS`] when last looked.
    broadcasts: u64,
    /// Every registration is due at the next scan.
    everything: bool,
}

impl<R: Copy + Eq + Hash, T> PollSet<R, T> {
    pub(crate) fn new() -> Self {
        PollSet {
            list: Arc::new(ReadyList {
                id: AtomicU64::new(0),
                domain: AtomicUsize::new(0),
                marks: Mutex::default(),
            }),
            slots: Vec::new(),
            free: Vec::new(),
            index: HashMap::default(),
            watched: HashMap::default(),
            due: Vec::new(),
            timed: 0,
            scans: 0,
            broadcasts: BROADCASTS.load(Ordering::Acquire),
            everything: false,
        }
    }

    pub(crate) fn list(&self) -> &Arc<ReadyList> {
        &self.list
    }

    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub(crate) fn get(&self, r: &R) -> Option<&T> {
        let slot = *self.index.get(r)?;
        self.slots[slot as usize]
            .held
            .as_ref()
            .map(|(_, value)| value)
    }

    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub(crate) fn get_mut(&mut self, r: &R) -> Option<&mut T> {
        let slot = *self.index.get(r)?;
        self.slots[slot as usize]
            .held
            .as_mut()
            .map(|(_, value)| value)
    }

    pub(crate) fn contains_key(&self, r: &R) -> bool {
        self.index.contains_key(r)
    }

    /// Every registration, in slot order.
    pub(crate) fn iter(&self) -> impl Iterator<Item = (&R, &T)> {
        self.slots
            .iter()
            .filter_map(|slot| slot.held.as_ref().map(|(r, value)| (r, value)))
    }

    /// Registers `value` under `r`, subscribed under `keys`, in place of any registration `r`
    /// held, and lists it for the next scan.
    pub(crate) fn insert(&mut self, r: R, value: T, keys: Keys) -> Option<T> {
        let (slot, old) = match self.index.get(&r) {
            Some(&slot) => {
                let held = self.slots[slot as usize].held.as_mut().unwrap();
                (slot, Some(std::mem::replace(&mut held.1, value)))
            }
            None => {
                let slot = self.free.pop().unwrap_or_else(|| {
                    self.slots.push(Slot {
                        held: None,
                        keys: Keys::default(),
                        generation: 0,
                        listed: false,
                        timed: false,
                        scanned: 0,
                    });
                    (self.slots.len() - 1) as u32
                });
                self.slots[slot as usize].held = Some((r, value));
                self.index.insert(r, slot);
                (slot, None)
            }
        };
        self.set_keys(slot, keys);
        self.relist_slot(slot);
        old
    }

    pub(crate) fn remove(&mut self, r: &R) -> Option<T> {
        let slot = self.index.remove(r)?;
        self.set_keys(slot, Keys::default());
        self.set_timed(slot, false);
        let entry = &mut self.slots[slot as usize];
        entry.listed = false;
        entry.generation = entry.generation.wrapping_add(1);
        let (_, value) = entry.held.take()?;
        self.free.push(slot);
        Some(value)
    }

    /// Keeps the registrations `keep` accepts, letting it change their values.
    pub(crate) fn retain(&mut self, mut keep: impl FnMut(&R, &mut T) -> bool) {
        let gone: Vec<R> = self
            .slots
            .iter_mut()
            .filter_map(|slot| {
                let (r, value) = slot.held.as_mut()?;
                (!keep(r, value)).then_some(*r)
            })
            .collect();
        for r in gone {
            self.remove(&r);
        }
    }

    fn relist_slot(&mut self, slot: u32) {
        let entry = &mut self.slots[slot as usize];
        entry.generation = entry.generation.wrapping_add(1);
        Self::list_slot(&mut self.slots, &mut self.due, slot);
    }

    fn list_slot(slots: &mut [Slot<R, T>], due: &mut Vec<u32>, slot: u32) {
        let entry = &mut slots[slot as usize];
        if entry.held.is_some() && !entry.listed {
            entry.listed = true;
            due.push(slot);
        }
    }

    fn set_keys(&mut self, slot: u32, keys: Keys) {
        let old = std::mem::replace(&mut self.slots[slot as usize].keys, keys);
        if old == keys {
            return;
        }
        for key in old.iter() {
            let Some(held) = self.watched.get_mut(&key) else {
                continue;
            };
            held.retain(|&other| other != slot);
            if held.is_empty() {
                self.watched.remove(&key);
                self.list.unsubscribe(key);
            }
        }
        for key in keys.iter() {
            let held = self.watched.entry(key).or_default();
            if held.is_empty() {
                self.list.subscribe(key);
            }
            if !held.contains(&slot) {
                held.push(slot);
            }
        }
    }

    fn set_timed(&mut self, slot: u32, timed: bool) {
        let entry = &mut self.slots[slot as usize];
        if entry.timed != timed {
            entry.timed = timed;
            if timed {
                self.timed += 1;
            } else {
                self.timed -= 1;
            }
        }
    }

    /// Makes every registration due at the next scan: their sources may have changed in ways no
    /// notice told (the set moved to another sim).
    pub(crate) fn everything(&mut self) {
        self.everything = true;
    }

    /// The registrations a scan must look at now: those listed, with the ones notices marked
    /// since. Each stays listed until [`settle`](Self::settle)d.
    pub(crate) fn due(&mut self) -> Vec<Ticket> {
        let (watched, slots, due) = (&self.watched, &mut self.slots, &mut self.due);
        self.list.take(|key| {
            for &slot in watched.get(&key).into_iter().flatten() {
                Self::list_slot(slots, due, slot);
            }
        });
        let broadcasts = BROADCASTS.load(Ordering::Acquire);
        if broadcasts != self.broadcasts {
            self.broadcasts = broadcasts;
            self.everything = true;
        }
        if std::mem::take(&mut self.everything) {
            for slot in 0..self.slots.len() as u32 {
                Self::list_slot(&mut self.slots, &mut self.due, slot);
            }
        }
        if self.due.is_empty() {
            return Vec::new();
        }
        self.scans += 1;
        let scan = self.scans;
        let slots = &mut self.slots;
        self.due.retain(|&slot| {
            let entry = &mut slots[slot as usize];
            let keep = entry.held.is_some() && entry.listed && entry.scanned != scan;
            if keep {
                entry.scanned = scan;
            }
            keep
        });
        self.due
            .iter()
            .map(|&slot| Ticket {
                slot,
                generation: self.slots[slot as usize].generation,
            })
            .collect()
    }

    /// `ticket` for its registration as it is now, whatever listed it again since the scan began.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn current(&self, ticket: Ticket) -> Ticket {
        Ticket {
            generation: self.slots[ticket.slot as usize].generation,
            ..ticket
        }
    }

    /// The registration `ticket` hands out, unless it has been listed again or replaced since.
    pub(crate) fn at(&self, ticket: Ticket) -> Option<(R, &T)> {
        let entry = &self.slots[ticket.slot as usize];
        if entry.generation != ticket.generation {
            return None;
        }
        entry.held.as_ref().map(|(r, value)| (*r, value))
    }

    pub(crate) fn at_mut(&mut self, ticket: Ticket) -> Option<(R, &mut T)> {
        let entry = &mut self.slots[ticket.slot as usize];
        if entry.generation != ticket.generation {
            return None;
        }
        entry.held.as_mut().map(|(r, value)| (*r, value))
    }

    /// Records what a scan found of `ticket`'s registration, subscribing it under `keys` from now
    /// on when given; nothing, if it has been listed again or replaced since.
    pub(crate) fn settle(&mut self, ticket: Ticket, settled: Settled, keys: Option<Keys>) {
        if self.at(ticket).is_none() {
            return;
        }
        if let Some(keys) = keys {
            self.set_keys(ticket.slot, keys);
        }
        self.set_timed(ticket.slot, settled == Settled::Timed);
        if settled == Settled::Idle {
            self.slots[ticket.slot as usize].listed = false;
        } else {
            Self::list_slot(&mut self.slots, &mut self.due, ticket.slot);
        }
    }

    /// Takes `r` off the list: nothing but a change to it can make it ready (it was disabled).
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub(crate) fn unlist(&mut self, r: &R) {
        if let Some(&slot) = self.index.get(r) {
            self.set_timed(slot, false);
            self.slots[slot as usize].listed = false;
        }
    }

    /// Whether a registration's readiness moves with the clock, as of the last scan.
    pub(crate) fn timed(&self) -> bool {
        self.timed > 0
    }
}

impl<R: Copy + Eq + Hash, T> Default for PollSet<R, T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<R: Copy + Eq + Hash, T> Drop for PollSet<R, T> {
    fn drop(&mut self) {
        for key in self.watched.keys() {
            self.list.unsubscribe(*key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn due<R: Copy + Eq + Hash, T>(set: &mut PollSet<R, T>) -> Vec<R> {
        let tickets = set.due();
        tickets
            .into_iter()
            .filter_map(|ticket| set.at(ticket).map(|(r, _)| r))
            .collect()
    }

    #[test]
    fn notices_list_only_the_registrations_they_name() {
        let (a, b) = (WakeKey::Socket(u64::MAX - 1), WakeKey::Socket(u64::MAX - 2));
        let mut set: PollSet<u32, ()> = PollSet::new();
        set.list().place(u64::MAX - 3, 7);
        set.insert(1, (), Keys::of(Some(a), None));
        set.insert(2, (), Keys::of(Some(b), None));
        let tickets = set.due();
        assert_eq!(tickets.len(), 2);
        for ticket in tickets {
            set.settle(ticket, Settled::Idle, None);
        }
        assert!(due(&mut set).is_empty());

        notice(8, a);
        assert!(due(&mut set).is_empty(), "another sim's notice");
        let named = [a];
        let mut reached = WakeKeys::default();
        let event = post(
            7,
            snare_interpose::ReadinessWake::Keys(&named),
            &mut reached,
        );
        let snare_interpose::ReadinessWake::Keys(keys) = event else {
            panic!("a keyed bump stays keyed");
        };
        assert_eq!(keys, &[a, set.list().key()]);
        assert_eq!(due(&mut set), vec![1]);
        assert_eq!(due(&mut set), vec![1], "listed until settled");
    }

    #[test]
    fn settling_keeps_fired_and_timed_registrations_and_skips_stale_tickets() {
        let key = WakeKey::Socket(u64::MAX - 4);
        let mut set: PollSet<u32, u8> = PollSet::new();
        set.insert(1, 0, Keys::of(Some(key), None));
        set.insert(2, 0, Keys::default());
        let tickets = set.due();
        set.settle(tickets[0], Settled::Timed, None);
        set.settle(tickets[1], Settled::Due, None);
        assert!(set.timed());
        assert_eq!(due(&mut set), vec![1, 2]);

        let tickets = set.due();
        set.insert(1, 9, Keys::of(Some(key), None));
        for ticket in tickets {
            set.settle(ticket, Settled::Idle, None);
        }
        assert_eq!(due(&mut set), vec![1], "replaced during the scan");
        assert_eq!(set.get(&1), Some(&9));

        set.remove(&1);
        notice(0, key);
        assert!(due(&mut set).is_empty());
    }
}
