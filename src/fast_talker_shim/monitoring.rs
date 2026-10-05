//! fast-talker's `Monitor` on snare: a background snare thread that samples
//! the simulated NICs, protocol counters and snare sockets on virtual time,
//! with fast-talker's sample layout and source-error rules.
//!
//! The thread is never a participant. Each sample holds a
//! [`busy`](crate::sched::busy) lease from before it is read until the
//! callback returns, so under a driver virtual time stands still while a
//! sample is built and handled. The lease is taken as the interval's timer
//! fires, so each sample is taken exactly when its interval is up. A lease
//! keeps the domain busy even while its holder
//! waits, so the callback must not block on a snare wait that needs time to
//! move (a blocking read, a sleep): under a driver that deadlocks.
//! Nonblocking snare calls and std channels are fine.

use std::io;
use std::sync::Arc;

use ::fast_talker::__sim::{MonitorCallback, MonitorHandle, ctor};
use ::fast_talker::counters::Counters;
use ::fast_talker::monitor::{Config, InterfaceSample, Sample, SourceError};
use ::fast_talker::nic::LinkStats;
use ::fast_talker::options::{Policy, Rules, ThreadOption};
use parking_lot::Mutex;

use super::nic::{DriverStats, Nic};
use super::sim::{FtEvent, MonitorRecord};
use super::slot::FtSlot;
use crate::netif::SocketId;
use crate::os::{Errno, OsSemantics};
use crate::sched::Unparker;
use crate::time::Instant;

const ENOENT: i32 = 2;

#[derive(Default)]
struct Control {
    stop: bool,
    unparker: Option<Unparker>,
}

struct SimMonitor {
    id: u64,
    control: Arc<Mutex<Control>>,
    slot: Arc<FtSlot>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl MonitorHandle for SimMonitor {
    fn stop(mut self: Box<Self>) {
        let unparker = {
            let mut c = self.control.lock();
            c.stop = true;
            c.unparker.clone()
        };
        if let Some(u) = unparker {
            u.unpark_now();
        }
        if crate::sched::try_slot().is_some() {
            mark_stopped(&self.slot, self.id, Instant::now());
        }
        let thread = self.thread.take();
        if crate::sched::driver_time().is_none()
            && let Some(t) = thread
        {
            let _ = t.join();
        }
    }
}

fn mark_stopped(slot: &FtSlot, id: u64, at: Instant) {
    let first = {
        let mut g = slot.inner.lock();
        match g.monitors.iter_mut().find(|m| m.id == id) {
            Some(m) if m.stopped_at.is_none() => {
                m.stopped_at = Some(at);
                true
            }
            _ => false,
        }
    };
    if first {
        slot.inner.lock().events.push(super::sim::FtEntry {
            at,
            tid: crate::threads::current_tid(),
            event: FtEvent::MonitorStopped { id },
        });
    }
}

/// A watched socket as the monitor reads it.
struct Watched {
    label: String,
    socket: Option<SocketId>,
    stream: bool,
}

/// `Monitor::start` on a snare thread: opens the interfaces (`NotFound`
/// before anything starts), then starts the sampling thread.
pub(crate) fn start(
    config: Config,
    callback: MonitorCallback,
) -> io::Result<Box<dyn MonitorHandle>> {
    let nics = config
        .interfaces
        .iter()
        .map(|name| Nic::open(name))
        .collect::<io::Result<Vec<_>>>()?;
    let watched: Vec<Watched> = config
        .sockets
        .iter()
        .map(|w| {
            let (label, handle, stream) = ::fast_talker::__sim::watched(w);
            Watched {
                label: label.to_owned(),
                socket: handle.map(|h| SocketId(h.0)),
                stream,
            }
        })
        .collect();
    let slot = crate::state::ft_slot();
    let started_at = Instant::now();
    let id = {
        let mut g = slot.inner.lock();
        let id = g.monitors.len() as u64 + 1;
        g.monitors.push(MonitorRecord {
            id,
            thread_tid: None,
            started_at,
            stopped_at: None,
            interval: config.interval,
            interfaces: config.interfaces.clone(),
            sockets: watched
                .iter()
                .filter_map(|w| w.socket.map(|s| (w.label.clone(), s, w.stream)))
                .collect(),
            protocol_counters: config.protocol_counters,
            driver_stats: config.driver_stats,
            queue_stats: config.queue_stats,
            clock_every: config.clock_every,
            plan: config.plan.clone(),
            plan_every: config.plan_every,
            thread: config.thread.clone(),
            samples: 0,
            last_sample: None,
            last_errors: Vec::new(),
        });
        id
    };
    super::sim::log(FtEvent::MonitorStarted { id });
    let control = Arc::new(Mutex::new(Control::default()));
    let thread = {
        let control = Arc::clone(&control);
        let slot = Arc::clone(&slot);
        crate::thread::spawn_background("fast-talker-mon", move || {
            run(id, &slot, &control, config, nics, watched, callback);
        })?
    };
    Ok(Box::new(SimMonitor {
        id,
        control,
        slot,
        thread: Some(thread),
    }))
}

fn run(
    id: u64,
    slot: &FtSlot,
    control: &Mutex<Control>,
    config: Config,
    nics: Vec<Nic>,
    watched: Vec<Watched>,
    mut callback: MonitorCallback,
) {
    control.lock().unparker = Some(crate::sched::own_unparker());
    let tid = crate::threads::current_tid();
    if let Some(m) = slot.inner.lock().monitors.iter_mut().find(|m| m.id == id) {
        m.thread_tid = tid;
    }
    let setup = ThreadOption::apply_all(
        &config.thread,
        &Rules {
            other_platform: Policy::Ignore,
            unsupported: Policy::Ignore,
            rejected: Policy::Ignore,
            allow: None,
        },
    );
    let mut state = State::new(config, nics, watched, Instant::now());
    if let Err(e) = setup {
        state
            .pending
            .push(ctor::source_error(None, "thread", e.to_string(), false));
    }
    let mut woke_with = None;
    loop {
        if control.lock().stop {
            break;
        }
        let lease = woke_with
            .take()
            .unwrap_or_else(|| crate::sched::busy("fast-talker-mon"));
        let at = Instant::now();
        let sample = state.sample(at);
        callback(&sample);
        {
            let mut g = slot.inner.lock();
            if let Some(m) = g.monitors.iter_mut().find(|m| m.id == id) {
                m.samples += 1;
                m.last_errors = sample.errors.clone();
                m.last_sample = Some(sample);
            }
        }
        drop(lease);
        let next = at + state.config.interval;
        loop {
            if control.lock().stop {
                break;
            }
            let (_, lease) = crate::sched::park_background_leased(next, "fast-talker-mon");
            if Instant::now() >= next {
                woke_with = lease;
                break;
            }
        }
    }
    drop(woke_with);
    mark_stopped(slot, id, Instant::now());
}

struct Interface {
    nic: Nic,
    link: Option<LinkStats>,
    driver: Option<DriverStats>,
    driver_prev: Vec<u64>,
    #[cfg(any(target_os = "linux", target_os = "android"))]
    queues: Option<Vec<::fast_talker::nic::QueueStats>>,
    disabled: Vec<&'static str>,
}

struct State {
    config: Config,
    interfaces: Vec<Interface>,
    watched: Vec<Watched>,
    counters: Option<Counters>,
    socket_drops: Vec<Option<u32>>,
    socket_retransmits: Vec<Option<u64>>,
    disabled: Vec<(&'static str, Option<String>)>,
    pending: Vec<SourceError>,
    sequence: u64,
    last: Instant,
}

/// fast-talker's test for a source that will never work: unsupported on
/// the platform, or missing from the driver.
fn is_unsupported(e: &io::Error) -> bool {
    if e.kind() == io::ErrorKind::Unsupported {
        return true;
    }
    let os = crate::os_semantics();
    if os == OsSemantics::Windows {
        return false;
    }
    let enotsup = match os {
        OsSemantics::MacOs => 45,
        _ => os.errno(Errno::OpNotSupp),
    };
    crate::os_error_code(e)
        .is_some_and(|c| c == os.errno(Errno::OpNotSupp) || c == enotsup || c == ENOENT)
}

/// fast-talker's counter delta: a drop from a 32-bit value is a wrap at
/// 2^32, a drop from anything larger a reset.
fn delta(before: u64, after: u64) -> u64 {
    if after >= before {
        after - before
    } else if before <= u64::from(u32::MAX) {
        after + (1 << 32) - before
    } else {
        after
    }
}

impl State {
    fn new(config: Config, nics: Vec<Nic>, watched: Vec<Watched>, now: Instant) -> Self {
        let interfaces = nics
            .into_iter()
            .map(|nic| Interface {
                nic,
                link: None,
                driver: None,
                driver_prev: Vec::new(),
                #[cfg(any(target_os = "linux", target_os = "android"))]
                queues: None,
                disabled: Vec::new(),
            })
            .collect();
        let sockets = watched.len();
        Self {
            config,
            interfaces,
            watched,
            counters: None,
            socket_drops: vec![None; sockets],
            socket_retransmits: vec![None; sockets],
            disabled: Vec::new(),
            pending: Vec::new(),
            sequence: 0,
            last: now,
        }
    }

    fn sample(&mut self, now: Instant) -> Sample {
        let elapsed = now - self.last;
        self.last = now;
        let sequence = self.sequence;
        self.sequence += 1;
        let mut errors = std::mem::take(&mut self.pending);

        let mut interfaces = Vec::with_capacity(self.interfaces.len());
        for i in &mut self.interfaces {
            interfaces.push(sample_interface(i, &self.config, sequence, &mut errors));
        }

        let (mut udp, mut udp6, mut counters) = (None, None, None);
        if self.config.protocol_counters && !self.is_disabled("counters", None) {
            match super::proto_counters::read() {
                Ok(now) => {
                    if let Some(prev) = &self.counters {
                        let d = now.since(prev);
                        udp = Some(d.udp());
                        udp6 = Some(d.udp6());
                        counters = Some(d);
                    }
                    self.counters = Some(now);
                }
                Err(e) => self.fail("counters", None, e, &mut errors),
            }
        }

        let mut sockets = Vec::with_capacity(self.watched.len());
        let mut tcp_failures = Vec::new();
        for idx in 0..self.watched.len() {
            let w = &self.watched[idx];
            let label = w.label.clone();
            let (mut memory, mut drops, mut tcp, mut retransmitted) = (None, None, None, None);
            let Some(id) = w.socket else {
                if !self.is_disabled("memory", Some(&label)) {
                    let e = io::Error::new(
                        io::ErrorKind::Unsupported,
                        "an OS socket is not sampled under the snare shim; watch a snare socket",
                    );
                    self.fail("memory", Some(label.clone()), e, &mut errors);
                }
                sockets.push(ctor::socket_sample(label, None, None, None, None));
                continue;
            };
            let stream = w.stream;
            match super::socket::socket_memory(id) {
                Ok(m) => {
                    if let (Some(prev), Some(now)) = (self.socket_drops[idx], m.drops) {
                        drops = Some(now.wrapping_sub(prev));
                    }
                    self.socket_drops[idx] = m.drops;
                    memory = Some(m);
                }
                Err(e) => errors.push(ctor::source_error(
                    Some(label.clone()),
                    "memory",
                    e.to_string(),
                    false,
                )),
            }
            if stream && !self.is_disabled("tcp_info", Some(&label)) {
                match super::tcp::tcp_info(id) {
                    Ok(info) => {
                        let now = info.bytes_retransmitted;
                        if let (Some(prev), Some(now)) = (self.socket_retransmits[idx], now) {
                            retransmitted = Some(now.wrapping_sub(prev));
                        }
                        self.socket_retransmits[idx] = now;
                        tcp = Some(info);
                    }
                    Err(e) => tcp_failures.push((label.clone(), e)),
                }
            }
            sockets.push(ctor::socket_sample(
                label,
                memory,
                drops,
                tcp,
                retransmitted,
            ));
        }
        for (label, e) in tcp_failures {
            self.fail("tcp_info", Some(label), e, &mut errors);
        }

        let drift = match &self.config.plan {
            Some(plan) if sequence.is_multiple_of(u64::from(self.config.plan_every.max(1))) => {
                Some(super::plans::check(plan))
            }
            _ => None,
        };

        ctor::sample(
            sequence,
            crate::sched::wall_of(now),
            elapsed,
            interfaces,
            udp,
            udp6,
            counters,
            sockets,
            drift,
            errors,
        )
    }

    fn is_disabled(&self, source: &str, owner: Option<&str>) -> bool {
        self.disabled
            .iter()
            .any(|(s, o)| *s == source && o.as_deref() == owner)
    }

    fn fail(
        &mut self,
        source: &'static str,
        owner: Option<String>,
        e: io::Error,
        errors: &mut Vec<SourceError>,
    ) {
        let disabled = is_unsupported(&e);
        if disabled {
            self.disabled.push((source, owner.clone()));
        }
        errors.push(ctor::source_error(owner, source, e.to_string(), disabled));
    }
}

fn sample_interface(
    i: &mut Interface,
    config: &Config,
    sequence: u64,
    errors: &mut Vec<SourceError>,
) -> InterfaceSample {
    let name = i.nic.name().to_owned();
    let mut fail = |disabled: &mut Vec<&'static str>, source: &'static str, e: io::Error| {
        let off = is_unsupported(&e);
        if off {
            disabled.push(source);
        }
        errors.push(ctor::source_error(
            Some(name.clone()),
            source,
            e.to_string(),
            off,
        ));
    };
    let mut link = None;
    let mut link_delta = None;
    let mut driver_delta = Vec::new();

    if !i.disabled.contains(&"link") {
        match i.nic.link_stats() {
            Ok(now) => {
                link_delta = i.link.map(|prev| now.since(&prev));
                link = Some(now);
                i.link = Some(now);
            }
            Err(e) => fail(&mut i.disabled, "link", e),
        }
    }

    if config.driver_stats && !i.disabled.contains(&"driver_stats") {
        let read = match &mut i.driver {
            Some(d) => d.refresh(&i.nic),
            None => i.nic.driver_stats().map(|d| i.driver = Some(d)),
        };
        match read {
            Ok(()) => {
                if let Some(d) = &i.driver {
                    if i.driver_prev.len() == d.len() {
                        driver_delta = d
                            .iter()
                            .zip(&i.driver_prev)
                            .map(|((n, v), &p)| (n.to_owned(), delta(p, v)))
                            .filter(|&(_, v)| v > 0)
                            .collect();
                    }
                    i.driver_prev = d.values().to_vec();
                }
            }
            Err(e) => fail(&mut i.disabled, "driver_stats", e),
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let linux = crate::os_semantics() == OsSemantics::Linux;
        let mut queue_delta = None;
        let mut clock = None;
        if linux && config.queue_stats && !i.disabled.contains(&"queue_stats") {
            match i.nic.queue_stats() {
                Ok(now) => {
                    if let Some(prev) = &i.queues {
                        queue_delta = Some(
                            now.iter()
                                .filter_map(|q| {
                                    prev.iter()
                                        .find(|p| p.kind == q.kind && p.queue == q.queue)
                                        .map(|p| q.since(p))
                                })
                                .collect(),
                        );
                    }
                    i.queues = Some(now);
                }
                Err(e) => fail(&mut i.disabled, "queue_stats", e),
            }
        }
        if linux
            && let Some(every) = config.clock_every
            && sequence.is_multiple_of(u64::from(every.max(1)))
            && !i.disabled.contains(&"clock")
        {
            match i.nic.clock_offset() {
                Ok(c) => clock = Some(c),
                Err(e) => fail(&mut i.disabled, "clock", e),
            }
        }
        ctor::interface_sample(name, link, link_delta, driver_delta, queue_delta, clock)
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        let _ = sequence;
        ctor::interface_sample(name, link, link_delta, driver_delta)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_deltas_wrap_like_fast_talkers() {
        assert_eq!(delta(5, 9), 4);
        assert_eq!(delta(u64::from(u32::MAX) - 1, 3), 5);
        assert_eq!(delta(u64::from(u32::MAX) + 10, 3), 3);
    }
}
