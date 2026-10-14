//! A tracefs under `/sys/kernel/tracing`, as a Linux kernel with the hist-trigger, synthetic
//! event, osnoise and timerlat machinery serves it: enough of the control-file grammar and the
//! registration rules that code driving the real thing can be run under a sim and caught when
//! it writes something the kernel would refuse, removes things in the wrong order, or stops a
//! tracer a thread still waits on. The numbers it reports are made up (see
//! [`TracefsSim`] for the hooks a test injects them with); the acceptance rules are the kernel's:
//!
//! - `instances/<name>`: `mkdir` makes one with the defaults a fresh instance has, `rmdir` fails
//!   with `EBUSY` while it has triggers or an open `trace_pipe` (kernel/trace/trace.c
//!   `__remove_instance`: `trace_ref`, and `trace_array_destroy` of the event files).
//! - `events/<sys>/<event>/trigger`: `hist:` commands as kernel/trace/trace_events_hist.c parses
//!   them: `keys=` of the event's fields or `common_cpu`/`cpu` with `.log2`/`.hex`/`.sym`/
//!   `.usecs` modifiers, `vals=`, variables (`name=expr`), `onmatch(sys.event).trace(synth,…)`
//!   with the parameter count and types checked against the synthetic event, `onmax($var)` with
//!   `.snapshot()` or `.save(…)`, `sort=`, `size=`, `clock=`, `pause`/`continue`/`clear`, and an
//!   ` if` filter over the event's fields. A `$var` must resolve to this trigger, or to exactly
//!   one trigger on one event of the instance (`HIST_ERR_VAR_NOT_UNIQUE`). `!hist:…` removes the
//!   trigger whose parsed form matches, `EBUSY` while another trigger reads its variables.
//!   Opening the file with `O_TRUNC` removes every trigger on the event first, as the kernel
//!   does (`event_trigger_regex_open`).
//! - `synthetic_events`: `name type field; …` definitions, `EEXIST` for a name in use,
//!   `!name` to remove, `EBUSY` while a trigger produces or histograms the event; `O_TRUNC`
//!   removes every unreferenced one.
//! - `osnoise/*`: global, not per instance. `options` prints each option's name, `NO_`-prefixed
//!   when clear, and takes `DEFAULTS`, a name or `NO_name`. `cpus` is a cpulist.
//!   `per_cpu/cpuN/timerlat_fd` opens only while an instance runs the timerlat tracer with
//!   `OSNOISE_WORKLOAD` clear, from a thread whose affinity is exactly CPU N (`EPERM`), once per
//!   CPU (`EBUSY`); each `read` sleeps one `timerlat_period_us` on the sim's clock and records
//!   that period's samples on the instance's pipes. Switching the tracer away while a reader
//!   waits is what kills the real process (`stop_kthread`'s `SIGKILL`); here it is recorded as
//!   [`TracefsFault::TracerStoppedWithReader`] and the reader's next `read` fails with `EINTR`.
//! - `trace_pipe` and `per_cpu/cpuN/trace_pipe` are pipes the sim made, so `poll` on them waits
//!   on the sim's clock and a non-blocking `read` gives `EAGAIN` when empty. The osnoise tracer
//!   and timerlat with the kernel workload write one sample per period of virtual time, caught
//!   up whenever a pipe is read.
//! - `snapshot` reads the lines the ring held when an `onmax().snapshot()` fired; `2` clears it.
//!   `trace` reads the ring.
//! - Writes the kernel would refuse are `EINVAL`, and the reason goes to `error_log`.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::ffi::{c_char, c_int};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::Duration;

use snare_interpose::{Fs, NetResult as FsResult};

use crate::clock::Clock;
use crate::fs_sim::{
    DirEntry, DirStream, OpenFiles, Stamp, descriptor_fcntl, path_of, set_cloexec, status_flags,
};
use crate::scope::SimShared;
#[cfg(target_os = "linux")]
use crate::simhost::host_statx;
use crate::simhost::{SimHost, host_stat};
use snare_interpose::SleepRequest;

/// The tracefs a [`HostProfile`](crate::HostProfile) serves. The default is a kernel with
/// everything: the `nop`, `function`, `osnoise` and `timerlat` tracers, hist triggers,
/// synthetic events and a snapshot buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tracefs {
    tracers: Vec<String>,
    hist_triggers: bool,
    synthetic_events: bool,
    snapshot: bool,
}

impl Default for Tracefs {
    fn default() -> Self {
        Self {
            tracers: ["timerlat", "osnoise", "function", "nop"]
                .map(str::to_owned)
                .to_vec(),
            hist_triggers: true,
            synthetic_events: true,
            snapshot: true,
        }
    }
}

impl Tracefs {
    /// A kernel with every tracer and feature this module models.
    pub fn full() -> Self {
        Self::default()
    }

    /// A kernel built without `tracer` (`CONFIG_TIMERLAT_TRACER`, `CONFIG_OSNOISE_TRACER`).
    pub fn without_tracer(mut self, tracer: &str) -> Self {
        self.tracers.retain(|t| t != tracer);
        self
    }

    /// `CONFIG_HIST_TRIGGERS`.
    pub fn hist_triggers(mut self, on: bool) -> Self {
        self.hist_triggers = on;
        self
    }

    /// `CONFIG_SYNTH_EVENTS`.
    pub fn synthetic_events(mut self, on: bool) -> Self {
        self.synthetic_events = on;
        self
    }

    /// `CONFIG_TRACER_SNAPSHOT`.
    pub fn snapshot(mut self, on: bool) -> Self {
        self.snapshot = on;
        self
    }
}

/// Something the code under test did to tracefs that a real kernel would punish or that a test
/// should know about, from [`TracefsSim::faults`] and the sim's recorded events.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TracefsFault {
    /// The timerlat tracer of `instance` was stopped (or the instance removed) while a thread
    /// still waited in `timerlat_fd` of `cpu`: a real kernel sends the process `SIGKILL`.
    TracerStoppedWithReader { instance: String, cpu: usize },
    /// An instance was removed with triggers still registered: a real kernel refuses with
    /// `EBUSY`, which this one did too; recorded so a cleanup that silently leaves an instance
    /// behind shows up.
    RemoveWithTriggers { instance: String },
}

/// A field of an event, as the format file and the hist parser see it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Field {
    name: &'static str,
    ty: FieldType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FieldType {
    /// Signed integer of this many bytes.
    Int(u8),
    /// Unsigned integer of this many bytes.
    Uint(u8),
    /// `char[N]`.
    Str,
}

impl FieldType {
    fn parse(ty: &str) -> Option<Self> {
        let ty = ty.trim();
        if let Some(rest) = ty.strip_prefix("char").map(str::trim)
            && rest.starts_with('[')
            && rest.ends_with(']')
        {
            return Some(Self::Str);
        }
        Some(match ty {
            "s8" | "char" => Self::Int(1),
            "u8" | "unsigned char" | "bool" => Self::Uint(1),
            "s16" | "short" => Self::Int(2),
            "u16" | "unsigned short" => Self::Uint(2),
            "s32" | "int" | "pid_t" => Self::Int(4),
            "u32" | "unsigned int" | "gfp_t" => Self::Uint(4),
            "s64" | "long" | "long long" => Self::Int(8),
            "u64" | "unsigned long" | "unsigned long long" | "size_t" => Self::Uint(8),
            _ => return None,
        })
    }

    /// `check_synth_field`: a parameter fits a synthetic field when both are strings, or both
    /// are integers of the same size and signedness.
    fn compatible(self, other: Self) -> bool {
        self == other
    }
}

/// The tracepoints this tracefs has, with the fields their format files list, and the generic
/// fields every event has (`trace_define_generic_fields`, `ftrace_common_fields`).
fn event_fields(system: &str, event: &str) -> Option<Vec<Field>> {
    let f = |name, ty| Field { name, ty };
    let pid = FieldType::Int(4);
    let int = FieldType::Int(4);
    let uint = FieldType::Uint(4);
    Some(match (system, event) {
        ("irq", "irq_handler_entry") => vec![f("irq", int), f("name", FieldType::Str)],
        ("irq", "irq_handler_exit") => vec![f("irq", int), f("ret", int)],
        ("irq", "softirq_entry") | ("irq", "softirq_exit") | ("irq", "softirq_raise") => {
            vec![f("vec", uint)]
        }
        ("sched", "sched_switch") => vec![
            f("prev_comm", FieldType::Str),
            f("prev_pid", pid),
            f("prev_prio", int),
            f("prev_state", FieldType::Int(8)),
            f("next_comm", FieldType::Str),
            f("next_pid", pid),
            f("next_prio", int),
        ],
        ("sched", "sched_waking") | ("sched", "sched_wakeup") | ("sched", "sched_wakeup_new") => {
            vec![
                f("comm", FieldType::Str),
                f("pid", pid),
                f("prio", int),
                f("target_cpu", int),
            ]
        }
        ("sched", "sched_migrate_task") => vec![
            f("comm", FieldType::Str),
            f("pid", pid),
            f("prio", int),
            f("orig_cpu", int),
            f("dest_cpu", int),
        ],
        ("timer", "hrtimer_expire_entry") => vec![f("function", FieldType::Uint(8))],
        _ => return None,
    })
}

const SYSTEMS: [&str; 3] = ["irq", "sched", "timer"];

/// `cpu` and `common_cpu` are the CPU the event was recorded on, `comm` the recording task's
/// name; `common_pid`, `common_timestamp` the rest.
fn generic_field(name: &str) -> Option<FieldType> {
    match name {
        "cpu" | "CPU" | "common_cpu" => Some(FieldType::Uint(4)),
        "comm" | "COMM" => Some(FieldType::Str),
        "common_pid" => Some(FieldType::Int(4)),
        "common_timestamp" => Some(FieldType::Uint(8)),
        "common_preempt_count" | "common_flags" => Some(FieldType::Uint(1)),
        "common_type" => Some(FieldType::Uint(2)),
        _ => None,
    }
}

/// A key of a hist trigger: a field with an optional modifier.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Key {
    field: String,
    modifier: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Action {
    /// `onmatch(system.event).trace(synth, params…)`: `params` as written (`$var` or field).
    Trace {
        system: String,
        event: String,
        synth: String,
        params: Vec<String>,
    },
    /// `onmax($var).snapshot()`.
    Snapshot { var: String },
    /// `onmax($var).save(fields…)`.
    Save { var: String, fields: Vec<String> },
}

/// One hist trigger, parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Trigger {
    keys: Vec<Key>,
    vals: Vec<String>,
    /// `name=expr`, in order.
    vars: Vec<(String, String)>,
    /// `$var` references this trigger makes that another trigger defines: `(event, var)`.
    refs: Vec<(String, String)>,
    actions: Vec<Action>,
    sort: Option<String>,
    size: u64,
    clock: Option<String>,
    filter: Option<String>,
    paused: bool,
    /// The table: keys as printed, to `hitcount`.
    table: BTreeMap<Vec<(String, String)>, u64>,
    hits: u64,
    dropped: u64,
    /// `onmax` tracking: the current maximum and the keys that set it.
    max: Option<(u64, Vec<(String, String)>)>,
    /// The `onmax` fired a snapshot of the instance's ring.
    snapshot: bool,
}

impl Trigger {
    /// Variables of this trigger `name` refers to (`$name`).
    fn defines(&self, name: &str) -> bool {
        self.vars.iter().any(|(n, _)| n == name)
    }

    /// The trigger as the kernel prints it back, without the state suffix.
    fn text(&self) -> String {
        let mut s = String::from("hist:keys=");
        s += &self
            .keys
            .iter()
            .map(|k| match &k.modifier {
                Some(m) => format!("{}.{m}", k.field),
                None => k.field.clone(),
            })
            .collect::<Vec<_>>()
            .join(",");
        s += ":vals=";
        s += &self.vals.join(",");
        for (name, expr) in &self.vars {
            let _ = write!(s, ":{name}={expr}");
        }
        let _ = write!(s, ":sort={}", self.sort.as_deref().unwrap_or("hitcount"));
        let _ = write!(s, ":size={}", self.size);
        if let Some(c) = &self.clock {
            let _ = write!(s, ":clock={c}");
        }
        for a in &self.actions {
            match a {
                Action::Trace {
                    system,
                    event,
                    synth,
                    params,
                } => {
                    let _ = write!(
                        s,
                        ":onmatch({system}.{event}).trace({synth},{})",
                        params.join(",")
                    );
                }
                Action::Snapshot { var } => {
                    let _ = write!(s, ":onmax(${var}).snapshot()");
                }
                Action::Save { var, fields } => {
                    let _ = write!(s, ":onmax(${var}).save({})", fields.join(","));
                }
            }
        }
        if let Some(f) = &self.filter {
            let _ = write!(s, " if {f}");
        }
        s
    }

    /// Whether `other` names the same trigger, as `hist_trigger_match` compares them.
    fn matches(&self, other: &Trigger) -> bool {
        self.keys == other.keys
            && self.vals == other.vals
            && self.vars == other.vars
            && self.actions == other.actions
            && self.filter == other.filter
            && self.sort == other.sort
            && self.size == other.size
            && self.clock == other.clock
    }
}

/// One event's trigger file, filter and enable bit in one instance.
#[derive(Debug, Default)]
struct EventState {
    enabled: bool,
    filter: Option<String>,
    triggers: Vec<Trigger>,
}

/// A synthetic event, global to the kernel.
#[derive(Debug, Clone)]
struct Synth {
    fields: Vec<(String, FieldType, String)>,
}

/// A pipe the sim made for a `trace_pipe`: the read end handed out by `open`, the write end the
/// tracers fill.
#[derive(Debug)]
struct Pipe {
    read: c_int,
    write: c_int,
}

impl Pipe {
    fn new(shared: Option<&Arc<SimShared>>) -> Option<Self> {
        let mut fds = [0 as c_int; 2];
        let rc = snare_interpose::real(|| unsafe { libc::pipe(fds.as_mut_ptr()) });
        if rc != 0 {
            return None;
        }
        snare_interpose::real(|| unsafe {
            for fd in fds {
                libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
            }
            let flags = libc::fcntl(fds[1], libc::F_GETFL);
            libc::fcntl(fds[1], libc::F_SETFL, flags | libc::O_NONBLOCK);
        });
        if let Some(shared) = shared {
            shared.pipes.add(fds);
        }
        Some(Pipe {
            read: fds[0],
            write: fds[1],
        })
    }

    /// Writes `line` to the pipe; a full pipe drops it, as a full ring buffer overwrites.
    fn push(&self, line: &str) {
        let mut text = line.to_owned();
        text.push('\n');
        snare_interpose::real(|| unsafe {
            libc::write(self.write, text.as_ptr().cast(), text.len());
        });
    }
}

impl Drop for Pipe {
    fn drop(&mut self) {
        snare_interpose::real(|| unsafe {
            libc::close(self.read);
            libc::close(self.write);
        });
    }
}

/// One tracing instance: the top level, or `instances/<name>`.
#[derive(Debug)]
struct Instance {
    tracer: String,
    tracing_on: bool,
    clock: String,
    cpumask: Vec<usize>,
    buffer_kb: u64,
    events: BTreeMap<String, EventState>,
    /// The ring buffer's lines, newest last, bounded by `RING_LINES`.
    ring: VecDeque<String>,
    snapshot: Option<Vec<String>>,
    pipe: Option<Pipe>,
    per_cpu: BTreeMap<usize, Pipe>,
    /// Descriptors handed out on the pipes: `rmdir` is `EBUSY` while any is open.
    pipe_fds: usize,
    /// Timerlat and osnoise bookkeeping: the period sequence numbers and the virtual time the
    /// kernel workload last caught up to.
    seq: BTreeMap<usize, u64>,
    caught_up: Option<Duration>,
}

const RING_LINES: usize = 1024;

impl Instance {
    fn new(cpus: usize, snapshot: bool) -> Self {
        Self {
            tracer: "nop".into(),
            tracing_on: true,
            clock: "local".into(),
            cpumask: (0..cpus).collect(),
            buffer_kb: 1408,
            events: BTreeMap::new(),
            ring: VecDeque::new(),
            snapshot: snapshot.then(Vec::new),
            pipe: None,
            per_cpu: BTreeMap::new(),
            pipe_fds: 0,
            seq: BTreeMap::new(),
            caught_up: None,
        }
    }

    fn has_triggers(&self) -> bool {
        self.events.values().any(|e| !e.triggers.is_empty())
    }

    /// Records `line` for `cpu`: in the ring, and on the pipes that exist.
    fn record(&mut self, cpu: usize, line: String) {
        if !self.tracing_on || !self.cpumask.contains(&cpu) {
            return;
        }
        if let Some(p) = &self.pipe {
            p.push(&line);
        }
        if let Some(p) = self.per_cpu.get(&cpu) {
            p.push(&line);
        }
        if self.ring.len() == RING_LINES {
            self.ring.pop_front();
        }
        self.ring.push_back(line);
    }
}

/// The `osnoise/` directory.
#[derive(Debug)]
struct Osnoise {
    /// Set options, of [`OSNOISE_OPTIONS`].
    options: BTreeSet<&'static str>,
    cpus: Vec<usize>,
    timerlat_period_us: u64,
    period_us: u64,
    runtime_us: u64,
    stop_tracing_us: u64,
    stop_tracing_total_us: u64,
    print_stack: u64,
}

const OSNOISE_OPTIONS: [&str; 4] = [
    "OSNOISE_WORKLOAD",
    "PANIC_ON_STOP",
    "OSNOISE_PREEMPT_DISABLE",
    "OSNOISE_IRQ_DISABLE",
];

impl Osnoise {
    fn new(cpus: usize) -> Self {
        let mut o = Self {
            options: BTreeSet::new(),
            cpus: (0..cpus).collect(),
            timerlat_period_us: 1000,
            period_us: 1_000_000,
            runtime_us: 1_000_000,
            stop_tracing_us: 0,
            stop_tracing_total_us: 0,
            print_stack: 0,
        };
        o.defaults();
        o
    }

    fn defaults(&mut self) {
        self.options.clear();
        self.options.insert("OSNOISE_WORKLOAD");
    }

    fn options_text(&self) -> String {
        let mut s = String::from("DEFAULTS");
        for o in OSNOISE_OPTIONS {
            s.push(' ');
            if !self.options.contains(o) {
                s += "NO_";
            }
            s += o;
        }
        s.push('\n');
        s
    }

    fn set_option(&mut self, word: &str) -> Result<(), c_int> {
        if word == "DEFAULTS" {
            self.defaults();
            return Ok(());
        }
        let (on, name) = match word.strip_prefix("NO_") {
            Some(n) => (false, n),
            None => (true, word),
        };
        let Some(&o) = OSNOISE_OPTIONS.iter().find(|&&o| o == name) else {
            return Err(libc::EINVAL);
        };
        if on {
            self.options.insert(o);
        } else {
            self.options.remove(o);
        }
        Ok(())
    }
}

/// A thread blocked, or about to be, in a `timerlat_fd` read.
#[derive(Debug)]
struct Reader {
    cpu: usize,
    /// The tracer was stopped under it: its next read fails.
    killed: bool,
}

/// An open control file: its contents snapshotted at `open`, and the writes it took.
#[derive(Debug)]
struct Open {
    path: PathBuf,
    kind: OpenKind,
    data: Vec<u8>,
    cursor: usize,
    flags: c_int,
    writable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum OpenKind {
    Control,
    /// A `trace_pipe` read end, `dup`ed from the pipe: reads and the rest go to the real
    /// descriptor, after the tracers caught up.
    Pipe {
        instance: String,
    },
    TimerlatFd {
        cpu: usize,
    },
}

/// The made-up samples the tracers report, per CPU.
#[derive(Debug, Clone, Copy)]
struct Samples {
    irq_ns: u64,
    thread_ns: u64,
    user_ns: u64,
    noise_us: u64,
    max_sample_us: u64,
    hw: u64,
    nmi: u64,
}

impl Default for Samples {
    fn default() -> Self {
        Self {
            irq_ns: 1_500,
            thread_ns: 9_000,
            user_ns: 12_000,
            noise_us: 3,
            max_sample_us: 2,
            hw: 0,
            nmi: 0,
        }
    }
}

struct State {
    spec: Tracefs,
    root: bool,
    cpu_count: usize,
    synthetic: BTreeMap<String, Synth>,
    osnoise: Osnoise,
    instances: BTreeMap<String, Instance>,
    error_log: Vec<String>,
    faults: Vec<TracefsFault>,
    readers: BTreeMap<c_int, Reader>,
    samples: BTreeMap<usize, Samples>,
    open: OpenFiles<Open>,
    dirs: OpenFiles<DirStream>,
}

/// The plane: one tracefs per sim.
pub struct TracefsPlane {
    /// The profile has no tracefs: every path under the mount is `ENOENT`, so the real
    /// machine's never leaks through.
    absent: bool,
    state: Mutex<State>,
    devnull: c_int,
    clock: Arc<Clock>,
    shared: std::sync::OnceLock<Weak<SimShared>>,
    host: std::sync::OnceLock<Weak<SimHost>>,
    boot: Stamp,
}

impl std::fmt::Debug for TracefsPlane {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TracefsPlane").finish_non_exhaustive()
    }
}

const ROOT: &str = "/sys/kernel/tracing";

/// Where a path under the mount points: the instance (`""` for the top level) and the path
/// inside it.
fn locate(path: &Path) -> Option<(String, String)> {
    let rel = path.strip_prefix(ROOT).ok()?.to_str()?.trim_matches('/');
    if let Some(rest) = rel.strip_prefix("instances/") {
        let (name, inner) = rest.split_once('/').unwrap_or((rest, ""));
        return Some((name.to_owned(), inner.trim_matches('/').to_owned()));
    }
    Some((String::new(), rel.to_owned()))
}

fn is_ident(s: &str) -> bool {
    !s.is_empty()
        && !s.starts_with(|c: char| c.is_ascii_digit())
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// `1,3-5` to a CPU list.
fn parse_cpulist(s: &str, cpus: usize) -> Option<Vec<usize>> {
    let mut out = Vec::new();
    for part in s.trim().split(',').filter(|p| !p.is_empty()) {
        let (lo, hi) = part.split_once('-').unwrap_or((part, part));
        let (lo, hi): (usize, usize) = (lo.trim().parse().ok()?, hi.trim().parse().ok()?);
        if lo > hi || hi >= cpus {
            return None;
        }
        out.extend(lo..=hi);
    }
    out.sort_unstable();
    out.dedup();
    Some(out)
}

fn format_cpulist(cpus: &[usize]) -> String {
    let mut out = Vec::new();
    let mut i = 0;
    while i < cpus.len() {
        let start = cpus[i];
        while i + 1 < cpus.len() && cpus[i + 1] == cpus[i] + 1 {
            i += 1;
        }
        out.push(if cpus[i] == start {
            start.to_string()
        } else {
            format!("{start}-{}", cpus[i])
        });
        i += 1;
    }
    out.join(",")
}

/// `ff,00000003` to a CPU list, bits past `cpus` ignored as `cpumask_parse` does.
fn parse_cpumask(s: &str, cpus: usize) -> Option<Vec<usize>> {
    let digits: Vec<u8> = s.trim().bytes().filter(|&b| b != b',').collect();
    if digits.is_empty() {
        return None;
    }
    let mut out = Vec::new();
    for (i, &d) in digits.iter().rev().enumerate() {
        let v = (d as char).to_digit(16)? as usize;
        out.extend(
            (0..4)
                .filter(|b| v & (1 << b) != 0)
                .map(|b| i * 4 + b)
                .filter(|&c| c < cpus),
        );
    }
    Some(out)
}

fn format_cpumask(cpus: &[usize], count: usize) -> String {
    let words = count.div_ceil(32).max(1);
    let mut w = vec![0u32; words];
    for &c in cpus {
        if c / 32 < words {
            w[c / 32] |= 1 << (c % 32);
        }
    }
    let mut out = format!("{:x}", w[words - 1]);
    for word in w[..words - 1].iter().rev() {
        let _ = write!(out, ",{word:08x}");
    }
    out
}

/// A value an injected event carries, or a key prints.
fn log2_bucket(v: u64) -> u64 {
    if v <= 1 {
        0
    } else {
        64 - (v - 1).leading_zeros() as u64
    }
}

/// The field type `name` has on `event` (`system/event`), counting the generic fields.
fn field_type(fields: &[Field], synth: Option<&Synth>, name: &str) -> Option<FieldType> {
    if let Some(t) = generic_field(name) {
        return Some(t);
    }
    if let Some(f) = fields.iter().find(|f| f.name == name) {
        return Some(f.ty);
    }
    synth?
        .fields
        .iter()
        .find(|(n, _, _)| n == name)
        .map(|(_, t, _)| *t)
}

/// The fields of `system/event`: a tracepoint's, or a synthetic event's.
fn fields_of(state: &State, system: &str, event: &str) -> Option<(Vec<Field>, Option<Synth>)> {
    if system == "synthetic" {
        let s = state.synthetic.get(event)?.clone();
        return Some((Vec::new(), Some(s)));
    }
    event_fields(system, event).map(|f| (f, None))
}

/// The type of a variable expression: a timestamp or arithmetic is `u64`, a field its own.
fn expr_type(expr: &str, fields: &[Field], synth: Option<&Synth>) -> FieldType {
    let t = expr.trim();
    if t.contains('-') || t.contains('+') || t.starts_with("common_timestamp") {
        return FieldType::Uint(8);
    }
    field_type(fields, synth, t.split('.').next().unwrap_or(t)).unwrap_or(FieldType::Uint(8))
}

struct ParseCtx<'a> {
    state: &'a State,
    instance: &'a Instance,
    system: &'a str,
    event: &'a str,
    fields: Vec<Field>,
    synth: Option<Synth>,
}

impl ParseCtx<'_> {
    fn own_type(&self, name: &str) -> Option<FieldType> {
        field_type(&self.fields, self.synth.as_ref(), name)
    }

    /// Resolves `$name` to the trigger defining it: this trigger (`None`), or exactly one
    /// trigger on one event of the instance.
    fn resolve_var(
        &self,
        trigger: &Trigger,
        name: &str,
    ) -> Result<Option<(String, FieldType)>, String> {
        if trigger.defines(name) {
            return Ok(None);
        }
        let mut found: Vec<(String, FieldType)> = Vec::new();
        for (ev, es) in &self.instance.events {
            for t in &es.triggers {
                if let Some((_, expr)) = t.vars.iter().find(|(n, _)| n == name) {
                    let (system, event) = ev.split_once('/').unwrap_or((ev, ""));
                    let ty = fields_of(self.state, system, event)
                        .map(|(f, s)| expr_type(expr, &f, s.as_ref()))
                        .unwrap_or(FieldType::Uint(8));
                    found.push((ev.clone(), ty));
                }
            }
        }
        match found.len() {
            0 => Err(format!("Couldn't find variable: ${name}")),
            1 => Ok(Some(found.remove(0))),
            _ => Err(format!("Variable not unique: ${name}")),
        }
    }

    /// Checks `expr`, a variable's value: fields, `$var`s, `common_timestamp[.usecs]` and
    /// literals joined by `+` or `-`.
    fn check_expr(&self, trigger: &mut Trigger, expr: &str) -> Result<(), String> {
        if expr.trim().is_empty() {
            return Err("Missing expression".into());
        }
        for tok in expr.split(['+', '-']).map(str::trim) {
            if tok.is_empty() {
                return Err(format!("Bad expression: {expr}"));
            }
            if let Some(var) = tok.strip_prefix('$') {
                if let Some((ev, _)) = self.resolve_var(trigger, var)? {
                    trigger.refs.push((ev, var.to_owned()));
                }
                continue;
            }
            if tok.parse::<i64>().is_ok() || tok.starts_with("0x") {
                continue;
            }
            let base = tok.split('.').next().unwrap_or(tok);
            if self.own_type(base).is_none() {
                return Err(format!("Couldn't find field: {tok}"));
            }
        }
        Ok(())
    }

    fn parse(&self, cmd: &str) -> Result<Trigger, String> {
        let (cmd, filter) = match cmd.split_once(" if ") {
            Some((c, f)) => (c.trim(), Some(f.trim().to_owned())),
            None => (cmd.trim(), None),
        };
        if let Some(f) = &filter {
            check_filter(f, |name| self.own_type(name))?;
        }
        let mut parts = cmd.split(':');
        if parts.next().map(str::trim) != Some("hist") {
            return Err("Unknown trigger command".into());
        }
        let mut t = Trigger {
            keys: Vec::new(),
            vals: Vec::new(),
            vars: Vec::new(),
            refs: Vec::new(),
            actions: Vec::new(),
            sort: None,
            size: 2048,
            clock: None,
            filter,
            paused: false,
            table: BTreeMap::new(),
            hits: 0,
            dropped: 0,
            max: None,
            snapshot: false,
        };
        for part in parts.map(str::trim) {
            if part.is_empty() {
                continue;
            }
            if let Some(keys) = part
                .strip_prefix("keys=")
                .or_else(|| part.strip_prefix("key="))
            {
                for k in keys.split(',').map(str::trim) {
                    let (field, modifier) = match k.split_once('.') {
                        Some((f, m)) => (f, Some(m.to_owned())),
                        None => (k, None),
                    };
                    let ty = self
                        .own_type(field)
                        .ok_or_else(|| format!("Couldn't find field: {field}"))?;
                    if let Some(m) = &modifier {
                        let numeric = !matches!(ty, FieldType::Str);
                        let ok = match m.as_str() {
                            "log2" | "hex" | "usecs" | "sym" | "sym-offset" | "execname"
                            | "syscall" | "percent" | "graph" => numeric,
                            m if m.starts_with("buckets=") => numeric,
                            "stacktrace" => field == "common_stacktrace",
                            _ => false,
                        };
                        if !ok {
                            return Err(format!("Invalid field modifier: {m}"));
                        }
                    }
                    t.keys.push(Key {
                        field: field.to_owned(),
                        modifier,
                    });
                }
            } else if let Some(vals) = part
                .strip_prefix("vals=")
                .or_else(|| part.strip_prefix("val="))
            {
                for v in vals.split(',').map(str::trim) {
                    if v != "hitcount"
                        && !matches!(
                            self.own_type(v),
                            Some(FieldType::Int(_) | FieldType::Uint(_))
                        )
                    {
                        return Err(format!("Couldn't find field: {v}"));
                    }
                    t.vals.push(v.to_owned());
                }
            } else if let Some(s) = part.strip_prefix("sort=") {
                let s = s
                    .trim_end_matches(".descending")
                    .trim_end_matches(".ascending");
                if s != "hitcount"
                    && self.own_type(s).is_none()
                    && !t.vars.iter().any(|(n, _)| n == s)
                {
                    return Err(format!("Couldn't find field: {s}"));
                }
                t.sort = Some(s.to_owned());
            } else if let Some(n) = part.strip_prefix("size=") {
                t.size = n.parse().map_err(|_| format!("Invalid size: {n}"))?;
            } else if let Some(c) = part.strip_prefix("clock=") {
                t.clock = Some(c.to_owned());
            } else if part == "pause" {
                t.paused = true;
            } else if part == "continue" || part == "clear" {
            } else if let Some(rest) = part.strip_prefix("onmatch(") {
                let (target, rest) = rest
                    .split_once(')')
                    .ok_or_else(|| format!("Bad action: {part}"))?;
                let (sys, ev) = target
                    .split_once('.')
                    .ok_or_else(|| format!("Bad action: {part}"))?;
                let (mfields, msynth) = fields_of(self.state, sys, ev)
                    .ok_or_else(|| format!("Couldn't find onmatch event: {target}"))?;
                let _ = (mfields, msynth);
                let args = rest
                    .strip_prefix(".trace(")
                    .and_then(|a| a.strip_suffix(')'))
                    .ok_or_else(|| format!("Bad action: {part}"))?;
                let mut params: Vec<&str> = args.split(',').map(str::trim).collect();
                let synth_name = params.remove(0);
                let synth = self
                    .state
                    .synthetic
                    .get(synth_name)
                    .ok_or_else(|| format!("Couldn't find synthetic event: {synth_name}"))?;
                if params.len() != synth.fields.len() {
                    return Err(format!(
                        "Param count mismatch for {synth_name}: {} given, {} expected",
                        params.len(),
                        synth.fields.len()
                    ));
                }
                for (p, (fname, fty, _)) in params.iter().zip(&synth.fields) {
                    let pty = if let Some(var) = p.strip_prefix('$') {
                        match self.resolve_var(&t, var)? {
                            Some((ev, ty)) => {
                                t.refs.push((ev, var.to_owned()));
                                ty
                            }
                            None => {
                                let expr =
                                    &t.vars.iter().find(|(n, _)| n == var).expect("defined").1;
                                expr_type(expr, &self.fields, self.synth.as_ref())
                            }
                        }
                    } else {
                        self.own_type(p)
                            .ok_or_else(|| format!("Couldn't find param: {p}"))?
                    };
                    if !pty.compatible(*fty) {
                        return Err(format!(
                            "Param type doesn't match synthetic event field type: {p} for {fname}"
                        ));
                    }
                }
                t.actions.push(Action::Trace {
                    system: sys.to_owned(),
                    event: ev.to_owned(),
                    synth: synth_name.to_owned(),
                    params: params.iter().map(|p| (*p).to_owned()).collect(),
                });
            } else if let Some(rest) = part
                .strip_prefix("onmax(")
                .or_else(|| part.strip_prefix("onchange("))
            {
                let (var, rest) = rest
                    .split_once(')')
                    .ok_or_else(|| format!("Bad action: {part}"))?;
                let var = var
                    .strip_prefix('$')
                    .ok_or_else(|| format!("onmax needs a variable: {part}"))?;
                if let Some((ev, _)) = self.resolve_var(&t, var)? {
                    t.refs.push((ev, var.to_owned()));
                }
                if rest == ".snapshot()" {
                    if !self.state.spec.snapshot {
                        return Err("snapshot action needs CONFIG_TRACER_SNAPSHOT".into());
                    }
                    t.actions.push(Action::Snapshot {
                        var: var.to_owned(),
                    });
                } else if let Some(args) = rest
                    .strip_prefix(".save(")
                    .and_then(|a| a.strip_suffix(')'))
                {
                    let fields: Vec<String> =
                        args.split(',').map(|s| s.trim().to_owned()).collect();
                    for f in &fields {
                        if self.own_type(f).is_none() {
                            return Err(format!("Couldn't find field: {f}"));
                        }
                    }
                    t.actions.push(Action::Save {
                        var: var.to_owned(),
                        fields,
                    });
                } else {
                    return Err(format!("Bad action: {part}"));
                }
            } else if let Some((name, expr)) = part.split_once('=') {
                let name = name.trim();
                if !is_ident(name) {
                    return Err(format!("Invalid variable name: {name}"));
                }
                if self.own_type(name).is_some() {
                    return Err(format!("Variable name clashes with a field: {name}"));
                }
                if t.defines(name) {
                    return Err(format!("Variable already defined: {name}"));
                }
                self.check_expr(&mut t, expr)?;
                t.vars.push((name.to_owned(), expr.trim().to_owned()));
            } else {
                return Err(format!("Unknown parameter: {part}"));
            }
        }
        if t.keys.is_empty() {
            return Err("Missing keys".into());
        }
        if t.vals.is_empty() {
            t.vals.push("hitcount".into());
        }
        let _ = (self.system, self.event);
        Ok(t)
    }
}

/// Splits `s` at the top-level occurrences of `sep`, outside quotes and parentheses.
fn split_top(s: &str, sep: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0;
    let mut quoted = false;
    let mut start = 0;
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => quoted = !quoted,
            b'(' if !quoted => depth += 1,
            b')' if !quoted => depth -= 1,
            _ if !quoted && depth == 0 && s[i..].starts_with(sep) => {
                out.push(s[start..i].to_owned());
                i += sep.len();
                start = i;
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    out.push(s[start..].to_owned());
    out
}

/// One `field op value` of a filter.
fn predicate(p: &str) -> Option<(&str, &str, &str)> {
    for op in ["==", "!=", "<=", ">=", "~", "<", ">", "&"] {
        if let Some((l, r)) = p.split_once(op) {
            return Some((l.trim(), op, r.trim()));
        }
    }
    None
}

/// Checks a filter (kernel/trace/trace_events_filter.c): predicates over fields `ty` knows,
/// joined by `&&` and `||`, with parentheses; strings compare quoted.
fn check_filter(filter: &str, ty: impl Fn(&str) -> Option<FieldType> + Copy) -> Result<(), String> {
    let f = filter.trim();
    if f.is_empty() {
        return Err("Empty filter".into());
    }
    let ors = split_top(f, "||");
    if ors.len() > 1 {
        return ors.iter().try_for_each(|o| check_filter(o, ty));
    }
    let ands = split_top(f, "&&");
    if ands.len() > 1 {
        return ands.iter().try_for_each(|a| check_filter(a, ty));
    }
    if f.starts_with('(') && f.ends_with(')') {
        return check_filter(&f[1..f.len() - 1], ty);
    }
    let (field, op, value) = predicate(f).ok_or_else(|| format!("Invalid filter: {f}"))?;
    let t = ty(field).ok_or_else(|| format!("Field not found: {field}"))?;
    match t {
        FieldType::Str => {
            if !(value.starts_with('"') && value.ends_with('"') && value.len() >= 2) {
                return Err(format!("Expected a quoted string: {value}"));
            }
            if !matches!(op, "==" | "!=" | "~") {
                return Err(format!("Illegal operation on a string: {op}"));
            }
        }
        _ => {
            if value.trim_start_matches('-').parse::<u64>().is_err()
                && u64::from_str_radix(value.trim_start_matches("0x"), 16).is_err()
            {
                return Err(format!("Expected a number: {value}"));
            }
        }
    }
    Ok(())
}

/// Evaluates a checked filter against injected `fields`.
fn eval_filter(filter: &str, fields: &BTreeMap<String, String>) -> bool {
    let f = filter.trim();
    let ors = split_top(f, "||");
    if ors.len() > 1 {
        return ors.iter().any(|o| eval_filter(o, fields));
    }
    let ands = split_top(f, "&&");
    if ands.len() > 1 {
        return ands.iter().all(|a| eval_filter(a, fields));
    }
    if f.starts_with('(') && f.ends_with(')') {
        return eval_filter(&f[1..f.len() - 1], fields);
    }
    let Some((field, op, value)) = predicate(f) else {
        return false;
    };
    let Some(actual) = lookup(fields, field) else {
        return false;
    };
    let value = value.trim_matches('"');
    match (actual.parse::<i64>(), value.parse::<i64>()) {
        (Ok(a), Ok(v)) => match op {
            "==" => a == v,
            "!=" => a != v,
            "<" => a < v,
            "<=" => a <= v,
            ">" => a > v,
            ">=" => a >= v,
            "&" => a & v != 0,
            _ => false,
        },
        _ => match op {
            "==" => actual == value,
            "!=" => actual != value,
            "~" => glob(value, actual),
            _ => false,
        },
    }
}

fn glob(pattern: &str, s: &str) -> bool {
    match pattern.split_once('*') {
        None => pattern == s,
        Some((pre, post)) => {
            s.starts_with(pre) && s.len() >= pre.len() + post.len() && s.ends_with(post)
        }
    }
}

/// An injected field by any of its names: `cpu` is also `common_cpu`.
fn lookup<'a>(fields: &'a BTreeMap<String, String>, name: &str) -> Option<&'a str> {
    let alt = match name {
        "cpu" | "CPU" | "common_cpu" => Some(["cpu", "common_cpu", "CPU"]),
        "comm" | "COMM" => Some(["comm", "COMM", "comm"]),
        _ => None,
    };
    if let Some(names) = alt {
        return names
            .iter()
            .find_map(|n| fields.get(*n).map(String::as_str));
    }
    fields.get(name).map(String::as_str)
}

/// A key's printed form for an injected value.
fn key_text(key: &Key, value: &str) -> String {
    match key.modifier.as_deref() {
        Some("log2") => format!("~ 2^{:<2}", log2_bucket(value.parse().unwrap_or(0))),
        Some("hex") => format!("{:#x}", value.parse::<u64>().unwrap_or(0)),
        Some("usecs") => (value.parse::<u64>().unwrap_or(0) / 1000).to_string(),
        _ => value.to_owned(),
    }
}

/// Parses a synthetic event definition: `name type field; type field`.
fn parse_synth(def: &str) -> Result<(String, Synth), String> {
    let def = def.trim().trim_end_matches(';');
    let (name, rest) = def
        .split_once(char::is_whitespace)
        .ok_or_else(|| "Missing fields".to_owned())?;
    if !is_ident(name) {
        return Err(format!("Invalid event name: {name}"));
    }
    let mut fields = Vec::new();
    for f in rest.split(';').map(str::trim).filter(|f| !f.is_empty()) {
        let (ty, fname) = f
            .rsplit_once(char::is_whitespace)
            .ok_or_else(|| format!("Invalid field: {f}"))?;
        let (fname, ty) = match fname.split_once('[') {
            Some((n, dim)) => (n, format!("{ty}[{dim}")),
            None => (fname, ty.trim().to_owned()),
        };
        let parsed = FieldType::parse(&ty).ok_or_else(|| format!("Invalid field type: {ty}"))?;
        if !is_ident(fname) {
            return Err(format!("Invalid field name: {fname}"));
        }
        fields.push((fname.to_owned(), parsed, ty));
    }
    if fields.is_empty() {
        return Err("Missing fields".into());
    }
    Ok((name.to_owned(), Synth { fields }))
}

impl State {
    fn err(&mut self, where_: &str, msg: &str) -> c_int {
        self.error_log.push(format!("{where_}: error: {msg}"));
        libc::EINVAL
    }

    fn instance(&self, name: &str) -> Option<&Instance> {
        self.instances.get(name)
    }

    fn has_tracer(&self, t: &str) -> bool {
        self.spec.tracers.iter().any(|x| x == t)
    }

    fn has_osnoise_dir(&self) -> bool {
        self.has_tracer("osnoise") || self.has_tracer("timerlat")
    }

    /// Whether any trigger anywhere produces or histograms synthetic event `name`.
    fn synth_referenced(&self, name: &str) -> bool {
        self.instances.values().any(|i| {
            i.events
                .get(&format!("synthetic/{name}"))
                .is_some_and(|e| !e.triggers.is_empty())
                || i.events.values().any(|e| {
                    e.triggers.iter().any(|t| {
                        t.actions
                            .iter()
                            .any(|a| matches!(a, Action::Trace { synth, .. } if synth == name))
                    })
                })
        })
    }

    /// Whether another trigger in `instance` reads a variable of the trigger at `index` on
    /// `event`.
    fn var_referenced(&self, instance: &str, event: &str, index: usize) -> bool {
        let Some(inst) = self.instances.get(instance) else {
            return false;
        };
        let Some(me) = inst.events.get(event).and_then(|e| e.triggers.get(index)) else {
            return false;
        };
        inst.events.iter().any(|(ev, es)| {
            es.triggers.iter().enumerate().any(|(i, t)| {
                !(ev == event && i == index)
                    && t.refs
                        .iter()
                        .any(|(rev, var)| rev == event && me.defines(var))
            })
        })
    }

    /// Adds or removes a trigger from one line written to `instance`'s `event` trigger file.
    fn trigger_write(&mut self, instance: &str, event: &str, line: &str) -> Result<(), c_int> {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return Ok(());
        }
        let (system, name) = event.split_once('/').unwrap_or((event, ""));
        let where_ = format!("hist:{system}:{name}");
        let Some((fields, synth)) = fields_of(self, system, name) else {
            return Err(libc::ENOENT);
        };
        let (remove, cmd) = match line.strip_prefix('!') {
            Some(c) => (true, c),
            None => (false, line),
        };
        if cmd.starts_with("hist") && !self.spec.hist_triggers {
            return Err(self.err(&where_, "Unknown trigger command (CONFIG_HIST_TRIGGERS)"));
        }
        let parsed = {
            let inst = self.instances.get(instance).ok_or(libc::ENOENT)?;
            let ctx = ParseCtx {
                state: self,
                instance: inst,
                system,
                event: name,
                fields,
                synth,
            };
            ctx.parse(cmd)
        };
        let parsed = match parsed {
            Ok(t) => t,
            Err(msg) => return Err(self.err(&where_, &msg)),
        };
        let existing = self
            .instances
            .get(instance)
            .and_then(|i| i.events.get(event))
            .map(|e| e.triggers.iter().position(|t| t.matches(&parsed)));
        if remove {
            let Some(Some(index)) = existing else {
                return Err(libc::ENOENT);
            };
            if self.var_referenced(instance, event, index) {
                return Err(self.err(&where_, "Trigger has variables other triggers reference"));
            }
            let inst = self.instances.get_mut(instance).expect("exists");
            let es = inst.events.get_mut(event).expect("exists");
            es.triggers.remove(index);
            return Ok(());
        }
        if existing.flatten().is_some() {
            return Err(libc::EEXIST);
        }
        let inst = self.instances.get_mut(instance).expect("exists");
        inst.events
            .entry(event.to_owned())
            .or_default()
            .triggers
            .push(parsed);
        Ok(())
    }

    /// Removes every trigger of `event` in `instance` whose variables nothing reads: what an
    /// `O_TRUNC` open of the trigger file does.
    fn trigger_truncate(&mut self, instance: &str, event: &str) {
        let n = self
            .instances
            .get(instance)
            .and_then(|i| i.events.get(event))
            .map_or(0, |e| e.triggers.len());
        for index in (0..n).rev() {
            if !self.var_referenced(instance, event, index) {
                let es = self
                    .instances
                    .get_mut(instance)
                    .and_then(|i| i.events.get_mut(event))
                    .expect("exists");
                es.triggers.remove(index);
            }
        }
    }

    fn synth_write(&mut self, line: &str) -> Result<(), c_int> {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return Ok(());
        }
        if let Some(name) = line.strip_prefix('!') {
            let name = name.trim();
            if !self.synthetic.contains_key(name) {
                return Err(libc::ENOENT);
            }
            if self.synth_referenced(name) {
                return Err(libc::EBUSY);
            }
            self.synthetic.remove(name);
            return Ok(());
        }
        let (name, synth) = match parse_synth(line) {
            Ok(s) => s,
            Err(msg) => return Err(self.err("synthetic_events", &msg)),
        };
        if self.synthetic.contains_key(&name) {
            return Err(libc::EEXIST);
        }
        self.synthetic.insert(name, synth);
        Ok(())
    }

    fn synth_truncate(&mut self) -> Result<(), c_int> {
        let names: Vec<String> = self.synthetic.keys().cloned().collect();
        let mut busy = false;
        for n in names {
            if self.synth_referenced(&n) {
                busy = true;
            } else {
                self.synthetic.remove(&n);
            }
        }
        if busy { Err(libc::EBUSY) } else { Ok(()) }
    }

    /// Reports `fault` and records it with the sim's events.
    fn fault(&mut self, shared: Option<&Arc<SimShared>>, fault: TracefsFault) {
        if let Some(shared) = shared {
            let f = fault.clone();
            shared
                .events
                .push(|| shared.stamp(), crate::events::RecordedEvent::Tracefs(f));
        }
        self.faults.push(fault);
    }

    /// The timerlat tracer of `instance` stops: readers waiting in `timerlat_fd` would be killed.
    fn timerlat_stops(&mut self, shared: Option<&Arc<SimShared>>, instance: &str) {
        let cpus: Vec<usize> = self.readers.values().map(|r| r.cpu).collect();
        for r in self.readers.values_mut() {
            r.killed = true;
        }
        for cpu in cpus {
            self.fault(
                shared,
                TracefsFault::TracerStoppedWithReader {
                    instance: instance.to_owned(),
                    cpu,
                },
            );
        }
    }

    /// Whether some instance runs the timerlat tracer.
    fn timerlat_running(&self) -> bool {
        self.instances.values().any(|i| i.tracer == "timerlat")
    }

    /// Records one event on every instance that enables it, and feeds every hist trigger on it.
    fn inject(&mut self, event: &str, fields: &BTreeMap<String, String>, now: Duration, depth: u8) {
        if depth > 4 {
            return;
        }
        let cpu: usize = lookup(fields, "cpu")
            .and_then(|c| c.parse().ok())
            .unwrap_or(0);
        let comm = lookup(fields, "comm").unwrap_or("<...>").to_owned();
        let pid: u64 = lookup(fields, "common_pid")
            .or_else(|| lookup(fields, "pid"))
            .and_then(|p| p.parse().ok())
            .unwrap_or(0);
        let (_, name) = event.split_once('/').unwrap_or((event, event));
        let mut follow: Vec<(String, BTreeMap<String, String>)> = Vec::new();
        let names: Vec<String> = self.instances.keys().cloned().collect();
        for iname in names {
            let inst = self.instances.get_mut(&iname).expect("exists");
            let Some(es) = inst.events.get_mut(event) else {
                continue;
            };
            let filtered_out = es
                .filter
                .as_deref()
                .is_some_and(|f| !eval_filter(f, fields));
            if es.enabled && !filtered_out {
                let body: Vec<String> = fields
                    .iter()
                    .filter(|(k, _)| !matches!(k.as_str(), "cpu" | "common_cpu" | "common_pid"))
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect();
                let line = format!("{}{name}: {}", header(&comm, pid, cpu, now), body.join(" "));
                let mut line = Some(line);
                let es = inst.events.get_mut(event).expect("exists");
                let _ = &es;
                if let Some(l) = line.take() {
                    inst.record(cpu, l);
                }
            }
            let inst = self.instances.get_mut(&iname).expect("exists");
            let es = inst.events.get_mut(event).expect("exists");
            let mut snapshot = false;
            for t in &mut es.triggers {
                if t.paused || t.filter.as_deref().is_some_and(|f| !eval_filter(f, fields)) {
                    continue;
                }
                let mut key = Vec::new();
                let mut complete = true;
                for k in &t.keys {
                    match lookup(fields, &k.field) {
                        Some(v) => key.push((k.field.clone(), key_text(k, v))),
                        None => complete = false,
                    }
                }
                if !complete {
                    continue;
                }
                t.hits += 1;
                if !t.table.contains_key(&key) && t.table.len() as u64 >= t.size {
                    t.dropped += 1;
                } else {
                    *t.table.entry(key.clone()).or_insert(0) += 1;
                }
                for a in &t.actions {
                    match a {
                        Action::Trace { synth, params, .. } => {
                            let Some(s) = self.synthetic.get(synth) else {
                                continue;
                            };
                            let mut out = BTreeMap::new();
                            for (p, (fname, _, _)) in params.iter().zip(&s.fields) {
                                let v = match p.strip_prefix('$') {
                                    Some(var) => lookup(fields, var),
                                    None => lookup(fields, p),
                                };
                                if let Some(v) = v {
                                    out.insert(fname.clone(), v.to_owned());
                                }
                            }
                            out.insert("cpu".into(), cpu.to_string());
                            follow.push((format!("synthetic/{synth}"), out));
                        }
                        Action::Snapshot { var } | Action::Save { var, .. } => {
                            if let Some(v) = lookup(fields, var).and_then(|v| v.parse::<u64>().ok())
                                && t.max.as_ref().is_none_or(|(m, _)| v > *m)
                            {
                                t.max = Some((v, key.clone()));
                                if matches!(a, Action::Snapshot { .. }) {
                                    t.snapshot = true;
                                    snapshot = true;
                                }
                            }
                        }
                    }
                }
            }
            if snapshot && inst.snapshot.is_some() {
                inst.snapshot = Some(inst.ring.iter().cloned().collect());
            }
        }
        for (ev, f) in follow {
            self.inject(&ev, &f, now, depth + 1);
        }
    }

    /// One timerlat period on `cpu` of `instance`: the samples, the stack dump and the stop.
    fn emit_timerlat(&mut self, instance: &str, cpu: usize, now: Duration, user: bool) {
        let s = self.samples.get(&cpu).copied().unwrap_or_default();
        let o = (
            self.osnoise.stop_tracing_us,
            self.osnoise.stop_tracing_total_us,
            self.osnoise.print_stack,
        );
        let Some(inst) = self.instances.get_mut(instance) else {
            return;
        };
        let seq = inst.seq.entry(cpu).or_insert(0);
        *seq += 1;
        let seq = *seq;
        let pid = 1000 + cpu as u64;
        let comm = if user {
            format!("timerlatu/{cpu}")
        } else {
            format!("timerlat/{cpu}")
        };
        let idle = header("<idle>", 0, cpu, now);
        let thread = header(&comm, pid, cpu, now);
        let sample =
            |ctx: &str, ns: u64| format!("#{seq:<5} context {ctx:>6} timer_latency {ns:>9} ns");
        inst.record(cpu, format!("{idle}{}", sample("irq", s.irq_ns)));
        if o.0 != 0 && s.irq_ns / 1000 >= o.0 {
            inst.record(cpu, format!("{thread}stop tracing hit on cpu {cpu}"));
            inst.tracing_on = false;
            return;
        }
        inst.record(cpu, format!("{thread}{}", sample("thread", s.thread_ns)));
        let thread_us = s.thread_ns / 1000;
        if o.2 != 0 && thread_us >= o.2 {
            inst.record(cpu, format!("{thread}<stack trace>"));
            for f in [
                "=> timerlat_irq",
                "=> __hrtimer_run_queues",
                "=> hrtimer_interrupt",
            ] {
                inst.record(cpu, format!("{thread}{f}"));
            }
        }
        if o.1 != 0 && thread_us >= o.1 {
            inst.record(cpu, format!("{thread}stop tracing hit on cpu {cpu}"));
            inst.tracing_on = false;
            return;
        }
        if user {
            inst.record(cpu, format!("{thread}{}", sample("user-ret", s.user_ns)));
        }
    }

    /// Samples the kernel-workload tracers owe for the virtual time since they last did.
    fn catch_up(&mut self, now: Duration) {
        let names: Vec<String> = self.instances.keys().cloned().collect();
        for name in names {
            let inst = self.instances.get(&name).expect("exists");
            let period = match inst.tracer.as_str() {
                "osnoise" => Duration::from_micros(self.osnoise.period_us.max(1)),
                "timerlat" if self.osnoise.options.contains("OSNOISE_WORKLOAD") => {
                    Duration::from_micros(self.osnoise.timerlat_period_us.max(1))
                }
                _ => continue,
            };
            let from = inst.caught_up.unwrap_or(now);
            let mut at = from + period;
            let mut n = 0;
            while at <= now && n < 10_000 {
                let cpus: Vec<usize> = self
                    .osnoise
                    .cpus
                    .iter()
                    .copied()
                    .filter(|c| self.instances[&name].cpumask.contains(c))
                    .collect();
                for cpu in cpus {
                    if self.instances[&name].tracer == "osnoise" {
                        let s = self.samples.get(&cpu).copied().unwrap_or_default();
                        let runtime = self.osnoise.runtime_us;
                        let pct = 100.0 - (s.noise_us as f64 * 100.0 / runtime.max(1) as f64);
                        let line = format!(
                            "{}{runtime} {:>10} {:>3}.{:05} {:>7} {:>6} {:>6} {:>6} {:>6} {:>6}",
                            header(&format!("osnoise/{cpu}"), 2000 + cpu as u64, cpu, at),
                            s.noise_us,
                            pct as u64,
                            ((pct.fract()) * 100_000.0) as u64,
                            s.max_sample_us,
                            s.hw,
                            s.nmi,
                            1,
                            0,
                            0
                        );
                        self.instances
                            .get_mut(&name)
                            .expect("exists")
                            .record(cpu, line);
                    } else {
                        self.emit_timerlat(&name, cpu, at, false);
                    }
                }
                at += period;
                n += 1;
            }
            self.instances.get_mut(&name).expect("exists").caught_up = Some(at - period);
        }
    }

    /// Renders a hist file: one table per trigger.
    fn render_hist(&self, instance: &str, event: &str) -> String {
        let mut out = String::new();
        let Some(es) = self.instance(instance).and_then(|i| i.events.get(event)) else {
            return out;
        };
        for t in &es.triggers {
            let _ = write!(
                out,
                "# event histogram\n#\n# trigger info: {} [{}]\n#\n\n",
                t.text(),
                if t.paused { "paused" } else { "active" }
            );
            let mut entries: Vec<(&Vec<(String, String)>, &u64)> = t.table.iter().collect();
            entries.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
            for (keys, n) in &entries {
                out.push_str("{ ");
                let parts: Vec<String> = keys
                    .iter()
                    .zip(&t.keys)
                    .map(|((name, v), k)| {
                        let ty = field_type(
                            &event
                                .split_once('/')
                                .and_then(|(s, e)| event_fields(s, e))
                                .unwrap_or_default(),
                            event
                                .strip_prefix("synthetic/")
                                .and_then(|s| self.synthetic.get(s)),
                            name,
                        );
                        match (k.modifier.as_deref(), ty) {
                            (Some("log2"), _) => format!("{name}: {v}"),
                            (_, Some(FieldType::Str)) => format!("{name}: {v:<50}"),
                            _ => format!("{name}: {v:>10}"),
                        }
                    })
                    .collect();
                out.push_str(&parts.join(", "));
                let _ = write!(out, " }} hitcount: {n:>10}");
                if let Some((m, keys)) = &t.max
                    && *keys == **keys
                    && t.actions.iter().any(|a| matches!(a, Action::Save { .. }))
                {
                    let _ = write!(out, "\n\tmax: {m:>10}");
                }
                out.push('\n');
            }
            if let Some((m, keys)) = &t.max
                && t.snapshot
            {
                let var = t
                    .actions
                    .iter()
                    .find_map(|a| match a {
                        Action::Snapshot { var } => Some(var.as_str()),
                        _ => None,
                    })
                    .unwrap_or("");
                let _ = write!(
                    out,
                    "\nSnapshot taken (see tracing/snapshot).  Details:\n\ttriggering value {{ onmax(${var}) }}: {m:>10}\n\ttriggered by event with key: {{ {} }}\n",
                    keys.iter()
                        .map(|(k, v)| format!("{k}: {v}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
            let _ = write!(
                out,
                "\nTotals:\n    Hits: {}\n    Entries: {}\n    Dropped: {}\n\n",
                t.hits,
                t.table.len(),
                t.dropped
            );
        }
        out
    }

    fn render_trigger_file(&self, instance: &str, event: &str) -> String {
        let mut out = String::from(
            "# Available triggers:\n# traceon traceoff snapshot stacktrace enable_event disable_event",
        );
        if self.spec.hist_triggers {
            out += " enable_hist disable_hist hist";
        }
        out.push('\n');
        if let Some(es) = self.instance(instance).and_then(|i| i.events.get(event)) {
            for t in &es.triggers {
                let _ = writeln!(
                    out,
                    "{} [{}]",
                    t.text(),
                    if t.paused { "paused" } else { "active" }
                );
            }
        }
        out
    }

    fn render_trace(&self, instance: &str, lines: &[String]) -> String {
        let tracer = self.instance(instance).map_or("nop", |i| i.tracer.as_str());
        let mut out = format!(
            "# tracer: {tracer}\n#\n# entries-in-buffer/entries-written: {}/{}   #P:{}\n#\n",
            lines.len(),
            lines.len(),
            self.cpu_count
        );
        for l in lines {
            out.push_str(l);
            out.push('\n');
        }
        out
    }
}

/// What a path names.
enum Node {
    Dir(Vec<DirEntry>),
    /// A control file; `writable` whether the kernel lets root write it.
    File {
        writable: bool,
    },
    Pipe,
    TimerlatFd,
}

fn entry(name: &str, dir: bool) -> DirEntry {
    DirEntry {
        name: name.as_bytes().to_vec(),
        ino: 1,
        dtype: if dir { libc::DT_DIR } else { libc::DT_REG },
    }
}

impl State {
    /// The node at `rel` in `instance`, or `None` for a path this tracefs does not have.
    fn node(&self, instance: &str, rel: &str) -> Option<Node> {
        let inst = self.instance(instance)?;
        let root = instance.is_empty();
        let parts: Vec<&str> = rel.split('/').filter(|p| !p.is_empty()).collect();
        let file = |w| Some(Node::File { writable: w });
        match parts.as_slice() {
            [] => {
                let mut e = vec![
                    entry("tracing_on", false),
                    entry("current_tracer", false),
                    entry("trace_clock", false),
                    entry("tracing_cpumask", false),
                    entry("buffer_size_kb", false),
                    entry("trace", false),
                    entry("trace_pipe", false),
                    entry("set_event", false),
                    entry("events", true),
                    entry("per_cpu", true),
                ];
                if self.spec.snapshot {
                    e.push(entry("snapshot", false));
                }
                if root {
                    e.push(entry("available_tracers", false));
                    e.push(entry("available_events", false));
                    e.push(entry("error_log", false));
                    e.push(entry("instances", true));
                    if self.spec.synthetic_events {
                        e.push(entry("synthetic_events", false));
                    }
                    if self.has_osnoise_dir() {
                        e.push(entry("osnoise", true));
                    }
                }
                Some(Node::Dir(e))
            }
            [
                "tracing_on" | "current_tracer" | "trace_clock" | "tracing_cpumask"
                | "buffer_size_kb" | "trace" | "set_event",
            ] => file(true),
            ["snapshot"] if self.spec.snapshot => file(true),
            ["trace_pipe"] => Some(Node::Pipe),
            ["available_tracers" | "available_events"] if root => file(false),
            ["error_log"] if root => file(true),
            ["synthetic_events"] if root && self.spec.synthetic_events => file(true),
            ["instances"] if root => Some(Node::Dir(
                self.instances
                    .keys()
                    .filter(|k| !k.is_empty())
                    .map(|k| entry(k, true))
                    .collect(),
            )),
            ["osnoise"] if root && self.has_osnoise_dir() => Some(Node::Dir(
                [
                    "options",
                    "cpus",
                    "timerlat_period_us",
                    "period_us",
                    "runtime_us",
                    "stop_tracing_us",
                    "stop_tracing_total_us",
                    "print_stack",
                ]
                .iter()
                .map(|f| entry(f, false))
                .chain(std::iter::once(entry("per_cpu", true)))
                .collect(),
            )),
            [
                "osnoise",
                "options"
                | "cpus"
                | "timerlat_period_us"
                | "period_us"
                | "runtime_us"
                | "stop_tracing_us"
                | "stop_tracing_total_us"
                | "print_stack",
            ] if root && self.has_osnoise_dir() => file(true),
            ["osnoise", "per_cpu"] if root && self.has_tracer("timerlat") => Some(Node::Dir(
                (0..self.cpu_count)
                    .map(|c| entry(&format!("cpu{c}"), true))
                    .collect(),
            )),
            ["osnoise", "per_cpu", cpu] if root && self.has_tracer("timerlat") => {
                cpu_index(cpu, self.cpu_count)?;
                Some(Node::Dir(vec![entry("timerlat_fd", false)]))
            }
            ["osnoise", "per_cpu", cpu, "timerlat_fd"] if root && self.has_tracer("timerlat") => {
                cpu_index(cpu, self.cpu_count)?;
                Some(Node::TimerlatFd)
            }
            ["per_cpu"] => Some(Node::Dir(
                (0..self.cpu_count)
                    .map(|c| entry(&format!("cpu{c}"), true))
                    .collect(),
            )),
            ["per_cpu", cpu] => {
                cpu_index(cpu, self.cpu_count)?;
                Some(Node::Dir(vec![
                    entry("trace", false),
                    entry("trace_pipe", false),
                ]))
            }
            ["per_cpu", cpu, "trace"] => {
                cpu_index(cpu, self.cpu_count)?;
                file(true)
            }
            ["per_cpu", cpu, "trace_pipe"] => {
                cpu_index(cpu, self.cpu_count)?;
                Some(Node::Pipe)
            }
            ["events"] => {
                let mut e = vec![entry("enable", false)];
                e.extend(SYSTEMS.iter().map(|s| entry(s, true)));
                if self.spec.synthetic_events {
                    e.push(entry("synthetic", true));
                }
                Some(Node::Dir(e))
            }
            ["events", "enable"] => file(true),
            ["events", sys] => {
                let names: Vec<String> = self.events_of(sys)?;
                let mut e = vec![entry("enable", false), entry("filter", false)];
                e.extend(names.iter().map(|n| entry(n, true)));
                Some(Node::Dir(e))
            }
            ["events", sys, "enable" | "filter"] => {
                self.events_of(sys)?;
                file(true)
            }
            ["events", sys, ev] => {
                fields_of(self, sys, ev)?;
                let mut e = vec![
                    entry("enable", false),
                    entry("filter", false),
                    entry("trigger", false),
                    entry("format", false),
                    entry("id", false),
                ];
                if self.spec.hist_triggers {
                    e.push(entry("hist", false));
                }
                Some(Node::Dir(e))
            }
            ["events", sys, ev, "enable" | "filter" | "trigger"] => {
                fields_of(self, sys, ev)?;
                file(true)
            }
            ["events", sys, ev, "format" | "id"] => {
                fields_of(self, sys, ev)?;
                file(false)
            }
            ["events", sys, ev, "hist"] if self.spec.hist_triggers => {
                fields_of(self, sys, ev)?;
                file(false)
            }
            _ => {
                let _ = inst;
                None
            }
        }
    }

    fn events_of(&self, system: &str) -> Option<Vec<String>> {
        Some(match system {
            "irq" => [
                "irq_handler_entry",
                "irq_handler_exit",
                "softirq_entry",
                "softirq_exit",
                "softirq_raise",
            ]
            .map(str::to_owned)
            .to_vec(),
            "sched" => [
                "sched_switch",
                "sched_waking",
                "sched_wakeup",
                "sched_wakeup_new",
                "sched_migrate_task",
            ]
            .map(str::to_owned)
            .to_vec(),
            "timer" => vec!["hrtimer_expire_entry".to_owned()],
            "synthetic" if self.spec.synthetic_events => self.synthetic.keys().cloned().collect(),
            _ => return None,
        })
    }

    /// The contents of control file `rel` of `instance`.
    fn render(&self, instance: &str, rel: &str) -> String {
        let inst = match self.instance(instance) {
            Some(i) => i,
            None => return String::new(),
        };
        let parts: Vec<&str> = rel.split('/').filter(|p| !p.is_empty()).collect();
        match parts.as_slice() {
            ["tracing_on"] => format!("{}\n", u8::from(inst.tracing_on)),
            ["current_tracer"] => format!("{}\n", inst.tracer),
            ["trace_clock"] => {
                let clocks = [
                    "local", "global", "counter", "uptime", "perf", "mono", "mono_raw", "boot",
                    "tai",
                ];
                let s: Vec<String> = clocks
                    .iter()
                    .map(|c| {
                        if *c == inst.clock {
                            format!("[{c}]")
                        } else {
                            (*c).to_owned()
                        }
                    })
                    .collect();
                format!("{}\n", s.join(" "))
            }
            ["tracing_cpumask"] => format!("{}\n", format_cpumask(&inst.cpumask, self.cpu_count)),
            ["buffer_size_kb"] => format!("{}\n", inst.buffer_kb),
            ["trace"] => {
                let lines: Vec<String> = inst.ring.iter().cloned().collect();
                self.render_trace(instance, &lines)
            }
            ["per_cpu", cpu, "trace"] => {
                let c = cpu_index(cpu, self.cpu_count).unwrap_or(usize::MAX);
                let lines: Vec<String> = inst
                    .ring
                    .iter()
                    .filter(|l| l.contains(&format!("[{c:03}]")))
                    .cloned()
                    .collect();
                self.render_trace(instance, &lines)
            }
            ["snapshot"] => match &inst.snapshot {
                Some(lines) => self.render_trace(instance, lines),
                None => "# tracer: nop\n#\n# * Snapshot is freed *\n#\n".into(),
            },
            ["set_event"] => inst
                .events
                .iter()
                .filter(|(_, e)| e.enabled)
                .map(|(k, _)| format!("{}\n", k.replacen('/', ":", 1)))
                .collect(),
            ["available_tracers"] => format!("{}\n", self.spec.tracers.join(" ")),
            ["available_events"] => {
                let mut s = String::new();
                for sys in SYSTEMS {
                    for ev in self.events_of(sys).unwrap_or_default() {
                        let _ = writeln!(s, "{sys}:{ev}");
                    }
                }
                for name in self.synthetic.keys() {
                    let _ = writeln!(s, "synthetic:{name}");
                }
                s
            }
            ["error_log"] => self.error_log.iter().map(|e| format!("{e}\n")).collect(),
            ["synthetic_events"] => self
                .synthetic
                .iter()
                .map(|(name, s)| {
                    let f: Vec<String> = s
                        .fields
                        .iter()
                        .map(|(n, _, ty)| match ty.split_once('[') {
                            Some((base, dim)) => format!("{base} {n}[{dim}"),
                            None => format!("{ty} {n}"),
                        })
                        .collect();
                    format!("{name} {}\n", f.join("; "))
                })
                .collect(),
            ["osnoise", "options"] => self.osnoise.options_text(),
            ["osnoise", "cpus"] => format!("{}\n", format_cpulist(&self.osnoise.cpus)),
            ["osnoise", "timerlat_period_us"] => format!("{}\n", self.osnoise.timerlat_period_us),
            ["osnoise", "period_us"] => format!("{}\n", self.osnoise.period_us),
            ["osnoise", "runtime_us"] => format!("{}\n", self.osnoise.runtime_us),
            ["osnoise", "stop_tracing_us"] => format!("{}\n", self.osnoise.stop_tracing_us),
            ["osnoise", "stop_tracing_total_us"] => {
                format!("{}\n", self.osnoise.stop_tracing_total_us)
            }
            ["osnoise", "print_stack"] => format!("{}\n", self.osnoise.print_stack),
            ["events", "enable"] => {
                let all = inst.events.values().all(|e| e.enabled);
                let any = inst.events.values().any(|e| e.enabled);
                format!(
                    "{}\n",
                    if all && any {
                        "1"
                    } else if any {
                        "X"
                    } else {
                        "0"
                    }
                )
            }
            ["events", sys, "enable"] => {
                let any = inst
                    .events
                    .iter()
                    .any(|(k, e)| k.starts_with(&format!("{sys}/")) && e.enabled);
                format!("{}\n", u8::from(any))
            }
            ["events", _, "filter"] => "none\n".into(),
            ["events", sys, ev, "enable"] => format!(
                "{}\n",
                u8::from(
                    inst.events
                        .get(&format!("{sys}/{ev}"))
                        .is_some_and(|e| e.enabled)
                )
            ),
            ["events", sys, ev, "filter"] => format!(
                "{}\n",
                inst.events
                    .get(&format!("{sys}/{ev}"))
                    .and_then(|e| e.filter.as_deref())
                    .unwrap_or("none")
            ),
            ["events", sys, ev, "trigger"] => {
                self.render_trigger_file(instance, &format!("{sys}/{ev}"))
            }
            ["events", sys, ev, "hist"] => self.render_hist(instance, &format!("{sys}/{ev}")),
            ["events", sys, ev, "id"] => format!("{}\n", 1000 + (sys.len() * 31 + ev.len())),
            ["events", sys, ev, "format"] => {
                let mut s = format!("name: {ev}\nID: 1\nformat:\n");
                if let Some((fields, synth)) = fields_of(self, sys, ev) {
                    for f in fields {
                        let _ = writeln!(s, "\tfield:{} {};", type_name(f.ty), f.name);
                    }
                    if let Some(synth) = synth {
                        for (n, _, ty) in synth.fields {
                            let _ = writeln!(s, "\tfield:{ty} {n};");
                        }
                    }
                }
                s
            }
            _ => String::new(),
        }
    }

    /// A write of `text` to control file `rel` of `instance`.
    fn write(
        &mut self,
        shared: Option<&Arc<SimShared>>,
        instance: &str,
        rel: &str,
        text: &str,
        now: Duration,
    ) -> Result<(), c_int> {
        let parts: Vec<&str> = rel.split('/').filter(|p| !p.is_empty()).collect();
        let value = text.trim();
        let number = || value.parse::<u64>().map_err(|_| libc::EINVAL);
        let cpu_count = self.cpu_count;
        match parts.as_slice() {
            ["tracing_on"] => {
                let on = match value.trim_start_matches('0').chars().next() {
                    None => false,
                    Some('1') => true,
                    _ => return Err(libc::EINVAL),
                };
                self.instances
                    .get_mut(instance)
                    .ok_or(libc::ENOENT)?
                    .tracing_on = on;
            }
            ["current_tracer"] => {
                if !self.has_tracer(value) {
                    return Err(libc::EINVAL);
                }
                let was = self
                    .instances
                    .get(instance)
                    .ok_or(libc::ENOENT)?
                    .tracer
                    .clone();
                if was == "timerlat" && value != "timerlat" {
                    self.timerlat_stops(shared, instance);
                }
                let inst = self.instances.get_mut(instance).expect("exists");
                inst.tracer = value.to_owned();
                inst.caught_up = Some(now);
                inst.seq.clear();
                inst.ring.clear();
            }
            ["trace_clock"] => {
                let clocks = [
                    "local", "global", "counter", "uptime", "perf", "mono", "mono_raw", "boot",
                    "tai",
                ];
                if !clocks.contains(&value) {
                    return Err(libc::EINVAL);
                }
                let inst = self.instances.get_mut(instance).ok_or(libc::ENOENT)?;
                inst.clock = value.to_owned();
                inst.ring.clear();
            }
            ["tracing_cpumask"] => {
                let cpus = parse_cpumask(value, cpu_count).ok_or(libc::EINVAL)?;
                self.instances
                    .get_mut(instance)
                    .ok_or(libc::ENOENT)?
                    .cpumask = cpus;
            }
            ["buffer_size_kb"] => {
                let kb = number()?;
                self.instances
                    .get_mut(instance)
                    .ok_or(libc::ENOENT)?
                    .buffer_kb = kb;
            }
            ["trace"] | ["per_cpu", _, "trace"] => {
                self.instances
                    .get_mut(instance)
                    .ok_or(libc::ENOENT)?
                    .ring
                    .clear();
            }
            ["snapshot"] => {
                let n = number()?;
                let inst = self.instances.get_mut(instance).ok_or(libc::ENOENT)?;
                match n {
                    0 => inst.snapshot = None,
                    1 => inst.snapshot = Some(inst.ring.iter().cloned().collect()),
                    _ => inst.snapshot = Some(Vec::new()),
                }
            }
            ["error_log"] => self.error_log.clear(),
            ["set_event"] => {
                for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
                    let (off, spec) = match line.strip_prefix('!') {
                        Some(s) => (true, s),
                        None => (false, line),
                    };
                    let key = spec.replacen(':', "/", 1);
                    let (sys, ev) = key.split_once('/').ok_or(libc::EINVAL)?;
                    fields_of(self, sys, ev).ok_or(libc::EINVAL)?;
                    let inst = self.instances.get_mut(instance).ok_or(libc::ENOENT)?;
                    inst.events.entry(key.clone()).or_default().enabled = !off;
                }
            }
            ["events", "enable"] => {
                let on = number()? != 0;
                let inst = self.instances.get_mut(instance).ok_or(libc::ENOENT)?;
                for e in inst.events.values_mut() {
                    e.enabled = on;
                }
                if on {
                    for sys in SYSTEMS {
                        for ev in self.events_of(sys).unwrap_or_default() {
                            self.instances
                                .get_mut(instance)
                                .expect("exists")
                                .events
                                .entry(format!("{sys}/{ev}"))
                                .or_default()
                                .enabled = true;
                        }
                    }
                }
            }
            ["events", sys, "enable"] => {
                let on = number()? != 0;
                let names = self.events_of(sys).ok_or(libc::ENOENT)?;
                let inst = self.instances.get_mut(instance).ok_or(libc::ENOENT)?;
                for ev in names {
                    inst.events
                        .entry(format!("{sys}/{ev}"))
                        .or_default()
                        .enabled = on;
                }
            }
            ["events", _, "filter"] => return Err(libc::EINVAL),
            ["events", sys, ev, "enable"] => {
                fields_of(self, sys, ev).ok_or(libc::ENOENT)?;
                let on = number()? != 0;
                let inst = self.instances.get_mut(instance).ok_or(libc::ENOENT)?;
                inst.events
                    .entry(format!("{sys}/{ev}"))
                    .or_default()
                    .enabled = on;
            }
            ["events", sys, ev, "filter"] => {
                let (fields, synth) = fields_of(self, sys, ev).ok_or(libc::ENOENT)?;
                let key = format!("{sys}/{ev}");
                if value == "0" || value.is_empty() {
                    if let Some(e) = self
                        .instances
                        .get_mut(instance)
                        .ok_or(libc::ENOENT)?
                        .events
                        .get_mut(&key)
                    {
                        e.filter = None;
                    }
                } else {
                    if let Err(msg) =
                        check_filter(value, |n| field_type(&fields, synth.as_ref(), n))
                    {
                        return Err(self.err(&format!("{sys}:{ev}"), &msg));
                    }
                    let inst = self.instances.get_mut(instance).ok_or(libc::ENOENT)?;
                    inst.events.entry(key).or_default().filter = Some(value.to_owned());
                }
            }
            ["events", sys, ev, "trigger"] => {
                let key = format!("{sys}/{ev}");
                for line in text.lines() {
                    self.trigger_write(instance, &key, line)?;
                }
            }
            ["synthetic_events"] => {
                for line in text.lines() {
                    self.synth_write(line)?;
                }
            }
            ["osnoise", file] => {
                let o = &mut self.osnoise;
                match *file {
                    "options" => {
                        for word in value.split_whitespace() {
                            o.set_option(word)?;
                        }
                    }
                    "cpus" => o.cpus = parse_cpulist(value, cpu_count).ok_or(libc::EINVAL)?,
                    "timerlat_period_us" => o.timerlat_period_us = number()?,
                    "period_us" => o.period_us = number()?,
                    "runtime_us" => o.runtime_us = number()?,
                    "stop_tracing_us" => o.stop_tracing_us = number()?,
                    "stop_tracing_total_us" => o.stop_tracing_total_us = number()?,
                    "print_stack" => o.print_stack = number()?,
                    _ => return Err(libc::EACCES),
                }
            }
            _ => return Err(libc::EACCES),
        }
        Ok(())
    }
}

/// The common line header: `task-pid [cpu] flags secs.usecs: `.
fn header(comm: &str, pid: u64, cpu: usize, now: Duration) -> String {
    format!(
        "{:>16}-{:<7} [{:03}] ..... {:>5}.{:06}: ",
        comm,
        pid,
        cpu,
        now.as_secs(),
        now.subsec_micros()
    )
}

fn cpu_index(s: &str, count: usize) -> Option<usize> {
    let n: usize = s.strip_prefix("cpu")?.parse().ok()?;
    (n < count).then_some(n)
}

fn type_name(t: FieldType) -> &'static str {
    match t {
        FieldType::Int(4) => "int",
        FieldType::Int(8) => "long",
        FieldType::Int(_) => "short",
        FieldType::Uint(4) => "unsigned int",
        FieldType::Uint(8) => "unsigned long",
        FieldType::Uint(_) => "unsigned char",
        FieldType::Str => "char[16]",
    }
}

fn ok(v: i64) -> Option<FsResult> {
    Some(FsResult::Ok(v))
}

fn err(errno: c_int) -> Option<FsResult> {
    Some(FsResult::Err(errno))
}

const MODE_RW: u32 = 0o100644;
const MODE_RO: u32 = 0o100444;
const MODE_DIR: u32 = 0o040755;

impl TracefsPlane {
    pub(crate) fn new(
        spec: Option<Tracefs>,
        root: bool,
        cpu_count: usize,
        clock: Arc<Clock>,
    ) -> Self {
        let absent = spec.is_none();
        let spec = spec.unwrap_or_default();
        let devnull = snare_interpose::real(|| unsafe {
            libc::open(c"/dev/null".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC)
        });
        let boot = clock.base_realtime().as_nanos() as Stamp;
        let mut instances = BTreeMap::new();
        instances.insert(String::new(), Instance::new(cpu_count, spec.snapshot));
        Self {
            absent,
            state: Mutex::new(State {
                spec,
                root,
                cpu_count,
                synthetic: BTreeMap::new(),
                osnoise: Osnoise::new(cpu_count),
                instances,
                error_log: Vec::new(),
                faults: Vec::new(),
                readers: BTreeMap::new(),
                samples: BTreeMap::new(),
                open: OpenFiles::default(),
                dirs: OpenFiles::default(),
            }),
            devnull,
            clock,
            shared: std::sync::OnceLock::new(),
            host: std::sync::OnceLock::new(),
            boot,
        }
    }

    pub(crate) fn attach(&self, shared: &Arc<SimShared>, host: &Arc<SimHost>) {
        let _ = self.shared.set(Arc::downgrade(shared));
        let _ = self.host.set(Arc::downgrade(host));
    }

    fn shared(&self) -> Option<Arc<SimShared>> {
        self.shared.get().and_then(Weak::upgrade)
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn now(&self) -> Duration {
        Duration::from_nanos(self.clock.peek())
    }

    fn reserve_fd(&self) -> Result<c_int, c_int> {
        if self.devnull < 0 {
            return Err(libc::EMFILE);
        }
        let fd = snare_interpose::real(|| unsafe { libc::dup(self.devnull) });
        if fd < 0 {
            return Err(std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EMFILE));
        }
        Ok(fd)
    }

    /// The calling thread's CPU affinity, when the host models it (`None` where it does not).
    fn affinity(&self) -> Option<Vec<usize>> {
        self.host.get()?.upgrade()?.current_affinity()
    }

    /// Where `path` points under the mount; `Err` is the errno to answer for a path there on a
    /// host that has no tracefs.
    fn located(&self, path: &Path) -> Option<Result<(String, String), c_int>> {
        let at = locate(path)?;
        Some(if self.absent {
            Err(libc::ENOENT)
        } else {
            Ok(at)
        })
    }

    fn stat_of(&self, path: &Path, buf: *mut u8, statx: bool) -> Option<FsResult> {
        let (instance, rel) = match self.located(path)? {
            Ok(at) => at,
            Err(e) => return err(e),
        };
        let state = self.state();
        let (mode, links) = match state.node(&instance, &rel)? {
            Node::Dir(_) => (MODE_DIR, 2),
            Node::File { writable } => (if writable { MODE_RW } else { MODE_RO }, 1),
            Node::Pipe | Node::TimerlatFd => (MODE_RW, 1),
        };
        drop(state);
        #[cfg(target_os = "linux")]
        if statx {
            return host_statx(buf, path, mode, 0, links, self.boot);
        }
        let _ = statx;
        host_stat(buf, path, mode, 0, links, self.boot)
    }

    /// `rmdir instances/<name>`.
    fn remove_instance(&self, name: &str) -> Option<FsResult> {
        let shared = self.shared();
        let mut state = self.state();
        let Some(inst) = state.instances.get(name) else {
            return err(libc::ENOENT);
        };
        if inst.pipe_fds > 0 {
            return err(libc::EBUSY);
        }
        if inst.has_triggers() {
            state.fault(
                shared.as_ref(),
                TracefsFault::RemoveWithTriggers {
                    instance: name.to_owned(),
                },
            );
            return err(libc::EBUSY);
        }
        if inst.tracer == "timerlat" {
            state.timerlat_stops(shared.as_ref(), name);
        }
        state.instances.remove(name);
        ok(0)
    }
}

impl Drop for TracefsPlane {
    fn drop(&mut self) {
        if self.devnull >= 0 {
            snare_interpose::real(|| unsafe { libc::close(self.devnull) });
        }
    }
}

impl Fs for TracefsPlane {
    fn owns(&self, fd: c_int) -> bool {
        let state = self.state();
        state.open.contains_key(&fd) || state.dirs.contains_key(&fd)
    }

    unsafe fn open(&self, path: *const c_char, flags: c_int, _mode: u32) -> Option<FsResult> {
        let path = unsafe { path_of(path) }?;
        let (instance, rel) = match self.located(&path)? {
            Ok(at) => at,
            Err(e) => return err(e),
        };
        let writing = flags & (libc::O_WRONLY | libc::O_RDWR) != 0;
        let shared = self.shared();
        let now = self.now();
        let mut state = self.state();
        let node = match state.node(&instance, &rel) {
            Some(n) => n,
            None => return err(libc::ENOENT),
        };
        let kind = match node {
            Node::Dir(_) => {
                if writing {
                    return err(libc::EISDIR);
                }
                drop(state);
                return unsafe {
                    self.opendir(path.as_os_str().as_encoded_bytes().as_ptr().cast())
                };
            }
            Node::File { writable } => {
                if writing && (!writable || !state.root) {
                    return err(libc::EACCES);
                }
                if writing && flags & libc::O_TRUNC != 0 {
                    let parts: Vec<&str> = rel.split('/').filter(|p| !p.is_empty()).collect();
                    match parts.as_slice() {
                        ["events", sys, ev, "trigger"] => {
                            let key = format!("{sys}/{ev}");
                            state.trigger_truncate(&instance, &key);
                        }
                        ["synthetic_events"] => {
                            if let Err(e) = state.synth_truncate() {
                                return err(e);
                            }
                        }
                        _ => {}
                    }
                }
                OpenKind::Control
            }
            Node::Pipe => {
                if writing {
                    return err(libc::EACCES);
                }
                state.catch_up(now);
                let parts: Vec<&str> = rel.split('/').filter(|p| !p.is_empty()).collect();
                let cpu = match parts.as_slice() {
                    ["per_cpu", cpu, _] => cpu_index(cpu, state.cpu_count),
                    _ => None,
                };
                let inst = state.instances.get_mut(&instance).expect("exists");
                let pipe = match cpu {
                    Some(c) => {
                        if let std::collections::btree_map::Entry::Vacant(v) = inst.per_cpu.entry(c)
                        {
                            v.insert(Pipe::new(shared.as_ref())?);
                        }
                        inst.per_cpu.get(&c).expect("made")
                    }
                    None => inst
                        .pipe
                        .get_or_insert_with(|| Pipe::new(shared.as_ref()).expect("pipe")),
                };
                let fd = snare_interpose::real(|| unsafe { libc::dup(pipe.read) });
                if fd < 0 {
                    return err(libc::EMFILE);
                }
                inst.pipe_fds += 1;
                set_cloexec(fd, flags);
                state.open.insert(
                    fd,
                    Open {
                        path,
                        kind: OpenKind::Pipe {
                            instance: instance.clone(),
                        },
                        data: Vec::new(),
                        cursor: 0,
                        flags: status_flags(flags),
                        writable: false,
                    },
                );
                return ok(fd as i64);
            }
            Node::TimerlatFd => {
                let parts: Vec<&str> = rel.split('/').filter(|p| !p.is_empty()).collect();
                let cpu = match parts.as_slice() {
                    ["osnoise", "per_cpu", cpu, _] => cpu_index(cpu, state.cpu_count)?,
                    _ => return err(libc::ENOENT),
                };
                if !state.root {
                    return err(libc::EACCES);
                }
                if !state.timerlat_running() || state.osnoise.options.contains("OSNOISE_WORKLOAD") {
                    return err(libc::EINVAL);
                }
                if let Some(a) = self.affinity()
                    && a != [cpu]
                {
                    return err(libc::EPERM);
                }
                if state.readers.values().any(|r| r.cpu == cpu) {
                    return err(libc::EBUSY);
                }
                OpenKind::TimerlatFd { cpu }
            }
        };
        let fd = match self.reserve_fd() {
            Ok(fd) => fd,
            Err(e) => return err(e),
        };
        let data = if matches!(kind, OpenKind::Control) && !writing {
            state.render(&instance, &rel).into_bytes()
        } else {
            Vec::new()
        };
        if let OpenKind::TimerlatFd { cpu } = kind {
            state.readers.insert(fd, Reader { cpu, killed: false });
        }
        set_cloexec(fd, flags);
        state.open.insert(
            fd,
            Open {
                path,
                kind,
                data,
                cursor: 0,
                flags: status_flags(flags),
                writable: writing,
            },
        );
        ok(fd as i64)
    }

    unsafe fn openat(
        &self,
        dirfd: c_int,
        path: *const c_char,
        flags: c_int,
        mode: u32,
    ) -> Option<FsResult> {
        let absolute = unsafe { path.as_ref() }.is_some_and(|p| *p == b'/' as c_char);
        if dirfd != libc::AT_FDCWD && !absolute {
            return None;
        }
        unsafe { self.open(path, flags, mode) }
    }

    unsafe fn stat(&self, path: *const c_char, buf: *mut u8) -> Option<FsResult> {
        let path = unsafe { path_of(path) }?;
        if let Err(e) = self.located(&path)? {
            return err(e);
        }
        self.stat_of(&path, buf, false)
            .or_else(|| err(libc::ENOENT))
    }

    unsafe fn lstat(&self, path: *const c_char, buf: *mut u8) -> Option<FsResult> {
        unsafe { self.stat(path, buf) }
    }

    unsafe fn fstatat(
        &self,
        dirfd: c_int,
        path: *const c_char,
        buf: *mut u8,
        _flags: c_int,
    ) -> Option<FsResult> {
        if unsafe { path.as_ref() }.is_some_and(|p| *p == 0) {
            return unsafe { self.fstat(dirfd, buf) };
        }
        unsafe { self.stat(path, buf) }
    }

    unsafe fn statx(
        &self,
        dirfd: c_int,
        path: *const c_char,
        _flags: c_int,
        _mask: u32,
        buf: *mut u8,
    ) -> Option<FsResult> {
        if unsafe { path.as_ref() }.is_some_and(|p| *p == 0) {
            let p = self.state().open.get(&dirfd)?.path.clone();
            return self.stat_of(&p, buf, true).or_else(|| err(libc::ENOENT));
        }
        let path = unsafe { path_of(path) }?;
        if let Err(e) = self.located(&path)? {
            return err(e);
        }
        self.stat_of(&path, buf, true).or_else(|| err(libc::ENOENT))
    }

    unsafe fn access(&self, path: *const c_char, mode: c_int) -> Option<FsResult> {
        let path = unsafe { path_of(path) }?;
        let (instance, rel) = match self.located(&path)? {
            Ok(at) => at,
            Err(e) => return err(e),
        };
        let state = self.state();
        let Some(node) = state.node(&instance, &rel) else {
            return err(libc::ENOENT);
        };
        if mode & libc::W_OK != 0 {
            let writable = match node {
                Node::File { writable } => writable,
                Node::Dir(_) | Node::TimerlatFd => true,
                Node::Pipe => false,
            };
            if !writable || !state.root {
                return err(libc::EACCES);
            }
        }
        if mode & libc::X_OK != 0 && !matches!(node, Node::Dir(_)) {
            return err(libc::EACCES);
        }
        ok(0)
    }

    unsafe fn faccessat(
        &self,
        _dirfd: c_int,
        path: *const c_char,
        mode: c_int,
        _flags: c_int,
    ) -> Option<FsResult> {
        unsafe { self.access(path, mode) }
    }

    unsafe fn fstat(&self, fd: c_int, buf: *mut u8) -> Option<FsResult> {
        let p = {
            let state = self.state();
            if let Some(d) = state.dirs.get(&fd) {
                let _ = d;
                return host_stat(buf, Path::new(ROOT), MODE_DIR, 0, 2, self.boot);
            }
            state.open.get(&fd)?.path.clone()
        };
        self.stat_of(&p, buf, false).or_else(|| err(libc::ENOENT))
    }

    unsafe fn lseek(&self, fd: c_int, offset: i64, whence: c_int) -> Option<FsResult> {
        let mut state = self.state();
        let file = state.open.get_mut(&fd)?;
        if file.kind != OpenKind::Control {
            return err(libc::ESPIPE);
        }
        let base = match whence {
            libc::SEEK_SET => 0,
            libc::SEEK_CUR => file.cursor as i64,
            libc::SEEK_END => file.data.len() as i64,
            _ => return err(libc::EINVAL),
        };
        let target = base.saturating_add(offset);
        if target < 0 {
            return err(libc::EINVAL);
        }
        file.cursor = target as usize;
        ok(target)
    }

    unsafe fn pread(&self, fd: c_int, buf: *mut u8, len: usize, offset: i64) -> Option<FsResult> {
        let state = self.state();
        let file = state.open.get(&fd)?;
        if file.kind != OpenKind::Control || offset < 0 {
            return err(libc::ESPIPE);
        }
        let start = (offset as usize).min(file.data.len());
        let n = len.min(file.data.len() - start);
        if n != 0 {
            unsafe { std::ptr::copy_nonoverlapping(file.data[start..].as_ptr(), buf, n) };
        }
        ok(n as i64)
    }

    unsafe fn read(&self, fd: c_int, buf: *mut u8, len: usize) -> Option<FsResult> {
        let kind = {
            let state = self.state();
            state.open.get(&fd)?.kind.clone()
        };
        match kind {
            OpenKind::Control => {
                let mut state = self.state();
                let file = state.open.get_mut(&fd)?;
                if file.writable && file.data.is_empty() {
                    return err(libc::EBADF);
                }
                let start = file.cursor.min(file.data.len());
                let n = len.min(file.data.len() - start);
                if n != 0 {
                    unsafe { std::ptr::copy_nonoverlapping(file.data[start..].as_ptr(), buf, n) };
                }
                file.cursor = start + n;
                ok(n as i64)
            }
            OpenKind::Pipe { .. } => {
                let now = self.now();
                self.state().catch_up(now);
                let n = snare_interpose::real(|| unsafe { libc::read(fd, buf.cast(), len) });
                if n < 0 {
                    err(std::io::Error::last_os_error()
                        .raw_os_error()
                        .unwrap_or(libc::EIO))
                } else {
                    ok(n as i64)
                }
            }
            OpenKind::TimerlatFd { cpu } => {
                let period = {
                    let state = self.state();
                    if state.readers.get(&fd).is_some_and(|r| r.killed) {
                        return err(libc::EINTR);
                    }
                    Duration::from_micros(state.osnoise.timerlat_period_us.max(1))
                };
                self.clock.sleep(SleepRequest::For(period));
                let now = self.now();
                let mut state = self.state();
                if state.readers.get(&fd).is_none_or(|r| r.killed) {
                    return err(libc::EINTR);
                }
                let instance = state
                    .instances
                    .iter()
                    .find(|(_, i)| i.tracer == "timerlat")
                    .map(|(n, _)| n.clone());
                if let Some(instance) = instance {
                    state.emit_timerlat(&instance, cpu, now, true);
                }
                ok(0)
            }
        }
    }

    unsafe fn write(&self, fd: c_int, buf: *const u8, len: usize) -> Option<FsResult> {
        let (path, kind, writable) = {
            let state = self.state();
            let f = state.open.get(&fd)?;
            (f.path.clone(), f.kind.clone(), f.writable)
        };
        if kind != OpenKind::Control || !writable {
            return err(libc::EBADF);
        }
        let text = unsafe { std::slice::from_raw_parts(buf, len) };
        let text = String::from_utf8_lossy(text).into_owned();
        let (instance, rel) = match self.located(&path)? {
            Ok(at) => at,
            Err(e) => return err(e),
        };
        let shared = self.shared();
        let now = self.now();
        let mut state = self.state();
        match state.write(shared.as_ref(), &instance, &rel, &text, now) {
            Ok(()) => ok(len as i64),
            Err(e) => err(e),
        }
    }

    unsafe fn pwrite(
        &self,
        fd: c_int,
        buf: *const u8,
        len: usize,
        _offset: i64,
    ) -> Option<FsResult> {
        unsafe { self.write(fd, buf, len) }
    }

    unsafe fn ftruncate(&self, fd: c_int, _len: i64) -> Option<FsResult> {
        self.owns(fd).then_some(FsResult::Ok(0))
    }

    unsafe fn fsync(&self, fd: c_int) -> Option<FsResult> {
        self.owns(fd).then_some(FsResult::Ok(0))
    }

    unsafe fn close(&self, fd: c_int) -> Option<FsResult> {
        let mut state = self.state();
        let removed = state.open.remove(&fd)?;
        if let Some(Some(file)) = Some(removed) {
            match file.kind {
                OpenKind::Pipe { instance } => {
                    if let Some(i) = state.instances.get_mut(&instance) {
                        i.pipe_fds = i.pipe_fds.saturating_sub(1);
                    }
                }
                OpenKind::TimerlatFd { .. } => {
                    state.readers.remove(&fd);
                }
                OpenKind::Control => {}
            }
        }
        snare_interpose::real(|| unsafe { libc::close(fd) });
        ok(0)
    }

    unsafe fn fd_replaced(&self, fd: c_int) -> Option<FsResult> {
        self.state().open.remove(&fd)?;
        ok(0)
    }

    unsafe fn fcntl(&self, fd: c_int, cmd: c_int, arg: i64) -> Option<FsResult> {
        let mut state = self.state();
        let kind = state.open.get(&fd)?.kind.clone();
        match cmd {
            libc::F_DUPFD | libc::F_DUPFD_CLOEXEC => {
                let result = descriptor_fcntl(fd, cmd, arg)?;
                if let FsResult::Ok(newfd) = result {
                    state.open.alias(fd, newfd as c_int);
                }
                Some(result)
            }
            libc::F_GETFD | libc::F_SETFD => descriptor_fcntl(fd, cmd, arg),
            libc::F_GETFL | libc::F_SETFL if matches!(kind, OpenKind::Pipe { .. }) => {
                descriptor_fcntl(fd, cmd, arg)
            }
            libc::F_GETFL => ok(state.open.get(&fd)?.flags as i64),
            libc::F_SETFL => {
                let file = state.open.get_mut(&fd)?;
                let mask = libc::O_APPEND | libc::O_NONBLOCK;
                file.flags = (file.flags & !mask) | (arg as c_int & mask);
                ok(0)
            }
            _ => err(libc::EINVAL),
        }
    }

    unsafe fn dup(&self, oldfd: c_int, newfd: c_int) -> Option<FsResult> {
        self.state().open.alias(oldfd, newfd)?;
        ok(newfd as i64)
    }

    unsafe fn dup_to(&self, oldfd: c_int, newfd: c_int, flags: Option<c_int>) -> Option<FsResult> {
        let mut state = self.state();
        state.open.get(&oldfd)?;
        let result = crate::fabric::duplicate_to(oldfd, newfd, flags);
        if result < 0 {
            return err(std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EBADF));
        }
        state.open.alias(oldfd, newfd);
        ok(result as i64)
    }

    unsafe fn mkdir(&self, path: *const c_char, _mode: u32) -> Option<FsResult> {
        let path = unsafe { path_of(path) }?;
        let (instance, rel) = match self.located(&path)? {
            Ok(at) => at,
            Err(e) => return err(e),
        };
        let mut state = self.state();
        if !instance.is_empty() && rel.is_empty() {
            if !state.root {
                return err(libc::EACCES);
            }
            if state.instances.contains_key(&instance) {
                return err(libc::EEXIST);
            }
            let snapshot = state.spec.snapshot;
            let cpus = state.cpu_count;
            state
                .instances
                .insert(instance, Instance::new(cpus, snapshot));
            return ok(0);
        }
        if state.node(&instance, &rel).is_some() {
            return err(libc::EEXIST);
        }
        err(libc::EPERM)
    }

    unsafe fn mkdirat(&self, dirfd: c_int, path: *const c_char, mode: u32) -> Option<FsResult> {
        let absolute = unsafe { path.as_ref() }.is_some_and(|p| *p == b'/' as c_char);
        if dirfd != libc::AT_FDCWD && !absolute {
            return None;
        }
        unsafe { self.mkdir(path, mode) }
    }

    unsafe fn rmdir(&self, path: *const c_char) -> Option<FsResult> {
        let path = unsafe { path_of(path) }?;
        let (instance, rel) = match self.located(&path)? {
            Ok(at) => at,
            Err(e) => return err(e),
        };
        if !instance.is_empty() && rel.is_empty() {
            if !self.state().root {
                return err(libc::EACCES);
            }
            return self.remove_instance(&instance);
        }
        let state = self.state();
        match state.node(&instance, &rel) {
            Some(Node::Dir(_)) => err(libc::EPERM),
            Some(_) => err(libc::ENOTDIR),
            None => err(libc::ENOENT),
        }
    }

    unsafe fn unlink(&self, path: *const c_char) -> Option<FsResult> {
        let path = unsafe { path_of(path) }?;
        let (instance, rel) = match self.located(&path)? {
            Ok(at) => at,
            Err(e) => return err(e),
        };
        match self.state().node(&instance, &rel) {
            Some(Node::Dir(_)) => err(libc::EISDIR),
            Some(_) => err(libc::EPERM),
            None => err(libc::ENOENT),
        }
    }

    unsafe fn opendir(&self, path: *const c_char) -> Option<FsResult> {
        let path = unsafe { path_of(path) }?;
        let (instance, rel) = match self.located(&path)? {
            Ok(at) => at,
            Err(e) => return err(e),
        };
        let mut state = self.state();
        let entries = match state.node(&instance, &rel) {
            Some(Node::Dir(e)) => e,
            Some(_) => return err(libc::ENOTDIR),
            None => return err(libc::ENOENT),
        };
        let fd = match self.reserve_fd() {
            Ok(fd) => fd,
            Err(e) => return err(e),
        };
        let stream = DirStream::new(entries);
        state.dirs.insert(fd, stream);
        set_cloexec(fd, libc::O_CLOEXEC);
        ok(fd as i64)
    }

    unsafe fn readdir(&self, fd: c_int) -> Option<FsResult> {
        let mut state = self.state();
        let d = state.dirs.get_mut(&fd)?;
        let Some(e) = d.entries.get(d.cursor) else {
            return ok(0);
        };
        let (name, ino, dtype) = (e.name.clone(), e.ino, e.dtype);
        d.cursor += 1;
        crate::fs_sim::fill_dirent(&mut d.scratch, &name, ino, dtype);
        ok((&*d.scratch as *const _) as i64)
    }

    unsafe fn fdopendir(&self, fd: c_int) -> Option<FsResult> {
        if self.state().dirs.contains_key(&fd) {
            ok(fd as i64)
        } else {
            None
        }
    }

    #[cfg(target_os = "linux")]
    unsafe fn getdents64(&self, fd: c_int, buf: *mut u8, len: usize) -> Option<FsResult> {
        let mut state = self.state();
        if let Some(stream) = state.dirs.get_mut(&fd) {
            crate::fs_sim::pack_directory(stream, buf, len)
        } else if state.open.contains_key(&fd) {
            err(libc::ENOTDIR)
        } else {
            None
        }
    }

    unsafe fn closedir(&self, fd: c_int) -> Option<FsResult> {
        self.state().dirs.remove(&fd)?;
        snare_interpose::real(|| unsafe { libc::close(fd) });
        ok(0)
    }
}

/// The test's view of a sim's tracefs, from [`SimHost::tracefs`](crate::SimHost::tracefs):
/// what the code under test registered, and the hooks that make the tracers report something.
#[derive(Debug, Clone)]
pub struct TracefsSim {
    plane: Arc<TracefsPlane>,
}

impl TracefsSim {
    pub(crate) fn new(plane: Arc<TracefsPlane>) -> Self {
        Self { plane }
    }

    /// The faults recorded so far (see [`TracefsFault`]).
    pub fn faults(&self) -> Vec<TracefsFault> {
        self.plane.state().faults.clone()
    }

    /// The `error_log` lines: why writes were refused.
    pub fn error_log(&self) -> Vec<String> {
        self.plane.state().error_log.clone()
    }

    /// The instances under `instances/`.
    pub fn instances(&self) -> Vec<String> {
        self.plane
            .state()
            .instances
            .keys()
            .filter(|k| !k.is_empty())
            .cloned()
            .collect()
    }

    /// The tracer `instance` (`""` for the top level) runs.
    pub fn tracer(&self, instance: &str) -> Option<String> {
        self.plane
            .state()
            .instance(instance)
            .map(|i| i.tracer.clone())
    }

    /// Whether `instance` records.
    pub fn tracing_on(&self, instance: &str) -> Option<bool> {
        self.plane.state().instance(instance).map(|i| i.tracing_on)
    }

    /// The triggers on `event` (`system/event`) in `instance`, as the kernel prints them.
    pub fn triggers(&self, instance: &str, event: &str) -> Vec<String> {
        self.plane
            .state()
            .instance(instance)
            .and_then(|i| i.events.get(event))
            .map(|e| e.triggers.iter().map(Trigger::text).collect())
            .unwrap_or_default()
    }

    /// The events enabled in `instance`.
    pub fn enabled_events(&self, instance: &str) -> Vec<String> {
        self.plane
            .state()
            .instance(instance)
            .map(|i| {
                i.events
                    .iter()
                    .filter(|(_, e)| e.enabled)
                    .map(|(k, _)| k.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The synthetic events registered, by name.
    pub fn synthetic_events(&self) -> Vec<String> {
        self.plane.state().synthetic.keys().cloned().collect()
    }

    /// One `osnoise/<file>` as it reads.
    pub fn osnoise(&self, file: &str) -> String {
        self.plane
            .state()
            .render("", &format!("osnoise/{file}"))
            .trim_end()
            .to_owned()
    }

    /// The CPUs a thread waits on `timerlat_fd` of.
    pub fn timerlat_readers(&self) -> Vec<usize> {
        let mut cpus: Vec<usize> = self.plane.state().readers.values().map(|r| r.cpu).collect();
        cpus.sort_unstable();
        cpus
    }

    /// Records one tracepoint hit, `event` as `system/event` with its `fields` (`cpu` for the
    /// CPU, `comm` for the recording task; a variable a trigger tracks, such as `wakelat`, by
    /// its name), on every instance: into the ring buffer and pipes of those that enable it,
    /// and through every hist trigger on it, whose `onmatch` actions in turn record the
    /// synthetic event with the parameters taken from these fields.
    pub fn inject(&self, event: &str, fields: &[(&str, &str)]) {
        let now = self.plane.now();
        let map: BTreeMap<String, String> = fields
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        self.plane.state().inject(event, &map, now, 0);
    }

    /// What the timerlat tracer reports for `cpu` from now on: the interrupt, thread and
    /// user-return latencies, in nanoseconds.
    pub fn set_timerlat(&self, cpu: usize, irq_ns: u64, thread_ns: u64, user_ns: u64) {
        let mut state = self.plane.state();
        let s = state.samples.entry(cpu).or_default();
        s.irq_ns = irq_ns;
        s.thread_ns = thread_ns;
        s.user_ns = user_ns;
    }

    /// What the osnoise tracer reports for `cpu` from now on, per sample: the noise and the
    /// longest single interruption in microseconds, and the hardware and NMI counts.
    pub fn set_osnoise(&self, cpu: usize, noise_us: u64, max_sample_us: u64, hw: u64, nmi: u64) {
        let mut state = self.plane.state();
        let s = state.samples.entry(cpu).or_default();
        s.noise_us = noise_us;
        s.max_sample_us = max_sample_us;
        s.hw = hw;
        s.nmi = nmi;
    }
}
