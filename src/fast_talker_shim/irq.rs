//! fast-talker's `irq` over the simulated host's interrupts: one per
//! combined channel of each interface (`<nic>-TxRx-<q>`, see
//! [`nic`](super::nic)), plus any a test adds with
//! [`sim::set_irq`](super::sim::set_irq). Linux only. Changing affinity
//! needs `root` or `net_admin`, else `EACCES`; tests read the result back
//! with [`sim::irq`](super::sim::irq).

use std::io;

use ::fast_talker::rt::Scheduler;

use super::platform::{Item, require};
use super::rt::Thread;
use super::sim::{FtEntry, FtEvent, NicApply};
use super::slot::FtState;
use crate::netif::Privileges;
use crate::os::{OsSemantics, SysErrno, code_err, os_error_code, sys_err_for};
use crate::time::Instant;

const ENOENT: i32 = 2;

/// A hardware interrupt line of the simulated host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Irq(u32);

fn no_irq(os: OsSemantics) -> io::Error {
    code_err(os, ENOENT, "ENOENT", io::ErrorKind::NotFound)
}

fn sorted(cpus: &[usize]) -> Vec<usize> {
    let mut v = cpus.to_vec();
    v.sort_unstable();
    v.dedup();
    v
}

/// Check the caller may move interrupts to `cpus`: `root` or `net_admin`,
/// and a non-empty list of CPUs the host has.
fn check(g: &FtState, cpus: &[usize], os: OsSemantics, p: &Privileges) -> io::Result<()> {
    if !p.root && !p.net_admin {
        return Err(sys_err_for(os, SysErrno::Access));
    }
    if cpus.is_empty() || cpus.iter().any(|&c| c >= g.cpus.count) {
        return Err(sys_err_for(os, SysErrno::Inval));
    }
    Ok(())
}

/// Move `irq` to `cpus` in `g`; its handler threads follow.
fn place(g: &mut FtState, irq: u32, cpus: &[usize]) -> bool {
    let Some(rec) = g.irqs.get_mut(&irq) else {
        return false;
    };
    rec.affinity = cpus.to_vec();
    let threads = rec.threads.clone();
    for tid in threads {
        g.rt.entry(tid).or_default().affinity = Some(cpus.to_vec());
    }
    true
}

/// Run `f` under the shim's lock and log it on `irqs` and as an
/// [`FtEvent::Irq`] for `irq`.
fn record<R>(
    irq: Option<u32>,
    irqs: impl FnOnce(&FtState) -> Vec<u32>,
    what: String,
    f: impl FnOnce(&mut FtState, OsSemantics, &Privileges) -> io::Result<R>,
) -> io::Result<R> {
    let os = crate::os_semantics();
    let privs = crate::privileges();
    let at = Instant::now();
    let tid = crate::threads::current_tid();
    let slot = crate::state::ft_slot();
    let mut g = slot.inner.lock();
    let targets = irqs(&g);
    let result = f(&mut g, os, &privs);
    let status = result.as_ref().map(|_| ()).map_err(io::Error::kind);
    let entry = NicApply {
        at,
        tid,
        what: what.clone(),
        result: status,
        os_error: result.as_ref().err().and_then(os_error_code),
    };
    for n in targets {
        if let Some(rec) = g.irqs.get_mut(&n) {
            rec.log.push(entry.clone());
        }
    }
    g.events.push(FtEntry {
        at,
        tid,
        event: FtEvent::Irq {
            irq,
            what,
            result: status,
        },
    });
    result
}

impl Irq {
    /// Interrupt number `n`.
    pub fn new(n: u32) -> Self {
        Self(n)
    }

    /// Every interrupt the simulated host has, in number order.
    pub fn all() -> io::Result<Vec<Irq>> {
        require(Item::Irq)?;
        super::nic::ensure_all();
        let slot = crate::state::ft_slot();
        let g = slot.inner.lock();
        Ok(g.irqs.keys().copied().map(Irq).collect())
    }

    /// Interrupt number.
    pub fn number(&self) -> u32 {
        self.0
    }

    fn read<R>(&self, f: impl FnOnce(&super::slot::IrqRec) -> R) -> io::Result<R> {
        require(Item::Irq)?;
        let os = crate::os_semantics();
        let slot = crate::state::ft_slot();
        let g = slot.inner.lock();
        g.irqs.get(&self.0).map(f).ok_or_else(|| no_irq(os))
    }

    /// Handler names on this line (`eth0-TxRx-0`).
    pub fn name(&self) -> io::Result<String> {
        self.read(|r| r.name.clone())
    }

    /// CPUs this interrupt may be delivered to.
    pub fn affinity(&self) -> io::Result<Vec<usize>> {
        self.read(|r| r.affinity.clone())
    }

    /// CPUs the interrupt controller delivers it to: the first of
    /// [`Irq::affinity`], as x86 does.
    pub fn effective_affinity(&self) -> io::Result<Vec<usize>> {
        self.read(|r| r.affinity.first().copied().into_iter().collect())
    }

    /// Delivers this interrupt to `cpus`. Its handler threads follow. An
    /// empty list, or a CPU the host lacks, is `EINVAL`.
    pub fn set_affinity(&self, cpus: &[usize]) -> io::Result<()> {
        require(Item::Irq)?;
        let n = self.0;
        let cpus = sorted(cpus);
        record(
            Some(n),
            |_| vec![n],
            format!("set_affinity({cpus:?})"),
            |g, os, privs| {
                if !g.irqs.contains_key(&n) {
                    return Err(no_irq(os));
                }
                check(g, &cpus, os, privs)?;
                place(g, n, &cpus);
                Ok(())
            },
        )
    }

    /// Kernel threads running this interrupt's handlers (`irq/<n>-*`).
    pub fn threads(&self) -> io::Result<Vec<Thread>> {
        Thread::find(&format!("irq/{}-", self.0))
    }

    /// Delivers the interrupt to `cpus` and sets its handler threads'
    /// scheduling.
    pub fn pin(&self, cpus: &[usize], scheduler: Scheduler) -> io::Result<()> {
        self.set_affinity(cpus)?;
        for t in self.threads()? {
            t.set_scheduler(scheduler)?;
        }
        Ok(())
    }
}

/// The affinity new interrupts start with: every CPU until set.
pub fn default_affinity() -> io::Result<Vec<usize>> {
    require(Item::Irq)?;
    Ok(crate::state::ft_slot()
        .inner
        .lock()
        .irq_default_affinity
        .clone())
}

/// Moves every interrupt, and the default for new ones, to `cpus`.
/// Returns how many moved. Missing privilege fails on the default mask,
/// before any interrupt moves.
pub fn set_all_affinity(cpus: &[usize]) -> io::Result<usize> {
    require(Item::Irq)?;
    super::nic::ensure_all();
    let cpus = sorted(cpus);
    record(
        None,
        |g| g.irqs.keys().copied().collect(),
        format!("set_all_affinity({cpus:?})"),
        |g, os, privs| {
            check(g, &cpus, os, privs)?;
            g.irq_default_affinity = cpus.clone();
            let all: Vec<u32> = g.irqs.keys().copied().collect();
            Ok(all.into_iter().filter(|&n| place(g, n, &cpus)).count())
        },
    )
}
