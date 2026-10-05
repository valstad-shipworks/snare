//! The interrupts, NAPIs and kernel threads of simulated interfaces. Each
//! Ethernet interface gets them on first use: one interrupt per combined
//! channel from 120 up (`<nic>-TxRx-<q>`, with its `irq/<n>-<nic>-TxRx-<q>`
//! handler thread at `Fifo(50)`), one NAPI per channel from 8193 up, and a
//! `napi/<nic>-<id>` thread per NAPI while NAPI is threaded. The host's
//! `ksoftirqd/<cpu>` threads come with the first interface. Only Linux
//! has them.

use ::fast_talker::rt::Scheduler;

use crate::fast_talker_shim::slot::{FtSlot, IrqRec, NapiRec};
use crate::netif::{NicId, NicRec, with_nic_rec};
use crate::os::OsSemantics;
use crate::threads::{add_kernel_thread, exit_kernel_thread};

const IRQ_THREAD_PRIORITY: u8 = 50;

/// The kernel objects an interface dropped, to be torn down once the
/// state lock is released.
pub(crate) struct Retired {
    irqs: Vec<u32>,
    napi_threads: Vec<u64>,
}

/// Take `n`'s interrupts and NAPIs off it, so the next use makes new ones.
pub(crate) fn retire_locked(n: &mut NicRec) -> Retired {
    let irqs = std::mem::take(&mut n.ft.irqs);
    let napi_threads = n.ft.napis.drain(..).filter_map(|x| x.thread).collect();
    n.ft.objects_built = false;
    Retired { irqs, napi_threads }
}

/// Tear down the kernel objects of the removed interface `n`.
pub(crate) fn retire_removed(mut n: NicRec) {
    let id = n.id;
    let r = retire_locked(&mut n);
    rebuild(id, r);
}

/// Tear down what `retire_locked` took off the interface `id`, and give it
/// new objects.
pub(crate) fn rebuild(id: NicId, r: Retired) {
    let slot = crate::state::ft_slot();
    let _kernel = slot.kernel.lock();
    let irq_threads: Vec<u64> = {
        let mut g = slot.inner.lock();
        r.irqs
            .iter()
            .filter_map(|n| g.irqs.remove(n))
            .flat_map(|rec| rec.threads)
            .collect()
    };
    for tid in irq_threads.into_iter().chain(r.napi_threads) {
        exit_kernel_thread(tid);
    }
    ensure_locked(&slot, id);
}

/// Give every interface its kernel objects.
pub(crate) fn ensure_all() {
    let ids: Vec<NicId> = crate::nics().into_iter().map(|n| n.id).collect();
    for id in ids {
        ensure(id);
    }
}

fn seed_per_cpu(slot: &FtSlot) {
    let count = {
        let mut g = slot.inner.lock();
        if g.kernel_seeded {
            return;
        }
        g.kernel_seeded = true;
        g.cpus.count
    };
    for cpu in 0..count {
        add_kernel_thread(&format!("ksoftirqd/{cpu}"));
    }
}

/// Give the interface `id` its interrupts, NAPIs and kernel threads, unless
/// it has them or is the loopback.
pub(crate) fn ensure(id: NicId) {
    let slot = crate::state::ft_slot();
    let _kernel = slot.kernel.lock();
    ensure_locked(&slot, id);
}

fn ensure_locked(slot: &FtSlot, id: NicId) {
    let wanted = with_nic_rec(id, |n, os| {
        let linux = os == OsSemantics::Linux;
        (linux && !n.ft.objects_built && !n.is_loopback()).then(|| {
            (
                n.spec.name.clone(),
                n.ft.channels.combined.max(1),
                n.ft.threaded_napi,
            )
        })
    })
    .flatten();
    let Some((name, queues, threaded)) = wanted else {
        return;
    };
    seed_per_cpu(slot);
    let (irqs, napis): (Vec<u32>, Vec<u32>) = {
        let mut g = slot.inner.lock();
        let irq = g.next_irq;
        let napi = g.next_napi;
        g.next_irq += queues;
        g.next_napi += queues;
        (
            (irq..irq + queues).collect(),
            (napi..napi + queues).collect(),
        )
    };
    let irq_threads: Vec<u64> = irqs
        .iter()
        .enumerate()
        .map(|(q, n)| add_kernel_thread(&format!("irq/{n}-{name}-TxRx-{q}")))
        .collect();
    let napi_threads: Vec<Option<u64>> = napis
        .iter()
        .map(|napi| threaded.then(|| add_kernel_thread(&format!("napi/{name}-{napi}"))))
        .collect();
    {
        let mut g = slot.inner.lock();
        let affinity = g.irq_default_affinity.clone();
        for (q, (&n, &tid)) in irqs.iter().zip(&irq_threads).enumerate() {
            g.irqs.insert(
                n,
                IrqRec {
                    name: format!("{name}-TxRx-{q}"),
                    nic: Some(id),
                    affinity: affinity.clone(),
                    threads: vec![tid],
                    log: Vec::new(),
                },
            );
            let rt = g.rt.entry(tid).or_default();
            rt.scheduler = Some(Scheduler::Fifo(IRQ_THREAD_PRIORITY));
            rt.affinity = Some(affinity.clone());
        }
    }
    let committed = with_nic_rec(id, |n, _| {
        if n.ft.objects_built || n.ft.channels.combined.max(1) != queues {
            return false;
        }
        n.ft.napis = napis
            .iter()
            .zip(&irqs)
            .zip(&napi_threads)
            .map(|((&id, &irq), &thread)| NapiRec {
                id,
                irq: Some(irq),
                thread,
            })
            .collect();
        n.ft.irqs = irqs.clone();
        n.ft.objects_built = true;
        true
    });
    if committed == Some(true) {
        sync_napi_threads_locked(id);
        return;
    }
    slot.inner.lock().irqs.retain(|n, _| !irqs.contains(n));
    for tid in irq_threads
        .into_iter()
        .chain(napi_threads.into_iter().flatten())
    {
        exit_kernel_thread(tid);
    }
    if committed.is_some() {
        ensure_locked(slot, id);
    }
}

/// Start a `napi/<nic>-<id>` thread for each NAPI of the interface `id`
/// while its NAPI is threaded, and stop them when it is not.
pub(crate) fn sync_napi_threads(id: NicId) {
    let slot = crate::state::ft_slot();
    let _kernel = slot.kernel.lock();
    sync_napi_threads_locked(id);
}

fn sync_napi_threads_locked(id: NicId) {
    let Some((name, threaded, napis)) = with_nic_rec(id, |n, _| {
        (n.spec.name.clone(), n.ft.threaded_napi, n.ft.napis.clone())
    }) else {
        return;
    };
    let mut changes: Vec<(u32, Option<u64>)> = Vec::new();
    for napi in napis {
        match (threaded, napi.thread) {
            (true, None) => {
                let tid = add_kernel_thread(&format!("napi/{name}-{}", napi.id));
                changes.push((napi.id, Some(tid)));
            }
            (false, Some(tid)) => {
                exit_kernel_thread(tid);
                changes.push((napi.id, None));
            }
            _ => {}
        }
    }
    if changes.is_empty() {
        return;
    }
    with_nic_rec(id, |n, _| {
        for (napi, thread) in changes {
            if let Some(rec) = n.ft.napis.iter_mut().find(|r| r.id == napi) {
                rec.thread = thread;
            }
        }
    });
}
