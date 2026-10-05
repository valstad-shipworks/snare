//! Queueing disciplines. Each interface starts with the kernel's default:
//! `noqueue` on the loopback, `pfifo_fast` on a single-queue device, and
//! otherwise an `mq` root without a handle over one `pfifo_fast` per
//! transmit queue. ETF qdiscs set here are the ones timed sends
//! ([`Timestamped::send_at`](crate::fast_talker::Timestamped::send_at))
//! wait in.

use std::io;

use super::{Etf, Need, Nic, Qdisc, done, mk_qdisc, not_supported};
use crate::fast_talker_shim::platform::Item;
use crate::fast_talker_shim::sim::QdiscSnapshot;
use crate::netif::NicRec;
use crate::os::{OsSemantics, code_err};

const TC_H_ROOT: u32 = 0xffff_ffff;
/// Handle given to a root `mq` that had none.
const MQ_HANDLE: u32 = 0x7ff0_0000;
/// The first handle the kernel picks for a qdisc added without one.
const AUTO_HANDLE: u32 = 0x8001_0000;
const ENOENT: i32 = 2;
const DEFAULT_KIND: &str = "pfifo_fast";

fn tx_queues(n: &NicRec) -> u16 {
    if n.is_loopback() {
        return 1;
    }
    let c = n.ft.channels;
    u16::try_from((c.combined + c.tx).max(1)).unwrap_or(u16::MAX)
}

fn entry(
    kind: &str,
    handle: u32,
    parent: u32,
    queue: Option<u16>,
    etf: Option<Etf>,
) -> QdiscSnapshot {
    QdiscSnapshot {
        kind: kind.to_string(),
        handle,
        parent,
        queue,
        etf,
    }
}

/// The interface's qdiscs, root first, as `tc qdisc show` lists them.
pub(crate) fn qdisc_tree(n: &NicRec) -> Vec<QdiscSnapshot> {
    if let Some(etf) = n.ft.etf.get(&None) {
        return vec![entry("etf", AUTO_HANDLE, TC_H_ROOT, None, Some(*etf))];
    }
    if n.is_loopback() {
        return vec![entry("noqueue", 0, TC_H_ROOT, None, None)];
    }
    let tx = tx_queues(n);
    if tx == 1 && !n.ft.root_mq_named {
        return vec![entry(DEFAULT_KIND, 0, TC_H_ROOT, None, None)];
    }
    let mq = if n.ft.root_mq_named { MQ_HANDLE } else { 0 };
    let mut out = vec![entry("mq", mq, TC_H_ROOT, None, None)];
    for q in 0..tx {
        let parent = mq | (u32::from(q) + 1);
        let child = match n.ft.etf.get(&Some(q)) {
            Some(etf) => entry(
                "etf",
                AUTO_HANDLE + ((u32::from(q) + 1) << 16),
                parent,
                Some(q),
                Some(*etf),
            ),
            None => {
                let kind =
                    n.ft.queue_qdisc
                        .get(&q)
                        .map_or(DEFAULT_KIND, String::as_str);
                entry(kind, 0, parent, Some(q), None)
            }
        };
        out.push(child);
    }
    out
}

fn root_kind(n: &NicRec) -> String {
    qdisc_tree(n)
        .into_iter()
        .next()
        .map(|q| q.kind)
        .unwrap_or_default()
}

fn no_class(n: &NicRec) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!(
            "{}: root qdisc is {}; a per-queue qdisc needs mq, mqprio or taprio with a handle",
            n.spec.name,
            root_kind(n)
        ),
    )
}

fn no_queue(os: OsSemantics) -> io::Error {
    code_err(os, ENOENT, "ENOENT", io::ErrorKind::NotFound)
}

impl Nic {
    /// The interface's qdiscs.
    pub fn qdiscs(&self) -> io::Result<Vec<Qdisc>> {
        self.get(Item::LinuxNicTuning, |n, _| {
            Ok(qdisc_tree(n)
                .into_iter()
                .map(|q| mk_qdisc(q.kind, q.handle, q.parent))
                .collect())
        })
    }

    /// Replaces the qdisc on transmit queue `queue` with ETF, or the root
    /// with `None`. A single queue needs an `mq` root; the default one,
    /// which has no handle, is replaced by `mq` with handle `7ff0:` first,
    /// which resets every queue's qdisc once. Launch-time offload without
    /// [`NicCaps::etf_offload`](crate::NicCaps) is `EOPNOTSUPP`.
    pub fn set_etf(&self, queue: Option<u16>, etf: &Etf) -> io::Result<()> {
        let etf = *etf;
        self.set(
            Item::LinuxNicTuning,
            Need::NetAdmin,
            format!("set_etf({queue:?}, {etf:?})"),
            |n, os| {
                if i32::try_from(etf.delta.as_nanos()).is_err() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "ETF delta too large",
                    ));
                }
                if etf.offload && !n.spec.caps.etf_offload {
                    return Err(not_supported(os));
                }
                let Some(q) = queue else {
                    n.ft.etf.clear();
                    n.ft.queue_qdisc.clear();
                    n.ft.root_mq_named = false;
                    n.ft.etf.insert(None, etf);
                    return done(());
                };
                let multi_queue = !n.is_loopback() && tx_queues(n) > 1;
                if n.ft.etf.contains_key(&None) || !(n.ft.root_mq_named || multi_queue) {
                    return Err(no_class(n));
                }
                if !n.ft.root_mq_named {
                    n.ft.root_mq_named = true;
                    n.ft.queue_qdisc.clear();
                }
                if q >= tx_queues(n) {
                    return Err(no_queue(os));
                }
                n.ft.etf.insert(Some(q), etf);
                done(())
            },
        )
    }

    /// Undoes [`Nic::set_etf`]: the root goes back to the kernel's default,
    /// and a single queue gets the system default qdisc
    /// (`net.core.default_qdisc`, `pfifo_fast` unless
    /// [`SysFacts::sysctls`](crate::fast_talker::sim::SysFacts) says
    /// otherwise).
    pub fn restore_qdisc(&self, queue: Option<u16>) -> io::Result<()> {
        let default = crate::state::ft_slot()
            .inner
            .lock()
            .sys_facts
            .sysctls
            .get("net.core.default_qdisc")
            .cloned()
            .unwrap_or_else(|| DEFAULT_KIND.to_string());
        self.set(
            Item::LinuxNicTuning,
            Need::NetAdmin,
            format!("restore_qdisc({queue:?})"),
            |n, os| {
                let Some(q) = queue else {
                    n.ft.etf.clear();
                    n.ft.queue_qdisc.clear();
                    n.ft.root_mq_named = false;
                    return done(());
                };
                if n.ft.etf.contains_key(&None) || !n.ft.root_mq_named {
                    return Err(no_class(n));
                }
                if q >= tx_queues(n) {
                    return Err(no_queue(os));
                }
                n.ft.etf.remove(&Some(q));
                n.ft.queue_qdisc.insert(q, default);
                done(())
            },
        )
    }
}
