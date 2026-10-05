//! The traffic-control qdiscs of a [`SimHost`](crate::SimHost)'s interfaces as rtnetlink shows
//! and changes them: `RTM_GETQDISC` dumps, and `RTM_NEWQDISC`/`RTM_DELQDISC` replacing a root
//! qdisc or the qdisc of one transmit queue under `mq`, with `etf`'s parameters and its
//! launch-time offload checked as the kernel checks them.
//!
//! The rules are net/sched/sch_api.c `tc_modify_qdisc`/`tc_get_qdisc` (Linux 6.12) for where a
//! qdisc goes, net/sched/sch_mq.c `mq_init_common`/`mq_attach` (Linux 7.0) for `mq`, and
//! net/sched/sch_etf.c `etf_init` for
//! `etf`; message layouts are include/uapi/linux/rtnetlink.h (`struct tcmsg`, `TCA_*`) and
//! include/uapi/linux/pkt_sched.h (`struct tc_etf_qopt`, `TC_ETF_*`). Changing a qdisc needs
//! `CAP_NET_ADMIN`, which net/core/rtnetlink.c `rtnetlink_rcv_msg` demands of every request but a
//! `GET` (`EPERM`).
//!
//! The tables live in the host's state and change under its lock.

use std::collections::BTreeMap;
use std::ffi::c_int;

/// `TC_H_ROOT` (include/uapi/linux/pkt_sched.h): the parent of a root qdisc.
pub(crate) const TC_H_ROOT: u32 = 0xFFFF_FFFF;
/// `TC_H_INGRESS`: the ingress hook's parent.
const TC_H_INGRESS: u32 = 0xFFFF_FFF1;
/// `TC_H_MAJ_MASK`: the major half of a handle.
const TC_H_MAJ_MASK: u32 = 0xFFFF_0000;
/// `TC_H_MIN_MASK`: the minor half.
const TC_H_MIN_MASK: u32 = 0x0000_FFFF;
/// `NLM_F_REPLACE` (include/uapi/linux/netlink.h).
const NLM_F_REPLACE: u16 = 0x100;
/// `NLM_F_EXCL`.
const NLM_F_EXCL: u16 = 0x200;
/// `NLM_F_CREATE`.
const NLM_F_CREATE: u16 = 0x400;
/// `TCA_KIND`: the qdisc's name.
const TCA_KIND: u16 = 1;
/// `TCA_OPTIONS`: its nested parameters.
const TCA_OPTIONS: u16 = 2;
/// `TCA_ETF_PARMS`: the `struct tc_etf_qopt` inside `etf`'s `TCA_OPTIONS`.
const TCA_ETF_PARMS: u16 = 1;
/// `TC_ETF_OFFLOAD_ON`: hand each frame to the NIC to launch at its time.
const TC_ETF_OFFLOAD_ON: u32 = 1 << 1;
/// `ENOTSUPP` (include/linux/errno.h): kernel-internal, but `etf_init` returns it for a dynamic
/// clock id and rtnetlink passes it to userspace as is.
const ENOTSUPP: c_int = 524;

/// The qdisc kinds the sim knows (each a `struct Qdisc_ops` `.id` in net/sched/); any other name
/// is `ENOENT`, as `qdisc_create` reports a kind with no module.
const KINDS: [&str; 15] = [
    "pfifo_fast",
    "pfifo",
    "bfifo",
    "noqueue",
    "fq",
    "fq_codel",
    "codel",
    "sfq",
    "prio",
    "tbf",
    "htb",
    "mq",
    "mqprio",
    "taprio",
    "etf",
];

/// One qdisc: its kind, handle and, for `etf`, its `tc_etf_qopt` `(delta, clockid, flags)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Qdisc {
    pub(crate) kind: String,
    pub(crate) handle: u32,
    pub(crate) etf: Option<(i32, i32, u32)>,
}

/// An interface's qdiscs: the root and, under a classful root (`mq`), one per transmit queue by
/// class minor (queue + 1).
#[derive(Debug, Clone)]
pub(crate) struct NicQdiscs {
    pub(crate) root: Qdisc,
    pub(crate) children: BTreeMap<u32, Qdisc>,
}

/// What a request runs against: the interface's transmit queues, allocated (`num_tx_queues`) and
/// in use (`real_num_tx_queues`), whether it is `IFF_NO_QUEUE`, the host's default qdisc and the
/// transmit queues whose driver can launch frames at their time.
pub(crate) struct Device<'a> {
    pub(crate) num_tx_queues: usize,
    pub(crate) real_tx_queues: usize,
    pub(crate) no_queue: bool,
    pub(crate) default_qdisc: &'a str,
    pub(crate) etf_offload: Option<&'a [u16]>,
}

impl NicQdiscs {
    /// The qdiscs the kernel attaches to a device coming up (net/sched/sch_generic.c
    /// `attach_default_qdiscs`, Linux 7.0): `noqueue` on an `IFF_NO_QUEUE` device; else `mq`
    /// (handle 0) over the default qdiscs of [`defaults`](Self::defaults) on a multi-queue
    /// device, which `netif_is_multiqueue` decides by the queues allocated (`num_tx_queues >
    /// 1`), not those in use; else the default qdisc itself. `etf` is the
    /// [`HostProfile::etf_qdisc`](crate::HostProfile::etf_qdisc) root.
    pub(crate) fn initial(dev: &Device<'_>, etf: Option<(i32, i32, u32)>) -> Self {
        let leaf = |kind: &str| Qdisc {
            kind: kind.to_string(),
            handle: 0,
            etf: etf.filter(|_| kind == "etf"),
        };
        if dev.no_queue {
            return NicQdiscs {
                root: leaf("noqueue"),
                children: BTreeMap::new(),
            };
        }
        if dev.num_tx_queues > 1 && dev.default_qdisc != "etf" {
            NicQdiscs {
                root: leaf("mq"),
                children: Self::defaults(dev),
            }
        } else {
            NicQdiscs {
                root: leaf(dev.default_qdisc),
                children: BTreeMap::new(),
            }
        }
    }

    /// One default qdisc per allocated transmit queue, as net/sched/sch_mq.c `mq_init_common`
    /// creates them: the host's default qdisc on the queues in use and `pfifo_fast` on the rest
    /// (include/net/sch_generic.h `get_default_qdisc_ops`).
    fn defaults(dev: &Device<'_>) -> BTreeMap<u32, Qdisc> {
        (1..=dev.num_tx_queues as u32)
            .map(|minor| (minor, Self::default_for(dev, minor)))
            .collect()
    }

    /// The default qdisc `mq` puts on the queue of class `minor` (queue `minor - 1`).
    fn default_for(dev: &Device<'_>, minor: u32) -> Qdisc {
        let kind = if (minor as usize) <= dev.real_tx_queues {
            dev.default_qdisc
        } else {
            "pfifo_fast"
        };
        Qdisc {
            kind: kind.to_string(),
            handle: 0,
            etf: None,
        }
    }

    /// Whether the root has classes to graft onto.
    fn classful(&self) -> bool {
        matches!(self.root.kind.as_str(), "mq" | "mqprio" | "taprio")
    }

    /// Builds the qdisc a request asks for at transmit queue `queue`, checking its parameters:
    /// `mq` only at the root of a device allocated more than one transmit queue
    /// (`mq_init_common`: `EOPNOTSUPP` unless `sch->parent` is `TC_H_ROOT` and
    /// `netif_is_multiqueue`, `num_tx_queues > 1`, however few are in use); `etf` needs its
    /// `TCA_ETF_PARMS` (`EINVAL`), a clock id that is not dynamic (`ENOTSUPP`) and is
    /// `CLOCK_TAI` (`EINVAL`), a non-negative delta (`EINVAL`), and for offload a driver with
    /// `ndo_setup_tc` (`EOPNOTSUPP`) that can launch on that queue (igb_offload_txtime,
    /// drivers/net/ethernet/intel/igb/igb_main.c: `EINVAL` past queue 1 of an i210, `EOPNOTSUPP`
    /// on other parts).
    fn create(
        dev: &Device<'_>,
        kind: &str,
        handle: u32,
        options: Option<&[u8]>,
        queue: Option<u32>,
    ) -> Result<Qdisc, c_int> {
        if !KINDS.contains(&kind) {
            return Err(libc::ENOENT);
        }
        let mut etf = None;
        if kind == "mq" && (queue.is_some() || dev.num_tx_queues < 2) {
            return Err(libc::EOPNOTSUPP);
        }
        if kind == "etf" {
            let parms = options
                .and_then(|o| find_attr(o, TCA_ETF_PARMS))
                .filter(|p| p.len() >= 12)
                .ok_or(libc::EINVAL)?;
            let word = |at: usize| i32::from_ne_bytes(parms[at..at + 4].try_into().unwrap());
            let (delta, clockid, flags) = (word(0), word(4), word(8) as u32);
            if clockid < 0 {
                return Err(ENOTSUPP);
            }
            if clockid != libc::CLOCK_TAI || delta < 0 {
                return Err(libc::EINVAL);
            }
            if flags & TC_ETF_OFFLOAD_ON != 0 {
                let queues = dev.etf_offload.ok_or(libc::EOPNOTSUPP)?;
                if !queues.contains(&(queue.unwrap_or(0) as u16)) {
                    return Err(libc::EINVAL);
                }
            }
            etf = Some((delta, clockid, flags));
        }
        Ok(Qdisc {
            kind: kind.to_string(),
            handle,
            etf,
        })
    }

    /// `RTM_NEWQDISC` with `tcmsg` handle `handle` under parent `parent`, kind and options from
    /// the attributes, deciding between creating a qdisc and changing the one there as
    /// `tc_modify_qdisc` does. A qdisc created with handle 0 gets the next automatic handle
    /// from `auto` (`qdisc_alloc_handle`: `8001:`, `8002:`, … host-wide). Changing a qdisc in
    /// place succeeds for any kind without options and is `EINVAL` with options for `mq` and
    /// `etf`, which have no `change` operation (`qdisc_change`). Ingress is `EOPNOTSUPP`, a
    /// snare simplification.
    pub(crate) fn modify(
        &mut self,
        dev: &Device<'_>,
        auto: &mut u32,
        flags: u16,
        handle: u32,
        parent: u32,
        attrs: &[u8],
    ) -> Result<(), c_int> {
        let kind = find_attr(attrs, TCA_KIND).map(|k| {
            let end = k.iter().position(|&b| b == 0).unwrap_or(k.len());
            String::from_utf8_lossy(&k[..end]).into_owned()
        });
        let options = find_attr(attrs, TCA_OPTIONS);
        if parent == TC_H_INGRESS {
            return Err(libc::EOPNOTSUPP);
        }
        if parent == 0 {
            return Err(if handle == 0 {
                libc::EINVAL
            } else {
                libc::ENOENT
            });
        }
        let queue = if parent == TC_H_ROOT {
            None
        } else {
            if self.root.handle == 0 || self.root.handle & TC_H_MAJ_MASK != parent & TC_H_MAJ_MASK {
                return Err(libc::ENOENT);
            }
            if !self.classful() {
                return Err(libc::EOPNOTSUPP);
            }
            let minor = parent & TC_H_MIN_MASK;
            if minor == 0 || minor as usize > dev.num_tx_queues {
                return Err(libc::ENOENT);
            }
            Some(minor - 1)
        };
        let existing = match queue {
            None => &self.root,
            Some(q) => &self.children[&(q + 1)],
        };
        let present = existing.handle != 0;
        let differs = kind.as_deref().is_some_and(|k| k != existing.kind);
        let both = |a: u16, b: u16| flags & (a | b) == a | b;
        let create = if !present || handle == 0 || existing.handle != handle {
            if handle != 0 {
                if present && flags & NLM_F_REPLACE == 0 {
                    return Err(libc::EEXIST);
                }
                if handle & TC_H_MIN_MASK != 0 {
                    return Err(libc::EINVAL);
                }
                Some(true)
            } else if !present
                || differs && (both(NLM_F_CREATE, NLM_F_REPLACE) || both(NLM_F_CREATE, NLM_F_EXCL))
            {
                Some(true)
            } else if differs && flags & (NLM_F_CREATE | NLM_F_REPLACE | NLM_F_EXCL) == 0 {
                Some(false)
            } else {
                None
            }
        } else {
            None
        };
        match create {
            None => {
                if flags & NLM_F_EXCL != 0 {
                    return Err(libc::EEXIST);
                }
                if differs {
                    return Err(libc::EINVAL);
                }
                if options.is_some() && matches!(existing.kind.as_str(), "mq" | "etf") {
                    return Err(libc::EINVAL);
                }
                Ok(())
            }
            Some(needs_create_flag) => {
                if needs_create_flag && flags & NLM_F_CREATE == 0 {
                    return Err(libc::ENOENT);
                }
                let kind = kind.ok_or(libc::EINVAL)?;
                let next_auto = auto.wrapping_add(0x1_0000);
                let new = Self::create(
                    dev,
                    &kind,
                    if handle != 0 { handle } else { next_auto },
                    options,
                    queue,
                )?;
                if handle == 0 {
                    *auto = next_auto;
                }
                match queue {
                    None => {
                        self.children = if new.kind == "mq" {
                            Self::defaults(dev)
                        } else {
                            BTreeMap::new()
                        };
                        self.root = new;
                    }
                    Some(q) => {
                        self.children.insert(q + 1, new);
                    }
                }
                Ok(())
            }
        }
    }

    /// `RTM_DELQDISC` (`tc_get_qdisc`): a parent is required (`EINVAL`); the qdisc there must
    /// match a given handle (`EINVAL`) and not be a default one with handle 0 (`ENOENT`).
    /// Deleting the root restores the device's defaults, deleting an `mq` class's qdisc that
    /// queue's default qdisc.
    pub(crate) fn delete(
        &mut self,
        dev: &Device<'_>,
        handle: u32,
        parent: u32,
    ) -> Result<(), c_int> {
        if parent == 0 {
            return Err(libc::EINVAL);
        }
        let queue = if parent == TC_H_ROOT {
            None
        } else {
            if self.root.handle == 0
                || self.root.handle & TC_H_MAJ_MASK != parent & TC_H_MAJ_MASK
                || !self.classful()
            {
                return Err(libc::ENOENT);
            }
            let minor = parent & TC_H_MIN_MASK;
            if minor == 0 || minor as usize > dev.num_tx_queues {
                return Err(libc::ENOENT);
            }
            Some(minor)
        };
        let q = match queue {
            None => &self.root,
            Some(m) => &self.children[&m],
        };
        if handle != 0 && q.handle != handle {
            return Err(libc::EINVAL);
        }
        if q.handle == 0 {
            return Err(libc::ENOENT);
        }
        match queue {
            None => *self = Self::initial(dev, None),
            Some(m) => {
                self.children.insert(m, Self::default_for(dev, m));
            }
        }
        Ok(())
    }

    /// Every qdisc a dump shows as `(handle, parent, qdisc)`, root first, then the children
    /// in class order (`tc_dump_qdisc_root` walks the device's qdisc hash, whose order the sim
    /// does not reproduce). A child is in that hash when it was created by a request (net/sched/
    /// sch_api.c `qdisc_create` hashes every qdisc with a handle) or is the default qdisc of a
    /// queue in use (`mq_attach` hashes only those below `real_num_tx_queues`, and
    /// net/sched/sch_generic.c `mq_change_real_num_tx` follows a channel change), so `mq`'s
    /// defaults on the allocated queues beyond `real_tx_queues` are not listed.
    pub(crate) fn listing(&self, real_tx_queues: usize) -> Vec<(u32, u32, &Qdisc)> {
        let mut out = vec![(self.root.handle, TC_H_ROOT, &self.root)];
        let major = self.root.handle & TC_H_MAJ_MASK;
        for (&minor, q) in &self.children {
            if q.handle != 0 || minor as usize <= real_tx_queues {
                out.push((q.handle, major | minor, q));
            }
        }
        out
    }
}

/// Finds attribute `want` in a run of `struct nlattr` (include/uapi/linux/netlink.h), ignoring
/// the `NLA_F_NESTED`/`NLA_F_NET_BYTEORDER` flag bits.
fn find_attr(attrs: &[u8], want: u16) -> Option<&[u8]> {
    let mut pos = 0;
    while pos + 4 <= attrs.len() {
        let len = u16::from_ne_bytes([attrs[pos], attrs[pos + 1]]) as usize;
        let ty = u16::from_ne_bytes([attrs[pos + 2], attrs[pos + 3]]) & 0x3FFF;
        if len < 4 || pos + len > attrs.len() {
            return None;
        }
        if ty == want {
            return Some(&attrs[pos + 4..pos + len]);
        }
        pos += len.next_multiple_of(4);
    }
    None
}
