//! fast-talker's `Plan::apply` and `Plan::check` against snare's NICs,
//! interrupts and threads, in fast-talker's order and with its error
//! contexts and drift names. Which settings exist, and the errors for the
//! rest, follow [`os_semantics`](crate::os_semantics) as fast-talker's
//! per-OS code does.

use std::fmt;
use std::io;
use std::time::Duration;

use ::fast_talker::__sim::ctor;
use ::fast_talker::nic::{Coalesce, FlowRule, Pause};
use ::fast_talker::plan::{Drift, InterfacePlan, Plan, ReceivePlan};
use ::fast_talker::rt::Scheduler;

use super::irq;
use super::nic::{Nic, Rss};
use super::sim::{FtEvent, PlanRecord};
use crate::os::OsSemantics;
use crate::time::Instant;

const DEFAULT_PRIORITY: u8 = 90;

/// `Plan::apply`, recorded for [`sim::plans_applied`](super::sim::plans_applied).
pub(crate) fn apply(plan: &Plan) -> io::Result<()> {
    let at = Instant::now();
    let result = apply_plan(plan, crate::os_semantics());
    let error = result.as_ref().err().map(ToString::to_string);
    record(plan, at, false, error.clone(), Vec::new());
    super::sim::log(FtEvent::PlanApplied {
        interfaces: plan.interfaces.iter().map(|p| p.name.clone()).collect(),
        error,
    });
    result
}

/// `Plan::check`, recorded for [`sim::plans_applied`](super::sim::plans_applied).
pub(crate) fn check(plan: &Plan) -> Vec<Drift> {
    let at = Instant::now();
    let drift = check_plan(plan, crate::os_semantics());
    record(plan, at, true, None, drift.clone());
    super::sim::log(FtEvent::PlanChecked { drift: drift.len() });
    drift
}

fn record(plan: &Plan, at: Instant, check: bool, error: Option<String>, drift: Vec<Drift>) {
    let tid = crate::threads::current_tid();
    crate::state::ft_slot().inner.lock().plans.push(PlanRecord {
        at,
        tid,
        plan: plan.clone(),
        check,
        error,
        drift,
    });
}

fn apply_plan(plan: &Plan, os: OsSemantics) -> io::Result<()> {
    let nics = plan
        .interfaces
        .iter()
        .map(|p| {
            Nic::open(&p.name)
                .map(|n| (p, n))
                .map_err(context(Some(&p.name), "open"))
        })
        .collect::<io::Result<Vec<_>>>()?;
    for (p, nic) in &nics {
        apply_link(p, nic, os)?;
    }
    if let Some(cpus) = &plan.housekeeping_irqs {
        housekeeping(cpus, os).map_err(context(None, "housekeeping_irqs"))?;
    }
    for (p, nic) in &nics {
        apply_placement(p, nic, os)?;
    }
    Ok(())
}

fn check_plan(plan: &Plan, os: OsSemantics) -> Vec<Drift> {
    let mut out = Vec::new();
    if let Some(cpus) = &plan.housekeeping_irqs {
        let mut c = Checker {
            interface: None,
            out: &mut out,
        };
        c.compare("housekeeping_irqs", sorted(cpus), housekeeping_live(os));
    }
    for p in &plan.interfaces {
        let mut c = Checker {
            interface: Some(p.name.clone()),
            out: &mut out,
        };
        match Nic::open(&p.name) {
            Ok(nic) => check_interface(p, &nic, os, &mut c),
            Err(e) => c.push("interface", "present".into(), e.to_string()),
        }
    }
    out
}

/// Reads before writing, as fast-talker does: many drivers reset the NIC on
/// any rings, pause or channels request, even a no-op one.
fn apply_link(p: &InterfacePlan, nic: &Nic, os: OsSemantics) -> io::Result<()> {
    let ctx = |what| context(Some(&p.name), what);
    if let Some(on) = p.eee
        && eee(nic, os).map_err(ctx("eee"))? != on
    {
        set_eee(nic, on, os).map_err(ctx("eee"))?;
    }
    if p.rx_ring.is_some() || p.tx_ring.is_some() {
        let live = nic.rings().map_err(ctx("rings"))?;
        let mut r = live;
        r.rx = p.rx_ring.unwrap_or(r.rx);
        r.tx = p.tx_ring.unwrap_or(r.tx);
        if r != live {
            nic.set_rings(&r).map_err(ctx("rings"))?;
        }
    }
    if let Some(want) = &p.coalesce {
        let live = nic.coalesce().map_err(ctx("coalesce"))?;
        let mut c = live;
        c.adaptive_rx = want.adaptive_rx.unwrap_or(c.adaptive_rx);
        c.rx_usecs = want.rx_usecs.unwrap_or(c.rx_usecs);
        c.rx_frames = want.rx_frames.unwrap_or(c.rx_frames);
        c.adaptive_tx = want.adaptive_tx.unwrap_or(c.adaptive_tx);
        c.tx_usecs = want.tx_usecs.unwrap_or(c.tx_usecs);
        c.tx_frames = want.tx_frames.unwrap_or(c.tx_frames);
        if c != live {
            nic.set_coalesce(&c).map_err(ctx("coalesce"))?;
        }
    }
    if let Some(on) = p.flow_control {
        let want = Pause {
            autoneg: false,
            rx: on,
            tx: on,
        };
        let live = nic.pause().map_err(ctx("flow_control"))?;
        if (live.rx, live.tx) != (on, on) || (live.autoneg && os != OsSemantics::Windows) {
            nic.set_pause(&want).map_err(ctx("flow_control"))?;
        }
    }
    if let Some(n) = p.channels {
        let live = nic.channels().map_err(ctx("channels"))?;
        if live.combined != n {
            let mut c = live;
            c.combined = n;
            nic.set_channels(&c).map_err(ctx("channels"))?;
        }
    }
    Ok(())
}

fn apply_placement(p: &InterfacePlan, nic: &Nic, os: OsSemantics) -> io::Result<()> {
    let ctx = |what| context(Some(&p.name), what);
    if let Some(r) = &p.receive {
        place_receive(nic, r, os).map_err(ctx("receive"))?;
    }
    if let Some(cpus) = &p.rps_cpus {
        set_rps(nic, cpus, os).map_err(ctx("rps_cpus"))?;
    }
    if let Some(cpus) = &p.xps_cpus {
        set_xps(nic, cpus, os).map_err(ctx("xps_cpus"))?;
    }
    if let Some(n) = p.bql_limit_max {
        set_bql(nic, n, os).map_err(ctx("bql_limit_max"))?;
    }
    if let Some(n) = p.napi_defer_hard_irqs {
        linux_only(os, "napi_defer_hard_irqs")
            .and_then(|()| nic.set_napi_defer_hard_irqs(n))
            .map_err(ctx("napi_defer_hard_irqs"))?;
    }
    if let Some(us) = p.gro_flush_timeout_us {
        linux_only(os, "gro_flush_timeout")
            .and_then(|()| nic.set_gro_flush_timeout(Duration::from_micros(us)))
            .map_err(ctx("gro_flush_timeout_us"))?;
    }
    if let Some(on) = p.rx_timestamping {
        timestamping_control(os)
            .and_then(|()| nic.set_rx_timestamping(on))
            .map_err(ctx("rx_timestamping"))?;
    }
    if let Some(rules) = &p.flow_rules {
        set_flows(nic, rules, os).map_err(ctx("flow_rules"))?;
    }
    Ok(())
}

fn check_interface(p: &InterfacePlan, nic: &Nic, os: OsSemantics, c: &mut Checker) {
    if let Some(on) = p.eee {
        c.compare("eee", on, eee(nic, os));
    }
    if p.rx_ring.is_some() || p.tx_ring.is_some() {
        let rings = nic.rings();
        if let Some(v) = p.rx_ring {
            c.compare("rx_ring", v, rings.as_ref().map(|r| r.rx).map_err(clone));
        }
        if let Some(v) = p.tx_ring {
            c.compare("tx_ring", v, rings.as_ref().map(|r| r.tx).map_err(clone));
        }
    }
    if let Some(want) = &p.coalesce {
        let live = nic.coalesce();
        let get = |f: fn(&Coalesce) -> u32| live.as_ref().map(f).map_err(clone);
        let flag = |f: fn(&Coalesce) -> bool| live.as_ref().map(f).map_err(clone);
        if let Some(v) = want.adaptive_rx {
            c.compare("coalesce.adaptive_rx", v, flag(|c| c.adaptive_rx));
        }
        if let Some(v) = want.rx_usecs {
            c.compare("coalesce.rx_usecs", v, get(|c| c.rx_usecs));
        }
        if let Some(v) = want.rx_frames {
            c.compare("coalesce.rx_frames", v, get(|c| c.rx_frames));
        }
        if let Some(v) = want.adaptive_tx {
            c.compare("coalesce.adaptive_tx", v, flag(|c| c.adaptive_tx));
        }
        if let Some(v) = want.tx_usecs {
            c.compare("coalesce.tx_usecs", v, get(|c| c.tx_usecs));
        }
        if let Some(v) = want.tx_frames {
            c.compare("coalesce.tx_frames", v, get(|c| c.tx_frames));
        }
    }
    if let Some(on) = p.flow_control {
        let live = nic.pause().map(|p| (p.rx, p.tx));
        c.compare("flow_control", (on, on), live);
    }
    if let Some(n) = p.channels {
        c.compare("channels", n, nic.channels().map(|c| c.combined));
    }
    if let Some(r) = &p.receive {
        check_receive(nic, r, os, c);
    }
    if let Some(cpus) = &p.rps_cpus {
        check_rps(nic, cpus, os, c);
    }
    if let Some(cpus) = &p.xps_cpus {
        check_xps(nic, cpus, os, c);
    }
    if let Some(n) = p.bql_limit_max {
        check_bql(nic, n, os, c);
    }
    if let Some(n) = p.napi_defer_hard_irqs {
        let live = linux_only(os, "napi_defer_hard_irqs").and_then(|()| nic.napi_defer_hard_irqs());
        c.compare("napi_defer_hard_irqs", n, live);
    }
    if let Some(us) = p.gro_flush_timeout_us {
        let live = linux_only(os, "gro_flush_timeout")
            .and_then(|()| nic.gro_flush_timeout())
            .map(|d| d.as_micros() as u64);
        c.compare("gro_flush_timeout_us", us, live);
    }
    if let Some(on) = p.rx_timestamping {
        let live = timestamping_control(os).and_then(|()| nic.rx_timestamping());
        c.compare("rx_timestamping", on, live);
    }
    if let Some(rules) = &p.flow_rules {
        check_flows(nic, rules, os, c);
    }
}

struct Checker<'a> {
    interface: Option<String>,
    out: &'a mut Vec<Drift>,
}

impl Checker<'_> {
    fn compare<T: PartialEq + fmt::Debug>(
        &mut self,
        setting: &str,
        expected: T,
        actual: io::Result<T>,
    ) {
        match actual {
            Ok(a) if a == expected => {}
            Ok(a) => self.push(setting, format!("{expected:?}"), format!("{a:?}")),
            Err(e) => self.push(setting, format!("{expected:?}"), format!("error: {e}")),
        }
    }

    fn push(&mut self, setting: &str, expected: String, actual: String) {
        self.out.push(ctor::drift(
            self.interface.clone(),
            setting.to_owned(),
            expected,
            actual,
        ));
    }
}

fn context(interface: Option<&str>, what: &str) -> impl FnOnce(io::Error) -> io::Error {
    let prefix = match interface {
        Some(i) => format!("{i}: {what}"),
        None => what.to_owned(),
    };
    move |e| io::Error::new(e.kind(), format!("{prefix}: {e}"))
}

fn clone(e: &io::Error) -> io::Error {
    io::Error::new(e.kind(), e.to_string())
}

fn sorted(cpus: &[usize]) -> Vec<usize> {
    let mut v = cpus.to_vec();
    v.sort_unstable();
    v.dedup();
    v
}

fn unsupported<T>(what: &str) -> io::Result<T> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        format!("{what} is not available on this platform"),
    ))
}

fn linux_only(os: OsSemantics, what: &str) -> io::Result<()> {
    match os {
        OsSemantics::Linux => Ok(()),
        _ => unsupported(what),
    }
}

fn timestamping_control(os: OsSemantics) -> io::Result<()> {
    match os {
        OsSemantics::MacOs => unsupported("NIC timestamping control"),
        _ => Ok(()),
    }
}

fn housekeeping(cpus: &[usize], os: OsSemantics) -> io::Result<()> {
    linux_only(os, "moving every interrupt")?;
    irq::set_all_affinity(cpus).map(|_| ())
}

fn housekeeping_live(os: OsSemantics) -> io::Result<Vec<usize>> {
    linux_only(os, "moving every interrupt")?;
    irq::default_affinity().map(|a| sorted(&a))
}

fn eee(nic: &Nic, os: OsSemantics) -> io::Result<bool> {
    match os {
        OsSemantics::MacOs => unsupported("EEE"),
        _ => nic.eee().map(|e| e.enabled),
    }
}

fn set_eee(nic: &Nic, on: bool, os: OsSemantics) -> io::Result<()> {
    match os {
        OsSemantics::MacOs => unsupported("EEE"),
        _ => nic.set_eee(on),
    }
}

fn rss(r: &ReceivePlan) -> Rss {
    Rss {
        enabled: true,
        base_cpu: r.cpus.iter().min().map(|&c| c as u32),
        max_processors: Some(r.cpus.len() as u32),
        ..Rss::default()
    }
}

fn place_receive(nic: &Nic, r: &ReceivePlan, os: OsSemantics) -> io::Result<()> {
    match os {
        OsSemantics::Linux => {
            nic.set_threaded_napi(true)?;
            let napis = nic.napis()?;
            if napis.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "the interface has no NAPI instances to place; drivers create them when it is brought up",
                ));
            }
            let sched = Scheduler::Fifo(r.priority.unwrap_or(DEFAULT_PRIORITY));
            for napi in napis {
                napi.pin(&r.cpus, sched)?;
            }
            Ok(())
        }
        OsSemantics::Windows => {
            if r.priority.is_some() {
                return unsupported("receive priority");
            }
            nic.set_rss(&rss(r))?;
            nic.set_irq_affinity(&r.cpus)
        }
        _ => unsupported("receive placement"),
    }
}

fn check_receive(nic: &Nic, r: &ReceivePlan, os: OsSemantics, c: &mut Checker) {
    match os {
        OsSemantics::Linux => {
            let cpus = sorted(&r.cpus);
            let sched = Scheduler::Fifo(r.priority.unwrap_or(DEFAULT_PRIORITY));
            c.compare("receive.threaded_napi", true, nic.threaded_napi());
            let napis = match nic.napis() {
                Ok(n) => n,
                Err(e) => {
                    c.push("receive", format!("{cpus:?}"), format!("error: {e}"));
                    return;
                }
            };
            for napi in napis {
                let id = napi.id;
                if let Some(t) = napi.thread {
                    c.compare(
                        &format!("receive.napi[{id}].cpus"),
                        cpus.clone(),
                        t.affinity(),
                    );
                    c.compare(
                        &format!("receive.napi[{id}].priority"),
                        sched,
                        t.scheduler(),
                    );
                }
                if let Some(i) = napi.irq {
                    c.compare(
                        &format!("receive.napi[{id}].irq[{}].cpus", i.number()),
                        cpus.clone(),
                        i.affinity().map(|a| sorted(&a)),
                    );
                }
            }
        }
        OsSemantics::Windows => {
            let want = rss(r);
            let live = nic.rss().map(|l| (l.enabled, l.base_cpu, l.max_processors));
            c.compare(
                "receive.rss",
                (want.enabled, want.base_cpu, want.max_processors),
                live,
            );
            c.compare(
                "receive.irq_affinity",
                Some(sorted(&r.cpus)),
                nic.irq_affinity(),
            );
        }
        _ => c.compare("receive", r.cpus.clone(), unsupported("receive placement")),
    }
}

fn set_rps(nic: &Nic, cpus: &[usize], os: OsSemantics) -> io::Result<()> {
    linux_only(os, "RPS")?;
    for q in 0..nic.rx_queues()? {
        nic.set_rps_cpus(q, cpus)?;
    }
    Ok(())
}

fn check_rps(nic: &Nic, cpus: &[usize], os: OsSemantics, c: &mut Checker) {
    if os != OsSemantics::Linux {
        c.compare("rps_cpus", cpus.to_vec(), unsupported("RPS"));
        return;
    }
    for q in 0..nic.rx_queues().unwrap_or(0) {
        c.compare(&format!("rps_cpus[{q}]"), sorted(cpus), nic.rps_cpus(q));
    }
}

fn set_xps(nic: &Nic, cpus: &[usize], os: OsSemantics) -> io::Result<()> {
    linux_only(os, "XPS")?;
    let n = nic.tx_queues()?;
    if n > 1 {
        for q in 0..n {
            nic.set_xps_cpus(q, cpus)?;
        }
    }
    Ok(())
}

fn check_xps(nic: &Nic, cpus: &[usize], os: OsSemantics, c: &mut Checker) {
    if os != OsSemantics::Linux {
        c.compare("xps_cpus", cpus.to_vec(), unsupported("XPS"));
        return;
    }
    let n = nic.tx_queues().unwrap_or(0);
    if n > 1 {
        for q in 0..n {
            c.compare(&format!("xps_cpus[{q}]"), sorted(cpus), nic.xps_cpus(q));
        }
    }
}

fn set_bql(nic: &Nic, bytes: u64, os: OsSemantics) -> io::Result<()> {
    linux_only(os, "byte queue limits")?;
    for q in 0..nic.tx_queues()? {
        nic.set_bql_limit_max(q, bytes)?;
    }
    Ok(())
}

fn check_bql(nic: &Nic, bytes: u64, os: OsSemantics, c: &mut Checker) {
    if os != OsSemantics::Linux {
        c.compare("bql_limit_max", bytes, unsupported("byte queue limits"));
        return;
    }
    for q in 0..nic.tx_queues().unwrap_or(0) {
        c.compare(&format!("bql_limit_max[{q}]"), bytes, nic.bql_limit_max(q));
    }
}

fn set_flows(nic: &Nic, rules: &[FlowRule], os: OsSemantics) -> io::Result<()> {
    linux_only(os, "flow steering rules")?;
    if rules.is_empty() {
        return Ok(());
    }
    if !nic.ntuple()? {
        nic.set_ntuple(true)?;
    }
    let installed = nic.flow_rules()?;
    for rule in rules {
        if !installed.iter().any(|i| rule.same_as(i)) {
            nic.add_flow_rule(rule)?;
        }
    }
    Ok(())
}

fn check_flows(nic: &Nic, rules: &[FlowRule], os: OsSemantics, c: &mut Checker) {
    if os != OsSemantics::Linux {
        c.compare(
            "flow_rules",
            rules.to_vec(),
            unsupported("flow steering rules"),
        );
        return;
    }
    if rules.is_empty() {
        return;
    }
    c.compare("flow_rules.ntuple", true, nic.ntuple());
    match nic.flow_rules() {
        Ok(installed) => {
            for (i, rule) in rules.iter().enumerate() {
                if !installed.iter().any(|x| rule.same_as(x)) {
                    c.push(
                        &format!("flow_rules[{i}]"),
                        format!("{rule:?}"),
                        "not installed".into(),
                    );
                }
            }
        }
        Err(e) => c.push("flow_rules", format!("{rules:?}"), format!("error: {e}")),
    }
}
