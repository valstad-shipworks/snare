//! `sys_check` under the shim: every check answered from the simulated
//! host ([`SysFacts`], [`CpuTopology`], privileges, socket limits and the
//! NICs' PTP clocks) as fast-talker's own check would read it on the
//! emulated OS, with the same expected and actual texts.

use std::collections::BTreeMap;
use std::time::Duration;

use ::fast_talker::__sim::ctor;
use ::fast_talker::sys_check::{Check, Finding, Status};

use super::sim::{CpuTopology, FtEntry, FtEvent, SysCheckRecord, SysFacts, WIN_FAST_PLANS};
use super::slot::PtpState;
use crate::netif::{Privileges, SysLimits};
use crate::os::{OsSemantics, SysErrno, sys_err_for};
use crate::time::Instant;

const IRQBALANCE_PID: u32 = 812;
const ENOENT: i32 = 2;

/// What an interface named by a `PhcSynced` check has: `None` for no such
/// interface, `Some(None)` for one with no PTP clock.
type PtpLookup = Option<Option<PtpState>>;

struct Host {
    os: OsSemantics,
    privs: Privileges,
    limits: SysLimits,
    facts: SysFacts,
    cpus: CpuTopology,
    tai: Duration,
    ptp: BTreeMap<String, PtpLookup>,
}

pub(crate) fn run(checks: &[Check]) -> Vec<Finding> {
    let at = Instant::now();
    let tid = crate::threads::current_tid();
    let ptp = checks
        .iter()
        .filter_map(|c| match c {
            Check::PhcSynced { interface, .. } => Some(interface.clone()),
            _ => None,
        })
        .map(|name| {
            let clock = crate::netif::with_nic_ft(&name, |ft| ft.ptp);
            (name, clock)
        })
        .collect();
    let slot = crate::state::ft_slot();
    let (facts, cpus, tai) = {
        let g = slot.inner.lock();
        (g.sys_facts.clone(), g.cpus.clone(), g.tai_offset)
    };
    let host = Host {
        os: crate::os_semantics(),
        privs: crate::privileges(),
        limits: crate::sys_limits(),
        facts,
        cpus,
        tai,
        ptp,
    };
    let findings: Vec<Finding> = checks
        .iter()
        .map(|c| ctor::finding(c.clone(), host.status(c)))
        .collect();
    let passed = findings.iter().filter(|f| f.is_pass()).count();
    let mut g = slot.inner.lock();
    g.sys_checks.push(SysCheckRecord {
        at,
        tid,
        checks: checks.to_vec(),
        findings: findings.clone(),
    });
    g.events.push(FtEntry {
        at,
        tid,
        event: FtEvent::SysCheck {
            checks: checks.len(),
            passed,
        },
    });
    findings
}

fn fail(expected: impl Into<String>, actual: impl Into<String>) -> Status {
    Status::Fail {
        expected: expected.into(),
        actual: actual.into(),
    }
}

fn pass_if(ok: bool, expected: impl Into<String>, actual: impl Into<String>) -> Status {
    if ok {
        Status::Pass
    } else {
        fail(expected, actual)
    }
}

fn format_list(cpus: &[usize]) -> String {
    let mut sorted = cpus.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    let mut out = Vec::new();
    let mut i = 0;
    while i < sorted.len() {
        let start = sorted[i];
        while i + 1 < sorted.len() && sorted[i + 1] == sorted[i] + 1 {
            i += 1;
        }
        out.push(if sorted[i] == start {
            start.to_string()
        } else {
            format!("{start}-{}", sorted[i])
        });
        i += 1;
    }
    out.join(",")
}

fn parse_list(s: &str) -> Vec<usize> {
    s.split(',')
        .filter_map(|part| {
            let (lo, hi) = part.split_once('-').unwrap_or((part, part));
            Some(lo.trim().parse::<usize>().ok()?..=hi.trim().parse::<usize>().ok()?)
        })
        .flatten()
        .collect()
}

fn has_arg(args: &[String], want: &str) -> bool {
    if want.contains('=') {
        args.iter().any(|a| a == want)
    } else {
        args.iter()
            .any(|a| a == want || a.strip_prefix(want).is_some_and(|r| r.starts_with('=')))
    }
}

fn subset(what: &str, want: &[usize], have: &[usize]) -> Status {
    let missing: Vec<usize> = want.iter().copied().filter(|c| !have.contains(c)).collect();
    pass_if(
        missing.is_empty(),
        format!("{what} to include {}", format_list(want)),
        format!(
            "{what} = {:?}, missing {}",
            format_list(have),
            format_list(&missing)
        ),
    )
}

fn sysctl_status(key: &str, want: &str, have: &str) -> Status {
    let norm = |s: &str| s.split_whitespace().collect::<Vec<_>>().join(" ");
    pass_if(
        norm(have) == norm(want),
        format!("{key} = {want}"),
        format!("{key} = {have}"),
    )
}

impl Host {
    fn status(&self, check: &Check) -> Status {
        match self.os {
            OsSemantics::Linux => self.linux(check),
            OsSemantics::MacOs => self.macos(check),
            OsSemantics::Windows => self.windows(check),
        }
    }

    fn unavailable(&self) -> Status {
        Status::Unsupported(format!("not available on {}", self.os))
    }

    fn not_found(&self) -> String {
        crate::os::code_err(self.os, ENOENT, "ENOENT", std::io::ErrorKind::NotFound).to_string()
    }

    fn online(&self, cpus: &[usize]) -> Vec<usize> {
        cpus.iter()
            .copied()
            .filter(|&c| c < self.cpus.count)
            .collect()
    }

    fn physical_cores(&self) -> usize {
        if self.facts.smt_enabled {
            (self.cpus.count / 2).max(1)
        } else {
            self.cpus.count
        }
    }

    fn kernel_args(&self) -> Vec<String> {
        let mut args = self.facts.kernel_args.clone();
        for (name, cpus) in [
            ("isolcpus", &self.cpus.isolated),
            ("nohz_full", &self.cpus.nohz_full),
            ("rcu_nocbs", &self.cpus.rcu_nocbs),
        ] {
            if !cpus.is_empty() {
                args.push(format!("{name}={}", format_list(cpus)));
            }
        }
        args
    }

    /// A sysctl's value: the seeded one, else snare's own where it has
    /// one.
    fn sysctl(&self, key: &str) -> Option<String> {
        if let Some(v) = self.facts.sysctls.get(key) {
            return Some(v.clone());
        }
        let l = &self.limits;
        let v = match (self.os, key) {
            (OsSemantics::Linux, "kernel.ostype") => "Linux".to_string(),
            (OsSemantics::Linux, "kernel.sched_rt_runtime_us") => {
                self.facts.rt_runtime_us.to_string()
            }
            (OsSemantics::Linux, "net.core.rmem_default") => l.rmem_default.to_string(),
            (OsSemantics::Linux, "net.core.rmem_max") => l.rmem_max.to_string(),
            (OsSemantics::Linux, "net.core.wmem_default") => l.wmem_default.to_string(),
            (OsSemantics::Linux, "net.core.wmem_max") => l.wmem_max.to_string(),
            (OsSemantics::MacOs, "kern.ostype") => "Darwin".to_string(),
            (OsSemantics::MacOs, "kern.ipc.maxsockbuf") => l.max_sockbuf.to_string(),
            (OsSemantics::MacOs, "net.inet.udp.recvspace") => l.rmem_default.to_string(),
            (OsSemantics::MacOs, "net.inet.udp.maxdgram") => l.udp_max_dgram?.to_string(),
            _ => return None,
        };
        Some(v)
    }

    fn linux(&self, check: &Check) -> Status {
        let f = &self.facts;
        let p = &self.privs;
        match check {
            Check::PreemptRt => pass_if(f.preempt_rt, "a PREEMPT_RT kernel", f.kernel.clone()),
            Check::Isolated(want) => subset("isolated", want, &self.cpus.isolated),
            Check::NohzFull(want) => subset("nohz_full", want, &self.cpus.nohz_full),
            Check::RcuNocbs(want) => {
                let mut have = self.cpus.nohz_full.clone();
                have.extend(&self.cpus.rcu_nocbs);
                for arg in &f.kernel_args {
                    if let Some(list) = arg.strip_prefix("rcu_nocbs=") {
                        have.extend(parse_list(list));
                    }
                }
                have.sort_unstable();
                have.dedup();
                subset("rcu_nocbs", want, &have)
            }
            Check::IrqbalanceStopped => pass_if(
                !f.irqbalance_running,
                "irqbalance not running",
                format!("running as pid {IRQBALANCE_PID}"),
            ),
            Check::RtThrottlingDisabled => self.linux_sysctl("kernel.sched_rt_runtime_us", "-1"),
            Check::Governor { cpus, governor } => {
                let cpus = self.online(cpus);
                if cpus.is_empty() || f.governor.is_empty() {
                    return Status::Unsupported(
                        "no cpufreq driver; frequency is fixed or firmware-controlled".into(),
                    );
                }
                let wrong: Vec<String> = cpus
                    .iter()
                    .filter(|_| &f.governor != governor)
                    .map(|c| format!("cpu{c}={}", f.governor))
                    .collect();
                pass_if(
                    wrong.is_empty(),
                    format!("governor {governor}"),
                    wrong.join(", "),
                )
            }
            Check::IdleLatency { cpus, max_us } => {
                let cpus = self.online(cpus);
                if cpus.is_empty() || f.idle_states.is_empty() {
                    return Status::Unsupported("no cpuidle driver".into());
                }
                let slow: Vec<String> = cpus
                    .iter()
                    .flat_map(|c| {
                        f.idle_states
                            .iter()
                            .filter(|s| s.latency_us > *max_us && !s.disabled)
                            .map(move |s| format!("cpu{c} {} ({} µs)", s.name, s.latency_us))
                    })
                    .collect();
                pass_if(
                    slow.is_empty(),
                    format!("no enabled idle state slower than {max_us} µs"),
                    slow.join(", "),
                )
            }
            Check::TransparentHugepages(want) => {
                if f.transparent_hugepages.is_empty() {
                    return if want == "never" {
                        Status::Pass
                    } else {
                        Status::Unsupported("kernel built without transparent huge pages".into())
                    };
                }
                pass_if(
                    &f.transparent_hugepages == want,
                    want.clone(),
                    f.transparent_hugepages.clone(),
                )
            }
            Check::SmtDisabled => pass_if(!f.smt_enabled, "SMT off", "on"),
            Check::Sysctl { key, value } => self.linux_sysctl(key, value),
            Check::KernelArg(arg) => pass_if(
                has_arg(&self.kernel_args(), arg),
                format!("{arg} on the kernel command line"),
                "absent",
            ),
            Check::PhcSynced {
                interface,
                max_offset,
            } => self.phc_synced(interface, *max_offset),
            Check::Elevated => pass_if(p.root, "root", "uid 1000"),
            Check::CanConfigureNic => pass_if(
                p.net_admin,
                "CAP_NET_ADMIN",
                "CAP_NET_ADMIN not in the effective set",
            ),
            Check::CanSetRealtime(priority) => pass_if(
                p.sys_nice || p.rtprio_limit >= *priority,
                format!("CAP_SYS_NICE or RLIMIT_RTPRIO >= {priority}"),
                format!("no CAP_SYS_NICE, RLIMIT_RTPRIO = {}", p.rtprio_limit),
            ),
            Check::CanLockMemory => pass_if(
                p.ipc_lock || p.memlock_limit.is_none(),
                "CAP_IPC_LOCK or unlimited RLIMIT_MEMLOCK",
                format!(
                    "no CAP_IPC_LOCK, RLIMIT_MEMLOCK = {} bytes",
                    p.memlock_limit.unwrap_or(0)
                ),
            ),
            Check::CanSetIrqAffinity => pass_if(
                p.root,
                "write access to /proc/irq/default_smp_affinity",
                "denied",
            ),
            Check::CanHoldCpuDmaLatency => {
                pass_if(p.root, "write access to /dev/cpu_dma_latency", "denied")
            }
            _ => self.unavailable(),
        }
    }

    fn linux_sysctl(&self, key: &str, want: &str) -> Status {
        match self.sysctl(key) {
            Some(have) => sysctl_status(key, want, &have),
            None => Status::Error(self.not_found()),
        }
    }

    fn phc_synced(&self, interface: &str, max_offset: Duration) -> Status {
        let ptp = match self.ptp.get(interface).copied().flatten() {
            None => return Status::Error(format!("no interface named {interface:?}")),
            Some(None) => {
                return Status::Unsupported(format!("{interface} has no PTP hardware clock"));
            }
            Some(Some(ptp)) => ptp,
        };
        if !self.privs.root {
            return Status::Error(sys_err_for(self.os, SysErrno::Access).to_string());
        }
        let tai = self.tai.as_nanos() as i64;
        let raw = ptp.offset_nanos + if ptp.tai { tai } else { 0 };
        let nanos = [raw, raw - tai]
            .into_iter()
            .min_by_key(|o| o.unsigned_abs())
            .unwrap_or(raw);
        let off = u128::from(nanos.unsigned_abs()) + ptp.uncertainty.as_nanos();
        pass_if(
            off <= max_offset.as_nanos(),
            format!("{interface} clock within {max_offset:?} of the system clock"),
            format!(
                "{}{:?} off (± {:?}) on /dev/ptp{}",
                if nanos < 0 { "-" } else { "" },
                Duration::from_nanos(nanos.unsigned_abs()),
                ptp.uncertainty,
                ptp.clock
            ),
        )
    }

    fn macos(&self, check: &Check) -> Status {
        match check {
            Check::SmtDisabled => {
                let (threads, cores) = (self.cpus.count, self.physical_cores());
                pass_if(
                    threads == cores,
                    "SMT off",
                    format!("{threads} logical CPUs on {cores} cores"),
                )
            }
            Check::Sysctl { key, value } => match self.sysctl(key) {
                Some(have) => {
                    let have = match (value.trim().parse::<i64>(), have.trim().parse::<i64>()) {
                        (Ok(_), Ok(n)) => n.to_string(),
                        _ => have,
                    };
                    sysctl_status(key, value, &have)
                }
                None => Status::Error(self.not_found()),
            },
            Check::MacOsLowPowerModeOff => {
                pass_if(!self.facts.macos_low_power_mode, "Low Power Mode off", "on")
            }
            Check::Elevated => pass_if(self.privs.root, "root", "uid 501"),
            Check::CanSetRealtime(_) => Status::Pass,
            _ => self.unavailable(),
        }
    }

    fn windows(&self, check: &Check) -> Status {
        let p = &self.privs;
        let elevated = || pass_if(p.root, "an elevated process", "not elevated");
        let privilege = |held: bool, name: &str| pass_if(held, name, "not held by this process");
        match check {
            Check::SmtDisabled => {
                let cores = self.physical_cores();
                let smt = if self.facts.smt_enabled { cores } else { 0 };
                pass_if(
                    smt == 0,
                    "SMT off",
                    format!("{smt} of {cores} cores run two threads"),
                )
            }
            Check::WinHighPerformancePower => pass_if(
                WIN_FAST_PLANS.contains(&self.facts.win_power_plan.as_str()),
                "High performance or Ultimate Performance power plan",
                self.facts.win_power_plan.clone(),
            ),
            Check::WinCoreParkingDisabled => {
                let percent = self.facts.win_unparked_percent;
                pass_if(
                    percent >= 100,
                    "100% of cores unparked",
                    format!("class 0 keeps {percent}% of cores unparked"),
                )
            }
            Check::Elevated | Check::CanConfigureNic | Check::CanSetIrqAffinity => elevated(),
            Check::CanSetRealtime(_) => privilege(p.sys_nice, "SeIncreaseBasePriorityPrivilege"),
            Check::CanLockMemory => privilege(p.ipc_lock, "SeIncreaseWorkingSetPrivilege"),
            _ => self.unavailable(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists_and_args_parse_as_fast_talker_does() {
        assert_eq!(format_list(&[6, 0, 1, 2, 3, 9, 10]), "0-3,6,9-10");
        assert_eq!(parse_list("0-2,5"), [0, 1, 2, 5]);
        let args: Vec<String> = ["quiet", "isolcpus=managed_irq,domain,6-7", "nosmt"]
            .map(String::from)
            .to_vec();
        assert!(has_arg(&args, "nosmt"));
        assert!(has_arg(&args, "isolcpus"));
        assert!(!has_arg(&args, "isolcpus=6-7"));
        assert!(!has_arg(&args, "iso"));
    }
}
