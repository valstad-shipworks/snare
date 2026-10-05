#![cfg(target_os = "linux")]

//! The real NIC's driver against the sim's `ethtool` model ([`snare::Nic`], src/ethtool.rs):
//! every read-only `SIOCETHTOOL` command answered by the real driver, then by a sim whose `Nic`
//! was built from those answers ([`hw::linux::nic_profile`]), must come back identical, so the
//! model's struct layouts, its derived fields (EEE `eee_active`, `ETHTOOL_GLINK`, the
//! `ETHTOOL_GDRVINFO` statistics count) and its error codes hold for that driver. With
//! `SNARE_HW_MUTATE=1` it also changes settings on both and compares what is read back and which
//! changes are refused, restoring the real NIC afterwards.
//!
//! Layouts and command numbers: include/uapi/linux/ethtool.h; the core's checks before the driver
//! sees a change: net/ethtool/ioctl.c (`ethtool_set_ringparam`, `ethtool_set_channels`,
//! `ethtool_set_coalesce_supported`, the `CAP_NET_ADMIN` test in `__dev_ethtool`).

#[path = "support/hw.rs"]
mod hw;

use hw::linux::*;
use hw::{need, require};

fn iface() -> Option<String> {
    hw::hw().iface.clone()
}

const NEEDS_IFACE: &str = "needs a wired NIC (set SNARE_HW_IFACE=<name>)";

/// Each read-only answer, field by field, so a failure names the command that differs.
#[test]
#[ignore = "hardware: needs a NIC"]
fn hw_ethtool_reads_match_the_model() {
    let iface = need!(iface(), "{NEEDS_IFACE}");
    let (nic, assumed) = snare::real(|| nic_profile(&iface));
    let real = snare::real(|| view(&iface));
    let sim = sim_with(nic).run(|| view(&iface));
    eprintln!(
        "{iface}: {}\nreal: {real:#?}\nassumed: {assumed:?}",
        hw::hw().summary()
    );

    match (&real.drvinfo, &sim.drvinfo) {
        (Ok(r), Ok(s)) => {
            assert_eq!(
                (
                    &s.driver,
                    &s.version,
                    &s.fw_version,
                    &s.bus_info,
                    &s.erom_version,
                    s.n_stats
                ),
                (
                    &r.driver,
                    &r.version,
                    &r.fw_version,
                    &r.bus_info,
                    &r.erom_version,
                    r.n_stats
                ),
                "ETHTOOL_GDRVINFO strings and n_stats"
            );
            let unmodelled =
                |s: &DrvInfo| (s.n_priv_flags, s.testinfo_len, s.eedump_len, s.regdump_len);
            if unmodelled(s) != unmodelled(r) {
                hw::note(&format!(
                    "ETHTOOL_GDRVINFO (n_priv_flags, testinfo_len, eedump_len, regdump_len): real {:?}, sim {:?} (not modelled)",
                    unmodelled(r),
                    unmodelled(s)
                ));
            }
        }
        (r, s) => assert_eq!(s.as_ref().err(), r.as_ref().err(), "ETHTOOL_GDRVINFO"),
    }
    assert_eq!(
        sim.link, real.link,
        "ETHTOOL_GLINK (sim: admin up and operstate \"up\")"
    );
    assert_eq!(sim.rings, real.rings, "ETHTOOL_GRINGPARAM");
    assert_eq!(sim.coalesce, real.coalesce, "ETHTOOL_GCOALESCE");
    assert_eq!(sim.channels, real.channels, "ETHTOOL_GCHANNELS");
    assert_eq!(sim.pause, real.pause, "ETHTOOL_GPAUSEPARAM");
    assert_eq!(
        sim.eee, real.eee,
        "ETHTOOL_GEEE [supported, advertised, lp_advertised, active, enabled, tx_lpi_enabled, tx_lpi_timer] (sim derives active)"
    );
    assert_eq!(sim.flags, real.flags, "ETHTOOL_GFLAGS");
    assert_eq!(sim.ts_info, real.ts_info, "ETHTOOL_GET_TS_INFO");
    assert_eq!(
        sim.stats_count, real.stats_count,
        "ETHTOOL_GSSET_INFO(ETH_SS_STATS)"
    );
    assert_eq!(
        sim.stat_names, real.stat_names,
        "ETHTOOL_GSTRINGS(ETH_SS_STATS)"
    );
}

/// Commands nobody may run without `CAP_NET_ADMIN` fail with `EPERM` before the driver is asked,
/// so even a write of the current values changes nothing. Runs only without the capability.
#[test]
#[ignore = "hardware: needs a NIC"]
fn hw_ethtool_setters_need_net_admin() {
    let iface = need!(iface(), "{NEEDS_IFACE}");
    require!(
        !hw::hw().cap(hw::CAP_NET_ADMIN),
        "needs to run without CAP_NET_ADMIN (run as an ordinary user)"
    );
    let (nic, _) = snare::real(|| nic_profile(&iface));
    let probe = || {
        let mut out = Vec::new();
        for (get, set, n) in [
            (ETHTOOL_GRINGPARAM, ETHTOOL_SRINGPARAM, 8),
            (ETHTOOL_GCOALESCE, ETHTOOL_SCOALESCE, 22),
            (ETHTOOL_GCHANNELS, ETHTOOL_SCHANNELS, 8),
            (ETHTOOL_GPAUSEPARAM, ETHTOOL_SPAUSEPARAM, 3),
            (ETHTOOL_GEEE, ETHTOOL_SEEE, 9),
        ] {
            let current = get_words::<22>(&iface, get).unwrap_or([0; 22]);
            out.push((set, set_words(&iface, set, &current[..n])));
        }
        out
    };
    let real = snare::real(probe);
    let sim = sim_with(nic).run(probe);
    assert_eq!(sim, real);
    assert!(real.iter().all(|(_, r)| *r == Err(libc::EPERM)), "{real:?}");
}

/// The real NIC's settings at the start, written back when dropped (and the link awaited, since
/// several drivers reset the port to resize rings or queues).
struct Restore {
    iface: String,
    saved: Vec<(u32, Vec<u32>)>,
}

impl Restore {
    fn save(iface: &str) -> Restore {
        let mut saved = Vec::new();
        for (get, set, n) in [
            (ETHTOOL_GRINGPARAM, ETHTOOL_SRINGPARAM, 8),
            (ETHTOOL_GCOALESCE, ETHTOOL_SCOALESCE, 22),
            (ETHTOOL_GCHANNELS, ETHTOOL_SCHANNELS, 8),
            (ETHTOOL_GPAUSEPARAM, ETHTOOL_SPAUSEPARAM, 3),
            (ETHTOOL_GEEE, ETHTOOL_SEEE, 9),
        ] {
            if let Ok(w) = snare::real(|| get_words::<22>(iface, get)) {
                saved.push((set, w[..n].to_vec()));
            }
        }
        eprintln!("saved {iface}: {saved:?}");
        Restore {
            iface: iface.to_string(),
            saved,
        }
    }
}

impl Drop for Restore {
    fn drop(&mut self) {
        snare::real(|| {
            for (set, words) in &self.saved {
                let current =
                    get_words::<22>(&self.iface, set - 1).map(|w| w[..words.len()].to_vec());
                if current.as_ref() != Ok(words)
                    && let Err(e) = set_words(&self.iface, *set, words)
                {
                    eprintln!(
                        "could not restore ethtool command {set:#x} on {}: errno {e}",
                        self.iface
                    );
                }
            }
            for _ in 0..200 {
                if get_words::<1>(&self.iface, ETHTOOL_GLINK) == Ok([1]) {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        });
    }
}

fn mutating() -> Result<(String, std::sync::MutexGuard<'static, ()>), String> {
    let h = hw::hw();
    let iface = h.iface.clone().ok_or(NEEDS_IFACE.to_string())?;
    if !h.mutate {
        return Err(format!(
            "changes {iface}'s settings (set SNARE_HW_MUTATE=1; they are restored after)"
        ));
    }
    if !h.cap(hw::CAP_NET_ADMIN) {
        return Err("needs CAP_NET_ADMIN (run as root)".into());
    }
    Ok((iface, hw::nic_lock()))
}

/// Ring sizes: the largest allowed is taken and read back as asked or as the driver rounds it,
/// one past the maximum is `EINVAL` (`ethtool_set_ringparam`).
#[test]
#[ignore = "hardware: needs a NIC, CAP_NET_ADMIN and SNARE_HW_MUTATE=1"]
fn hw_ethtool_ring_changes_match() {
    let (iface, _lock) = match mutating() {
        Ok(v) => v,
        Err(why) => return hw::skip(&why),
    };
    let rings = need!(
        snare::real(|| get_words::<8>(&iface, ETHTOOL_GRINGPARAM)).ok(),
        "needs a driver with ETHTOOL_GRINGPARAM"
    );
    let (nic, _) = snare::real(|| nic_profile(&iface));
    let _restore = Restore::save(&iface);
    let target = if rings[4] == rings[0] {
        rings[0] / 2
    } else {
        rings[0]
    };
    let probe = || {
        let mut w = rings;
        w[4] = target;
        let set = set_words(&iface, ETHTOOL_SRINGPARAM, &w);
        let read = get_words::<8>(&iface, ETHTOOL_GRINGPARAM);
        let mut over = rings;
        over[4] = rings[0] + 1;
        let refused = set_words(&iface, ETHTOOL_SRINGPARAM, &over);
        let mut tx_over = rings;
        tx_over[7] = rings[3] + 1;
        let tx_refused = set_words(&iface, ETHTOOL_SRINGPARAM, &tx_over);
        (set, read, refused, tx_refused)
    };
    let real = snare::real(probe);
    let sim = sim_with(nic).run(probe);
    assert_eq!(
        sim, real,
        "rx ring {} -> {target} (max {})",
        rings[4], rings[0]
    );
}

/// Coalescing: a non-zero value in a field the driver does not support is `EOPNOTSUPP` from the
/// core (`ethtool_set_coalesce_supported`); a supported field moved by one reads back as set.
#[test]
#[ignore = "hardware: needs a NIC, CAP_NET_ADMIN and SNARE_HW_MUTATE=1"]
fn hw_ethtool_coalesce_changes_match() {
    let (iface, _lock) = match mutating() {
        Ok(v) => v,
        Err(why) => return hw::skip(&why),
    };
    let current = need!(
        snare::real(|| get_words::<22>(&iface, ETHTOOL_GCOALESCE)).ok(),
        "needs a driver with ETHTOOL_GCOALESCE"
    );
    let (nic, assumed) = snare::real(|| nic_profile(&iface));
    require!(
        assumed.coalesce_supported_exact,
        "needs ethtool netlink (Linux 5.6+) to learn which coalescing fields {iface} supports"
    );
    let supported = assumed.coalesce_supported;
    let unsupported = (0..22).find(|i| supported & 1 << i == 0);
    let settable = [0usize, 4].into_iter().find(|i| supported & 1 << i != 0);
    let _restore = Restore::save(&iface);
    let probe = || {
        let mut out = Vec::new();
        if let Some(i) = unsupported {
            let mut w = current;
            w[i] = 1;
            out.push((
                "unsupported field",
                i,
                set_words(&iface, ETHTOOL_SCOALESCE, &w),
                None,
            ));
        }
        if let Some(i) = settable {
            let mut w = current;
            w[i] = if w[i] > 1 { w[i] - 1 } else { w[i] + 1 };
            let set = set_words(&iface, ETHTOOL_SCOALESCE, &w);
            let read = get_words::<22>(&iface, ETHTOOL_GCOALESCE).map(|r| r[i]);
            out.push(("supported usecs field", i, set, Some(read)));
        }
        out
    };
    let real = snare::real(probe);
    let sim = sim_with(nic).run(probe);
    assert_eq!(sim, real, "supported coalescing fields {supported:#x}");
}

/// Channels: counts past their maxima and a layout with no RX or TX queue are `EINVAL`
/// (`ethtool_set_channels`); writing the current layout succeeds.
#[test]
#[ignore = "hardware: needs a NIC, CAP_NET_ADMIN and SNARE_HW_MUTATE=1"]
fn hw_ethtool_channel_changes_match() {
    let (iface, _lock) = match mutating() {
        Ok(v) => v,
        Err(why) => return hw::skip(&why),
    };
    let c = need!(
        snare::real(|| get_words::<8>(&iface, ETHTOOL_GCHANNELS)).ok(),
        "needs a driver with ETHTOOL_GCHANNELS"
    );
    let (nic, _) = snare::real(|| nic_profile(&iface));
    let _restore = Restore::save(&iface);
    let probe = || {
        let mut out = vec![set_words(&iface, ETHTOOL_SCHANNELS, &c)];
        let mut over = c;
        over[7] = c[3] + 1;
        out.push(set_words(&iface, ETHTOOL_SCHANNELS, &over));
        let mut none = c;
        (none[4], none[5], none[7]) = (0, 0, 0);
        out.push(set_words(&iface, ETHTOOL_SCHANNELS, &none));
        out.push(get_words::<8>(&iface, ETHTOOL_GCHANNELS).map(|_| ()));
        out
    };
    let real = snare::real(probe);
    let sim = sim_with(nic).run(probe);
    assert_eq!(sim, real, "channels {c:?}");
}

/// Flow control and EEE: the current settings written back read back unchanged; advertising an
/// EEE mode outside `supported` is refused as the driver refuses it.
#[test]
#[ignore = "hardware: needs a NIC, CAP_NET_ADMIN and SNARE_HW_MUTATE=1"]
fn hw_ethtool_pause_and_eee_changes_match() {
    let (iface, _lock) = match mutating() {
        Ok(v) => v,
        Err(why) => return hw::skip(&why),
    };
    let (nic, _) = snare::real(|| nic_profile(&iface));
    let _restore = Restore::save(&iface);
    let probe = || {
        let pause = get_words::<3>(&iface, ETHTOOL_GPAUSEPARAM);
        let pause_set = pause.map(|p| set_words(&iface, ETHTOOL_SPAUSEPARAM, &p));
        let eee = get_words::<9>(&iface, ETHTOOL_GEEE);
        let eee_set = eee.map(|e| set_words(&iface, ETHTOOL_SEEE, &e));
        let eee_bad = eee.map(|mut e| {
            e[1] = !e[0] & 0x0000_ffff;
            set_words(&iface, ETHTOOL_SEEE, &e)
        });
        let after = (
            get_words::<3>(&iface, ETHTOOL_GPAUSEPARAM),
            get_words::<7>(&iface, ETHTOOL_GEEE),
        );
        (pause_set, eee_set, eee_bad, after)
    };
    let real = snare::real(probe);
    let sim = sim_with(nic).run(probe);
    assert_eq!(sim, real);
}
