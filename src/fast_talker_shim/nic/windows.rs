//! Windows adapter settings: driver timestamping, the interrupt affinity
//! policy and receive-side scaling. Reading needs no privileges; every
//! change needs an elevated process and restarts the adapter.

use std::io;

use super::{Need, Nic, Rss, physical};
use crate::fast_talker_shim::platform::Item;

/// The interrupt affinity policy covers processor group 0 only.
const GROUP_SIZE: usize = usize::BITS as usize;

impl Nic {
    /// Whether the driver stamps sent packets (`*SoftwareTimestamp`).
    pub fn tx_timestamping(&self) -> io::Result<bool> {
        self.get(Item::WindowsNic, |n, os| {
            physical(n, os)?;
            Ok(n.ft.win_timestamping.tx)
        })
    }

    /// Turns transmit timestamping in the driver on or off, keeping its
    /// receive setting.
    pub fn set_tx_timestamping(&self, on: bool) -> io::Result<()> {
        self.set(
            Item::WindowsNic,
            Need::Elevated,
            format!("set_tx_timestamping({on})"),
            |n, os| {
                physical(n, os)?;
                let changed = n.ft.win_timestamping.tx != on;
                n.ft.win_timestamping.tx = on;
                Ok(((), changed))
            },
        )
    }

    /// The CPUs the adapter's interrupts are pinned to by its interrupt
    /// affinity policy, or `None` when Windows chooses.
    pub fn irq_affinity(&self) -> io::Result<Option<Vec<usize>>> {
        self.get(Item::WindowsNic, |n, os| {
            physical(n, os)?;
            Ok(n.ft.win_irq_affinity.clone())
        })
    }

    pub(super) fn set_windows_irq_affinity(&self, cpus: &[usize]) -> io::Result<()> {
        let mut want = cpus.to_vec();
        want.sort_unstable();
        want.dedup();
        self.set(
            Item::WindowsNic,
            Need::Elevated,
            format!("set_irq_affinity({cpus:?})"),
            |n, os| {
                physical(n, os)?;
                let want = (!want.is_empty()).then_some(want);
                if n.ft.win_irq_affinity == want {
                    return Ok(((), false));
                }
                if want.iter().flatten().any(|&c| c >= GROUP_SIZE) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "interrupt affinity policy only covers processor group 0",
                    ));
                }
                n.ft.win_irq_affinity = want;
                Ok(((), true))
            },
        )
    }

    /// Receive-side scaling placement.
    pub fn rss(&self) -> io::Result<Rss> {
        self.get(Item::WindowsNic, |n, os| {
            physical(n, os)?;
            Ok(n.ft.rss)
        })
    }

    /// Sets receive-side scaling placement. `None` fields are left alone.
    pub fn set_rss(&self, rss: &Rss) -> io::Result<()> {
        let rss = *rss;
        self.set(
            Item::WindowsNic,
            Need::Elevated,
            format!("set_rss({rss:?})"),
            |n, os| {
                physical(n, os)?;
                let cur = n.ft.rss;
                let new = Rss {
                    enabled: rss.enabled,
                    base_cpu: rss.base_cpu.or(cur.base_cpu),
                    max_cpu: rss.max_cpu.or(cur.max_cpu),
                    max_processors: rss.max_processors.or(cur.max_processors),
                };
                n.ft.rss = new;
                Ok(((), new != cur))
            },
        )
    }
}
