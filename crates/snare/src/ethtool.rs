//! A simulated NIC's driver as `ethtool` sees it: the `SIOCETHTOOL` commands a tuning library
//! issues (driver info, link, ring sizes, interrupt coalescing, channels, flow control, Energy
//! Efficient Ethernet, the feature flags, n-tuple flow steering rules and driver statistics), with
//! what a [`Nic`](crate::Nic) declares as the driver's capabilities and what the code under test
//! sets persisting for it to read back.
//!
//! The dispatch follows `__dev_ethtool` in net/ethtool/ioctl.c (Linux 6.12): commands outside
//! its "allow some commands to be done by anyone" list need `CAP_NET_ADMIN` (`EPERM`, checked
//! before anything else), a command the driver has no operation for is `EOPNOTSUPP`, and the
//! core's own checks (`ethtool_set_ringparam`, `ethtool_set_channels`,
//! `ethtool_set_coalesce_supported`, `__ethtool_set_flags`) run before the driver's. Where only a
//! driver decides, the sim behaves as a generic driver and cites the one it follows. Command
//! numbers and struct layouts are from include/uapi/linux/ethtool.h.
//!
//! Every value here is read and written under the [`SimHost`](crate::SimHost)'s state lock, with
//! no other lock taken inside it. The types are cross-platform so a [`Nic`](crate::Nic) builds
//! anywhere; only Linux has `SIOCETHTOOL` to serve.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::collections::BTreeMap;
use std::ffi::c_int;

/// `ETHTOOL_GDRVINFO`: `struct ethtool_drvinfo`.
const ETHTOOL_GDRVINFO: u32 = 0x03;
/// `ETHTOOL_GLINK`: `struct ethtool_value`, `data` 1 when the link is up.
const ETHTOOL_GLINK: u32 = 0x0a;
/// `ETHTOOL_GCOALESCE`: `struct ethtool_coalesce`.
const ETHTOOL_GCOALESCE: u32 = 0x0e;
/// `ETHTOOL_SCOALESCE`.
const ETHTOOL_SCOALESCE: u32 = 0x0f;
/// `ETHTOOL_GRINGPARAM`: `struct ethtool_ringparam`.
const ETHTOOL_GRINGPARAM: u32 = 0x10;
/// `ETHTOOL_SRINGPARAM`.
const ETHTOOL_SRINGPARAM: u32 = 0x11;
/// `ETHTOOL_GPAUSEPARAM`: `struct ethtool_pauseparam`.
const ETHTOOL_GPAUSEPARAM: u32 = 0x12;
/// `ETHTOOL_SPAUSEPARAM`.
const ETHTOOL_SPAUSEPARAM: u32 = 0x13;
/// `ETHTOOL_GSTRINGS`: `struct ethtool_gstrings`.
const ETHTOOL_GSTRINGS: u32 = 0x1b;
/// `ETHTOOL_GSTATS`: `struct ethtool_stats`.
const ETHTOOL_GSTATS: u32 = 0x1d;
/// `ETHTOOL_GFLAGS`: `struct ethtool_value` holding `ETH_FLAG_*`.
const ETHTOOL_GFLAGS: u32 = 0x25;
/// `ETHTOOL_SFLAGS`.
const ETHTOOL_SFLAGS: u32 = 0x26;
/// `ETHTOOL_GRXCLSRLCNT`: `struct ethtool_rxnfc`, the rule count and table size.
const ETHTOOL_GRXCLSRLCNT: u32 = 0x2e;
/// `ETHTOOL_GRXCLSRULE`: one rule by location.
const ETHTOOL_GRXCLSRULE: u32 = 0x2f;
/// `ETHTOOL_GRXCLSRLALL`: every rule's location.
const ETHTOOL_GRXCLSRLALL: u32 = 0x30;
/// `ETHTOOL_SRXCLSRLDEL`: delete the rule at a location.
const ETHTOOL_SRXCLSRLDEL: u32 = 0x31;
/// `ETHTOOL_SRXCLSRLINS`: insert a rule.
const ETHTOOL_SRXCLSRLINS: u32 = 0x32;
/// `ETHTOOL_GSSET_INFO`: `struct ethtool_sset_info`.
const ETHTOOL_GSSET_INFO: u32 = 0x37;
/// `ETHTOOL_GCHANNELS`: `struct ethtool_channels`.
const ETHTOOL_GCHANNELS: u32 = 0x3c;
/// `ETHTOOL_SCHANNELS`.
const ETHTOOL_SCHANNELS: u32 = 0x3d;
/// `ETHTOOL_GET_TS_INFO`: `struct ethtool_ts_info`.
const ETHTOOL_GET_TS_INFO: u32 = 0x41;
/// `ETHTOOL_GEEE`: `struct ethtool_eee`.
const ETHTOOL_GEEE: u32 = 0x44;
/// `ETHTOOL_SEEE`.
const ETHTOOL_SEEE: u32 = 0x45;

/// `ETH_SS_STATS`: the driver-statistics string set (`enum ethtool_stringset`).
const ETH_SS_STATS: u32 = 1;
const ETH_SS_PRIV_FLAGS: u32 = 2;
/// `ETH_GSTRING_LEN`: the width of one statistic's name.
const ETH_GSTRING_LEN: usize = 32;

/// `ETH_FLAG_TXVLAN` (`enum ethtool_flags`).
const ETH_FLAG_TXVLAN: u32 = 1 << 7;
/// `ETH_FLAG_RXVLAN`.
const ETH_FLAG_RXVLAN: u32 = 1 << 8;
/// `ETH_FLAG_LRO`.
const ETH_FLAG_LRO: u32 = 1 << 15;
/// `ETH_FLAG_NTUPLE`: n-tuple flow steering enabled.
pub(crate) const ETH_FLAG_NTUPLE: u32 = 1 << 27;
/// `ETH_FLAG_RXHASH`.
const ETH_FLAG_RXHASH: u32 = 1 << 28;
/// `ETH_ALL_FLAGS` (net/ethtool/ioctl.c): the flags `ETHTOOL_SFLAGS` may name at all.
const ETH_ALL_FLAGS: u32 =
    ETH_FLAG_LRO | ETH_FLAG_RXVLAN | ETH_FLAG_TXVLAN | ETH_FLAG_NTUPLE | ETH_FLAG_RXHASH;

/// `RX_CLS_FLOW_DISC`: a rule's `ring_cookie` that drops matching packets.
const RX_CLS_FLOW_DISC: u64 = u64::MAX;
/// `RX_CLS_FLOW_WAKE`: a `ring_cookie` that wakes the host.
const RX_CLS_FLOW_WAKE: u64 = 0xffff_ffff_ffff_fffe;
/// `FLOW_RSS` in a rule's `flow_type`: the rule targets an RSS context, not a queue.
const FLOW_RSS: u32 = 0x2000_0000;
/// `ETHTOOL_RX_FLOW_SPEC_RING_VF`: the VF bits of a `ring_cookie`.
const ETHTOOL_RX_FLOW_SPEC_RING_VF: u64 = 0x0000_00FF_0000_0000;

/// The size of `struct ethtool_rx_flow_spec`: `flow_type` (4), the `h_u`/`m_u` unions (52
/// each), `h_ext`/`m_ext` (20 each), padding to the 8-byte `ring_cookie` at 152, `location` at
/// 160, padded to 168.
const FLOW_SPEC_LEN: usize = 168;
/// Where `struct ethtool_rxnfc` puts its fields: `cmd` 0, `flow_type` 4, `data` 8, `fs` 16,
/// `rule_cnt` 184, `rule_locs[]` 188.
const RXNFC_FS: usize = 16;
/// `ethtool_rxnfc.rule_cnt`.
const RXNFC_RULE_CNT: usize = RXNFC_FS + FLOW_SPEC_LEN;
/// `ethtool_rxnfc.rule_locs`.
const RXNFC_RULE_LOCS: usize = RXNFC_RULE_CNT + 4;

/// Descriptor ring sizes and their maxima (`struct ethtool_ringparam`, `ethtool -g`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Rings {
    /// `rx_max_pending`.
    pub rx_max: u32,
    /// `rx_mini_max_pending`.
    pub rx_mini_max: u32,
    /// `rx_jumbo_max_pending`.
    pub rx_jumbo_max: u32,
    /// `tx_max_pending`.
    pub tx_max: u32,
    /// `rx_pending`: the RX ring's size.
    pub rx: u32,
    /// `rx_mini_pending`.
    pub rx_mini: u32,
    /// `rx_jumbo_pending`.
    pub rx_jumbo: u32,
    /// `tx_pending`: the TX ring's size.
    pub tx: u32,
}

/// Queue counts and their maxima (`struct ethtool_channels`, `ethtool -l`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Channels {
    /// `max_rx`.
    pub rx_max: u32,
    /// `max_tx`.
    pub tx_max: u32,
    /// `max_other`.
    pub other_max: u32,
    /// `max_combined`.
    pub combined_max: u32,
    /// `rx_count`: RX-only queues.
    pub rx: u32,
    /// `tx_count`: TX-only queues.
    pub tx: u32,
    /// `other_count`: link and other interrupts.
    pub other: u32,
    /// `combined_count`: queue pairs.
    pub combined: u32,
}

/// Ethernet flow control (`struct ethtool_pauseparam`, `ethtool -a`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Pause {
    /// `autoneg`: negotiate pause with the link partner.
    pub autoneg: bool,
    /// `rx_pause`: honour received PAUSE frames.
    pub rx: bool,
    /// `tx_pause`: send PAUSE frames.
    pub tx: bool,
}

/// Energy Efficient Ethernet (`struct ethtool_eee`, `ethtool --show-eee`). Link modes are the
/// legacy `SUPPORTED_*`/`ADVERTISED_*` bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Eee {
    /// `supported`: the link modes EEE can run at.
    pub supported: u32,
    /// `advertised`.
    pub advertised: u32,
    /// `lp_advertised`: what the link partner advertises.
    pub lp_advertised: u32,
    /// `eee_active`: negotiated and in use. Reported as `eee_enabled` with the link up and a
    /// mode both ends advertise; the value given here is ignored.
    pub active: bool,
    /// `eee_enabled`.
    pub enabled: bool,
    /// `tx_lpi_enabled`: whether the transmitter may enter low-power idle.
    pub tx_lpi_enabled: bool,
    /// `tx_lpi_timer`, in µs.
    pub tx_lpi_timer: u32,
}

/// Interrupt coalescing (`struct ethtool_coalesce`, `ethtool -c`), field for field in the
/// kernel's order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Coalesce {
    /// `rx_coalesce_usecs`.
    pub rx_usecs: u32,
    /// `rx_max_coalesced_frames`.
    pub rx_frames: u32,
    /// `rx_coalesce_usecs_irq`.
    pub rx_usecs_irq: u32,
    /// `rx_max_coalesced_frames_irq`.
    pub rx_frames_irq: u32,
    /// `tx_coalesce_usecs`.
    pub tx_usecs: u32,
    /// `tx_max_coalesced_frames`.
    pub tx_frames: u32,
    /// `tx_coalesce_usecs_irq`.
    pub tx_usecs_irq: u32,
    /// `tx_max_coalesced_frames_irq`.
    pub tx_frames_irq: u32,
    /// `stats_block_coalesce_usecs`.
    pub stats_block_usecs: u32,
    /// `use_adaptive_rx_coalesce`.
    pub adaptive_rx: bool,
    /// `use_adaptive_tx_coalesce`.
    pub adaptive_tx: bool,
    /// `pkt_rate_low`.
    pub pkt_rate_low: u32,
    /// `rx_coalesce_usecs_low`.
    pub rx_usecs_low: u32,
    /// `rx_max_coalesced_frames_low`.
    pub rx_frames_low: u32,
    /// `tx_coalesce_usecs_low`.
    pub tx_usecs_low: u32,
    /// `tx_max_coalesced_frames_low`.
    pub tx_frames_low: u32,
    /// `pkt_rate_high`.
    pub pkt_rate_high: u32,
    /// `rx_coalesce_usecs_high`.
    pub rx_usecs_high: u32,
    /// `rx_max_coalesced_frames_high`.
    pub rx_frames_high: u32,
    /// `tx_coalesce_usecs_high`.
    pub tx_usecs_high: u32,
    /// `tx_max_coalesced_frames_high`.
    pub tx_frames_high: u32,
    /// `rate_sample_interval`.
    pub sample_interval: u32,
}

impl Coalesce {
    /// The 22 words after `cmd`, in `struct ethtool_coalesce` order.
    fn words(&self) -> [u32; 22] {
        [
            self.rx_usecs,
            self.rx_frames,
            self.rx_usecs_irq,
            self.rx_frames_irq,
            self.tx_usecs,
            self.tx_frames,
            self.tx_usecs_irq,
            self.tx_frames_irq,
            self.stats_block_usecs,
            u32::from(self.adaptive_rx),
            u32::from(self.adaptive_tx),
            self.pkt_rate_low,
            self.rx_usecs_low,
            self.rx_frames_low,
            self.tx_usecs_low,
            self.tx_frames_low,
            self.pkt_rate_high,
            self.rx_usecs_high,
            self.rx_frames_high,
            self.tx_usecs_high,
            self.tx_frames_high,
            self.sample_interval,
        ]
    }

    /// The struct from its 22 words.
    fn from_words(w: [u32; 22]) -> Self {
        Coalesce {
            rx_usecs: w[0],
            rx_frames: w[1],
            rx_usecs_irq: w[2],
            rx_frames_irq: w[3],
            tx_usecs: w[4],
            tx_frames: w[5],
            tx_usecs_irq: w[6],
            tx_frames_irq: w[7],
            stats_block_usecs: w[8],
            adaptive_rx: w[9] != 0,
            adaptive_tx: w[10] != 0,
            pkt_rate_low: w[11],
            rx_usecs_low: w[12],
            rx_frames_low: w[13],
            tx_usecs_low: w[14],
            tx_frames_low: w[15],
            pkt_rate_high: w[16],
            rx_usecs_high: w[17],
            rx_frames_high: w[18],
            tx_usecs_high: w[19],
            tx_frames_high: w[20],
            sample_interval: w[21],
        }
    }
}

/// The coalescing parameters a driver accepts: its `supported_coalesce_params`, a set of
/// `ETHTOOL_COALESCE_*` bits (include/linux/ethtool.h). Bit `n` covers word `n` of
/// [`Coalesce`] in kernel order, so `ETHTOOL_SCOALESCE` with a non-zero value in an unsupported
/// field is `EOPNOTSUPP` (`ethtool_set_coalesce_supported`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct CoalesceParams(pub u32);

impl CoalesceParams {
    /// None.
    pub const NONE: Self = Self(0);
    /// Every field of `struct ethtool_coalesce` (bits 0–21).
    pub const ALL: Self = Self((1 << 22) - 1);
    /// `ETHTOOL_COALESCE_RX_USECS`.
    pub const RX_USECS: Self = Self(1 << 0);
    /// `ETHTOOL_COALESCE_RX_MAX_FRAMES`.
    pub const RX_MAX_FRAMES: Self = Self(1 << 1);
    /// `ETHTOOL_COALESCE_RX_USECS_IRQ`.
    pub const RX_USECS_IRQ: Self = Self(1 << 2);
    /// `ETHTOOL_COALESCE_RX_MAX_FRAMES_IRQ`.
    pub const RX_MAX_FRAMES_IRQ: Self = Self(1 << 3);
    /// `ETHTOOL_COALESCE_TX_USECS`.
    pub const TX_USECS: Self = Self(1 << 4);
    /// `ETHTOOL_COALESCE_TX_MAX_FRAMES`.
    pub const TX_MAX_FRAMES: Self = Self(1 << 5);
    /// `ETHTOOL_COALESCE_TX_USECS_IRQ`.
    pub const TX_USECS_IRQ: Self = Self(1 << 6);
    /// `ETHTOOL_COALESCE_TX_MAX_FRAMES_IRQ`.
    pub const TX_MAX_FRAMES_IRQ: Self = Self(1 << 7);
    /// `ETHTOOL_COALESCE_STATS_BLOCK_USECS`.
    pub const STATS_BLOCK_USECS: Self = Self(1 << 8);
    /// `ETHTOOL_COALESCE_USE_ADAPTIVE_RX`.
    pub const USE_ADAPTIVE_RX: Self = Self(1 << 9);
    /// `ETHTOOL_COALESCE_USE_ADAPTIVE_TX`.
    pub const USE_ADAPTIVE_TX: Self = Self(1 << 10);
    /// `ETHTOOL_COALESCE_PKT_RATE_LOW`.
    pub const PKT_RATE_LOW: Self = Self(1 << 11);
    /// `ETHTOOL_COALESCE_RX_USECS_LOW`.
    pub const RX_USECS_LOW: Self = Self(1 << 12);
    /// `ETHTOOL_COALESCE_RX_MAX_FRAMES_LOW`.
    pub const RX_MAX_FRAMES_LOW: Self = Self(1 << 13);
    /// `ETHTOOL_COALESCE_TX_USECS_LOW`.
    pub const TX_USECS_LOW: Self = Self(1 << 14);
    /// `ETHTOOL_COALESCE_TX_MAX_FRAMES_LOW`.
    pub const TX_MAX_FRAMES_LOW: Self = Self(1 << 15);
    /// `ETHTOOL_COALESCE_PKT_RATE_HIGH`.
    pub const PKT_RATE_HIGH: Self = Self(1 << 16);
    /// `ETHTOOL_COALESCE_RX_USECS_HIGH`.
    pub const RX_USECS_HIGH: Self = Self(1 << 17);
    /// `ETHTOOL_COALESCE_RX_MAX_FRAMES_HIGH`.
    pub const RX_MAX_FRAMES_HIGH: Self = Self(1 << 18);
    /// `ETHTOOL_COALESCE_TX_USECS_HIGH`.
    pub const TX_USECS_HIGH: Self = Self(1 << 19);
    /// `ETHTOOL_COALESCE_TX_MAX_FRAMES_HIGH`.
    pub const TX_MAX_FRAMES_HIGH: Self = Self(1 << 20);
    /// `ETHTOOL_COALESCE_RATE_SAMPLE_INTERVAL`.
    pub const RATE_SAMPLE_INTERVAL: Self = Self(1 << 21);
    /// `ETHTOOL_COALESCE_USECS`: `RX_USECS | TX_USECS`.
    pub const USECS: Self = Self(Self::RX_USECS.0 | Self::TX_USECS.0);
    /// `ETHTOOL_COALESCE_MAX_FRAMES`: `RX_MAX_FRAMES | TX_MAX_FRAMES`.
    pub const MAX_FRAMES: Self = Self(Self::RX_MAX_FRAMES.0 | Self::TX_MAX_FRAMES.0);
    /// `ETHTOOL_COALESCE_USE_ADAPTIVE`: `USE_ADAPTIVE_RX | USE_ADAPTIVE_TX`.
    pub const USE_ADAPTIVE: Self = Self(Self::USE_ADAPTIVE_RX.0 | Self::USE_ADAPTIVE_TX.0);
}

impl std::ops::BitOr for CoalesceParams {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

/// An n-tuple flow steering rule as the driver holds it (`ethtool -u`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowRule {
    /// The rule's slot (`fs.location`).
    pub location: u32,
    /// `fs.flow_type`: `TCP_V4_FLOW`, `UDP_V4_FLOW`, `ETHER_FLOW`, … with the `FLOW_EXT` bits.
    pub flow_type: u32,
    /// `fs.ring_cookie`: the RX queue matching packets go to, or `RX_CLS_FLOW_DISC`.
    pub ring_cookie: u64,
    /// The whole `struct ethtool_rx_flow_spec` (168 bytes) as the code under test wrote it,
    /// match values and masks included.
    pub spec: Vec<u8>,
}

/// What a [`Nic`](crate::Nic)'s driver can do and what has been set on it: the `ethtool` view
/// of the interface. Read it back with [`SimHost::ethtool`](crate::SimHost::ethtool). A `None`
/// operation is one the driver lacks, so its commands fail with `EOPNOTSUPP`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NicEthtool {
    /// `ETHTOOL_GDRVINFO` `fw_version`.
    pub firmware: String,
    /// `ETHTOOL_GDRVINFO` `erom_version`: the expansion ROM (option ROM) version.
    pub expansion_rom: String,
    /// `ETHTOOL_GDRVINFO` `regdump_len`, in bytes.
    pub register_dump_len: u32,
    /// `ETHTOOL_GDRVINFO` `eedump_len`, in bytes.
    pub eeprom_len: u32,
    /// `ETHTOOL_GDRVINFO` `n_priv_flags` and the `ETH_SS_PRIV_FLAGS` string-set count.
    pub private_flags_count: u32,
    /// The descriptor rings, with their maxima.
    pub rings: Option<Rings>,
    /// Interrupt coalescing: what the driver accepts and the current values.
    pub coalesce: Option<(CoalesceParams, Coalesce)>,
    /// The largest `*_usecs*` coalescing value the driver accepts; above it `EINVAL`.
    pub coalesce_usecs_max: u32,
    /// The largest `*_frames*` coalescing value the driver accepts; above it `EINVAL`.
    pub coalesce_frames_max: u32,
    /// Queue counts, with their maxima.
    pub channels: Option<Channels>,
    /// Flow control.
    pub pause: Option<Pause>,
    /// Energy Efficient Ethernet.
    pub eee: Option<Eee>,
    /// The `ETH_FLAG_*` features on now (`ETHTOOL_GFLAGS`).
    pub features: u32,
    /// The `ETH_FLAG_*` features the code under test may toggle (the driver's `hw_features`).
    pub hw_features: u32,
    /// The flow-rule table size, `None` without n-tuple steering.
    pub flow_slots: Option<u32>,
    /// The installed flow rules, by location.
    pub flow_rules: BTreeMap<u32, FlowRule>,
    /// Driver statistics (`ethtool -S`), in report order.
    pub stats: Vec<(String, u64)>,
    /// Whether NAPI runs in kernel threads (`/sys/class/net/<if>/threaded`).
    pub threaded_napi: bool,
    /// The transmit queues whose hardware launches frames at their `SO_TXTIME` (the driver's
    /// `ndo_setup_tc(TC_SETUP_QDISC_ETF)`), `None` for a driver without ETF offload.
    pub etf_offload: Option<Vec<u16>>,
    /// The PTP hardware clock `ETHTOOL_GET_TS_INFO` reports (`phc_index`), from
    /// [`Nic::ptp_index`](crate::Nic::ptp_index).
    pub phc_index: Option<u32>,
    /// `ETHTOOL_GET_TS_INFO`'s `so_timestamping`, `tx_types` and `rx_filters` exactly as a real
    /// driver reports them, from [`Nic::timestamping_caps`](crate::Nic::timestamping_caps);
    /// `None` reports the I210 set of `ETHTOOL_GET_TS_INFO`'s handler below.
    pub ts_info: Option<(u32, u32, u32)>,
}

/// The interface facts outside [`NicEthtool`] that the commands report or change.
pub(crate) struct Ctx<'a> {
    /// `CAP_NET_ADMIN` held.
    pub(crate) net_admin: bool,
    /// Administratively up with carrier: what `ETHTOOL_GLINK` reports.
    pub(crate) link_up: bool,
    /// Whether the NIC timestamps in hardware (`Nic::hardware_timestamping`).
    pub(crate) hw_timestamping: bool,
    /// The driver name, version and bus address of `ETHTOOL_GDRVINFO`.
    pub(crate) driver: &'a str,
    pub(crate) version: &'a str,
    pub(crate) bus_info: &'a str,
    /// The RX and TX queue counts, which a channel change resizes.
    pub(crate) queues: (&'a mut usize, &'a mut usize),
}

/// Whether `cmd` is one `__dev_ethtool` lets anyone run; every other needs `CAP_NET_ADMIN`.
fn unprivileged(cmd: u32) -> bool {
    matches!(
        cmd,
        0x01 // GSET
            | ETHTOOL_GDRVINFO
            | 0x07 // GMSGLVL
            | ETHTOOL_GLINK
            | ETHTOOL_GCOALESCE
            | ETHTOOL_GRINGPARAM
            | ETHTOOL_GPAUSEPARAM
            | 0x14 // GRXCSUM
            | 0x16 // GTXCSUM
            | 0x18 // GSG
            | ETHTOOL_GSSET_INFO
            | ETHTOOL_GSTRINGS
            | ETHTOOL_GSTATS
            | 0x4a // GPHYSTATS
            | 0x1e // GTSO
            | 0x20 // GPERMADDR
            | 0x21 // GUFO
            | 0x23 // GGSO
            | 0x2b // GGRO
            | ETHTOOL_GFLAGS
            | 0x27 // GPFLAGS
            | 0x29 // GRXFH
            | 0x2d // GRXRINGS
            | ETHTOOL_GRXCLSRLCNT
            | ETHTOOL_GRXCLSRULE
            | ETHTOOL_GRXCLSRLALL
            | 0x38 // GRXFHINDIR
            | 0x46 // GRSSH
            | 0x3a // GFEATURES
            | ETHTOOL_GCHANNELS
            | ETHTOOL_GET_TS_INFO
            | ETHTOOL_GEEE
            | 0x48 // GTUNABLE
            | 0x4e // PHY_GTUNABLE
            | 0x4c // GLINKSETTINGS
            | 0x50 // GFECPARAM
    )
}

/// Reads the `n` 32-bit words at `data`.
///
/// # Safety
/// `data` points to at least `n` words.
unsafe fn read_words<const N: usize>(data: *const u8) -> [u32; N] {
    let mut w = [0u32; N];
    for (i, v) in w.iter_mut().enumerate() {
        *v = unsafe { (data.add(4 * i) as *const u32).read_unaligned() };
    }
    w
}

/// Writes `w` at `data`.
///
/// # Safety
/// `data` points to at least `w.len()` writable words.
unsafe fn write_words(data: *mut u8, w: &[u32]) {
    for (i, v) in w.iter().enumerate() {
        unsafe { (data.add(4 * i) as *mut u32).write_unaligned(*v) };
    }
}

/// Writes `s` NUL-terminated and truncated into the `width`-byte field at `base + offset`.
///
/// # Safety
/// `base + offset .. + width` is writable.
unsafe fn write_cstr(base: *mut u8, offset: usize, width: usize, s: &str) {
    let bytes = s.as_bytes();
    let n = bytes.len().min(width - 1);
    unsafe {
        std::ptr::write_bytes(base.add(offset), 0, width);
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), base.add(offset), n);
    }
}

impl NicEthtool {
    /// The driver of a NIC that declares nothing: driver info and link only, as a minimal driver
    /// with no optional `ethtool_ops`.
    pub(crate) fn new() -> Self {
        NicEthtool {
            coalesce_usecs_max: u32::MAX,
            coalesce_frames_max: u32::MAX,
            ..Default::default()
        }
    }

    /// Runs `SIOCETHTOOL` command block `data` against this driver; `Err` is the errno.
    ///
    /// # Safety
    /// `data` points to the command's struct, as large as the kernel copies for that command.
    pub(crate) unsafe fn ioctl(&mut self, ctx: Ctx<'_>, data: *mut u8) -> Result<(), c_int> {
        let cmd = unsafe { (data as *const u32).read_unaligned() };
        if !unprivileged(cmd) && !ctx.net_admin {
            return Err(libc::EPERM);
        }
        match cmd {
            ETHTOOL_GDRVINFO => {
                self.drvinfo(&ctx, data);
                Ok(())
            }
            ETHTOOL_GET_TS_INFO => {
                self.ts_info(&ctx, data);
                Ok(())
            }
            ETHTOOL_GLINK => {
                unsafe { write_words(data, &[ETHTOOL_GLINK, u32::from(ctx.link_up)]) };
                Ok(())
            }
            ETHTOOL_GRINGPARAM => {
                let r = self.rings.ok_or(libc::EOPNOTSUPP)?;
                let w = [
                    ETHTOOL_GRINGPARAM,
                    r.rx_max,
                    r.rx_mini_max,
                    r.rx_jumbo_max,
                    r.tx_max,
                    r.rx,
                    r.rx_mini,
                    r.rx_jumbo,
                    r.tx,
                ];
                unsafe { write_words(data, &w) };
                Ok(())
            }
            ETHTOOL_SRINGPARAM => {
                let r = self.rings.as_mut().ok_or(libc::EOPNOTSUPP)?;
                let w = unsafe { read_words::<9>(data) };
                // ethtool_set_ringparam: the `*_max` fields given are ignored; each size must
                // be within the driver's maximum.
                if w[5] > r.rx_max
                    || w[6] > r.rx_mini_max
                    || w[7] > r.rx_jumbo_max
                    || w[8] > r.tx_max
                {
                    return Err(libc::EINVAL);
                }
                (r.rx, r.rx_mini, r.rx_jumbo, r.tx) = (w[5], w[6], w[7], w[8]);
                Ok(())
            }
            ETHTOOL_GCOALESCE => {
                let (_, c) = self.coalesce.ok_or(libc::EOPNOTSUPP)?;
                let mut w = vec![ETHTOOL_GCOALESCE];
                w.extend(c.words());
                unsafe { write_words(data, &w) };
                Ok(())
            }
            ETHTOOL_SCOALESCE => self.set_coalesce(data),
            ETHTOOL_GPAUSEPARAM => {
                let p = self.pause.ok_or(libc::EOPNOTSUPP)?;
                let w = [
                    ETHTOOL_GPAUSEPARAM,
                    p.autoneg.into(),
                    p.rx.into(),
                    p.tx.into(),
                ];
                unsafe { write_words(data, &w) };
                Ok(())
            }
            ETHTOOL_SPAUSEPARAM => {
                let p = self.pause.as_mut().ok_or(libc::EOPNOTSUPP)?;
                let w = unsafe { read_words::<4>(data) };
                *p = Pause {
                    autoneg: w[1] != 0,
                    rx: w[2] != 0,
                    tx: w[3] != 0,
                };
                Ok(())
            }
            ETHTOOL_GCHANNELS => {
                let c = self.channels.ok_or(libc::EOPNOTSUPP)?;
                let w = [
                    ETHTOOL_GCHANNELS,
                    c.rx_max,
                    c.tx_max,
                    c.other_max,
                    c.combined_max,
                    c.rx,
                    c.tx,
                    c.other,
                    c.combined,
                ];
                unsafe { write_words(data, &w) };
                Ok(())
            }
            ETHTOOL_SCHANNELS => self.set_channels(ctx, data),
            ETHTOOL_GEEE => {
                let e = self.eee.ok_or(libc::EOPNOTSUPP)?;
                let active = e.enabled && ctx.link_up && e.advertised & e.lp_advertised != 0;
                let w = [
                    ETHTOOL_GEEE,
                    e.supported,
                    e.advertised,
                    e.lp_advertised,
                    active.into(),
                    e.enabled.into(),
                    e.tx_lpi_enabled.into(),
                    e.tx_lpi_timer,
                    0,
                    0,
                ];
                unsafe { write_words(data, &w) };
                Ok(())
            }
            ETHTOOL_SEEE => {
                let e = self.eee.as_mut().ok_or(libc::EOPNOTSUPP)?;
                let w = unsafe { read_words::<8>(data) };
                // Drivers refuse to advertise a mode EEE cannot run at, e.g. igb_set_eee
                // (drivers/net/ethernet/intel/igb/igb_ethtool.c) with EINVAL.
                if w[2] & !e.supported != 0 {
                    return Err(libc::EINVAL);
                }
                e.advertised = w[2];
                e.enabled = w[5] != 0;
                e.tx_lpi_enabled = w[6] != 0;
                e.tx_lpi_timer = w[7];
                Ok(())
            }
            ETHTOOL_GFLAGS => {
                unsafe { write_words(data, &[ETHTOOL_GFLAGS, self.features]) };
                Ok(())
            }
            ETHTOOL_SFLAGS => {
                let flags = unsafe { (data.add(4) as *const u32).read_unaligned() };
                // __ethtool_set_flags: unknown flags EINVAL; changing a feature outside
                // hw_features is EOPNOTSUPP, or EINVAL if the change also touches allowed ones.
                if flags & !ETH_ALL_FLAGS != 0 {
                    return Err(libc::EINVAL);
                }
                let changed = (flags ^ self.features) & ETH_ALL_FLAGS;
                if changed & !self.hw_features != 0 {
                    return Err(if changed & self.hw_features != 0 {
                        libc::EINVAL
                    } else {
                        libc::EOPNOTSUPP
                    });
                }
                self.features = (self.features & !changed) | (flags & changed);
                Ok(())
            }
            ETHTOOL_GRXCLSRLCNT | ETHTOOL_GRXCLSRULE | ETHTOOL_GRXCLSRLALL => unsafe {
                self.get_rxnfc(cmd, data)
            },
            ETHTOOL_SRXCLSRLINS | ETHTOOL_SRXCLSRLDEL => unsafe { self.set_rxnfc(cmd, &ctx, data) },
            ETHTOOL_GSSET_INFO => {
                let mask = unsafe { (data.add(8) as *const u64).read_unaligned() };
                if mask == 0 {
                    return Ok(());
                }
                let mut out_mask = 0u64;
                unsafe {
                    std::ptr::write_bytes(data.add(4), 0, 12);
                    let mut offset = 16;
                    for (set, count) in [
                        (ETH_SS_STATS, self.stats.len() as u32),
                        (ETH_SS_PRIV_FLAGS, self.private_flags_count),
                    ] {
                        if mask & (1 << set) != 0 && count != 0 {
                            out_mask |= 1 << set;
                            (data.add(offset) as *mut u32).write_unaligned(count);
                            offset += 4;
                        }
                    }
                    (data.add(8) as *mut u64).write_unaligned(out_mask);
                }
                Ok(())
            }
            ETHTOOL_GSTRINGS => {
                let set = unsafe { (data.add(4) as *const u32).read_unaligned() };
                if set != ETH_SS_STATS || self.stats.is_empty() {
                    return Err(libc::EOPNOTSUPP);
                }
                unsafe {
                    (data.add(8) as *mut u32).write_unaligned(self.stats.len() as u32);
                    for (i, (name, _)) in self.stats.iter().enumerate() {
                        write_cstr(data, 12 + i * ETH_GSTRING_LEN, ETH_GSTRING_LEN, name);
                    }
                }
                Ok(())
            }
            ETHTOOL_GSTATS => {
                if self.stats.is_empty() {
                    return Err(libc::EOPNOTSUPP);
                }
                unsafe {
                    (data.add(4) as *mut u32).write_unaligned(self.stats.len() as u32);
                    for (i, (_, v)) in self.stats.iter().enumerate() {
                        (data.add(8 + 8 * i) as *mut u64).write_unaligned(*v);
                    }
                }
                Ok(())
            }
            _ => Err(libc::EOPNOTSUPP),
        }
    }

    /// `ETHTOOL_GDRVINFO`: `struct ethtool_drvinfo` is `cmd` @0, then 32-byte strings `driver`
    /// @4, `version` @36, `fw_version` @68, `bus_info` @100, `erom_version` @132, 12 reserved
    /// bytes, and `n_priv_flags` @176, `n_stats` @180, `testinfo_len` @184, `eedump_len` @188,
    /// `regdump_len` @192 (196 bytes). `ethtool_get_drvinfo` fills `n_stats` from the driver's
    /// `ETH_SS_STATS` count.
    fn drvinfo(&self, ctx: &Ctx<'_>, data: *mut u8) {
        unsafe {
            write_cstr(data, 4, 32, ctx.driver);
            write_cstr(data, 36, 32, ctx.version);
            write_cstr(data, 68, 32, &self.firmware);
            write_cstr(data, 100, 32, ctx.bus_info);
            write_cstr(data, 132, 32, &self.expansion_rom);
            std::ptr::write_bytes(data.add(164), 0, 32);
            (data.add(176) as *mut u32).write_unaligned(self.private_flags_count);
            (data.add(180) as *mut u32).write_unaligned(self.stats.len() as u32);
            (data.add(188) as *mut u32).write_unaligned(self.eeprom_len);
            (data.add(192) as *mut u32).write_unaligned(self.register_dump_len);
        }
    }

    /// `ETHTOOL_GET_TS_INFO`: `struct ethtool_ts_info` is `cmd`, `so_timestamping`,
    /// `phc_index` (-1 for none), `tx_types`, three reserved words, `rx_filters` and three more
    /// (44 bytes). `__ethtool_get_ts_info` (net/ethtool/common.c, Linux 6.12) starts from
    /// `phc_index` -1 and adds `SOF_TIMESTAMPING_RX_SOFTWARE | SOF_TIMESTAMPING_SOFTWARE` to
    /// whatever the driver reports; a hardware-timestamping NIC reports what igb_get_ts_info
    /// does for an I210 (drivers/net/ethernet/intel/igb/igb_ethtool.c): software TX stamps,
    /// hardware TX/RX/raw stamps, `HWTSTAMP_TX_OFF`/`ON` and `HWTSTAMP_FILTER_NONE`/`ALL`. The
    /// `SOF_TIMESTAMPING_*`, `HWTSTAMP_*` bits are include/uapi/linux/net_tstamp.h.
    fn ts_info(&self, ctx: &Ctx<'_>, data: *mut u8) {
        let (stamping, tx_types, rx_filters) = self.timestamping(ctx.hw_timestamping);
        let phc = self.phc_index.map_or(-1, |i| i as i32) as u32;
        let w = [
            ETHTOOL_GET_TS_INFO,
            stamping,
            phc,
            tx_types,
            0,
            0,
            0,
            rx_filters,
            0,
            0,
            0,
        ];
        unsafe { write_words(data, &w) };
    }

    /// `ETHTOOL_GET_TS_INFO`'s `(so_timestamping, tx_types, rx_filters)` for a NIC that
    /// timestamps in hardware when `hw`: the profile's, else the I210's set described at
    /// [`ts_info`](Self::ts_info), else software stamping alone.
    pub(crate) fn timestamping(&self, hw: bool) -> (u32, u32, u32) {
        const TX_HARDWARE: u32 = 1 << 0;
        const TX_SOFTWARE: u32 = 1 << 1;
        const RX_HARDWARE: u32 = 1 << 2;
        const RX_SOFTWARE: u32 = 1 << 3;
        const SOFTWARE: u32 = 1 << 4;
        const RAW_HARDWARE: u32 = 1 << 6;
        match self.ts_info {
            Some(caps) => caps,
            None if hw => (
                TX_SOFTWARE | TX_HARDWARE | RX_HARDWARE | RAW_HARDWARE | RX_SOFTWARE | SOFTWARE,
                0b11,
                0b11,
            ),
            None => (RX_SOFTWARE | SOFTWARE, 0, 0),
        }
    }

    /// `ETHTOOL_SCOALESCE`: `ethtool_set_coalesce` refuses a non-zero value in a field the
    /// driver does not support (`EOPNOTSUPP`), then the driver range-checks; the sim's driver
    /// refuses a `*usecs*` value above [`coalesce_usecs_max`](Self::coalesce_usecs_max) or a
    /// `*frames*` value above [`coalesce_frames_max`](Self::coalesce_frames_max) with `EINVAL`
    /// (as igb_set_coalesce does above `IGB_MAX_ITR_USECS`, drivers/net/ethernet/intel/igb/
    /// igb_ethtool.c).
    fn set_coalesce(&mut self, data: *mut u8) -> Result<(), c_int> {
        let usecs_max = self.coalesce_usecs_max;
        let frames_max = self.coalesce_frames_max;
        let (supported, current) = self.coalesce.as_mut().ok_or(libc::EOPNOTSUPP)?;
        let w = unsafe { read_words::<23>(data) };
        let mut values = [0u32; 22];
        values.copy_from_slice(&w[1..]);
        let nonzero = values
            .iter()
            .enumerate()
            .filter(|&(_, &v)| v != 0)
            .fold(0u32, |m, (i, _)| m | 1 << i);
        if supported.0 & nonzero != nonzero {
            return Err(libc::EOPNOTSUPP);
        }
        const USECS: [usize; 9] = [0, 2, 4, 6, 8, 12, 14, 17, 19];
        const FRAMES: [usize; 8] = [1, 3, 5, 7, 13, 15, 18, 20];
        if USECS.iter().any(|&i| values[i] > usecs_max)
            || FRAMES.iter().any(|&i| values[i] > frames_max)
        {
            return Err(libc::EINVAL);
        }
        *current = Coalesce::from_words(values);
        Ok(())
    }

    /// `ETHTOOL_SCHANNELS` (`ethtool_set_channels`): no change succeeds at once; a count above
    /// its maximum, or no RX or no TX queue at all, is `EINVAL`; so is shrinking below a queue a
    /// flow rule steers to (`ethtool_check_max_channel` in net/ethtool/common.c). The RX and TX
    /// queue counts follow (`combined + rx`, `combined + tx`).
    fn set_channels(&mut self, ctx: Ctx<'_>, data: *mut u8) -> Result<(), c_int> {
        let max_ring = self.max_rule_ring();
        let c = self.channels.as_mut().ok_or(libc::EOPNOTSUPP)?;
        let w = unsafe { read_words::<9>(data) };
        let (rx, tx, other, combined) = (w[5], w[6], w[7], w[8]);
        if (rx, tx, combined, other) == (c.rx, c.tx, c.combined, c.other) {
            return Ok(());
        }
        if rx > c.rx_max || tx > c.tx_max || combined > c.combined_max || other > c.other_max {
            return Err(libc::EINVAL);
        }
        if combined == 0 && (rx == 0 || tx == 0) {
            return Err(libc::EINVAL);
        }
        if let Some(max_ring) = max_ring
            && u64::from(combined + rx) <= max_ring
        {
            return Err(libc::EINVAL);
        }
        (c.rx, c.tx, c.other, c.combined) = (rx, tx, other, combined);
        *ctx.queues.0 = (combined + rx) as usize;
        *ctx.queues.1 = (combined + tx) as usize;
        Ok(())
    }

    /// The highest RX queue a flow rule steers to, as `ethtool_get_max_rxnfc_channel` computes
    /// it (drop, wake, RSS-context and VF rules excluded), or `None` with no rules.
    fn max_rule_ring(&self) -> Option<u64> {
        if self.flow_rules.is_empty() {
            return None;
        }
        Some(
            self.flow_rules
                .values()
                .filter(|r| {
                    r.ring_cookie != RX_CLS_FLOW_DISC
                        && r.ring_cookie != RX_CLS_FLOW_WAKE
                        && r.flow_type & FLOW_RSS == 0
                        && r.ring_cookie & ETHTOOL_RX_FLOW_SPEC_RING_VF == 0
                })
                .map(|r| r.ring_cookie)
                .max()
                .unwrap_or(0),
        )
    }

    /// The flow-rule reads (`ethtool_get_rxnfc`), answered as igb_get_rxnfc does
    /// (drivers/net/ethernet/intel/igb/igb_ethtool.c): `GRXCLSRLCNT` reports the rule count
    /// and the table size in `data`; `GRXCLSRULE` an installed rule (`EINVAL` for an empty
    /// slot); `GRXCLSRLALL` the locations in ascending order into `rule_locs`, `EMSGSIZE` if the
    /// caller's `rule_cnt` is too small.
    ///
    /// # Safety
    /// `data` points to a `struct ethtool_rxnfc`, followed for `GRXCLSRLALL` by `rule_cnt`
    /// words.
    unsafe fn get_rxnfc(&self, cmd: u32, data: *mut u8) -> Result<(), c_int> {
        let slots = self.flow_slots.ok_or(libc::EOPNOTSUPP)?;
        match cmd {
            ETHTOOL_GRXCLSRLCNT => unsafe {
                (data.add(8) as *mut u64).write_unaligned(u64::from(slots));
                (data.add(RXNFC_RULE_CNT) as *mut u32)
                    .write_unaligned(self.flow_rules.len() as u32);
            },
            ETHTOOL_GRXCLSRULE => {
                let location = unsafe { (data.add(RXNFC_FS + 160) as *const u32).read_unaligned() };
                let rule = self.flow_rules.get(&location).ok_or(libc::EINVAL)?;
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        rule.spec.as_ptr(),
                        data.add(RXNFC_FS),
                        FLOW_SPEC_LEN,
                    )
                };
            }
            _ => {
                let room =
                    unsafe { (data.add(RXNFC_RULE_CNT) as *const u32).read_unaligned() } as usize;
                if self.flow_rules.len() > room {
                    return Err(libc::EMSGSIZE);
                }
                unsafe {
                    (data.add(8) as *mut u64).write_unaligned(u64::from(slots));
                    for (i, &loc) in self.flow_rules.keys().enumerate() {
                        (data.add(RXNFC_RULE_LOCS + 4 * i) as *mut u32).write_unaligned(loc);
                    }
                    (data.add(RXNFC_RULE_CNT) as *mut u32)
                        .write_unaligned(self.flow_rules.len() as u32);
                }
            }
        }
        Ok(())
    }

    /// The flow-rule changes (`ethtool_set_rxnfc`), as igb does them
    /// (drivers/net/ethernet/intel/igb/igb_ethtool.c `igb_add_ethtool_nfc_entry`,
    /// `igb_del_ethtool_nfc_entry`): inserting needs the n-tuple capability (the hardware
    /// feature, not the flag being on: `EOPNOTSUPP`), a location inside the table and a queue
    /// the interface has (`EINVAL`), and replaces a rule already at that location; deleting an
    /// empty slot is `EINVAL`.
    ///
    /// # Safety
    /// `data` points to a `struct ethtool_rxnfc`.
    unsafe fn set_rxnfc(&mut self, cmd: u32, ctx: &Ctx<'_>, data: *mut u8) -> Result<(), c_int> {
        let slots = self.flow_slots.ok_or(libc::EOPNOTSUPP)?;
        let fs = unsafe { data.add(RXNFC_FS) };
        let location = unsafe { (fs.add(160) as *const u32).read_unaligned() };
        if cmd == ETHTOOL_SRXCLSRLDEL {
            return self
                .flow_rules
                .remove(&location)
                .map(drop)
                .ok_or(libc::EINVAL);
        }
        if location >= slots {
            return Err(libc::EINVAL);
        }
        let ring_cookie = unsafe { (fs.add(152) as *const u64).read_unaligned() };
        if ring_cookie >= *ctx.queues.0 as u64 {
            return Err(libc::EINVAL);
        }
        let flow_type = unsafe { (fs as *const u32).read_unaligned() };
        let mut spec = vec![0u8; FLOW_SPEC_LEN];
        unsafe { std::ptr::copy_nonoverlapping(fs, spec.as_mut_ptr(), FLOW_SPEC_LEN) };
        self.flow_rules.insert(
            location,
            FlowRule {
                location,
                flow_type,
                ring_cookie,
                spec,
            },
        );
        Ok(())
    }
}
