//! What the machine running the `hw_*` truth tests has, and the skip those tests take when it
//! lacks something. Tests requiring devices, peers or hardware mutation are ignored;
//! `scripts/test-hardware.sh` (or `.ps1`) runs them with `--include-ignored hw_`.
//! A test that then finds its hardware missing returns early through [`require!`] or [`need!`],
//! printing `skipped: needs X (set SNARE_HW_...)`, and appends the same line to the file
//! `SNARE_HW_REPORT` names, which the runner folds into its report.
//!
//! Discovery reads the environment first and falls back to looking:
//!
//! | Variable | Meaning | Fallback |
//! |---|---|---|
//! | `SNARE_HW_IFACE` | the NIC under test (Linux name) | the first `/sys/class/net/*` with a `device` link that is not wireless, carrier up first |
//! | `SNARE_HW_PTP` | its PTP hardware clock | `/dev/ptp<phc_index>` from the NIC's `ETHTOOL_GET_TS_INFO` |
//! | `SNARE_HW_PEER` | `ip[:port]` of a second machine running the reflector | none |
//! | `SNARE_HW_MUTATE` | `1` lets tests change NIC and qdisc settings (restored after) | off |
//! | `SNARE_HW_WIN_ADAPTER` | the Windows adapter's alias | the first Ethernet adapter that is up |
//! | `SNARE_HW_NPCAP` | `1` when npcap is installed | `%SystemRoot%\System32\Npcap\wpcap.dll` exists |
//! | `SNARE_HW_REPORT` | file the skips and notes are appended to | none |

#![allow(dead_code)]

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard, OnceLock};

/// The UDP port the peer's reflector listens on when `SNARE_HW_PEER` names none.
pub const DEFAULT_PEER_PORT: u16 = 47_000;

/// What discovery found. Read it with [`hw`].
#[derive(Debug, Clone, Default)]
pub struct Hw {
    /// The NIC under test.
    pub iface: Option<String>,
    /// Where [`iface`](Self::iface) came from: `"SNARE_HW_IFACE"` or `"auto"`.
    pub iface_from: &'static str,
    /// Its driver (`ETHTOOL_GDRVINFO`).
    pub driver: Option<String>,
    /// The PTP clock device.
    pub ptp: Option<PathBuf>,
    /// The peer's reflector.
    pub peer: Option<SocketAddr>,
    /// `SNARE_HW_MUTATE=1`.
    pub mutate: bool,
    /// A PREEMPT_RT kernel (`uname -v` or `/sys/kernel/realtime`).
    pub preempt_rt: bool,
    /// `uname -r` and `uname -v`.
    pub kernel: String,
    /// Effective uid 0.
    pub root: bool,
    /// The effective capability set (`CapEff:` of `/proc/self/status`).
    pub caps: u64,
    /// The Windows adapter under test (its alias).
    pub win_adapter: Option<String>,
    /// npcap is installed.
    pub npcap: bool,
}

impl Hw {
    /// Whether capability `cap` (include/uapi/linux/capability.h numbering) is effective.
    pub fn cap(&self, cap: u32) -> bool {
        cap < 64 && self.caps & (1 << cap) != 0
    }

    /// One line per fact, for the runner's header and a failing test's message.
    pub fn summary(&self) -> String {
        format!(
            "iface={:?} ({}) driver={:?} ptp={:?} peer={:?} mutate={} preempt_rt={} root={} caps={:#x} kernel={:?} win_adapter={:?} npcap={}",
            self.iface,
            self.iface_from,
            self.driver,
            self.ptp,
            self.peer,
            self.mutate,
            self.preempt_rt,
            self.root,
            self.caps,
            self.kernel,
            self.win_adapter,
            self.npcap
        )
    }
}

/// `CAP_NET_ADMIN`.
pub const CAP_NET_ADMIN: u32 = 12;
/// `CAP_NET_RAW`.
pub const CAP_NET_RAW: u32 = 13;
/// `CAP_IPC_LOCK`.
pub const CAP_IPC_LOCK: u32 = 14;
/// `CAP_SYS_NICE`.
pub const CAP_SYS_NICE: u32 = 23;

/// The machine's hardware, discovered once per test binary.
pub fn hw() -> &'static Hw {
    static HW: OnceLock<Hw> = OnceLock::new();
    HW.get_or_init(|| snare::real(discover))
}

/// Serialises the tests of one binary that change the NIC, so a restore never races another
/// test's reads.
pub fn nic_lock() -> MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

fn test_name() -> String {
    std::thread::current().name().unwrap_or("?").to_string()
}

fn report(kind: &str, text: &str) {
    let Ok(path) = std::env::var("SNARE_HW_REPORT") else {
        return;
    };
    let line = format!(
        "{kind}\t{}\t{}\n",
        test_name(),
        text.replace(['\n', '\t'], " ")
    );
    snare::real(|| {
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
        {
            let _ = f.write_all(line.as_bytes());
        }
    });
}

/// Records that the running test is skipped and why. Use [`require!`] or [`need!`].
pub fn skip(reason: &str) {
    eprintln!("skipped: {reason}");
    report("SKIP", reason);
}

/// Records something the test saw but does not assert: a difference the sim does not model.
pub fn note(text: &str) {
    eprintln!("note: {text}");
    report("NOTE", text);
}

/// Returns from the test, recorded as skipped, unless `cond` holds.
#[allow(unused_macros)]
macro_rules! require {
    ($cond:expr, $($why:tt)+) => {
        if !$cond {
            $crate::hw::skip(&format!($($why)+));
            return;
        }
    };
}
#[allow(unused_imports)]
pub(crate) use require;

/// The value of an `Option`, or a return from the test recorded as skipped.
#[allow(unused_macros)]
macro_rules! need {
    ($opt:expr, $($why:tt)+) => {
        match $opt {
            Some(v) => v,
            None => {
                $crate::hw::skip(&format!($($why)+));
                return;
            }
        }
    };
}
#[allow(unused_imports)]
pub(crate) use need;

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

fn flag(name: &str) -> bool {
    env(name).is_some_and(|v| v.trim() == "1")
}

/// `ip`, `ip:port` or `[v6]:port`.
fn parse_peer(s: &str) -> Option<SocketAddr> {
    let s = s.trim();
    s.parse::<SocketAddr>().ok().or_else(|| {
        s.parse::<IpAddr>()
            .ok()
            .map(|ip| SocketAddr::new(ip, DEFAULT_PEER_PORT))
    })
}

fn discover() -> Hw {
    let mut hw = Hw {
        peer: env("SNARE_HW_PEER").and_then(|p| parse_peer(&p)),
        mutate: flag("SNARE_HW_MUTATE"),
        ..Hw::default()
    };
    os::discover(&mut hw);
    hw
}

#[cfg(target_os = "linux")]
mod os {
    use super::*;

    pub fn discover(hw: &mut Hw) {
        let mut u: libc::utsname = unsafe { std::mem::zeroed() };
        unsafe { libc::uname(&mut u) };
        let field = |f: &[libc::c_char]| {
            let bytes: Vec<u8> = f
                .iter()
                .take_while(|&&c| c != 0)
                .map(|&c| c.to_ne_bytes()[0])
                .collect();
            String::from_utf8_lossy(&bytes).into_owned()
        };
        let (release, version) = (field(&u.release), field(&u.version));
        hw.preempt_rt = version.contains("PREEMPT_RT")
            || std::fs::read_to_string("/sys/kernel/realtime").is_ok_and(|s| s.trim() == "1");
        hw.kernel = format!("{release} {version}");
        hw.root = unsafe { libc::geteuid() } == 0;
        hw.caps = std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|s| {
                s.lines()
                    .find_map(|l| l.strip_prefix("CapEff:"))
                    .and_then(|v| u64::from_str_radix(v.trim(), 16).ok())
            })
            .unwrap_or(0);
        match env("SNARE_HW_IFACE") {
            Some(name) => {
                hw.iface = Some(name);
                hw.iface_from = "SNARE_HW_IFACE";
            }
            None => {
                hw.iface = auto_iface();
                hw.iface_from = "auto";
            }
        }
        let iface = hw.iface.clone();
        hw.driver = iface
            .as_deref()
            .and_then(|i| super::linux::drvinfo(i).ok())
            .map(|d| d.driver);
        hw.ptp = env("SNARE_HW_PTP").map(PathBuf::from).or_else(|| {
            let phc = iface
                .as_deref()
                .and_then(|i| super::linux::ts_info(i).ok())?
                .phc_index;
            let path = PathBuf::from(format!("/dev/ptp{}", u32::try_from(phc).ok()?));
            path.exists().then_some(path)
        });
    }

    /// Physical, wired interfaces, those with carrier first.
    fn auto_iface() -> Option<String> {
        let mut found: Vec<(bool, String)> = std::fs::read_dir("/sys/class/net")
            .ok()?
            .flatten()
            .filter_map(|e| {
                let dir = e.path();
                let wireless = dir.join("wireless").exists() || dir.join("phy80211").exists();
                if !dir.join("device").exists() || wireless {
                    return None;
                }
                let up =
                    std::fs::read_to_string(dir.join("operstate")).is_ok_and(|s| s.trim() == "up");
                Some((!up, e.file_name().to_string_lossy().into_owned()))
            })
            .collect();
        found.sort();
        found.into_iter().next().map(|(_, name)| name)
    }
}

#[cfg(windows)]
mod os {
    use super::*;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST,
        GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;

    /// `IF_TYPE_ETHERNET_CSMACD` (ipifcons.h).
    const IF_TYPE_ETHERNET_CSMACD: u32 = 6;

    pub fn discover(hw: &mut Hw) {
        hw.win_adapter = env("SNARE_HW_WIN_ADAPTER").or_else(auto_adapter);
        hw.iface_from = if env("SNARE_HW_WIN_ADAPTER").is_some() {
            "SNARE_HW_WIN_ADAPTER"
        } else {
            "auto"
        };
        let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        hw.npcap = flag("SNARE_HW_NPCAP")
            || std::path::Path::new(&system_root)
                .join(r"System32\Npcap\wpcap.dll")
                .exists();
    }

    /// The first Ethernet adapter that is up and has a MAC address, by its alias.
    fn auto_adapter() -> Option<String> {
        let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
        let mut len = 0u32;
        unsafe { GetAdaptersAddresses(0, flags, std::ptr::null(), std::ptr::null_mut(), &mut len) };
        let mut buf = vec![0u64; (len as usize).div_ceil(8) + 1];
        let first = buf.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        if unsafe { GetAdaptersAddresses(0, flags, std::ptr::null(), first, &mut len) } != 0 {
            return None;
        }
        let mut at = first as *const IP_ADAPTER_ADDRESSES_LH;
        while !at.is_null() {
            let a = unsafe { &*at };
            if a.IfType == IF_TYPE_ETHERNET_CSMACD
                && a.OperStatus == IfOperStatusUp
                && a.PhysicalAddressLength == 6
            {
                return Some(wide_str(a.FriendlyName));
            }
            at = a.Next;
        }
        None
    }

    fn wide_str(p: *const u16) -> String {
        if p.is_null() {
            return String::new();
        }
        let len = (0..).take_while(|&i| unsafe { *p.add(i) } != 0).count();
        String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(p, len) })
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
mod os {
    use super::*;

    pub fn discover(hw: &mut Hw) {
        hw.root = unsafe { libc::geteuid() } == 0;
    }
}

/// The NIC as `ethtool` and the kernel's interface tables see it: one `SIOCETHTOOL` per command
/// (include/uapi/linux/ethtool.h), each made the same way on the real kernel (under
/// `snare::real`) and in a sim, so the two answers compare field by field; and [`nic_profile`],
/// which turns the real answers into a [`snare::Nic`].
#[cfg(target_os = "linux")]
pub mod linux {
    use std::net::IpAddr;

    use snare::{Channels, Coalesce, CoalesceParams, Eee, Nic, Pause, Rings};

    pub const SIOCETHTOOL: u64 = 0x8946;
    pub const ETHTOOL_GDRVINFO: u32 = 0x03;
    pub const ETHTOOL_GLINK: u32 = 0x0a;
    pub const ETHTOOL_GCOALESCE: u32 = 0x0e;
    pub const ETHTOOL_SCOALESCE: u32 = 0x0f;
    pub const ETHTOOL_GRINGPARAM: u32 = 0x10;
    pub const ETHTOOL_SRINGPARAM: u32 = 0x11;
    pub const ETHTOOL_GPAUSEPARAM: u32 = 0x12;
    pub const ETHTOOL_SPAUSEPARAM: u32 = 0x13;
    pub const ETHTOOL_GSTRINGS: u32 = 0x1b;
    pub const ETHTOOL_GSTATS: u32 = 0x1d;
    pub const ETHTOOL_GFLAGS: u32 = 0x25;
    pub const ETHTOOL_GSSET_INFO: u32 = 0x37;
    pub const ETHTOOL_GCHANNELS: u32 = 0x3c;
    pub const ETHTOOL_SCHANNELS: u32 = 0x3d;
    pub const ETHTOOL_GET_TS_INFO: u32 = 0x41;
    pub const ETHTOOL_GEEE: u32 = 0x44;
    pub const ETHTOOL_SEEE: u32 = 0x45;
    /// `ETH_SS_STATS` (`enum ethtool_stringset`).
    pub const ETH_SS_STATS: u32 = 1;
    /// `SOF_TIMESTAMPING_RAW_HARDWARE` (include/uapi/linux/net_tstamp.h).
    pub const SOF_TIMESTAMPING_RAW_HARDWARE: u32 = 1 << 6;

    pub fn errno() -> i32 {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
    }

    /// `struct ifreq` with `ifr_data` (include/uapi/linux/if.h): 16 name bytes, then the union.
    #[repr(C)]
    pub struct IfreqData {
        pub name: [u8; 16],
        pub data: *mut libc::c_void,
        pub pad: [u8; 16],
    }

    impl IfreqData {
        pub fn new(iface: &str, data: *mut libc::c_void) -> Self {
            let mut name = [0u8; 16];
            let n = iface.len().min(15);
            name[..n].copy_from_slice(&iface.as_bytes()[..n]);
            IfreqData {
                name,
                data,
                pad: [0; 16],
            }
        }
    }

    /// One `SIOCETHTOOL` on `iface` with the command block `data` (its first word the command).
    pub fn ethtool(iface: &str, data: &mut [u8]) -> Result<(), i32> {
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
        if fd < 0 {
            return Err(errno());
        }
        let mut req = IfreqData::new(iface, data.as_mut_ptr().cast());
        let rc = unsafe { libc::ioctl(fd, SIOCETHTOOL as _, &mut req) };
        let e = errno();
        unsafe { libc::close(fd) };
        if rc == 0 { Ok(()) } else { Err(e) }
    }

    /// A command whose struct is `N` words, `cmd` first; the reply's words after `cmd`.
    pub fn get_words<const N: usize>(iface: &str, cmd: u32) -> Result<[u32; N], i32> {
        let mut buf = [0u8; 512];
        buf[..4].copy_from_slice(&cmd.to_ne_bytes());
        ethtool(iface, &mut buf)?;
        let mut w = [0u32; N];
        for (i, v) in w.iter_mut().enumerate() {
            *v = word(&buf, 4 + 4 * i);
        }
        Ok(w)
    }

    /// A set command: `cmd` followed by `words`.
    pub fn set_words(iface: &str, cmd: u32, words: &[u32]) -> Result<(), i32> {
        let mut buf = [0u8; 512];
        buf[..4].copy_from_slice(&cmd.to_ne_bytes());
        for (i, v) in words.iter().enumerate() {
            buf[4 + 4 * i..8 + 4 * i].copy_from_slice(&v.to_ne_bytes());
        }
        ethtool(iface, &mut buf)
    }

    pub fn word(b: &[u8], at: usize) -> u32 {
        u32::from_ne_bytes(b[at..at + 4].try_into().unwrap())
    }

    fn cstr(b: &[u8]) -> String {
        let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
        String::from_utf8_lossy(&b[..end]).into_owned()
    }

    /// `struct ethtool_drvinfo`.
    #[derive(Debug, Clone, PartialEq, Eq, Default)]
    pub struct DrvInfo {
        pub driver: String,
        pub version: String,
        pub fw_version: String,
        pub bus_info: String,
        pub erom_version: String,
        pub n_priv_flags: u32,
        pub n_stats: u32,
        pub testinfo_len: u32,
        pub eedump_len: u32,
        pub regdump_len: u32,
    }

    /// `ETHTOOL_GDRVINFO`: strings of 32 bytes at 4, 36, 68, 100 and 132, the counts from 176.
    pub fn drvinfo(iface: &str) -> Result<DrvInfo, i32> {
        let mut buf = [0u8; 512];
        buf[..4].copy_from_slice(&ETHTOOL_GDRVINFO.to_ne_bytes());
        ethtool(iface, &mut buf)?;
        Ok(DrvInfo {
            driver: cstr(&buf[4..36]),
            version: cstr(&buf[36..68]),
            fw_version: cstr(&buf[68..100]),
            bus_info: cstr(&buf[100..132]),
            erom_version: cstr(&buf[132..164]),
            n_priv_flags: word(&buf, 176),
            n_stats: word(&buf, 180),
            testinfo_len: word(&buf, 184),
            eedump_len: word(&buf, 188),
            regdump_len: word(&buf, 192),
        })
    }

    /// `struct ethtool_ts_info`: the words that are not reserved.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct TsInfo {
        pub so_timestamping: u32,
        pub phc_index: i32,
        pub tx_types: u32,
        pub rx_filters: u32,
    }

    /// `SIOCGHWTSTAMP` (include/uapi/linux/sockios.h): the device's `struct hwtstamp_config`
    /// `(flags, tx_type, rx_filter)`, or the driver's errno.
    pub fn hwtstamp_config(iface: &str) -> Result<[i32; 3], i32> {
        const SIOCGHWTSTAMP: u64 = 0x89b1;
        let mut cfg = [0i32; 3];
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
        if fd < 0 {
            return Err(errno());
        }
        let mut req = IfreqData::new(iface, cfg.as_mut_ptr().cast());
        let rc = unsafe { libc::ioctl(fd, SIOCGHWTSTAMP as _, &mut req) };
        let e = errno();
        unsafe { libc::close(fd) };
        if rc == 0 { Ok(cfg) } else { Err(e) }
    }

    pub fn ts_info(iface: &str) -> Result<TsInfo, i32> {
        let w = get_words::<10>(iface, ETHTOOL_GET_TS_INFO)?;
        Ok(TsInfo {
            so_timestamping: w[0],
            phc_index: w[1] as i32,
            tx_types: w[2],
            rx_filters: w[6],
        })
    }

    /// `ETHTOOL_GSSET_INFO` for `ETH_SS_STATS`: `struct ethtool_sset_info` is `cmd`, a reserved
    /// word, the 64-bit `sset_mask` at 8 and the counts from 16. A driver without the set clears
    /// its bit, read here as no statistics.
    pub fn stats_count(iface: &str) -> Result<Option<u32>, i32> {
        let mut buf = [0u8; 64];
        buf[..4].copy_from_slice(&ETHTOOL_GSSET_INFO.to_ne_bytes());
        buf[8..16].copy_from_slice(&(1u64 << ETH_SS_STATS).to_ne_bytes());
        ethtool(iface, &mut buf)?;
        let mask = u64::from_ne_bytes(buf[8..16].try_into().unwrap());
        Ok((mask & 1 << ETH_SS_STATS != 0).then(|| word(&buf, 16)))
    }

    /// `ETHTOOL_GSTRINGS` for `ETH_SS_STATS`: `struct ethtool_gstrings` is `cmd`, `string_set`,
    /// `len`, then `len` names of `ETH_GSTRING_LEN` (32) bytes.
    pub fn stat_names(iface: &str, count: u32) -> Result<Vec<String>, i32> {
        let mut buf = vec![0u8; 12 + 32 * count as usize];
        buf[..4].copy_from_slice(&ETHTOOL_GSTRINGS.to_ne_bytes());
        buf[4..8].copy_from_slice(&ETH_SS_STATS.to_ne_bytes());
        buf[8..12].copy_from_slice(&count.to_ne_bytes());
        ethtool(iface, &mut buf)?;
        let n = word(&buf, 8).min(count) as usize;
        Ok((0..n)
            .map(|i| cstr(&buf[12 + 32 * i..44 + 32 * i]))
            .collect())
    }

    /// `ETHTOOL_GSTATS`: `struct ethtool_stats` is `cmd`, `n_stats`, then the 64-bit values.
    pub fn stat_values(iface: &str, count: u32) -> Result<Vec<u64>, i32> {
        let mut buf = vec![0u8; 8 + 8 * count as usize];
        buf[..4].copy_from_slice(&ETHTOOL_GSTATS.to_ne_bytes());
        buf[4..8].copy_from_slice(&count.to_ne_bytes());
        ethtool(iface, &mut buf)?;
        let n = word(&buf, 4).min(count) as usize;
        Ok((0..n)
            .map(|i| u64::from_ne_bytes(buf[8 + 8 * i..16 + 8 * i].try_into().unwrap()))
            .collect())
    }

    /// Every read-only answer `ethtool` gives for an interface, each as its words after `cmd` or
    /// the errno. Statistics values move, so only their names are kept.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct EthtoolView {
        pub drvinfo: Result<DrvInfo, i32>,
        pub link: Result<[u32; 1], i32>,
        pub rings: Result<[u32; 8], i32>,
        pub coalesce: Result<[u32; 22], i32>,
        pub channels: Result<[u32; 8], i32>,
        pub pause: Result<[u32; 3], i32>,
        pub eee: Result<[u32; 7], i32>,
        pub flags: Result<[u32; 1], i32>,
        pub ts_info: Result<TsInfo, i32>,
        pub stats_count: Result<Option<u32>, i32>,
        pub stat_names: Result<Vec<String>, i32>,
    }

    pub fn view(iface: &str) -> EthtoolView {
        let stats_count = stats_count(iface);
        let stat_names = match stats_count {
            Ok(Some(n)) => stat_names(iface, n),
            Ok(None) => Ok(Vec::new()),
            Err(e) => Err(e),
        };
        EthtoolView {
            drvinfo: drvinfo(iface),
            link: get_words(iface, ETHTOOL_GLINK),
            rings: get_words(iface, ETHTOOL_GRINGPARAM),
            coalesce: get_words(iface, ETHTOOL_GCOALESCE),
            channels: get_words(iface, ETHTOOL_GCHANNELS),
            pause: get_words(iface, ETHTOOL_GPAUSEPARAM),
            eee: get_words(iface, ETHTOOL_GEEE),
            flags: get_words(iface, ETHTOOL_GFLAGS),
            ts_info: ts_info(iface),
            stats_count,
            stat_names,
        }
    }

    /// The interface's `ifindex`, from sysfs.
    pub fn ifindex(iface: &str) -> Option<u32> {
        sysfs(iface, "ifindex")?.parse().ok()
    }

    /// `/sys/class/net/<iface>/<file>`, trimmed.
    pub fn sysfs(iface: &str, file: &str) -> Option<String> {
        std::fs::read_to_string(format!("/sys/class/net/{iface}/{file}"))
            .ok()
            .map(|s| s.trim().to_string())
    }

    fn count_dir(iface: &str, prefix: &str) -> usize {
        std::fs::read_dir(format!("/sys/class/net/{iface}/queues"))
            .map(|d| {
                d.flatten()
                    .filter(|e| e.file_name().to_string_lossy().starts_with(prefix))
                    .count()
            })
            .unwrap_or(1)
            .max(1)
    }

    /// The interface's addresses with their prefix lengths (`getifaddrs`).
    pub fn addresses(iface: &str) -> Vec<(IpAddr, u8)> {
        let mut out = Vec::new();
        let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
        if unsafe { libc::getifaddrs(&mut head) } != 0 {
            return out;
        }
        let mut at = head;
        while !at.is_null() {
            let a = unsafe { &*at };
            let name = unsafe { std::ffi::CStr::from_ptr(a.ifa_name) }.to_string_lossy();
            if name == iface
                && !a.ifa_addr.is_null()
                && !a.ifa_netmask.is_null()
                && let (Some(ip), Some(mask)) =
                    unsafe { (sockaddr_ip(a.ifa_addr), sockaddr_ip(a.ifa_netmask)) }
            {
                let prefix = match mask {
                    IpAddr::V4(m) => u32::from(m).count_ones(),
                    IpAddr::V6(m) => u128::from(m).count_ones(),
                };
                out.push((ip, prefix as u8));
            }
            at = a.ifa_next;
        }
        unsafe { libc::freeifaddrs(head) };
        out
    }

    unsafe fn sockaddr_ip(sa: *const libc::sockaddr) -> Option<IpAddr> {
        match unsafe { (*sa).sa_family } as i32 {
            libc::AF_INET => {
                let sin = unsafe { &*(sa as *const libc::sockaddr_in) };
                Some(IpAddr::from(
                    u32::from_be(sin.sin_addr.s_addr).to_be_bytes(),
                ))
            }
            libc::AF_INET6 => {
                let sin6 = unsafe { &*(sa as *const libc::sockaddr_in6) };
                Some(IpAddr::from(sin6.sin6_addr.s6_addr))
            }
            _ => None,
        }
    }

    /// The coalescing fields the driver supports, from the ethtool netlink `COALESCE_GET` reply
    /// (net/ethtool/coalesce.c `coalesce_fill_reply` puts an attribute when the driver's
    /// `supported_coalesce_params` has its bit or its value is non-zero; attribute
    /// `ETHTOOL_A_COALESCE_RX_USECS + n` is `ETHTOOL_COALESCE_*` bit `n`,
    /// include/uapi/linux/ethtool_netlink.h). `None` when the kernel has no ethtool netlink
    /// (before Linux 5.6) or the driver no coalescing.
    pub fn coalesce_supported(iface: &str) -> Option<u32> {
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_GENERIC,
            )
        };
        if fd < 0 {
            return None;
        }
        let result = (|| {
            let family = genl_family(fd, "ethtool")?;
            let mut header = Vec::new();
            put_attr(&mut header, 2, format!("{iface}\0").as_bytes());
            let mut attrs = Vec::new();
            put_attr(&mut attrs, 1 | NLA_F_NESTED, &header);
            let reply = genl_request(fd, family, ETHTOOL_MSG_COALESCE_GET, &attrs)?;
            let mut mask = 0u32;
            for (ty, _) in attrs_of(&reply) {
                let ty = ty & !NLA_F_NESTED;
                if (2..24).contains(&ty) {
                    mask |= 1 << (ty - 2);
                }
            }
            Some(mask)
        })();
        unsafe { libc::close(fd) };
        result
    }

    const NLA_F_NESTED: u16 = 1 << 15;
    const GENL_ID_CTRL: u16 = 0x10;
    const CTRL_CMD_GETFAMILY: u8 = 3;
    const CTRL_ATTR_FAMILY_ID: u16 = 1;
    const CTRL_ATTR_FAMILY_NAME: u16 = 2;
    const ETHTOOL_MSG_COALESCE_GET: u8 = 19;
    const NLMSG_ERROR: u16 = 2;

    fn put_attr(out: &mut Vec<u8>, ty: u16, data: &[u8]) {
        out.extend_from_slice(&((4 + data.len()) as u16).to_ne_bytes());
        out.extend_from_slice(&ty.to_ne_bytes());
        out.extend_from_slice(data);
        while !out.len().is_multiple_of(4) {
            out.push(0);
        }
    }

    fn attrs_of(b: &[u8]) -> Vec<(u16, Vec<u8>)> {
        let mut out = Vec::new();
        let mut at = 0;
        while at + 4 <= b.len() {
            let len = u16::from_ne_bytes([b[at], b[at + 1]]) as usize;
            let ty = u16::from_ne_bytes([b[at + 2], b[at + 3]]);
            if len < 4 || at + len > b.len() {
                break;
            }
            out.push((ty, b[at + 4..at + len].to_vec()));
            at += len.next_multiple_of(4);
        }
        out
    }

    /// One generic-netlink request; the attributes of the reply (after `nlmsghdr` and
    /// `genlmsghdr`), `None` on an error reply.
    fn genl_request(fd: i32, family: u16, cmd: u8, attrs: &[u8]) -> Option<Vec<u8>> {
        let mut msg = Vec::new();
        msg.extend_from_slice(&((16 + 4 + attrs.len()) as u32).to_ne_bytes());
        msg.extend_from_slice(&family.to_ne_bytes());
        msg.extend_from_slice(&1u16.to_ne_bytes());
        msg.extend_from_slice(&1u32.to_ne_bytes());
        msg.extend_from_slice(&0u32.to_ne_bytes());
        msg.extend_from_slice(&[cmd, 1, 0, 0]);
        msg.extend_from_slice(attrs);
        if unsafe { libc::send(fd, msg.as_ptr().cast(), msg.len(), 0) } != msg.len() as isize {
            return None;
        }
        let mut reply = vec![0u8; 16384];
        let n = unsafe { libc::recv(fd, reply.as_mut_ptr().cast(), reply.len(), 0) };
        if n < 20 {
            return None;
        }
        reply.truncate(n as usize);
        let len = (word(&reply, 0) as usize).min(reply.len());
        if u16::from_ne_bytes([reply[4], reply[5]]) == NLMSG_ERROR {
            return None;
        }
        Some(reply[20..len].to_vec())
    }

    fn genl_family(fd: i32, name: &str) -> Option<u16> {
        let mut attrs = Vec::new();
        put_attr(
            &mut attrs,
            CTRL_ATTR_FAMILY_NAME,
            format!("{name}\0").as_bytes(),
        );
        let reply = genl_request(fd, GENL_ID_CTRL, CTRL_CMD_GETFAMILY, &attrs)?;
        attrs_of(&reply)
            .into_iter()
            .find(|(ty, _)| *ty == CTRL_ATTR_FAMILY_ID)
            .map(|(_, v)| u16::from_ne_bytes([v[0], v[1]]))
    }

    /// What [`nic_profile`] could not read off the real interface and so had to assume.
    #[derive(Debug, Clone, Default)]
    pub struct Assumed {
        /// The coalescing fields taken as supported: the netlink answer, or (without one) the
        /// fields that read non-zero.
        pub coalesce_supported: u32,
        /// Whether that came from netlink.
        pub coalesce_supported_exact: bool,
    }

    /// A [`Nic`] that answers the read-only `ethtool` commands as the real `iface` does now: its
    /// driver info, link, rings, coalescing, channels, flow control, EEE, legacy feature flags,
    /// timestamping capabilities and PHC, statistics names and values, MTU, queues, addresses,
    /// bus and threaded-NAPI setting. What `ethtool` cannot report is assumed (see [`Assumed`]):
    /// the coalescing limits stay unlimited, no flag is settable, and ETF offload is left off.
    pub fn nic_profile(iface: &str) -> (Nic, Assumed) {
        let mut assumed = Assumed::default();
        let ifindex = ifindex(iface).unwrap_or(2);
        let mut nic = Nic::new(iface, ifindex)
            .operstate(sysfs(iface, "operstate").unwrap_or_else(|| "up".into()))
            .queues(count_dir(iface, "rx-"), count_dir(iface, "tx-"));
        if let Some(mtu) = sysfs(iface, "mtu").and_then(|m| m.parse().ok()) {
            nic = nic.mtu(mtu);
        }
        if let Some(bus) = std::fs::read_link(format!("/sys/class/net/{iface}/device/subsystem"))
            .ok()
            .and_then(|p| p.file_name().map(|f| f.to_string_lossy().into_owned()))
        {
            nic = nic.subsystem(bus);
        }
        if let Some(on) = sysfs(iface, "threaded") {
            nic = nic.threaded_napi(on == "1");
        }
        if let Ok(irqs) = std::fs::read_dir(format!("/sys/class/net/{iface}/device/msi_irqs")) {
            let mut irqs: Vec<u32> = irqs
                .flatten()
                .filter_map(|e| e.file_name().to_string_lossy().parse().ok())
                .collect();
            irqs.sort();
            nic = nic.msi_irqs(irqs);
        }
        for (ip, prefix) in addresses(iface) {
            if let Ok(net) = format!("{ip}/{prefix}").parse::<snare::IpNet>() {
                nic = nic.network(net);
            }
        }
        if let Ok(d) = drvinfo(iface) {
            nic = nic
                .driver(d.driver, d.version)
                .bus_info(d.bus_info)
                .firmware(d.fw_version)
                .expansion_rom(d.erom_version);
        }
        if let Ok(ts) = ts_info(iface) {
            nic = nic
                .hardware_timestamping(ts.so_timestamping & SOF_TIMESTAMPING_RAW_HARDWARE != 0)
                .timestamping_caps(ts.so_timestamping, ts.tx_types, ts.rx_filters);
            if let Ok(phc) = u32::try_from(ts.phc_index) {
                nic = nic.ptp_index(phc);
            }
        }
        if let Ok([flags, tx_type, rx_filter]) = hwtstamp_config(iface) {
            nic = nic.hwtstamp_config(flags, tx_type, rx_filter);
        }
        if let Ok(r) = get_words::<8>(iface, ETHTOOL_GRINGPARAM) {
            nic = nic.rings(Rings {
                rx_max: r[0],
                rx_mini_max: r[1],
                rx_jumbo_max: r[2],
                tx_max: r[3],
                rx: r[4],
                rx_mini: r[5],
                rx_jumbo: r[6],
                tx: r[7],
            });
        }
        if let Ok(c) = get_words::<22>(iface, ETHTOOL_GCOALESCE) {
            let nonzero = c
                .iter()
                .enumerate()
                .filter(|(_, v)| **v != 0)
                .fold(0u32, |m, (i, _)| m | 1 << i);
            let exact = coalesce_supported(iface);
            assumed.coalesce_supported_exact = exact.is_some();
            assumed.coalesce_supported = exact.unwrap_or(nonzero) | nonzero;
            nic = nic.coalesce(CoalesceParams(assumed.coalesce_supported), coalesce_of(&c));
        }
        if let Ok(c) = get_words::<8>(iface, ETHTOOL_GCHANNELS) {
            nic = nic.channels(Channels {
                rx_max: c[0],
                tx_max: c[1],
                other_max: c[2],
                combined_max: c[3],
                rx: c[4],
                tx: c[5],
                other: c[6],
                combined: c[7],
            });
        }
        if let Ok(p) = get_words::<3>(iface, ETHTOOL_GPAUSEPARAM) {
            nic = nic.pause(Pause {
                autoneg: p[0] != 0,
                rx: p[1] != 0,
                tx: p[2] != 0,
            });
        }
        if let Ok(e) = get_words::<7>(iface, ETHTOOL_GEEE) {
            nic = nic.eee(Eee {
                supported: e[0],
                advertised: e[1],
                lp_advertised: e[2],
                active: e[3] != 0,
                enabled: e[4] != 0,
                tx_lpi_enabled: e[5] != 0,
                tx_lpi_timer: e[6],
            });
        }
        if let Ok([on]) = get_words::<1>(iface, ETHTOOL_GFLAGS) {
            nic = nic.flags(on, 0);
        }
        if let Ok(Some(n)) = stats_count(iface)
            && n > 0
            && let (Ok(names), Ok(values)) = (stat_names(iface, n), stat_values(iface, n))
        {
            nic = nic.driver_stats(names.into_iter().zip(values));
        }
        (nic, assumed)
    }

    pub fn coalesce_of(c: &[u32; 22]) -> Coalesce {
        Coalesce {
            rx_usecs: c[0],
            rx_frames: c[1],
            rx_usecs_irq: c[2],
            rx_frames_irq: c[3],
            tx_usecs: c[4],
            tx_frames: c[5],
            tx_usecs_irq: c[6],
            tx_frames_irq: c[7],
            stats_block_usecs: c[8],
            adaptive_rx: c[9] != 0,
            adaptive_tx: c[10] != 0,
            pkt_rate_low: c[11],
            rx_usecs_low: c[12],
            rx_frames_low: c[13],
            tx_usecs_low: c[14],
            tx_frames_low: c[15],
            pkt_rate_high: c[16],
            rx_usecs_high: c[17],
            rx_frames_high: c[18],
            tx_usecs_high: c[19],
            tx_frames_high: c[20],
            sample_interval: c[21],
        }
    }

    /// A sim on a [`snare::HostProfile`] holding just `nic`, with the real process's root flag,
    /// capabilities and privileges.
    pub fn sim_with(nic: Nic) -> snare::Sim {
        sim_builder(nic).build()
    }

    /// [`sim_with`]'s builder, for tests that configure more.
    pub fn sim_builder(nic: Nic) -> snare::SimBuilder {
        let privileges =
            snare::Privileges::from_real_process().expect("the real process's privileges");
        let mut profile = snare::HostProfile::new().nic(nic).root(privileges.root);
        for (held, cap) in [
            (privileges.net_admin, super::CAP_NET_ADMIN),
            (privileges.net_raw, super::CAP_NET_RAW),
            (privileges.ipc_lock, super::CAP_IPC_LOCK),
            (privileges.sys_nice, super::CAP_SYS_NICE),
        ] {
            if held {
                profile = profile.cap(cap as i32);
            }
        }
        snare::Sim::builder()
            .host(profile.build())
            .privileges(privileges)
    }
}

/// The peer side of the exchanges: echoes every datagram back to its sender from `sock` until
/// `quit` is received or `limit` passes without traffic. `scripts/test-hardware.sh --reflector`
/// runs this on the second machine; tests run it in a sim for the sim's side of an exchange.
pub fn reflect(sock: &std::net::UdpSocket, limit: std::time::Duration) -> usize {
    sock.set_read_timeout(Some(limit)).unwrap();
    let mut buf = vec![0u8; 65_536];
    let mut echoed = 0;
    while let Ok((n, from)) = sock.recv_from(&mut buf) {
        if &buf[..n] == b"quit" {
            break;
        }
        if sock.send_to(&buf[..n], from).is_ok() {
            echoed += 1;
        }
    }
    echoed
}

/// Socket calls the timestamping and buffer tests share: options, `recvmsg` with its control
/// buffer, and control-message parsing (man 3 cmsg).
#[cfg(target_os = "linux")]
pub mod sock {
    use std::mem::size_of;

    pub const SO_TIMESTAMPING: i32 = 37;
    pub const SO_MEMINFO: i32 = 55;
    pub const SO_TXTIME: i32 = 61;
    pub const SCM_TXTIME: i32 = 61;
    pub const TX_HARDWARE: u32 = 1 << 0;
    pub const TX_SOFTWARE: u32 = 1 << 1;
    pub const RX_HARDWARE: u32 = 1 << 2;
    pub const RX_SOFTWARE: u32 = 1 << 3;
    pub const SOFTWARE: u32 = 1 << 4;
    pub const RAW_HARDWARE: u32 = 1 << 6;
    pub const OPT_ID: u32 = 1 << 7;
    pub const TX_SCHED: u32 = 1 << 8;
    pub const OPT_CMSG: u32 = 1 << 10;
    pub const OPT_TSONLY: u32 = 1 << 11;
    pub const BIND_PHC: u32 = 1 << 15;

    pub fn errno() -> i32 {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
    }

    pub fn setsockopt<T>(fd: i32, level: i32, name: i32, value: &T) -> Result<(), i32> {
        let rc = unsafe {
            libc::setsockopt(
                fd,
                level,
                name,
                (value as *const T).cast(),
                size_of::<T>() as u32,
            )
        };
        if rc == 0 { Ok(()) } else { Err(errno()) }
    }

    pub fn getsockopt_int(fd: i32, level: i32, name: i32) -> Result<i32, i32> {
        let mut v = 0i32;
        let mut len = 4u32;
        let rc =
            unsafe { libc::getsockopt(fd, level, name, (&mut v as *mut i32).cast(), &mut len) };
        if rc == 0 { Ok(v) } else { Err(errno()) }
    }

    /// `SO_MEMINFO`'s `SK_MEMINFO_*` words (include/uapi/linux/sock_diag.h); `[0]` is
    /// `RMEM_ALLOC`, `[1]` `RCVBUF`.
    pub fn meminfo(fd: i32) -> [u32; 9] {
        let mut v = [0u32; 9];
        let mut len = size_of::<[u32; 9]>() as u32;
        unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                SO_MEMINFO,
                v.as_mut_ptr().cast(),
                &mut len,
            )
        };
        v
    }

    /// One `recvmsg`: the byte count or errno, `msg_flags` and the control messages.
    #[derive(Debug, Clone, PartialEq)]
    pub struct Got {
        pub n: Result<usize, i32>,
        pub flags: i32,
        pub cmsgs: Vec<(i32, i32, Vec<u8>)>,
        pub data: Vec<u8>,
    }

    #[repr(C, align(8))]
    struct Control([u8; 1024]);

    pub fn recvmsg(fd: i32, data_cap: usize, flags: i32) -> Got {
        let mut data = vec![0u8; data_cap];
        let mut control = Control([0; 1024]);
        let mut name: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut iov = libc::iovec {
            iov_base: data.as_mut_ptr().cast(),
            iov_len: data.len(),
        };
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_name = (&raw mut name).cast();
        msg.msg_namelen = size_of::<libc::sockaddr_storage>() as u32;
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.0.as_mut_ptr().cast();
        msg.msg_controllen = control.0.len() as _;
        let rc = unsafe { libc::recvmsg(fd, &mut msg, flags) };
        let n = if rc < 0 {
            Err(errno())
        } else {
            Ok(rc as usize)
        };
        data.truncate(*n.as_ref().unwrap_or(&0));
        let used = if n.is_ok() {
            msg.msg_controllen as usize
        } else {
            0
        };
        Got {
            n,
            flags: msg.msg_flags & !libc::MSG_CMSG_CLOEXEC,
            cmsgs: cmsgs(&control.0[..used]),
            data,
        }
    }

    /// The complete control messages in `control`: `(level, type, payload)`.
    #[allow(clippy::unnecessary_cast)]
    pub fn cmsgs(control: &[u8]) -> Vec<(i32, i32, Vec<u8>)> {
        let hdr = size_of::<libc::cmsghdr>();
        let align = std::mem::align_of::<libc::cmsghdr>();
        let mut out = Vec::new();
        let mut off = 0;
        while off + hdr <= control.len() {
            let c: libc::cmsghdr = unsafe {
                control
                    .as_ptr()
                    .add(off)
                    .cast::<libc::cmsghdr>()
                    .read_unaligned()
            };
            let len = c.cmsg_len as usize;
            if len < hdr || off + len > control.len() {
                break;
            }
            let data_at = off + unsafe { libc::CMSG_LEN(0) } as usize;
            out.push((
                c.cmsg_level,
                c.cmsg_type,
                control[data_at..off + len].to_vec(),
            ));
            off += (len + align - 1) & !(align - 1);
        }
        out
    }

    /// Which of `struct scm_timestamping`'s three `timespec`s are set: software, the
    /// deprecated one, raw hardware (Documentation/networking/timestamping.rst).
    pub fn filled_slots(payload: &[u8]) -> [bool; 3] {
        std::array::from_fn(|i| payload[16 * i..16 * i + 16].iter().any(|&b| b != 0))
    }
}
