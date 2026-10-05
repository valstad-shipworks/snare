//! Pins, byte for byte, every `/sys`, `/proc` and `/dev` file a `SimHost` renders for a fixed,
//! explicitly built `HostProfile` and for `EasyBuilder::realtime()`: CPU lists and per-CPU
//! attributes, the qdisc and SYN-retry sysctls, `/proc/self/status`, every modelled
//! `/sys/class/net/<if>/` attribute of loopback, an up NIC and a down NIC, the `queues/` and
//! `device/msi_irqs/` listings, and a sequence of `threaded` writes and reads — each read's bytes
//! or errno kept in `golden/edge_host_sysfs.<os>.txt`. On macOS the `NET_RT_IFLIST2` blob and
//! `net.inet.udp.stats` a `SimHost` serves through `sysctl` are kept in
//! `golden/edge_host_sysctl.macos.txt`. Rendering is also pinned to be repeatable within a run and
//! the same on every thread, and (Linux) a `threaded` write to persist across runs, stay in its
//! sim, leave an already open file's snapshot alone and need root to open and `CAP_NET_ADMIN` to write.
#![cfg(unix)]

#[path = "support/golden.rs"]
mod golden;

use std::io::Write;
use std::net::Ipv4Addr;
use std::sync::Arc;

use snare::{CAP_NET_ADMIN, EasyBuilder, HostProfile, LinkStats, Nic, Sim, SimHost};

fn profile() -> Arc<SimHost> {
    HostProfile::new()
        .cpus(6)
        .online([0, 1, 2, 3, 5])
        .isolated([2, 3, 5])
        .nohz_full([3])
        .governor("schedutil")
        .preempt_rt(true)
        .default_qdisc("fq")
        .root(true)
        .cap(CAP_NET_ADMIN)
        .nic(
            Nic::new("eth0", 2)
                .mtu(9000)
                .address(Ipv4Addr::new(10, 0, 0, 10))
                .queues(3, 2)
                .msi_irqs([40, 41, 42])
                .threaded_napi(true)
                .link_stats(LinkStats {
                    rx_packets: 1000,
                    tx_packets: 2000,
                    rx_bytes: 64_000,
                    tx_bytes: 128_000,
                    rx_errors: 1,
                    tx_errors: 2,
                    rx_dropped: 3,
                    tx_dropped: 4,
                }),
        )
        .nic(Nic::new("eth1", 3).operstate("down"))
        .build()
}

const EXPLICIT: &[&str] = &["lo", "lo0", "eth0", "eth1"];
const PRESET: &[&str] = &["lo", "lo0", "eth0"];

const NIC_ATTRS: &[&str] = &[
    "mtu",
    "ifindex",
    "operstate",
    "carrier",
    "flags",
    "address",
    "statistics/rx_packets",
    "statistics/tx_packets",
    "statistics/rx_bytes",
    "statistics/tx_bytes",
    "statistics/rx_errors",
    "statistics/tx_errors",
    "statistics/rx_dropped",
    "statistics/tx_dropped",
    "statistics/multicast",
    "statistics/tx_carrier_errors",
    "statistics/rx_nohandler",
    "threaded",
];

fn paths(nics: &[&str]) -> Vec<String> {
    let mut out: Vec<String> = [
        "/sys/devices/system/cpu/online",
        "/sys/devices/system/cpu/isolated",
        "/sys/devices/system/cpu/nohz_full",
        "/sys/kernel/realtime",
        "/proc/sys/net/core/default_qdisc",
        "/proc/sys/net/ipv4/tcp_syn_retries",
        "/proc/self/status",
        "/proc/thread-self/status",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    for cpu in 0..6 {
        out.push(format!("/sys/devices/system/cpu/cpu{cpu}/online"));
        out.push(format!(
            "/sys/devices/system/cpu/cpu{cpu}/cpufreq/scaling_governor"
        ));
    }
    for nic in nics {
        for attr in NIC_ATTRS {
            out.push(format!("/sys/class/net/{nic}/{attr}"));
        }
    }
    out
}

fn show(result: std::io::Result<Vec<u8>>) -> String {
    match result {
        Ok(bytes) => format!("= {:?}\n", String::from_utf8_lossy(&bytes)),
        Err(e) => format!("! errno {}\n", e.raw_os_error().unwrap_or(-1)),
    }
}

fn listing(dir: &str) -> String {
    match std::fs::read_dir(dir) {
        Ok(entries) => {
            let names: Vec<String> = entries
                .map(|e| {
                    e.map(|e| e.file_name().to_string_lossy().into_owned())
                        .unwrap_or_else(|e| format!("!{e}"))
                })
                .collect();
            format!("= {names:?}\n")
        }
        Err(e) => format!("! errno {}\n", e.raw_os_error().unwrap_or(-1)),
    }
}

fn write_threaded(nic: &str, text: &[u8]) -> String {
    let r = std::fs::OpenOptions::new()
        .write(true)
        .open(format!("/sys/class/net/{nic}/threaded"))
        .and_then(|mut f| f.write_all(text));
    match r {
        Ok(()) => "= ok\n".to_string(),
        Err(e) => format!("! errno {}\n", e.raw_os_error().unwrap_or(-1)),
    }
}

/// Every rendered file, both listings and a `threaded` write sequence, as golden text.
fn render_host(nics: &[&str]) -> String {
    let mut out = String::new();
    for path in paths(nics) {
        out.push_str(&format!("{path} {}", show(std::fs::read(&path))));
    }
    let dirs = nics.iter().flat_map(|nic| {
        [
            format!("/sys/class/net/{nic}/queues"),
            format!("/sys/class/net/{nic}/device/msi_irqs"),
        ]
    });
    for dir in dirs.filter(|d| d.contains("/eth")) {
        out.push_str(&format!("ls {dir} {}", listing(&dir)));
    }
    for text in [&b"0\n"[..], b"2", b"x", b"0x1", b"+0", b"01", b"1\n\n", b""] {
        out.push_str(&format!(
            "write eth0/threaded {:?} {}",
            String::from_utf8_lossy(text),
            write_threaded("eth0", text)
        ));
        out.push_str(&format!(
            "  read {}",
            show(std::fs::read("/sys/class/net/eth0/threaded"))
        ));
    }
    out
}

fn os() -> &'static str {
    if cfg!(target_os = "linux") {
        "linux"
    } else {
        "macos"
    }
}

#[test]
fn rendered_files_match_the_golden() {
    let mut text = String::from("# explicit profile\n");
    text.push_str(
        &Sim::builder()
            .host(profile())
            .build()
            .run(|| render_host(EXPLICIT)),
    );
    text.push_str("# EasyBuilder::realtime()\n");
    text.push_str(
        &Sim::builder()
            .host(EasyBuilder::realtime().build())
            .build()
            .run(|| render_host(PRESET)),
    );
    golden::check_text(&format!("edge_host_sysfs.{}.txt", os()), &text);
}

#[test]
fn rendering_is_repeatable_and_the_same_on_every_thread() {
    let sim = Sim::builder().host(profile()).build();
    let read_all = || {
        paths(EXPLICIT)
            .into_iter()
            .map(|p| show(std::fs::read(p)))
            .collect::<Vec<_>>()
    };
    let (first, second, on_child) = sim.run(|| {
        let first = read_all();
        let second = read_all();
        let on_child = std::thread::spawn(read_all).join().unwrap();
        (first, second, on_child)
    });
    assert_eq!(first, second);
    assert_eq!(first, on_child);
    assert_eq!(sim.run(read_all), first, "and on a later run");
}

#[cfg(target_os = "linux")]
#[test]
fn a_write_persists_across_runs_but_not_into_another_sim() {
    let sim = Sim::builder().host(profile()).build();
    sim.run(|| assert_eq!(write_threaded("eth0", b"0"), "= ok\n"));
    assert_eq!(
        sim.run(|| std::fs::read("/sys/class/net/eth0/threaded").unwrap()),
        b"0\n"
    );
    let other = Sim::builder().host(profile()).build();
    assert_eq!(
        other.run(|| std::fs::read("/sys/class/net/eth0/threaded").unwrap()),
        b"1\n"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn a_file_open_before_a_change_keeps_its_snapshot() {
    use std::io::Read;
    Sim::builder().host(profile()).build().run(|| {
        let mut before = std::fs::File::open("/sys/class/net/eth0/threaded").unwrap();
        assert_eq!(write_threaded("eth0", b"0"), "= ok\n");
        let mut text = String::new();
        before.read_to_string(&mut text).unwrap();
        assert_eq!(text, "1\n");
        assert_eq!(
            std::fs::read_to_string("/sys/class/net/eth0/threaded").unwrap(),
            "0\n"
        );
    });
}

#[cfg(target_os = "linux")]
#[test]
fn an_unprivileged_threaded_write_is_eperm() {
    let host = HostProfile::new()
        .root(true)
        .nic(Nic::new("eth0", 2))
        .build();
    let opener = HostProfile::new()
        .cap(CAP_NET_ADMIN)
        .nic(Nic::new("eth0", 2))
        .build();
    Sim::builder().host(opener).build().run(|| {
        assert_eq!(
            write_threaded("eth0", b"1"),
            format!("! errno {}\n", libc::EACCES),
            "opening it to write needs root"
        );
    });
    Sim::builder().host(host).build().run(|| {
        assert_eq!(
            write_threaded("eth0", b"1"),
            format!("! errno {}\n", libc::EPERM)
        );
        assert_eq!(
            std::fs::read("/sys/class/net/eth0/threaded").unwrap(),
            b"0\n"
        );
    });
}

#[cfg(target_os = "macos")]
mod macos {
    use super::*;

    const CTL_NET: libc::c_int = 4;
    const PF_ROUTE: libc::c_int = 17;
    const NET_RT_IFLIST2: libc::c_int = 6;

    fn sysctl(mib: &mut [libc::c_int], len: Option<usize>) -> (i32, usize, Vec<u8>) {
        let mut needed = len.unwrap_or(0);
        let mut buf = vec![0u8; needed];
        let ptr = if len.is_some() {
            buf.as_mut_ptr().cast()
        } else {
            std::ptr::null_mut()
        };
        let r = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as u32,
                ptr,
                &mut needed,
                std::ptr::null_mut(),
                0,
            )
        };
        let e = if r == 0 {
            0
        } else {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
        };
        buf.truncate(needed.min(buf.len()));
        (e, needed, buf)
    }

    fn sysctlbyname(name: &std::ffi::CStr, len: Option<usize>) -> (i32, usize, Vec<u8>) {
        let mut needed = len.unwrap_or(0);
        let mut buf = vec![0u8; needed];
        let ptr = if len.is_some() {
            buf.as_mut_ptr().cast()
        } else {
            std::ptr::null_mut()
        };
        let r =
            unsafe { libc::sysctlbyname(name.as_ptr(), ptr, &mut needed, std::ptr::null_mut(), 0) };
        let e = if r == 0 {
            0
        } else {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
        };
        buf.truncate(needed.min(buf.len()));
        (e, needed, buf)
    }

    fn line(what: &str, (e, n, bytes): (i32, usize, Vec<u8>)) -> String {
        format!("{what}: errno {e} len {n}\n{}", golden::hex(&bytes))
    }

    fn render_sysctl() -> String {
        let mut out = String::new();
        let mut mib = [CTL_NET, PF_ROUTE, 0, 0, NET_RT_IFLIST2, 0];
        let size = sysctl(&mut mib, None);
        let full = size.1;
        out.push_str(&line("iflist2 size", size));
        out.push_str(&line("iflist2 full", sysctl(&mut mib, Some(full))));
        out.push_str(&line("iflist2 short", sysctl(&mut mib, Some(full - 1))));
        let mut udp = [CTL_NET, libc::PF_INET, libc::IPPROTO_UDP, 2];
        out.push_str(&line("udp.stats size", sysctl(&mut udp, None)));
        out.push_str(&line("udp.stats full", sysctl(&mut udp, Some(104))));
        out.push_str(&line("udp.stats short", sysctl(&mut udp, Some(10))));
        out.push_str(&line(
            "udp.stats by name",
            sysctlbyname(c"net.inet.udp.stats", Some(104)),
        ));
        out
    }

    #[test]
    fn sysctl_answers_match_the_golden() {
        let mut text = String::from("# explicit profile\n");
        text.push_str(&Sim::builder().host(profile()).build().run(render_sysctl));
        text.push_str("# EasyBuilder::realtime()\n");
        text.push_str(
            &Sim::builder()
                .host(EasyBuilder::realtime().build())
                .build()
                .run(render_sysctl),
        );
        golden::check_text("edge_host_sysctl.macos.txt", &text);
    }
}
