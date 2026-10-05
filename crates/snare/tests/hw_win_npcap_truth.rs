#![cfg(all(windows, feature = "hw-npcap"))]

//! npcap on the real machine against the sim's pcap model (the `wpcap.dll` interposer and
//! src/win_net.rs): the device list, opening the real adapter's `\Device\NPF_{GUID}` the way
//! ethercrab's Windows transport does (immediate mode, nonblocking), opening a device that does
//! not exist, and, with `SNARE_HW_MUTATE=1`, sending frames with `pcap_sendpacket` and a send
//! queue (`SendSync::Off` and `On`) and reading the adapter's own frames back. Sending is gated
//! like a settings change because it puts frames on the real wire: one broadcast frame per send,
//! EtherType 0x88B5 (IEEE 802 local experimental), which no station acts on.
//!
//! The file compiles to an empty test binary unless the `hw-npcap` feature is on: the `pcap`
//! crate links `wpcap.lib`, which exists only where the npcap SDK is installed, so a default
//! build or `cargo test` must not reference it. `scripts/test-hardware.ps1` turns the feature on
//! when npcap is present (or with `-Npcap`).
//!
//! References: [Npcap Users' Guide: Npcap API](https://npcap.com/guide/npcap-devguide.html);
//! [pcap_sendqueue_transmit](https://npcap.com/guide/wpcap/pcap_sendqueue_transmit.html);
//! [pcap_findalldevs(3PCAP)](https://www.tcpdump.org/manpages/pcap_findalldevs.3pcap.html);
//! [pcap_activate(3PCAP)](https://www.tcpdump.org/manpages/pcap_activate.3pcap.html).

#[path = "support/hw.rs"]
mod hw;

use std::mem::zeroed;
use std::time::{Duration, Instant};

use hw::{need, require};
use pcap::sendqueue::{SendQueue, SendSync};
use pcap::{Active, Capture, Device};
use snare::{NicSpec, Sim};
use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceAliasToLuid, GetIfEntry2, MIB_IF_ROW2,
};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;

const ETHERTYPE: [u8; 2] = [0x88, 0xb5];

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

/// `alias`'s npcap device name, `\Device\NPF_{GUID}`, and its MAC address.
fn npf_name(alias: &str) -> Option<(String, [u8; 6])> {
    let mut luid: NET_LUID_LH = unsafe { zeroed() };
    if unsafe { ConvertInterfaceAliasToLuid(wide(alias).as_ptr(), &mut luid) } != ERROR_SUCCESS {
        return None;
    }
    let mut row: MIB_IF_ROW2 = unsafe { zeroed() };
    row.InterfaceLuid = luid;
    if unsafe { GetIfEntry2(&mut row) } != ERROR_SUCCESS {
        return None;
    }
    let g = row.InterfaceGuid;
    let d = g.data4;
    let name = format!(
        r"\Device\NPF_{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        g.data1, g.data2, g.data3, d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]
    );
    let mut mac = [0u8; 6];
    mac.copy_from_slice(&row.PhysicalAddress[..6]);
    Some((name, mac))
}

/// The error's variant, without the message text, which differs between npcap and the sim.
fn kind(e: &pcap::Error) -> String {
    let text = format!("{e:?}");
    text.split(['(', ' ', '{'])
        .next()
        .unwrap_or_default()
        .to_string()
}

fn open(device: &str) -> Result<Capture<Active>, String> {
    Capture::from_device(device)
        .map_err(|e| kind(&e))?
        .immediate_mode(true)
        .open()
        .map_err(|e| kind(&e))?
        .setnonblock()
        .map_err(|e| kind(&e))
}

/// `name`'s entry in the device list as its (loopback, up) flags, `None` when unlisted.
fn listed(name: &str) -> Result<Option<(bool, bool)>, String> {
    let devices = Device::list().map_err(|e| kind(&e))?;
    Ok(devices
        .iter()
        .find(|d| d.name.eq_ignore_ascii_case(name))
        .map(|d| (d.flags.is_loopback(), d.flags.is_up())))
}

const NEEDS: &str =
    "needs npcap and a wired adapter (set SNARE_HW_NPCAP=1 and SNARE_HW_WIN_ADAPTER=<alias>)";

fn target() -> Option<(String, String, [u8; 6])> {
    let h = hw::hw();
    if !h.npcap {
        return None;
    }
    let alias = h.win_adapter.clone()?;
    let (name, mac) = snare::real(|| npf_name(&alias))?;
    Some((alias, name, mac))
}

/// A sim whose interface carries the npcap device name, so frames sent on it cross its link.
fn sim_for(name: &str, mac: [u8; 6]) -> Sim {
    Sim::builder().nic(NicSpec::new(name).mac(mac)).build()
}

#[test]
#[ignore = "hardware: needs npcap and a wired adapter"]
fn hw_npcap_open_matches() {
    let (alias, name, mac) = need!(target(), "{NEEDS}");
    let probe = || {
        let listed = listed(&name);
        let opened = open(&name).map(drop);
        let bogus = open(r"\Device\NPF_{00000000-0000-0000-0000-000000000000}").map(drop);
        (listed, opened, bogus)
    };
    let real = snare::real(probe);
    let sim = sim_for(&name, mac).run(probe);
    eprintln!("{alias} = {name}: real {real:?}");
    assert_eq!(sim.1, real.1, "opening {name} immediate + nonblocking");
    assert_eq!(sim.2, real.2, "opening a device that does not exist");
    if sim.0 != real.0 {
        hw::note(&format!(
            "pcap_findalldevs passes through to npcap in the sim: real {:?}, sim {:?}",
            real.0, sim.0
        ));
    }
}

/// A broadcast frame from `mac` carrying `tag`.
fn frame(mac: [u8; 6], tag: u8) -> Vec<u8> {
    let mut f = vec![0xff; 6];
    f.extend_from_slice(&mac);
    f.extend_from_slice(&ETHERTYPE);
    f.extend(std::iter::repeat_n(tag, 46));
    f
}

/// How many of our frames tagged `tag` come back on `cap` within half a second.
fn seen(cap: &mut Capture<Active>, tag: u8) -> usize {
    let mut n = 0;
    let start = Instant::now();
    while start.elapsed() < Duration::from_millis(500) {
        match cap.next_packet() {
            Ok(p) if p.data.len() >= 15 && p.data[12..14] == ETHERTYPE && p.data[14] == tag => {
                n += 1
            }
            Ok(_) => {}
            Err(_) => std::thread::sleep(Duration::from_millis(5)),
        }
    }
    n
}

#[test]
#[ignore = "hardware: needs npcap, a wired adapter and SNARE_HW_MUTATE=1"]
fn hw_npcap_send_matches() {
    let (_, name, mac) = need!(target(), "{NEEDS}");
    require!(
        hw::hw().mutate,
        "sends broadcast frames on {name} (set SNARE_HW_MUTATE=1)"
    );
    let probe = || {
        let mut cap = open(&name).expect("open");
        let mut out = Vec::new();
        out.push((
            "sendpacket",
            cap.sendpacket(&frame(mac, 1)[..]).map_err(|e| kind(&e)),
            seen(&mut cap, 1),
        ));
        for (tag, sync) in [(2u8, SendSync::Off), (3, SendSync::On)] {
            let mut queue = SendQueue::new(64 * 1024).expect("send queue");
            queue.queue(None, &frame(mac, tag)).expect("queue");
            queue.queue(None, &frame(mac, tag)).expect("queue");
            out.push((
                "sendqueue",
                queue.transmit(&mut cap, sync).map_err(|e| kind(&e)),
                seen(&mut cap, tag),
            ));
        }
        out
    };
    let real = snare::real(probe);
    let sim = sim_for(&name, mac).run(probe);
    assert_eq!(sim, real, "(call, result, own frames read back)");
}
