//! pcapng capture across two interfaces: one interface block each, and
//! every packet on the interface it left through, stamped in nanoseconds
//! at the instant it was on the wire.
//!
//! One test only: it sets `SNARE_PCAPNG_DIR` for the whole process.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{Duration, UNIX_EPOCH};

use snare::net::UdpSocket;
use snare::{
    IpNet, NicSpec, add_nic, advance_time, enable_pcapng, pause_time, register_test, set_nic_policy,
};

const BLOCK_IDB: u32 = 0x0000_0001;
const BLOCK_EPB: u32 = 0x0000_0006;

fn net(s: &str) -> IpNet {
    s.parse().unwrap()
}

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

fn unique_dir() -> PathBuf {
    let n = std::time::SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("snare-pcapng-nics-{n}"))
}

fn wall_ns() -> u64 {
    snare::time::SystemTime::now()
        .duration_since(snare::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

#[test]
fn each_interface_gets_one_block_and_its_packets() {
    let dir = unique_dir();
    std::fs::create_dir_all(&dir).unwrap();
    // SAFETY: single-test integration crate, no concurrent env access.
    unsafe {
        std::env::set_var("SNARE_PCAPNG_DIR", &dir);
    }
    register_test();
    enable_pcapng();
    pause_time();
    add_nic(NicSpec::new("eth0").address(net("10.0.0.1/24"))).unwrap();
    add_nic(NicSpec::new("eth1").address(net("10.0.0.2/24"))).unwrap();
    set_nic_policy("eth1", |p| p.latency = Duration::from_millis(5)).unwrap();
    let a = UdpSocket::bind("10.0.0.1:5000").unwrap();
    let b = UdpSocket::bind("10.0.0.2:5000").unwrap();

    let t0 = wall_ns();
    a.send_to(b"from-eth0", addr("10.0.0.2:5000")).unwrap();
    advance_time(Duration::from_millis(1));
    let t1 = wall_ns();
    b.send_to(b"from-eth1", addr("10.0.0.1:5000")).unwrap();
    a.send_to(b"again", addr("10.0.0.2:5000")).unwrap();

    let path = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| p.extension().and_then(|s| s.to_str()) == Some("pcapng"))
        .expect("a pcapng file");
    let bytes = std::fs::read(&path).unwrap();
    let word = |o: usize| u32::from_le_bytes(bytes[o..o + 4].try_into().unwrap());
    let mut idb_names = Vec::new();
    let mut epbs = Vec::new();
    let mut o = 0;
    while o < bytes.len() {
        let (kind, len) = (word(o), word(o + 4) as usize);
        if kind == BLOCK_IDB {
            let mut opt = o + 16;
            let mut name = None;
            while opt + 4 <= o + len - 4 {
                let code = u16::from_le_bytes([bytes[opt], bytes[opt + 1]]);
                let olen = u16::from_le_bytes([bytes[opt + 2], bytes[opt + 3]]) as usize;
                if code == 0 {
                    break;
                }
                if code == 2 {
                    name =
                        Some(String::from_utf8(bytes[opt + 4..opt + 4 + olen].to_vec()).unwrap());
                }
                opt += 4 + olen.next_multiple_of(4);
            }
            idb_names.push(name);
        } else if kind == BLOCK_EPB {
            let stamp = ((word(o + 12) as u64) << 32) | word(o + 16) as u64;
            epbs.push((word(o + 8), stamp));
        }
        o += len;
    }
    assert_eq!(
        idb_names,
        [None, Some("eth0".to_string()), Some("eth1".to_string())]
    );
    assert_eq!(epbs, [(1, t0), (2, t1), (1, t1)]);
    let _ = std::fs::remove_dir_all(&dir);
}
