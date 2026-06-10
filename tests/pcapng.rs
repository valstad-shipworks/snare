//! End-to-end pcapng capture test. Sets `SNARE_PCAPNG_DIR` for the test
//! process, runs a TCP+UDP round trip through the shim, and verifies that
//! a pcapng file with the expected magic and block sequence appears on disk.
//!
//! Cargo runs all `#[test]`s in this integration-test crate in one process
//! and shares env vars across them, so this file contains exactly one test
//! to keep things deterministic.

use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use snare::net::{TcpListener as ShimListener, TcpStream as ShimStream, UdpSocket as ShimUdp};
use snare::{ThreadExt, enable_pcapng, register_test};

const BLOCK_SHB: u32 = 0x0A0D_0D0A;
const BLOCK_IDB: u32 = 0x0000_0001;
const BLOCK_EPB: u32 = 0x0000_0006;
const BYTE_ORDER_MAGIC: u32 = 0x1A2B_3C4D;

fn unique_dir() -> PathBuf {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("snare-pcapng-test-{n}"))
}

#[test]
fn pcapng_capture_writes_valid_file_with_packets() {
    // Mute std:: imports — they're here so cargo doesn't drop them as unused
    // in case the test gets restructured later.
    let _ = std::mem::size_of::<TcpListener>();
    let _ = std::mem::size_of::<TcpStream>();
    let _ = std::mem::size_of::<UdpSocket>();

    let dir = unique_dir();
    std::fs::create_dir_all(&dir).unwrap();
    // SAFETY: single-test integration crate, no concurrent env access.
    unsafe {
        std::env::set_var("SNARE_PCAPNG_DIR", &dir);
    }

    register_test();
    enable_pcapng();

    // --- TCP round trip ---
    let listener = ShimListener::bind("127.0.0.1:0").unwrap();
    let server_addr: SocketAddr = listener.local_addr().unwrap();

    let server_thread = std::thread::spawn(move || {
        let (mut s, _peer) = listener.accept().unwrap();
        use std::io::{Read, Write};
        let mut buf = [0u8; 16];
        let n = s.read(&mut buf).unwrap();
        s.write_all(&buf[..n]).unwrap();
    })
    .register_as_child();

    {
        use std::io::{Read, Write};
        let mut client = ShimStream::connect(server_addr).unwrap();
        client.write_all(b"hello").unwrap();
        let mut echo = [0u8; 8];
        let n = client.read(&mut echo).unwrap();
        assert_eq!(&echo[..n], b"hello");
    }
    server_thread.join().unwrap();

    // --- UDP send (the shim only auto-delivers UDP via the framework tester
    // loop, but `send_to` still flows through `enqueue_udp_outbound` so the
    // pcap tap fires unconditionally — which is what we want to verify).
    let server = ShimUdp::bind("127.0.0.1:45100").unwrap();
    let server_addr = server.local_addr().unwrap();
    let client = ShimUdp::bind("127.0.0.1:45101").unwrap();
    client.send_to(b"ping", server_addr).unwrap();

    // Drop the writer (held in per-test state) by ending the test. But the
    // file is flushed on every write_epb, so we can read it now.
    let entries: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(Result::ok)
        .collect();
    assert_eq!(
        entries.len(),
        1,
        "expected exactly one pcapng file in {dir:?}"
    );
    let path = entries[0].path();
    assert!(
        path.extension().and_then(|s| s.to_str()) == Some("pcapng"),
        "unexpected file: {path:?}"
    );

    let bytes = std::fs::read(&path).unwrap();
    assert!(bytes.len() >= 48, "file too small: {} bytes", bytes.len());
    // Section Header Block at offset 0.
    assert_eq!(
        &bytes[..4],
        &BLOCK_SHB.to_le_bytes(),
        "missing SHB magic at byte 0"
    );
    assert_eq!(
        &bytes[8..12],
        &BYTE_ORDER_MAGIC.to_le_bytes(),
        "wrong byte-order magic"
    );
    // Interface Description Block follows immediately (SHB total = 28).
    assert_eq!(
        &bytes[28..32],
        &BLOCK_IDB.to_le_bytes(),
        "missing IDB after SHB"
    );
    // At least one Enhanced Packet Block after IDB (IDB total = 20).
    assert_eq!(
        &bytes[48..52],
        &BLOCK_EPB.to_le_bytes(),
        "missing EPB after IDB"
    );

    // Sanity: payload bytes appear somewhere in the file (verifies TCP data
    // was actually captured, not just the handshake).
    assert!(
        bytes.windows(5).any(|w| w == b"hello"),
        "TCP payload `hello` not found in pcapng"
    );
    assert!(
        bytes.windows(4).any(|w| w == b"ping"),
        "UDP payload `ping` not found in pcapng"
    );

    // Cleanup.
    let _ = std::fs::remove_dir_all(&dir);
}
