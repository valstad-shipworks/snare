//! Optional pcapng capture of every byte that crosses the shim.
//!
//! Activated when `SNARE_PCAPNG_DIR` is set and either the test name appears in
//! the comma-separated `SNARE_PCAPNG_TESTS` allow-list OR the test calls
//! [`crate::enable_pcapng`]. The shim has no real packets, so this module
//! fabricates Ethernet + IPv4/IPv6 + TCP/UDP framing per flow — including a
//! synthetic 3-way handshake and ACKs — so the output renders as a normal
//! conversation in Wireshark.

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const BLOCK_SHB: u32 = 0x0A0D_0D0A;
const BLOCK_IDB: u32 = 0x0000_0001;
const BLOCK_EPB: u32 = 0x0000_0006;
const BYTE_ORDER_MAGIC: u32 = 0x1A2B_3C4D;

const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86dd;

const IP_PROTO_TCP: u8 = 6;
const IP_PROTO_UDP: u8 = 17;

const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_PSH: u8 = 0x08;
const TCP_ACK: u8 = 0x10;

const SNAPLEN: u32 = 65535;
const LINKTYPE_ETHERNET: u16 = 1;

pub const ENV_DIR: &str = "SNARE_PCAPNG_DIR";
pub const ENV_TESTS: &str = "SNARE_PCAPNG_TESTS";

pub struct PcapWriter {
    file: BufWriter<File>,
    flows: HashMap<FlowKey, FlowState>,
    next_isn: u32,
}

#[derive(Clone, Copy, Hash, PartialEq, Eq)]
struct FlowKey {
    a: SocketAddrCanon,
    b: SocketAddrCanon,
}

// Hashable wrapper that ignores IPv6 zone IDs for ordering purposes.
#[derive(Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
struct SocketAddrCanon {
    ip: [u8; 17], // 1 byte family tag + 16 bytes
    port: u16,
}

impl SocketAddrCanon {
    fn from(a: SocketAddr) -> Self {
        let mut ip = [0u8; 17];
        match a.ip() {
            IpAddr::V4(v) => {
                ip[0] = 4;
                ip[1..5].copy_from_slice(&v.octets());
            }
            IpAddr::V6(v) => {
                ip[0] = 6;
                ip[1..17].copy_from_slice(&v.octets());
            }
        }
        SocketAddrCanon { ip, port: a.port() }
    }
}

impl FlowKey {
    fn new(a: SocketAddr, b: SocketAddr) -> Self {
        let ca = SocketAddrCanon::from(a);
        let cb = SocketAddrCanon::from(b);
        if ca <= cb {
            FlowKey { a: ca, b: cb }
        } else {
            FlowKey { a: cb, b: ca }
        }
    }

    fn src_is_a(&self, src: SocketAddr) -> bool {
        SocketAddrCanon::from(src) == self.a
    }
}

struct FlowState {
    /// Next byte the "a" side will send (i.e. the seq field of its next segment).
    seq_a: u32,
    seq_b: u32,
    handshake_done: bool,
    closed_a: bool,
    closed_b: bool,
}

/// True if the current test should be auto-opened for pcap capture based on
/// `SNARE_PCAPNG_TESTS` (only meaningful when `SNARE_PCAPNG_DIR` is also set).
pub fn env_force_match(test_name: &str) -> bool {
    let Ok(list) = std::env::var(ENV_TESTS) else {
        return false;
    };
    list.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .any(|s| s == test_name)
}

/// Open a `<SNARE_PCAPNG_DIR>/<sanitized test name>.pcapng` writer. Returns
/// `None` if the env var is unset or the file/dir can't be created (with a
/// stderr warning in the latter case).
pub fn open_writer(test_name: &str) -> Option<PcapWriter> {
    let dir = std::env::var(ENV_DIR).ok()?;
    let dir = PathBuf::from(dir);
    if let Err(e) = std::fs::create_dir_all(&dir) {
        eprintln!("snare: pcapng: failed to create dir {}: {}", dir.display(), e);
        return None;
    }
    let path = dir.join(format!("{}.pcapng", sanitize_name(test_name)));
    match PcapWriter::create(&path) {
        Ok(w) => Some(w),
        Err(e) => {
            eprintln!("snare: pcapng: failed to open {}: {}", path.display(), e);
            None
        }
    }
}

fn sanitize_name(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' => c,
            ':' => '-',
            _ => '_',
        })
        .collect()
}

impl PcapWriter {
    pub fn create(path: &Path) -> io::Result<Self> {
        let file = File::create(path)?;
        let mut w = PcapWriter {
            file: BufWriter::new(file),
            flows: HashMap::new(),
            next_isn: 1000,
        };
        w.write_shb()?;
        w.write_idb()?;
        Ok(w)
    }

    fn write_shb(&mut self) -> io::Result<()> {
        let total: u32 = 28;
        self.file.write_all(&BLOCK_SHB.to_le_bytes())?;
        self.file.write_all(&total.to_le_bytes())?;
        self.file.write_all(&BYTE_ORDER_MAGIC.to_le_bytes())?;
        self.file.write_all(&1u16.to_le_bytes())?;
        self.file.write_all(&0u16.to_le_bytes())?;
        self.file.write_all(&(-1i64).to_le_bytes())?;
        self.file.write_all(&total.to_le_bytes())?;
        Ok(())
    }

    fn write_idb(&mut self) -> io::Result<()> {
        let total: u32 = 20;
        self.file.write_all(&BLOCK_IDB.to_le_bytes())?;
        self.file.write_all(&total.to_le_bytes())?;
        self.file.write_all(&LINKTYPE_ETHERNET.to_le_bytes())?;
        self.file.write_all(&0u16.to_le_bytes())?;
        self.file.write_all(&SNAPLEN.to_le_bytes())?;
        self.file.write_all(&total.to_le_bytes())?;
        Ok(())
    }

    fn write_epb(&mut self, frame: &[u8]) -> io::Result<()> {
        let cap_len = frame.len() as u32;
        let orig_len = cap_len;
        let pad = (4 - (frame.len() % 4)) % 4;
        let total: u32 = 32 + cap_len + pad as u32;
        let micros = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_micros() as u64)
            .unwrap_or(0);
        let ts_high = (micros >> 32) as u32;
        let ts_low = micros as u32;

        self.file.write_all(&BLOCK_EPB.to_le_bytes())?;
        self.file.write_all(&total.to_le_bytes())?;
        self.file.write_all(&0u32.to_le_bytes())?;
        self.file.write_all(&ts_high.to_le_bytes())?;
        self.file.write_all(&ts_low.to_le_bytes())?;
        self.file.write_all(&cap_len.to_le_bytes())?;
        self.file.write_all(&orig_len.to_le_bytes())?;
        self.file.write_all(frame)?;
        if pad > 0 {
            self.file.write_all(&[0u8; 4][..pad])?;
        }
        self.file.write_all(&total.to_le_bytes())?;
        self.file.flush()?;
        Ok(())
    }

    fn alloc_isn(&mut self) -> u32 {
        let isn = self.next_isn;
        self.next_isn = self.next_isn.wrapping_add(10_000);
        isn
    }

    /// Returns (existed_before, src_seq_pre_emit, peer_ack_pre_emit).
    fn touch_flow(&mut self, src: SocketAddr, dst: SocketAddr) -> (bool, u32, u32) {
        let key = FlowKey::new(src, dst);
        let existed = self.flows.contains_key(&key);
        if !existed {
            let seq_a = self.alloc_isn();
            let seq_b = self.alloc_isn();
            self.flows.insert(
                key,
                FlowState {
                    seq_a,
                    seq_b,
                    handshake_done: false,
                    closed_a: false,
                    closed_b: false,
                },
            );
        }
        let f = self.flows.get(&key).unwrap();
        let (src_seq, peer_ack) = if key.src_is_a(src) {
            (f.seq_a, f.seq_b)
        } else {
            (f.seq_b, f.seq_a)
        };
        (existed, src_seq, peer_ack)
    }

    /// Open a TCP connection by emitting a synthetic 3-way handshake. `client`
    /// is the side that initiated the connect.
    pub fn tcp_open(&mut self, client: SocketAddr, server: SocketAddr) {
        let (existed, client_seq, server_seq) = self.touch_flow(client, server);
        let key = FlowKey::new(client, server);
        if existed && self.flows.get(&key).unwrap().handshake_done {
            return;
        }

        let _ = self.emit_tcp(client, server, client_seq, 0, TCP_SYN, &[]);
        let _ = self.emit_tcp(
            server,
            client,
            server_seq,
            client_seq.wrapping_add(1),
            TCP_SYN | TCP_ACK,
            &[],
        );
        let _ = self.emit_tcp(
            client,
            server,
            client_seq.wrapping_add(1),
            server_seq.wrapping_add(1),
            TCP_ACK,
            &[],
        );

        let f = self.flows.get_mut(&key).unwrap();
        let new_client = client_seq.wrapping_add(1);
        let new_server = server_seq.wrapping_add(1);
        if key.src_is_a(client) {
            f.seq_a = new_client;
            f.seq_b = new_server;
        } else {
            f.seq_b = new_client;
            f.seq_a = new_server;
        }
        f.handshake_done = true;
    }

    pub fn tcp_data(&mut self, src: SocketAddr, dst: SocketAddr, payload: &[u8]) {
        if payload.is_empty() {
            return;
        }
        let key = FlowKey::new(src, dst);
        let needs_open = self
            .flows
            .get(&key)
            .map_or(true, |f| !f.handshake_done);
        if needs_open {
            // Use `src` as the initiator — best effort when we missed the actual
            // connect (e.g. data injected via `inject_tcp_from_test`).
            self.tcp_open(src, dst);
        }

        let (src_seq, peer_ack) = {
            let f = self.flows.get(&key).unwrap();
            if key.src_is_a(src) {
                (f.seq_a, f.seq_b)
            } else {
                (f.seq_b, f.seq_a)
            }
        };

        let _ = self.emit_tcp(src, dst, src_seq, peer_ack, TCP_PSH | TCP_ACK, payload);
        let new_src_seq = src_seq.wrapping_add(payload.len() as u32);
        let _ = self.emit_tcp(dst, src, peer_ack, new_src_seq, TCP_ACK, &[]);

        let f = self.flows.get_mut(&key).unwrap();
        if key.src_is_a(src) {
            f.seq_a = new_src_seq;
        } else {
            f.seq_b = new_src_seq;
        }
    }

    pub fn tcp_fin(&mut self, src: SocketAddr, dst: SocketAddr) {
        let key = FlowKey::new(src, dst);
        let Some(f) = self.flows.get(&key) else {
            return;
        };
        let src_is_a = key.src_is_a(src);
        let (src_seq, peer_ack, already_closed) = if src_is_a {
            (f.seq_a, f.seq_b, f.closed_a)
        } else {
            (f.seq_b, f.seq_a, f.closed_b)
        };
        if already_closed {
            return;
        }

        let _ = self.emit_tcp(src, dst, src_seq, peer_ack, TCP_FIN | TCP_ACK, &[]);
        let _ = self.emit_tcp(dst, src, peer_ack, src_seq.wrapping_add(1), TCP_ACK, &[]);

        let f = self.flows.get_mut(&key).unwrap();
        if src_is_a {
            f.seq_a = src_seq.wrapping_add(1);
            f.closed_a = true;
        } else {
            f.seq_b = src_seq.wrapping_add(1);
            f.closed_b = true;
        }
    }

    pub fn tcp_rst(&mut self, src: SocketAddr, dst: SocketAddr) {
        let key = FlowKey::new(src, dst);
        let (src_seq, peer_ack) = match self.flows.get(&key) {
            Some(f) => {
                if key.src_is_a(src) {
                    (f.seq_a, f.seq_b)
                } else {
                    (f.seq_b, f.seq_a)
                }
            }
            None => (0, 0),
        };
        let flags = if peer_ack == 0 { TCP_RST } else { TCP_RST | TCP_ACK };
        let _ = self.emit_tcp(src, dst, src_seq, peer_ack, flags, &[]);
    }

    pub fn udp_datagram(&mut self, src: SocketAddr, dst: SocketAddr, payload: &[u8]) {
        let datagram = build_udp_datagram(src.port(), dst.port(), payload);
        let frame = build_eth_ip(src, dst, IP_PROTO_UDP, &datagram);
        let _ = self.write_epb(&frame);
    }

    fn emit_tcp(
        &mut self,
        src: SocketAddr,
        dst: SocketAddr,
        seq: u32,
        ack: u32,
        flags: u8,
        payload: &[u8],
    ) -> io::Result<()> {
        let segment = build_tcp_segment(src.port(), dst.port(), seq, ack, flags, payload);
        let frame = build_eth_ip(src, dst, IP_PROTO_TCP, &segment);
        self.write_epb(&frame)
    }
}

// --- frame builders ---

fn build_eth_ip(src: SocketAddr, dst: SocketAddr, proto: u8, l4: &[u8]) -> Vec<u8> {
    let (eth_type, ip_hdr) = match (src.ip(), dst.ip()) {
        (IpAddr::V4(s), IpAddr::V4(d)) => (
            ETHERTYPE_IPV4,
            build_ipv4_header(s.octets(), d.octets(), proto, l4.len()),
        ),
        (IpAddr::V6(s), IpAddr::V6(d)) => (
            ETHERTYPE_IPV6,
            build_ipv6_header(s.octets(), d.octets(), proto, l4.len()),
        ),
        // Mixed families — map v4 into v6 so the packet still parses.
        _ => {
            let to6 = |ip: IpAddr| -> [u8; 16] {
                match ip {
                    IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
                    IpAddr::V6(v6) => v6.octets(),
                }
            };
            (
                ETHERTYPE_IPV6,
                build_ipv6_header(to6(src.ip()), to6(dst.ip()), proto, l4.len()),
            )
        }
    };

    let mut out = Vec::with_capacity(14 + ip_hdr.len() + l4.len());
    out.extend_from_slice(&mac_for(dst));
    out.extend_from_slice(&mac_for(src));
    out.extend_from_slice(&eth_type.to_be_bytes());
    out.extend_from_slice(&ip_hdr);
    out.extend_from_slice(l4);
    out
}

fn mac_for(addr: SocketAddr) -> [u8; 6] {
    // Locally-administered unicast (02:..) hashed from the addr so flows are
    // visually distinguishable in Wireshark.
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let mut feed = |b: u8| {
        h = h.wrapping_mul(0x100_0000_01b3);
        h ^= b as u64;
    };
    match addr.ip() {
        IpAddr::V4(v) => v.octets().iter().for_each(|b| feed(*b)),
        IpAddr::V6(v) => v.octets().iter().for_each(|b| feed(*b)),
    }
    for b in addr.port().to_be_bytes() {
        feed(b);
    }
    let bs = h.to_be_bytes();
    [0x02, bs[2], bs[3], bs[4], bs[5], bs[6]]
}

fn build_ipv4_header(src: [u8; 4], dst: [u8; 4], proto: u8, payload_len: usize) -> Vec<u8> {
    let total_len = 20 + payload_len;
    let mut h = vec![
        0x45,
        0x00,
        ((total_len >> 8) & 0xff) as u8,
        (total_len & 0xff) as u8,
        0x00,
        0x00,
        0x40,
        0x00,
        64,
        proto,
        0x00,
        0x00,
        src[0],
        src[1],
        src[2],
        src[3],
        dst[0],
        dst[1],
        dst[2],
        dst[3],
    ];
    let ck = ipv4_checksum(&h);
    h[10] = (ck >> 8) as u8;
    h[11] = (ck & 0xff) as u8;
    h
}

fn ipv4_checksum(h: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in h.chunks(2) {
        let word = ((chunk[0] as u32) << 8) | (*chunk.get(1).unwrap_or(&0) as u32);
        sum = sum.wrapping_add(word);
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn build_ipv6_header(src: [u8; 16], dst: [u8; 16], proto: u8, payload_len: usize) -> Vec<u8> {
    let mut h = Vec::with_capacity(40);
    h.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
    h.extend_from_slice(&(payload_len as u16).to_be_bytes());
    h.push(proto);
    h.push(64);
    h.extend_from_slice(&src);
    h.extend_from_slice(&dst);
    h
}

fn build_tcp_segment(
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut seg = Vec::with_capacity(20 + payload.len());
    seg.extend_from_slice(&src_port.to_be_bytes());
    seg.extend_from_slice(&dst_port.to_be_bytes());
    seg.extend_from_slice(&seq.to_be_bytes());
    seg.extend_from_slice(&ack.to_be_bytes());
    seg.push(0x50);
    seg.push(flags);
    seg.extend_from_slice(&65535u16.to_be_bytes());
    seg.extend_from_slice(&[0, 0]);
    seg.extend_from_slice(&[0, 0]);
    seg.extend_from_slice(payload);
    seg
}

fn build_udp_datagram(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let len = 8 + payload.len();
    let mut d = Vec::with_capacity(len);
    d.extend_from_slice(&src_port.to_be_bytes());
    d.extend_from_slice(&dst_port.to_be_bytes());
    d.extend_from_slice(&(len as u16).to_be_bytes());
    d.extend_from_slice(&[0, 0]);
    d.extend_from_slice(payload);
    d
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn sa(port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), port))
    }

    #[test]
    fn writer_emits_shb_idb_then_epbs() {
        let dir = std::env::temp_dir().join(format!(
            "snare_pcapng_unit_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("t.pcapng");
        {
            let mut w = PcapWriter::create(&path).unwrap();
            w.tcp_open(sa(40000), sa(40001));
            w.tcp_data(sa(40000), sa(40001), b"hello");
            w.tcp_fin(sa(40000), sa(40001));
            w.udp_datagram(sa(50000), sa(50001), b"udp");
        }
        let bytes = std::fs::read(&path).unwrap();
        // SHB magic at offset 0.
        assert_eq!(&bytes[..4], &BLOCK_SHB.to_le_bytes());
        // Byte-order magic.
        assert_eq!(&bytes[8..12], &BYTE_ORDER_MAGIC.to_le_bytes());
        // IDB starts after SHB (28 bytes).
        assert_eq!(&bytes[28..32], &BLOCK_IDB.to_le_bytes());
        // At least one EPB after IDB (20 bytes).
        assert_eq!(&bytes[48..52], &BLOCK_EPB.to_le_bytes());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ipv4_checksum_matches_known_value() {
        // Known IPv4 header from Wikipedia example, expected checksum 0xb861.
        let mut h = vec![
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ];
        let ck = ipv4_checksum(&h);
        assert_eq!(ck, 0xb861);
        h[10] = (ck >> 8) as u8;
        h[11] = (ck & 0xff) as u8;
        // Recomputing including the checksum should now yield zero.
        assert_eq!(ipv4_checksum(&h), 0);
    }
}
