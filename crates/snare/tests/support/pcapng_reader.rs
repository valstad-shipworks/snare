//! A minimal pcapng reader for the capture tests: section header, interface and enhanced packet
//! blocks, and a decoder for the Ethernet / IPv4 / IPv6 / TCP / UDP / ICMP frames snare writes,
//! verifying every checksum on the way.

#![allow(dead_code)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

pub const FIN: u8 = 0x01;
pub const SYN: u8 = 0x02;
pub const RST: u8 = 0x04;
pub const PSH: u8 = 0x08;
pub const ACK: u8 = 0x10;

pub const EPOCH_NS: u64 = 1_700_000_000 * 1_000_000_000;

pub struct File {
    pub os: String,
    pub appl: String,
    pub ifaces: Vec<String>,
    pub packets: Vec<Pkt>,
}

#[derive(Clone, Debug)]
pub struct Pkt {
    pub iface: String,
    pub ns: u64,
    pub inbound: bool,
    pub data: Vec<u8>,
    pub orig_len: usize,
    /// The EPB's opt_comment, if it has one.
    pub comment: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum L4 {
    Tcp {
        seq: u32,
        ack: u32,
        flags: u8,
        mss: Option<u16>,
    },
    Udp,
    Icmp {
        kind: u8,
        code: u8,
        quoted: Vec<u8>,
    },
    Other(u8),
}

#[derive(Clone, Debug)]
pub struct Frame {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub src: IpAddr,
    pub dst: IpAddr,
    pub ttl: u8,
    pub ip_id: u16,
    pub sport: u16,
    pub dport: u16,
    pub l4: L4,
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn tcp_flags(&self) -> Option<u8> {
        match self.l4 {
            L4::Tcp { flags, .. } => Some(flags),
            _ => None,
        }
    }

    pub fn seq_ack(&self) -> (u32, u32) {
        match self.l4 {
            L4::Tcp { seq, ack, .. } => (seq, ack),
            _ => panic!("not TCP: {self:?}"),
        }
    }
}

fn le16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(b[at..at + 2].try_into().unwrap())
}

fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}

fn be16(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes(b[at..at + 2].try_into().unwrap())
}

fn be32(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes(b[at..at + 4].try_into().unwrap())
}

fn options(b: &[u8]) -> Vec<(u16, Vec<u8>)> {
    let mut out = Vec::new();
    let mut at = 0;
    while at + 4 <= b.len() {
        let code = le16(b, at);
        let len = le16(b, at + 2) as usize;
        if code == 0 {
            break;
        }
        out.push((code, b[at + 4..at + 4 + len].to_vec()));
        at += 4 + len.next_multiple_of(4);
    }
    out
}

pub fn read(path: &Path) -> File {
    let bytes = snare::real(|| std::fs::read(path)).expect("read capture");
    parse(&bytes)
}

pub fn parse(bytes: &[u8]) -> File {
    let mut file = File {
        os: String::new(),
        appl: String::new(),
        ifaces: Vec::new(),
        packets: Vec::new(),
    };
    let mut at = 0;
    let mut tsresol = Vec::new();
    while at < bytes.len() {
        let kind = le32(bytes, at);
        let len = le32(bytes, at + 4) as usize;
        assert!(len >= 12 && len.is_multiple_of(4), "block length {len}");
        assert_eq!(le32(bytes, at + len - 4) as usize, len, "trailing length");
        let body = &bytes[at + 8..at + len - 4];
        match kind {
            0x0A0D_0D0A => {
                assert_eq!(le32(body, 0), 0x1A2B_3C4D, "byte order magic");
                assert_eq!((le16(body, 4), le16(body, 6)), (1, 0), "version");
                for (code, v) in options(&body[16..]) {
                    match code {
                        3 => file.os = String::from_utf8(v).unwrap(),
                        4 => file.appl = String::from_utf8(v).unwrap(),
                        _ => {}
                    }
                }
            }
            1 => {
                assert_eq!(le16(body, 0), 1, "LINKTYPE_ETHERNET");
                let mut name = String::new();
                let mut resol = 6;
                for (code, v) in options(&body[8..]) {
                    match code {
                        2 => name = String::from_utf8(v).unwrap(),
                        9 => resol = v[0],
                        _ => {}
                    }
                }
                assert_eq!(resol, 9, "nanosecond stamps");
                tsresol.push(resol);
                file.ifaces.push(name);
            }
            6 => {
                let iface = le32(body, 0) as usize;
                let ns = (u64::from(le32(body, 4)) << 32) | u64::from(le32(body, 8));
                let caplen = le32(body, 12) as usize;
                let orig_len = le32(body, 16) as usize;
                let data = body[20..20 + caplen].to_vec();
                let mut inbound = None;
                let mut comment = None;
                for (code, v) in options(&body[20 + caplen.next_multiple_of(4)..]) {
                    match code {
                        1 => comment = Some(String::from_utf8(v).unwrap()),
                        2 => inbound = Some(le32(&v, 0) & 3 == 1),
                        _ => {}
                    }
                }
                file.packets.push(Pkt {
                    iface: file.ifaces[iface].clone(),
                    ns,
                    inbound: inbound.expect("epb_flags"),
                    data,
                    orig_len,
                    comment,
                });
            }
            other => panic!("unexpected block {other:#x}"),
        }
        at += len;
    }
    file
}

fn sum(parts: &[&[u8]]) -> u16 {
    let mut s: u64 = 0;
    let joined: Vec<u8> = parts.concat();
    for pair in joined.chunks(2) {
        let hi = pair[0];
        let lo = pair.get(1).copied().unwrap_or(0);
        s += u64::from(u16::from_be_bytes([hi, lo]));
    }
    while s >> 16 != 0 {
        s = (s & 0xffff) + (s >> 16);
    }
    !(s as u16)
}

fn pseudo(src: IpAddr, dst: IpAddr, proto: u8, len: usize) -> Vec<u8> {
    let mut p = Vec::new();
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            p.extend_from_slice(&s.octets());
            p.extend_from_slice(&d.octets());
            p.extend_from_slice(&[0, proto]);
            p.extend_from_slice(&(len as u16).to_be_bytes());
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            p.extend_from_slice(&s.octets());
            p.extend_from_slice(&d.octets());
            p.extend_from_slice(&(len as u32).to_be_bytes());
            p.extend_from_slice(&[0, 0, 0, proto]);
        }
        _ => panic!("mixed families"),
    }
    p
}

/// Decodes one frame, panicking on a malformed header or a bad checksum.
pub fn decode(data: &[u8]) -> Frame {
    let dst_mac: [u8; 6] = data[0..6].try_into().unwrap();
    let src_mac: [u8; 6] = data[6..12].try_into().unwrap();
    let ethertype = be16(data, 12);
    let ip = &data[14..];
    let (src, dst, proto, ttl, ip_id, l4) = match ethertype {
        0x0800 => {
            assert_eq!(ip[0], 0x45, "IHL 5");
            assert_eq!(be16(ip, 6), 0x4000, "DF");
            assert_eq!(sum(&[&ip[..20]]), 0, "IPv4 header checksum");
            let total = be16(ip, 2) as usize;
            let src = IpAddr::V4(Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]));
            let dst = IpAddr::V4(Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]));
            (
                src,
                dst,
                ip[9],
                ip[8],
                be16(ip, 4),
                &ip[20..total.min(ip.len())],
            )
        }
        0x86dd => {
            assert_eq!(ip[0] >> 4, 6);
            let len = be16(ip, 4) as usize;
            let src = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&ip[8..24]).unwrap()));
            let dst = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&ip[24..40]).unwrap()));
            (src, dst, ip[6], ip[7], 0, &ip[40..(40 + len).min(ip.len())])
        }
        other => panic!("ethertype {other:#x}"),
    };
    let (sport, dport, l4v, payload) = match proto {
        6 => {
            assert_eq!(
                sum(&[&pseudo(src, dst, 6, l4.len()), l4]),
                0,
                "TCP checksum"
            );
            let off = usize::from(l4[12] >> 4) * 4;
            let mss = (off > 20 && l4[20] == 2).then(|| be16(l4, 22));
            (
                be16(l4, 0),
                be16(l4, 2),
                L4::Tcp {
                    seq: be32(l4, 4),
                    ack: be32(l4, 8),
                    flags: l4[13],
                    mss,
                },
                l4[off..].to_vec(),
            )
        }
        17 => {
            assert_eq!(be16(l4, 4) as usize, l4.len(), "UDP length");
            assert_ne!(be16(l4, 6), 0, "UDP checksum present");
            let check = sum(&[&pseudo(src, dst, 17, l4.len()), l4]);
            assert!(check == 0 || check == 0xffff, "UDP checksum");
            (be16(l4, 0), be16(l4, 2), L4::Udp, l4[8..].to_vec())
        }
        1 => {
            assert_eq!(sum(&[l4]), 0, "ICMP checksum");
            (
                0,
                0,
                L4::Icmp {
                    kind: l4[0],
                    code: l4[1],
                    quoted: l4[8..].to_vec(),
                },
                Vec::new(),
            )
        }
        58 => {
            assert_eq!(
                sum(&[&pseudo(src, dst, 58, l4.len()), l4]),
                0,
                "ICMPv6 checksum"
            );
            (
                0,
                0,
                L4::Icmp {
                    kind: l4[0],
                    code: l4[1],
                    quoted: l4[8..].to_vec(),
                },
                Vec::new(),
            )
        }
        other => (0, 0, L4::Other(other), Vec::new()),
    };
    Frame {
        dst_mac,
        src_mac,
        src,
        dst,
        ttl,
        ip_id,
        sport,
        dport,
        l4: l4v,
        payload,
    }
}

/// Checks that every TCP flow in `frames` has consistent sequence numbers: each end's data and
/// FIN follow on from its SYN, and every ACK acknowledges no more than the other end sent.
pub fn check_tcp_sequences(frames: &[Frame]) {
    use std::collections::HashMap;
    let mut next: HashMap<(IpAddr, u16, IpAddr, u16), u32> = HashMap::new();
    for f in frames {
        let L4::Tcp {
            seq, ack, flags, ..
        } = f.l4
        else {
            continue;
        };
        let me = (f.src, f.sport, f.dst, f.dport);
        let peer = (f.dst, f.dport, f.src, f.sport);
        if flags & RST != 0 {
            if let (true, Some(&sent)) = (flags & ACK != 0, next.get(&peer)) {
                assert_eq!(ack, sent, "a reset acknowledges all the peer sent: {f:?}");
            }
            continue;
        }
        if flags & SYN != 0 {
            next.insert(me, seq.wrapping_add(1));
        } else {
            let expected = *next.get(&me).expect("a SYN before data");
            assert_eq!(seq, expected, "sequence number of {f:?}");
            let mut n = seq.wrapping_add(f.payload.len() as u32);
            if flags & FIN != 0 {
                n = n.wrapping_add(1);
            }
            next.insert(me, n);
        }
        if flags & ACK != 0 {
            let sent = *next.get(&peer).expect("ACK of a peer that sent a SYN");
            assert!(
                sent.wrapping_sub(ack) < 1 << 30,
                "ACK {ack} beyond what the peer sent ({sent}) in {f:?}"
            );
        }
    }
}
