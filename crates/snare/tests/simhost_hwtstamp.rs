#![cfg(target_os = "linux")]

//! A `SimHost` NIC's hardware timestamping: the `SIOC[GS]HWTSTAMP` configuration as net/core/
//! dev_ioctl.c (Linux 7.0) and the driver, modelled from its `ETHTOOL_GET_TS_INFO` answer, apply
//! it, and the hardware stamps that configuration puts in `scm_timestamping.ts[2]` of transmit
//! reports and received datagrams (net/socket.c `__sock_recv_timestamp`, net/core/skbuff.c
//! `__skb_tstamp_tx`).

use std::net::UdpSocket;
use std::os::fd::AsRawFd;

use snare::{CAP_NET_ADMIN, HostProfile, IpNet, Nic, Sim};

const SIOCSHWTSTAMP: libc::c_ulong = 0x89b0;
const SIOCGHWTSTAMP: libc::c_ulong = 0x89b1;
const HWTSTAMP_TX_OFF: i32 = 0;
const HWTSTAMP_TX_ON: i32 = 1;
const HWTSTAMP_TX_ONESTEP_SYNC: i32 = 2;
const HWTSTAMP_FILTER_NONE: i32 = 0;
const HWTSTAMP_FILTER_ALL: i32 = 1;
const HWTSTAMP_FILTER_PTP_V1_L4_EVENT: i32 = 3;
const HWTSTAMP_FILTER_PTP_V1_L4_SYNC: i32 = 4;
const HWTSTAMP_FILTER_PTP_V2_L4_EVENT: i32 = 6;
const HWTSTAMP_FILTER_PTP_V2_EVENT: i32 = 12;
const HWTSTAMP_FILTER_NTP_ALL: i32 = 15;

const SO_TIMESTAMPING: i32 = 37;
const TX_HARDWARE: u32 = 1 << 0;
const TX_SOFTWARE: u32 = 1 << 1;
const RX_HARDWARE: u32 = 1 << 2;
const SOFTWARE: u32 = 1 << 4;
const RAW_HARDWARE: u32 = 1 << 6;
const OPT_TSONLY: u32 = 1 << 11;
const OPT_TX_SWHW: u32 = 1 << 14;
const OPT_RX_FILTER: u32 = 1 << 17;

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

#[repr(C)]
struct Ifreq {
    name: [u8; 16],
    data: *mut i32,
}

/// `SIOCSHWTSTAMP`/`SIOCGHWTSTAMP` on `iface` with `struct hwtstamp_config { flags, tx_type,
/// rx_filter }`: what the call wrote back, or its errno.
fn hwtstamp(iface: &str, request: libc::c_ulong, cfg: [i32; 3]) -> Result<[i32; 3], i32> {
    let mut cfg = cfg;
    let mut req = Ifreq {
        name: [0; 16],
        data: cfg.as_mut_ptr(),
    };
    req.name[..iface.len()].copy_from_slice(iface.as_bytes());
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    let rc = unsafe { libc::ioctl(fd, request, &mut req) };
    let e = errno();
    unsafe { libc::close(fd) };
    if rc == 0 { Ok(cfg) } else { Err(e) }
}

fn set(iface: &str, cfg: [i32; 3]) -> Result<[i32; 3], i32> {
    hwtstamp(iface, SIOCSHWTSTAMP, cfg)
}

fn get(iface: &str) -> Result<[i32; 3], i32> {
    hwtstamp(iface, SIOCGHWTSTAMP, [0; 3])
}

/// dev_get_hwtstamp: a driver without `ndo_hwtstamp_get` is `EOPNOTSUPP`, before any copy; a
/// hardware-stamping one reads back the configuration it started with.
#[test]
fn get_needs_hardware_timestamping() {
    let host = HostProfile::new()
        .nic(Nic::new("eth0", 2))
        .nic(
            Nic::new("eth1", 3)
                .hardware_timestamping(true)
                .hwtstamp_config(0, HWTSTAMP_TX_ON, HWTSTAMP_FILTER_ALL),
        )
        .build();
    Sim::builder().host(host).build().run(|| {
        assert_eq!(get("eth0"), Err(libc::EOPNOTSUPP));
        assert_eq!(get("eth1"), Ok([0, HWTSTAMP_TX_ON, HWTSTAMP_FILTER_ALL]));
    });
}

/// dev_set_hwtstamp: `net_hwtstamp_validate` refuses an unknown flag (`EINVAL`) and an unknown
/// `tx_type` or `rx_filter` (`ERANGE`) before asking whether the device can stamp at all
/// (`EOPNOTSUPP`).
#[test]
fn set_is_validated_by_the_core_first() {
    let host = HostProfile::new()
        .nic(Nic::new("eth0", 2))
        .cap(CAP_NET_ADMIN)
        .build();
    Sim::builder().host(host).build().run(|| {
        assert_eq!(
            set("eth0", [2, HWTSTAMP_TX_OFF, HWTSTAMP_FILTER_NONE]),
            Err(libc::EINVAL)
        );
        assert_eq!(
            set("eth0", [0, 99, HWTSTAMP_FILTER_NONE]),
            Err(libc::ERANGE)
        );
        assert_eq!(set("eth0", [0, HWTSTAMP_TX_OFF, 99]), Err(libc::ERANGE));
        assert_eq!(
            set("eth0", [0, HWTSTAMP_TX_ON, HWTSTAMP_FILTER_ALL]),
            Err(libc::EOPNOTSUPP)
        );
    });
}

/// The driver applies what its `ETHTOOL_GET_TS_INFO` offers and writes the result back: the
/// default (I210) NIC turns every PTP filter into `HWTSTAMP_FILTER_ALL`, as igb_ptp.c
/// `igb_ptp_set_timestamp_mode` does, and refuses a one-step transmit type (`ERANGE`), leaving
/// the configuration as it was.
#[test]
fn an_i210_widens_ptp_filters_to_all() {
    let host = HostProfile::new()
        .nic(Nic::new("eth0", 2).hardware_timestamping(true))
        .cap(CAP_NET_ADMIN)
        .build();
    Sim::builder().host(host).build().run(|| {
        let all = [0, HWTSTAMP_TX_ON, HWTSTAMP_FILTER_ALL];
        assert_eq!(
            set("eth0", [0, HWTSTAMP_TX_ON, HWTSTAMP_FILTER_PTP_V2_L4_EVENT]),
            Ok(all)
        );
        assert_eq!(get("eth0"), Ok(all));
        assert_eq!(
            set("eth0", [0, HWTSTAMP_TX_OFF, HWTSTAMP_FILTER_NTP_ALL]),
            Ok([0, HWTSTAMP_TX_OFF, HWTSTAMP_FILTER_ALL])
        );
        assert_eq!(
            set("eth0", [0, HWTSTAMP_TX_ONESTEP_SYNC, HWTSTAMP_FILTER_NONE]),
            Err(libc::ERANGE)
        );
        assert_eq!(get("eth0"), Ok([0, HWTSTAMP_TX_OFF, HWTSTAMP_FILTER_ALL]));
        assert_eq!(
            set("eth0", [1, HWTSTAMP_TX_OFF, HWTSTAMP_FILTER_NONE]),
            Ok([1, 0, 0])
        );
    });
}

/// A driver offering only some PTP filters (an 82576: v1 sync and delay-request, all v2 events)
/// widens to the narrowest it has and refuses what none covers.
#[test]
fn a_filter_widens_to_the_narrowest_the_driver_offers() {
    let filters = 1 << HWTSTAMP_FILTER_NONE
        | 1 << HWTSTAMP_FILTER_PTP_V1_L4_SYNC
        | 1 << 5
        | 1 << HWTSTAMP_FILTER_PTP_V2_EVENT;
    let nic = Nic::new("eth0", 2)
        .hardware_timestamping(true)
        .timestamping_caps(0x5f, 0b11, filters);
    let host = HostProfile::new().nic(nic).cap(CAP_NET_ADMIN).build();
    Sim::builder().host(host).build().run(|| {
        let with = |rx| set("eth0", [0, HWTSTAMP_TX_ON, rx]).map(|c| c[2]);
        assert_eq!(
            with(HWTSTAMP_FILTER_PTP_V1_L4_SYNC),
            Ok(HWTSTAMP_FILTER_PTP_V1_L4_SYNC)
        );
        assert_eq!(
            with(HWTSTAMP_FILTER_PTP_V2_L4_EVENT),
            Ok(HWTSTAMP_FILTER_PTP_V2_EVENT)
        );
        assert_eq!(with(HWTSTAMP_FILTER_PTP_V1_L4_EVENT), Err(libc::ERANGE));
        assert_eq!(with(HWTSTAMP_FILTER_ALL), Err(libc::ERANGE));
    });
}

#[test]
fn captured_filter_results_override_capability_inference() {
    let nic = Nic::new("eth0", 2)
        .hardware_timestamping(true)
        .timestamping_caps(0x5f, 0b11, 1 << HWTSTAMP_FILTER_ALL | 1 << 7)
        .hwtstamp_rx_mapping(7, Ok(HWTSTAMP_FILTER_PTP_V2_EVENT))
        .unwrap()
        .hwtstamp_rx_mapping(HWTSTAMP_FILTER_PTP_V1_L4_EVENT, Err(libc::EBUSY))
        .unwrap();
    let host = HostProfile::new().nic(nic).cap(CAP_NET_ADMIN).build();
    Sim::builder().host(host).build().run(|| {
        let applied = [0, HWTSTAMP_TX_ON, HWTSTAMP_FILTER_PTP_V2_EVENT];
        assert_eq!(set("eth0", [0, HWTSTAMP_TX_ON, 7]), Ok(applied));
        assert_eq!(get("eth0"), Ok(applied));
        assert_eq!(
            set("eth0", [0, HWTSTAMP_TX_ON, HWTSTAMP_FILTER_PTP_V1_L4_EVENT]),
            Err(libc::EBUSY)
        );
        assert_eq!(get("eth0"), Ok(applied));
        assert_eq!(
            set("eth0", [2, HWTSTAMP_TX_ON, HWTSTAMP_FILTER_PTP_V1_L4_EVENT]),
            Err(libc::EINVAL)
        );
        assert_eq!(
            set(
                "eth0",
                [0, HWTSTAMP_TX_ONESTEP_SYNC, HWTSTAMP_FILTER_PTP_V1_L4_EVENT]
            ),
            Err(libc::ERANGE)
        );
        assert_eq!(get("eth0"), Ok(applied));
        assert_eq!(
            set("eth0", [0, HWTSTAMP_TX_OFF, HWTSTAMP_FILTER_NTP_ALL]),
            Ok([0, HWTSTAMP_TX_OFF, HWTSTAMP_FILTER_ALL])
        );
        assert_eq!(
            set("eth0", [0, HWTSTAMP_TX_OFF, HWTSTAMP_FILTER_NONE]),
            Ok([0, HWTSTAMP_TX_OFF, HWTSTAMP_FILTER_NONE])
        );
    });
}

#[test]
fn captured_filter_results_reject_invalid_enums_and_errnos() {
    for (requested, applied) in [
        (-1, Ok(0)),
        (16, Ok(0)),
        (0, Ok(-1)),
        (0, Ok(16)),
        (0, Err(0)),
        (0, Err(-libc::EBUSY)),
    ] {
        assert_eq!(
            Nic::new("eth0", 2)
                .hwtstamp_rx_mapping(requested, applied)
                .err()
                .unwrap()
                .raw_os_error(),
            Some(libc::EINVAL)
        );
    }
}

/// A host with an I210-like NIC on 192.168.9.0/24 and a station at .20 on its segment.
fn stamping_host(cfg: [i32; 3]) -> std::sync::Arc<snare::SimHost> {
    let nic = Nic::new("eth0", 2)
        .network("192.168.9.10/24".parse::<IpNet>().unwrap())
        .station("192.168.9.20".parse::<std::net::IpAddr>().unwrap())
        .hardware_timestamping(true)
        .ptp_index(0)
        .hwtstamp_config(cfg[0], cfg[1], cfg[2]);
    HostProfile::new()
        .nic(nic)
        .ptp_clock_offset(0, 5_000)
        .build()
}

/// Every error-queue entry of `fd` as (filled `scm_timestamping` slots, `ee_info` stage).
fn error_queue(fd: i32) -> Vec<([bool; 3], u32)> {
    let mut out = Vec::new();
    loop {
        let mut buf = [0u8; 256];
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        let mut control = [0u8; 512];
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = control.len();
        if unsafe { libc::recvmsg(fd, &mut msg, libc::MSG_ERRQUEUE | libc::MSG_DONTWAIT) } < 0 {
            return out;
        }
        let (mut slots, mut stage) = ([false; 3], u32::MAX);
        let mut c = unsafe { libc::CMSG_FIRSTHDR(&msg) };
        while !c.is_null() {
            let data = unsafe { libc::CMSG_DATA(c) };
            match unsafe { ((*c).cmsg_level, (*c).cmsg_type) } {
                (libc::SOL_SOCKET, SO_TIMESTAMPING) => {
                    slots = std::array::from_fn(|i| {
                        let ts = unsafe { data.add(16 * i).cast::<[u64; 2]>().read_unaligned() };
                        ts != [0, 0]
                    })
                }
                (libc::SOL_IP, libc::IP_RECVERR) => {
                    stage = unsafe { data.add(8).cast::<u32>().read_unaligned() }
                }
                _ => {}
            }
            c = unsafe { libc::CMSG_NXTHDR(&msg, c) };
        }
        out.push((slots, stage));
    }
}

fn timestamping(sock: &UdpSocket, flags: u32) {
    let rc = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::SOL_SOCKET,
            SO_TIMESTAMPING,
            (&raw const flags).cast(),
            4,
        )
    };
    assert_eq!(rc, 0);
}

fn timestamp_messages(fd: i32, flags: i32) -> Vec<(i32, Vec<u8>)> {
    let mut buf = [0u8; 256];
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: buf.len(),
    };
    let mut control = [0u8; 512];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = control.len();
    assert!(unsafe { libc::recvmsg(fd, &mut msg, flags) } >= 0);
    let mut out = Vec::new();
    let mut c = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    while !c.is_null() {
        if unsafe { (*c).cmsg_level } == libc::SOL_SOCKET {
            let len = unsafe { (*c).cmsg_len } - unsafe { libc::CMSG_LEN(0) } as usize;
            let data = unsafe { std::slice::from_raw_parts(libc::CMSG_DATA(c), len) };
            out.push((unsafe { (*c).cmsg_type }, data.to_vec()));
        }
        c = unsafe { libc::CMSG_NXTHDR(&msg, c) };
    }
    out
}

fn stamp_ns(bytes: &[u8]) -> u128 {
    let seconds = i64::from_ne_bytes(bytes[..8].try_into().unwrap());
    let nanos = i64::from_ne_bytes(bytes[8..16].try_into().unwrap());
    seconds as u128 * 1_000_000_000 + nanos as u128
}

#[test]
fn receive_filters_match_ptp_versions_messages_and_ntp_port() {
    let mut v1_sync = [0u8; 34];
    v1_sync[1] = 1;
    let mut v1_delay = v1_sync;
    v1_delay[32] = 1;
    let mut v2_sync = [0u8; 34];
    v2_sync[1] = 2;
    let mut v2_delay = v2_sync;
    v2_delay[0] = 1;
    let mut v2_peer = v2_sync;
    v2_peer[0] = 3;
    let mut v2_general = v2_sync;
    v2_general[0] = 8;
    for filter in 0..16 {
        Sim::builder()
            .host(stamping_host([0, 0, filter]))
            .privileges(snare::Privileges::all())
            .build()
            .run(move || {
                let station = UdpSocket::bind("192.168.9.20:0").unwrap();
                for (port, payload, version, message) in [
                    (319, &v1_sync[..], 1, 0),
                    (319, &v1_delay[..], 1, 1),
                    (319, &v2_sync[..], 2, 0),
                    (319, &v2_delay[..], 2, 1),
                    (319, &v2_peer[..], 2, 3),
                    (319, &v2_general[..], 2, 8),
                    (319, &b"junk"[..], 0, 0),
                    (320, &v2_sync[..], 2, 0),
                    (123, &b"ntp"[..], 0, 0),
                    (7100, &v2_sync[..], 2, 0),
                ] {
                    let sock = UdpSocket::bind(("192.168.9.10", port)).unwrap();
                    timestamping(&sock, RAW_HARDWARE | RX_HARDWARE);
                    station
                        .send_to(payload, sock.local_addr().unwrap())
                        .unwrap();
                    let expected = match filter {
                        1 | 2 => true,
                        3 => port == 319 && version == 1 && message <= 1,
                        4 => port == 319 && version == 1 && message == 0,
                        5 => port == 319 && version == 1 && message == 1,
                        6 | 12 => port == 319 && version == 2 && message <= 3,
                        7 | 13 => port == 319 && version == 2 && message == 0,
                        8 | 14 => port == 319 && version == 2 && message == 1,
                        15 => port == 123,
                        _ => false,
                    };
                    let got = timestamp_messages(sock.as_raw_fd(), 0)
                        .iter()
                        .any(|(ty, data)| *ty == SO_TIMESTAMPING && stamp_ns(&data[32..]) != 0);
                    assert_eq!(
                        got, expected,
                        "filter={filter} port={port} version={version} message={message}"
                    );
                }
            });
    }
}

#[test]
fn hardware_tx_legacy_timestamp_is_the_error_queue_read_time() {
    for option in [libc::SO_TIMESTAMP, libc::SO_TIMESTAMPNS] {
        Sim::builder()
            .host(stamping_host([0, HWTSTAMP_TX_ON, 0]))
            .build()
            .run(move || {
                let sock = UdpSocket::bind("192.168.9.10:0").unwrap();
                let _peer = UdpSocket::bind("192.168.9.20:7100").unwrap();
                let on = 1i32;
                assert_eq!(
                    unsafe {
                        libc::setsockopt(
                            sock.as_raw_fd(),
                            libc::SOL_SOCKET,
                            option,
                            (&raw const on).cast(),
                            4,
                        )
                    },
                    0
                );
                timestamping(&sock, TX_HARDWARE | RAW_HARDWARE | SOFTWARE | OPT_TSONLY);
                sock.send_to(b"ptp", "192.168.9.20:7100").unwrap();
                std::thread::sleep(std::time::Duration::from_millis(20));
                let now = || {
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_nanos()
                };
                let before = now();
                let messages = timestamp_messages(sock.as_raw_fd(), libc::MSG_ERRQUEUE);
                let after = now();
                let legacy = &messages.iter().find(|(ty, _)| *ty == option).unwrap().1;
                let software = &messages
                    .iter()
                    .find(|(ty, _)| *ty == SO_TIMESTAMPING)
                    .unwrap()
                    .1;
                let sw = stamp_ns(software);
                assert!((before..=after).contains(&sw));
                let seconds = i64::from_ne_bytes(legacy[..8].try_into().unwrap()) as u128;
                let fraction = i64::from_ne_bytes(legacy[8..16].try_into().unwrap()) as u128;
                let scale = if option == libc::SO_TIMESTAMP {
                    1_000
                } else {
                    1
                };
                let legacy_ns = seconds * 1_000_000_000 + fraction * scale;
                assert!(sw >= legacy_ns && sw - legacy_ns < 1_000);
                assert!(sw > stamp_ns(&software[32..]) + 19_000_000);
            });
    }
}

/// `__skb_tstamp_tx`: with `TX_HARDWARE` on a NIC whose `tx_type` is on, the driver's report
/// carries only `ts[2]`, and the driver marking the packet in progress drops the software report
/// unless `OPT_TX_SWHW` asks for both; with transmit stamps off in the NIC only the software one
/// comes.
#[test]
fn transmit_reports_carry_the_hardware_stamp() {
    let sends = |cfg: [i32; 3], flags: u32| {
        Sim::builder()
            .host(stamping_host(cfg))
            .build()
            .run(move || {
                let sock = UdpSocket::bind("192.168.9.10:0").unwrap();
                let _peer = UdpSocket::bind("192.168.9.20:7100").unwrap();
                timestamping(&sock, flags);
                sock.send_to(b"ptp", "192.168.9.20:7100").unwrap();
                error_queue(sock.as_raw_fd())
            })
    };
    let on = [0, HWTSTAMP_TX_ON, HWTSTAMP_FILTER_NONE];
    let hw = TX_HARDWARE | RAW_HARDWARE | OPT_TSONLY;
    let sw = TX_SOFTWARE | SOFTWARE;
    assert_eq!(sends(on, hw), vec![([false, false, true], 0)]);
    assert_eq!(sends(on, hw | sw), vec![([false, false, true], 0)]);
    assert_eq!(
        sends(on, hw | sw | OPT_TX_SWHW),
        vec![([true, false, false], 0), ([false, false, true], 0)]
    );
    assert_eq!(sends([0; 3], hw | sw), vec![([true, false, false], 0)]);
    assert_eq!(
        sends(on, TX_HARDWARE | sw),
        vec![([false; 3], 0)],
        "a hardware report without RAW_HARDWARE has no SCM_TIMESTAMPING"
    );
}

#[test]
fn one_step_messages_suppress_only_the_hardware_report() {
    for deterministic in [false, true] {
        for mode in 0..4 {
            let nic = Nic::new("eth0", 2)
                .network("192.168.9.10/24".parse::<IpNet>().unwrap())
                .station("192.168.9.20".parse::<std::net::IpAddr>().unwrap())
                .hardware_timestamping(true)
                .timestamping_caps(0x5f, 0b1111, 0b11);
            let host = HostProfile::new().nic(nic).cap(CAP_NET_ADMIN).build();
            let builder = Sim::builder()
                .host(host)
                .privileges(snare::Privileges::all());
            let sim = if deterministic {
                builder.deterministic().build()
            } else {
                builder.build()
            };
            sim.run(|| {
                assert_eq!(set("eth0", [0, mode, HWTSTAMP_FILTER_NONE]), Ok([0, mode, 0]));
                let sock = UdpSocket::bind("192.168.9.10:0").unwrap();
                for (port, message, version, two_step, length) in [
                    (319, 0, 2, false, 44),
                    (319, 3, 2, false, 54),
                    (319, 1, 2, false, 44),
                    (319, 0, 2, true, 44),
                    (319, 3, 2, true, 54),
                    (319, 0, 1, false, 44),
                    (319, 0, 2, false, 34),
                    (319, 3, 2, false, 44),
                    (320, 0, 2, false, 44),
                ] {
                    let peer = UdpSocket::bind(("192.168.9.20", port)).unwrap();
                    let mut payload = vec![0u8; length];
                    payload[0] = message;
                    payload[1] = version;
                    payload[2..4].copy_from_slice(&(length as u16).to_be_bytes());
                    payload[6] = u8::from(two_step) * 2;
                    let inline = port == 319
                        && version == 2
                        && !two_step
                        && (message == 0 && length >= 44 && mode >= 2
                            || message == 3 && length >= 54 && mode == 3);
                    for software in [false, true] {
                        timestamping(
                            &sock,
                            TX_HARDWARE | RAW_HARDWARE | OPT_TSONLY
                                | if software { TX_SOFTWARE | SOFTWARE } else { 0 },
                        );
                        sock.send_to(&payload, peer.local_addr().unwrap()).unwrap();
                        let reports = error_queue(sock.as_raw_fd());
                        let expected = if mode != 0 && !inline {
                            vec![([false, false, true], 0)]
                        } else if software {
                            vec![([true, false, false], 0)]
                        } else {
                            vec![]
                        };
                        assert_eq!(
                            reports, expected,
                            "det={deterministic} mode={mode} port={port} message={message} version={version} two_step={two_step} len={length} sw={software}"
                        );
                        let mut received = [0u8; 64];
                        peer.recv(&mut received).unwrap();
                    }
                }
            });
        }
    }
}

/// `__sock_recv_timestamp`: a datagram the NIC stamped (`rx_filter` `ALL`) carries the stamp on
/// the NIC's clock in `ts[2]` for a socket reporting `RAW_HARDWARE`; under `OPT_RX_FILTER` only
/// with `RX_HARDWARE` too; and without a filter in the NIC, none.
#[test]
fn received_datagrams_carry_the_nic_stamp() {
    let receive = |cfg: [i32; 3], flags: u32| {
        Sim::builder()
            .host(stamping_host(cfg))
            .build()
            .run(move || {
                let sock = UdpSocket::bind("192.168.9.10:7200").unwrap();
                let station = UdpSocket::bind("192.168.9.20:0").unwrap();
                timestamping(&sock, flags);
                station.send_to(b"sync", "192.168.9.10:7200").unwrap();
                let mut buf = [0u8; 64];
                let mut iov = libc::iovec {
                    iov_base: buf.as_mut_ptr().cast(),
                    iov_len: buf.len(),
                };
                let mut control = [0u8; 256];
                let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
                msg.msg_iov = &mut iov;
                msg.msg_iovlen = 1;
                msg.msg_control = control.as_mut_ptr().cast();
                msg.msg_controllen = control.len();
                assert!(unsafe { libc::recvmsg(sock.as_raw_fd(), &mut msg, 0) } > 0);
                let c = unsafe { libc::CMSG_FIRSTHDR(&msg) };
                if c.is_null() {
                    return None;
                }
                let data = unsafe { libc::CMSG_DATA(c) };
                let ts: [[i64; 2]; 3] = unsafe { data.cast::<[[i64; 2]; 3]>().read_unaligned() };
                Some(ts.map(|[s, ns]| s as i128 * 1_000_000_000 + ns as i128))
            })
    };
    let all = [0, HWTSTAMP_TX_OFF, HWTSTAMP_FILTER_ALL];
    let ts = receive(all, RAW_HARDWARE | SOFTWARE).expect("SCM_TIMESTAMPING");
    assert_eq!(ts[2] - ts[0], 5_000, "the stamp is on the PHC, 5 µs ahead");
    assert_eq!(receive(all, RAW_HARDWARE | OPT_RX_FILTER), None);
    assert!(receive(all, RAW_HARDWARE | RX_HARDWARE | OPT_RX_FILTER).is_some_and(|t| t[2] != 0));
    assert_eq!(
        receive([0; 3], RAW_HARDWARE),
        None,
        "the NIC stamps nothing"
    );
}
