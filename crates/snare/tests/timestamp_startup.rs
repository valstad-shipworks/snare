#![cfg(target_os = "linux")]

use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream, UdpSocket};
use std::os::fd::AsRawFd;
use std::time::Duration;

use snare::{HostProfile, IpNet, Nic, Sim};

const STARTUP: Duration = Duration::from_millis(10);
const RX_SOFTWARE: i32 = 1 << 3;
const SOFTWARE: i32 = 1 << 4;
const TX_SOFTWARE: i32 = 1 << 1;
const RX_HARDWARE: i32 = 1 << 2;
const RAW_HARDWARE: i32 = 1 << 6;

#[repr(align(8))]
struct Control([u8; 256]);

#[derive(Debug, PartialEq, Eq)]
struct Packet {
    bytes: Vec<u8>,
    stamps: Vec<(i32, Vec<Duration>)>,
}

fn set(socket: &impl AsRawFd, option: i32, value: i32) -> Result<(), i32> {
    set_len(socket, option, value, size_of::<i32>() as libc::socklen_t)
}

fn set_len(
    socket: &impl AsRawFd,
    option: i32,
    value: i32,
    len: libc::socklen_t,
) -> Result<(), i32> {
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            option,
            (&value as *const i32).cast(),
            len,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error().raw_os_error().unwrap())
    }
}

fn receive(socket: &impl AsRawFd, flags: i32) -> Packet {
    let mut bytes = [0; 16];
    let mut control = Control([0; 256]);
    let mut iov = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.0.as_mut_ptr().cast();
    message.msg_controllen = control.0.len();
    let count =
        unsafe { libc::recvmsg(socket.as_raw_fd(), &mut message, flags | libc::MSG_DONTWAIT) };
    assert!(count >= 0, "{}", std::io::Error::last_os_error());
    assert_eq!(message.msg_flags & libc::MSG_CTRUNC, 0);
    let mut stamps = Vec::new();
    let mut header = unsafe { libc::CMSG_FIRSTHDR(&message) };
    while !header.is_null() {
        let (level, kind) = unsafe { ((*header).cmsg_level, (*header).cmsg_type) };
        if level == libc::SOL_SOCKET {
            let data = unsafe { libc::CMSG_DATA(header) };
            let timestamp = |offset: usize| {
                let value = unsafe { data.add(offset).cast::<libc::timespec>().read_unaligned() };
                Duration::new(value.tv_sec as u64, value.tv_nsec as u32)
            };
            if kind == libc::SCM_TIMESTAMPING {
                stamps.push((
                    kind,
                    (0..3)
                        .map(|slot| timestamp(slot * size_of::<libc::timespec>()))
                        .collect(),
                ));
            } else if kind == libc::SCM_TIMESTAMPNS {
                stamps.push((kind, vec![timestamp(0)]));
            } else if kind == libc::SCM_TIMESTAMP {
                let value = unsafe { data.cast::<libc::timeval>().read_unaligned() };
                stamps.push((
                    kind,
                    vec![Duration::new(
                        value.tv_sec as u64,
                        value.tv_usec as u32 * 1_000,
                    )],
                ));
            }
        }
        header = unsafe { libc::CMSG_NXTHDR(&message, header) };
    }
    Packet {
        bytes: bytes[..count as usize].to_vec(),
        stamps,
    }
}

fn realtime() -> Duration {
    let mut value: libc::timespec = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut value) },
        0
    );
    Duration::new(value.tv_sec as u64, value.tv_nsec as u32)
}

fn pair() -> (UdpSocket, UdpSocket) {
    (
        UdpSocket::bind("127.0.0.1:0").unwrap(),
        UdpSocket::bind("127.0.0.1:0").unwrap(),
    )
}

fn send(sender: &UdpSocket, receiver: &UdpSocket, bytes: &[u8]) {
    assert_eq!(
        sender
            .send_to(bytes, receiver.local_addr().unwrap())
            .unwrap(),
        bytes.len()
    );
}

fn assert_software(packet: &Packet, expected: Option<Duration>) {
    let expected: Vec<_> = expected
        .into_iter()
        .map(|at| {
            (
                libc::SCM_TIMESTAMPING,
                vec![at, Duration::ZERO, Duration::ZERO],
            )
        })
        .collect();
    assert_eq!(packet.stamps, expected);
}

fn scenarios(delay: Duration, test: impl Fn(&Sim)) {
    for deterministic in [false, true] {
        for host in [false, true] {
            let mut builder = Sim::builder().rx_timestamp_startup_delay(delay);
            if deterministic {
                builder = builder.deterministic();
            }
            if host {
                builder = builder.host(HostProfile::new().build());
            }
            let sim = builder.build();
            sim.pause_time();
            sim.run(|| test(&sim));
        }
    }
}

#[test]
fn the_default_generates_software_timestamps_immediately() {
    scenarios(Duration::ZERO, |_| {
        let (receiver, sender) = pair();
        set(&receiver, libc::SO_TIMESTAMPING, RX_SOFTWARE | SOFTWARE).unwrap();
        let at = realtime();
        send(&sender, &receiver, b"warm");
        assert_software(&receive(&receiver, 0), Some(at));
    });
}

#[test]
fn cold_packets_stay_cold_when_read_or_peeked_after_activation() {
    scenarios(STARTUP, |sim| {
        let (receiver, sender) = pair();
        set(&receiver, libc::SO_TIMESTAMPING, RX_SOFTWARE | SOFTWARE).unwrap();
        send(&sender, &receiver, b"cold");
        sim.advance_time(STARTUP);
        for flags in [libc::MSG_PEEK, libc::MSG_PEEK, 0] {
            let packet = receive(&receiver, flags);
            assert_eq!(packet.bytes, b"cold");
            assert_software(&packet, None);
        }
        let at = realtime();
        send(&sender, &receiver, b"warm");
        let first = receive(&receiver, libc::MSG_PEEK);
        assert_software(&first, Some(at));
        assert_eq!(receive(&receiver, libc::MSG_PEEK), first);
        assert_eq!(receive(&receiver, 0), first);
    });
}

#[test]
fn generation_uses_the_packet_arrival_including_the_activation_boundary() {
    scenarios(STARTUP, |sim| {
        let (receiver, sender) = pair();
        set(&receiver, libc::SO_TIMESTAMPING, RX_SOFTWARE | SOFTWARE).unwrap();
        let start = realtime();
        sim.set_udp_policy(receiver.local_addr().unwrap(), |policy| {
            policy.latency = STARTUP / 2
        });
        send(&sender, &receiver, b"before");
        sim.set_udp_policy(receiver.local_addr().unwrap(), |policy| {
            policy.latency = STARTUP
        });
        send(&sender, &receiver, b"boundary");
        sim.advance_time(STARTUP * 2);
        let cold = receive(&receiver, 0);
        assert_eq!(cold.bytes, b"before");
        assert_software(&cold, None);
        let warm = receive(&receiver, 0);
        assert_eq!(warm.bytes, b"boundary");
        assert_software(&warm, Some(start + STARTUP));
    });
}

#[test]
fn the_first_successful_generation_request_starts_one_sim_wide_window() {
    scenarios(STARTUP, |sim| {
        let (first, sender) = pair();
        let second = UdpSocket::bind("127.0.0.1:0").unwrap();
        set(&first, libc::SO_TIMESTAMPING, RX_SOFTWARE | SOFTWARE).unwrap();
        sim.advance_time(STARTUP / 2);
        set(&second, libc::SO_TIMESTAMPING, RX_SOFTWARE | SOFTWARE).unwrap();
        set(&first, libc::SO_TIMESTAMPING, 0).unwrap();
        set(&first, libc::SO_TIMESTAMPING, RX_SOFTWARE | SOFTWARE).unwrap();
        sim.advance_time(STARTUP / 2);
        let at = realtime();
        for receiver in [&first, &second] {
            send(&sender, receiver, b"warm");
            assert_software(&receive(receiver, 0), Some(at));
        }
    });
}

#[test]
fn invalid_and_reporting_only_options_do_not_start_generation() {
    scenarios(STARTUP, |sim| {
        let (receiver, sender) = pair();
        assert_eq!(
            set_len(&receiver, libc::SO_TIMESTAMPNS, 1, 2),
            Err(libc::EINVAL)
        );
        assert_eq!(
            set(
                &receiver,
                libc::SO_TIMESTAMPING,
                RX_SOFTWARE | SOFTWARE | (1 << 30)
            ),
            Err(libc::EINVAL)
        );
        set(&receiver, libc::SO_TIMESTAMPING, SOFTWARE).unwrap();
        sim.advance_time(STARTUP * 2);
        set(&receiver, libc::SO_TIMESTAMPING, RX_SOFTWARE | SOFTWARE).unwrap();
        send(&sender, &receiver, b"cold");
        assert_software(&receive(&receiver, 0), None);
        sim.advance_time(STARTUP);
        let at = realtime();
        send(&sender, &receiver, b"warm");
        assert_software(&receive(&receiver, 0), Some(at));
    });
}

#[test]
fn generation_without_reporting_starts_the_window() {
    scenarios(STARTUP, |sim| {
        let (receiver, sender) = pair();
        set(&receiver, libc::SO_TIMESTAMPING, RX_SOFTWARE).unwrap();
        sim.advance_time(STARTUP);
        set(&receiver, libc::SO_TIMESTAMPING, RX_SOFTWARE | SOFTWARE).unwrap();
        let at = realtime();
        send(&sender, &receiver, b"warm");
        assert_software(&receive(&receiver, 0), Some(at));
    });
}

#[test]
fn legacy_datagram_fallback_is_cached_by_the_first_peek() {
    for legacy in [libc::SO_TIMESTAMP, libc::SO_TIMESTAMPNS] {
        scenarios(STARTUP, |sim| {
            let (receiver, sender) = pair();
            set(&receiver, legacy, 1).unwrap();
            set(&receiver, libc::SO_TIMESTAMPING, RX_SOFTWARE | SOFTWARE).unwrap();
            send(&sender, &receiver, b"cold");
            sim.advance_time(STARTUP * 2);
            let fallback = realtime();
            let first = receive(&receiver, libc::MSG_PEEK);
            assert_eq!(first.bytes, b"cold");
            assert_eq!(
                first.stamps,
                [
                    (legacy, vec![fallback]),
                    (
                        libc::SCM_TIMESTAMPING,
                        vec![fallback, Duration::ZERO, Duration::ZERO]
                    ),
                ]
            );
            sim.advance_time(STARTUP * 2);
            assert_eq!(receive(&receiver, libc::MSG_PEEK), first);
            assert_eq!(receive(&receiver, 0), first);
        });
    }
}

#[test]
fn a_plain_datagram_peek_initializes_the_legacy_fallback_stamp() {
    for legacy in [libc::SO_TIMESTAMP, libc::SO_TIMESTAMPNS] {
        for (receive_from, capacity) in [(false, 0usize), (false, 16), (true, 0), (true, 16)] {
            scenarios(STARTUP, |sim| {
                let (receiver, sender) = pair();
                set(&receiver, legacy, 1).unwrap();
                set(&receiver, libc::SO_TIMESTAMPING, RX_SOFTWARE | SOFTWARE).unwrap();
                send(&sender, &receiver, b"cold");
                sim.advance_time(STARTUP * 2);
                let fallback = realtime();
                let mut bytes = [0; 16];
                let count = unsafe {
                    if receive_from {
                        let mut address: libc::sockaddr_storage = std::mem::zeroed();
                        let mut len = size_of_val(&address) as libc::socklen_t;
                        libc::recvfrom(
                            receiver.as_raw_fd(),
                            bytes.as_mut_ptr().cast(),
                            capacity,
                            libc::MSG_PEEK | libc::MSG_DONTWAIT,
                            (&raw mut address).cast(),
                            &mut len,
                        )
                    } else {
                        libc::recv(
                            receiver.as_raw_fd(),
                            bytes.as_mut_ptr().cast(),
                            capacity,
                            libc::MSG_PEEK | libc::MSG_DONTWAIT,
                        )
                    }
                };
                assert_eq!(count, capacity.min(4) as isize);
                assert_eq!(&bytes[..count as usize], &b"cold"[..capacity.min(4)]);
                sim.advance_time(STARTUP * 2);
                let packet = receive(&receiver, 0);
                assert_eq!(packet.bytes, b"cold");
                assert_eq!(
                    packet.stamps,
                    [
                        (legacy, vec![fallback]),
                        (
                            libc::SCM_TIMESTAMPING,
                            vec![fallback, Duration::ZERO, Duration::ZERO]
                        ),
                    ]
                );
            });
        }
    }
}

#[test]
fn legacy_generation_starts_the_window_before_modern_reporting_is_enabled() {
    for legacy in [libc::SO_TIMESTAMP, libc::SO_TIMESTAMPNS] {
        scenarios(STARTUP, |sim| {
            let (receiver, sender) = pair();
            set(&receiver, legacy, 1).unwrap();
            sim.advance_time(STARTUP / 2);
            set(&receiver, legacy, 0).unwrap();
            set(&receiver, libc::SO_TIMESTAMPING, RX_SOFTWARE | SOFTWARE).unwrap();
            sim.advance_time(STARTUP / 2);
            let at = realtime();
            send(&sender, &receiver, b"warm");
            sim.advance_time(STARTUP);
            assert_software(&receive(&receiver, 0), Some(at));
        });
    }
}

#[test]
fn disabling_legacy_reporting_does_not_discard_a_peeks_fallback_stamp() {
    scenarios(STARTUP, |sim| {
        let (receiver, sender) = pair();
        set(&receiver, libc::SO_TIMESTAMPNS, 1).unwrap();
        set(&receiver, libc::SO_TIMESTAMPING, RX_SOFTWARE | SOFTWARE).unwrap();
        send(&sender, &receiver, b"cold");
        sim.advance_time(STARTUP * 2);
        let at = realtime();
        let first = receive(&receiver, libc::MSG_PEEK);
        assert_eq!(first.stamps[0], (libc::SCM_TIMESTAMPNS, vec![at]));
        set(&receiver, libc::SO_TIMESTAMPNS, 0).unwrap();
        sim.advance_time(STARTUP);
        for flags in [libc::MSG_PEEK, 0] {
            let packet = receive(&receiver, flags);
            assert_eq!(packet.bytes, b"cold");
            assert_software(&packet, Some(at));
        }
    });
}

#[test]
fn legacy_stream_timestamps_do_not_synthesize_a_stamp_for_cold_data() {
    scenarios(STARTUP, |sim| {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let mut sender = TcpStream::connect(address).unwrap();
        let (receiver, _) = listener.accept().unwrap();
        set(&receiver, libc::SO_TIMESTAMPNS, 1).unwrap();
        set(&receiver, libc::SO_TIMESTAMPING, RX_SOFTWARE | SOFTWARE).unwrap();
        sim.set_tcp_policy(address, |policy| policy.latency = STARTUP / 2);
        sender.write_all(b"cold").unwrap();
        sim.advance_time(STARTUP * 2);
        for flags in [libc::MSG_PEEK, 0] {
            let packet = receive(&receiver, flags);
            assert_eq!(packet.bytes, b"cold");
            assert!(packet.stamps.is_empty(), "{packet:?}");
        }
        let sent = realtime();
        sender.write_all(b"warm").unwrap();
        sim.advance_time(STARTUP);
        let packet = receive(&receiver, 0);
        let at = sent + STARTUP / 2;
        assert_eq!(packet.bytes, b"warm");
        assert_eq!(
            packet.stamps,
            [
                (libc::SCM_TIMESTAMPNS, vec![at]),
                (
                    libc::SCM_TIMESTAMPING,
                    vec![at, Duration::ZERO, Duration::ZERO]
                ),
            ]
        );
    });
}

#[test]
fn a_new_sim_has_its_own_startup_window() {
    let warm = Sim::builder().rx_timestamp_startup_delay(STARTUP).build();
    warm.pause_time();
    warm.run(|| {
        let (receiver, sender) = pair();
        set(&receiver, libc::SO_TIMESTAMPING, RX_SOFTWARE | SOFTWARE).unwrap();
        warm.advance_time(STARTUP);
        send(&sender, &receiver, b"warm");
        assert_software(&receive(&receiver, 0), Some(realtime()));
    });
    scenarios(STARTUP, |_| {
        let (receiver, sender) = pair();
        set(&receiver, libc::SO_TIMESTAMPING, RX_SOFTWARE | SOFTWARE).unwrap();
        send(&sender, &receiver, b"cold");
        assert_software(&receive(&receiver, 0), None);
    });
}

#[test]
fn transmit_timestamps_do_not_wait_for_receive_startup_or_start_it() {
    scenarios(STARTUP, |sim| {
        let (receiver, sender) = pair();
        set(&sender, libc::SO_TIMESTAMPING, TX_SOFTWARE | SOFTWARE).unwrap();
        let at = realtime();
        send(&sender, &receiver, b"tx");
        assert_software(&receive(&sender, libc::MSG_ERRQUEUE), Some(at));
        receive(&receiver, 0);
        sim.advance_time(STARTUP * 2);
        set(&receiver, libc::SO_TIMESTAMPING, RX_SOFTWARE | SOFTWARE).unwrap();
        send(&sender, &receiver, b"cold");
        assert_software(&receive(&receiver, 0), None);
    });
}

#[test]
fn hardware_receive_timestamps_do_not_wait_for_software_startup() {
    for deterministic in [false, true] {
        let address = Ipv4Addr::new(10, 0, 0, 1);
        let station = Ipv4Addr::new(10, 0, 0, 2);
        let host = HostProfile::new()
            .ptp_clock(0)
            .nic(
                Nic::new("eth0", 2)
                    .network("10.0.0.1/24".parse::<IpNet>().unwrap())
                    .station(IpAddr::V4(station))
                    .ptp_index(0)
                    .hardware_timestamping(true)
                    .hwtstamp_config(0, 1, 1),
            )
            .build();
        let mut builder = Sim::builder()
            .host(host)
            .rx_timestamp_startup_delay(STARTUP);
        if deterministic {
            builder = builder.deterministic();
        }
        let sim = builder.build();
        sim.pause_time();
        sim.run(|| {
            let receiver = UdpSocket::bind((address, 0)).unwrap();
            let sender = UdpSocket::bind((station, 0)).unwrap();
            set(&receiver, libc::SO_TIMESTAMPING, RX_HARDWARE | RAW_HARDWARE).unwrap();
            let at = realtime();
            send(&sender, &receiver, b"hardware");
            let packet = receive(&receiver, 0);
            assert_eq!(
                packet.stamps,
                [(
                    libc::SCM_TIMESTAMPING,
                    vec![Duration::ZERO, Duration::ZERO, at]
                )]
            );
            sim.advance_time(STARTUP * 2);
            set(
                &receiver,
                libc::SO_TIMESTAMPING,
                RX_HARDWARE | RAW_HARDWARE | RX_SOFTWARE | SOFTWARE,
            )
            .unwrap();
            let at = realtime();
            send(&sender, &receiver, b"still cold");
            let packet = receive(&receiver, 0);
            assert_eq!(
                packet.stamps,
                [(
                    libc::SCM_TIMESTAMPING,
                    vec![Duration::ZERO, Duration::ZERO, at]
                )]
            );
        });
    }
}
