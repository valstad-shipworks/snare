//! fast-talker's `TimestampedStream` over snare's TCP streams: receive
//! stamps on the virtual clock, send stages, connection info.

use std::io::{self, Write};
use std::time::{Duration, SystemTime};

use snare::fast_talker::sim;
use snare::fast_talker::tcp::{Stage, TimestampedStream, TxEvent};
use snare::fast_talker::{Config, Hardware, Source, Timestamp, compat};
use snare::net::{TcpListener, TcpStream};
use snare::{
    IpNet, NicSpec, OsSemantics, add_nic, advance_time, pause_time, register_test, set_link,
    set_nic_policy, set_os_semantics, set_tcp_inbound_latency, socket_id,
};

const ALL: [OsSemantics; 3] = [OsSemantics::Linux, OsSemantics::MacOs, OsSemantics::Windows];
const SERVER: &str = "10.0.0.1:7000";
const LATENCY: Duration = Duration::from_millis(5);

fn net(s: &str) -> IpNet {
    s.parse().unwrap()
}

/// A fresh slot on `os` with a paused clock and `eth0` at 10.0.0.1 with
/// 5 ms latency, and a connection over it: the client and the accepted
/// server end, which is nonblocking.
fn pair(os: OsSemantics) -> (TcpStream, TcpStream) {
    register_test();
    set_os_semantics(os);
    pause_time();
    add_nic(NicSpec::new("eth0").address(net("10.0.0.1/24"))).unwrap();
    set_nic_policy("eth0", |p| p.latency = LATENCY).unwrap();
    let listener = TcpListener::bind(SERVER).unwrap();
    let client = TcpStream::connect(SERVER).unwrap();
    let (server, _) = listener.accept().unwrap();
    server.set_nonblocking(true).unwrap();
    (client, server)
}

fn config(transmit: bool) -> Config {
    Config {
        hardware: Hardware::Off,
        transmit,
        ..Config::default()
    }
}

fn recv(s: &TimestampedStream<TcpStream>, len: usize) -> (Vec<u8>, Timestamp) {
    let mut buf = vec![0u8; len];
    let (n, t) = s.recv(&mut buf).unwrap();
    buf.truncate(n);
    (buf, t)
}

fn events(s: &TimestampedStream<TcpStream>) -> Vec<(u32, Stage, SystemTime, Source)> {
    let mut out: Vec<TxEvent> = Vec::new();
    let n = s.tx_events(&mut out).unwrap();
    assert_eq!(n, out.len());
    out.iter()
        .map(|e| (e.id, e.stage, e.timestamp.time, e.timestamp.source))
        .collect()
}

#[test]
fn a_read_is_stamped_with_the_arrival_of_its_newest_bytes() {
    let (mut client, server) = pair(OsSemantics::Linux);
    let server = TimestampedStream::try_with_config(server, config(false)).unwrap();
    assert_eq!(server.source(), Source::Kernel);
    let t1 = compat::now();
    client.write_all(b"ab").unwrap();
    advance_time(Duration::from_millis(1));
    let t2 = compat::now();
    client.write_all(b"cd").unwrap();
    advance_time(Duration::from_millis(10));

    let (data, t) = recv(&server, 1);
    assert_eq!(data, b"a");
    assert_eq!(t.time, t1 + LATENCY, "a partial read of the first chunk");
    assert_eq!(t.source, Source::Kernel);
    let (data, t) = recv(&server, 16);
    assert_eq!(data, b"bcd");
    assert_eq!(t.time, t2 + LATENCY, "one read over both chunks");

    let t3 = compat::now();
    client.write_all(b"ef").unwrap();
    client.write_all(b"gh").unwrap();
    advance_time(LATENCY);
    let (data, t) = recv(&server, 2);
    assert_eq!(data, b"ef");
    assert_eq!(t.time, t3 + LATENCY);
    assert_eq!(
        server.recv(&mut [0u8; 8]).unwrap().1.time,
        t3 + LATENCY,
        "bytes that waited to be read keep their arrival"
    );
    let e = server.recv(&mut [0u8; 8]).unwrap_err();
    assert_eq!(e.kind(), io::ErrorKind::WouldBlock);
}

#[test]
fn off_linux_reads_are_stamped_in_user_space_when_they_return() {
    for os in [OsSemantics::MacOs, OsSemantics::Windows] {
        let (mut client, server) = pair(os);
        let e = TimestampedStream::try_with_config(server.try_clone().unwrap(), config(false))
            .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::Unsupported, "{os}");
        let server = TimestampedStream::with_config(server, config(false));
        assert_eq!(server.source(), Source::UserSpace);
        client.write_all(b"ab").unwrap();
        advance_time(Duration::from_millis(20));
        let (data, t) = recv(&server, 8);
        assert_eq!(data, b"ab");
        assert_eq!(t.source, Source::UserSpace, "{os}");
        assert_eq!(t.time, compat::now(), "{os}");
    }
}

#[test]
fn drain_reads_until_it_would_block_and_never_waits() {
    let (mut client, server) = pair(OsSemantics::Linux);
    server.set_nonblocking(false).unwrap();
    let server = TimestampedStream::with_config(server, config(false));
    let mut buf = [0u8; 2];
    let mut got = Vec::new();
    assert_eq!(
        server.drain(&mut buf, |_, _| unreachable!()).unwrap(),
        0,
        "a blocking stream with nothing to read"
    );

    let mut sent = Vec::new();
    for chunk in [b"ab", b"cd", b"ef"] {
        sent.push(compat::now() + LATENCY);
        client.write_all(chunk).unwrap();
        advance_time(Duration::from_millis(1));
    }
    advance_time(LATENCY);
    let n = server
        .drain(&mut buf, |p, t| got.push((p.to_vec(), t.time)))
        .unwrap();
    assert_eq!(n, 3);
    assert_eq!(
        got,
        [
            (b"ab".to_vec(), sent[0]),
            (b"cd".to_vec(), sent[1]),
            (b"ef".to_vec(), sent[2])
        ]
    );

    client.write_all(b"gh").unwrap();
    drop(client);
    advance_time(LATENCY);
    got.clear();
    let n = server
        .drain(&mut [0u8; 64], |p, _| got.push((p.to_vec(), compat::now())))
        .unwrap();
    assert_eq!(n, 1, "stops at end of stream");
    assert_eq!(got[0].0, b"gh");
}

#[test]
fn send_ids_are_stream_offsets_and_linux_stamps_every_stage() {
    let (client, mut server) = pair(OsSemantics::Linux);
    let client = TimestampedStream::with_config(client, config(true));
    let t0 = compat::now();
    assert_eq!(client.send(b"abc").unwrap().id, Some(2));
    (&*client).write_all(b"d").unwrap();
    advance_time(Duration::from_millis(1));
    let t1 = compat::now();
    assert_eq!(
        client.send(b"ef").unwrap().id,
        Some(5),
        "the kernel's offsets count every write on the stream"
    );
    assert_eq!(
        events(&client),
        [
            (2, Stage::Scheduled, t0, Source::Kernel),
            (2, Stage::Sent, t0, Source::Kernel),
            (3, Stage::Scheduled, t0, Source::Kernel),
            (3, Stage::Sent, t0, Source::Kernel),
            (5, Stage::Scheduled, t1, Source::Kernel),
            (5, Stage::Sent, t1, Source::Kernel),
        ]
    );
    let rtt = client.info().unwrap().rtt;
    assert_eq!(rtt, LATENCY * 2);
    advance_time(rtt - Duration::from_millis(1));
    assert_eq!(
        events(&client),
        [
            (2, Stage::Acked, t0 + rtt, Source::Kernel),
            (3, Stage::Acked, t0 + rtt, Source::Kernel)
        ]
    );
    advance_time(Duration::from_millis(1));
    assert_eq!(
        events(&client),
        [(5, Stage::Acked, t1 + rtt, Source::Kernel)]
    );
    let mut buf = [0u8; 16];
    assert_eq!(io::Read::read(&mut server, &mut buf).unwrap(), 6);

    let snap = sim::socket(socket_id(&*client)).unwrap();
    assert!(snap.stream);
    assert_eq!(snap.timestamping, Some(config(true)));
    assert_eq!(snap.source, Some(Source::Kernel));
    assert_eq!(snap.tx_ids_issued, 3);
    assert_eq!(snap.pending_tx_stamps, 0);
    assert_eq!(snap.bytes_sent, 6);
    assert_eq!(sim::socket(socket_id(&server)).unwrap().bytes_received, 6);
    assert!(
        sim::sockets()
            .iter()
            .any(|s| s.stream && s.entry.id == snap.entry.id)
    );

    let plain = TimestampedStream::with_config(server, config(false));
    assert_eq!(plain.send(b"x").unwrap().id, None);
    assert!(events(&plain).is_empty());
}

#[test]
fn off_linux_only_sends_through_the_stream_are_stamped_once() {
    for os in [OsSemantics::MacOs, OsSemantics::Windows] {
        let (client, _server) = pair(os);
        let client = TimestampedStream::with_config(client, config(true));
        let t0 = compat::now();
        assert_eq!(client.send(b"abc").unwrap().id, Some(2), "{os}");
        (&*client).write_all(b"d").unwrap();
        assert_eq!(client.send(b"ef").unwrap().id, Some(4), "{os}");
        advance_time(Duration::from_millis(50));
        assert_eq!(
            events(&client),
            [
                (2, Stage::Sent, t0, Source::UserSpace),
                (4, Stage::Sent, t0, Source::UserSpace)
            ],
            "{os}"
        );
        let client = TimestampedStream::with_config(client.into_inner(), config(true));
        assert_eq!(
            client.send(b"g").unwrap().id,
            Some(0),
            "{os}: a new wrapper counts from zero"
        );
    }
}

#[test]
fn info_reports_the_round_trip_and_segment_size() {
    for os in ALL {
        let (client, server) = pair(os);
        snare::set_nic("eth0", |n| n.mtu = 9000).unwrap();
        set_nic_policy("eth0", |p| p.jitter = Duration::from_micros(1500)).unwrap();
        set_tcp_inbound_latency(client.local_addr().unwrap(), Duration::from_millis(2));
        set_tcp_inbound_latency(server.local_addr().unwrap(), Duration::from_millis(3));
        let client = TimestampedStream::new(client);
        let info = client.info().unwrap();
        let rtt = Duration::from_millis(2 + 3) + LATENCY * 2;
        assert_eq!(info.mss, 8960, "{os}");
        assert_eq!(info.cwnd, 10 * 8960, "{os}");
        assert_eq!(info.send_window, Some(65535), "{os}");
        assert_eq!(info.bytes_sent, Some(0), "{os}");
        match os {
            OsSemantics::Linux => {
                assert_eq!(info.rtt, rtt);
                assert_eq!(info.rtt_var, Some(Duration::from_micros(1500)));
                assert_eq!(info.min_rtt, Some(rtt));
                assert_eq!(info.rto, Some(Duration::from_millis(200)));
            }
            OsSemantics::MacOs => {
                assert_eq!(info.rtt, rtt);
                assert_eq!(
                    info.rtt_var,
                    Some(Duration::from_millis(1)),
                    "ms resolution"
                );
                assert_eq!(info.min_rtt, None);
                assert_eq!(info.rto, Some(Duration::from_secs(1)));
            }
            _ => {
                assert_eq!(info.rtt, rtt);
                assert_eq!(info.rtt_var, None);
                assert_eq!(info.min_rtt, Some(rtt));
                assert_eq!(info.rto, None);
            }
        }
        assert_eq!(compat::tcp_info(&client).unwrap(), info, "{os}");
    }
}

#[test]
fn info_counts_bytes_and_the_peers_window() {
    let (mut client, server) = pair(OsSemantics::Linux);
    snare::set_tcp_recv_window(server.local_addr().unwrap(), Some(100));
    client.write_all(&[0u8; 30]).unwrap();
    advance_time(LATENCY);
    let info = compat::tcp_info(&client).unwrap();
    assert_eq!(info.bytes_sent, Some(30));
    assert_eq!(info.send_window, Some(70));
    assert_eq!(compat::tcp_info(&server).unwrap().bytes_received, Some(30));
}

#[test]
fn bytes_held_on_a_downed_link_are_stamped_when_it_returns() {
    let (mut client, server) = pair(OsSemantics::Linux);
    let server = TimestampedStream::with_config(server, config(false));
    let client_ts = TimestampedStream::with_config(client.try_clone().unwrap(), config(true));
    set_link("eth0", false).unwrap();
    client.write_all(b"ab").unwrap();
    client_ts.send(b"c").unwrap();
    advance_time(Duration::from_millis(50));
    assert_eq!(
        server.recv(&mut [0u8; 8]).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    let up = compat::now();
    set_link("eth0", true).unwrap();
    advance_time(LATENCY);
    let (data, t) = recv(&server, 8);
    assert_eq!(data, b"abc");
    assert_eq!(t.time, up + LATENCY);
    let acked: Vec<_> = events(&client_ts)
        .into_iter()
        .filter(|(_, stage, _, _)| *stage != Stage::Scheduled && *stage != Stage::Sent)
        .collect();
    assert!(acked.is_empty(), "the ack is still on its way: {acked:?}");
    advance_time(LATENCY);
    assert_eq!(
        events(&client_ts),
        [
            (1, Stage::Acked, up + LATENCY * 2, Source::Kernel),
            (2, Stage::Acked, up + LATENCY * 2, Source::Kernel)
        ],
        "held bytes are acknowledged once they reach the peer"
    );
}

#[test]
fn raw_fd_paths_fail_cleanly_and_compat_works() {
    let (client, _server) = pair(OsSemantics::Linux);
    #[cfg(unix)]
    {
        let e = ::fast_talker::tcp::TcpInfo::of(&client).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::Unsupported);
        assert_eq!(e.raw_os_error(), None);
        assert!(e.to_string().contains("no OS socket (snare shim)"), "{e}");
    }
    let info = compat::tcp_info(&client).unwrap();
    assert_eq!(info.rtt, LATENCY * 2);
    assert_eq!(info.mss, 1460);
}

#[test]
fn hardware_stamping_follows_the_interface() {
    register_test();
    set_os_semantics(OsSemantics::Linux);
    pause_time();
    add_nic(
        NicSpec::new("eth0")
            .address(net("10.0.0.1/24"))
            .caps(snare::NicCaps {
                hw_rx_timestamp: true,
                hw_tx_timestamp: true,
                phc_index: Some(0),
                ..snare::NicCaps::default()
            }),
    )
    .unwrap();
    let listener = TcpListener::bind(SERVER).unwrap();
    let client = TcpStream::connect(SERVER).unwrap();
    let (server, _) = listener.accept().unwrap();
    let server = TimestampedStream::try_with_config(
        server,
        Config {
            hardware: Hardware::Interface("eth0".into()),
            ..Config::default()
        },
    )
    .unwrap();
    assert_eq!(server.source(), Source::Hardware);
    assert_eq!(server.hardware_interface(), Some("eth0"));
    let e = TimestampedStream::try_with_config(
        client,
        Config {
            hardware: Hardware::Interface("eth9".into()),
            ..Config::default()
        },
    )
    .unwrap_err();
    assert_eq!(e.kind(), io::ErrorKind::NotFound);
}
