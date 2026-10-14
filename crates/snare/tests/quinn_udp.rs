//! QUIC on a plain sim: `quinn-udp`'s socket state sets up its receive options (ECN, packet
//! info, GRO, path-MTU modes) and sends with ECN control messages, segmentation offload (Linux
//! GSO, Windows USO) and source selection; then a whole `quinn` connection runs over the sim's
//! loopback, IPv4, IPv6, and from a dual-stack IPv6 client to an IPv4 server. Every run is under
//! `strict_sockopts`.
//!
//! On Windows `quinn-udp` reaches `WSARecvMsg` through `SIO_GET_EXTENSION_FUNCTION_POINTER` and
//! sends with `WSASendMsg`, always with an `IP_ECN`/`IPV6_ECN` message; Windows refuses to send
//! CE. Its receive coalescing (URO) is off unless `set_gro` turns it on.

use std::io::IoSliceMut;
use std::net::{IpAddr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use quinn_udp::{EcnCodepoint, RecvMeta, Transmit, UdpSocketState};
use snare::Sim;

/// Runs `f` in a strict sim.
fn run(f: impl FnOnce() + Send) {
    Sim::builder()
        .stuck_after(Duration::from_secs(20))
        .strict_sockopts()
        .build()
        .run(f);
}

const AT: [&str; 2] = ["127.0.0.1", "::1"];

/// Receives one batch from `socket`, retrying while nothing has arrived.
fn recv(state: &UdpSocketState, socket: &UdpSocket) -> (Vec<u8>, RecvMeta) {
    let mut buf = vec![0u8; 64 * 1500];
    let mut meta = [RecvMeta::default()];
    loop {
        match state.recv(socket.into(), &mut [IoSliceMut::new(&mut buf)], &mut meta) {
            Ok(n) => {
                assert_eq!(n, 1);
                buf.truncate(meta[0].len);
                return (buf, meta[0]);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(e) => panic!("recv: {e}"),
        }
    }
}

fn pair(at: IpAddr) -> ((UdpSocket, UdpSocketState), (UdpSocket, UdpSocketState)) {
    let a = UdpSocket::bind((at, 0)).unwrap();
    let b = UdpSocket::bind((at, 0)).unwrap();
    let sa = UdpSocketState::new((&a).into()).unwrap();
    let sb = UdpSocketState::new((&b).into()).unwrap();
    ((a, sa), (b, sb))
}

#[test]
fn ecn_and_destination_round_trip() {
    for at in AT.map(|a| a.parse::<IpAddr>().unwrap()) {
        run(|| {
            let ((a, sa), (b, sb)) = pair(at);
            let to = b.local_addr().unwrap();
            assert!(!sa.may_fragment());
            if cfg!(windows) {
                let refused = sa.try_send(
                    (&a).into(),
                    &Transmit {
                        destination: to,
                        ecn: Some(EcnCodepoint::Ce),
                        contents: b"congested",
                        segment_size: None,
                        src_ip: None,
                    },
                );
                assert_eq!(refused.unwrap_err().raw_os_error(), Some(10022));
            }
            let sent: &[EcnCodepoint] = if cfg!(windows) {
                &[EcnCodepoint::Ect0, EcnCodepoint::Ect1]
            } else {
                &[EcnCodepoint::Ect0, EcnCodepoint::Ect1, EcnCodepoint::Ce]
            };
            for &ecn in sent {
                let payload = vec![ecn as u8; 1200];
                sa.try_send(
                    (&a).into(),
                    &Transmit {
                        destination: to,
                        ecn: Some(ecn),
                        contents: &payload,
                        segment_size: None,
                        src_ip: Some(to.ip()),
                    },
                )
                .unwrap();
                let (got, meta) = recv(&sb, &b);
                assert_eq!(got, payload);
                assert_eq!(meta.addr, a.local_addr().unwrap());
                assert_eq!(meta.ecn, Some(ecn));
                assert_eq!(meta.dst_ip, Some(to.ip()));
                assert_eq!(meta.stride, payload.len());
            }
        });
    }
}

#[test]
fn segmentation_offload() {
    for at in AT.map(|a| a.parse::<IpAddr>().unwrap()) {
        run(|| {
            let ((a, sa), (b, sb)) = pair(at);
            let to = b.local_addr().unwrap();
            if cfg!(target_os = "linux") {
                assert_eq!(sa.max_gso_segments(), 64);
                assert_eq!(sb.gro_segments(), 64);
            } else if cfg!(windows) {
                assert_eq!(sa.max_gso_segments(), 512);
                assert_eq!(sb.gro_segments(), 64);
                #[cfg(windows)]
                sb.set_gro((&b).into(), true).unwrap();
            } else {
                assert_eq!(sa.max_gso_segments(), 1);
                assert_eq!(sb.gro_segments(), 1);
            }
            let segment = 1200;
            let segments = sa.max_gso_segments().min(4);
            let payload: Vec<u8> = (0..segment * segments - 100).map(|i| i as u8).collect();
            sa.try_send(
                (&a).into(),
                &Transmit {
                    destination: to,
                    ecn: Some(EcnCodepoint::Ect1),
                    contents: &payload,
                    segment_size: (segments > 1).then_some(segment),
                    src_ip: None,
                },
            )
            .unwrap();
            let (got, meta) = recv(&sb, &b);
            assert_eq!(got, payload);
            assert_eq!(meta.ecn, Some(EcnCodepoint::Ect1));
            assert_eq!(meta.stride, segment.min(payload.len()));
            assert_eq!(meta.dst_ip, Some(to.ip()));
        });
    }
}

/// A socket without `UDP_GRO` (Windows: `UDP_RECV_MAX_COALESCED_SIZE`) reads a segmented send
/// as its segments.
#[cfg(any(target_os = "linux", windows))]
#[test]
fn segments_reach_a_socket_without_gro() {
    let at = IpAddr::from([127, 0, 0, 1]);
    run(|| {
        let ((a, sa), _) = pair(at);
        let plain = UdpSocket::bind((at, 0)).unwrap();
        plain
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let payload = vec![7u8; 2500];
        sa.try_send(
            (&a).into(),
            &Transmit {
                destination: plain.local_addr().unwrap(),
                ecn: None,
                contents: &payload,
                segment_size: Some(1000),
                src_ip: None,
            },
        )
        .unwrap();
        let mut buf = [0u8; 4096];
        let sizes: Vec<usize> = (0..3).map(|_| plain.recv(&mut buf).unwrap()).collect();
        assert_eq!(sizes, [1000, 1000, 500]);
    });
}

/// A self-signed certificate for `localhost` and the server and client configurations that
/// trust it.
fn configs() -> (quinn::ServerConfig, quinn::ClientConfig) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let der = quinn::rustls::pki_types::CertificateDer::from(cert.cert.der().to_vec());
    let key = quinn::rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
    let server = quinn::ServerConfig::with_single_cert(vec![der.clone()], key.into()).unwrap();
    let mut roots = quinn::rustls::RootCertStore::empty();
    roots.add(der).unwrap();
    let client = quinn::ClientConfig::with_root_certificates(Arc::new(roots)).unwrap();
    (server, client)
}

/// A client at `client_at` opens a bidirectional stream, sends 256 KiB and reads it echoed back,
/// over a quinn connection to a server at `at` on the sim's loopback.
async fn echo(at: IpAddr, client_at: IpAddr) {
    let (server_config, client_config) = configs();
    let server = quinn::Endpoint::server(server_config, SocketAddr::new(at, 0)).unwrap();
    let to = server.local_addr().unwrap();
    let serve = tokio::spawn(async move {
        let conn = server.accept().await.unwrap().await.unwrap();
        let (mut send, mut recv) = conn.accept_bi().await.unwrap();
        let data = recv.read_to_end(1 << 20).await.unwrap();
        send.write_all(&data).await.unwrap();
        send.finish().unwrap();
        conn.closed().await;
    });
    let mut client = quinn::Endpoint::client(SocketAddr::new(client_at, 0)).unwrap();
    client.set_default_client_config(client_config);
    let conn = client.connect(to, "localhost").unwrap().await.unwrap();
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    let data: Vec<u8> = (0..256 * 1024).map(|i| (i % 251) as u8).collect();
    send.write_all(&data).await.unwrap();
    send.finish().unwrap();
    let back = recv.read_to_end(1 << 20).await.unwrap();
    assert_eq!(back, data);
    let stats = conn.stats();
    conn.close(0u32.into(), b"done");
    serve.await.unwrap();
    client.wait_idle().await;
    assert!(stats.path.sent_packets > 0);
    assert_eq!(stats.path.lost_packets, 0);
}

fn block_on(at: IpAddr, client_at: IpAddr) {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(echo(at, client_at));
}

/// A server at each loopback address and a client at the same one, except on Windows, where the
/// IPv6 client binds the wildcard: `quinn-udp` turns on IPv4 options for the dual-stack socket
/// quinn makes, which Windows refuses on an IPv6 socket bound to `::1`
/// (`client_on_ipv6_loopback_fails_like_the_host`).
#[test]
fn quinn_connection() {
    for at in AT.map(|a| a.parse::<IpAddr>().unwrap()) {
        let client_at = if cfg!(windows) && at.is_ipv6() {
            Ipv6Addr::UNSPECIFIED.into()
        } else {
            at
        };
        run(|| block_on(at, client_at));
    }
}

/// quinn's dual-stack client endpoint (`[::]:0`, `IPV6_V6ONLY` off) reaches an IPv4 server
/// through its v4-mapped address.
#[test]
fn quinn_dual_stack_client_reaches_ipv4_server() {
    let at = IpAddr::from([127, 0, 0, 1]);
    run(|| block_on(at, Ipv6Addr::UNSPECIFIED.into()));
}

/// The same connection between a `SimHost`'s datagram sockets.
#[cfg(target_os = "linux")]
#[test]
fn quinn_connection_on_simhost() {
    let at = IpAddr::from([127, 0, 0, 1]);
    let sim = Sim::builder()
        .host(snare::HostProfile::new().build())
        .strict_sockopts()
        .stuck_after(Duration::from_secs(20))
        .build();
    sim.run(|| block_on(at, at));
}

/// quinn's client endpoint at `[::1]:0`: on Windows the socket is IPv6 bound to `::1` with
/// `IPV6_V6ONLY` off, where `quinn-udp`'s `IP_DONTFRAGMENT` fails with `WSAEINVAL`, on the host as
/// in the sim. The sim is built first: `quinn-udp` keeps the `WSARecvMsg` it fetches first for
/// the whole process, and only once the sim's hooks are in place is that one which serves sim
/// sockets too.
#[cfg(windows)]
#[test]
fn client_on_ipv6_loopback_fails_like_the_host() {
    let sim = Sim::new();
    let client = || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                quinn::Endpoint::client(SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 0))
                    .map(drop)
                    .map_err(|e| e.raw_os_error())
            })
    };
    let real = snare::real(client);
    assert_eq!(real, Err(Some(10022)));
    assert_eq!(sim.run(client), real);
}
