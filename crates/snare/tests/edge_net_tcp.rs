#![cfg(unix)]
//! TCP edge cases of the unix fabric, pinned before a performance pass: zero-length calls, partial
//! writes past both buffers, every order of half-close, closes with and without unread data,
//! resets that end blocked calls, end of stream read again and again, `SO_LINGER` 0, byte-stream
//! integrity across arbitrary write and read sizes, `MSG_PEEK`/`MSG_WAITALL`/`MSG_DONTWAIT`,
//! nonblocking connects, connecting to oneself, the listen backlog, a listener closed with
//! connections queued, fresh state on a new socket, descriptor duplication, and the exact virtual
//! time `SO_RCVTIMEO`/`SO_SNDTIMEO` give up at.
//!
//! The `*_os_truth` tests run one function on the host's loopback and in a sim and assert the same
//! observations; the others pin the sim's own answers where the host's are timing- or
//! tuning-dependent. A real stack moves loopback segments asynchronously, so each scenario lets it
//! settle with a short sleep (virtual, so free, in the sim) before it looks.

#[path = "support/golden.rs"]
mod golden;
#[path = "support/netfault.rs"]
mod netfault;

use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::fd::{AsRawFd, RawFd};
use std::thread;
use std::time::{Duration, Instant};

use snare::Sim;

#[cfg(target_os = "linux")]
const NOSIGNAL: libc::c_int = libc::MSG_NOSIGNAL;
#[cfg(not(target_os = "linux"))]
const NOSIGNAL: libc::c_int = 0;

fn settle() {
    thread::sleep(Duration::from_millis(50));
}

fn last_errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap()
}

fn recv(fd: RawFd, len: usize, flags: libc::c_int) -> Result<Vec<u8>, i32> {
    let mut buf = vec![0u8; len];
    let n = unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), len, flags) };
    if n < 0 {
        return Err(last_errno());
    }
    buf.truncate(n as usize);
    Ok(buf)
}

fn send(fd: RawFd, data: &[u8], flags: libc::c_int) -> Result<usize, i32> {
    let n = unsafe { libc::send(fd, data.as_ptr().cast(), data.len(), flags | NOSIGNAL) };
    if n < 0 {
        Err(last_errno())
    } else {
        Ok(n as usize)
    }
}

fn dontwait(fd: RawFd) -> Result<Vec<u8>, i32> {
    recv(fd, 64, libc::MSG_DONTWAIT)
}

fn so_error(fd: RawFd) -> i32 {
    let mut v: libc::c_int = 0;
    let mut len = size_of::<libc::c_int>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ERROR,
            (&mut v as *mut libc::c_int).cast(),
            &mut len,
        )
    };
    assert_eq!(rc, 0, "getsockopt SO_ERROR");
    v
}

fn o_nonblock(fd: RawFd) -> bool {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    assert!(flags >= 0, "F_GETFL");
    flags & libc::O_NONBLOCK != 0
}

fn linger_on(fd: RawFd) -> bool {
    let mut l = libc::linger {
        l_onoff: 0,
        l_linger: 0,
    };
    let mut len = size_of::<libc::linger>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_LINGER,
            (&mut l as *mut libc::linger).cast(),
            &mut len,
        )
    };
    assert_eq!(rc, 0, "getsockopt SO_LINGER");
    l.l_onoff != 0
}

/// A connected loopback stream: (client, server).
fn pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server, _) = listener.accept().unwrap();
    (client, server)
}

/// Aborts `s` with a reset when it is dropped.
fn abort_on_drop(s: &TcpStream) {
    netfault::set_linger(s.as_raw_fd(), 0);
}

fn zero_length_calls() -> Vec<String> {
    let (c, s) = pair();
    let (c, s) = (c.as_raw_fd(), s.as_raw_fd());
    let mut seen = vec![
        format!("{:?}", send(c, b"", 0)),
        format!("{:?}", recv(s, 0, libc::MSG_DONTWAIT)),
    ];
    send(c, b"ab", 0).unwrap();
    settle();
    seen.push(format!("{:?}", recv(s, 0, libc::MSG_DONTWAIT)));
    seen.push(format!("{:?}", dontwait(s)));
    send(c, b"", 0).unwrap();
    settle();
    seen.push(format!("{:?}", dontwait(s)));
    unsafe { libc::shutdown(c, libc::SHUT_WR) };
    settle();
    seen.push(format!("{:?}", recv(s, 0, libc::MSG_DONTWAIT)));
    seen.push(format!("{:?}", dontwait(s)));
    seen
}

#[test]
fn zero_length_calls_os_truth() {
    let real = zero_length_calls();
    let sim = Sim::new().run(zero_length_calls);
    assert_eq!(sim, real);
}

/// The sim's own answer to zero-length sends and receives, whatever the host says.
#[test]
fn zero_length_calls_in_the_sim() {
    let sim = Sim::new().run(zero_length_calls);
    let empty = if cfg!(target_os = "macos") {
        "Ok([])".into()
    } else {
        format!("Err({})", libc::EAGAIN)
    };
    assert_eq!(
        sim,
        [
            "Ok(0)".into(),
            empty,
            "Ok([])".into(),
            "Ok([97, 98])".into(),
            format!("Err({})", libc::EAGAIN),
            "Ok([])".into(),
            "Ok([])".into()
        ]
    );
}

/// A nonblocking writer with 4096-byte buffers on both ends: what each write takes as the reader
/// frees room a little at a time.
fn partial_writes() -> (usize, usize, Vec<Result<usize, i32>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    netfault::set_buf(listener.as_raw_fd(), true, 4096);
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    netfault::set_buf(client.as_raw_fd(), false, 4096);
    let (mut server, _) = listener.accept().unwrap();
    let (c, s) = (client.as_raw_fd(), server.as_raw_fd());
    let (snd, rcv) = (netfault::sndbuf(c), netfault::rcvbuf(s));
    client.set_nonblocking(true).unwrap();
    let big = vec![7u8; 1 << 20];
    let mut seen = vec![send(c, &big, 0), send(c, &big, 0)];
    let mut sink = vec![0u8; 1 << 20];
    for take in [1000, 1000, 2000, 1, 100_000] {
        let n = server.read(&mut sink[..take]).unwrap();
        seen.push(Ok(n));
        seen.push(send(c, &big, 0));
    }
    (snd, rcv, seen)
}

#[test]
fn writes_larger_than_both_buffers_take_what_the_host_rule_allows() {
    let (snd, rcv, seen) = Sim::new().run(partial_writes);
    let eagain = Err(libc::EAGAIN);
    if cfg!(target_os = "linux") {
        assert_eq!((snd, rcv), (8192, 8192));
        assert_eq!(
            seen,
            [
                Ok(16384),
                eagain,
                Ok(1000),
                Ok(1000),
                Ok(1000),
                Ok(1000),
                Ok(2000),
                Ok(2000),
                Ok(1),
                Ok(1),
                Ok(16384),
                Ok(16384),
            ]
        );
    } else {
        assert_eq!((snd, rcv), (4096, 4096));
        assert_eq!(
            seen,
            [
                Ok(8192),
                eagain,
                Ok(1000),
                eagain,
                Ok(1000),
                eagain,
                Ok(2000),
                Ok(4000),
                Ok(1),
                eagain,
                Ok(8191),
                Ok(8192),
            ]
        );
    }
}

#[derive(Clone, Copy, Debug)]
enum Half {
    ClientWr,
    ClientRd,
    ClientBoth,
    ServerWr,
    ServerRd,
    ServerBoth,
}

const HALVES: [Half; 6] = [
    Half::ClientWr,
    Half::ClientRd,
    Half::ClientBoth,
    Half::ServerWr,
    Half::ServerRd,
    Half::ServerBoth,
];

fn apply(half: Half, c: RawFd, s: RawFd) -> i32 {
    let (fd, how) = match half {
        Half::ClientWr => (c, libc::SHUT_WR),
        Half::ClientRd => (c, libc::SHUT_RD),
        Half::ClientBoth => (c, libc::SHUT_RDWR),
        Half::ServerWr => (s, libc::SHUT_WR),
        Half::ServerRd => (s, libc::SHUT_RD),
        Half::ServerBoth => (s, libc::SHUT_RDWR),
    };
    unsafe { libc::shutdown(fd, how) }
}

/// Each ordered pair of shutdowns on a stream with a few bytes unread each way: what each end
/// reads and writes afterwards, and reads again once the writes have crossed.
fn half_closes() -> Vec<String> {
    let mut seen = Vec::new();
    for first in HALVES {
        for second in HALVES {
            let (client, server) = pair();
            let (c, s) = (client.as_raw_fd(), server.as_raw_fd());
            send(c, b"c1", 0).unwrap();
            send(s, b"s1", 0).unwrap();
            settle();
            let first_rc = apply(first, c, s);
            settle();
            let rc = (first_rc, apply(second, c, s));
            settle();
            let reads = (dontwait(c), dontwait(s));
            let client_write = send(c, b"c2", 0);
            settle();
            let server_write = send(s, b"s2", 0);
            let line = format!(
                "{first:?} {second:?} rc {rc:?} | c reads {:?} s reads {:?} | c writes {:?} s writes {:?}",
                reads.0, reads.1, client_write, server_write,
            );
            settle();
            seen.push(format!(
                "{line} | then c reads {:?} s reads {:?}",
                dontwait(c),
                dontwait(s)
            ));
        }
    }
    seen
}

#[test]
fn half_close_in_every_order_os_truth() {
    let real = half_closes();
    let sim = Sim::new().run(half_closes);
    let differ: Vec<String> = real
        .iter()
        .zip(&sim)
        .filter(|(r, s)| r != s)
        .map(|(r, s)| format!("host {r}\nsim  {s}"))
        .collect();
    assert!(differ.is_empty(), "{}", differ.join("\n"));
}

#[test]
fn half_close_in_every_order_in_the_sim() {
    let sim = Sim::new().run(half_closes);
    let name = format!("edge_net_tcp_half_close.{}.txt", std::env::consts::OS);
    golden::check_text(&name, &(sim.join("\n") + "\n"));
}

fn simultaneous_close() -> Vec<String> {
    let (client, server) = pair();
    let (c, s) = (client.as_raw_fd(), server.as_raw_fd());
    let other = thread::spawn(move || unsafe { libc::shutdown(s, libc::SHUT_WR) });
    let mine = unsafe { libc::shutdown(c, libc::SHUT_WR) };
    let theirs = other.join().unwrap();
    settle();
    vec![
        format!("{mine} {theirs}"),
        format!("{:?} {:?}", dontwait(c), dontwait(s)),
        format!("{:?} {:?}", dontwait(c), dontwait(s)),
        format!("{:?} {:?}", send(c, b"x", 0), send(s, b"x", 0)),
    ]
}

#[test]
fn simultaneous_close_os_truth() {
    let real = simultaneous_close();
    let sim = Sim::new().run(simultaneous_close);
    assert_eq!(sim, real);
    assert_eq!(sim[1], "Ok([]) Ok([])");
    assert_eq!(sim[3], format!("Err({0}) Err({0})", libc::EPIPE));
}

/// The client closes while the server's bytes wait unread on it, and the server then reads and
/// writes twice.
fn close_with_unread_data() -> Vec<String> {
    let (client, server) = pair();
    let s = server.as_raw_fd();
    send(s, b"unread", 0).unwrap();
    settle();
    drop(client);
    settle();
    let mut seen = vec![
        format!("{:?}", dontwait(s)),
        format!("{:?}", send(s, b"x", 0)),
    ];
    settle();
    seen.push(format!("{:?}", send(s, b"y", 0)));
    seen.push(format!("{:?}", dontwait(s)));
    seen
}

#[test]
fn close_with_unread_data_resets_os_truth() {
    let real = close_with_unread_data();
    let sim = Sim::new().run(close_with_unread_data);
    assert_eq!(sim, real);
}

#[test]
fn close_with_unread_data_in_the_sim() {
    assert_eq!(
        Sim::new().run(close_with_unread_data),
        [
            format!("Err({})", libc::ECONNRESET),
            format!("Err({})", libc::EPIPE),
            format!("Err({})", libc::EPIPE),
            "Ok([])".into()
        ]
    );
}

/// The client reads everything, then closes: a plain FIN. The server reads end of stream and
/// writes into the closed end.
fn close_after_reading() -> Vec<String> {
    let (mut client, server) = pair();
    let s = server.as_raw_fd();
    send(s, b"read", 0).unwrap();
    let mut buf = [0u8; 4];
    client.read_exact(&mut buf).unwrap();
    drop(client);
    settle();
    let mut seen = vec![
        format!("{:?}", dontwait(s)),
        format!("{:?}", send(s, b"x", 0)),
    ];
    settle();
    seen.push(format!("{:?}", send(s, b"y", 0)));
    seen.push(format!("{:?}", dontwait(s)));
    seen
}

#[test]
fn write_after_peer_close_os_truth() {
    let real = close_after_reading();
    let sim = Sim::new().run(close_after_reading);
    assert_eq!(sim, real);
}

#[test]
fn write_after_peer_close_in_the_sim() {
    let last = if cfg!(target_os = "macos") {
        format!("Err({})", libc::ECONNRESET)
    } else {
        "Ok([])".into()
    };
    assert_eq!(
        Sim::new().run(close_after_reading),
        [
            "Ok([])".into(),
            "Ok(1)".into(),
            format!("Err({})", libc::EPIPE),
            last
        ]
    );
}

/// A read blocked on an idle stream when the peer aborts it.
fn reset_during_blocked_read() -> Vec<String> {
    let (client, server) = pair();
    let reader = thread::spawn(move || {
        let r = recv(server.as_raw_fd(), 16, 0);
        let again = dontwait(server.as_raw_fd());
        format!("{r:?} then {again:?}")
    });
    settle();
    abort_on_drop(&client);
    drop(client);
    vec![reader.join().unwrap()]
}

#[test]
fn reset_during_blocked_read_os_truth() {
    let real = reset_during_blocked_read();
    let sim = Sim::new().run(reset_during_blocked_read);
    assert_eq!(sim, real);
}

#[test]
fn reset_during_blocked_read_in_the_sim() {
    assert_eq!(
        Sim::new().run(reset_during_blocked_read),
        [format!("Err({}) then Ok([])", libc::ECONNRESET)]
    );
}

/// A write blocked on a full stream when the reader aborts it, then one more write.
fn reset_during_blocked_write() -> Vec<String> {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    netfault::set_buf(listener.as_raw_fd(), true, 4096);
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    netfault::set_buf(client.as_raw_fd(), false, 4096);
    let (server, _) = listener.accept().unwrap();
    let c = client.as_raw_fd();
    let chunk = [1u8; 4096];
    for _ in 0..3 {
        while send(c, &chunk, libc::MSG_DONTWAIT).is_ok() {}
        settle();
    }
    let writer = thread::spawn(move || {
        let first = send(c, &[2u8; 65536], 0);
        let second = send(c, b"z", 0);
        drop(client);
        format!("{first:?} then {second:?}")
    });
    settle();
    abort_on_drop(&server);
    drop(server);
    vec![writer.join().unwrap()]
}

#[cfg(target_os = "linux")]
#[test]
fn reset_during_blocked_write_os_truth() {
    let real = reset_during_blocked_write();
    let sim = Sim::new().run(reset_during_blocked_write);
    assert_eq!(sim, real);
}

#[test]
fn reset_during_blocked_write_in_the_sim() {
    assert_eq!(
        Sim::new().run(reset_during_blocked_write),
        [format!(
            "Err({}) then Err({})",
            libc::ECONNRESET,
            libc::EPIPE
        )]
    );
}

fn read_after_eof() -> Vec<String> {
    let (mut client, mut server) = pair();
    client.write_all(b"last").unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    settle();
    let mut seen = Vec::new();
    let mut buf = [0u8; 16];
    for _ in 0..4 {
        seen.push(format!(
            "{:?}",
            server.read(&mut buf).map(|n| buf[..n].to_vec())
        ));
    }
    seen.push(format!(
        "{:?}",
        server.write(b"back").map_err(|e| e.raw_os_error())
    ));
    settle();
    seen.push(format!(
        "{:?}",
        client.read(&mut buf).map(|n| buf[..n].to_vec())
    ));
    seen.push(format!(
        "{:?}",
        client.write(b"x").map_err(|e| e.raw_os_error())
    ));
    seen
}

#[test]
fn read_after_eof_repeatedly_os_truth() {
    let real = read_after_eof();
    let sim = Sim::new().run(read_after_eof);
    assert_eq!(sim, real);
    assert_eq!(
        sim[..4],
        ["Ok([108, 97, 115, 116])", "Ok([])", "Ok([])", "Ok([])"]
    );
}

/// `SO_LINGER` 0 on the client: with nothing pending, then with bytes the server has not read.
/// The server reads twice and writes once after each.
fn linger_zero() -> Vec<String> {
    let mut seen = Vec::new();
    for pending in [&b""[..], b"pending"] {
        let (client, server) = pair();
        let s = server.as_raw_fd();
        if !pending.is_empty() {
            send(client.as_raw_fd(), pending, 0).unwrap();
            settle();
        }
        abort_on_drop(&client);
        drop(client);
        settle();
        seen.push(format!(
            "{:?} {:?} {:?}",
            dontwait(s),
            dontwait(s),
            send(s, b"x", 0)
        ));
    }
    seen
}

#[test]
fn linger_zero_os_truth() {
    let real = linger_zero();
    let sim = Sim::new().run(linger_zero);
    assert_eq!(sim, real);
}

#[test]
fn linger_zero_in_the_sim() {
    assert_eq!(
        Sim::new().run(linger_zero),
        [
            format!("Err({}) Ok([]) Err({})", libc::ECONNRESET, libc::EPIPE),
            format!(
                "Ok([112, 101, 110, 100, 105, 110, 103]) Err({}) Err({})",
                libc::ECONNRESET,
                libc::EPIPE
            )
        ]
    );
}

/// A small deterministic generator, so the split is the same on every run.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self, below: usize) -> usize {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        ((self.0 >> 33) as usize) % below
    }
}

/// 600 writes of 0 to 9 bytes, read back in reads of 1 to 13 bytes by another thread.
fn many_small_writes() -> (Vec<u8>, Vec<u8>, usize) {
    let (mut client, mut server) = pair();
    let mut rng = Lcg(0x5eed);
    let mut sent = Vec::new();
    let mut writes = Vec::new();
    for i in 0..600u32 {
        let len = rng.next(10);
        let piece: Vec<u8> = (0..len).map(|j| (i as usize * 7 + j) as u8).collect();
        sent.extend_from_slice(&piece);
        writes.push(piece);
    }
    let total = sent.len();
    let reader = thread::spawn(move || {
        let mut rng = Lcg(0xbeef);
        let mut got = Vec::new();
        let mut reads = 0;
        while got.len() < total {
            let mut buf = vec![0u8; 1 + rng.next(13)];
            let n = server.read(&mut buf).unwrap();
            assert!(n > 0, "end of stream before every byte arrived");
            got.extend_from_slice(&buf[..n]);
            reads += 1;
        }
        (got, reads)
    });
    for piece in writes {
        client.write_all(&piece).unwrap();
    }
    let (got, reads) = reader.join().unwrap();
    (sent, got, reads)
}

#[test]
fn many_small_writes_keep_bytes_not_boundaries() {
    let (sent, got, reads) = Sim::new().run(many_small_writes);
    assert_eq!(got, sent);
    let (sent, got, det_reads) = Sim::builder()
        .deterministic()
        .build()
        .run(many_small_writes);
    assert_eq!(got, sent);
    assert!(reads > 0 && det_reads > 0);
}

/// 100 writes of 3 bytes, then one large read once they crossed: the sim, like Linux, gives them all
/// to that read (macOS loopback spreads them over several).
fn coalesced() -> (usize, Result<Vec<u8>, i32>) {
    let (client, server) = pair();
    let c = client.as_raw_fd();
    for i in 0..100u8 {
        send(c, &[i, i, i], 0).unwrap();
    }
    settle();
    let first = recv(server.as_raw_fd(), 4096, libc::MSG_DONTWAIT).unwrap();
    (first.len(), dontwait(server.as_raw_fd()))
}

#[test]
fn small_writes_coalesce_in_one_read_os_truth() {
    let real = coalesced();
    let sim = Sim::new().run(coalesced);
    if cfg!(target_os = "linux") {
        assert_eq!(sim, real);
    }
    assert_eq!(sim, (300, Err(libc::EAGAIN)));
}

fn dontwait_calls() -> Vec<String> {
    let (client, server) = pair();
    let (c, s) = (client.as_raw_fd(), server.as_raw_fd());
    let mut seen = vec![format!("{:?}", recv(s, 8, libc::MSG_DONTWAIT))];
    send(c, b"hello", 0).unwrap();
    settle();
    seen.push(format!("{:?}", recv(s, 2, libc::MSG_DONTWAIT)));
    seen.push(format!("{:?}", recv(s, 8, libc::MSG_DONTWAIT)));
    seen.push(format!("{:?}", recv(s, 8, libc::MSG_DONTWAIT)));
    seen.push(format!("blocking fd: {}", o_nonblock(s)));
    seen
}

#[test]
fn msg_dontwait_os_truth() {
    let real = dontwait_calls();
    let sim = Sim::new().run(dontwait_calls);
    assert_eq!(sim, real);
    let eagain = format!("Err({})", libc::EAGAIN);
    assert_eq!(
        sim,
        [
            eagain.clone(),
            "Ok([104, 101])".into(),
            "Ok([108, 108, 111])".into(),
            eagain,
            "blocking fd: false".into(),
        ]
    );
}

fn peek_calls() -> Vec<String> {
    let (client, server) = pair();
    let (c, s) = (client.as_raw_fd(), server.as_raw_fd());
    send(c, b"hello", 0).unwrap();
    settle();
    let peek = libc::MSG_PEEK | libc::MSG_DONTWAIT;
    vec![
        format!("{:?}", recv(s, 3, peek)),
        format!("{:?}", recv(s, 8, peek)),
        format!("{:?}", recv(s, 2, libc::MSG_DONTWAIT)),
        format!("{:?}", recv(s, 8, libc::MSG_PEEK)),
        format!(
            "{:?}",
            server.peek(&mut [0u8; 8]).map_err(|e| e.raw_os_error())
        ),
        format!("{:?}", recv(s, 8, libc::MSG_DONTWAIT)),
        format!("{:?}", recv(s, 8, peek)),
    ]
}

#[test]
fn msg_peek_leaves_stream_bytes_queued_os_truth() {
    let real = peek_calls();
    let sim = Sim::new().run(peek_calls);
    assert_eq!(sim, real);
}

#[test]
fn msg_peek_on_a_stream_in_the_sim() {
    assert_eq!(
        Sim::new().run(peek_calls),
        [
            "Ok([104, 101, 108])".into(),
            "Ok([104, 101, 108, 108, 111])".into(),
            "Ok([104, 101])".into(),
            "Ok([108, 108, 111])".into(),
            "Ok(3)".into(),
            "Ok([108, 108, 111])".into(),
            format!("Err({})", libc::EAGAIN)
        ]
    );
}

/// A `MSG_WAITALL` read of 4 bytes that the writer sends as 2, then 2 more a little later.
fn waitall() -> Vec<String> {
    let (client, server) = pair();
    let c = client.as_raw_fd();
    let writer = thread::spawn(move || {
        send(c, b"ab", 0).unwrap();
        settle();
        send(c, b"cd", 0).unwrap();
        client
    });
    let got = recv(server.as_raw_fd(), 4, libc::MSG_WAITALL);
    let client = writer.join().unwrap();
    drop(client);
    settle();
    let at_eof = recv(server.as_raw_fd(), 4, libc::MSG_WAITALL);
    vec![format!("{got:?}"), format!("{at_eof:?}")]
}

#[test]
fn msg_waitall_waits_for_the_whole_length_os_truth() {
    let real = waitall();
    let sim = Sim::new().run(waitall);
    assert_eq!(sim, real);
}

#[test]
fn msg_waitall_in_the_sim() {
    assert_eq!(Sim::new().run(waitall), ["Ok([97, 98, 99, 100])", "Ok([])"]);
}

fn raw_connect(fd: RawFd, to: SocketAddr) -> Result<(), i32> {
    let SocketAddr::V4(v4) = to else {
        panic!("IPv4 only")
    };
    let mut sin: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    #[cfg(target_os = "macos")]
    {
        sin.sin_len = size_of::<libc::sockaddr_in>() as u8;
    }
    sin.sin_family = libc::AF_INET as libc::sa_family_t;
    sin.sin_port = v4.port().to_be();
    sin.sin_addr.s_addr = u32::from(*v4.ip()).to_be();
    let rc = unsafe {
        libc::connect(
            fd,
            (&sin as *const libc::sockaddr_in).cast(),
            size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if rc == 0 { Ok(()) } else { Err(last_errno()) }
}

fn raw_bind(fd: RawFd, to: SocketAddr) {
    let SocketAddr::V4(v4) = to else {
        panic!("IPv4 only")
    };
    let mut sin: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    #[cfg(target_os = "macos")]
    {
        sin.sin_len = size_of::<libc::sockaddr_in>() as u8;
    }
    sin.sin_family = libc::AF_INET as libc::sa_family_t;
    sin.sin_port = v4.port().to_be();
    sin.sin_addr.s_addr = u32::from(*v4.ip()).to_be();
    let rc = unsafe {
        libc::bind(
            fd,
            (&sin as *const libc::sockaddr_in).cast(),
            size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    assert_eq!(rc, 0, "bind: {}", last_errno());
}

fn local_addr(fd: RawFd) -> SocketAddr {
    let mut sin: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut len = size_of::<libc::sockaddr_in>() as libc::socklen_t;
    let rc =
        unsafe { libc::getsockname(fd, (&mut sin as *mut libc::sockaddr_in).cast(), &mut len) };
    assert_eq!(rc, 0, "getsockname");
    SocketAddr::from((
        u32::from_be(sin.sin_addr.s_addr).to_be_bytes(),
        u16::from_be(sin.sin_port),
    ))
}

fn tcp_socket() -> RawFd {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    assert!(fd >= 0, "socket");
    fd
}

fn set_fd_nonblocking(fd: RawFd) {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    assert_eq!(
        unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) },
        0
    );
}

/// A nonblocking connect to a loopback listener: the first answer, `SO_ERROR` once writable, a
/// second connect, and whether the listener has it.
fn nonblocking_connect_to_listener() -> Vec<String> {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let fd = tcp_socket();
    set_fd_nonblocking(fd);
    let first = raw_connect(fd, listener.local_addr().unwrap());
    let ready = netfault::poll(fd, false, true, 5000);
    let seen = vec![
        format!("{first:?}"),
        format!("writable {} error {}", ready.writable, ready.error),
        format!("SO_ERROR {}", so_error(fd)),
        format!("{:?}", raw_connect(fd, listener.local_addr().unwrap())),
        format!("accepted {}", listener.accept().is_ok()),
    ];
    unsafe { libc::close(fd) };
    seen
}

#[test]
fn nonblocking_connect_to_listener_os_truth() {
    let real = nonblocking_connect_to_listener();
    let sim = Sim::new().run(nonblocking_connect_to_listener);
    assert_eq!(sim, real);
}

#[test]
fn nonblocking_connect_to_listener_in_the_sim() {
    assert_eq!(
        Sim::new().run(nonblocking_connect_to_listener),
        [
            format!("Err({})", libc::EINPROGRESS),
            "writable true error false".into(),
            "SO_ERROR 0".into(),
            if cfg!(target_os = "linux") {
                "Ok(())".into()
            } else {
                format!("Err({})", libc::EISCONN)
            },
            "accepted true".into()
        ]
    );
}

/// A nonblocking connect nobody answers, step by step on the virtual clock: `EINPROGRESS`, nothing
/// to poll, `EALREADY`, then the SYN plan's end with `ETIMEDOUT` in `SO_ERROR` once and the socket
/// reusable for another connect.
#[test]
fn nonblocking_connect_to_silence_settles_at_the_plan_end() {
    let (seen, waited) = Sim::builder().deterministic().build().run(|| {
        let fd = tcp_socket();
        set_fd_nonblocking(fd);
        let silent: SocketAddr = "10.255.0.1:80".parse().unwrap();
        let start = Instant::now();
        let mut seen = vec![format!("{:?}", raw_connect(fd, silent))];
        let idle = netfault::poll(fd, true, true, 0);
        seen.push(format!(
            "r {} w {} e {}",
            idle.readable, idle.writable, idle.error
        ));
        seen.push(format!("SO_ERROR {}", so_error(fd)));
        seen.push(format!("{:?}", raw_connect(fd, silent)));
        let done = netfault::poll(fd, true, true, -1);
        let waited = start.elapsed();
        seen.push(format!(
            "r {} w {} e {}",
            done.readable, done.writable, done.error
        ));
        seen.push(format!("SO_ERROR {}", so_error(fd)));
        seen.push(format!("SO_ERROR {}", so_error(fd)));
        unsafe { libc::close(fd) };
        (seen, waited)
    });
    assert_eq!(
        seen,
        [
            format!("Err({})", libc::EINPROGRESS),
            "r false w false e false".into(),
            "SO_ERROR 0".into(),
            format!("Err({})", libc::EALREADY),
            if cfg!(target_os = "linux") {
                "r true w true e true".into()
            } else {
                "r true w false e false".into()
            },
            format!("SO_ERROR {}", libc::ETIMEDOUT),
            "SO_ERROR 0".into(),
        ]
    );
    let span = if cfg!(target_os = "linux") { 131 } else { 75 };
    assert!(
        waited >= Duration::from_secs(span)
            && waited < Duration::from_secs(span) + Duration::from_millis(1),
        "{waited:?}"
    );
}

/// A socket bound to a loopback port connecting to that same address, then echoing a byte to
/// itself.
fn connect_to_self() -> Vec<String> {
    let fd = tcp_socket();
    raw_bind(fd, "127.0.0.1:0".parse().unwrap());
    let me = local_addr(fd);
    let connected = raw_connect(fd, me);
    let mut seen = vec![format!("{connected:?}")];
    if connected.is_ok() {
        seen.push(format!("{:?}", send(fd, b"me", 0)));
        settle();
        seen.push(format!("{:?}", recv(fd, 8, libc::MSG_DONTWAIT)));
    }
    unsafe { libc::close(fd) };
    seen
}

#[test]
fn connect_to_self_os_truth() {
    let real = connect_to_self();
    let sim = Sim::new().run(connect_to_self);
    assert_eq!(sim, real);
}

#[test]
fn connect_to_self_in_the_sim() {
    let expected = if cfg!(target_os = "linux") {
        vec!["Ok(())".into(), "Ok(2)".into(), "Ok([109, 101])".into()]
    } else {
        vec![format!("Err({})", libc::EINVAL)]
    };
    assert_eq!(Sim::new().run(connect_to_self), expected);
}

fn listener_backlog(backlog: i32, relisten: Option<i32>) -> usize {
    let fd = tcp_socket();
    raw_bind(fd, "127.0.0.1:0".parse().unwrap());
    assert_eq!(unsafe { libc::listen(fd, backlog) }, 0);
    let at = local_addr(fd);
    let mut clients = Vec::new();
    for _ in 0..5 {
        match TcpStream::connect_timeout(&at, Duration::from_millis(100)) {
            Ok(client) => clients.push(client),
            Err(error) => {
                assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
                break;
            }
        }
    }
    if let Some(backlog) = relisten {
        assert_eq!(unsafe { libc::listen(fd, backlog) }, 0);
        clients.push(TcpStream::connect_timeout(&at, Duration::from_secs(2)).unwrap());
    }
    let order: Vec<_> = clients
        .iter()
        .map(|client| client.local_addr().unwrap())
        .collect();
    let accepted: Vec<_> = (0..clients.len())
        .map(|_| {
            let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            let mut len = size_of::<libc::sockaddr_in>() as libc::socklen_t;
            let new =
                unsafe { libc::accept(fd, (&mut sa as *mut libc::sockaddr_in).cast(), &mut len) };
            assert!(new >= 0);
            unsafe { libc::close(new) };
            SocketAddr::from((
                u32::from_be(sa.sin_addr.s_addr).to_be_bytes(),
                u16::from_be(sa.sin_port),
            ))
        })
        .collect();
    assert_eq!(accepted, order);
    set_fd_nonblocking(fd);
    assert_eq!(
        unsafe { libc::accept(fd, std::ptr::null_mut(), std::ptr::null_mut()) },
        -1
    );
    assert_eq!(last_errno(), libc::EAGAIN);
    unsafe { libc::close(fd) };
    clients.len()
}

#[test]
fn listener_backlog_capacity_and_relisten_os_truth() {
    for (backlog, relisten) in [(0, None), (1, None), (2, None), (3, None), (1, Some(4))] {
        let real = listener_backlog(backlog, relisten);
        let expected = if relisten.is_some() {
            if cfg!(target_os = "linux") { 3 } else { 2 }
        } else if backlog == 0 && cfg!(target_os = "macos") {
            5
        } else {
            backlog as usize + usize::from(cfg!(target_os = "linux"))
        };
        assert_eq!(real, expected, "backlog={backlog}, relisten={relisten:?}");
        assert_eq!(Sim::new().run(|| listener_backlog(backlog, relisten)), real);
        assert_eq!(
            Sim::builder()
                .deterministic()
                .seed(7)
                .build()
                .run(|| listener_backlog(backlog, relisten)),
            real
        );
        #[cfg(target_os = "linux")]
        assert_eq!(
            Sim::builder()
                .host(snare::HostProfile::new().build())
                .build()
                .run(|| listener_backlog(backlog, relisten)),
            real
        );
    }
}

/// A connection queued on a listener that closes before accepting it, and a connect to the
/// address afterwards.
fn listener_closed_with_a_queued_connection() -> Vec<String> {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let at = listener.local_addr().unwrap();
    let client = TcpStream::connect(at).unwrap();
    settle();
    drop(listener);
    settle();
    let c = client.as_raw_fd();
    vec![
        format!("{:?}", dontwait(c)),
        format!("{:?}", dontwait(c)),
        format!("{:?}", send(c, b"x", 0)),
        format!("{:?}", TcpStream::connect(at).map_err(|e| e.raw_os_error())),
    ]
}

#[test]
fn listener_closed_with_a_queued_connection_os_truth() {
    let real = listener_closed_with_a_queued_connection();
    let sim = Sim::new().run(listener_closed_with_a_queued_connection);
    assert_eq!(sim, real);
}

#[test]
fn listener_closed_with_a_queued_connection_in_the_sim() {
    assert_eq!(
        Sim::new().run(listener_closed_with_a_queued_connection),
        [
            format!("Err({})", libc::ECONNRESET),
            "Ok([])".into(),
            format!("Err({})", libc::EPIPE),
            format!("Err(Some({}))", libc::ECONNREFUSED)
        ]
    );
}

/// A stream configured every way and left with a pending reset is closed; the next stream starts
/// clean.
fn fresh_after_close() -> Vec<String> {
    let (old, peer) = pair();
    old.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    old.set_write_timeout(Some(Duration::from_secs(4))).unwrap();
    old.set_nodelay(true).unwrap();
    old.set_nonblocking(true).unwrap();
    netfault::set_linger(old.as_raw_fd(), 5);
    abort_on_drop(&peer);
    drop(peer);
    settle();
    let old_fd = old.as_raw_fd();
    let pending = so_error(old_fd);
    drop(old);
    let (new, _peer) = pair();
    let fd = new.as_raw_fd();
    vec![
        format!(
            "old pending {}",
            pending == libc::ECONNRESET || pending == 0
        ),
        format!("{:?}", new.read_timeout().unwrap()),
        format!("{:?}", new.write_timeout().unwrap()),
        format!("{}", new.nodelay().unwrap()),
        format!("{}", o_nonblock(fd)),
        format!("{}", linger_on(fd)),
        format!("{}", so_error(fd)),
        format!("{:?}", new.take_error().unwrap()),
    ]
}

#[test]
fn a_new_socket_after_close_has_no_stale_state_os_truth() {
    let real = fresh_after_close();
    let sim = Sim::new().run(fresh_after_close);
    assert_eq!(sim, real);
    assert_eq!(
        sim,
        [
            "old pending true",
            "None",
            "None",
            "false",
            "false",
            "false",
            "0",
            "None"
        ]
    );
}

#[test]
fn a_new_socket_after_close_has_a_fresh_record() {
    Sim::new().run(|| {
        let (mut old, mut peer) = pair();
        old.write_all(b"12345").unwrap();
        let mut buf = [0u8; 5];
        peer.read_exact(&mut buf).unwrap();
        let old_id = snare::socket_id(&old).unwrap();
        drop(old);
        drop(peer);
        let (new, _peer) = pair();
        let id = snare::socket_id(&new).unwrap();
        assert!(id > old_id);
        let entry = snare::socket_entry(id).unwrap();
        assert_eq!(
            (
                entry.sent,
                entry.delivered,
                entry.delivered_bytes,
                entry.pending_error
            ),
            (0, 0, 0, None)
        );
        assert!(snare::closed_sockets().iter().any(|e| e.id == old_id));
    });
}

/// `try_clone` (`F_DUPFD_CLOEXEC`): a write through the clone is read through the original, and the
/// clone keeps the stream alive once the original is closed.
fn cloned_stream() -> Vec<String> {
    let (client, mut server) = pair();
    let mut clone = client.try_clone().unwrap();
    clone.write_all(b"via clone").unwrap();
    let mut buf = [0u8; 9];
    server.read_exact(&mut buf).unwrap();
    let mut seen = vec![String::from_utf8_lossy(&buf).into_owned()];
    drop(client);
    settle();
    server.write_all(b"still").unwrap();
    let mut buf = [0u8; 5];
    clone.read_exact(&mut buf).unwrap();
    seen.push(String::from_utf8_lossy(&buf).into_owned());
    seen.push(format!("{:?}", dontwait(server.as_raw_fd())));
    drop(clone);
    settle();
    seen.push(format!("{:?}", dontwait(server.as_raw_fd())));
    seen
}

#[test]
fn try_clone_shares_the_stream_os_truth() {
    let real = cloned_stream();
    let sim = Sim::new().run(cloned_stream);
    assert_eq!(sim, real);
    assert_eq!(
        sim,
        [
            "via clone".to_string(),
            "still".into(),
            format!("Err({})", libc::EAGAIN),
            "Ok([])".into(),
        ]
    );
}

/// Duplicated descriptors share status flags on their open file description.
#[test]
fn f_dupfd_copies_share_their_nonblocking_flag_os_truth() {
    let flags = |nonblock_after_set_on_original: &mut Vec<bool>| {
        let (client, _server) = pair();
        let clone = client.try_clone().unwrap();
        client.set_nonblocking(true).unwrap();
        nonblock_after_set_on_original.push(o_nonblock(client.as_raw_fd()));
        nonblock_after_set_on_original.push(o_nonblock(clone.as_raw_fd()));
    };
    let mut real = Vec::new();
    flags(&mut real);
    assert_eq!(real, [true, true]);
    let sim = Sim::new().run(|| {
        let mut sim = Vec::new();
        flags(&mut sim);
        sim
    });
    assert_eq!(sim, real);
}

/// A raw `dup(2)` of a stream: a write through the copy reaches the peer.
fn raw_dup() -> Vec<String> {
    let (client, server) = pair();
    let copy = unsafe { libc::dup(client.as_raw_fd()) };
    assert!(copy >= 0, "dup");
    let sent = send(copy, b"dup", 0);
    settle();
    let seen = vec![
        format!("{sent:?}"),
        format!("{:?}", dontwait(server.as_raw_fd())),
    ];
    unsafe { libc::close(copy) };
    seen
}

#[test]
fn raw_dup_shares_the_socket_os_truth() {
    let real = raw_dup();
    let sim = Sim::new().run(raw_dup);
    assert_eq!(sim, real);
}

#[test]
fn raw_dup_in_the_sim() {
    assert_eq!(Sim::new().run(raw_dup), ["Ok(3)", "Ok([100, 117, 112])"]);
}

/// How long a blocking read with `SO_RCVTIMEO` 1.5 s waits on the virtual clock, and how it fails.
fn rcvtimeo_span() -> (ErrorKind, Duration) {
    let (_client, mut server) = pair();
    server
        .set_read_timeout(Some(Duration::from_millis(1500)))
        .unwrap();
    let start = Instant::now();
    let err = server.read(&mut [0u8; 8]).unwrap_err();
    (err.kind(), start.elapsed())
}

#[test]
fn so_rcvtimeo_gives_up_at_the_exact_virtual_deadline() {
    let (kind, waited) = Sim::builder().deterministic().build().run(rcvtimeo_span);
    assert_eq!(kind, ErrorKind::WouldBlock);
    assert_eq!(waited, Duration::from_nanos(1_500_000_001));
    let (kind, waited) = Sim::new().run(rcvtimeo_span);
    assert_eq!(kind, ErrorKind::WouldBlock);
    assert!(
        waited >= Duration::from_millis(1500) && waited < Duration::from_micros(1_500_100),
        "{waited:?}"
    );
}

/// How long a blocking write into a full stream with `SO_SNDTIMEO` 2 s waits, and how it fails;
/// then a write with room for part of it.
fn sndtimeo_span() -> (Result<usize, i32>, Duration, Result<usize, i32>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    netfault::set_buf(listener.as_raw_fd(), true, 4096);
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    netfault::set_buf(client.as_raw_fd(), false, 4096);
    let (mut server, _) = listener.accept().unwrap();
    let c = client.as_raw_fd();
    while send(c, &[1u8; 4096], libc::MSG_DONTWAIT).is_ok() {}
    client
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let start = Instant::now();
    let blocked = send(c, &[2u8; 100], 0);
    let waited = start.elapsed();
    let mut sink = [0u8; 3000];
    server.read_exact(&mut sink).unwrap();
    let partial = send(c, &[3u8; 10_000], 0);
    (blocked, waited, partial)
}

#[test]
fn so_sndtimeo_gives_up_at_the_exact_virtual_deadline() {
    let (blocked, waited, partial) = Sim::builder().deterministic().build().run(sndtimeo_span);
    assert_eq!(blocked, Err(libc::EAGAIN));
    assert_eq!(waited, Duration::from_nanos(2_000_000_001));
    assert_eq!(partial, Ok(3000));
}

#[test]
fn duplicated_fresh_sockets_share_bind_listen_connect_and_options_os_truth() {
    use std::os::fd::FromRawFd;
    let probe = || {
        let listener = unsafe { TcpListener::from_raw_fd(tcp_socket()) };
        let listening = listener.try_clone().unwrap();
        raw_bind(listening.as_raw_fd(), "127.0.0.1:0".parse().unwrap());
        assert_eq!(unsafe { libc::listen(listening.as_raw_fd(), 8) }, 0);
        assert_eq!(
            listener.local_addr().unwrap(),
            listening.local_addr().unwrap()
        );
        let address = listener.local_addr().unwrap();
        drop(listening);
        let mut client = unsafe { TcpStream::from_raw_fd(tcp_socket()) };
        let connecting = client.try_clone().unwrap();
        assert_eq!(raw_connect(connecting.as_raw_fd(), address), Ok(()));
        assert_eq!(client.peer_addr().unwrap(), connecting.peer_addr().unwrap());
        assert_eq!(
            client.local_addr().unwrap(),
            connecting.local_addr().unwrap()
        );
        drop(connecting);
        let (mut server, _) = listener.accept().unwrap();
        client.write_all(b"aliases").unwrap();
        let mut received = [0; 7];
        server.read_exact(&mut received).unwrap();
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        assert!(fd >= 0);
        let udp = unsafe { std::net::UdpSocket::from_raw_fd(fd) };
        let bound = udp.try_clone().unwrap();
        raw_bind(bound.as_raw_fd(), "127.0.0.1:0".parse().unwrap());
        assert_eq!(udp.local_addr().unwrap(), bound.local_addr().unwrap());
        let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        bound.connect(peer.local_addr().unwrap()).unwrap();
        assert_eq!(udp.peer_addr().unwrap(), bound.peer_addr().unwrap());
        bound.set_broadcast(true).unwrap();
        assert!(udp.broadcast().unwrap());
        drop(bound);
        udp.send(b"udp alias").unwrap();
        let mut bytes = [0; 16];
        let n = peer.recv(&mut bytes).unwrap();
        (received, bytes[..n].to_vec())
    };
    let real = probe();
    assert_eq!(real, (*b"aliases", b"udp alias".to_vec()));
    assert_eq!(Sim::new().run(probe), real);
}

#[test]
fn duplicated_descriptors_honor_minimum_and_local_cloexec_os_truth() {
    use std::os::fd::FromRawFd;
    let probe = || {
        let (client, _server) = pair();
        let fd = client.as_raw_fd();
        assert_eq!(
            unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) },
            0
        );
        assert_eq!(unsafe { libc::fcntl(fd, libc::F_DUPFD, -1) }, -1);
        let invalid_minimum = last_errno();
        let minimum = fd + 16;
        let plain_fd = unsafe { libc::fcntl(fd, libc::F_DUPFD, minimum) };
        assert!(plain_fd >= minimum);
        let plain = unsafe { TcpStream::from_raw_fd(plain_fd) };
        let cloexec_fd = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, minimum) };
        assert!(cloexec_fd >= minimum);
        let cloexec = unsafe { TcpStream::from_raw_fd(cloexec_fd) };
        let flags = |fd| unsafe { libc::fcntl(fd, libc::F_GETFD) };
        let initial = [fd, plain_fd, cloexec_fd].map(flags);
        assert_eq!(
            unsafe { libc::fcntl(plain_fd, libc::F_SETFD, libc::FD_CLOEXEC) },
            0
        );
        assert_eq!(unsafe { libc::fcntl(fd, libc::F_SETFD, 0) }, 0);
        let changed = [fd, plain_fd, cloexec_fd].map(flags);
        plain.set_nonblocking(true).unwrap();
        let shared_nonblock = [fd, plain_fd, cloexec_fd].map(o_nonblock);
        cloexec.set_nonblocking(false).unwrap();
        let shared_block = [fd, plain_fd, cloexec_fd].map(o_nonblock);
        (
            invalid_minimum,
            initial,
            changed,
            shared_nonblock,
            shared_block,
        )
    };
    let real = probe();
    assert_eq!(
        real,
        (
            libc::EINVAL,
            [libc::FD_CLOEXEC, 0, libc::FD_CLOEXEC],
            [0, libc::FD_CLOEXEC, libc::FD_CLOEXEC],
            [true; 3],
            [false; 3]
        )
    );
    assert_eq!(Sim::new().run(probe), real);
}
