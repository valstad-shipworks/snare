//! A blocking read with no timeout keeps waiting while the thread that will answer it is stuck on a
//! lock in static data held by a thread outside the sim, as another test running in parallel may
//! hold std's stdout lock or a shared `static`. Every thread of the sim is blocked meanwhile with no
//! timer pending, which is no deadlock: the read must not give up with `WouldBlock`, which a real
//! blocking socket never reports.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::sync::Mutex;
use std::sync::mpsc;
use std::time::Duration;

use snare::Sim;

/// Longer than any grace snare gives an outside holder before it counts the waiter blocked.
const HELD: Duration = Duration::from_millis(300);

static SHARED: Mutex<()> = Mutex::new(());

fn sims() -> [(&'static str, Sim); 2] {
    [
        ("discrete", Sim::new()),
        (
            "deterministic",
            Sim::builder().deterministic().seed(1).build(),
        ),
    ]
}

/// Runs `body` in each kind of sim while a thread outside it holds [`SHARED`] for [`HELD`].
fn with_outside_holder(body: fn()) {
    for (kind, sim) in sims() {
        let (held, release) = mpsc::channel();
        let holder = std::thread::spawn(move || {
            let _guard = SHARED.lock().unwrap();
            held.send(()).unwrap();
            std::thread::sleep(HELD);
        });
        release.recv().unwrap();
        println!("{kind} sim");
        sim.run(body);
        holder.join().unwrap();
    }
}

#[test]
fn a_blocking_udp_receive_waits_out_an_outside_lock_holder() {
    with_outside_holder(|| {
        let reader = UdpSocket::bind("127.0.0.1:7001").unwrap();
        let sender = std::thread::spawn(|| {
            let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
            drop(SHARED.lock().unwrap());
            socket.send_to(&[7], "127.0.0.1:7001").unwrap();
        });
        let mut buf = [0; 4];
        let (n, _) = reader
            .recv_from(&mut buf)
            .expect("a blocking receive waits for its datagram");
        assert_eq!(&buf[..n], [7]);
        sender.join().unwrap();
    });
}

#[test]
fn a_blocking_tcp_read_waits_out_an_outside_lock_holder() {
    with_outside_holder(|| {
        let listener = TcpListener::bind("127.0.0.1:7000").unwrap();
        let writer = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            drop(SHARED.lock().unwrap());
            stream.write_all(&[7]).unwrap();
        });
        let mut stream = TcpStream::connect("127.0.0.1:7000").unwrap();
        let mut byte = [0];
        stream
            .read_exact(&mut byte)
            .expect("a blocking read waits for its byte");
        assert_eq!(byte, [7]);
        writer.join().unwrap();
    });
}
