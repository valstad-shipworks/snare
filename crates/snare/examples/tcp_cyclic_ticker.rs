//! A peer that pushes unprompted traffic: `with_cyclic_action` fires on a period and sends to every
//! open connection, modelling a device that streams telemetry without being polled. The sim clock
//! is virtual, so the cyclic period is honoured deterministically rather than against wall time.
//!
//! Run with: `cargo run -p snare --example tcp_cyclic_ticker`

#[cfg(unix)]
fn main() {
    use std::io::{BufRead, BufReader};
    use std::net::TcpStream;
    use std::time::Duration;

    use snare::{Line, Sim, TesterAction, connect_tester, run_testers};

    Sim::new().run(|| {
        let server = connect_tester::<Line>("127.0.0.2:9502")
            .with_cyclic_action(Duration::from_millis(10), || TesterAction::Send(Line("tick".into())))
            .until_after(Duration::from_millis(400));

        let client = std::thread::spawn(|| {
            let stream = TcpStream::connect("127.0.0.2:9502").unwrap();
            let mut reader = BufReader::new(stream);
            let mut ticks = 0u32;
            let mut line = String::new();
            while ticks < 5 {
                line.clear();
                if reader.read_line(&mut line).unwrap() == 0 {
                    break;
                }
                if line.trim() == "tick" {
                    ticks += 1;
                }
            }
            ticks
        });

        run_testers!(server);
        let ticks = client.join().unwrap();
        assert_eq!(ticks, 5);
        println!("tcp_cyclic_ticker: received {ticks} unprompted ticks");
    });
}

#[cfg(not(unix))]
fn main() {
    println!("tcp_cyclic_ticker: this example needs a unix target");
}
