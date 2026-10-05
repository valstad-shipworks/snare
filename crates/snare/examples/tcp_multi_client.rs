//! One tester serving several concurrent connections: the `from` address distinguishes each
//! client, and the tester accepts and answers all of them from its single run loop. Each
//! connection is its own independent TCP byte stream (man 7 tcp).
//!
//! Run with: `cargo run -p snare --example tcp_multi_client`

#[cfg(unix)]
fn main() {
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpStream;
    use std::time::Duration;

    use snare::{Line, Sim, TesterAction, connect_tester, run_testers};

    Sim::new().run(|| {
        let server = connect_tester::<Line>("127.0.0.2:9503")
            .then_action(|msg, _from| TesterAction::Send(Line(format!("ack:{}", msg.0))))
            .until_after(Duration::from_millis(500));

        let clients: Vec<_> = (0..4)
            .map(|id| {
                std::thread::spawn(move || {
                    let stream = TcpStream::connect("127.0.0.2:9503").unwrap();
                    let mut writer = stream.try_clone().unwrap();
                    let mut reader = BufReader::new(stream);
                    writeln!(writer, "client-{id}").unwrap();
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    line.trim().to_string()
                })
            })
            .collect();

        run_testers!(server);
        let mut acks: Vec<String> = clients.into_iter().map(|c| c.join().unwrap()).collect();
        acks.sort();
        assert_eq!(
            acks,
            vec![
                "ack:client-0",
                "ack:client-1",
                "ack:client-2",
                "ack:client-3"
            ]
        );
        println!("tcp_multi_client: {} clients acked: {acks:?}", acks.len());
    });
}

#[cfg(not(unix))]
fn main() {
    println!("tcp_multi_client: this example needs a unix target");
}
