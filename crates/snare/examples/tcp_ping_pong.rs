//! A stateful peer: it counts the requests it has answered and folds that count into each reply,
//! showing that a `then_action` closure may carry mutable state across messages on one connection
//! (man 7 tcp: one ordered byte stream per connection).
//!
//! Run with: `cargo run -p snare --example tcp_ping_pong`

#[cfg(unix)]
fn main() {
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpStream;
    use std::time::Duration;

    use snare::{Line, Sim, TesterAction, connect_tester, run_testers};

    Sim::new().run(|| {
        let server = connect_tester::<Line>("127.0.0.2:9501")
            .then_action({
                let mut answered = 0u64;
                move |msg, _from| {
                    answered += 1;
                    TesterAction::Send(Line(format!("pong#{answered}:{}", msg.0)))
                }
            })
            .until_after(Duration::from_millis(300));

        let client = std::thread::spawn(|| {
            let stream = TcpStream::connect("127.0.0.2:9501").unwrap();
            let mut writer = stream.try_clone().unwrap();
            let mut reader = BufReader::new(stream);
            let mut replies = Vec::new();
            for word in ["ping", "ping", "ping"] {
                writeln!(writer, "{word}").unwrap();
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                replies.push(line.trim().to_string());
            }
            replies
        });

        run_testers!(server);
        let replies = client.join().unwrap();
        assert_eq!(replies, vec!["pong#1:ping", "pong#2:ping", "pong#3:ping"]);
        println!("tcp_ping_pong: {replies:?}");
    });
}

#[cfg(not(unix))]
fn main() {
    println!("tcp_ping_pong: this example needs a unix target");
}
