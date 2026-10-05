//! A newline-framed echo server played by a tester, with the code under test connecting to it
//! over a real `std::net::TcpStream`. TCP carries an unframed byte stream (man 7 tcp); `Line`
//! draws the message boundaries at each `\n`.
//!
//! Run with: `cargo run -p snare --example tcp_echo`

#[cfg(unix)]
fn main() {
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpStream;
    use std::time::Duration;

    use snare::{Line, Sim, TesterAction, connect_tester, run_testers};

    Sim::new().run(|| {
        let server = connect_tester::<Line>("127.0.0.2:9500")
            .then_action(|msg, _from| TesterAction::Send(Line(format!("echo:{}", msg.0))))
            .until_after(Duration::from_millis(300));

        let client = std::thread::spawn(|| {
            let stream = TcpStream::connect("127.0.0.2:9500").unwrap();
            let mut writer = stream.try_clone().unwrap();
            let mut reader = BufReader::new(stream);
            writer.write_all(b"hello\n").unwrap();
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            line
        });

        run_testers!(server);
        let reply = client.join().unwrap();
        assert_eq!(reply, "echo:hello\n");
        println!("tcp_echo: sent 'hello', received {reply:?}");
    });
}

#[cfg(not(unix))]
fn main() {
    println!("tcp_echo: this example needs a unix target");
}
