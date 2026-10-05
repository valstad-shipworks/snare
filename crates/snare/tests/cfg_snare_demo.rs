#![allow(unexpected_cfgs)]
#![cfg(all(unix, snare))]

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::time::Duration;

use snare::{Line, Sim, TesterAction, connect_tester, run_testers};

#[test]
fn echo_runs_under_interposition() {
    let sim = Sim::new();
    sim.run(|| {
        let server = connect_tester::<Line>("127.0.0.3:9500")
            .then_action(|msg, _from| TesterAction::Send(Line(format!("echo:{}", msg.0))))
            .until_after(Duration::from_millis(300));

        let client = std::thread::spawn(|| {
            let stream = TcpStream::connect("127.0.0.3:9500").unwrap();
            let mut writer = stream.try_clone().unwrap();
            let mut reader = BufReader::new(stream);
            writer.write_all(b"hello\n").unwrap();
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            line
        });

        run_testers!(server);
        assert_eq!(client.join().unwrap(), "echo:hello\n");
    });
}
