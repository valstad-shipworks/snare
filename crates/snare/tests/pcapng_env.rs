//! `SNARE_PCAPNG_DIR` captures every sim built without an explicit path, named after the thread
//! that builds it. The only test in its binary, since it sets a process-wide variable.

use std::net::UdpSocket;

use snare::Sim;

#[test]
fn env_dir_opt_in_names_file_after_test_thread_with_suffix() {
    let dir = std::env::temp_dir().join(format!("snare-pcapng-env-{}", std::process::id()));
    unsafe { std::env::set_var("SNARE_PCAPNG_DIR", &dir) };
    let first = Sim::new();
    let second = Sim::new();
    let name = std::thread::current().name().unwrap().replace(':', "-");
    assert_eq!(
        first.pcapng_path(),
        Some(dir.join(format!("{name}.pcapng")).as_path())
    );
    assert_eq!(
        second.pcapng_path(),
        Some(dir.join(format!("{name}-2.pcapng")).as_path())
    );
    second.run(|| {
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        s.send_to(b"x", "127.0.0.1:9").unwrap();
    });
    drop(second);
    drop(first);
    let explicit = dir.join("explicit.pcapng");
    let sim = Sim::builder().pcapng(&explicit).build();
    assert_eq!(sim.pcapng_path(), Some(explicit.as_path()));
    drop(sim);
    unsafe { std::env::remove_var("SNARE_PCAPNG_DIR") };
    assert_eq!(Sim::new().pcapng_path(), None);
    let written = std::fs::read(dir.join(format!("{name}-2.pcapng"))).unwrap();
    assert!(
        written.len() > 100,
        "the second sim's datagram was captured"
    );
}
