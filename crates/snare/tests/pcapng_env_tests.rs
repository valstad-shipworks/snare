//! `SNARE_PCAPNG_TESTS` captures the sims of the listed test threads only, into `SNARE_PCAPNG_DIR`
//! or a default directory, and `SNARE_PCAPNG_WALL_COMMENT` adds wall-time comments. The only test
//! in its binary, since it sets process-wide variables.

#[path = "support/pcapng_reader.rs"]
mod reader;

use std::net::UdpSocket;
use std::path::PathBuf;

use snare::Sim;

/// A sim built on a thread named `name`, returning where it captures.
fn built_on(name: &str) -> Option<PathBuf> {
    std::thread::Builder::new()
        .name(name.into())
        .spawn(|| Sim::new().pcapng_path().map(PathBuf::from))
        .unwrap()
        .join()
        .unwrap()
}

fn set(key: &str, value: impl AsRef<std::ffi::OsStr>) {
    unsafe { std::env::set_var(key, value) };
}

fn unset(key: &str) {
    unsafe { std::env::remove_var(key) };
}

#[test]
fn tests_list_selects_sims_by_thread_name() {
    let me = std::thread::current().name().unwrap().to_owned();
    unset("SNARE_PCAPNG_DIR");
    unset("SNARE_PCAPNG_WALL_COMMENT");

    set("SNARE_PCAPNG_TESTS", format!("unrelated, {me} ,"));
    let default_dir = std::env::temp_dir().join("snare-pcapng");
    let sim = Sim::new();
    assert_eq!(
        sim.pcapng_path(),
        Some(default_dir.join(format!("{me}.pcapng")).as_path()),
        "a listed test captures to the default directory without SNARE_PCAPNG_DIR"
    );
    sim.run(|| {
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        s.send_to(b"listed", "127.0.0.1:9").unwrap();
    });
    let path = sim.pcapng_path().unwrap().to_owned();
    drop(sim);
    let file = reader::read(&path);
    assert!(!file.packets.is_empty());
    assert!(file.packets.iter().all(|p| p.comment.is_none()));
    assert_eq!(
        built_on("someone_else"),
        None,
        "an unlisted thread is not captured"
    );

    let dir = std::env::temp_dir().join(format!("snare-pcapng-tests-{}", std::process::id()));
    set("SNARE_PCAPNG_DIR", &dir);
    set("SNARE_PCAPNG_TESTS", "worker");
    assert_eq!(
        built_on("pool::worker"),
        Some(dir.join("pool--worker.pcapng")),
        "an entry matches the thread name's last `::` segments, into SNARE_PCAPNG_DIR"
    );
    assert_eq!(
        built_on("coworker"),
        None,
        "a suffix inside a segment does not match"
    );
    assert_eq!(
        Sim::new().pcapng_path(),
        None,
        "the list narrows SNARE_PCAPNG_DIR"
    );

    set("SNARE_PCAPNG_TESTS", " , ");
    let everyone = Sim::new();
    assert_eq!(
        everyone.pcapng_path(),
        Some(dir.join(format!("{me}.pcapng")).as_path()),
        "a blank list is no list: SNARE_PCAPNG_DIR captures every sim"
    );
    drop(everyone);

    unset("SNARE_PCAPNG_TESTS");
    set("SNARE_PCAPNG_WALL_COMMENT", "1");
    let explicit = dir.join("wall-env.pcapng");
    let sim = Sim::builder().pcapng(&explicit).build();
    sim.run(|| {
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        s.send_to(b"wall", "127.0.0.1:9").unwrap();
    });
    drop(sim);
    let file = reader::read(&explicit);
    assert!(
        file.packets[0]
            .comment
            .as_deref()
            .is_some_and(|c| c.starts_with("wall ")),
        "{:?}",
        file.packets[0].comment
    );
    set("SNARE_PCAPNG_WALL_COMMENT", "0");
    let sim = Sim::builder().pcapng(&explicit).build();
    sim.run(|| {
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        s.send_to(b"plain", "127.0.0.1:9").unwrap();
    });
    drop(sim);
    assert_eq!(reader::read(&explicit).packets[0].comment, None);

    unset("SNARE_PCAPNG_WALL_COMMENT");
    unset("SNARE_PCAPNG_DIR");
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(&path);
}
