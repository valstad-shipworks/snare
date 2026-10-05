#![cfg(unix)]

use std::io::Write;

use snare::{FsBuilder, HostProfile, Sim};

#[test]
fn append_mode_should_extend_rather_than_overwrite() {
    let fs = FsBuilder::new()
        .own_prefix("/o")
        .dir("/o")
        .file("/o/log", "ORIGINAL")
        .build();
    Sim::builder().fs(fs).build().run(|| {
        {
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open("/o/log")
                .unwrap();
            f.write_all(b"-MORE").unwrap();
        }
        assert_eq!(std::fs::read_to_string("/o/log").unwrap(), "ORIGINAL-MORE");
    });
}

#[cfg_attr(
    target_os = "linux",
    ignore = "bug: Linux environ is a directly accessed process-global variable"
)]
#[test]
fn vars_should_enumerate_the_simulated_environment() {
    let host = HostProfile::new()
        .env("SIM_A", "1")
        .env("SIM_B", "2")
        .build();
    Sim::builder().host(host).build().run(|| {
        let keys: Vec<String> = std::env::vars().map(|(k, _)| k).collect();
        assert!(keys.contains(&"SIM_A".to_string()));
        assert!(keys.contains(&"SIM_B".to_string()));
    });
}
