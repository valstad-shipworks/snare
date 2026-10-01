#![cfg(unix)]
//! Known limitations of the current virtual-fs / env model, pinned as `#[ignore]` tests so the
//! behaviour is documented and a future fix has a ready-made check to un-ignore. Running the suite
//! stays green; `cargo test -- --ignored` shows the gaps.

use std::io::Write;

use snare::{FsBuilder, HostProfile, Sim};

#[ignore = "sim limitation: O_APPEND is not modelled; writes start at offset 0 instead of end"]
#[test]
fn append_mode_should_extend_rather_than_overwrite() {
    let fs = FsBuilder::new()
        .own_prefix("/o")
        .dir("/o")
        .file("/o/log", "ORIGINAL")
        .build();
    Sim::builder().fs(fs).build().run(|| {
        // man 2 open O_APPEND: before each write the offset is set to the end of the file, so the
        // bytes should be appended. The sim opens at offset 0, so this currently overwrites.
        {
            let mut f = std::fs::OpenOptions::new().append(true).open("/o/log").unwrap();
            f.write_all(b"-MORE").unwrap();
        }
        assert_eq!(std::fs::read_to_string("/o/log").unwrap(), "ORIGINAL-MORE");
    });
}

#[ignore = "sim limitation: only getenv/setenv/unsetenv are interposed; std::env::vars() reads the real environ"]
#[test]
fn vars_should_enumerate_the_simulated_environment() {
    let host = HostProfile::new().env("SIM_A", "1").env("SIM_B", "2").build();
    Sim::builder().host(host).build().run(|| {
        // std::env::vars() walks the `environ` global directly rather than calling getenv(3), so
        // the interposer does not see it and the simulated keys are absent.
        let keys: Vec<String> = std::env::vars().map(|(k, _)| k).collect();
        assert!(keys.contains(&"SIM_A".to_string()));
        assert!(keys.contains(&"SIM_B".to_string()));
    });
}
