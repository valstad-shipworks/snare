//! Serve a config file from memory to code that uses ordinary `std::fs`.
//!
//! Run with: `cargo run -p snare --example vfs_config_file`
//!
//! The "application" below reads `/etc/app/config.toml` with a plain `std::fs::read_to_string`
//! (man 2 open + man 2 read under the hood). The sim serves the declared bytes; nothing touches
//! the real disk, and undeclared paths under the owned `/etc/app` prefix fail with ENOENT.

#[cfg(unix)]
fn main() {
    use snare::{FsBuilder, Sim};

    fn load_max_connections() -> u32 {
        let text = std::fs::read_to_string("/etc/app/config.toml").expect("config present");
        text.lines()
            .find_map(|l| l.strip_prefix("max_connections = "))
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0)
    }

    let fs = FsBuilder::new()
        .own_prefix("/etc/app")
        .file(
            "/etc/app/config.toml",
            "name = \"demo\"\nmax_connections = 128\n",
        )
        .build();

    let sim = Sim::builder().fs(fs).build();
    let n = sim.run(load_max_connections);

    println!("vfs_config_file: loaded max_connections = {n} from a virtual /etc/app/config.toml");
    assert_eq!(n, 128);
}

#[cfg(not(unix))]
fn main() {
    println!("vfs_config_file: the virtual filesystem is a unix-only feature");
}
