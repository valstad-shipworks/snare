//! Enumerate a virtual directory with `std::fs::read_dir`.
//!
//! Run with: `cargo run -p snare --example vfs_directory_listing`
//!
//! `read_dir` drives `opendir(3)` + `readdir(3)` (on Linux, `getdents64(2)`). The sim snapshots the
//! declared tree and returns one record at a time, distinguishing files from subdirectories by
//! their `d_type`. Output is sorted so the example is deterministic under the virtual clock.

#[cfg(unix)]
fn main() {
    use snare::{FsBuilder, Sim};

    let fs = FsBuilder::new()
        .own_prefix("/srv/data")
        .file("/srv/data/readme.txt", "hello")
        .file("/srv/data/values.csv", "1,2,3\n")
        .dir("/srv/data/archive")
        .build();

    let sim = Sim::builder().fs(fs).build();
    let mut entries = sim.run(|| {
        std::fs::read_dir("/srv/data")
            .expect("directory present")
            .map(|e| {
                let e = e.unwrap();
                let kind = if e.file_type().unwrap().is_dir() { "dir " } else { "file" };
                format!("{kind}  {}", e.file_name().to_string_lossy())
            })
            .collect::<Vec<_>>()
    });
    entries.sort();

    println!("vfs_directory_listing: /srv/data contains {} entries:", entries.len());
    for e in &entries {
        println!("  {e}");
    }
    assert_eq!(entries.len(), 3);
}

#[cfg(not(unix))]
fn main() {
    println!("vfs_directory_listing: the virtual filesystem is a unix-only feature");
}
