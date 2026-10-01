//! Reach the real machine from inside a sim with `snare::real`.
//!
//! Run with: `cargo run -p snare --example vfs_real_escape`
//!
//! The code under test sees an owned virtual `/workspace`, where undeclared paths ENOENT. Support
//! code that genuinely needs the real filesystem or the real environment wraps its `std` calls in
//! `snare::real(|| ...)`, which routes this thread's OS calls (man 2 open, man 3 getenv) straight
//! to the kernel for the duration of the closure.

#[cfg(unix)]
fn main() {
    use snare::{FsBuilder, Sim};

    let mut scratch = std::env::temp_dir();
    scratch.push(format!("snare-real-escape-{}.txt", std::process::id()));
    let _ = std::fs::remove_file(&scratch);

    let fs = FsBuilder::new()
        .own_prefix("/workspace")
        .file("/workspace/input.txt", "virtual input\n")
        .build();

    let sim = Sim::builder().fs(fs).build();
    let scratch_in = scratch.clone();
    let virtual_input = sim.run(move || {
        let input = std::fs::read_to_string("/workspace/input.txt").unwrap();

        // The virtual plane owns "/workspace", but a real report file must persist to disk.
        snare::real(|| std::fs::write(&scratch_in, format!("report for: {input}")))
            .expect("real write");

        input
    });

    let persisted = std::fs::read_to_string(&scratch).unwrap();
    println!("vfs_real_escape: virtual input was {virtual_input:?}");
    println!("vfs_real_escape: real file on disk holds {persisted:?}");
    assert!(persisted.starts_with("report for: virtual input"));
    let _ = std::fs::remove_file(&scratch);
}

#[cfg(not(unix))]
fn main() {
    println!("vfs_real_escape: the escape hatch is a unix-only feature");
}
