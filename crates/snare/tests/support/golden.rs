//! Golden files: byte-exact expected outputs kept under `tests/golden/`. A test renders what it
//! observed to bytes and hands it to [`check`] (or [`check_text`]); a mismatch fails with both
//! sides. Run with `SNARE_BLESS=1` to write the observed bytes as the new golden instead (only on a
//! writable checkout; the Linux Docker run mounts the tree read-only, so bless Linux goldens with a
//! writable mount). A missing golden fails unless blessing.
//!
//! The file is read and written with [`snare::real`], so a check inside a `Sim` (a `VirtualFs`
//! in front of the real tree) still reaches the checkout.

#![allow(dead_code)]

use std::path::PathBuf;

/// `tests/golden/<name>`.
pub fn path(name: &str) -> PathBuf {
    let compiled = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("golden");
    snare::real(|| {
        if compiled.is_dir() {
            return compiled.join(name);
        }
        if let Ok(executable) = std::env::current_exe() {
            for ancestor in executable.ancestors() {
                let directory = ancestor.join("crates/snare/tests/golden");
                if directory.is_dir() {
                    return directory.join(name);
                }
            }
        }
        compiled.join(name)
    })
}

/// Whether `SNARE_BLESS` asks for goldens to be rewritten.
pub fn blessing() -> bool {
    snare::real(|| std::env::var("SNARE_BLESS")).is_ok_and(|v| !v.is_empty() && v != "0")
}

/// Asserts `actual` equals `tests/golden/<name>` byte for byte, or writes it there when
/// [`blessing`].
#[track_caller]
pub fn check(name: &str, actual: &[u8]) {
    let path = path(name);
    if blessing() {
        snare::real(|| {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, actual).unwrap();
        });
        return;
    }
    let expected = match snare::real(|| std::fs::read(&path)) {
        Ok(bytes) => bytes,
        Err(e) => panic!(
            "golden {} unreadable ({e}); run with SNARE_BLESS=1 to create it",
            path.display()
        ),
    };
    if expected != actual {
        panic!(
            "golden {} differs (SNARE_BLESS=1 rewrites it)\n--- expected\n{}\n--- actual\n{}",
            path.display(),
            String::from_utf8_lossy(&expected),
            String::from_utf8_lossy(actual)
        );
    }
}

/// [`check`] for text.
#[track_caller]
pub fn check_text(name: &str, actual: &str) {
    check(name, actual.as_bytes());
}

/// Lowercase hex, 32 bytes to a line, for binary goldens that stay diffable.
pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2 + bytes.len() / 32 + 1);
    for line in bytes.chunks(32) {
        for b in line {
            out.push_str(&format!("{b:02x}"));
        }
        out.push('\n');
    }
    out
}
