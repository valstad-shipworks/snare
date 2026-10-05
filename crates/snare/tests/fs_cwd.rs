#![cfg(unix)]

use snare::{FsBuilder, Sim};
use std::ffi::{CStr, CString};
use std::path::{Path, PathBuf};

static CWD_TESTS: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn observation(root: &Path) -> (Vec<PathBuf>, Vec<Vec<u8>>, Vec<i32>) {
    let dir = CString::new(root.join("sub").as_os_str().as_encoded_bytes()).unwrap();
    let fd = unsafe { libc::open(dir.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) };
    assert!(fd >= 0);
    std::env::set_current_dir(root.join("alias")).unwrap();
    let mut paths = vec![std::env::current_dir().unwrap()];
    let mut contents = vec![std::fs::read("../file").unwrap()];
    std::fs::write("created", b"new").unwrap();
    std::fs::rename(root.join("sub"), root.join("moved")).unwrap();
    paths.push(std::env::current_dir().unwrap());
    contents.push(std::fs::read("created").unwrap());
    std::env::set_current_dir(root).unwrap();
    assert_eq!(unsafe { libc::fchdir(fd) }, 0);
    paths.push(std::env::current_dir().unwrap());
    let mut errors = Vec::new();
    for (null, len) in [
        (false, 0),
        (false, 1),
        (false, 4096),
        (true, 0),
        (true, 1),
        (true, 4096),
    ] {
        let mut bytes = [0; 4096];
        let result = unsafe {
            libc::getcwd(
                if null {
                    std::ptr::null_mut()
                } else {
                    bytes.as_mut_ptr().cast()
                },
                len,
            )
        };
        errors.push(if result.is_null() {
            std::io::Error::last_os_error().raw_os_error().unwrap()
        } else {
            0
        });
        if !result.is_null() {
            contents.push(unsafe { CStr::from_ptr(result) }.to_bytes().to_vec());
            if null {
                unsafe { libc::free(result.cast()) };
            }
        }
    }
    unsafe { libc::close(fd) };
    (paths, contents, errors)
}

#[test]
fn cwd_follows_directory_inodes_without_changing_the_process_cwd() {
    let _guard = CWD_TESTS.lock().unwrap();
    let original = std::env::current_dir().unwrap();
    let root = std::fs::canonicalize(std::env::temp_dir())
        .unwrap()
        .join(format!("snare-cwd-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    std::fs::create_dir(root.join("sub")).unwrap();
    std::fs::write(root.join("file"), b"contents").unwrap();
    std::os::unix::fs::symlink("sub", root.join("alias")).unwrap();
    let native = observation(&root);
    std::env::set_current_dir(&original).unwrap();
    std::fs::remove_dir_all(&root).unwrap();
    for deterministic in [false, true] {
        let fs = FsBuilder::new()
            .own_prefix(&root)
            .file(root.join("file"), "contents")
            .dir(root.join("sub"))
            .symlink(root.join("alias"), "sub")
            .build();
        let builder = Sim::builder().fs(fs);
        let sim = if deterministic {
            builder.deterministic().build()
        } else {
            builder.build()
        };
        assert_eq!(
            sim.run(|| observation(&root)),
            native,
            "deterministic={deterministic}"
        );
        assert_eq!(std::env::current_dir().unwrap(), original);
        assert!(!root.exists());
    }
}

fn removed_directory(root: &Path) -> (Vec<i32>, Vec<bool>, u64) {
    let path = CString::new(root.join("directory").as_os_str().as_encoded_bytes()).unwrap();
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) };
    assert!(fd >= 0);
    assert_eq!(unsafe { libc::fchdir(fd) }, 0);
    std::fs::remove_dir(root.join("directory")).unwrap();
    let mut original: libc::stat = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::fstat(fd, &mut original) }, 0);
    let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { libc::fstatat(fd, c".".as_ptr(), &mut metadata, 0) },
        0
    );
    let mut same = vec![original.st_ino == metadata.st_ino];
    let cwd = std::fs::metadata(".").unwrap();
    use std::os::unix::fs::MetadataExt;
    same.push(cwd.ino() == original.st_ino);
    let child = unsafe { libc::openat(fd, c".".as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) };
    assert!(child >= 0);
    assert_eq!(unsafe { libc::fstat(child, &mut metadata) }, 0);
    same.push(original.st_ino == metadata.st_ino);
    let errors = vec![
        std::env::current_dir().unwrap_err().raw_os_error().unwrap(),
        std::env::set_current_dir(".")
            .err()
            .map_or(0, |error| error.raw_os_error().unwrap()),
    ];
    unsafe {
        libc::close(child);
        libc::close(fd);
    }
    (errors, same, original.st_nlink as u64)
}

#[test]
fn removed_directories_retain_descriptor_and_cwd_identity() {
    let _guard = CWD_TESTS.lock().unwrap();
    let original = std::env::current_dir().unwrap();
    let root = std::fs::canonicalize(std::env::temp_dir())
        .unwrap()
        .join(format!("snare-cwd-unlinked-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    std::fs::create_dir(root.join("directory")).unwrap();
    let native = removed_directory(&root);
    std::env::set_current_dir(&original).unwrap();
    std::fs::remove_dir_all(&root).unwrap();
    let sim = Sim::builder()
        .fs(FsBuilder::new()
            .own_prefix(&root)
            .dir(&root)
            .dir(root.join("directory"))
            .build())
        .build();
    assert_eq!(sim.run(|| removed_directory(&root)), native);
    assert_eq!(std::env::current_dir().unwrap(), original);
}
