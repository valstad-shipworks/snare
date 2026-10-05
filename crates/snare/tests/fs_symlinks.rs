#![cfg(unix)]

use snare::{FsBuilder, Sim};
use std::ffi::CString;
use std::os::unix::fs::{MetadataExt, symlink};
use std::path::Path;

fn errno<T>(result: std::io::Result<T>) -> i32 {
    result
        .err()
        .map_or(0, |error| error.raw_os_error().unwrap())
}

#[derive(Debug, PartialEq)]
struct Observation {
    reads: Vec<Result<Vec<u8>, i32>>,
    errors: Vec<i32>,
    link: Vec<u8>,
    kind: bool,
    size: u64,
    identity: bool,
    truncated: (isize, [u8; 4]),
    at: (i32, bool, Vec<u8>),
}

fn observe(root: &Path) -> Observation {
    let reads = [
        "relative",
        "absolute",
        "directory/file",
        "directory/../file",
    ]
    .map(|name| std::fs::read(root.join(name)).map_err(|error| error.raw_os_error().unwrap()))
    .to_vec();
    let mut errors = ["broken", "loop", "file/../relative", "missing/../relative"]
        .map(|name| errno(std::fs::read(root.join(name))))
        .to_vec();
    let relative = CString::new(root.join("relative").as_os_str().as_encoded_bytes()).unwrap();
    let mut truncated = [0xa5; 4];
    let count = unsafe { libc::readlink(relative.as_ptr(), truncated.as_mut_ptr().cast(), 2) };
    for name in ["relative", "broken", "directory"] {
        let path = CString::new(root.join(name).as_os_str().as_encoded_bytes()).unwrap();
        for mode in [libc::F_OK, libc::R_OK, libc::W_OK, libc::X_OK] {
            let result = unsafe { libc::access(path.as_ptr(), mode) };
            errors.push(if result < 0 {
                std::io::Error::last_os_error().raw_os_error().unwrap()
            } else {
                0
            });
        }
        let result = unsafe {
            libc::faccessat(
                libc::AT_FDCWD,
                path.as_ptr(),
                libc::F_OK,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        errors.push(if result < 0 {
            std::io::Error::last_os_error().raw_os_error().unwrap()
        } else {
            0
        });
    }
    let fd = unsafe { libc::open(relative.as_ptr(), libc::O_RDONLY | libc::O_NOFOLLOW) };
    errors.push(if fd < 0 {
        std::io::Error::last_os_error().raw_os_error().unwrap()
    } else {
        unsafe { libc::close(fd) };
        0
    });
    let link = std::fs::read_link(root.join("relative"))
        .unwrap()
        .into_os_string()
        .into_encoded_bytes();
    let metadata = std::fs::symlink_metadata(root.join("relative")).unwrap();
    let identity = std::fs::metadata(root.join("relative")).unwrap().ino()
        == std::fs::metadata(root.join("file")).unwrap().ino();
    let dir = CString::new(root.as_os_str().as_encoded_bytes()).unwrap();
    let dirfd = unsafe { libc::open(dir.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) };
    assert!(dirfd >= 0);
    let result = unsafe { libc::symlinkat(c"file".as_ptr(), dirfd, c"created".as_ptr()) };
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe {
            libc::fstatat(
                dirfd,
                c"created".as_ptr(),
                &mut stat,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        },
        0
    );
    let mut bytes = [0; 32];
    let length = unsafe {
        libc::readlinkat(
            dirfd,
            c"created".as_ptr(),
            bytes.as_mut_ptr().cast(),
            bytes.len(),
        )
    };
    assert!(length >= 0);
    unsafe { libc::close(dirfd) };
    Observation {
        reads,
        errors,
        link,
        kind: metadata.file_type().is_symlink(),
        size: metadata.len(),
        identity,
        truncated: (count, truncated),
        at: (
            result,
            stat.st_mode & libc::S_IFMT == libc::S_IFLNK,
            bytes[..length as usize].to_vec(),
        ),
    }
}

#[test]
fn symlink_traversal_and_directory_relative_calls_match_native() {
    let root = std::env::temp_dir().join(format!("snare-symlinks-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    std::fs::create_dir(root.join("sub")).unwrap();
    std::fs::write(root.join("file"), b"contents").unwrap();
    symlink("file", root.join("relative")).unwrap();
    symlink(root.join("file"), root.join("absolute")).unwrap();
    symlink("sub", root.join("directory")).unwrap();
    symlink("missing", root.join("broken")).unwrap();
    symlink("loop", root.join("loop")).unwrap();
    let native = observe(&root);
    std::fs::remove_dir_all(&root).unwrap();
    for deterministic in [false, true] {
        let fs = FsBuilder::new()
            .own_prefix(&root)
            .file(root.join("file"), "contents")
            .dir(root.join("sub"))
            .symlink(root.join("relative"), "file")
            .symlink(root.join("absolute"), root.join("file"))
            .symlink(root.join("directory"), "sub")
            .symlink(root.join("broken"), "missing")
            .symlink(root.join("loop"), "loop")
            .build();
        let builder = Sim::builder().fs(fs);
        let sim = if deterministic {
            builder.deterministic().build()
        } else {
            builder.build()
        };
        assert_eq!(
            sim.run(|| observe(&root)),
            native,
            "deterministic={deterministic}"
        );
        assert!(!root.exists());
    }
}

fn link_observation(root: &Path) -> (Vec<i32>, Vec<bool>, Vec<Vec<u8>>) {
    let mut errors = Vec::new();
    let mut kinds = Vec::new();
    let mut contents = Vec::new();
    let dir = CString::new(root.as_os_str().as_encoded_bytes()).unwrap();
    let fd = unsafe { libc::open(dir.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) };
    assert!(fd >= 0);
    for (name, flags) in [(c"hard", 0), (c"followed", libc::AT_SYMLINK_FOLLOW)] {
        let result = unsafe { libc::linkat(fd, c"relative".as_ptr(), fd, name.as_ptr(), flags) };
        errors.push(if result < 0 {
            std::io::Error::last_os_error().raw_os_error().unwrap()
        } else {
            0
        });
        let path = root.join(name.to_str().unwrap());
        kinds.push(
            std::fs::symlink_metadata(&path)
                .unwrap()
                .file_type()
                .is_symlink(),
        );
        contents.push(std::fs::read(&path).unwrap());
    }
    unsafe { libc::close(fd) };
    for name in ["loop", "broken", "relative", "directory"] {
        let path = root.join(name);
        errors.push(errno(std::fs::canonicalize(&path)));
    }
    errors.push(errno(symlink("file", root.join("relative"))));
    std::fs::rename(root.join("relative"), root.join("renamed")).unwrap();
    contents.push(std::fs::read(root.join("renamed")).unwrap());
    std::fs::remove_file(root.join("renamed")).unwrap();
    contents.push(std::fs::read(root.join("file")).unwrap());
    (errors, kinds, contents)
}

#[test]
fn links_follow_flags_and_path_mutations_match_native() {
    let root = std::env::temp_dir().join(format!("snare-symlink-mutations-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    std::fs::create_dir(root.join("sub")).unwrap();
    std::fs::write(root.join("file"), b"contents").unwrap();
    for (name, target) in [
        ("relative", "file"),
        ("loop", "loop"),
        ("broken", "missing"),
        ("directory", "sub"),
    ] {
        symlink(target, root.join(name)).unwrap();
    }
    let native = link_observation(&root);
    std::fs::remove_dir_all(&root).unwrap();
    for deterministic in [false, true] {
        let mut fs = FsBuilder::new()
            .own_prefix(&root)
            .file(root.join("file"), "contents")
            .dir(root.join("sub"));
        for (name, target) in [
            ("relative", "file"),
            ("loop", "loop"),
            ("broken", "missing"),
            ("directory", "sub"),
        ] {
            fs = fs.symlink(root.join(name), target);
        }
        let builder = Sim::builder().fs(fs.build());
        let sim = if deterministic {
            builder.deterministic().build()
        } else {
            builder.build()
        };
        assert_eq!(
            sim.run(|| link_observation(&root)),
            native,
            "deterministic={deterministic}"
        );
        assert!(!root.exists());
    }
}

fn symlink_errors(root: &Path) -> Vec<i32> {
    let mut errors = Vec::new();
    for path in ["relative/", "directory/", "broken/"] {
        errors.push(errno(std::fs::read_link(root.join(path))));
        errors.push(errno(std::fs::symlink_metadata(root.join(path))));
        errors.push(errno(std::fs::remove_file(root.join(path))));
        errors.push(errno(std::fs::remove_dir(root.join(path))));
        errors.push(errno(symlink("file", root.join(path))));
        errors.push(errno(std::fs::create_dir(root.join(path))));
    }
    errors.push(errno(std::fs::rename(
        root.join("directory/"),
        root.join("renamed"),
    )));
    errors
}

#[test]
fn terminal_symlink_slashes_match_native_errors() {
    let root = std::env::temp_dir().join(format!("snare-symlink-errors-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    std::fs::create_dir(root.join("sub")).unwrap();
    std::fs::write(root.join("sub/child"), b"contents").unwrap();
    std::fs::write(root.join("file"), b"contents").unwrap();
    for (name, target) in [
        ("relative", "file"),
        ("directory", "sub"),
        ("broken", "missing"),
    ] {
        symlink(target, root.join(name)).unwrap();
    }
    let native = symlink_errors(&root);
    std::fs::remove_dir_all(&root).unwrap();
    for deterministic in [false, true] {
        let mut fs = FsBuilder::new()
            .own_prefix(&root)
            .file(root.join("file"), "contents")
            .file(root.join("sub/child"), "contents");
        for (name, target) in [
            ("relative", "file"),
            ("directory", "sub"),
            ("broken", "missing"),
        ] {
            fs = fs.symlink(root.join(name), target);
        }
        let builder = Sim::builder().fs(fs.build());
        let sim = if deterministic {
            builder.deterministic().build()
        } else {
            builder.build()
        };
        assert_eq!(
            sim.run(|| symlink_errors(&root)),
            native,
            "deterministic={deterministic}"
        );
    }
}

#[test]
fn finite_symlink_chain_limit_matches_native() {
    let root = std::fs::canonicalize(std::env::temp_dir())
        .unwrap()
        .join(format!("snare-symlink-chains-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join("file"), b"contents").unwrap();
    for index in 0..45 {
        let target = if index == 44 {
            "file".to_owned()
        } else {
            format!("link{}", index + 1)
        };
        symlink(target, root.join(format!("link{index}"))).unwrap();
    }
    let observe = || {
        (0..45)
            .map(|index| errno(std::fs::read(root.join(format!("link{index}")))))
            .collect::<Vec<_>>()
    };
    let native = observe();
    std::fs::remove_dir_all(&root).unwrap();
    let mut fs = FsBuilder::new()
        .own_prefix(&root)
        .file(root.join("file"), "contents");
    for index in 0..45 {
        let target = if index == 44 {
            "file".to_owned()
        } else {
            format!("link{}", index + 1)
        };
        fs = fs.symlink(root.join(format!("link{index}")), target);
    }
    let sim = Sim::builder().fs(fs.build()).build();
    assert_eq!(sim.run(observe), native);
}
