#![cfg(unix)]
#![allow(clippy::unnecessary_cast)]
//! Permissions on a `VirtualFs` against the host. `script` runs one sequence of mode, ownership,
//! umask and permission-checked calls in a real directory outside every sim and in a `VirtualFs`
//! directory declared with the same owner and mode, and records each call's result and the
//! modes, owners and change times it leaves; the two logs must match. The sim takes the real
//! process's privileges, so the comparison holds as an unprivileged user (macOS, or Linux in a
//! container run with `--user 1000:1000`) and as root (Linux in a container). Rules that need
//! another user's files are pinned to measurements (Linux 7.0 as uid 1000, macOS 26 as uid
//! 501) where the host offers no such file to compare with.

use std::ffi::{CString, c_int};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use snare::{FsBuilder, HostProfile, Privileges, Sim};

/// Native runs set the process umask, which every thread shares.
static NATIVE: Mutex<()> = Mutex::new(());

fn c(path: &Path) -> CString {
    CString::new(path.as_os_str().as_encoded_bytes()).unwrap()
}

fn errno() -> c_int {
    std::io::Error::last_os_error().raw_os_error().unwrap()
}

fn outcome(result: i64) -> String {
    if result >= 0 {
        return "ok".into();
    }
    match errno() {
        libc::EPERM => "EPERM".into(),
        libc::ENOENT => "ENOENT".into(),
        libc::EACCES => "EACCES".into(),
        libc::EEXIST => "EEXIST".into(),
        libc::ENOTDIR => "ENOTDIR".into(),
        libc::EISDIR => "EISDIR".into(),
        libc::EINVAL => "EINVAL".into(),
        libc::EBADF => "EBADF".into(),
        libc::ENOTEMPTY => "ENOTEMPTY".into(),
        libc::EOPNOTSUPP => "EOPNOTSUPP".into(),
        other => format!("errno {other}"),
    }
}

/// An `open` that closes what it opened.
fn open(path: &Path, flags: c_int, mode: libc::c_uint) -> String {
    let fd = unsafe { libc::open(c(path).as_ptr(), flags | libc::O_CLOEXEC, mode) };
    let result = outcome(fd as i64);
    if fd >= 0 {
        unsafe { libc::close(fd) };
    }
    result
}

/// `lstat`'s mode, owner and group, and through `std` (`statx` on Linux) the same.
fn status(path: &Path) -> String {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::lstat(c(path).as_ptr(), &mut st) } != 0 {
        return outcome(-1);
    }
    let m = std::fs::symlink_metadata(path).unwrap();
    assert_eq!(
        (m.mode(), m.uid(), m.gid()),
        (st.st_mode as u32, st.st_uid, st.st_gid),
        "{}",
        path.display()
    );
    format!("{:o} {} {}", st.st_mode, st.st_uid, st.st_gid)
}

fn ctime(path: &Path) -> (i64, i64) {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    unsafe { libc::lstat(c(path).as_ptr(), &mut st) };
    (st.st_ctime as i64, st.st_ctime_nsec as i64)
}

struct Log<'a> {
    lines: Vec<String>,
    pause: &'a dyn Fn(),
}

impl Log<'_> {
    fn note(&mut self, name: &str, value: String) {
        self.lines.push(format!("{name}: {value}"));
    }

    /// Runs `call` on `path` and notes its result, `path`'s status after it, and whether its
    /// change time moved.
    fn change(&mut self, name: &str, path: &Path, call: impl FnOnce() -> i64) {
        let before = ctime(path);
        (self.pause)();
        let result = outcome(call());
        let moved = if ctime(path) != before { "c+" } else { "c-" };
        let status = status(path);
        self.note(name, format!("{result} {moved} {status}"));
    }
}

fn umask(mask: libc::mode_t) -> libc::mode_t {
    unsafe { libc::umask(mask) }
}

fn make(path: &Path, mode: libc::mode_t) {
    let fd = unsafe { libc::open(c(path).as_ptr(), libc::O_CREAT | libc::O_WRONLY, 0o600) };
    assert!(fd >= 0, "{}: {}", path.display(), errno());
    unsafe { libc::close(fd) };
    assert_eq!(unsafe { libc::chmod(c(path).as_ptr(), mode) }, 0);
}

fn make_dir(path: &Path, mode: libc::mode_t) {
    assert_eq!(
        unsafe { libc::mkdir(c(path).as_ptr(), 0o700) },
        0,
        "{}",
        path.display()
    );
    assert_eq!(unsafe { libc::chmod(c(path).as_ptr(), mode) }, 0);
}

fn chmod(path: &Path, mode: libc::mode_t) -> i64 {
    i64::from(unsafe { libc::chmod(c(path).as_ptr(), mode) })
}

fn chown(path: &Path, uid: u32, gid: u32) -> i64 {
    i64::from(unsafe { libc::chown(c(path).as_ptr(), uid, gid) })
}

/// A group the caller belongs to other than its own, if any.
fn other_group() -> Option<u32> {
    let mut groups = vec![0 as libc::gid_t; 64];
    let count = unsafe { libc::getgroups(groups.len() as c_int, groups.as_mut_ptr()) };
    let own = unsafe { libc::getegid() };
    groups[..count.max(0) as usize]
        .iter()
        .copied()
        .find(|group| *group != own && *group != 0)
}

const NONE: u32 = u32::MAX;

/// A call through a writable descriptor of a file given the mode first.
type Write<'a> = (&'a str, libc::mode_t, &'a dyn Fn(c_int));

/// The script, in `root`, an empty directory the caller owns.
fn script(root: &Path, pause: &dyn Fn()) -> Vec<String> {
    let mut log = Log {
        lines: Vec::new(),
        pause,
    };
    let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
    let at = |name: &str| root.join(name);
    log.note("root", status(root));

    let old = umask(0o022);
    for (index, mask) in [0o022, 0o000, 0o077].into_iter().enumerate() {
        umask(mask);
        let file = at(&format!("created{index}"));
        log.note(
            &format!("umask {mask:o} open 07777"),
            open(&file, libc::O_CREAT | libc::O_WRONLY, 0o7777),
        );
        log.note(&format!("umask {mask:o} file"), status(&file));
        let dir = at(&format!("dir{index}"));
        let made = unsafe { libc::mkdir(c(&dir).as_ptr(), 0o7777) };
        log.note(&format!("umask {mask:o} mkdir 07777"), outcome(made as i64));
        log.note(&format!("umask {mask:o} dir"), status(&dir));
        let link = at(&format!("link{index}"));
        std::os::unix::fs::symlink("x", &link).unwrap();
        log.note(&format!("umask {mask:o} symlink"), status(&link));
    }
    umask(0);
    log.note(
        "O_CREAT of an existing file",
        open(&at("created2"), libc::O_CREAT | libc::O_WRONLY, 0o777),
    );
    log.note("existing file keeps its mode", status(&at("created2")));
    umask(0o022);

    let f = at("f");
    make(&f, 0o644);
    for mode in [
        0o600, 0o600, 0o170777, 0o1644, 0o2644, 0o4755, 0o7777, 0o644,
    ] {
        log.change(&format!("chmod {mode:o}"), &f, || chmod(&f, mode));
    }
    let fd = unsafe { libc::open(c(&f).as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    log.change("fchmod a read-only descriptor", &f, || {
        i64::from(unsafe { libc::fchmod(fd, 0o640) })
    });
    log.change("fchown a read-only descriptor", &f, || {
        i64::from(unsafe { libc::fchown(fd, NONE, gid) })
    });
    unsafe { libc::close(fd) };
    let l = at("l");
    std::os::unix::fs::symlink("f", &l).unwrap();
    log.change("fchmodat NOFOLLOW a file", &f, || {
        let flags = libc::AT_SYMLINK_NOFOLLOW;
        i64::from(unsafe { libc::fchmodat(libc::AT_FDCWD, c(&f).as_ptr(), 0o600, flags) })
    });
    log.change("fchmodat NOFOLLOW a symlink", &l, || {
        let flags = libc::AT_SYMLINK_NOFOLLOW;
        i64::from(unsafe { libc::fchmodat(libc::AT_FDCWD, c(&l).as_ptr(), 0o700, flags) })
    });
    log.note(
        "fchmodat an unknown flag",
        outcome(i64::from(unsafe {
            libc::fchmodat(libc::AT_FDCWD, c(&f).as_ptr(), 0o600, 0x4000_0000)
        })),
    );
    log.change("chmod through a symlink", &f, || chmod(&l, 0o640));
    log.note(
        "chmod a missing file",
        outcome(chmod(&at("missing"), 0o644)),
    );
    log.note("chmod under a file", outcome(chmod(&f.join("x"), 0o644)));
    let d = at("d");
    make_dir(&d, 0o755);
    for mode in [0o700, 0o1777, 0o2755, 0o755] {
        log.change(&format!("chmod a directory {mode:o}"), &d, || {
            chmod(&d, mode)
        });
    }

    let o = at("o");
    make(&o, 0o644);
    log.change("chown naming no id", &o, || chown(&o, NONE, NONE));
    log.change("chown to its ids", &o, || chown(&o, uid, gid));
    log.change("chown to another user", &o, || chown(&o, uid + 1, NONE));
    chown(&o, uid, gid);
    if gid != 0 {
        log.change("chown to group 0", &o, || chown(&o, NONE, 0));
        chown(&o, uid, gid);
    }
    log.change("chown to a group it is not in", &o, || {
        chown(&o, NONE, 4242)
    });
    chown(&o, uid, gid);
    if let Some(group) = other_group() {
        log.change("chown to another of its groups", &o, || {
            chown(&o, NONE, group)
        });
        chown(&o, uid, gid);
    }
    for (mode, to_uid, to_gid) in [
        (0o6755, NONE, gid),
        (0o6755, uid, NONE),
        (0o6755, NONE, NONE),
        (0o6745, NONE, gid),
        (0o6644, NONE, gid),
    ] {
        chmod(&o, mode);
        log.change(
            &format!("chown {to_uid} {to_gid} a {mode:o} file"),
            &o,
            || chown(&o, to_uid, to_gid),
        );
    }
    let od = at("od");
    make_dir(&od, 0o755);
    chmod(&od, 0o6755);
    log.change("chown a 6755 directory", &od, || chown(&od, NONE, gid));
    let ol = at("ol");
    std::os::unix::fs::symlink("o", &ol).unwrap();
    log.change("lchown a symlink", &ol, || {
        i64::from(unsafe { libc::lchown(c(&ol).as_ptr(), NONE, gid) })
    });
    log.change("fchownat NOFOLLOW a symlink", &ol, || {
        let flags = libc::AT_SYMLINK_NOFOLLOW;
        i64::from(unsafe { libc::fchownat(libc::AT_FDCWD, c(&ol).as_ptr(), NONE, gid, flags) })
    });
    log.note(
        "fchownat an unknown flag",
        outcome(i64::from(unsafe {
            libc::fchownat(libc::AT_FDCWD, c(&o).as_ptr(), NONE, NONE, 0x4000_0000)
        })),
    );

    let s = at("s");
    make(&s, 0o644);
    let writes: [Write; 4] = [
        ("write to a 6755 file", 0o6755, &|fd| {
            assert_eq!(unsafe { libc::write(fd, b"x".as_ptr().cast(), 1) }, 1);
        }),
        ("write nothing to a 6755 file", 0o6755, &|fd| {
            assert_eq!(unsafe { libc::write(fd, b"x".as_ptr().cast(), 0) }, 0);
        }),
        ("write to a 6745 file", 0o6745, &|fd| {
            assert_eq!(unsafe { libc::write(fd, b"x".as_ptr().cast(), 1) }, 1);
        }),
        ("ftruncate a 6755 file", 0o6755, &|fd| {
            assert_eq!(unsafe { libc::ftruncate(fd, 0) }, 0);
        }),
    ];
    for (name, mode, call) in writes {
        chmod(&s, mode);
        let fd = unsafe { libc::open(c(&s).as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) };
        call(fd);
        unsafe { libc::close(fd) };
        log.note(name, status(&s));
    }
    chmod(&s, 0o6755);
    open(&s, libc::O_WRONLY | libc::O_TRUNC, 0);
    log.note("O_TRUNC a 6755 file", status(&s));

    let files = [
        ("a0", 0o000),
        ("a2", 0o200),
        ("a4", 0o444),
        ("a1", 0o100),
        ("a6", 0o644),
    ];
    for (name, mode) in files {
        make(&at(name), mode);
    }
    for (name, _) in files {
        for (flags, label) in [
            (libc::O_RDONLY, "RDONLY"),
            (libc::O_WRONLY, "WRONLY"),
            (libc::O_RDWR, "RDWR"),
            (libc::O_RDONLY | libc::O_TRUNC, "RDONLY|O_TRUNC"),
            (libc::O_WRONLY | libc::O_CREAT, "WRONLY|O_CREAT"),
            (
                libc::O_RDONLY | libc::O_CREAT | libc::O_EXCL,
                "O_CREAT|O_EXCL",
            ),
        ] {
            log.note(
                &format!("open {name} {label}"),
                open(&at(name), flags, 0o644),
            );
        }
        for (mode, label) in [
            (libc::F_OK, "F"),
            (libc::R_OK, "R"),
            (libc::W_OK, "W"),
            (libc::X_OK, "X"),
            (libc::R_OK | libc::W_OK, "RW"),
        ] {
            let result = unsafe { libc::access(c(&at(name)).as_ptr(), mode) };
            log.note(&format!("access {name} {label}"), outcome(result as i64));
        }
        let result = unsafe {
            libc::faccessat(
                libc::AT_FDCWD,
                c(&at(name)).as_ptr(),
                libc::W_OK,
                libc::AT_EACCESS,
            )
        };
        log.note(
            &format!("faccessat {name} W AT_EACCESS"),
            outcome(result as i64),
        );
    }

    let dx = at("dx");
    make_dir(&dx, 0o700);
    make(&dx.join("f"), 0o644);
    chmod(&dx, 0o600);
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let lstat = |path: &Path, st: &mut libc::stat| {
        outcome(i64::from(unsafe { libc::lstat(c(path).as_ptr(), st) }))
    };
    log.note(
        "search-less dir: open f",
        open(&dx.join("f"), libc::O_RDONLY, 0),
    );
    log.note("search-less dir: lstat f", lstat(&dx.join("f"), &mut st));
    log.note(
        "search-less dir: lstat missing",
        lstat(&dx.join("missing"), &mut st),
    );
    log.note("search-less dir: lstat itself", lstat(&dx, &mut st));
    log.note("search-less dir: lstat it/", lstat(&dx.join(""), &mut st));
    log.note("search-less dir: lstat it/.", lstat(&dx.join("."), &mut st));
    for (mode, label) in [(libc::X_OK, "X"), (libc::F_OK, "F")] {
        let result = unsafe { libc::access(c(&dx).as_ptr(), mode) };
        log.note(
            &format!("search-less dir: access {label}"),
            outcome(result as i64),
        );
    }
    log.note(
        "search-less dir: open it",
        open(&dx, libc::O_RDONLY | libc::O_DIRECTORY, 0),
    );
    log.note(
        "search-less dir: list it",
        std::fs::read_dir(&dx).map_or_else(
            |error| format!("{:?}", error.raw_os_error()),
            |entries| format!("{}", entries.count()),
        ),
    );
    log.note(
        "search-less dir: chdir",
        outcome(i64::from(unsafe { libc::chdir(c(&dx).as_ptr()) })),
    );
    log.note(
        "search-less dir: create",
        open(&dx.join("new"), libc::O_CREAT | libc::O_WRONLY, 0o644),
    );
    log.note(
        "search-less dir: mkdir",
        outcome(i64::from(unsafe {
            libc::mkdir(c(&dx.join("new")).as_ptr(), 0o755)
        })),
    );
    log.note(
        "search-less dir: unlink",
        outcome(i64::from(unsafe {
            libc::unlink(c(&dx.join("f")).as_ptr())
        })),
    );
    log.note(
        "search-less dir: readlink",
        outcome(unsafe {
            libc::readlink(c(&dx.join("f")).as_ptr(), [0i8; 8].as_mut_ptr().cast(), 8)
        } as i64),
    );
    log.note(
        "search-less dir: chmod",
        outcome(chmod(&dx.join("f"), 0o600)),
    );
    chmod(&dx, 0o700);

    let dr = at("dr");
    make_dir(&dr, 0o700);
    make(&dr.join("f"), 0o644);
    chmod(&dr, 0o300);
    log.note(
        "unreadable dir: open it",
        open(&dr, libc::O_RDONLY | libc::O_DIRECTORY, 0),
    );
    log.note(
        "unreadable dir: list it",
        std::fs::read_dir(&dr).map_or_else(
            |error| format!("{:?}", error.raw_os_error()),
            |entries| format!("{}", entries.count()),
        ),
    );
    log.note("unreadable dir: lstat f", lstat(&dr.join("f"), &mut st));
    log.note(
        "unreadable dir: create",
        open(&dr.join("new"), libc::O_CREAT | libc::O_WRONLY, 0o644),
    );
    chmod(&dr, 0o700);

    let dw = at("dw");
    make_dir(&dw, 0o700);
    make(&dw.join("f"), 0o644);
    make_dir(&dw.join("sub"), 0o700);
    make(&dw.join("sub").join("x"), 0o644);
    make_dir(&dw.join("empty"), 0o700);
    make(&at("y"), 0o644);
    chmod(&dw, 0o500);
    let path_call = |call: unsafe extern "C" fn(*const libc::c_char) -> c_int, path: &Path| {
        outcome(i64::from(unsafe { call(c(path).as_ptr()) }))
    };
    let pair_call =
        |call: unsafe extern "C" fn(*const libc::c_char, *const libc::c_char) -> c_int,
         from: &Path,
         to: &Path| {
            outcome(i64::from(unsafe { call(c(from).as_ptr(), c(to).as_ptr()) }))
        };
    log.note(
        "unwritable dir: create",
        open(&dw.join("new"), libc::O_CREAT | libc::O_WRONLY, 0o644),
    );
    log.note(
        "unwritable dir: O_CREAT an existing file",
        open(&dw.join("f"), libc::O_CREAT | libc::O_WRONLY, 0o644),
    );
    log.note(
        "unwritable dir: O_CREAT|O_EXCL an existing file",
        open(
            &dw.join("f"),
            libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY,
            0o644,
        ),
    );
    for (name, path) in [("an existing", dw.join("sub")), ("a new", dw.join("new"))] {
        log.note(
            &format!("unwritable dir: mkdir {name} directory"),
            outcome(i64::from(unsafe { libc::mkdir(c(&path).as_ptr(), 0o755) })),
        );
    }
    for name in ["f", "missing", "sub"] {
        log.note(
            &format!("unwritable dir: unlink {name}"),
            path_call(libc::unlink, &dw.join(name)),
        );
    }
    for name in ["sub", "empty", "missing"] {
        log.note(
            &format!("unwritable dir: rmdir {name}"),
            path_call(libc::rmdir, &dw.join(name)),
        );
    }
    log.note(
        "unwritable dir: rename out",
        pair_call(libc::rename, &dw.join("f"), &at("y2")),
    );
    log.note(
        "unwritable dir: rename in",
        pair_call(libc::rename, &at("y"), &dw.join("z")),
    );
    log.note(
        "unwritable dir: rename over",
        pair_call(libc::rename, &at("y"), &dw.join("f")),
    );
    log.note(
        "unwritable dir: rename a missing file out",
        pair_call(libc::rename, &dw.join("missing"), &at("y3")),
    );
    log.note(
        "unwritable dir: link in",
        pair_call(libc::link, &at("y"), &dw.join("z")),
    );
    log.note(
        "unwritable dir: link out",
        pair_call(libc::link, &dw.join("f"), &at("y4")),
    );
    log.note(
        "unwritable dir: symlink in",
        outcome(i64::from(unsafe {
            libc::symlink(c"y".as_ptr(), c(&dw.join("z")).as_ptr())
        })),
    );
    log.note(
        "unwritable dir: utimes its file",
        outcome(i64::from(unsafe {
            libc::utimes(c(&dw.join("f")).as_ptr(), std::ptr::null())
        })),
    );
    log.note(
        "unwritable dir: chmod its file",
        outcome(chmod(&dw.join("f"), 0o600)),
    );
    chmod(&dw, 0o700);

    let (one, two) = (at("mv1"), at("mv2"));
    make_dir(&one, 0o755);
    make_dir(&two, 0o755);
    make_dir(&one.join("sub"), 0o555);
    log.note(
        "rename an unwritable directory to another parent",
        pair_call(libc::rename, &one.join("sub"), &two.join("sub")),
    );
    log.note(
        "rename an unwritable directory within its parent",
        pair_call(libc::rename, &one.join("sub"), &one.join("sub2")),
    );
    make_dir(&one.join("a"), 0o755);
    make_dir(&one.join("b"), 0o555);
    log.note(
        "rename a directory over an unwritable empty one",
        pair_call(libc::rename, &one.join("a"), &one.join("b")),
    );
    for path in [
        one.join("sub"),
        one.join("sub2"),
        one.join("a"),
        one.join("b"),
    ] {
        chmod(&path, 0o755);
    }

    let ro = at("ro");
    make(&ro, 0o444);
    log.note(
        "utimes an unwritable file it owns",
        outcome(i64::from(unsafe {
            libc::utimes(c(&ro).as_ptr(), std::ptr::null())
        })),
    );
    log.note(
        "unlink an unwritable file it owns",
        path_call(libc::unlink, &ro),
    );
    let sticky = at("sticky");
    make_dir(&sticky, 0o1777);
    make(&sticky.join("mine"), 0o644);
    log.note(
        "unlink its file in its sticky directory",
        path_call(libc::unlink, &sticky.join("mine")),
    );

    umask(old);
    log.lines
}

/// The permission bits and owner of `path` as a builder declares them.
fn mirror(builder: FsBuilder, path: &Path, real: &Path) -> FsBuilder {
    let m = snare::real(|| std::fs::symlink_metadata(real)).unwrap();
    builder
        .mode(path, m.mode() & 0o7777)
        .owner(path, m.uid(), m.gid())
}

fn real_dir(base: &Path, tag: &str) -> PathBuf {
    let root = base.join(format!("snare-perm-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir(&root).unwrap();
    root
}

/// Grants every permission back so the tree can be removed.
fn remove(root: &Path) {
    for entry in walkdir(root) {
        let _ = std::fs::set_permissions(&entry, std::fs::Permissions::from_mode(0o700));
    }
    std::fs::remove_dir_all(root).unwrap();
}

fn walkdir(root: &Path) -> Vec<PathBuf> {
    let mut out = vec![root.to_path_buf()];
    let mut index = 0;
    while index < out.len() {
        let path = out[index].clone();
        index += 1;
        if std::fs::symlink_metadata(&path).is_ok_and(|m| m.is_dir()) {
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700));
            if let Ok(entries) = std::fs::read_dir(&path) {
                out.extend(entries.flatten().map(|entry| entry.path()));
            }
        }
    }
    out
}

fn native(base: &Path, tag: &str) -> (Vec<String>, PathBuf) {
    let _guard = NATIVE.lock().unwrap_or_else(|error| error.into_inner());
    let root = real_dir(base, tag);
    let log = script(&root, &|| std::thread::sleep(Duration::from_millis(20)));
    (log, root)
}

/// The script on the host under `base`, then in a sim on a `VirtualFs` whose root mirrors the
/// host's, with the real process's privileges.
fn compare(base: &Path, tag: &str) {
    let (truth, root) = native(base, tag);
    let fs = mirror(
        FsBuilder::new().own_prefix("/v").dir("/v"),
        Path::new("/v"),
        &root,
    );
    remove(&root);
    let sim = Sim::builder()
        .fs(fs.build())
        .privileges(Privileges::from_real_process().unwrap())
        .build();
    let log = sim.run(|| {
        script(Path::new("/v"), &|| {
            std::thread::sleep(Duration::from_secs(1))
        })
    });
    for (truth, log) in truth.iter().zip(&log) {
        assert_eq!(log, truth);
    }
    assert_eq!(log.len(), truth.len());
}

#[test]
fn permissions_match_the_host() {
    compare(&std::env::temp_dir(), "tmp");
}

/// macOS gives a new file its directory's group, so one made under `/private/tmp` (root's,
/// group `wheel`) belongs to a group the user is not in.
#[cfg(target_os = "macos")]
#[test]
fn permissions_in_a_foreign_group_match_the_host() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    compare(Path::new("/private/tmp"), "wheel");
}

fn others(path: &Path) -> Vec<String> {
    let mut log = Vec::new();
    log.push(format!("status: {}", status(path)));
    for (flags, label) in [(libc::O_RDONLY, "RDONLY"), (libc::O_RDWR, "RDWR")] {
        log.push(format!("open {label}: {}", open(path, flags, 0)));
    }
    let result = unsafe { libc::access(c(path).as_ptr(), libc::W_OK) };
    log.push(format!("access W: {}", outcome(result as i64)));
    log.push(format!("chmod: {}", outcome(chmod(path, 0o666))));
    let uid = unsafe { libc::geteuid() };
    log.push(format!(
        "chown to itself: {}",
        outcome(chown(path, uid, NONE))
    ));
    let times = [libc::timeval {
        tv_sec: 1,
        tv_usec: 0,
    }; 2];
    let explicit = unsafe { libc::utimes(c(path).as_ptr(), times.as_ptr()) };
    log.push(format!("utimes explicit: {}", outcome(explicit as i64)));
    let now = unsafe { libc::utimes(c(path).as_ptr(), std::ptr::null()) };
    log.push(format!("utimes now: {}", outcome(now as i64)));
    log
}

/// Another user's file, read-only to the caller: the calls that would change it fail on the host
/// and in the sim alike. Skipped as root, where they would succeed and change the host's file.
#[test]
fn another_users_file_matches_the_host() {
    let hosts = Path::new("/etc/hosts");
    let m = std::fs::metadata(hosts).unwrap();
    if unsafe { libc::geteuid() } == 0 || m.uid() == unsafe { libc::geteuid() } {
        return;
    }
    let truth = others(hosts);
    let fs = mirror(
        FsBuilder::new().own_prefix("/v").file("/v/hosts", "x"),
        Path::new("/v/hosts"),
        hosts,
    )
    .build();
    let sim = Sim::builder()
        .fs(fs)
        .privileges(Privileges::from_real_process().unwrap())
        .build();
    assert_eq!(sim.run(|| others(Path::new("/v/hosts"))), truth);
}

/// The rules for other users' files and foreign groups, as measured where the host has no such
/// file for a test to use: Linux 7.0 as uid 1000 among root's files, macOS 26 as uid 501 (its
/// sticky-directory rule from unlink(2) and rename(2)).
#[test]
fn other_users_entries_follow_the_measured_rules() {
    let fs = FsBuilder::new()
        .own_prefix("/m")
        .dir("/m")
        .mode("/m", 0o777)
        .dir("/m/sticky")
        .mode("/m/sticky", 0o1777)
        .owner("/m/sticky", 0, 0)
        .file("/m/sticky/theirs", "x")
        .mode("/m/sticky/theirs", 0o666)
        .owner("/m/sticky/theirs", 0, 0)
        .dir("/m/sticky/their-dir")
        .mode("/m/sticky/their-dir", 0o777)
        .owner("/m/sticky/their-dir", 0, 0)
        .dir("/m/theirs")
        .owner("/m/theirs", 0, 0)
        .file("/m/writable", "x")
        .mode("/m/writable", 0o666)
        .owner("/m/writable", 0, 0)
        .file("/m/readable", "x")
        .owner("/m/readable", 0, 0)
        .dir("/m/group")
        .mode("/m/group", 0o3777)
        .owner("/m/group", 0, 4242)
        .build();
    let sim = Sim::builder()
        .host(HostProfile::new().root(false).build())
        .fs(fs)
        .build();
    sim.run(|| {
        let p = Path::new;
        let unlink = |path: &str| outcome(i64::from(unsafe { libc::unlink(c(p(path)).as_ptr()) }));
        let rename = |from: &str, to: &str| {
            outcome(i64::from(unsafe {
                libc::rename(c(p(from)).as_ptr(), c(p(to)).as_ptr())
            }))
        };
        assert_eq!(unlink("/m/sticky/theirs"), "EPERM");
        assert_eq!(rename("/m/sticky/theirs", "/m/sticky/moved"), "EPERM");
        assert_eq!(
            outcome(i64::from(unsafe {
                libc::rmdir(c"/m/sticky/their-dir".as_ptr())
            })),
            "EPERM"
        );
        make(p("/m/sticky/mine"), 0o644);
        assert_eq!(rename("/m/sticky/mine", "/m/sticky/theirs"), "EPERM");
        assert_eq!(unlink("/m/sticky/mine"), "ok");
        assert_eq!(
            open(p("/m/theirs/f"), libc::O_CREAT | libc::O_WRONLY, 0o644),
            "EACCES"
        );

        let writable = p("/m/writable");
        assert_eq!(open(writable, libc::O_RDWR, 0), "ok");
        assert_eq!(outcome(chmod(writable, 0o600)), "EPERM");
        let before = ctime(writable);
        std::thread::sleep(Duration::from_secs(1));
        assert_eq!(outcome(chown(writable, NONE, NONE)), "ok");
        assert_eq!(ctime(writable) != before, cfg!(target_os = "linux"));
        let named = if cfg!(target_os = "linux") {
            "EPERM"
        } else {
            "ok"
        };
        assert_eq!(outcome(chown(writable, 0, 0)), named);
        assert_eq!(
            outcome(i64::from(unsafe {
                libc::utimes(c(writable).as_ptr(), std::ptr::null())
            })),
            "ok"
        );
        let times = [libc::timeval {
            tv_sec: 1,
            tv_usec: 0,
        }; 2];
        assert_eq!(
            outcome(i64::from(unsafe {
                libc::utimes(c(writable).as_ptr(), times.as_ptr())
            })),
            "EPERM"
        );
        assert_eq!(
            outcome(i64::from(unsafe {
                libc::utimes(c(p("/m/readable")).as_ptr(), std::ptr::null())
            })),
            "EACCES"
        );

        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        umask(0o022);
        let file = p("/m/group/f");
        make(file, 0o644);
        assert_eq!(status(file), format!("100644 {uid} 4242"));
        assert_eq!(outcome(chmod(file, 0o2644)), "ok");
        assert_eq!(status(file), format!("100644 {uid} 4242"));
        let dir = p("/m/group/d");
        assert_eq!(unsafe { libc::mkdir(c(dir).as_ptr(), 0o777) }, 0);
        let dir_mode = if cfg!(target_os = "linux") {
            42755
        } else {
            40755
        };
        assert_eq!(status(dir), format!("{dir_mode} {uid} 4242"));
        let special = p("/m/group/special");
        open(special, libc::O_CREAT | libc::O_WRONLY, 0o2777);
        assert_eq!(status(special), format!("100755 {uid} 4242"));
        let own = p("/m/own");
        make(own, 0o644);
        assert_eq!(status(own), format!("100644 {uid} {gid}"));
    });
}

/// Under a `SimHost` the code under test is root or the stock unprivileged user, with that
/// user's group, and files it creates carry both.
#[test]
fn a_sim_host_user_owns_what_it_creates() {
    let fs = FsBuilder::new().own_prefix("/h").dir("/h").build();
    for root in [false, true] {
        let sim = Sim::builder()
            .host(HostProfile::new().root(root).build())
            .fs(fs.clone())
            .build();
        sim.run(|| {
            let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
            assert_eq!(unsafe { (libc::getuid(), libc::getgid()) }, (uid, gid));
            let expected = match (root, cfg!(target_os = "macos")) {
                (true, _) => (0, 0),
                (false, true) => (501, 20),
                (false, false) => (1000, 1000),
            };
            assert_eq!((uid, gid), expected);
            let mut groups = [0 as libc::gid_t; 4];
            assert_eq!(unsafe { libc::getgroups(0, groups.as_mut_ptr()) }, 1);
            assert_eq!(unsafe { libc::getgroups(4, groups.as_mut_ptr()) }, 1);
            assert_eq!(groups[0], gid);
            let file = Path::new("/h").join(format!("made-{root}"));
            make(&file, 0o640);
            let group = if cfg!(target_os = "macos") {
                std::fs::metadata("/h").unwrap().gid()
            } else {
                gid
            };
            assert_eq!(status(&file), format!("100640 {uid} {group}"));
        });
    }
}

/// A sim keeps a umask of its own: setting it inside changes neither the process's nor another
/// sim's, and it masks what the sim creates.
#[test]
fn each_sim_keeps_its_own_umask() {
    let _guard = NATIVE.lock().unwrap_or_else(|error| error.into_inner());
    let process = snare::real(|| {
        let mask = umask(0o022);
        umask(mask);
        mask
    });
    let fs = FsBuilder::new().own_prefix("/u").dir("/u").build();
    let first = Sim::builder().fs(fs.clone()).build();
    let second = Sim::builder().fs(fs).build();
    first.run(|| {
        assert_eq!(umask(0o077), 0o022);
        assert_eq!(umask(0o077), 0o077);
        make(Path::new("/u/first"), 0o600);
        let fd = unsafe {
            libc::open(
                c"/u/created".as_ptr(),
                libc::O_CREAT | libc::O_WRONLY,
                0o666,
            )
        };
        unsafe { libc::close(fd) };
        assert_eq!(
            status(Path::new("/u/created")).split(' ').next(),
            Some("100600")
        );
    });
    second.run(|| assert_eq!(umask(0o022), 0o022));
    let after = snare::real(|| {
        let mask = umask(0o022);
        umask(mask);
        mask
    });
    assert_eq!(after, process);
}

/// The locks `flock` and `fcntl` take on a file: an exclusive `flock`, a second open's
/// conflicting non-blocking one, a read record lock and a write one on a read-only descriptor,
/// and open-file-description locks between two opens.
#[cfg(target_os = "linux")]
fn locks(path: &Path) -> Vec<String> {
    let first = unsafe { libc::open(c(path).as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    let second = unsafe { libc::open(c(path).as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    assert!(first >= 0 && second >= 0, "{}", path.display());
    let mut log = Vec::new();
    let mut note =
        |name: &str, result: c_int| log.push(format!("{name}: {}", outcome(result as i64)));
    note("flock LOCK_EX", unsafe {
        libc::flock(first, libc::LOCK_EX | libc::LOCK_NB)
    });
    note("second flock LOCK_SH", unsafe {
        libc::flock(second, libc::LOCK_SH | libc::LOCK_NB)
    });
    note("flock LOCK_UN", unsafe {
        libc::flock(first, libc::LOCK_UN)
    });
    note("second flock LOCK_SH again", unsafe {
        libc::flock(second, libc::LOCK_SH | libc::LOCK_NB)
    });
    let lock = |kind: c_int| {
        let mut lock: libc::flock = unsafe { std::mem::zeroed() };
        lock.l_type = kind as _;
        lock.l_whence = libc::SEEK_SET as _;
        lock
    };
    let mut read = lock(libc::F_RDLCK);
    note("F_SETLK read", unsafe {
        libc::fcntl(first, libc::F_SETLK, &mut read)
    });
    let mut write = lock(libc::F_WRLCK);
    note("F_SETLK write", unsafe {
        libc::fcntl(first, libc::F_SETLK, &mut write)
    });
    let mut ofd = lock(libc::F_RDLCK);
    note("F_OFD_SETLK read", unsafe {
        libc::fcntl(first, libc::F_OFD_SETLK, &mut ofd)
    });
    let mut probe = lock(libc::F_WRLCK);
    note("F_OFD_GETLK", unsafe {
        libc::fcntl(second, libc::F_OFD_GETLK, &mut probe)
    });
    log.push(format!("conflict: {}", probe.l_type));
    unsafe { libc::close(first) };
    let mut probe = lock(libc::F_WRLCK);
    unsafe { libc::fcntl(second, libc::F_OFD_GETLK, &mut probe) };
    log.push(format!("after close: {}", probe.l_type));
    unsafe { libc::close(second) };
    log
}

#[cfg(target_os = "linux")]
#[test]
fn sim_host_files_lock_like_the_host() {
    let paths = |nic: &str| {
        [
            PathBuf::from("/proc/self/status"),
            PathBuf::from("/proc/sys/net/ipv4/tcp_syn_retries"),
            PathBuf::from(format!("/sys/class/net/{nic}/mtu")),
        ]
    };
    let truth: Vec<_> = paths("lo").iter().map(|path| locks(path)).collect();
    let sim = Sim::builder()
        .host(
            HostProfile::new()
                .root(unsafe { libc::geteuid() } == 0)
                .nic(snare::Nic::new("eth0", 7))
                .build(),
        )
        .build();
    let log: Vec<_> = sim.run(move || paths("eth0").iter().map(|path| locks(path)).collect());
    assert_eq!(log, truth);
}
