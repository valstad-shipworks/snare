#![cfg(unix)]
#![allow(clippy::unnecessary_cast)]
//! File timestamps on the sim's clock. `VirtualFs` nodes, and real files a sim creates or
//! changes, report the sim's `CLOCK_REALTIME`; real files it never touched keep their age
//! relative to the sim's start. `script_os_truth` runs one script of file operations in a real
//! directory outside every sim and records which of the access, modification, change and birth
//! times each step moves; the `script_on_*` tests run it inside a sim, on a `VirtualFs` and on
//! the real file system, and must move the same ones. Linux and macOS differ (a read at end of
//! file, `utimensat` of the access time alone, a modification time set before the birth time),
//! and each side mimics its host.

use std::ffi::CString;
use std::fs::{File, FileTimes, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use snare::{FsBuilder, NodeTimes, Sim};

/// Unix time of a fresh sim's clock.
const START: u64 = 1_700_000_000;

fn at(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs)
}

/// Whole seconds since the epoch: a sleep in a sim wakes a nanosecond past its deadline.
trait Secs {
    fn secs(self) -> u64;
}

impl Secs for SystemTime {
    fn secs(self) -> u64 {
        self.duration_since(UNIX_EPOCH).unwrap().as_secs()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Stamps {
    accessed: (i64, i64),
    modified: (i64, i64),
    changed: (i64, i64),
    created: Option<SystemTime>,
}

fn stamps(path: &Path) -> Stamps {
    let m = std::fs::symlink_metadata(path).unwrap();
    Stamps {
        accessed: (m.atime(), m.atime_nsec()),
        modified: (m.mtime(), m.mtime_nsec()),
        changed: (m.ctime(), m.ctime_nsec()),
        created: m.created().ok(),
    }
}

/// Which times moved: `a`ccess, `m`odification, `c`hange, `b`irth, or `-`.
fn moved(before: Stamps, after: Stamps) -> String {
    let mut out = String::new();
    for (moved, letter) in [
        (before.accessed != after.accessed, 'a'),
        (before.modified != after.modified, 'm'),
        (before.changed != after.changed, 'c'),
        (before.created != after.created, 'b'),
    ] {
        if moved {
            out.push(letter);
        }
    }
    if out.is_empty() {
        out.push('-');
    }
    out
}

fn utimensat(path: &Path, accessed: libc::timespec, modified: libc::timespec) {
    let path = CString::new(path.to_str().unwrap()).unwrap();
    let times = [accessed, modified];
    assert_eq!(
        unsafe { libc::utimensat(libc::AT_FDCWD, path.as_ptr(), times.as_ptr(), 0) },
        0,
        "{}",
        std::io::Error::last_os_error()
    );
}

fn special(nanos: libc::c_long) -> libc::timespec {
    libc::timespec {
        tv_sec: 0,
        tv_nsec: nanos,
    }
}

/// Runs the file operations under `root` (an existing, empty directory), calling `pause` before
/// and after each so every step lands at a new instant, and returns each step's moved times for
/// the paths it watches.
fn script(root: &Path, pause: &dyn Fn()) -> Vec<(&'static str, Vec<String>)> {
    let mut log = Vec::new();
    let mut step = |name: &'static str, before: &[&Path], after: &[&Path], f: &mut dyn FnMut()| {
        let was: Vec<_> = before.iter().map(|path| stamps(path)).collect();
        pause();
        f();
        pause();
        let now: Vec<_> = after.iter().map(|path| stamps(path)).collect();
        log.push((
            name,
            was.into_iter()
                .zip(now)
                .map(|(was, now)| moved(was, now))
                .collect(),
        ));
    };
    let dir = root.join("d");
    std::fs::create_dir(&dir).unwrap();
    let f = dir.join("f");
    std::fs::write(&f, b"").unwrap();
    let (f, d) = (f.as_path(), dir.as_path());
    step("read an empty file", &[f, d], &[f, d], &mut || {
        std::fs::read(f).unwrap();
    });
    step("read it again", &[f], &[f], &mut || {
        std::fs::read(f).unwrap();
    });
    step("write nothing", &[f, d], &[f, d], &mut || {
        let written = OpenOptions::new()
            .write(true)
            .open(f)
            .unwrap()
            .write(b"")
            .unwrap();
        assert_eq!(written, 0);
    });
    step("write", &[f, d], &[f, d], &mut || {
        OpenOptions::new()
            .write(true)
            .open(f)
            .unwrap()
            .write_all(b"abc")
            .unwrap();
    });
    step("read", &[f], &[f], &mut || {
        std::fs::read(f).unwrap();
    });
    step("read again", &[f], &[f], &mut || {
        std::fs::read(f).unwrap();
    });
    step("read at end of file", &[f], &[f], &mut || {
        let mut file = File::open(f).unwrap();
        file.seek(SeekFrom::End(0)).unwrap();
        assert_eq!(file.read(&mut [0; 4]).unwrap(), 0);
    });
    step("pwrite", &[f], &[f], &mut || {
        use std::os::unix::fs::FileExt;
        OpenOptions::new()
            .write(true)
            .open(f)
            .unwrap()
            .write_at(b"z", 1)
            .unwrap();
    });
    step("truncate to the same size", &[f], &[f], &mut || {
        OpenOptions::new()
            .write(true)
            .open(f)
            .unwrap()
            .set_len(3)
            .unwrap();
    });
    step("truncate longer", &[f], &[f], &mut || {
        OpenOptions::new()
            .write(true)
            .open(f)
            .unwrap()
            .set_len(10)
            .unwrap();
    });
    step("open with O_TRUNC", &[f, d], &[f, d], &mut || {
        OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(f)
            .unwrap();
    });
    step("open an empty file with O_TRUNC", &[f], &[f], &mut || {
        OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(f)
            .unwrap();
    });
    step(
        "open an existing file with O_CREAT",
        &[f, d],
        &[f, d],
        &mut || {
            OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(false)
                .open(f)
                .unwrap();
        },
    );
    let g = dir.join("g");
    step("link", &[f, d], &[f, d], &mut || {
        std::fs::hard_link(f, &g).unwrap();
    });
    step("unlink the other link", &[f, d], &[f, d], &mut || {
        std::fs::remove_file(&g).unwrap();
    });
    let h = dir.join("h");
    step("rename within a directory", &[f, d], &[&h, d], &mut || {
        std::fs::rename(f, &h).unwrap();
    });
    let other = root.join("e");
    std::fs::create_dir(&other).unwrap();
    let k = other.join("k");
    step(
        "rename into another directory",
        &[&h, d, &other],
        &[&k, d, &other],
        &mut || {
            std::fs::rename(&h, &k).unwrap();
        },
    );
    std::fs::rename(&k, &h).unwrap();
    let r = dir.join("r");
    std::fs::write(&r, b"").unwrap();
    step("rename over a file", &[&r, d], &[&h, d], &mut || {
        std::fs::rename(&r, &h).unwrap();
    });
    let n = dir.join("n");
    step("create a file", &[d], &[d], &mut || {
        std::fs::write(&n, b"").unwrap();
    });
    let sub = dir.join("sub");
    step("make a directory", &[d], &[d], &mut || {
        std::fs::create_dir(&sub).unwrap();
    });
    step("list a directory", &[d], &[d], &mut || {
        std::fs::read_dir(d).unwrap().for_each(drop);
    });
    step("remove a directory", &[d], &[d], &mut || {
        std::fs::remove_dir(&sub).unwrap();
    });
    step("make a symlink", &[d], &[d], &mut || {
        std::os::unix::fs::symlink("n", dir.join("s")).unwrap();
    });
    step("utimensat to now", &[&n], &[&n], &mut || {
        utimensat(&n, special(libc::UTIME_NOW), special(libc::UTIME_NOW));
    });
    step("utimensat omitting both", &[&n], &[&n], &mut || {
        utimensat(&n, special(libc::UTIME_OMIT), special(libc::UTIME_OMIT));
    });
    step("utimensat the access time", &[&n], &[&n], &mut || {
        utimensat(
            &n,
            libc::timespec {
                tv_sec: 1_150_000_000,
                tv_nsec: 0,
            },
            special(libc::UTIME_OMIT),
        );
    });
    step(
        "set the modification time before birth",
        &[&n],
        &[&n],
        &mut || {
            File::options()
                .write(true)
                .open(&n)
                .unwrap()
                .set_modified(at(1_000_000_000))
                .unwrap();
        },
    );
    step("set the access time", &[&n], &[&n], &mut || {
        File::options()
            .write(true)
            .open(&n)
            .unwrap()
            .set_times(FileTimes::new().set_accessed(at(1_100_000_000)))
            .unwrap();
    });
    step("unlink", &[d], &[d], &mut || {
        std::fs::remove_file(&n).unwrap();
    });
    let o = dir.join("o");
    std::fs::write(&o, b"x").unwrap();
    let held = File::open(&o).unwrap();
    let changed = |file: &File| {
        let m = file.metadata().unwrap();
        (m.ctime(), m.ctime_nsec())
    };
    let before = changed(&held);
    pause();
    std::fs::remove_file(&o).unwrap();
    pause();
    let moved = if changed(&held) != before { "c" } else { "-" };
    log.push((
        "unlink the last link of an open file",
        vec![moved.to_string()],
    ));
    log
}

/// Ignores access times when the host never updates them (a `noatime` mount): the first read
/// of a just-written file moves them under both Linux's `relatime` and macOS.
fn comparable(
    mut log: Vec<(&'static str, Vec<String>)>,
    atime: bool,
) -> Vec<(&'static str, Vec<String>)> {
    if !atime {
        for (_, moved) in &mut log {
            for moved in moved {
                *moved = moved.replace('a', "");
                if moved.is_empty() {
                    moved.push('-');
                }
            }
        }
    }
    log
}

fn host_truth() -> (Vec<(&'static str, Vec<String>)>, bool) {
    let root = real_dir("truth");
    let log = script(&root, &|| std::thread::sleep(Duration::from_millis(20)));
    std::fs::remove_dir_all(&root).unwrap();
    let atime = log
        .iter()
        .find(|(name, _)| *name == "read")
        .is_some_and(|(_, moved)| moved[0].contains('a'));
    (log, atime)
}

fn real_dir(tag: &str) -> PathBuf {
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let root =
        std::env::temp_dir().join(format!("snare-fs-times-{}-{tag}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    root
}

#[test]
fn script_os_truth() {
    let (log, _) = host_truth();
    let expect = |name: &str| {
        log.iter()
            .find(|(step, _)| *step == name)
            .unwrap()
            .1
            .clone()
    };
    assert_eq!(expect("write"), ["mc", "-"]);
    assert_eq!(expect("link"), ["c", "mc"]);
    assert_eq!(expect("rename within a directory"), ["c", "mc"]);
    assert_eq!(expect("utimensat omitting both"), ["-"]);
    if cfg!(target_os = "macos") {
        assert_eq!(expect("utimensat the access time"), ["a"]);
        assert_eq!(expect("set the modification time before birth"), ["mcb"]);
    } else {
        assert_eq!(expect("utimensat the access time"), ["ac"]);
        assert_eq!(expect("set the modification time before birth"), ["mc"]);
    }
}

#[test]
fn script_on_a_virtual_fs_moves_what_the_host_moves() {
    let (truth, atime) = host_truth();
    let fs = FsBuilder::new().own_prefix("/t").dir("/t").build();
    let log = Sim::builder().fs(fs).fixed_epoch().build().run(|| {
        script(Path::new("/t"), &|| {
            std::thread::sleep(Duration::from_secs(1))
        })
    });
    assert_eq!(comparable(log, atime), comparable(truth, atime));
}

#[test]
fn script_on_real_files_in_a_sim_moves_what_the_host_moves() {
    let (truth, atime) = host_truth();
    let root = real_dir("sim");
    let inner = root.clone();
    let log = Sim::builder().fixed_epoch().build().run(move || {
        script(&inner, &|| {
            std::thread::sleep(Duration::from_secs(1));
            snare::real(|| std::thread::sleep(Duration::from_millis(20)));
        })
    });
    std::fs::remove_dir_all(&root).unwrap();
    assert_eq!(comparable(log, atime), comparable(truth, atime));
}

#[test]
fn virtual_nodes_start_at_the_sim_start_and_follow_its_clock() {
    let fs = FsBuilder::new()
        .own_prefix("/v")
        .file("/v/f", "abc")
        .file("/v/old", "")
        .times(
            "/v/old",
            NodeTimes {
                modified: Some(at(1_600_000_000)),
                created: Some(at(1_500_000_000)),
                ..NodeTimes::default()
            },
        )
        .build();
    Sim::builder().fs(fs).fixed_epoch().build().run(|| {
        let m = std::fs::metadata("/v/f").unwrap();
        for time in [m.accessed(), m.modified(), m.created()] {
            assert_eq!(time.unwrap().secs(), START);
        }
        assert_eq!((m.ctime(), m.ctime_nsec()), (START as i64, 0));
        let dir = std::fs::metadata("/v").unwrap();
        assert_eq!(dir.modified().unwrap().secs(), START);

        let old = std::fs::metadata("/v/old").unwrap();
        assert_eq!(old.modified().unwrap(), at(1_600_000_000));
        assert_eq!(old.created().unwrap(), at(1_500_000_000));
        assert_eq!(old.accessed().unwrap().secs(), START);

        std::thread::sleep(Duration::from_secs(10));
        OpenOptions::new()
            .append(true)
            .open("/v/f")
            .unwrap()
            .write_all(b"d")
            .unwrap();
        let m = std::fs::metadata("/v/f").unwrap();
        assert_eq!(m.modified().unwrap().secs(), START + 10);
        assert_eq!(m.ctime(), (START + 10) as i64);
        assert_eq!(m.accessed().unwrap().secs(), START);
        assert_eq!(m.created().unwrap().secs(), START);

        std::thread::sleep(Duration::from_secs(5));
        std::fs::read("/v/f").unwrap();
        assert_eq!(
            std::fs::metadata("/v/f")
                .unwrap()
                .accessed()
                .unwrap()
                .secs(),
            START + 15
        );

        std::thread::sleep(Duration::from_secs(5));
        std::fs::write("/v/new", b"").unwrap();
        let new = std::fs::metadata("/v/new").unwrap();
        assert_eq!(new.created().unwrap().secs(), START + 20);
        assert_eq!(
            std::fs::metadata("/v").unwrap().modified().unwrap().secs(),
            START + 20
        );

        let file = File::open("/v/new").unwrap();
        assert_eq!(
            file.metadata().unwrap().modified().unwrap().secs(),
            START + 20
        );
    });
}

#[test]
fn set_times_on_virtual_files() {
    let fs = FsBuilder::new()
        .own_prefix("/v")
        .file("/v/f", "abc")
        .build();
    Sim::builder().fs(fs).fixed_epoch().build().run(|| {
        let file = File::options().write(true).open("/v/f").unwrap();
        file.set_times(
            FileTimes::new()
                .set_accessed(at(1_650_000_000))
                .set_modified(at(1_660_000_000)),
        )
        .unwrap();
        let m = std::fs::metadata("/v/f").unwrap();
        assert_eq!(m.accessed().unwrap(), at(1_650_000_000));
        assert_eq!(m.modified().unwrap(), at(1_660_000_000));
        assert_eq!(m.ctime(), START as i64);

        std::thread::sleep(Duration::from_secs(3));
        utimensat(
            Path::new("/v/f"),
            special(libc::UTIME_NOW),
            libc::timespec {
                tv_sec: -10,
                tv_nsec: 5,
            },
        );
        let m = std::fs::metadata("/v/f").unwrap();
        assert_eq!(m.accessed().unwrap().secs(), START + 3);
        assert_eq!((m.mtime(), m.mtime_nsec()), (-10, 5));
        assert_eq!(m.ctime(), (START + 3) as i64);
        if cfg!(target_os = "macos") {
            assert_eq!((m.birthtime_secs(), m.birthtime_nanos()), (-10, 5));
        } else {
            assert_eq!(m.created().unwrap().secs(), START);
        }

        let missing = CString::new("/v/missing").unwrap();
        let times = [special(libc::UTIME_NOW); 2];
        assert_eq!(
            unsafe { libc::utimensat(libc::AT_FDCWD, missing.as_ptr(), times.as_ptr(), 0) },
            -1
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ENOENT)
        );
    });
}

/// `MetadataExt` has no birth time on Linux; the macOS one reads `st_birthtime`.
trait Birth {
    fn birthtime_secs(&self) -> i64;
    fn birthtime_nanos(&self) -> i64;
}

impl Birth for std::fs::Metadata {
    fn birthtime_secs(&self) -> i64 {
        let created = self.created().unwrap();
        match created.duration_since(UNIX_EPOCH) {
            Ok(after) => after.as_secs() as i64,
            Err(before) => -(before.duration().as_nanos().div_ceil(1_000_000_000) as i64),
        }
    }

    fn birthtime_nanos(&self) -> i64 {
        let created = self.created().unwrap();
        let nanos = match created.duration_since(UNIX_EPOCH) {
            Ok(after) => after.as_nanos() as i128,
            Err(before) => -(before.duration().as_nanos() as i128),
        };
        nanos.rem_euclid(1_000_000_000) as i64
    }
}

#[cfg(target_os = "macos")]
#[test]
fn set_created_on_virtual_files() {
    use std::os::macos::fs::FileTimesExt;
    let fs = FsBuilder::new()
        .own_prefix("/v")
        .file("/v/f", "abc")
        .build();
    Sim::builder().fs(fs).fixed_epoch().build().run(|| {
        File::options()
            .write(true)
            .open("/v/f")
            .unwrap()
            .set_times(FileTimes::new().set_created(at(1_200_000_000)))
            .unwrap();
        let m = std::fs::metadata("/v/f").unwrap();
        assert_eq!(m.created().unwrap(), at(1_200_000_000));
        assert_eq!(m.modified().unwrap().secs(), START);
    });
}

#[cfg(target_os = "linux")]
#[test]
fn statx_claims_every_time_of_a_virtual_file() {
    let fs = FsBuilder::new()
        .own_prefix("/v")
        .file("/v/f", "abc")
        .build();
    Sim::builder().fs(fs).fixed_epoch().build().run(|| {
        let path = CString::new("/v/f").unwrap();
        let mut stx: libc::statx = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::statx(libc::AT_FDCWD, path.as_ptr(), 0, libc::STATX_ALL, &mut stx) },
            0
        );
        let want = libc::STATX_ATIME | libc::STATX_MTIME | libc::STATX_CTIME | libc::STATX_BTIME;
        assert_eq!(stx.stx_mask & want, want);
        assert_eq!(stx.stx_btime.tv_sec, START as i64);
        assert_eq!(stx.stx_mtime.tv_sec, START as i64);
    });
}

/// A real file's birth time, where its file system records one (not every Linux one does).
fn born_at(m: &std::fs::Metadata, secs: u64) {
    if let Ok(created) = m.created() {
        assert_eq!(created.secs(), secs);
    }
}

#[test]
fn real_files_follow_the_sim_clock() {
    let root = real_dir("follow");
    let inner = root.clone();
    Sim::builder().fixed_epoch().build().run(move || {
        let dir = inner.join("logs");
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("a.log");
        let mut file = File::create(&path).unwrap();
        let m = std::fs::metadata(&path).unwrap();
        born_at(&m, START);
        assert_eq!(m.modified().unwrap().secs(), START);
        born_at(&std::fs::metadata(&dir).unwrap(), START);

        std::thread::sleep(Duration::from_secs(3600));
        file.write_all(b"line\n").unwrap();
        std::thread::sleep(Duration::from_secs(60));
        let m = std::fs::metadata(&path).unwrap();
        born_at(&m, START);
        assert_eq!(m.modified().unwrap().secs(), START + 3600);
        assert_eq!(m.ctime(), (START + 3600) as i64);
        assert_eq!(
            file.metadata().unwrap().modified().unwrap().secs(),
            START + 3600
        );

        let copy = file.try_clone().unwrap();
        std::thread::sleep(Duration::from_secs(1));
        (&copy).write_all(b"more\n").unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().modified().unwrap().secs(),
            START + 3661
        );

        std::thread::sleep(Duration::from_secs(1));
        std::fs::rename(&path, dir.join("b.log")).unwrap();
        assert_eq!(
            std::fs::metadata(&dir).unwrap().modified().unwrap().secs(),
            START + 3662
        );
        let moved = std::fs::metadata(dir.join("b.log")).unwrap();
        assert_eq!(moved.ctime(), (START + 3662) as i64);
        assert_eq!(moved.modified().unwrap().secs(), START + 3661);

        file.set_modified(at(1_650_000_000)).unwrap();
        assert_eq!(
            std::fs::metadata(dir.join("b.log"))
                .unwrap()
                .modified()
                .unwrap(),
            at(1_650_000_000)
        );
    });
    let host = std::fs::metadata(root.join("logs/b.log")).unwrap();
    assert_eq!(
        host.modified().unwrap(),
        at(1_650_000_000),
        "times the sim sets reach the real file"
    );
    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn real_files_the_sim_never_touched_keep_their_age() {
    let root = real_dir("age");
    std::fs::write(root.join("older"), b"").unwrap();
    File::options()
        .write(true)
        .open(root.join("older"))
        .unwrap()
        .set_modified(SystemTime::now() - Duration::from_secs(7200))
        .unwrap();
    std::fs::write(root.join("newer"), b"").unwrap();
    let inner = root.clone();
    let (older, newer) = Sim::builder().fixed_epoch().build().run(move || {
        (
            std::fs::metadata(inner.join("older"))
                .unwrap()
                .modified()
                .unwrap(),
            std::fs::metadata(inner.join("newer"))
                .unwrap()
                .modified()
                .unwrap(),
        )
    });
    assert!(newer <= at(START) && newer > at(START - 60), "{newer:?}");
    // Linux stamps files from its coarse clock, a tick behind `SystemTime::now`.
    let gap = newer.duration_since(older).unwrap();
    assert!(
        gap > Duration::from_secs(7190) && gap < Duration::from_secs(7260),
        "{gap:?}"
    );
    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn a_real_file_outlives_its_sim() {
    let root = real_dir("outlives");
    let path = root.join("log");
    let inner = path.clone();
    let mut file = {
        let sim = Sim::builder().fixed_epoch().build();
        sim.run(move || File::create(&inner).unwrap())
    };
    file.write_all(b"after the sim\n").unwrap();
    Sim::builder()
        .fixed_epoch()
        .build()
        .run(|| file.write_all(b"in another sim\n").unwrap());
    drop(file);
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        "after the sim\nin another sim\n"
    );
    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn a_wall_clock_sim_reports_host_times() {
    let root = real_dir("wall");
    let path = root.join("f");
    let inner = path.clone();
    let before = SystemTime::now();
    let created = Sim::builder().wall_clock().build().run(move || {
        std::fs::write(&inner, b"").unwrap();
        std::fs::metadata(&inner).unwrap().modified().unwrap()
    });
    assert!(created >= before - Duration::from_secs(1), "{created:?}");
    std::fs::remove_dir_all(&root).unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn synthesized_files_carry_the_boot_time() {
    let host = snare::HostProfile::new().cpus(2).build();
    Sim::builder().host(host).fixed_epoch().build().run(|| {
        std::thread::sleep(Duration::from_secs(30));
        for path in ["/sys/devices/system/cpu/online", "/proc/net/snmp"] {
            let m = std::fs::metadata(path).unwrap();
            assert_eq!(m.modified().unwrap().secs(), START, "{path}");
            assert_eq!(m.ctime(), START as i64, "{path}");
            assert!(
                m.created().is_err(),
                "procfs and sysfs report no birth time: {path}"
            );
        }
    });
}
