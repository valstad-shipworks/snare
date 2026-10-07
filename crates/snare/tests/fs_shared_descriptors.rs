#![cfg(unix)]
//! An open file description belongs to the process. A file opened in one sim's `VirtualFs` (or
//! served by its `SimHost`) is the same open file whichever thread reaches the descriptor: one of
//! another sim, or one of no sim at all, as a logger held in a global is. Calls through it land in
//! the plane that opened it; once that sim is gone they fail with `EBADF`, and the number stays
//! reserved until the holder closes it. The `*_os_truth` twin runs the same steps on a real file.

use std::ffi::{CString, c_int};
use std::path::PathBuf;

use snare::{FsBuilder, HostProfile, Sim};

fn errno() -> c_int {
    std::io::Error::last_os_error().raw_os_error().unwrap()
}

fn open(path: &str, flags: c_int) -> c_int {
    let path = CString::new(path).unwrap();
    let fd = unsafe { libc::open(path.as_ptr(), flags, 0o644) };
    assert!(fd >= 0, "open {path:?}: errno {}", errno());
    fd
}

fn write(fd: c_int, bytes: &[u8]) -> Result<usize, c_int> {
    let n = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
    if n < 0 { Err(errno()) } else { Ok(n as usize) }
}

fn read_from_start(fd: c_int) -> Result<Vec<u8>, c_int> {
    if unsafe { libc::lseek(fd, 0, libc::SEEK_SET) } < 0 {
        return Err(errno());
    }
    let mut out = Vec::new();
    let mut buf = [0u8; 64];
    loop {
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        match n {
            0 => return Ok(out),
            n if n < 0 => return Err(errno()),
            n => out.extend_from_slice(&buf[..n as usize]),
        }
    }
}

fn close(fd: c_int) -> Result<(), c_int> {
    if unsafe { libc::close(fd) } < 0 {
        Err(errno())
    } else {
        Ok(())
    }
}

fn size(fd: c_int) -> i64 {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { libc::fstat(fd, &mut st) },
        0,
        "fstat: errno {}",
        errno()
    );
    st.st_size as i64
}

/// What the steps taken elsewhere saw: the offset after them and the size `fstat` reported.
#[derive(Debug, PartialEq, Eq)]
struct Elsewhere {
    offset: i64,
    size: i64,
}

/// Writes through `fd` and through a `dup` and an `F_DUPFD` of it, closing both duplicates.
fn steps_elsewhere(fd: c_int) -> Elsewhere {
    write(fd, b"b").unwrap();
    let duplicate = unsafe { libc::dup(fd) };
    assert!(duplicate >= 0);
    write(duplicate, b"c").unwrap();
    close(duplicate).unwrap();
    let above = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    assert!(above >= 0);
    write(above, b"d").unwrap();
    close(above).unwrap();
    Elsewhere {
        offset: unsafe { libc::lseek(fd, 0, libc::SEEK_CUR) },
        size: size(fd),
    }
}

/// Writes "a" through `fd` where it was opened, runs [`steps_elsewhere`] through `elsewhere`, and
/// reads the file back where it was opened.
fn shared_description(
    opened: impl Fn(&mut dyn FnMut()),
    fd: c_int,
    elsewhere: impl FnOnce(Box<dyn FnOnce() -> Elsewhere + Send>) -> Elsewhere,
) -> (Elsewhere, Vec<u8>) {
    opened(&mut || {
        write(fd, b"a").unwrap();
    });
    let seen = elsewhere(Box::new(move || steps_elsewhere(fd)));
    let mut bytes = Vec::new();
    opened(&mut || bytes = read_from_start(fd).unwrap());
    (seen, bytes)
}

fn expected() -> (Elsewhere, Vec<u8>) {
    (Elsewhere { offset: 4, size: 4 }, b"abcd".to_vec())
}

fn logs() -> std::sync::Arc<snare::VirtualFs> {
    FsBuilder::new().dir("/xlogs").own_prefix("/xlogs").build()
}

fn opened_in(sim: &Sim) -> c_int {
    sim.run(|| {
        open(
            "/xlogs/x.log",
            libc::O_RDWR | libc::O_CREAT | libc::O_CLOEXEC,
        )
    })
}

#[test]
fn a_description_is_shared_os_truth() {
    let dir = std::env::temp_dir().join(format!("snare-shared-desc-{}", std::process::id()));
    let path = dir.join("x.log");
    let got = snare::real(|| {
        std::fs::create_dir_all(&dir).unwrap();
        let fd = open(
            path.to_str().unwrap(),
            libc::O_RDWR | libc::O_CREAT | libc::O_CLOEXEC,
        );
        let got = shared_description(|step| step(), fd, |f| std::thread::spawn(f).join().unwrap());
        close(fd).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        got
    });
    assert_eq!(got, expected());
}

#[test]
fn a_file_is_reached_from_another_sim() {
    let sim = Sim::builder().fs(logs()).build();
    let fd = opened_in(&sim);
    let got = shared_description(|step| sim.run(step), fd, |f| Sim::new().run(f));
    assert_eq!(got, expected());
    assert_eq!(
        sim.run(|| std::fs::read("/xlogs/x.log").unwrap()),
        b"abcd",
        "by path too"
    );
}

#[test]
fn a_file_is_reached_from_a_sim_with_a_file_system_of_its_own() {
    let sim = Sim::builder().fs(logs()).build();
    let fd = opened_in(&sim);
    let other = Sim::builder().fs(logs()).build();
    let got = shared_description(|step| sim.run(step), fd, |f| other.run(f));
    assert_eq!(got, expected());
    assert_eq!(
        other.run(|| std::fs::read("/xlogs/x.log").unwrap_err().raw_os_error()),
        Some(libc::ENOENT),
        "the other plane's own tree is untouched"
    );
}

#[test]
fn a_file_is_reached_from_outside_every_sim() {
    let sim = Sim::builder().fs(logs()).build();
    let fd = opened_in(&sim);
    let got = shared_description(|step| sim.run(step), fd, |f| f());
    assert_eq!(got, expected());
    let fd = opened_in(&sim);
    let got = shared_description(
        |step| sim.run(step),
        fd,
        |f| std::thread::spawn(f).join().unwrap(),
    );
    assert_eq!(got, expected(), "a second description of the same file");
}

#[test]
fn a_file_is_closed_from_outside_and_its_number_goes_back_to_the_os() {
    let sim = Sim::builder().fs(logs()).build();
    let fd = opened_in(&sim);
    sim.run(|| write(fd, b"kept").unwrap());
    close(fd).unwrap();
    assert_eq!(close(fd), Err(libc::EBADF));
    let real = std::env::temp_dir().join(format!("snare-shared-reuse-{}", std::process::id()));
    let reused = open(
        real.to_str().unwrap(),
        libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
    );
    write(reused, b"real").unwrap();
    assert_eq!(read_from_start(reused).unwrap(), b"real");
    let in_sim = sim.run(|| write(reused, b"!"));
    assert_eq!(
        in_sim,
        Ok(1),
        "a real descriptor stays the OS's inside a sim too"
    );
    close(reused).unwrap();
    assert_eq!(std::fs::read(&real).unwrap(), b"real!");
    std::fs::remove_file(&real).unwrap();
    assert_eq!(sim.run(|| std::fs::read("/xlogs/x.log").unwrap()), b"kept");
}

#[test]
fn dup2_from_outside_moves_descriptors_between_planes_and_the_os() {
    let sim = Sim::builder().fs(logs()).build();
    let fd = opened_in(&sim);
    let real = std::env::temp_dir().join(format!("snare-shared-dup2-{}", std::process::id()));
    let target = open(
        real.to_str().unwrap(),
        libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
    );
    assert_eq!(unsafe { libc::dup2(fd, target) }, target);
    write(target, b"via-dup2").unwrap();
    assert_eq!(
        sim.run(|| std::fs::read("/xlogs/x.log").unwrap()),
        b"via-dup2"
    );
    let other = open(real.to_str().unwrap(), libc::O_RDWR);
    assert_eq!(unsafe { libc::dup2(other, target) }, target);
    close(other).unwrap();
    sim.run(|| write(target, b"real").unwrap());
    close(target).unwrap();
    close(fd).unwrap();
    assert_eq!(std::fs::read(&real).unwrap(), b"real");
    std::fs::remove_file(&real).unwrap();
    assert_eq!(
        sim.run(|| std::fs::read("/xlogs/x.log").unwrap()),
        b"via-dup2"
    );
}

#[test]
fn a_file_of_a_dropped_sim_fails_with_ebadf_until_closed() {
    let sim = Sim::builder().fs(logs()).build();
    let fd = opened_in(&sim);
    drop(sim);
    assert_eq!(write(fd, b"lost"), Err(libc::EBADF));
    assert_eq!(read_from_start(fd), Err(libc::EBADF));
    assert_eq!(Sim::new().run(|| write(fd, b"lost")), Err(libc::EBADF));
    let devnull = open("/dev/null", libc::O_RDONLY);
    assert_ne!(devnull, fd, "the number stays reserved while it is open");
    close(devnull).unwrap();
    assert_eq!(close(fd), Ok(()));
    assert_eq!(close(fd), Err(libc::EBADF));
}

#[test]
fn a_virtual_fs_serves_behind_a_sim_host() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("shared-desc-host");
    let file = dir.join("f.log");
    let fs = FsBuilder::new()
        .dir(&dir)
        .own_prefix(&dir)
        .dir("/sys/devices/system/cpu")
        .own_prefix("/sys/devices/system/cpu")
        .build();
    let host = HostProfile::new().cpus(4).build();
    let sim = Sim::builder().host(host).fs(fs).build();
    let seen = sim.run(|| {
        std::fs::write(&file, "x").unwrap();
        (
            std::fs::read(&file).unwrap(),
            std::fs::metadata(&dir).unwrap().is_dir(),
            std::fs::read_to_string("/sys/devices/system/cpu/online").unwrap(),
        )
    });
    assert_eq!((seen.0.as_slice(), seen.1), (&b"x"[..], true));
    assert_eq!(seen.2, "0-3\n", "the host's paths come first");
    assert!(!file.exists(), "never the real disk");
}

#[test]
fn a_host_file_is_reached_from_outside_every_sim() {
    let host = HostProfile::new().cpus(4).build();
    let sim = Sim::builder().host(host).build();
    let fd = sim.run(|| open("/sys/devices/system/cpu/online", libc::O_RDONLY));
    assert_eq!(read_from_start(fd).unwrap(), b"0-3\n");
    assert_eq!(Sim::new().run(|| read_from_start(fd)).unwrap(), b"0-3\n");
    close(fd).unwrap();
    assert_eq!(close(fd), Err(libc::EBADF));
}
