#![cfg(unix)]

//! OS functions called through addresses stored in data rather than through the image's import
//! slots: a C-style dispatch table such as SQLite's `aSyscall[]`, or a Rust `static` holding
//! `libc::fstat`. The loader fills those words from data relocations (ELF `R_X86_64_64` /
//! `R_AARCH64_ABS64`, Mach-O binds in `__const` and `__data`), so they must lead to the sim just
//! as a direct call does. A table call that reached the real OS would act on the `/dev/null`
//! placeholder behind a virtual file descriptor.

use std::ffi::{CStr, c_char, c_int, c_void};
use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr};
use std::os::fd::AsRawFd;

use libc::{addrinfo, clockid_t, off_t, size_t, ssize_t, timespec};
use snare::{FsBuilder, HostProfile, Sim};

const VIRTUAL_EPOCH_SECS: libc::time_t = 1_700_000_000;
const TABLE_HOST: &CStr = c"table.local";
const TABLE_ADDRESS: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 40);

#[derive(Clone, Copy)]
struct Calls {
    fstat: unsafe extern "C" fn(c_int, *mut libc::stat) -> c_int,
    pread: unsafe extern "C" fn(c_int, *mut c_void, size_t, off_t) -> ssize_t,
    pwrite: unsafe extern "C" fn(c_int, *const c_void, size_t, off_t) -> ssize_t,
    write: unsafe extern "C" fn(c_int, *const c_void, size_t) -> ssize_t,
    clock_gettime: unsafe extern "C" fn(clockid_t, *mut timespec) -> c_int,
    getaddrinfo: unsafe extern "C" fn(
        *const c_char,
        *const c_char,
        *const addrinfo,
        *mut *mut addrinfo,
    ) -> c_int,
}

const CALLS: Calls = Calls {
    fstat: libc::fstat,
    pread: libc::pread,
    pwrite: libc::pwrite,
    write: libc::write,
    clock_gettime: libc::clock_gettime,
    getaddrinfo: libc::getaddrinfo,
};

/// Read-only after relocation: ELF `.data.rel.ro` under RELRO, Mach-O `__DATA_CONST,__const`.
static READ_ONLY: Calls = CALLS;
/// Writable: ELF `.data`, Mach-O `__DATA,__data`.
static mut WRITABLE: Calls = CALLS;

/// SQLite's shape: a writable array of named entries, each a pointer to a libc function.
struct Syscall {
    name: &'static CStr,
    call: unsafe extern "C" fn(c_int, *mut libc::stat) -> c_int,
}

static mut SYSCALLS: [Syscall; 2] = [
    Syscall {
        name: c"fstat",
        call: libc::fstat,
    },
    Syscall {
        name: c"osFstat",
        call: libc::fstat,
    },
];

fn sim() -> Sim {
    let fs = FsBuilder::new().own_prefix("/data").dir("/data").build();
    Sim::builder()
        .host(HostProfile::new().build())
        .fs(fs)
        .add_host(TABLE_HOST.to_str().unwrap(), [IpAddr::V4(TABLE_ADDRESS)])
        .fixed_epoch()
        .build()
}

fn exercise(calls: &Calls, path: &str) {
    let calls = black_box(calls);
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .unwrap();
    let fd = file.as_raw_fd();

    let n = unsafe { (calls.pwrite)(fd, b"hello".as_ptr().cast(), 5, 0) };
    assert_eq!(
        n,
        5,
        "pwrite through the table: {}",
        std::io::Error::last_os_error()
    );
    assert_eq!(std::fs::read(path).unwrap(), b"hello");

    let mut back = [0u8; 5];
    let n = unsafe { (calls.pread)(fd, back.as_mut_ptr().cast(), 5, 0) };
    assert_eq!(n, 5, "pread through the table");
    assert_eq!(&back, b"hello");

    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe { (calls.fstat)(fd, &mut st) };
    assert_eq!(rc, 0, "fstat through the table");
    assert_eq!(
        st.st_mode & libc::S_IFMT,
        libc::S_IFREG,
        "the virtual file, not its /dev/null placeholder"
    );
    assert_eq!(st.st_size, 5);

    let n = unsafe { (calls.write)(fd, b"J".as_ptr().cast(), 1) };
    assert_eq!(n, 1, "write through the table");
    assert_eq!(std::fs::read(path).unwrap(), b"Jello");

    let mut ts: timespec = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { (calls.clock_gettime)(libc::CLOCK_REALTIME, &mut ts) },
        0
    );
    assert_eq!(ts.tv_sec, VIRTUAL_EPOCH_SECS, "the virtual realtime clock");

    let mut hints: addrinfo = unsafe { std::mem::zeroed() };
    hints.ai_family = libc::AF_INET;
    hints.ai_socktype = libc::SOCK_STREAM;
    let mut result = std::ptr::null_mut();
    let rc =
        unsafe { (calls.getaddrinfo)(TABLE_HOST.as_ptr(), std::ptr::null(), &hints, &mut result) };
    assert_eq!(rc, 0, "getaddrinfo through the table finds the sim's host");
    let address = unsafe { *(*result).ai_addr.cast::<libc::sockaddr_in>() };
    assert_eq!(
        Ipv4Addr::from(u32::from_be(address.sin_addr.s_addr)),
        TABLE_ADDRESS
    );
    unsafe { libc::freeaddrinfo(result) };
}

#[test]
fn a_read_only_table_of_libc_functions_reaches_the_sim() {
    sim().run(|| exercise(&READ_ONLY, "/data/read_only"));
}

#[test]
fn a_writable_table_of_libc_functions_reaches_the_sim() {
    sim().run(|| {
        exercise(
            unsafe { &*black_box(&raw const WRITABLE) },
            "/data/writable",
        )
    });
}

#[test]
fn a_named_syscall_array_reaches_the_sim() {
    sim().run(|| {
        let file = std::fs::File::create("/data/named").unwrap();
        let syscalls = unsafe { &*black_box(&raw const SYSCALLS) };
        for entry in syscalls {
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            let rc = unsafe { (entry.call)(file.as_raw_fd(), &mut st) };
            assert_eq!(rc, 0, "{:?}", entry.name);
            assert_eq!(st.st_mode & libc::S_IFMT, libc::S_IFREG, "{:?}", entry.name);
        }
    });
}

/// A pointer taken in code (through the GOT), one stored in data and one from `dlsym` all name
/// the same function, so code comparing them agrees with itself.
#[test]
fn every_way_of_taking_the_address_agrees() {
    sim().run(|| {
        let in_code = black_box(libc::fstat as *const () as usize);
        let in_data = black_box(&READ_ONLY).fstat as *const () as usize;
        let in_writable = unsafe { (*black_box(&raw const WRITABLE)).fstat } as *const () as usize;
        let looked_up = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"fstat".as_ptr()) } as usize;
        assert_eq!(in_data, in_code);
        assert_eq!(in_writable, in_code);
        assert_eq!(looked_up, in_code);
    });
}

/// The tables still reach the real OS outside a sim.
#[test]
fn outside_a_sim_the_table_calls_the_os() {
    let _ = Sim::new();
    let calls = black_box(&READ_ONLY);
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let file = std::fs::File::open("/dev/null").unwrap();
    assert_eq!(unsafe { (calls.fstat)(file.as_raw_fd(), &mut st) }, 0);
    assert_eq!(st.st_mode & libc::S_IFMT, libc::S_IFCHR);
    let mut ts: timespec = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { (calls.clock_gettime)(libc::CLOCK_REALTIME, &mut ts) },
        0
    );
    assert!(ts.tv_sec > VIRTUAL_EPOCH_SECS);
}

fn sqlite_round_trip(path: &str, vfs: Option<&str>) -> rusqlite::Result<i64> {
    use rusqlite::{Connection, OpenFlags};
    let open = || match vfs {
        Some(vfs) => Connection::open_with_flags_and_vfs(path, OpenFlags::default(), vfs),
        None => Connection::open(path),
    };
    let a = open()?;
    a.execute_batch(
        "CREATE TABLE t(x INTEGER); BEGIN; INSERT INTO t VALUES(1); \
         INSERT INTO t VALUES(2); COMMIT;",
    )?;
    let b = open()?;
    b.query_row("SELECT sum(x) FROM t", [], |r| r.get(0))
}

/// SQLite reaches `fstat`, `pread`, `pwrite`, `ftruncate` and the rest through its `aSyscall[]`
/// table of libc addresses, so every file-backed database depends on those data pointers. The
/// `unix-none` VFS takes no file locks (for those, see
/// [`a_file_backed_sqlite_database_with_default_locking`]).
#[test]
fn a_file_backed_sqlite_database_on_the_virtual_fs() {
    sim().run(|| {
        assert_eq!(
            sqlite_round_trip("/data/nolock.db", Some("unix-none")),
            Ok(3)
        );
        assert!(std::fs::metadata("/data/nolock.db").unwrap().len() > 0);
    });
}

/// SQLite's default VFS, which takes `fcntl` record locks through the same table. On macOS it
/// probes the file with `F_GETLK` to choose a locking style, and would fall back to dot-file
/// locking, which has no WAL, were the probe to fail.
#[test]
fn a_file_backed_sqlite_database_with_default_locking() {
    sim().run(|| {
        assert_eq!(sqlite_round_trip("/data/locked.db", None), Ok(3));
        let wal = rusqlite::Connection::open("/data/wal.db").unwrap();
        let mode: String = wal
            .query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))
            .unwrap();
        assert_eq!(mode, "wal");
    });
}
