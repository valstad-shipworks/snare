#![cfg(unix)]

use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd};
#[cfg(target_os = "linux")]
use std::os::unix::fs::FileExt;
use std::os::unix::fs::MetadataExt;

use snare::{FsBuilder, Sim};

fn alias_roundtrip(path: &str) -> (Vec<i32>, Vec<u8>) {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    let fd = file.as_raw_fd();
    let mut first = [0; 2];
    file.read_exact(&mut first).unwrap();
    assert_eq!(&first, b"01");
    assert_eq!(
        unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) },
        0
    );
    assert_eq!(unsafe { libc::dup2(fd, fd) }, fd);
    let unchanged = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    let newfd = unsafe { libc::dup(fd) };
    assert!(newfd >= 0);
    let mut alias = unsafe { File::from_raw_fd(newfd) };
    let cleared = unsafe { libc::fcntl(newfd, libc::F_GETFD) };
    alias.read_exact(&mut first).unwrap();
    assert_eq!(&first, b"23");
    assert_eq!(file.stream_position().unwrap(), 4);
    assert_eq!(
        file.metadata().unwrap().ino(),
        alias.metadata().unwrap().ino()
    );
    let flags = unsafe { libc::fcntl(newfd, libc::F_GETFL) };
    assert_eq!(
        unsafe {
            libc::fcntl(
                newfd,
                libc::F_SETFL,
                flags | libc::O_APPEND | libc::O_NONBLOCK,
            )
        },
        0
    );
    let shared = unsafe { libc::fcntl(fd, libc::F_GETFL) }
        & (libc::O_ACCMODE | libc::O_APPEND | libc::O_NONBLOCK);
    let cloexec = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    assert!(cloexec >= 0);
    let cloexec_flags = unsafe { libc::fcntl(cloexec, libc::F_GETFD) };
    assert_eq!(unsafe { libc::close(cloexec) }, 0);
    file.seek(SeekFrom::Start(0)).unwrap();
    drop(file);
    alias.write_all(b"X").unwrap();
    assert_eq!(alias.stream_position().unwrap(), 11);
    alias.seek(SeekFrom::Start(0)).unwrap();
    let mut content = Vec::new();
    alias.read_to_end(&mut content).unwrap();
    drop(alias);
    assert_eq!(std::fs::read(path).unwrap(), content);
    (vec![unchanged, cleared, shared, cloexec_flags], content)
}

#[test]
fn duplicated_files_share_offsets_flags_and_last_close_contents_os_truth() {
    let path = std::env::temp_dir().join(format!("snare-fs-alias-{}", std::process::id()));
    std::fs::write(&path, b"0123456789").unwrap();
    let path = path.to_str().unwrap();
    let real = alias_roundtrip(path);
    assert_eq!(real.1, b"0123456789X");
    let fs = FsBuilder::new().file(path, "0123456789").build();
    assert_eq!(
        Sim::builder().fs(fs).build().run(|| alias_roundtrip(path)),
        real
    );
    std::fs::remove_file(path).unwrap();
}

fn replacement(path: &str, target_path: &str) -> (Vec<i32>, Vec<u8>, Vec<u8>) {
    let mut source = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    let mut target = OpenOptions::new()
        .read(true)
        .write(true)
        .open(target_path)
        .unwrap();
    target.write_all(b"saved").unwrap();
    let retained = target.try_clone().unwrap();
    let sourcefd = source.as_raw_fd();
    let targetfd = target.as_raw_fd();
    assert_eq!(unsafe { libc::dup2(-1, targetfd) }, -1);
    let invalid = std::io::Error::last_os_error().raw_os_error().unwrap();
    assert_eq!(unsafe { libc::dup2(sourcefd, targetfd) }, targetfd);
    assert_eq!(unsafe { libc::fcntl(targetfd, libc::F_GETFD) }, 0);
    drop(retained);
    let old_content = std::fs::read(target_path).unwrap();
    source.seek(SeekFrom::Start(2)).unwrap();
    let mut bytes = [0; 2];
    target.read_exact(&mut bytes).unwrap();
    assert_eq!(&bytes, b"23");
    drop(source);
    target.write_all(b"XY").unwrap();
    drop(target);
    (vec![invalid], old_content, std::fs::read(path).unwrap())
}

#[test]
fn replacing_a_file_preserves_each_open_description_os_truth() {
    let directory = std::env::temp_dir().join(format!("snare-fs-replace-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let source = directory.join("source");
    let target = directory.join("target");
    std::fs::write(&source, b"0123456789").unwrap();
    std::fs::write(&target, b"old").unwrap();
    let source = source.to_str().unwrap();
    let target = target.to_str().unwrap();
    let real = replacement(source, target);
    let fs = FsBuilder::new()
        .file(source, "0123456789")
        .file(target, "old")
        .build();
    assert_eq!(
        Sim::builder()
            .fs(fs)
            .build()
            .run(|| replacement(source, target)),
        real
    );
    std::fs::remove_dir_all(directory).unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn dup3_file_flags_and_failed_replacements_os_truth() {
    let path = std::env::temp_dir().join(format!("snare-fs-dup3-{}", std::process::id()));
    std::fs::write(&path, b"content").unwrap();
    let probe = || {
        let source = File::open(&path).unwrap();
        let target = File::open(&path).unwrap();
        let fd = source.as_raw_fd();
        let newfd = target.as_raw_fd();
        assert_eq!(unsafe { libc::dup3(fd, fd, 0) }, -1);
        let same = std::io::Error::last_os_error().raw_os_error().unwrap();
        assert_eq!(unsafe { libc::dup3(fd, newfd, libc::O_NONBLOCK) }, -1);
        let invalid = std::io::Error::last_os_error().raw_os_error().unwrap();
        assert_eq!(unsafe { libc::dup3(fd, newfd, libc::O_CLOEXEC) }, newfd);
        (same, invalid, unsafe { libc::fcntl(newfd, libc::F_GETFD) })
    };
    let real = probe();
    let fs = FsBuilder::new().file(&path, "content").build();
    assert_eq!(Sim::builder().fs(fs).build().run(probe), real);
    std::fs::remove_file(path).unwrap();
}

fn open_cloexec(path: &str) {
    let path = CString::new(path).unwrap();
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    assert!(fd >= 0);
    assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, libc::FD_CLOEXEC);
    let duplicated = unsafe { libc::fcntl(fd, libc::F_DUPFD, 0) };
    assert!(duplicated >= 0);
    assert_eq!(unsafe { libc::fcntl(duplicated, libc::F_GETFD) }, 0);
    assert_eq!(unsafe { libc::close(fd) }, 0);
    assert_eq!(unsafe { libc::close(duplicated) }, 0);
}

#[test]
fn virtual_open_cloexec_and_f_dupfd_flags() {
    let fs = FsBuilder::new().file("/virtual/cloexec", "data").build();
    Sim::builder()
        .fs(fs)
        .build()
        .run(|| open_cloexec("/virtual/cloexec"));
}

#[cfg(target_os = "linux")]
#[test]
fn synthetic_and_proc_files_keep_shared_offsets_after_source_closes() {
    let host = snare::HostProfile::new().cpus(32).build();
    let sim = Sim::builder().host(host).build();
    sim.run(|| {
        for path in ["/sys/devices/system/cpu/online", "/proc/net/snmp"] {
            let expected = std::fs::read(path).unwrap();
            let mut file = File::open(path).unwrap();
            let mut alias = file.try_clone().unwrap();
            let mut first = [0; 2];
            file.read_exact(&mut first).unwrap();
            assert_eq!(&first, &expected[..2]);
            assert_eq!(
                file.metadata().unwrap().ino(),
                alias.metadata().unwrap().ino()
            );
            drop(file);
            let mut suffix = Vec::new();
            alias.read_to_end(&mut suffix).unwrap();
            assert_eq!(suffix, expected[2..]);
            open_cloexec(path);
        }
    });
}

#[cfg(target_os = "linux")]
#[test]
fn synthetic_and_proc_positional_reads_preserve_alias_offsets() {
    let host = snare::HostProfile::new().cpus(32).build();
    Sim::builder().host(host).build().run(|| {
        for path in ["/sys/devices/system/cpu/online", "/proc/net/snmp"] {
            let expected = std::fs::read(path).unwrap();
            let mut file = File::open(path).unwrap();
            let alias = file.try_clone().unwrap();
            file.seek(SeekFrom::Start(2)).unwrap();
            let mut bytes = vec![0; expected.len()];
            assert_eq!(alias.read_at(&mut bytes, 0).unwrap(), expected.len());
            assert_eq!(bytes, expected);
            assert_eq!(file.stream_position().unwrap(), 2);
            assert_eq!(
                unsafe {
                    libc::pread(
                        alias.as_raw_fd(),
                        bytes.as_mut_ptr().cast(),
                        bytes.len(),
                        -1,
                    )
                },
                -1
            );
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EINVAL)
            );
            file.seek(SeekFrom::Start(10_000)).unwrap();
            assert_eq!(file.read(&mut bytes).unwrap(), 0);
            assert_eq!(file.stream_position().unwrap(), 10_000);
        }
    });
}

#[cfg(target_os = "linux")]
#[test]
fn fs_chain_replacement_flushes_virtual_target_and_preserves_proc_alias() {
    let fs = FsBuilder::new().file("/virtual/target", "old").build();
    Sim::builder().fs(fs).build().run(|| {
        let expected = std::fs::read("/proc/net/snmp").unwrap();
        let mut proc = File::open("/proc/net/snmp").unwrap();
        let mut target = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/virtual/target")
            .unwrap();
        target.write_all(b"saved").unwrap();
        assert_eq!(
            unsafe { libc::dup2(proc.as_raw_fd(), target.as_raw_fd()) },
            target.as_raw_fd()
        );
        assert_eq!(std::fs::read("/virtual/target").unwrap(), b"saved");
        let mut bytes = [0; 2];
        proc.read_exact(&mut bytes).unwrap();
        drop(proc);
        let mut suffix = Vec::new();
        target.read_to_end(&mut suffix).unwrap();
        assert_eq!(suffix, expected[2..]);
    });
}

fn directory_alias(path: &str) -> (bool, i32, u32, i32) {
    let path = CString::new(path).unwrap();
    let directory = unsafe { libc::opendir(path.as_ptr()) };
    assert!(!directory.is_null());
    let fd = unsafe { libc::dirfd(directory) };
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    let alias = unsafe { libc::dup(fd) };
    assert!(alias >= 0);
    let mut first: libc::stat = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::fstat(fd, &mut first) }, 0);
    assert_eq!(unsafe { libc::closedir(directory) }, 0);
    let mut retained: libc::stat = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::fstat(alias, &mut retained) }, 0);
    assert_eq!(unsafe { libc::close(alias) }, 0);
    #[cfg(target_os = "linux")]
    let mode = retained.st_mode & libc::S_IFMT;
    #[cfg(not(target_os = "linux"))]
    let mode = u32::from(retained.st_mode & libc::S_IFMT);
    (first.st_ino == retained.st_ino, flags, mode, alias)
}

#[test]
fn directory_descriptor_alias_survives_closedir_os_truth() {
    let directory = std::env::temp_dir().join(format!("snare-fs-dir-alias-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.to_str().unwrap();
    let real = directory_alias(path);
    let fs = FsBuilder::new().dir(path).build();
    let model = Sim::builder()
        .fs(fs.clone())
        .build()
        .run(|| directory_alias(path));
    assert_eq!((model.0, model.1, model.2), (real.0, real.1, real.2));
    assert!(!snare_interpose::Fs::owns(&*fs, model.3));
    std::fs::remove_dir(directory).unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn synthetic_directory_alias_is_retired_on_last_close() {
    let host = snare::HostProfile::new()
        .nic(snare::Nic::new("eth0", 1))
        .build();
    let result = Sim::builder()
        .host(host.clone())
        .build()
        .run(|| directory_alias("/sys/class/net/eth0/queues"));
    assert_eq!(
        (result.0, result.1, result.2),
        (true, libc::FD_CLOEXEC, libc::S_IFDIR)
    );
    assert!(!snare_interpose::Fs::owns(&*host, result.3));
}

#[cfg(target_os = "linux")]
fn readonly_host_operations(path: &str) -> Vec<(i64, Option<i32>)> {
    let file = File::open(path).unwrap();
    let fd = file.as_raw_fd();
    let mut observed = Vec::new();
    let mut record = |result: i64| {
        observed.push((
            result,
            (result < 0).then(|| std::io::Error::last_os_error().raw_os_error().unwrap()),
        ));
    };
    record(unsafe { libc::write(fd, b"1".as_ptr().cast(), 1) } as i64);
    record(unsafe { libc::pwrite(fd, b"1".as_ptr().cast(), 1, 0) } as i64);
    record(unsafe { libc::ftruncate(fd, 0) } as i64);
    record(unsafe { libc::fsync(fd) } as i64);
    observed
}

#[cfg(target_os = "linux")]
#[test]
fn readonly_proc_and_sysfs_operations_match_host_errors() {
    let host = snare::HostProfile::new()
        .nic(snare::Nic::new("eth0", 2))
        .build();
    for (native_path, modeled_path) in [
        ("/proc/net/snmp", "/proc/net/snmp"),
        ("/sys/class/net/lo/mtu", "/sys/class/net/eth0/mtu"),
    ] {
        let native = readonly_host_operations(native_path);
        let modeled = Sim::builder()
            .host(host.clone())
            .build()
            .run(|| readonly_host_operations(modeled_path));
        assert_eq!(modeled, native, "{native_path}");
    }
}

#[cfg(target_os = "linux")]
#[test]
fn zero_length_reads_accept_null_and_do_not_snapshot_proc_counters() {
    let host = snare::HostProfile::new()
        .nic(snare::Nic::new("eth0", 2))
        .build();
    Sim::builder().host(host).build().run(|| {
        let mut counters = File::open("/proc/net/snmp").unwrap();
        let sysfs = File::open("/sys/class/net/eth0/mtu").unwrap();
        for fd in [counters.as_raw_fd(), sysfs.as_raw_fd()] {
            assert_eq!(unsafe { libc::read(fd, std::ptr::null_mut(), 0) }, 0);
        }
        let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let receiver = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        sender
            .send_to(b"counter", receiver.local_addr().unwrap())
            .unwrap();
        let expected = std::fs::read("/proc/net/snmp").unwrap();
        let mut actual = Vec::new();
        counters.read_to_end(&mut actual).unwrap();
        assert_eq!(actual, expected);
    });
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
#[test]
fn fcntl64_reaches_the_file_plane() {
    unsafe extern "C" {
        fn fcntl64(fd: libc::c_int, cmd: libc::c_int, ...) -> libc::c_int;
    }
    let fs = FsBuilder::new().file("/fcntl64/f", "x").build();
    Sim::builder().fs(fs).build().run(|| {
        let file = OpenOptions::new().append(true).open("/fcntl64/f").unwrap();
        let flags = unsafe { fcntl64(file.as_raw_fd(), libc::F_GETFL) };
        assert_eq!(
            flags & (libc::O_ACCMODE | libc::O_APPEND),
            libc::O_WRONLY | libc::O_APPEND
        );
    });
}
