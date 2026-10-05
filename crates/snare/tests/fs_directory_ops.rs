#![cfg(unix)]

use std::ffi::{CStr, CString};
use std::path::Path;

use snare::{FsBuilder, Sim};

fn root(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("snare-directory-{name}-{}", std::process::id()))
}

fn listing(path: &Path) -> Vec<String> {
    let path = CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    unsafe {
        let fd = libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY);
        assert!(fd >= 0);
        let stream = libc::fdopendir(fd);
        assert!(!stream.is_null(), "{}", std::io::Error::last_os_error());
        assert_eq!(libc::dirfd(stream), fd);
        let mut names = Vec::new();
        loop {
            let entry = libc::readdir(stream);
            if entry.is_null() {
                break;
            }
            names.push(
                CStr::from_ptr((*entry).d_name.as_ptr())
                    .to_string_lossy()
                    .into_owned(),
            );
        }
        assert_eq!(libc::closedir(stream), 0);
        names.sort();
        names
    }
}

#[test]
fn fdopendir_owns_the_directory_descriptor_os_truth() {
    let path = root("stream");
    std::fs::create_dir(&path).unwrap();
    std::fs::write(path.join("file"), b"data").unwrap();
    let native = listing(&path);
    std::fs::remove_dir_all(&path).unwrap();
    let fs = FsBuilder::new()
        .file(path.join("file"), b"data".to_vec())
        .own_prefix(&path)
        .build();
    let modeled = Sim::builder().fs(fs).build().run(|| listing(&path));
    assert_eq!(modeled, native);
    assert!(!path.exists());
}

fn relative_mutations(path: &Path) -> (bool, bool, Vec<u8>) {
    let path_c = CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    unsafe {
        let fd = libc::open(path_c.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY);
        assert!(fd >= 0);
        assert_eq!(libc::mkdirat(fd, c"child".as_ptr(), 0o755), 0);
        let file = libc::openat(
            fd,
            c"child/file".as_ptr(),
            libc::O_RDWR | libc::O_CREAT,
            0o644,
        );
        assert!(file >= 0, "{}", std::io::Error::last_os_error());
        assert_eq!(libc::write(file, b"data".as_ptr().cast(), 4), 4);
        assert_eq!(
            libc::renameat(fd, c"child/file".as_ptr(), fd, c"file".as_ptr()),
            0
        );
        assert_eq!(libc::unlinkat(fd, c"child".as_ptr(), libc::AT_REMOVEDIR), 0);
        let mut stat = std::mem::zeroed::<libc::stat>();
        assert_eq!(libc::fstatat(fd, c"file".as_ptr(), &mut stat, 0), 0);
        assert_eq!(libc::unlinkat(fd, c"file".as_ptr(), 0), 0);
        let mut data = [0; 4];
        assert_eq!(libc::pread(file, data.as_mut_ptr().cast(), 4, 0), 4);
        assert_eq!(libc::close(file), 0);
        assert_eq!(libc::close(fd), 0);
        (
            !path.join("file").exists(),
            !path.join("child").exists(),
            data.to_vec(),
        )
    }
}

#[test]
fn directory_relative_mutations_os_truth() {
    let path = root("relative");
    std::fs::create_dir(&path).unwrap();
    let native = relative_mutations(&path);
    std::fs::remove_dir(&path).unwrap();
    let fs = FsBuilder::new().dir(&path).own_prefix(&path).build();
    let modeled = Sim::builder()
        .fs(fs)
        .build()
        .run(|| relative_mutations(&path));
    assert_eq!(modeled, native);
    assert!(!path.exists());
}

fn removals(path: &Path) -> Vec<i32> {
    std::fs::create_dir(path.join("empty")).unwrap();
    std::fs::create_dir(path.join("full")).unwrap();
    std::fs::write(path.join("full/file"), b"data").unwrap();
    [
        path.join("empty"),
        path.join("full"),
        path.join("full/file"),
        path.join("missing"),
    ]
    .iter()
    .map(|path| std::fs::remove_dir(path).map_or_else(|e| e.raw_os_error().unwrap(), |_| 0))
    .collect()
}

#[test]
fn remove_directories_os_truth() {
    let path = root("remove");
    std::fs::create_dir(&path).unwrap();
    let native = removals(&path);
    std::fs::remove_dir_all(&path).unwrap();
    let fs = FsBuilder::new().dir(&path).own_prefix(&path).build();
    assert_eq!(
        Sim::builder().fs(fs).build().run(|| removals(&path)),
        native
    );
    assert!(!path.exists());
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    #[link_name = "__getdirentries64"]
    fn getdirentries64(
        fd: libc::c_int,
        buf: *mut u8,
        len: usize,
        base: *mut libc::off_t,
    ) -> libc::ssize_t;
}

unsafe fn raw_entries(fd: libc::c_int, buf: &mut [u8]) -> libc::ssize_t {
    #[cfg(target_os = "linux")]
    {
        unsafe {
            libc::syscall(libc::SYS_getdents64, fd, buf.as_mut_ptr(), buf.len()) as libc::ssize_t
        }
    }
    #[cfg(target_os = "macos")]
    {
        let mut base = 0;
        unsafe { getdirentries64(fd, buf.as_mut_ptr(), buf.len(), &mut base) }
    }
}

fn raw_listing(path: &Path) -> (Vec<(String, u8)>, bool) {
    let path = CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    unsafe {
        let fd = libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY);
        assert!(fd >= 0);
        let alias = libc::dup(fd);
        assert!(alias >= 0);
        let mut buffer = [0u8; 128];
        let mut names = Vec::new();
        loop {
            let n = raw_entries(alias, &mut buffer);
            assert!(n >= 0, "{}", std::io::Error::last_os_error());
            if n == 0 {
                break;
            }
            let mut offset = 0;
            while offset < n as usize {
                let record = buffer.as_ptr().add(offset).cast::<libc::dirent>();
                let len = std::ptr::addr_of!((*record).d_reclen).read_unaligned() as usize;
                assert!(len > 0 && len <= n as usize - offset);
                let name = CStr::from_ptr(std::ptr::addr_of!((*record).d_name).cast())
                    .to_string_lossy()
                    .into_owned();
                let dtype = std::ptr::addr_of!((*record).d_type).read_unaligned();
                names.push((name, dtype));
                offset += len;
            }
        }
        assert_eq!(raw_entries(fd, &mut buffer), 0);
        assert_eq!(libc::lseek(fd, 0, libc::SEEK_SET), 0);
        let rewound = raw_entries(alias, &mut buffer) > 0;
        assert_eq!(libc::close(alias), 0);
        assert_eq!(libc::close(fd), 0);
        names.sort();
        (names, rewound)
    }
}

#[test]
fn raw_directory_records_share_offsets_across_aliases_os_truth() {
    let path = root("records");
    std::fs::create_dir(&path).unwrap();
    std::fs::create_dir(path.join("child")).unwrap();
    std::fs::write(path.join("file"), b"data").unwrap();
    let native = raw_listing(&path);
    std::fs::remove_dir_all(&path).unwrap();
    let fs = FsBuilder::new()
        .dir(path.join("child"))
        .file(path.join("file"), b"data".to_vec())
        .own_prefix(&path)
        .build();
    assert_eq!(
        Sim::builder().fs(fs).build().run(|| raw_listing(&path)),
        native
    );
    assert!(!path.exists());
}

#[cfg(target_os = "linux")]
#[test]
fn synthetic_directory_records_and_filesystem_type_use_the_owned_plane() {
    let sim = Sim::builder()
        .host(
            snare::HostProfile::new()
                .nic(snare::Nic::new("eth0", 1))
                .build(),
        )
        .build();
    sim.run(|| unsafe {
        let fd = libc::open(
            c"/sys/class/net".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY,
        );
        assert!(fd >= 0, "{}", std::io::Error::last_os_error());
        let alias = libc::dup(fd);
        assert!(alias >= 0);
        let mut buffer = [0; 1024];
        assert!(raw_entries(fd, &mut buffer) > 0);
        assert_eq!(libc::lseek(alias, 0, libc::SEEK_SET), 0);
        assert!(raw_entries(alias, &mut buffer) > 0);
        let stream = libc::fdopendir(alias);
        assert!(!stream.is_null());
        assert_eq!(libc::closedir(stream), 0);
        let mut modeled: libc::statfs = std::mem::zeroed();
        let mut native: libc::statfs = std::mem::zeroed();
        assert_eq!(libc::fstatfs(fd, &mut modeled), 0);
        assert_eq!(
            snare::real(|| libc::statfs(c"/sys".as_ptr(), &mut native)),
            0
        );
        assert_eq!(
            (
                modeled.f_type,
                modeled.f_bsize,
                modeled.f_blocks,
                modeled.f_files
            ),
            (
                native.f_type,
                native.f_bsize,
                native.f_blocks,
                native.f_files
            )
        );
        assert_eq!(libc::read(fd, buffer.as_mut_ptr().cast(), 1), -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EISDIR)
        );
        assert_eq!(libc::close(fd), 0);
    });
}

#[cfg(target_os = "linux")]
#[test]
fn directory_streams_accept_high_numbered_descriptors_os_truth() {
    struct RestoreLimit(libc::rlimit);
    impl Drop for RestoreLimit {
        fn drop(&mut self) {
            assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &self.0) }, 0);
        }
    }
    let mut limit = unsafe { std::mem::zeroed::<libc::rlimit>() };
    assert_eq!(
        unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) },
        0
    );
    let _restore = RestoreLimit(limit);
    let raised = libc::rlimit {
        rlim_cur: limit.rlim_cur.max(70001),
        rlim_max: limit.rlim_max,
    };
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raised) }, 0);
    fn high_listing(path: &Path) -> Vec<String> {
        let path = CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        unsafe {
            let fd = libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY);
            assert!(fd >= 0);
            let high = libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 70000);
            assert!(high >= 70000, "{}", std::io::Error::last_os_error());
            assert_eq!(libc::close(fd), 0);
            let stream = libc::fdopendir(high);
            assert!(!stream.is_null());
            assert_eq!(libc::dirfd(stream), high);
            let mut names = Vec::new();
            loop {
                let entry = libc::readdir(stream);
                if entry.is_null() {
                    break;
                }
                names.push(
                    CStr::from_ptr((*entry).d_name.as_ptr())
                        .to_string_lossy()
                        .into_owned(),
                );
            }
            assert_eq!(libc::closedir(stream), 0);
            assert_eq!(libc::fcntl(high, libc::F_GETFD), -1);
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EBADF)
            );
            names.sort();
            names
        }
    }
    let path = root("high-fd");
    std::fs::create_dir(&path).unwrap();
    std::fs::write(path.join("file"), b"data").unwrap();
    let native = high_listing(&path);
    std::fs::remove_dir_all(&path).unwrap();
    let fs = FsBuilder::new()
        .file(path.join("file"), b"data".to_vec())
        .own_prefix(&path)
        .build();
    assert_eq!(
        Sim::builder().fs(fs).build().run(|| high_listing(&path)),
        native
    );
}

fn stat_flags(path: &Path) -> Vec<i32> {
    let path = CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    unsafe {
        let fd = libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY);
        assert!(fd >= 0);
        let flags = vec![0, libc::AT_SYMLINK_NOFOLLOW, libc::AT_EACCESS, 0x10000000];
        #[cfg(target_os = "linux")]
        let flags = {
            let mut flags = flags;
            flags.extend([libc::AT_EMPTY_PATH, libc::AT_NO_AUTOMOUNT]);
            flags
        };
        let result = flags
            .into_iter()
            .map(|flag| {
                let mut stat = std::mem::zeroed::<libc::stat>();
                if libc::fstatat(fd, c"file".as_ptr(), &mut stat, flag) == 0 {
                    0
                } else {
                    std::io::Error::last_os_error().raw_os_error().unwrap()
                }
            })
            .collect();
        assert_eq!(libc::close(fd), 0);
        result
    }
}

#[test]
fn directory_relative_stat_flags_os_truth() {
    let path = root("stat-flags");
    std::fs::create_dir(&path).unwrap();
    std::fs::write(path.join("file"), b"data").unwrap();
    let native = stat_flags(&path);
    std::fs::remove_dir_all(&path).unwrap();
    let fs = FsBuilder::new()
        .file(path.join("file"), b"data".to_vec())
        .own_prefix(&path)
        .build();
    assert_eq!(
        Sim::builder().fs(fs).build().run(|| stat_flags(&path)),
        native
    );
}

#[test]
fn directory_streams_accept_descriptor_zero() {
    const CHILD: &str = "SNARE_DIRECTORY_FD_ZERO";
    if std::env::var_os(CHILD).is_none() {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "directory_streams_accept_descriptor_zero",
                "--test-threads=1",
            ])
            .env(CHILD, "1")
            .status()
            .unwrap();
        assert!(status.success());
        return;
    }
    let path = root("zero-fd");
    std::fs::create_dir(&path).unwrap();
    fn zero_stream(path: &Path) {
        let path = CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        unsafe {
            let saved = libc::dup(0);
            assert!(saved > 0);
            assert_eq!(libc::close(0), 0);
            let stream = libc::opendir(path.as_ptr());
            assert!(!stream.is_null(), "{}", std::io::Error::last_os_error());
            assert_eq!(libc::dirfd(stream), 0);
            assert!(!libc::readdir(stream).is_null());
            assert_eq!(libc::closedir(stream), 0);
            assert_eq!(libc::dup2(saved, 0), 0);
            assert_eq!(libc::close(saved), 0);
        }
    }
    zero_stream(&path);
    std::fs::remove_dir(&path).unwrap();
    let fs = FsBuilder::new().dir(&path).own_prefix(&path).build();
    Sim::builder().fs(fs).build().run(|| zero_stream(&path));
    #[cfg(target_os = "linux")]
    Sim::builder()
        .host(
            snare::HostProfile::new()
                .nic(snare::Nic::new("eth0", 1))
                .build(),
        )
        .build()
        .run(|| zero_stream(Path::new("/sys/class/net")));
}

#[cfg(target_os = "linux")]
#[test]
fn synthetic_metadata_matches_proc_and_sysfs_os_truth() {
    use std::os::unix::fs::MetadataExt;
    fn metadata(name: &str) -> Vec<(u32, u64, u64, u64, u64, u32, u32)> {
        [
            "/sys/class/net",
            &format!("/sys/class/net/{name}/mtu"),
            &format!("/sys/class/net/{name}/ifindex"),
            "/proc/self/status",
            "/proc/sys/net/ipv4/tcp_syn_retries",
            "/proc/net/snmp",
        ]
        .map(|path| {
            let named = std::fs::metadata(path).unwrap();
            let opened = std::fs::File::open(path).unwrap().metadata().unwrap();
            let fields = |value: &std::fs::Metadata| {
                (
                    value.mode(),
                    value.len(),
                    value.nlink(),
                    value.blocks(),
                    value.blksize(),
                    value.uid(),
                    value.gid(),
                )
            };
            assert_eq!(fields(&named), fields(&opened), "{path}");
            assert_eq!(named.ino(), opened.ino(), "{path}");
            fields(&named)
        })
        .to_vec()
    }
    let native = metadata("lo");
    let sim = Sim::builder()
        .host(
            snare::HostProfile::new()
                .nic(snare::Nic::new("eth0", 7))
                .build(),
        )
        .build();
    assert_eq!(sim.run(|| metadata("eth0")), native);
}

#[cfg(target_os = "linux")]
#[test]
fn synthetic_directory_descriptor_flags_os_truth() {
    fn descriptor_flags() -> Vec<(i32, i32)> {
        [0, libc::O_CLOEXEC]
            .into_iter()
            .map(|flag| unsafe {
                let fd = libc::open(
                    c"/sys/class/net".as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | flag,
                );
                assert!(fd >= 0);
                let before = libc::fcntl(fd, libc::F_GETFD);
                let stream = libc::fdopendir(fd);
                assert!(!stream.is_null());
                let after = libc::fcntl(fd, libc::F_GETFD);
                assert_eq!(libc::closedir(stream), 0);
                (before, after)
            })
            .collect()
    }
    let native = descriptor_flags();
    let sim = Sim::builder()
        .host(
            snare::HostProfile::new()
                .nic(snare::Nic::new("eth0", 7))
                .build(),
        )
        .build();
    assert_eq!(sim.run(descriptor_flags), native);
    let fs = FsBuilder::new()
        .dir("/sys/class/net")
        .own_prefix("/sys/class/net")
        .build();
    assert_eq!(Sim::builder().fs(fs).build().run(descriptor_flags), native);
}
