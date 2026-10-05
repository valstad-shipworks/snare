#![cfg(unix)]

use snare::{FsBuilder, Sim};
use std::path::{Path, PathBuf};

struct NativeDirectory(PathBuf);

impl NativeDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("snare-cwd-routing-{}", std::process::id()));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for NativeDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn virtual_cwd_routes_sibling_native_paths_without_native_virtual_parents() {
    let directory = NativeDirectory::new();
    let native = directory.0.join("native");
    std::fs::create_dir(&native).unwrap();
    for deterministic in [false, true] {
        std::fs::write(native.join("original"), b"host contents").unwrap();
        let cwd = directory.0.join("virtual");
        let fs = FsBuilder::new().dir(&cwd).own_prefix(&cwd).build();
        let builder = Sim::builder().fs(fs);
        let sim = if deterministic {
            builder.deterministic().build()
        } else {
            builder.build()
        };
        let host_cwd = std::env::current_dir().unwrap();
        sim.run(|| {
            std::env::set_current_dir(&cwd).unwrap();
            assert_eq!(std::env::current_dir().unwrap(), cwd);
            assert_eq!(snare::real(std::env::current_dir).unwrap(), host_cwd);
            assert_eq!(
                std::fs::read("../native/original").unwrap(),
                b"host contents"
            );
            std::fs::rename("../native/original", "./../native/renamed").unwrap();
            std::os::unix::fs::symlink("renamed", "../native/link").unwrap();
            assert_eq!(
                std::fs::read_link("../native/link").unwrap(),
                Path::new("renamed")
            );
            assert_eq!(std::fs::read("../native/link").unwrap(), b"host contents");
            std::fs::remove_file("../native/link").unwrap();
            std::fs::remove_file("../native/renamed").unwrap();
            assert!(!snare::real(|| cwd.exists()));
        });
        assert_eq!(std::env::current_dir().unwrap(), host_cwd);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn virtual_cwd_routes_leading_parents_to_the_proc_plane() {
    for deterministic in [false, true] {
        let cwd = Path::new("/snare-cwd-routing-proc");
        let fs = FsBuilder::new().dir(cwd).own_prefix(cwd).build();
        let builder = Sim::builder().fs(fs);
        let sim = if deterministic {
            builder.deterministic().build()
        } else {
            builder.build()
        };
        sim.run(|| {
            let absolute = std::fs::read("/proc/net/snmp").unwrap();
            std::env::set_current_dir(cwd).unwrap();
            assert_eq!(std::fs::read("../proc/net/snmp").unwrap(), absolute);
        });
    }
}

#[test]
fn native_cwd_transitions_clear_the_virtual_directory() {
    let host_cwd = std::env::current_dir().unwrap();
    for deterministic in [false, true] {
        let cwd = Path::new("/snare-cwd-routing-transition");
        let fs = FsBuilder::new().dir(cwd).own_prefix(cwd).build();
        let builder = Sim::builder().fs(fs);
        let sim = if deterministic {
            builder.deterministic().build()
        } else {
            builder.build()
        };
        sim.run(|| {
            std::env::set_current_dir(cwd).unwrap();
            std::env::set_current_dir(&host_cwd).unwrap();
            assert_eq!(std::env::current_dir().unwrap(), host_cwd);
            std::env::set_current_dir(cwd).unwrap();
            let directory = std::fs::File::open(&host_cwd).unwrap();
            use std::os::fd::AsRawFd;
            assert_eq!(unsafe { libc::fchdir(directory.as_raw_fd()) }, 0);
            assert_eq!(std::env::current_dir().unwrap(), host_cwd);
        });
        assert_eq!(std::env::current_dir().unwrap(), host_cwd);
    }
}
