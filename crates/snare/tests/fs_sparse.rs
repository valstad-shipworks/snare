#![cfg(unix)]

use std::ffi::CString;
use std::fs::OpenOptions;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::Path;

use snare::{FsBuilder, Sim};

fn sparse_changes(path: &Path) -> (Vec<u64>, Vec<u8>) {
    let file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    let length = 1u64 << 36;
    let position = (1u64 << 35) + 7;
    file.set_len(length).unwrap();
    let mut sizes = vec![file.metadata().unwrap().len()];
    file.write_at(b"value", position).unwrap();
    let mut hole = [1; 16];
    assert_eq!(file.read_at(&mut hole, position - 16).unwrap(), 16);
    assert_eq!(hole, [0; 16]);
    let mut bytes = [0; 5];
    assert_eq!(file.read_at(&mut bytes, position).unwrap(), 5);
    sizes.push(file.metadata().unwrap().len());
    assert!(file.metadata().unwrap().blocks() < length / 512);
    file.set_len(100).unwrap();
    file.set_len(length).unwrap();
    let mut cleared = [1; 5];
    assert_eq!(file.read_at(&mut cleared, position).unwrap(), 5);
    assert_eq!(cleared, [0; 5]);
    sizes.push(file.metadata().unwrap().len());
    (sizes, bytes.to_vec())
}

#[test]
fn sparse_growth_and_shrink_preserve_holes_os_truth() {
    let root = std::env::temp_dir().join(format!("snare-sparse-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    let path = root.join("file");
    let native = sparse_changes(&path);
    std::fs::remove_dir_all(&root).unwrap();
    let fs = FsBuilder::new()
        .dir(&root)
        .own_prefix(&root)
        .storage_limit(8192)
        .build();
    assert_eq!(
        Sim::builder().fs(fs).build().run(|| sparse_changes(&path)),
        native
    );
    assert!(!path.exists());
}

fn space(fd: libc::c_int) -> (u64, u64, u64) {
    unsafe {
        let mut stat: libc::statfs = std::mem::zeroed();
        assert_eq!(libc::fstatfs(fd, &mut stat), 0);
        (
            stat.f_bsize as u64,
            stat.f_blocks as u64,
            stat.f_bfree as u64,
        )
    }
}

#[test]
fn storage_limits_count_allocated_pages_and_last_inode_reference() {
    let path = "/snare-storage-limits";
    let fs = FsBuilder::new()
        .dir(path)
        .own_prefix(path)
        .storage_limit(8192)
        .build();
    Sim::builder().fs(fs).build().run(|| {
        let file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(format!("{path}/file"))
            .unwrap();
        assert_eq!(space(file.as_raw_fd()), (4096, 2, 2));
        assert_eq!(file.write_at(&[7; 12288], 0).unwrap(), 8192);
        assert_eq!(file.metadata().unwrap().len(), 8192);
        assert_eq!(space(file.as_raw_fd()), (4096, 2, 0));
        assert_eq!(
            file.write_at(b"x", 1 << 35).unwrap_err().raw_os_error(),
            Some(libc::ENOSPC)
        );
        file.set_len(4096).unwrap();
        assert_eq!(space(file.as_raw_fd()), (4096, 2, 1));
        assert_eq!(file.write_at(b"x", 1 << 35).unwrap(), 1);
        assert_eq!(space(file.as_raw_fd()), (4096, 2, 0));
        let alias = file.try_clone().unwrap();
        std::fs::remove_file(format!("{path}/file")).unwrap();
        drop(file);
        assert_eq!(space(alias.as_raw_fd()), (4096, 2, 0));
        drop(alias);
        let raw = CString::new(path).unwrap();
        unsafe {
            let mut stat: libc::statfs = std::mem::zeroed();
            assert_eq!(libc::statfs(raw.as_ptr(), &mut stat), 0);
            assert_eq!(stat.f_bfree as u64, 2);
            assert_eq!(libc::statfs(raw.as_ptr(), std::ptr::null_mut()), -1);
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EFAULT)
            );
        }
    });
}

/// A mapped file keeps its accounting: pages written through `pwrite` are allocated as before, a
/// page a shared mapping first fills counts once a `stat` or `statfs` finds data in it, past the
/// storage limit if need be (a full disk would raise `SIGBUS` instead), and truncation frees them.
#[test]
fn pages_a_shared_mapping_fills_count_as_allocated() {
    let path = "/snare-mapped-pages";
    let fs = FsBuilder::new()
        .dir(path)
        .own_prefix(path)
        .storage_limit(3 * 4096)
        .build();
    Sim::builder().fs(fs).build().run(|| {
        let file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(format!("{path}/file"))
            .unwrap();
        let fd = file.as_raw_fd();
        let len = 8 * 4096;
        file.set_len(len as u64).unwrap();
        file.write_at(b"a", 0).unwrap();
        assert_eq!(file.metadata().unwrap().blocks(), 8);
        let map = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        assert_ne!(map, libc::MAP_FAILED);
        let bytes = map.cast::<u8>();
        unsafe {
            assert_eq!(bytes.read_volatile(), b'a');
            bytes.add(2 * 4096 + 5).write_volatile(b'b');
            bytes.add(3 * 4096).write_volatile(0);
        }
        assert_eq!(file.metadata().unwrap().blocks(), 16);
        assert_eq!(space(fd), (4096, 3, 1));
        file.write_at(b"c", 4 * 4096).unwrap();
        unsafe { bytes.add(5 * 4096).write_volatile(b'd') };
        assert_eq!(space(fd), (4096, 3, 0));
        assert_eq!(file.metadata().unwrap().blocks(), 32);
        assert_eq!(unsafe { libc::munmap(map, len) }, 0);
        let mut back = [0; 1];
        assert_eq!(file.read_at(&mut back, 2 * 4096 + 5).unwrap(), 1);
        assert_eq!(back, *b"b");
        file.set_len(4096).unwrap();
        assert_eq!(file.metadata().unwrap().blocks(), 8);
        assert_eq!(space(fd), (4096, 3, 2));
    });
}
