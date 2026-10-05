//! Linux `/proc/net/snmp` and `/proc/net/snmp6`, rendered from the sim's protocol counters
//! ([`crate::netstats::linux`]) for every Linux sim, with or without a `SimHost` or a
//! `VirtualFs`. [`FsChain`] puts [`ProcNetFs`] in front of whichever file plane the sim has, since
//! a domain takes one [`Fs`].
//!
//! The first read takes a snapshot of the counters and later reads continue in it; a seek that
//! moves back to 0 makes the next read take a fresh one. That is how procfs's `single_open`
//! files behave (fs/seq_file.c: `seq_read` generates the text on the first read and serves the
//! rest from that buffer; `seq_lseek` to a new offset restarts the traversal, 0 regenerating
//! it). Like every procfs file they stat as an empty
//! `0444` regular file (fs/proc/generic.c, `proc_create_net_single`'s entries carry no size).

use std::ffi::{c_char, c_int};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Weak};

use snare_interpose::{Fs, NetResult as FsResult};

use crate::fs_sim::{OpenFiles, descriptor_fcntl, path_of, set_cloexec, status_flags};
use crate::scope::SimShared;
use crate::simhost::{host_stat, host_statx};

/// The open counter files of one sim, each a snapshot and a cursor.
pub(crate) struct ProcNetFs {
    shared: Weak<SimShared>,
    files: Mutex<OpenFiles<OpenFile>>,
    /// A real `/dev/null` descriptor, `dup`ed to mint each file's fd.
    devnull: c_int,
}

/// One open counter file.
struct OpenFile {
    path: PathBuf,
    /// The text, once a read generated it.
    data: Option<Vec<u8>>,
    cursor: usize,
    flags: c_int,
}

/// `0444` regular file (man 7 inode).
const MODE: u32 = 0o100444;

impl ProcNetFs {
    /// The counter files of `shared`.
    pub(crate) fn new(shared: &Arc<SimShared>) -> Self {
        let devnull = snare_interpose::real(|| unsafe {
            libc::open(c"/dev/null".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC)
        });
        ProcNetFs {
            shared: Arc::downgrade(shared),
            files: Mutex::default(),
            devnull,
        }
    }

    /// The text `file` reads, generated now if no read has yet.
    fn text<'a>(&self, file: &'a mut OpenFile) -> &'a [u8] {
        let path = &file.path;
        file.data
            .get_or_insert_with(|| self.render(path).unwrap_or_default())
    }

    /// The text of `path`, or `None` for a path this plane does not serve.
    fn render(&self, path: &Path) -> Option<Vec<u8>> {
        let counters = |shared: Arc<SimShared>| shared.proto_counters();
        match path.to_str()? {
            "/proc/net/snmp" | "/proc/self/net/snmp" => Some(crate::netstats::linux::snmp(
                &counters(self.shared.upgrade()?),
            )),
            "/proc/net/snmp6" | "/proc/self/net/snmp6" => Some(crate::netstats::linux::snmp6(
                &counters(self.shared.upgrade()?),
            )),
            _ => None,
        }
    }
}

/// Ok with a value.
fn ok(v: i64) -> Option<FsResult> {
    Some(FsResult::Ok(v))
}

/// Err with an errno.
fn err(errno: c_int) -> Option<FsResult> {
    Some(FsResult::Err(errno))
}

impl Drop for ProcNetFs {
    fn drop(&mut self) {
        for &fd in self.files.get_mut().unwrap().keys() {
            snare_interpose::real(|| unsafe { libc::close(fd) });
        }
        if self.devnull >= 0 {
            snare_interpose::real(|| unsafe { libc::close(self.devnull) });
        }
    }
}

impl Fs for ProcNetFs {
    fn owns(&self, fd: c_int) -> bool {
        self.files.lock().unwrap().contains_key(&fd)
    }

    /// Opens a counter file read-only; writing is `EACCES`, as for a `0444` procfs file opened
    /// without privilege to override its mode.
    unsafe fn open(&self, path: *const c_char, flags: c_int, _mode: u32) -> Option<FsResult> {
        let path = unsafe { path_of(path) }?;
        self.render(&path)?;
        if flags & (libc::O_WRONLY | libc::O_RDWR) != 0 {
            return err(libc::EACCES);
        }
        let fd = unsafe { libc::dup(self.devnull) };
        if fd < 0 {
            return err(std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EMFILE));
        }
        let file = OpenFile {
            path,
            data: None,
            cursor: 0,
            flags: status_flags(flags),
        };
        self.files.lock().unwrap().insert(fd, file);
        set_cloexec(fd, flags);
        ok(fd as i64)
    }

    /// `open` for an absolute path or one relative to `AT_FDCWD`.
    unsafe fn openat(
        &self,
        dirfd: c_int,
        path: *const c_char,
        flags: c_int,
        mode: u32,
    ) -> Option<FsResult> {
        let absolute = unsafe { path.as_ref() }.is_some_and(|p| *p == b'/' as c_char);
        if dirfd != libc::AT_FDCWD && !absolute {
            return None;
        }
        unsafe { self.open(path, flags, mode) }
    }

    unsafe fn stat(&self, path: *const c_char, buf: *mut u8) -> Option<FsResult> {
        let path = unsafe { path_of(path) }?;
        self.render(&path)?;
        host_stat(buf, &path, MODE, 0, 1)
    }

    unsafe fn lstat(&self, path: *const c_char, buf: *mut u8) -> Option<FsResult> {
        unsafe { self.stat(path, buf) }
    }

    /// `fstatat` of a counter path, or of an open counter file with `AT_EMPTY_PATH`.
    unsafe fn fstatat(
        &self,
        dirfd: c_int,
        path: *const c_char,
        buf: *mut u8,
        _flags: c_int,
    ) -> Option<FsResult> {
        if unsafe { path.as_ref() }.is_some_and(|p| *p == 0) {
            return unsafe { self.fstat(dirfd, buf) };
        }
        unsafe { self.stat(path, buf) }
    }

    unsafe fn statx(
        &self,
        dirfd: c_int,
        path: *const c_char,
        _flags: c_int,
        _mask: u32,
        buf: *mut u8,
    ) -> Option<FsResult> {
        if unsafe { path.as_ref() }.is_some_and(|p| *p == 0) {
            let files = self.files.lock().unwrap();
            let file = files.get(&dirfd)?;
            return host_statx(buf, &file.path, MODE, 0, 1);
        }
        let path = unsafe { path_of(path) }?;
        self.render(&path)?;
        host_statx(buf, &path, MODE, 0, 1)
    }

    /// Readable by anyone, writable by no one (`0444`).
    unsafe fn access(&self, path: *const c_char, mode: c_int) -> Option<FsResult> {
        self.render(&unsafe { path_of(path) }?)?;
        if mode & (libc::W_OK | libc::X_OK) != 0 {
            return err(libc::EACCES);
        }
        ok(0)
    }

    unsafe fn faccessat(
        &self,
        _dirfd: c_int,
        path: *const c_char,
        mode: c_int,
        _flags: c_int,
    ) -> Option<FsResult> {
        unsafe { self.access(path, mode) }
    }

    unsafe fn fstat(&self, fd: c_int, buf: *mut u8) -> Option<FsResult> {
        let files = self.files.lock().unwrap();
        let file = files.get(&fd)?;
        host_stat(buf, &file.path, MODE, 0, 1)
    }

    /// Moves the cursor (man 2 lseek); `EINVAL` for an unknown `whence` or a negative result.
    /// `SEEK_END` counts from the end of the text, generating it if no read has yet. Moving back
    /// to 0 makes the next read take the counters again.
    unsafe fn lseek(&self, fd: c_int, offset: i64, whence: c_int) -> Option<FsResult> {
        let mut files = self.files.lock().unwrap();
        let file = files.get_mut(&fd)?;
        let base = match whence {
            libc::SEEK_SET => 0,
            libc::SEEK_CUR => file.cursor as i64,
            libc::SEEK_END => self.text(file).len() as i64,
            _ => return err(libc::EINVAL),
        };
        let target = base.saturating_add(offset);
        if target < 0 {
            return err(libc::EINVAL);
        }
        if target == 0 && file.cursor != 0 {
            file.data = None;
        }
        file.cursor = target as usize;
        ok(target)
    }

    unsafe fn pread(&self, fd: c_int, buf: *mut u8, len: usize, offset: i64) -> Option<FsResult> {
        let mut files = self.files.lock().unwrap();
        let file = files.get_mut(&fd)?;
        if offset < 0 {
            return err(libc::EINVAL);
        }
        let data = self.text(file);
        let start = (offset as usize).min(data.len());
        let n = len.min(data.len() - start);
        if n != 0 {
            unsafe { std::ptr::copy_nonoverlapping(data[start..].as_ptr(), buf, n) };
        }
        ok(n as i64)
    }

    unsafe fn read(&self, fd: c_int, buf: *mut u8, len: usize) -> Option<FsResult> {
        let mut files = self.files.lock().unwrap();
        let file = files.get_mut(&fd)?;
        if len == 0 {
            return ok(0);
        }
        let cursor = file.cursor;
        let data = self.text(file);
        let start = cursor.min(data.len());
        let n = len.min(data.len() - start);
        if n != 0 {
            unsafe { std::ptr::copy_nonoverlapping(data[start..].as_ptr(), buf, n) };
        }
        file.cursor = cursor + n;
        ok(n as i64)
    }

    unsafe fn write(&self, fd: c_int, _buf: *const u8, _len: usize) -> Option<FsResult> {
        self.owns(fd).then_some(FsResult::Err(libc::EBADF))
    }

    unsafe fn pwrite(
        &self,
        fd: c_int,
        _buf: *const u8,
        _len: usize,
        _offset: i64,
    ) -> Option<FsResult> {
        self.owns(fd).then_some(FsResult::Err(libc::ESPIPE))
    }

    unsafe fn ftruncate(&self, fd: c_int, _len: i64) -> Option<FsResult> {
        self.owns(fd).then_some(FsResult::Err(libc::EINVAL))
    }

    unsafe fn fsync(&self, fd: c_int) -> Option<FsResult> {
        self.owns(fd).then_some(FsResult::Err(libc::EINVAL))
    }

    unsafe fn close(&self, fd: c_int) -> Option<FsResult> {
        self.files.lock().unwrap().remove(&fd)?;
        unsafe { libc::close(fd) };
        ok(0)
    }

    unsafe fn fd_replaced(&self, fd: c_int) -> Option<FsResult> {
        self.files.lock().unwrap().remove(&fd)?;
        ok(0)
    }

    unsafe fn fcntl(&self, fd: c_int, cmd: c_int, arg: i64) -> Option<FsResult> {
        let mut files = self.files.lock().unwrap();
        files.get(&fd)?;
        match cmd {
            libc::F_DUPFD | libc::F_DUPFD_CLOEXEC => {
                let result = descriptor_fcntl(fd, cmd, arg)?;
                if let FsResult::Ok(newfd) = result {
                    files.alias(fd, newfd as c_int);
                }
                Some(result)
            }
            libc::F_GETFD | libc::F_SETFD => descriptor_fcntl(fd, cmd, arg),
            libc::F_GETFL => ok(files.get(&fd)?.flags as i64),
            libc::F_SETFL => {
                let file = files.get_mut(&fd)?;
                let mask = libc::O_APPEND | libc::O_NONBLOCK;
                file.flags = (file.flags & !mask) | (arg as c_int & mask);
                ok(0)
            }
            _ => err(libc::EINVAL),
        }
    }

    unsafe fn dup(&self, oldfd: c_int, newfd: c_int) -> Option<FsResult> {
        self.files.lock().unwrap().alias(oldfd, newfd)?;
        ok(newfd as i64)
    }

    unsafe fn dup_to(&self, oldfd: c_int, newfd: c_int, flags: Option<c_int>) -> Option<FsResult> {
        let mut files = self.files.lock().unwrap();
        files.get(&oldfd)?;
        let result = crate::fabric::duplicate_to(oldfd, newfd, flags);
        if result < 0 {
            return err(std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EBADF));
        }
        files.alias(oldfd, newfd);
        ok(result as i64)
    }
}

/// File planes consulted in order, the first answer winning, so several can serve one domain.
pub(crate) struct FsChain(pub(crate) Vec<Arc<dyn Fs>>);

/// Forwards each call to the planes in order until one answers.
macro_rules! first {
    ($self:ident, |$fs:ident| $call:expr) => {
        $self.0.iter().find_map(|$fs| unsafe { $call })
    };
}

impl Fs for FsChain {
    fn owns(&self, fd: c_int) -> bool {
        self.0.iter().any(|fs| fs.owns(fd))
    }

    fn cwd_path(&self) -> Option<Result<Vec<u8>, c_int>> {
        self.0.iter().find_map(|fs| fs.cwd_path())
    }

    fn cwd_changed(&self) {
        for fs in &self.0 {
            fs.cwd_changed();
        }
    }

    unsafe fn open(&self, path: *const c_char, flags: c_int, mode: u32) -> Option<FsResult> {
        first!(self, |fs| fs.open(path, flags, mode))
    }

    unsafe fn openat(
        &self,
        dirfd: c_int,
        path: *const c_char,
        flags: c_int,
        mode: u32,
    ) -> Option<FsResult> {
        first!(self, |fs| fs.openat(dirfd, path, flags, mode))
    }

    unsafe fn stat(&self, path: *const c_char, buf: *mut u8) -> Option<FsResult> {
        first!(self, |fs| fs.stat(path, buf))
    }

    unsafe fn lstat(&self, path: *const c_char, buf: *mut u8) -> Option<FsResult> {
        first!(self, |fs| fs.lstat(path, buf))
    }

    unsafe fn fstatat(
        &self,
        dirfd: c_int,
        path: *const c_char,
        buf: *mut u8,
        flags: c_int,
    ) -> Option<FsResult> {
        first!(self, |fs| fs.fstatat(dirfd, path, buf, flags))
    }

    unsafe fn statx(
        &self,
        dirfd: c_int,
        path: *const c_char,
        flags: c_int,
        mask: u32,
        buf: *mut u8,
    ) -> Option<FsResult> {
        first!(self, |fs| fs.statx(dirfd, path, flags, mask, buf))
    }

    unsafe fn access(&self, path: *const c_char, mode: c_int) -> Option<FsResult> {
        first!(self, |fs| fs.access(path, mode))
    }

    unsafe fn faccessat(
        &self,
        dirfd: c_int,
        path: *const c_char,
        mode: c_int,
        flags: c_int,
    ) -> Option<FsResult> {
        first!(self, |fs| fs.faccessat(dirfd, path, mode, flags))
    }

    unsafe fn readlink(&self, path: *const c_char, buf: *mut u8, len: usize) -> Option<FsResult> {
        first!(self, |fs| fs.readlink(path, buf, len))
    }

    unsafe fn readlinkat(
        &self,
        dirfd: c_int,
        path: *const c_char,
        buf: *mut u8,
        len: usize,
    ) -> Option<FsResult> {
        first!(self, |fs| fs.readlinkat(dirfd, path, buf, len))
    }

    unsafe fn symlink(&self, target: *const c_char, link: *const c_char) -> Option<FsResult> {
        first!(self, |fs| fs.symlink(target, link))
    }

    unsafe fn symlinkat(
        &self,
        target: *const c_char,
        dirfd: c_int,
        link: *const c_char,
    ) -> Option<FsResult> {
        first!(self, |fs| fs.symlinkat(target, dirfd, link))
    }

    unsafe fn chdir(&self, path: *const c_char) -> Option<FsResult> {
        for (index, fs) in self.0.iter().enumerate() {
            if let Some(result) = unsafe { fs.chdir(path) } {
                if matches!(result, FsResult::Ok(_)) {
                    for other in self
                        .0
                        .iter()
                        .enumerate()
                        .filter(|(other, _)| *other != index)
                    {
                        other.1.cwd_changed();
                    }
                }
                return Some(result);
            }
        }
        None
    }

    unsafe fn fchdir(&self, fd: c_int) -> Option<FsResult> {
        for (index, fs) in self.0.iter().enumerate() {
            if let Some(result) = unsafe { fs.fchdir(fd) } {
                if matches!(result, FsResult::Ok(_)) {
                    for other in self
                        .0
                        .iter()
                        .enumerate()
                        .filter(|(other, _)| *other != index)
                    {
                        other.1.cwd_changed();
                    }
                }
                return Some(result);
            }
        }
        None
    }

    unsafe fn getcwd(&self, buf: *mut c_char, len: usize) -> Option<FsResult> {
        first!(self, |fs| fs.getcwd(buf, len))
    }

    unsafe fn unlink(&self, path: *const c_char) -> Option<FsResult> {
        first!(self, |fs| fs.unlink(path))
    }

    unsafe fn unlinkat(&self, fd: c_int, path: *const c_char, flags: c_int) -> Option<FsResult> {
        first!(self, |fs| fs.unlinkat(fd, path, flags))
    }

    unsafe fn rmdir(&self, path: *const c_char) -> Option<FsResult> {
        first!(self, |fs| fs.rmdir(path))
    }

    unsafe fn mkdir(&self, path: *const c_char, mode: u32) -> Option<FsResult> {
        first!(self, |fs| fs.mkdir(path, mode))
    }

    unsafe fn mkdirat(&self, fd: c_int, path: *const c_char, mode: u32) -> Option<FsResult> {
        first!(self, |fs| fs.mkdirat(fd, path, mode))
    }

    unsafe fn rename(&self, from: *const c_char, to: *const c_char) -> Option<FsResult> {
        first!(self, |fs| fs.rename(from, to))
    }

    unsafe fn renameat(
        &self,
        fromfd: c_int,
        from: *const c_char,
        tofd: c_int,
        to: *const c_char,
    ) -> Option<FsResult> {
        first!(self, |fs| fs.renameat(fromfd, from, tofd, to))
    }

    unsafe fn realpath(&self, path: *const c_char, resolved: *mut c_char) -> Option<FsResult> {
        first!(self, |fs| fs.realpath(path, resolved))
    }

    unsafe fn link(&self, from: *const c_char, to: *const c_char) -> Option<FsResult> {
        first!(self, |fs| fs.link(from, to))
    }

    unsafe fn linkat(
        &self,
        fromfd: c_int,
        from: *const c_char,
        tofd: c_int,
        to: *const c_char,
        flags: c_int,
    ) -> Option<FsResult> {
        first!(self, |fs| fs.linkat(fromfd, from, tofd, to, flags))
    }

    unsafe fn statfs(&self, path: *const c_char, buf: *mut u8) -> Option<FsResult> {
        first!(self, |fs| fs.statfs(path, buf))
    }

    unsafe fn fstatfs(&self, fd: c_int, buf: *mut u8) -> Option<FsResult> {
        first!(self, |fs| fs.fstatfs(fd, buf))
    }

    unsafe fn fstat(&self, fd: c_int, buf: *mut u8) -> Option<FsResult> {
        first!(self, |fs| fs.fstat(fd, buf))
    }

    unsafe fn lseek(&self, fd: c_int, offset: i64, whence: c_int) -> Option<FsResult> {
        first!(self, |fs| fs.lseek(fd, offset, whence))
    }

    unsafe fn pread(&self, fd: c_int, buf: *mut u8, len: usize, offset: i64) -> Option<FsResult> {
        first!(self, |fs| fs.pread(fd, buf, len, offset))
    }

    unsafe fn pwrite(
        &self,
        fd: c_int,
        buf: *const u8,
        len: usize,
        offset: i64,
    ) -> Option<FsResult> {
        first!(self, |fs| fs.pwrite(fd, buf, len, offset))
    }

    unsafe fn ftruncate(&self, fd: c_int, len: i64) -> Option<FsResult> {
        first!(self, |fs| fs.ftruncate(fd, len))
    }

    unsafe fn fsync(&self, fd: c_int) -> Option<FsResult> {
        first!(self, |fs| fs.fsync(fd))
    }

    unsafe fn getdents64(&self, fd: c_int, buf: *mut u8, len: usize) -> Option<FsResult> {
        first!(self, |fs| fs.getdents64(fd, buf, len))
    }

    unsafe fn opendir(&self, path: *const c_char) -> Option<FsResult> {
        first!(self, |fs| fs.opendir(path))
    }

    unsafe fn fdopendir(&self, fd: c_int) -> Option<FsResult> {
        first!(self, |fs| fs.fdopendir(fd))
    }

    unsafe fn readdir(&self, fd: c_int) -> Option<FsResult> {
        first!(self, |fs| fs.readdir(fd))
    }

    unsafe fn readdir_r(
        &self,
        fd: c_int,
        entry: *mut u8,
        result: *mut *mut u8,
    ) -> Option<FsResult> {
        first!(self, |fs| fs.readdir_r(fd, entry, result))
    }

    unsafe fn closedir(&self, fd: c_int) -> Option<FsResult> {
        first!(self, |fs| fs.closedir(fd))
    }

    unsafe fn read(&self, fd: c_int, buf: *mut u8, len: usize) -> Option<FsResult> {
        first!(self, |fs| fs.read(fd, buf, len))
    }

    unsafe fn write(&self, fd: c_int, buf: *const u8, len: usize) -> Option<FsResult> {
        first!(self, |fs| fs.write(fd, buf, len))
    }

    unsafe fn close(&self, fd: c_int) -> Option<FsResult> {
        first!(self, |fs| fs.close(fd))
    }

    unsafe fn fcntl(&self, fd: c_int, cmd: c_int, arg: i64) -> Option<FsResult> {
        first!(self, |fs| fs.fcntl(fd, cmd, arg))
    }

    unsafe fn ioctl(&self, fd: c_int, request: u64, arg: i64) -> Option<FsResult> {
        first!(self, |fs| fs.ioctl(fd, request, arg))
    }

    unsafe fn fd_replaced(&self, fd: c_int) -> Option<FsResult> {
        first!(self, |fs| fs.fd_replaced(fd))
    }

    unsafe fn dup(&self, oldfd: c_int, newfd: c_int) -> Option<FsResult> {
        first!(self, |fs| fs.dup(oldfd, newfd))
    }

    unsafe fn dup_to(&self, oldfd: c_int, newfd: c_int, flags: Option<c_int>) -> Option<FsResult> {
        let source = self.0.iter().position(|fs| fs.owns(oldfd))?;
        let target = self.0.iter().position(|fs| fs.owns(newfd));
        let result = unsafe { self.0[source].dup_to(oldfd, newfd, flags) }?;
        if matches!(result, FsResult::Ok(_))
            && oldfd != newfd
            && let Some(target) = target.filter(|target| *target != source)
        {
            unsafe { self.0[target].fd_replaced(newfd) };
        }
        Some(result)
    }
}
