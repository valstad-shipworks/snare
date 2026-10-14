//! The memory a virtual file is mapped from.
//!
//! `mmap(2)` maps a descriptor's file, never a process's own memory, so the first mapping of a
//! virtual file moves its bytes into a real shared memory object the harness owns: an anonymous
//! `memfd_create(2)` file on Linux, and on macOS, which has none (and whose POSIX `shm_open`
//! objects can be sized only once), an unlinked file in the per-user temporary directory. From
//! then on the plane reads, writes and truncates the object, and every mapping maps it, so the
//! mappings of one file share pages with each other and with `read`, `write` and `ftruncate`, a
//! `MAP_PRIVATE` mapping copies on write, and touching a page wholly past the end of the file
//! raises `SIGBUS` (man 2 mmap, "Use of a mapped region can result in these signals"), all by the
//! host's own rules.
//!
//! A mapping is made from a descriptor of the object opened with the virtual descriptor's access
//! mode, so `mmap` fails as the host's does for a descriptor of that mode (`EACCES` for a shared
//! writable mapping of a read-only descriptor, or any mapping of a write-only one on Linux), and so
//! does a later `mprotect` adding `PROT_WRITE` to a shared read-only mapping. A directory is mapped
//! from a real directory descriptor, for the host's `ENODEV` (Linux) or `EINVAL` (macOS) after its
//! own argument checks.
//!
//! The object's modification time tells the plane when a mapping wrote it: Linux moves it when a
//! write faults a page in, macOS when `msync` or the pager writes the page back, and the plane
//! stamps the virtual file at the sim's time of the first `stat` after. A page that a shared
//! writable mapping first fills counts as allocated from then on too, once a `stat` or `statfs`
//! finds data in it; the storage limit cannot refuse it, as a full disk would with `SIGBUS`.

use std::ffi::c_int;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicI32, Ordering};

use crate::fs_sim::last_error;

/// The page granularity [`crate::fs_sim`] allocates storage in.
const PAGE: usize = 4096;

/// A virtual file's bytes in a real shared memory object.
pub(crate) struct Backing {
    /// The object opened read-only, write-only and read-write, indexed by `O_ACCMODE`.
    fds: [OwnedFd; 3],
    /// The object's modification and change times when the plane last wrote it.
    seen: [i64; 4],
    /// Page index ranges `[start, end)` that a shared mapping of a writable descriptor covered.
    exposed: Vec<(usize, usize)>,
}

impl Backing {
    /// An object holding `length` bytes, with `pages` (index and bytes) written in.
    pub(crate) fn new<'a>(
        length: usize,
        pages: impl Iterator<Item = (usize, &'a [u8])>,
    ) -> Result<Self, c_int> {
        let fds = snare_interpose::real(create)?;
        let mut backing = Self {
            fds,
            seen: [0; 4],
            exposed: Vec::new(),
        };
        backing.truncate(length)?;
        for (index, bytes) in pages {
            let start = index * PAGE;
            let end = length.min(start + bytes.len());
            if start < end {
                backing.put(start, &bytes[..end - start])?;
            }
        }
        backing.seen = backing.times();
        Ok(backing)
    }

    /// The descriptor a mapping through a descriptor opened with `flags` maps.
    pub(crate) fn fd(&self, flags: c_int) -> c_int {
        let mode = match flags & libc::O_ACCMODE {
            libc::O_WRONLY => 1,
            libc::O_RDWR => 2,
            _ => 0,
        };
        self.fds[mode].as_raw_fd()
    }

    fn rw(&self) -> c_int {
        self.fds[2].as_raw_fd()
    }

    /// Notes that a shared mapping of a writable descriptor covers `len` bytes from `offset`.
    pub(crate) fn expose(&mut self, offset: u64, len: usize) {
        let start = (offset / PAGE as u64) as usize;
        let end = (offset as usize).saturating_add(len).div_ceil(PAGE);
        self.exposed.push((start, end));
        self.exposed.sort_unstable();
        let mut merged: Vec<(usize, usize)> = Vec::with_capacity(self.exposed.len());
        for &(start, end) in &self.exposed {
            match merged.last_mut() {
                Some(last) if start <= last.1 => last.1 = last.1.max(end),
                _ => merged.push((start, end)),
            }
        }
        self.exposed = merged;
    }

    /// The exposed page indices below `end`.
    pub(crate) fn exposed(&self, end: usize) -> impl Iterator<Item = usize> + '_ {
        self.exposed
            .iter()
            .flat_map(move |&(start, stop)| start.min(end)..stop.min(end))
    }

    /// Reads `count` bytes from `start` into `buf`.
    ///
    /// # Safety
    /// `buf` must be writable for `count` bytes.
    pub(crate) unsafe fn read(
        &self,
        start: usize,
        buf: *mut u8,
        count: usize,
    ) -> Result<usize, c_int> {
        let mut done = 0;
        while done < count {
            let n = snare_interpose::real(|| unsafe {
                libc::pread(
                    self.rw(),
                    buf.add(done).cast(),
                    count - done,
                    (start + done) as libc::off_t,
                )
            });
            match n {
                0 => break,
                n if n > 0 => done += n as usize,
                _ if last_error() == libc::EINTR => {}
                _ if done > 0 => break,
                _ => return Err(last_error()),
            }
        }
        Ok(done)
    }

    /// Writes `bytes` at `start`, extending the object as needed; the count written.
    pub(crate) fn write(&mut self, start: usize, bytes: &[u8]) -> Result<usize, c_int> {
        let written = self.put(start, bytes);
        self.seen = self.times();
        written
    }

    /// Sets the object's length, zero-filling growth and discarding what a shrink cuts off.
    pub(crate) fn resize(&mut self, length: usize) -> Result<(), c_int> {
        let result = self.truncate(length);
        self.seen = self.times();
        result
    }

    /// Whether the object's times moved since the plane last wrote it: a mapping wrote it.
    pub(crate) fn written_through_mapping(&mut self) -> bool {
        let now = self.times();
        let moved = now != self.seen;
        self.seen = now;
        moved
    }

    /// Whether page `index` of a file `length` bytes long holds any nonzero byte.
    pub(crate) fn page_has_data(&self, index: usize, length: usize) -> bool {
        let mut page = [0u8; PAGE];
        let count = PAGE.min(length.saturating_sub(index * PAGE));
        unsafe { self.read(index * PAGE, page.as_mut_ptr(), count) }
            .is_ok_and(|n| page[..n].iter().any(|&byte| byte != 0))
    }

    fn put(&self, start: usize, bytes: &[u8]) -> Result<usize, c_int> {
        let mut done = 0;
        while done < bytes.len() {
            let n = snare_interpose::real(|| unsafe {
                libc::pwrite(
                    self.rw(),
                    bytes[done..].as_ptr().cast(),
                    bytes.len() - done,
                    (start + done) as libc::off_t,
                )
            });
            match n {
                n if n > 0 => done += n as usize,
                n if n < 0 && last_error() == libc::EINTR => {}
                _ if done > 0 => break,
                0 => return Err(libc::ENOSPC),
                _ => return Err(last_error()),
            }
        }
        Ok(done)
    }

    fn truncate(&self, length: usize) -> Result<(), c_int> {
        let result =
            snare_interpose::real(|| unsafe { libc::ftruncate(self.rw(), length as libc::off_t) });
        if result < 0 {
            Err(last_error())
        } else {
            Ok(())
        }
    }

    fn times(&self) -> [i64; 4] {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if snare_interpose::real(|| unsafe { libc::fstat(self.rw(), &mut st) }) < 0 {
            return self.seen;
        }
        [st.st_mtime, st.st_mtime_nsec, st.st_ctime, st.st_ctime_nsec]
    }
}

fn opened(fd: c_int) -> Result<OwnedFd, c_int> {
    if fd < 0 {
        Err(last_error())
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

/// A fresh `memfd`, reopened through `/proc/self/fd` for the other access modes.
#[cfg(target_os = "linux")]
fn create() -> Result<[OwnedFd; 3], c_int> {
    let name = c"snare-mapped";
    // Linux 6.3 may make a memfd created without `MFD_EXEC` unmappable for `PROT_EXEC`
    // (`vm.memfd_noexec`), which a file on disk allows; earlier kernels reject the flag.
    let mut fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_EXEC) };
    if fd < 0 && last_error() == libc::EINVAL {
        fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) };
    }
    let rw = opened(fd)?;
    let path = std::ffi::CString::new(format!("/proc/self/fd/{fd}")).unwrap();
    let reopen = |mode| opened(unsafe { libc::open(path.as_ptr(), mode | libc::O_CLOEXEC) });
    Ok([reopen(libc::O_RDONLY)?, reopen(libc::O_WRONLY)?, rw])
}

/// A fresh file in the per-user temporary directory (`confstr(3)`
/// `_CS_DARWIN_USER_TEMP_DIR`), opened in each access mode and unlinked.
#[cfg(target_os = "macos")]
fn create() -> Result<[OwnedFd; 3], c_int> {
    let mut dir = [0 as std::ffi::c_char; libc::PATH_MAX as usize];
    let n = unsafe { libc::confstr(libc::_CS_DARWIN_USER_TEMP_DIR, dir.as_mut_ptr(), dir.len()) };
    let mut template = if n == 0 || n > dir.len() {
        b"/tmp".to_vec()
    } else {
        unsafe { std::ffi::CStr::from_ptr(dir.as_ptr()) }
            .to_bytes()
            .to_vec()
    };
    if !template.ends_with(b"/") {
        template.push(b'/');
    }
    template.extend_from_slice(b"snare-mapped-XXXXXX\0");
    let rw = opened(unsafe { libc::mkstemp(template.as_mut_ptr().cast()) })?;
    let path = template.as_ptr().cast();
    let read_only = opened(unsafe { libc::open(path, libc::O_RDONLY | libc::O_CLOEXEC) });
    let write_only = opened(unsafe { libc::open(path, libc::O_WRONLY | libc::O_CLOEXEC) });
    unsafe {
        libc::unlink(path);
        libc::fcntl(rw.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC);
    }
    Ok([read_only?, write_only?, rw])
}

/// A real directory descriptor, opened once for the process, that a mapping of a virtual
/// directory maps; -1 if it could not be opened.
pub(crate) fn directory() -> c_int {
    static DIRECTORY: AtomicI32 = AtomicI32::new(-1);
    let fd = DIRECTORY.load(Ordering::Acquire);
    if fd >= 0 {
        return fd;
    }
    let fd = snare_interpose::real(|| unsafe {
        libc::open(
            c"/".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    });
    match DIRECTORY.compare_exchange(-1, fd, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => fd,
        Err(existing) => {
            if fd >= 0 {
                snare_interpose::real(|| unsafe { libc::close(fd) });
            }
            existing
        }
    }
}
