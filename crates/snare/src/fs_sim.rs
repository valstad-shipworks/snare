//! An in-memory file system behind [`snare_interpose::Fs`]. The code under test uses ordinary
//! `std::fs` / `open`; declared paths are served from process memory, and glob passthrough lets
//! specific real paths reach the OS.
//!
//! Every hook returns `None` to decline (the call goes on to the real OS) or `Some` with the
//! result. A path is decided in a fixed order: a `deny` glob fails it with `EACCES`; a
//! `passthrough` glob declines it; a declared node is served; an undeclared path under an owned
//! prefix fails with `ENOENT`; anything else is declined. Relative paths use the virtual working
//! directory when one is selected, otherwise the process working directory. Owned directory
//! descriptors resolve relative paths against their live inode. Symlinks resolve within this
//! plane; targets escaping its namespace are rejected with `EXDEV`.
//!
//! An open virtual file holds a real fd, a `dup` of one `/dev/null` descriptor, so the number is
//! unique process-wide, `close` on it is safe, and any call the backend does not model degrades to
//! `/dev/null` behaviour instead of hitting someone else's fd. Opens of one file share its
//! contents. Each open-file description has its own offset and status flags; descriptor aliases
//! share the description.
//!
//! Locks: `tree` is never held together with `open` or `dirs`; `open` precedes `dirs` when both
//! tables are needed. File contents are locked after either table. Locks are plain `std`
//! mutexes; the backend runs inside the interposer's hook, where they are the real OS primitives.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::ffi::{CStr, CString, OsStr, c_char, c_int};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use glob::Pattern;
use snare_interpose::{Fs, NetResult as FsResult};

pub(crate) struct OpenFiles<T> {
    handles: HashMap<c_int, u64>,
    descriptions: HashMap<u64, (usize, T)>,
    next: u64,
}

impl<T> Default for OpenFiles<T> {
    fn default() -> Self {
        Self {
            handles: HashMap::new(),
            descriptions: HashMap::new(),
            next: 0,
        }
    }
}

impl<T> OpenFiles<T> {
    pub(crate) fn contains_key(&self, fd: &c_int) -> bool {
        self.handles.contains_key(fd)
    }
    pub(crate) fn get(&self, fd: &c_int) -> Option<&T> {
        self.descriptions
            .get(self.handles.get(fd)?)
            .map(|(_, value)| value)
    }
    pub(crate) fn get_mut(&mut self, fd: &c_int) -> Option<&mut T> {
        self.descriptions
            .get_mut(self.handles.get(fd)?)
            .map(|(_, value)| value)
    }
    pub(crate) fn keys(&self) -> impl Iterator<Item = &c_int> {
        self.handles.keys()
    }
    pub(crate) fn insert(&mut self, fd: c_int, value: T) {
        self.remove(&fd);
        let id = self.next;
        self.next += 1;
        self.descriptions.insert(id, (1, value));
        self.handles.insert(fd, id);
    }
    pub(crate) fn remove(&mut self, fd: &c_int) -> Option<Option<T>> {
        let id = self.handles.remove(fd)?;
        let (refs, _) = self.descriptions.get_mut(&id).unwrap();
        *refs -= 1;
        Some(if *refs == 0 {
            self.descriptions.remove(&id).map(|(_, value)| value)
        } else {
            None
        })
    }
    pub(crate) fn alias(&mut self, oldfd: c_int, newfd: c_int) -> Option<Option<T>> {
        let id = *self.handles.get(&oldfd)?;
        if oldfd == newfd {
            return Some(None);
        }
        let released = self.remove(&newfd).flatten();
        self.descriptions.get_mut(&id).unwrap().0 += 1;
        self.handles.insert(newfd, id);
        Some(released)
    }
}

pub(crate) fn status_flags(flags: c_int) -> c_int {
    flags & !(libc::O_CLOEXEC | libc::O_CREAT | libc::O_EXCL | libc::O_TRUNC | libc::O_NOCTTY)
}

pub(crate) fn set_cloexec(fd: c_int, flags: c_int) {
    if flags & libc::O_CLOEXEC != 0 {
        snare_interpose::real(|| unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) });
    }
}

pub(crate) fn descriptor_fcntl(fd: c_int, cmd: c_int, arg: i64) -> Option<FsResult> {
    let result = snare_interpose::real(|| unsafe { libc::fcntl(fd, cmd, arg as c_int) });
    if result < 0 {
        err(std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EINVAL))
    } else {
        ok(result as i64)
    }
}

/// One declared node of the tree. Permissions use fixed mode bits.
#[derive(Clone)]
enum VNode {
    File(Arc<VInode>),
    Dir(Arc<VInode>),
    Symlink(Arc<VInode>, Arc<Vec<u8>>),
}

struct VInode {
    number: u64,
    data: Mutex<SparseFile>,
    links: AtomicU64,
}

const PAGE_SIZE: usize = 4096;

struct Volume {
    capacity: u64,
    used: AtomicU64,
    files: AtomicU64,
}

impl Volume {
    #[allow(deprecated)]
    fn reserve(&self) -> bool {
        self.used
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                (used < self.capacity).then_some(used + 1)
            })
            .is_ok()
    }
}

struct SparseFile {
    pages: HashMap<usize, Box<[u8]>>,
    length: usize,
    volume: Option<Arc<Volume>>,
}

impl SparseFile {
    fn new(bytes: Vec<u8>) -> Self {
        let mut pages = HashMap::new();
        for (index, chunk) in bytes.chunks(PAGE_SIZE).enumerate() {
            let mut page = vec![0; PAGE_SIZE].into_boxed_slice();
            page[..chunk.len()].copy_from_slice(chunk);
            pages.insert(index, page);
        }
        Self {
            pages,
            length: bytes.len(),
            volume: None,
        }
    }

    fn attach(&mut self, volume: &Arc<Volume>) {
        assert!(self.volume.is_none());
        let allocated = self.pages.len() as u64;
        let previous = volume.used.fetch_add(allocated, Ordering::AcqRel);
        assert!(
            previous + allocated <= volume.capacity,
            "declared files exceed the storage limit"
        );
        volume.files.fetch_add(1, Ordering::AcqRel);
        self.volume = Some(volume.clone());
    }

    fn len(&self) -> usize {
        self.length
    }

    fn clear(&mut self) {
        self.resize(0);
    }

    fn resize(&mut self, length: usize) {
        let before = self.pages.len();
        self.pages
            .retain(|index, _| *index < length.div_ceil(PAGE_SIZE));
        if let Some(page) = self.pages.get_mut(&(length / PAGE_SIZE)) {
            page[length % PAGE_SIZE..].fill(0);
        }
        if let Some(volume) = &self.volume {
            volume
                .used
                .fetch_sub((before - self.pages.len()) as u64, Ordering::AcqRel);
        }
        self.length = length;
    }

    unsafe fn read(&self, start: usize, buf: *mut u8, len: usize) -> usize {
        let count = len.min(self.length.saturating_sub(start));
        let mut read = 0;
        while read < count {
            let offset = start + read;
            let within = offset % PAGE_SIZE;
            let n = (PAGE_SIZE - within).min(count - read);
            unsafe {
                if let Some(page) = self.pages.get(&(offset / PAGE_SIZE)) {
                    std::ptr::copy_nonoverlapping(page.as_ptr().add(within), buf.add(read), n);
                } else {
                    buf.add(read).write_bytes(0, n);
                }
            }
            read += n;
        }
        count
    }

    fn write(&mut self, start: usize, bytes: &[u8]) -> Result<usize, c_int> {
        if start
            .checked_add(bytes.len())
            .is_none_or(|end| end > i64::MAX as usize)
        {
            return Err(libc::EFBIG);
        }
        let mut written = 0;
        while written < bytes.len() {
            let offset = start + written;
            let index = offset / PAGE_SIZE;
            if !self.pages.contains_key(&index) {
                let error = if self.volume.as_ref().is_some_and(|volume| !volume.reserve()) {
                    Some(libc::ENOSPC)
                } else {
                    let mut page = Vec::new();
                    if page.try_reserve_exact(PAGE_SIZE).is_err()
                        || self.pages.try_reserve(1).is_err()
                    {
                        if let Some(volume) = &self.volume {
                            volume.used.fetch_sub(1, Ordering::AcqRel);
                        }
                        Some(libc::ENOMEM)
                    } else {
                        page.resize(PAGE_SIZE, 0);
                        self.pages.insert(index, page.into_boxed_slice());
                        None
                    }
                };
                if let Some(error) = error {
                    return if written == 0 {
                        Err(error)
                    } else {
                        Ok(written)
                    };
                }
            }
            let within = offset % PAGE_SIZE;
            let count = (PAGE_SIZE - within).min(bytes.len() - written);
            self.pages.get_mut(&index).unwrap()[within..within + count]
                .copy_from_slice(&bytes[written..written + count]);
            written += count;
            self.length = self.length.max(start + written);
        }
        Ok(written)
    }
}

impl Drop for SparseFile {
    fn drop(&mut self) {
        if let Some(volume) = &self.volume {
            volume
                .used
                .fetch_sub(self.pages.len() as u64, Ordering::AcqRel);
            volume.files.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

impl VInode {
    fn new(number: u64, data: Vec<u8>, directory: bool) -> Arc<Self> {
        Arc::new(Self {
            number,
            data: Mutex::new(SparseFile::new(data)),
            links: AtomicU64::new(if directory { 2 } else { 1 }),
        })
    }
}

impl VNode {
    fn inode(&self) -> &Arc<VInode> {
        match self {
            Self::File(inode) | Self::Dir(inode) | Self::Symlink(inode, _) => inode,
        }
    }
}

/// A virtual open-file description shared by its descriptor aliases.
struct OpenFile {
    inode: Arc<VInode>,
    /// The file offset; may sit past the end after `lseek` (a later write zero-fills the gap, as
    /// man 2 lseek describes for holes).
    cursor: usize,
    /// Opened `O_WRONLY` or `O_RDWR`.
    writable: bool,
    append: bool,
    flags: c_int,
    /// A directory opened with `open` rather than `opendir`: `fstat` reports it, `read` fails.
    is_dir: bool,
    directory: Option<Arc<Mutex<DirStream>>>,
}

/// Builds a [`VirtualFs`]: declare virtual files and directories, the prefixes it owns, and glob
/// patterns to pass through to (or deny at) the real OS.
#[derive(Default)]
pub struct FsBuilder {
    /// Declared nodes by normalized absolute path; ordered so a directory listing is sorted.
    tree: BTreeMap<PathBuf, VNode>,
    next_inode: u64,
    owned_prefixes: Vec<PathBuf>,
    passthrough: Vec<Pattern>,
    deny: Vec<Pattern>,
    storage_limit: Option<u64>,
}

impl FsBuilder {
    /// An empty builder: no nodes, no owned prefixes, every path passes to the real OS.
    pub fn new() -> Self {
        Self::default()
    }

    /// Limits allocated file pages, rounded down to 4096-byte pages. Holes consume no pages.
    /// The default is 1 GiB; declared initial contents must fit this limit.
    pub fn storage_limit(mut self, bytes: u64) -> Self {
        self.storage_limit = Some(bytes);
        self
    }

    /// Adds a virtual file with `contents`, creating its parent directories.
    pub fn file(mut self, path: impl AsRef<Path>, contents: impl Into<Vec<u8>>) -> Self {
        let path = normalize(path.as_ref());
        let mut dir = path.clone();
        while dir.pop() {
            if !self.tree.contains_key(&dir) {
                let inode = self.inode(Vec::new(), true);
                self.tree.insert(dir.clone(), VNode::Dir(inode));
            }
        }
        let inode = self.inode(contents.into(), false);
        self.tree.insert(path, VNode::File(inode));
        self
    }

    /// Adds a virtual directory. Unlike [`file`](Self::file) it does not create the parents, so
    /// declare those too if a listing of them should show it.
    pub fn dir(mut self, path: impl AsRef<Path>) -> Self {
        let inode = self.inode(Vec::new(), true);
        self.tree
            .insert(normalize(path.as_ref()), VNode::Dir(inode));
        self
    }

    /// Adds a symbolic link at `path`, storing `target` unchanged.
    pub fn symlink(mut self, path: impl AsRef<Path>, target: impl AsRef<Path>) -> Self {
        let path = normalize(path.as_ref());
        let mut parent = path.clone();
        while parent.pop() {
            if !self.tree.contains_key(&parent) {
                let inode = self.inode(Vec::new(), true);
                self.tree.insert(parent.clone(), VNode::Dir(inode));
            }
        }
        let inode = self.inode(Vec::new(), false);
        self.tree.insert(
            path,
            VNode::Symlink(
                inode,
                Arc::new(target.as_ref().as_os_str().as_bytes().to_vec()),
            ),
        );
        self
    }

    /// Marks a path prefix as owned: an undeclared path under it fails with `ENOENT` rather than
    /// reaching the real OS (default-deny within owned prefixes).
    pub fn own_prefix(mut self, path: impl AsRef<Path>) -> Self {
        self.owned_prefixes.push(normalize(path.as_ref()));
        self
    }

    /// A glob whose matching paths are passed through to the real OS, even under an owned prefix
    /// and even if declared. An invalid pattern is ignored.
    pub fn passthrough(mut self, glob: &str) -> Self {
        if let Ok(pattern) = Pattern::new(glob) {
            self.passthrough.push(pattern);
        }
        self
    }

    /// A glob whose matching paths are denied (`EACCES`) even if declared; checked before
    /// passthrough. An invalid pattern is ignored. `realpath` does not consult it.
    pub fn deny(mut self, glob: &str) -> Self {
        if let Ok(pattern) = Pattern::new(glob) {
            self.deny.push(pattern);
        }
        self
    }

    /// Builds the file system, opening the `/dev/null` descriptor its fds are duplicated from.
    pub fn build(self) -> std::sync::Arc<VirtualFs> {
        std::sync::Arc::new(VirtualFs::new(self))
    }

    fn inode(&mut self, data: Vec<u8>, directory: bool) -> Arc<VInode> {
        let number = self.next_inode | 1;
        self.next_inode = number + 2;
        VInode::new(number, data, directory)
    }
}

/// An in-memory file system serving the file plane of a [`Sim`](crate::Sim); build one with
/// [`FsBuilder`] and hand it to [`SimBuilder::fs`](crate::SimBuilder::fs).
pub struct VirtualFs {
    /// The declared nodes and files created with `O_CREAT`.
    tree: Mutex<BTreeMap<PathBuf, VNode>>,
    next_inode: AtomicU64,
    cwd: Mutex<Option<Arc<VInode>>>,
    volume: Arc<Volume>,
    /// Open virtual files by fd.
    open: Mutex<OpenFiles<OpenFile>>,
    /// Open directory streams by fd.
    dirs: Mutex<OpenFiles<Arc<Mutex<DirStream>>>>,
    owned_prefixes: Vec<PathBuf>,
    passthrough: Vec<Pattern>,
    deny: Vec<Pattern>,
    /// A real `/dev/null` fd, `O_CLOEXEC`, opened once and never closed; -1 if the open failed, in
    /// which case every virtual open fails with `EMFILE`.
    devnull: c_int,
}

/// A directory snapshot with a stable heap address for `readdir` results.
pub(crate) struct DirStream {
    /// The listing as it stood at `opendir`; later tree changes are not seen (POSIX leaves
    /// whether `readdir` sees entries added or removed after `opendir` unspecified: IEEE Std
    /// 1003.1-2017, `readdir`).
    pub(crate) entries: Vec<DirEntry>,
    /// Index of the next entry `readdir` returns.
    pub(crate) cursor: usize,
    /// The record `readdir` returns a pointer to, overwritten by the next call on the same stream
    /// (man 3 readdir allows exactly this).
    pub(crate) scratch: Box<Dirent>,
    inode: Option<Arc<VInode>>,
    #[cfg(target_os = "linux")]
    pub(crate) path: Option<PathBuf>,
}

impl DirStream {
    /// A fresh stream over `entries` with a zeroed scratch `dirent`.
    pub(crate) fn new(entries: Vec<DirEntry>) -> Self {
        // SAFETY: a zeroed dirent is valid (integers + a name buffer).
        let scratch = Box::new(unsafe { core::mem::zeroed::<Dirent>() });
        DirStream {
            entries,
            cursor: 0,
            scratch,
            inode: None,
            #[cfg(target_os = "linux")]
            path: None,
        }
    }
}

/// One entry of a directory snapshot, in the shape `fill_dirent` writes.
pub(crate) struct DirEntry {
    /// The entry's name, without a NUL.
    pub(crate) name: Vec<u8>,
    pub(crate) ino: u64,
    /// `DT_DIR` or `DT_REG` (man 3 readdir, `d_type`).
    pub(crate) dtype: u8,
}

// On glibc Linux std's `read_dir` calls `readdir64`, whose record is struct dirent64 (d_ino, d_off,
// d_reclen, d_type, d_name; glibc bits/dirent.h); macOS readdir(3) uses struct dirent (d_ino,
// d_seekoff, d_reclen, d_namlen, d_type, d_name; macOS dir(5), 64-bit-inode variant).
#[cfg(target_os = "linux")]
pub(crate) type Dirent = libc::dirent64;
#[cfg(not(target_os = "linux"))]
pub(crate) type Dirent = libc::dirent;

impl VirtualFs {
    fn volume_stats(&self, buf: *mut u8) -> Option<FsResult> {
        if buf.is_null() {
            return err(libc::EFAULT);
        }
        let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
        stat.f_bsize = PAGE_SIZE as _;
        stat.f_blocks = self.volume.capacity as _;
        let free = self
            .volume
            .capacity
            .saturating_sub(self.volume.used.load(Ordering::Acquire));
        stat.f_bfree = free as _;
        stat.f_bavail = free as _;
        stat.f_files = u64::MAX as _;
        stat.f_ffree = u64::MAX.saturating_sub(self.volume.files.load(Ordering::Acquire)) as _;
        #[cfg(target_os = "linux")]
        {
            stat.f_type = 0x0102_1994;
            stat.f_frsize = PAGE_SIZE as _;
            stat.f_namelen = 255;
        }
        #[cfg(target_os = "macos")]
        {
            stat.f_iosize = PAGE_SIZE as _;
            stat.f_flags = libc::MNT_LOCAL as _;
            for (out, byte) in stat.f_fstypename.iter_mut().zip(b"snare") {
                *out = *byte as c_char;
            }
            stat.f_mntonname[0] = b'/' as c_char;
            for (out, byte) in stat.f_mntfromname.iter_mut().zip(b"snare") {
                *out = *byte as c_char;
            }
        }
        unsafe {
            std::ptr::from_mut(&mut stat.f_fsid).cast::<i32>().write(1);
            buf.cast::<libc::statfs>().write(stat);
        }
        ok(0)
    }

    /// Takes the builder's declarations and opens the `/dev/null` template fd on the real OS.
    fn new(b: FsBuilder) -> Self {
        let volume = Arc::new(Volume {
            capacity: b.storage_limit.unwrap_or(1 << 30) / PAGE_SIZE as u64,
            used: AtomicU64::new(0),
            files: AtomicU64::new(0),
        });
        for node in b.tree.values() {
            node.inode().data.lock().unwrap().attach(&volume);
        }
        let devnull = snare_interpose::real(|| unsafe {
            libc::open(c"/dev/null".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC)
        });
        for (path, node) in &b.tree {
            if matches!(node, VNode::Dir(_))
                && let Some(VNode::Dir(parent)) =
                    path.parent().and_then(|parent| b.tree.get(parent))
            {
                parent.links.fetch_add(1, Ordering::Relaxed);
            }
        }
        VirtualFs {
            tree: Mutex::new(b.tree),
            next_inode: AtomicU64::new(b.next_inode | 1),
            cwd: Mutex::default(),
            volume,
            open: Mutex::default(),
            dirs: Mutex::default(),
            owned_prefixes: b.owned_prefixes,
            passthrough: b.passthrough,
            deny: b.deny,
            devnull,
        }
    }

    /// Mints a real, unique fd for a virtual file or directory by `dup`ing the `/dev/null` fd;
    /// `dup` returns the lowest free descriptor (man 2 dup), so it never collides with an fd
    /// another part of the process holds. `EMFILE` when the template is missing.
    fn reserve_fd(&self) -> std::io::Result<c_int> {
        if self.devnull < 0 {
            return Err(std::io::Error::from_raw_os_error(libc::EMFILE));
        }
        let fd = unsafe { libc::dup(self.devnull) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(fd)
    }

    /// Whether `path` lies under an owned prefix (component-wise, so `/a` does not own `/ab`).
    fn owned(&self, path: &Path) -> bool {
        self.owned_prefixes
            .iter()
            .any(|prefix| path.starts_with(prefix))
    }

    /// (mode, size, nlink) for an owned fd, for `fstat` and `statx(AT_EMPTY_PATH)`.
    fn fd_meta(&self, fd: c_int) -> Option<(u32, u64, u64, u64)> {
        let open = self.open.lock().unwrap();
        let Some(file) = open.get(&fd) else {
            let dirs = self.dirs.lock().unwrap();
            let stream = dirs.get(&fd)?.lock().unwrap();
            let inode = stream.inode.as_ref()?;
            return Some((
                dir_mode(),
                0,
                inode.links.load(Ordering::Acquire),
                inode.number,
            ));
        };
        Some(if file.is_dir {
            (
                dir_mode(),
                0,
                file.inode.links.load(Ordering::Acquire),
                file.inode.number,
            )
        } else {
            (
                reg_mode(),
                file.inode.data.lock().unwrap().len() as u64,
                file.inode.links.load(Ordering::Acquire),
                file.inode.number,
            )
        })
    }

    /// Whether any of `patterns` matches `path`, with the `glob` crate's default options (`*`
    /// crosses `/`).
    fn matches(patterns: &[Pattern], path: &Path) -> bool {
        patterns.iter().any(|p| p.matches_path(path))
    }

    fn claims(&self, tree: &BTreeMap<PathBuf, VNode>, path: &Path) -> bool {
        self.owned(path)
            || tree.contains_key(path)
            || path
                .parent()
                .is_some_and(|parent| tree.contains_key(parent))
    }

    fn parent(tree: &BTreeMap<PathBuf, VNode>, path: &Path) -> Result<Arc<VInode>, c_int> {
        if path
            .ancestors()
            .skip(1)
            .any(|ancestor| matches!(tree.get(ancestor), Some(VNode::File(_))))
        {
            return Err(libc::ENOTDIR);
        }
        match path.parent().and_then(|parent| tree.get(parent)) {
            Some(VNode::Dir(inode)) => Ok(inode.clone()),
            _ => Err(libc::ENOENT),
        }
    }

    unsafe fn retained_directory(&self, fd: c_int, raw: *const c_char) -> Option<Arc<VInode>> {
        if raw.is_null() {
            return None;
        }
        let bytes = unsafe { CStr::from_ptr(raw) }.to_bytes();
        if bytes.is_empty()
            || bytes.starts_with(b"/")
            || !bytes
                .split(|byte| *byte == b'/')
                .all(|component| component.is_empty() || component == b".")
        {
            return None;
        }
        if fd == libc::AT_FDCWD {
            return self.cwd.lock().unwrap().clone();
        }
        self.open
            .lock()
            .unwrap()
            .get(&fd)
            .filter(|file| file.is_dir)
            .map(|file| file.inode.clone())
    }

    fn open_directory_inode(&self, inode: Arc<VInode>, flags: c_int) -> Option<FsResult> {
        if writable(flags) {
            return err(libc::EISDIR);
        }
        if flags & (libc::O_CREAT | libc::O_EXCL) == (libc::O_CREAT | libc::O_EXCL) {
            return err(libc::EEXIST);
        }
        if cfg!(target_os = "linux") && flags & libc::O_CREAT != 0 {
            return err(libc::EISDIR);
        }
        let fd = match self.reserve_fd() {
            Ok(fd) => fd,
            Err(error) => return err(error.raw_os_error().unwrap_or(libc::EMFILE)),
        };
        let entries = {
            let tree = self.tree.lock().unwrap();
            tree.iter()
                .find(|(_, node)| Arc::ptr_eq(node.inode(), &inode))
                .map_or_else(Vec::new, |(path, _)| snapshot(&tree, path))
        };
        let mut stream = DirStream::new(entries);
        stream.inode = Some(inode.clone());
        self.open.lock().unwrap().insert(
            fd,
            OpenFile {
                inode,
                cursor: 0,
                writable: false,
                append: flags & libc::O_APPEND != 0,
                flags: status_flags(flags),
                is_dir: true,
                directory: Some(Arc::new(Mutex::new(stream))),
            },
        );
        set_cloexec(fd, flags);
        ok(fd as i64)
    }

    unsafe fn absolute(&self, raw: *const c_char) -> Result<Option<CString>, c_int> {
        if raw.is_null() {
            return Ok(None);
        }
        let path = unsafe { CStr::from_ptr(raw) };
        if path.to_bytes().starts_with(b"/") {
            return Ok(Some(path.to_owned()));
        }
        if path.to_bytes().is_empty() {
            return Err(libc::ENOENT);
        }
        let cwd = match self.cwd_bytes() {
            Some(result) => result?,
            None => std::env::current_dir()
                .map_err(|error| error.raw_os_error().unwrap_or(libc::ENOENT))?
                .into_os_string()
                .into_encoded_bytes(),
        };
        let mut absolute = cwd;
        absolute.push(b'/');
        absolute.extend_from_slice(path.to_bytes());
        Ok(Some(CString::new(absolute).unwrap()))
    }

    fn cwd_bytes(&self) -> Option<Result<Vec<u8>, c_int>> {
        let inode = self.cwd.lock().unwrap().clone()?;
        let tree = self.tree.lock().unwrap();
        Some(
            tree.iter()
                .find(|(_, node)| Arc::ptr_eq(node.inode(), &inode))
                .map(|(path, _)| path.as_os_str().as_bytes().to_vec())
                .ok_or(libc::ENOENT),
        )
    }

    unsafe fn traversal(
        &self,
        tree: &BTreeMap<PathBuf, VNode>,
        raw: *const c_char,
        path: &Path,
        strict_dots: bool,
        follow_final: bool,
    ) -> Result<PathBuf, c_int> {
        let raw = unsafe { CStr::from_ptr(raw) }.to_bytes();
        let raw_path = Path::new(OsStr::from_bytes(raw));
        if !self.claims(tree, path)
            && !tree.iter().any(|(entry, node)| {
                matches!(node, VNode::Symlink(..)) && raw_path.starts_with(entry)
            })
        {
            return Ok(path.to_path_buf());
        }
        let mut pending: VecDeque<Vec<u8>> = raw
            .split(|byte| *byte == b'/')
            .filter(|component| !component.is_empty())
            .map(<[u8]>::to_vec)
            .collect();
        if raw.ends_with(b"/") && (follow_final || cfg!(target_os = "macos")) {
            pending.push_back(b".".to_vec());
        }
        let mut current = PathBuf::from("/");
        let mut links = 0;
        while let Some(component) = pending.pop_front() {
            match tree.get(&current) {
                Some(VNode::File(_) | VNode::Symlink(..))
                    if strict_dots || !matches!(component.as_slice(), b"." | b"..") =>
                {
                    return Err(libc::ENOTDIR);
                }
                None if current != Path::new("/") && self.claims(tree, &current) => {
                    return Err(libc::ENOENT);
                }
                _ => {}
            }
            match component.as_slice() {
                b"." => continue,
                b".." => {
                    current.pop();
                    continue;
                }
                component => current.push(OsStr::from_bytes(component)),
            }
            if let Some(VNode::Symlink(_, target)) = tree.get(&current)
                && (follow_final || !pending.is_empty())
            {
                if target.is_empty() {
                    return Err(libc::ENOENT);
                }
                links += 1;
                if links > if cfg!(target_os = "macos") { 32 } else { 40 } {
                    return Err(libc::ELOOP);
                }
                current.pop();
                if target.starts_with(b"/") {
                    current = PathBuf::from("/");
                }
                let mut components: VecDeque<Vec<u8>> = target
                    .split(|byte| *byte == b'/')
                    .filter(|component| !component.is_empty())
                    .map(<[u8]>::to_vec)
                    .collect();
                if target.ends_with(b"/") && pending.is_empty() {
                    components.push_back(b".".to_vec());
                }
                components.append(&mut pending);
                pending = components;
            }
        }
        if links > 0
            && (Self::matches(&self.passthrough, &current)
                || (!self.owned(&current) && !tree.contains_key(&current)))
        {
            return Err(libc::EXDEV);
        }
        if links > 0 && Self::matches(&self.deny, &current) {
            return Err(libc::EACCES);
        }
        Ok(current)
    }

    unsafe fn stat_path(
        &self,
        path: *const c_char,
        buf: *mut u8,
        follow: bool,
    ) -> Option<FsResult> {
        if let Some(inode) = unsafe { self.retained_directory(libc::AT_FDCWD, path) } {
            return fill_stat(
                buf,
                dir_mode(),
                0,
                inode.number,
                inode.links.load(Ordering::Acquire),
            );
        }
        let path_absolute = match unsafe { self.absolute(path) } {
            Ok(path) => path?,
            Err(error) => return err(error),
        };
        let path = path_absolute.as_ptr();
        let raw = path;
        let trailing_slash =
            !path.is_null() && unsafe { CStr::from_ptr(path) }.to_bytes().ends_with(b"/");
        let path = unsafe { path_of(path) }?;
        if Self::matches(&self.deny, &path) {
            return err(libc::EACCES);
        }
        if Self::matches(&self.passthrough, &path) {
            return None;
        }
        let tree = self.tree.lock().unwrap();
        let path =
            match unsafe { self.traversal(&tree, raw, &path, true, follow || trailing_slash) } {
                Ok(path) => path,
                Err(error) => return err(error),
            };
        match tree.get(&path) {
            Some(node) => {
                if trailing_slash && matches!(node, VNode::File(_)) {
                    return err(libc::ENOTDIR);
                }
                let (mode, size, nlink) = mode_size_nlink(node);
                let blocks = node.inode().data.lock().unwrap().pages.len() as u64 * 8;
                allocated_blocks(
                    buf,
                    fill_stat(buf, mode, size, node.inode().number, nlink),
                    blocks,
                    false,
                )
            }
            None if self.owned(&path) => err(libc::ENOENT),
            None => None,
        }
    }

    unsafe fn resolve_at(&self, fd: c_int, raw: *const c_char) -> Result<Option<CString>, c_int> {
        if raw.is_null() {
            return if self.owns(fd) {
                Err(libc::EFAULT)
            } else {
                Ok(None)
            };
        }
        let path = unsafe { CStr::from_ptr(raw) };
        if path.to_bytes().starts_with(b"/") || fd == libc::AT_FDCWD {
            return Ok(Some(path.to_owned()));
        }
        let inode = {
            let open = self.open.lock().unwrap();
            let Some(file) = open.get(&fd) else {
                return Ok(None);
            };
            if !file.is_dir {
                return Err(libc::ENOTDIR);
            }
            file.inode.clone()
        };
        if path.to_bytes().is_empty() {
            return Err(libc::ENOENT);
        }
        let tree = self.tree.lock().unwrap();
        let Some((directory, _)) = tree
            .iter()
            .find(|(_, node)| Arc::ptr_eq(node.inode(), &inode))
        else {
            return Err(libc::ENOENT);
        };
        let mut bytes = directory.as_os_str().as_encoded_bytes().to_vec();
        bytes.push(b'/');
        bytes.extend_from_slice(path.to_bytes());
        Ok(Some(CString::new(bytes).unwrap()))
    }
}

impl Drop for VirtualFs {
    fn drop(&mut self) {
        snare_interpose::real(|| unsafe {
            for &fd in self.open.get_mut().unwrap().keys() {
                libc::close(fd);
            }
            for &fd in self.dirs.get_mut().unwrap().keys() {
                if !self.open.get_mut().unwrap().contains_key(&fd) {
                    libc::close(fd);
                }
            }
            if self.devnull >= 0 {
                libc::close(self.devnull);
            }
        });
    }
}

/// A handled call returning `n`.
pub(crate) fn ok(n: i64) -> Option<FsResult> {
    Some(FsResult::Ok(n))
}

/// A handled call failing with `errno`; the hook sets `errno` and returns -1.
pub(crate) fn err(errno: c_int) -> Option<FsResult> {
    Some(FsResult::Err(errno))
}

/// Lexically normalizes an absolute path (no syscalls, so it never re-enters our own hooks): `.`
/// is dropped and `..` pops a component, stopping at the root ("in the root directory, dot-dot
/// may refer to the root directory itself": IEEE Std 1003.1-2017, Base Definitions §4.13
/// Pathname Resolution). Symlinks are not resolved.
pub(crate) fn normalize(raw: impl AsRef<Path>) -> PathBuf {
    let mut out = PathBuf::from("/");
    for component in raw.as_ref().components() {
        match component {
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(c) => out.push(c),
            _ => {}
        }
    }
    out
}

/// A virtual path, or `None` for a null or relative path (which the OS should resolve itself).
///
/// # Safety
/// `path` must be a valid C string.
pub(crate) unsafe fn path_of(path: *const c_char) -> Option<PathBuf> {
    if path.is_null() {
        return None;
    }
    let bytes = unsafe { CStr::from_ptr(path) }.to_bytes();
    if bytes.first() != Some(&b'/') {
        return None; // relative: let the real OS resolve it against the cwd
    }
    Some(normalize(Path::new(OsStr::from_bytes(bytes))))
}

impl Fs for VirtualFs {
    /// Whether `fd` is an open virtual file or directory stream, i.e. one this backend minted;
    /// fd-only calls on any other fd are declined.
    fn owns(&self, fd: c_int) -> bool {
        self.open.lock().unwrap().contains_key(&fd) || self.dirs.lock().unwrap().contains_key(&fd)
    }

    fn cwd_path(&self) -> Option<Result<Vec<u8>, c_int>> {
        self.cwd_bytes()
    }

    fn cwd_changed(&self) {
        *self.cwd.lock().unwrap() = None;
    }

    unsafe fn chdir(&self, path: *const c_char) -> Option<FsResult> {
        if unsafe { self.retained_directory(libc::AT_FDCWD, path) }.is_some() {
            return ok(0);
        }
        let absolute = match unsafe { self.absolute(path) } {
            Ok(path) => path?,
            Err(error) => return err(error),
        };
        let path = unsafe { path_of(absolute.as_ptr()) }?;
        if Self::matches(&self.passthrough, &path) {
            return None;
        }
        if Self::matches(&self.deny, &path) {
            return err(libc::EACCES);
        }
        let tree = self.tree.lock().unwrap();
        if !self.claims(&tree, &path) {
            return None;
        }
        let path = match unsafe { self.traversal(&tree, absolute.as_ptr(), &path, true, true) } {
            Ok(path) => path,
            Err(error) => return err(error),
        };
        let inode = match tree.get(&path) {
            Some(VNode::Dir(inode)) => inode.clone(),
            Some(_) => return err(libc::ENOTDIR),
            None => return err(libc::ENOENT),
        };
        drop(tree);
        *self.cwd.lock().unwrap() = Some(inode);
        ok(0)
    }

    unsafe fn fchdir(&self, fd: c_int) -> Option<FsResult> {
        let inode = {
            let open = self.open.lock().unwrap();
            let file = open.get(&fd)?;
            if !file.is_dir {
                return err(libc::ENOTDIR);
            }
            file.inode.clone()
        };
        *self.cwd.lock().unwrap() = Some(inode);
        ok(0)
    }

    unsafe fn getcwd(&self, buf: *mut c_char, len: usize) -> Option<FsResult> {
        let bytes = match self.cwd_bytes()? {
            Ok(bytes) => bytes,
            Err(error) => return err(error),
        };
        if !buf.is_null() && len == 0 {
            return err(libc::EINVAL);
        }
        let len = if cfg!(target_os = "macos") && buf.is_null() {
            0
        } else {
            len
        };
        if len != 0 && len <= bytes.len() {
            return err(libc::ERANGE);
        }
        let out = if buf.is_null() {
            let out = unsafe { libc::malloc(if len == 0 { bytes.len() + 1 } else { len }) }
                .cast::<c_char>();
            if out.is_null() {
                return err(libc::ENOMEM);
            }
            out
        } else {
            buf
        };
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr().cast::<c_char>(), out, bytes.len());
            *out.add(bytes.len()) = 0;
        }
        ok(out as i64)
    }

    unsafe fn symlink(&self, target: *const c_char, link: *const c_char) -> Option<FsResult> {
        let absolute = match unsafe { self.absolute(link) } {
            Ok(path) => path?,
            Err(error) => return err(error),
        };
        let path = unsafe { path_of(absolute.as_ptr()) }?;
        if Self::matches(&self.passthrough, &path) {
            return None;
        }
        if Self::matches(&self.deny, &path) {
            return err(libc::EACCES);
        }
        let mut tree = self.tree.lock().unwrap();
        if !self.claims(&tree, &path) {
            return None;
        }
        if target.is_null() {
            return err(libc::EFAULT);
        }
        let target = unsafe { CStr::from_ptr(target) }.to_bytes();
        if target.is_empty() {
            return err(libc::ENOENT);
        }
        let path = match unsafe { self.traversal(&tree, absolute.as_ptr(), &path, true, false) } {
            Ok(path) => path,
            Err(error) => return err(error),
        };
        if tree.contains_key(&path) {
            return err(libc::EEXIST);
        }
        if let Err(error) = Self::parent(&tree, &path) {
            return err(error);
        }
        if absolute.to_bytes().ends_with(b"/") {
            return err(libc::ENOENT);
        }
        let inode = VInode::new(
            self.next_inode.fetch_add(2, Ordering::Relaxed),
            Vec::new(),
            false,
        );
        inode.data.lock().unwrap().attach(&self.volume);
        tree.insert(path, VNode::Symlink(inode, Arc::new(target.to_vec())));
        ok(0)
    }

    unsafe fn symlinkat(
        &self,
        target: *const c_char,
        fd: c_int,
        link: *const c_char,
    ) -> Option<FsResult> {
        let link = match unsafe { self.resolve_at(fd, link) } {
            Ok(path) => path?,
            Err(error) => return err(error),
        };
        unsafe { self.symlink(target, link.as_ptr()) }
    }

    unsafe fn access(&self, path: *const c_char, mode: c_int) -> Option<FsResult> {
        unsafe { self.faccessat(libc::AT_FDCWD, path, mode, 0) }
    }

    unsafe fn faccessat(
        &self,
        dirfd: c_int,
        path: *const c_char,
        mode: c_int,
        flags: c_int,
    ) -> Option<FsResult> {
        let path = match unsafe { self.resolve_at(dirfd, path) } {
            Ok(path) => path?,
            Err(error) => return err(error),
        };
        let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
        let result = unsafe {
            self.stat_path(
                path.as_ptr(),
                std::ptr::from_mut(&mut metadata).cast(),
                flags & libc::AT_SYMLINK_NOFOLLOW == 0,
            )
        }?;
        if mode & !(libc::R_OK | libc::W_OK | libc::X_OK) != 0
            || flags & !(libc::AT_EACCESS | libc::AT_SYMLINK_NOFOLLOW) != 0
        {
            return err(libc::EINVAL);
        }
        if matches!(result, FsResult::Ok(_))
            && mode & libc::X_OK != 0
            && metadata.st_mode & 0o111 == 0
        {
            return err(libc::EACCES);
        }
        Some(result)
    }

    unsafe fn readlink(&self, raw: *const c_char, buf: *mut u8, len: usize) -> Option<FsResult> {
        let absolute = match unsafe { self.absolute(raw) } {
            Ok(path) => path?,
            Err(error) => return err(error),
        };
        let path = unsafe { path_of(absolute.as_ptr()) }?;
        if Self::matches(&self.passthrough, &path) {
            return None;
        }
        if Self::matches(&self.deny, &path) {
            return err(libc::EACCES);
        }
        let tree = self.tree.lock().unwrap();
        if !self.claims(&tree, &path) {
            return None;
        }
        let path = match unsafe {
            self.traversal(
                &tree,
                absolute.as_ptr(),
                &path,
                true,
                absolute.to_bytes().ends_with(b"/"),
            )
        } {
            Ok(path) => path,
            Err(error) => return err(error),
        };
        let target = match tree.get(&path) {
            Some(VNode::Symlink(_, target)) => target,
            Some(_) => return err(libc::EINVAL),
            None => return err(libc::ENOENT),
        };
        if len == 0 {
            return err(libc::EINVAL);
        }
        if buf.is_null() {
            return err(libc::EFAULT);
        }
        let count = len.min(target.len());
        unsafe {
            std::ptr::copy_nonoverlapping(target.as_ptr(), buf, count);
        }
        ok(count as i64)
    }

    unsafe fn readlinkat(
        &self,
        fd: c_int,
        path: *const c_char,
        buf: *mut u8,
        len: usize,
    ) -> Option<FsResult> {
        let path = match unsafe { self.resolve_at(fd, path) } {
            Ok(path) => path?,
            Err(error) => return err(error),
        };
        unsafe { self.readlink(path.as_ptr(), buf, len) }
    }

    /// Opens a virtual path with the requested access and creation flags.
    unsafe fn open(&self, path: *const c_char, flags: c_int, _mode: u32) -> Option<FsResult> {
        if let Some(inode) = unsafe { self.retained_directory(libc::AT_FDCWD, path) } {
            return self.open_directory_inode(inode, flags);
        }
        let path_absolute = match unsafe { self.absolute(path) } {
            Ok(path) => path?,
            Err(error) => return err(error),
        };
        let path = path_absolute.as_ptr();
        let raw = path;
        let trailing_slash =
            !path.is_null() && unsafe { CStr::from_ptr(path) }.to_bytes().ends_with(b"/");
        let path = unsafe { path_of(path) }?;
        if Self::matches(&self.deny, &path) {
            return err(libc::EACCES);
        }
        if Self::matches(&self.passthrough, &path) {
            return None; // a real, un-owned fd opens; later calls on it decline (fs never minted it)
        }

        let mut tree = self.tree.lock().unwrap();
        #[cfg(target_os = "linux")]
        if trailing_slash && flags & libc::O_CREAT != 0 && self.claims(&tree, &path) {
            return err(libc::EISDIR);
        }
        let path = match unsafe {
            self.traversal(
                &tree,
                raw,
                &path,
                true,
                trailing_slash
                    || (flags & libc::O_NOFOLLOW == 0
                        && flags & (libc::O_CREAT | libc::O_EXCL)
                            != (libc::O_CREAT | libc::O_EXCL)),
            )
        } {
            Ok(path) => path,
            Err(error) => return err(error),
        };
        let node = tree.get(&path).cloned();
        #[cfg(target_os = "macos")]
        if flags & libc::O_SYMLINK != 0 && self.claims(&tree, &path) {
            return err(libc::EOPNOTSUPP);
        }
        #[cfg(target_os = "linux")]
        if flags & (libc::O_PATH | libc::O_NOFOLLOW) == (libc::O_PATH | libc::O_NOFOLLOW)
            && matches!(node, Some(VNode::Symlink(..)))
        {
            return err(libc::EOPNOTSUPP);
        }
        if trailing_slash && matches!(node, Some(VNode::File(_))) {
            return err(libc::ENOTDIR);
        }
        if trailing_slash && node.is_none() {
            return if self.owned(&path) {
                err(libc::ENOENT)
            } else {
                None
            };
        }
        if node.is_some()
            && flags & (libc::O_CREAT | libc::O_EXCL) == (libc::O_CREAT | libc::O_EXCL)
        {
            return err(libc::EEXIST);
        }
        if matches!(node, Some(VNode::Dir(_))) && writable(flags) {
            return err(libc::EISDIR);
        }
        if matches!(node, Some(VNode::File(_))) && flags & libc::O_DIRECTORY != 0 {
            return err(libc::ENOTDIR);
        }
        #[cfg(target_os = "linux")]
        if matches!(node, Some(VNode::Dir(_))) && flags & libc::O_CREAT != 0 {
            return err(libc::EISDIR);
        }
        let creating = node.is_none();
        let (data, is_dir, writable) = match node {
            Some(VNode::File(bytes)) => (bytes, false, writable(flags)),
            Some(VNode::Symlink(..)) => return err(libc::ELOOP),
            Some(VNode::Dir(inode)) => (inode, true, false),
            None => {
                // man 2 open: O_CREAT creates the file if it does not exist.
                if flags & libc::O_CREAT != 0
                    && (self.owned(&path) || path.parent().is_some_and(|p| tree.contains_key(p)))
                {
                    if let Err(error) = Self::parent(&tree, &path) {
                        return err(error);
                    }
                    (
                        VInode::new(
                            self.next_inode.fetch_add(2, Ordering::Relaxed),
                            Vec::new(),
                            false,
                        ),
                        false,
                        writable(flags),
                    )
                } else if self.owned(&path) {
                    return err(libc::ENOENT); // default-deny within owned prefixes
                } else {
                    return None; // default-pass outside owned prefixes
                }
            }
        };
        let fd = match self.reserve_fd() {
            Ok(fd) => fd,
            Err(e) => return err(e.raw_os_error().unwrap_or(libc::EMFILE)),
        };
        if creating {
            data.data.lock().unwrap().attach(&self.volume);
            tree.insert(path.clone(), VNode::File(data.clone()));
        }
        if !is_dir && flags & libc::O_TRUNC != 0 {
            data.data.lock().unwrap().clear();
        }
        let directory = is_dir.then(|| {
            let mut stream = DirStream::new(snapshot(&tree, &path));
            stream.inode = Some(data.clone());
            Arc::new(Mutex::new(stream))
        });
        drop(tree);
        self.open.lock().unwrap().insert(
            fd,
            OpenFile {
                inode: data,
                cursor: 0,
                writable,
                append: flags & libc::O_APPEND != 0,
                flags: status_flags(flags),
                is_dir,
                directory,
            },
        );
        set_cloexec(fd, flags);
        ok(fd as i64)
    }

    /// Opens a path relative to the working directory or an owned directory descriptor.
    unsafe fn openat(
        &self,
        dirfd: c_int,
        path: *const c_char,
        flags: c_int,
        mode: u32,
    ) -> Option<FsResult> {
        if let Some(inode) = unsafe { self.retained_directory(dirfd, path) } {
            return self.open_directory_inode(inode, flags);
        }
        let path = match unsafe { self.resolve_at(dirfd, path) } {
            Ok(path) => path?,
            Err(error) => return err(error),
        };
        unsafe { self.open(path.as_ptr(), flags, mode) }
    }

    unsafe fn unlinkat(&self, fd: c_int, raw: *const c_char, flags: c_int) -> Option<FsResult> {
        let path = match unsafe { self.resolve_at(fd, raw) } {
            Ok(path) => path?,
            Err(error) => return err(error),
        };
        if flags & !libc::AT_REMOVEDIR != 0 {
            return err(libc::EINVAL);
        }
        if flags & libc::AT_REMOVEDIR != 0 {
            unsafe { self.rmdir(path.as_ptr()) }
        } else {
            unsafe { self.unlink(path.as_ptr()) }
        }
    }

    unsafe fn mkdirat(&self, fd: c_int, raw: *const c_char, mode: u32) -> Option<FsResult> {
        let path = match unsafe { self.resolve_at(fd, raw) } {
            Ok(path) => path?,
            Err(error) => return err(error),
        };
        unsafe { self.mkdir(path.as_ptr(), mode) }
    }

    unsafe fn renameat(
        &self,
        fromfd: c_int,
        from: *const c_char,
        tofd: c_int,
        to: *const c_char,
    ) -> Option<FsResult> {
        let from = match unsafe { self.resolve_at(fromfd, from) } {
            Ok(path) => path?,
            Err(error) => return err(error),
        };
        let to = match unsafe { self.resolve_at(tofd, to) } {
            Ok(path) => path?,
            Err(error) => return err(error),
        };
        unsafe { self.rename(from.as_ptr(), to.as_ptr()) }
    }

    unsafe fn rmdir(&self, raw: *const c_char) -> Option<FsResult> {
        let raw_absolute = match unsafe { self.absolute(raw) } {
            Ok(path) => path?,
            Err(error) => return err(error),
        };
        let raw = raw_absolute.as_ptr();
        let path = unsafe { path_of(raw) }?;
        if Self::matches(&self.deny, &path) {
            return err(libc::EACCES);
        }
        if Self::matches(&self.passthrough, &path) {
            return None;
        }
        let mut tree = self.tree.lock().unwrap();
        if !self.claims(&tree, &path) {
            return None;
        }
        let path = match unsafe { self.traversal(&tree, raw, &path, true, false) } {
            Ok(path) => path,
            Err(error) => return err(error),
        };
        let final_component = unsafe { CStr::from_ptr(raw) }
            .to_bytes()
            .rsplit(|b| *b == b'/')
            .find(|c| !c.is_empty());
        if final_component == Some(b".") {
            return err(libc::EINVAL);
        }
        if path == Path::new("/") {
            return err(libc::EBUSY);
        }
        let inode = match tree.get(&path) {
            Some(VNode::File(_) | VNode::Symlink(..)) => return err(libc::ENOTDIR),
            Some(VNode::Dir(inode)) => inode.clone(),
            None => return err(libc::ENOENT),
        };
        if tree
            .keys()
            .any(|entry| entry != &path && entry.starts_with(&path))
        {
            return err(libc::ENOTEMPTY);
        }
        tree.remove(&path);
        if cfg!(target_os = "linux") {
            inode.links.store(0, Ordering::Release);
        }
        if let Some(VNode::Dir(parent)) = path.parent().and_then(|parent| tree.get(parent)) {
            parent.links.fetch_sub(1, Ordering::Release);
        }
        ok(0)
    }

    unsafe fn unlink(&self, raw: *const c_char) -> Option<FsResult> {
        let raw_absolute = match unsafe { self.absolute(raw) } {
            Ok(path) => path?,
            Err(error) => return err(error),
        };
        let raw = raw_absolute.as_ptr();
        let trailing_slash =
            !raw.is_null() && unsafe { CStr::from_ptr(raw) }.to_bytes().ends_with(b"/");
        let path = unsafe { path_of(raw) }?;
        if Self::matches(&self.deny, &path) {
            return err(libc::EACCES);
        }
        if Self::matches(&self.passthrough, &path) {
            return None;
        }
        let mut tree = self.tree.lock().unwrap();
        if !self.claims(&tree, &path) {
            return None;
        }
        let path = match unsafe { self.traversal(&tree, raw, &path, true, false) } {
            Ok(path) => path,
            Err(error) => return err(error),
        };
        match tree.get(&path) {
            Some(VNode::Dir(_)) => {
                return err(if cfg!(target_os = "macos") {
                    libc::EPERM
                } else {
                    libc::EISDIR
                });
            }
            Some(VNode::File(_) | VNode::Symlink(..)) if trailing_slash => {
                return err(libc::ENOTDIR);
            }
            None => {
                return err(Self::parent(&tree, &path).err().unwrap_or(libc::ENOENT));
            }
            Some(VNode::File(_) | VNode::Symlink(..)) => {}
        }
        let inode = tree.remove(&path).unwrap();
        inode.inode().links.fetch_sub(1, Ordering::AcqRel);
        ok(0)
    }

    unsafe fn mkdir(&self, raw: *const c_char, _mode: u32) -> Option<FsResult> {
        let raw_absolute = match unsafe { self.absolute(raw) } {
            Ok(path) => path?,
            Err(error) => return err(error),
        };
        let raw = raw_absolute.as_ptr();
        let trailing_slash =
            !raw.is_null() && unsafe { CStr::from_ptr(raw) }.to_bytes().ends_with(b"/");
        let path = unsafe { path_of(raw) }?;
        if Self::matches(&self.deny, &path) {
            return err(libc::EACCES);
        }
        if Self::matches(&self.passthrough, &path) {
            return None;
        }
        let mut tree = self.tree.lock().unwrap();
        if !self.claims(&tree, &path) {
            return None;
        }
        let bytes = unsafe { CStr::from_ptr(raw) }.to_bytes();
        let end = bytes
            .iter()
            .rposition(|byte| *byte != b'/')
            .map_or(1, |last| last + 1);
        let walk = CString::new(&bytes[..end]).unwrap();
        let path = match unsafe {
            self.traversal(
                &tree,
                walk.as_ptr(),
                &path,
                true,
                cfg!(target_os = "macos") && trailing_slash,
            )
        } {
            Ok(path) => path,
            Err(error) => return err(error),
        };
        #[cfg(target_os = "macos")]
        if trailing_slash && matches!(tree.get(&path), Some(VNode::File(_))) {
            return err(libc::ENOTDIR);
        }
        if tree.contains_key(&path) {
            return err(libc::EEXIST);
        }
        let parent = match Self::parent(&tree, &path) {
            Ok(parent) => parent,
            Err(error) => return err(error),
        };
        let inode = VInode::new(
            self.next_inode.fetch_add(2, Ordering::Relaxed),
            Vec::new(),
            true,
        );
        inode.data.lock().unwrap().attach(&self.volume);
        tree.insert(path, VNode::Dir(inode));
        parent.links.fetch_add(1, Ordering::Release);
        ok(0)
    }

    unsafe fn rename(&self, from_raw: *const c_char, to_raw: *const c_char) -> Option<FsResult> {
        let from_raw_absolute = match unsafe { self.absolute(from_raw) } {
            Ok(path) => path?,
            Err(error) => return err(error),
        };
        let from_raw = from_raw_absolute.as_ptr();
        let to_raw_absolute = match unsafe { self.absolute(to_raw) } {
            Ok(path) => path?,
            Err(error) => return err(error),
        };
        let to_raw = to_raw_absolute.as_ptr();
        let from_slash = !from_raw.is_null()
            && unsafe { CStr::from_ptr(from_raw) }
                .to_bytes()
                .ends_with(b"/");
        let to_slash =
            !to_raw.is_null() && unsafe { CStr::from_ptr(to_raw) }.to_bytes().ends_with(b"/");
        let from = unsafe { path_of(from_raw) }?;
        let to = unsafe { path_of(to_raw) }?;
        if Self::matches(&self.deny, &from) || Self::matches(&self.deny, &to) {
            return err(libc::EACCES);
        }
        if Self::matches(&self.passthrough, &from) || Self::matches(&self.passthrough, &to) {
            return None;
        }
        let mut tree = self.tree.lock().unwrap();
        let source_claimed = self.claims(&tree, &from);
        let target_claimed = self.claims(&tree, &to);
        if !source_claimed && !target_claimed {
            return None;
        }
        if !source_claimed {
            return err(libc::EXDEV);
        }
        let from = match unsafe { self.traversal(&tree, from_raw, &from, true, false) } {
            Ok(path) => path,
            Err(error) => return err(error),
        };
        let to = match unsafe { self.traversal(&tree, to_raw, &to, true, false) } {
            Ok(path) => path,
            Err(error) => return err(error),
        };
        if [from_raw, to_raw].into_iter().any(|raw| {
            matches!(
                unsafe { CStr::from_ptr(raw) }
                    .to_bytes()
                    .rsplit(|byte| *byte == b'/')
                    .find(|component| !component.is_empty()),
                Some(b"." | b"..")
            )
        }) {
            return err(if cfg!(target_os = "macos") {
                libc::EINVAL
            } else {
                libc::EBUSY
            });
        }
        let source = match tree.get(&from).cloned() {
            Some(source) => source,
            None => return err(Self::parent(&tree, &from).err().unwrap_or(libc::ENOENT)),
        };
        let directory = matches!(source, VNode::Dir(_));
        if from_slash && !directory {
            return err(libc::ENOTDIR);
        }
        if from == to {
            return if to_slash && !directory {
                err(libc::ENOTDIR)
            } else {
                ok(0)
            };
        }
        if !target_claimed {
            return err(libc::EXDEV);
        }
        let target_parent = match Self::parent(&tree, &to) {
            Ok(parent) => parent,
            Err(error) => return err(error),
        };
        let target = tree.get(&to).cloned();
        if to_slash && !directory {
            #[cfg(target_os = "linux")]
            return err(libc::ENOTDIR);
            #[cfg(target_os = "macos")]
            match &target {
                Some(VNode::File(_) | VNode::Symlink(..)) => return err(libc::ENOTDIR),
                None => return err(libc::ENOENT),
                Some(VNode::Dir(_)) => {}
            }
        }
        if target
            .as_ref()
            .is_some_and(|target| Arc::ptr_eq(source.inode(), target.inode()))
        {
            return ok(0);
        }
        if directory && to.starts_with(&from) {
            return err(libc::EINVAL);
        }
        match (&source, &target) {
            (VNode::File(_) | VNode::Symlink(..), Some(VNode::Dir(_))) => return err(libc::EISDIR),
            (VNode::Dir(_), Some(VNode::File(_) | VNode::Symlink(..))) => {
                return err(libc::ENOTDIR);
            }
            (VNode::Dir(_), Some(VNode::Dir(_)))
                if tree.keys().any(|path| path != &to && path.starts_with(&to)) =>
            {
                return err(libc::ENOTEMPTY);
            }
            _ => {}
        }
        if let Some(target) = tree.remove(&to) {
            if matches!(target, VNode::Dir(_)) {
                #[cfg(target_os = "linux")]
                target.inode().links.store(0, Ordering::Release);
            } else {
                target.inode().links.fetch_sub(1, Ordering::AcqRel);
            }
        }
        let moving: Vec<_> = tree
            .keys()
            .filter(|path| *path == &from || (directory && path.starts_with(&from)))
            .cloned()
            .collect();
        let moved: Vec<_> = moving
            .into_iter()
            .map(|path| {
                let destination = if path == from {
                    to.clone()
                } else {
                    to.join(path.strip_prefix(&from).unwrap())
                };
                (destination, tree.remove(&path).unwrap())
            })
            .collect();
        tree.extend(moved);
        if directory {
            if let Some(VNode::Dir(parent)) = from.parent().and_then(|parent| tree.get(parent)) {
                parent.links.fetch_sub(1, Ordering::Release);
            }
            if !matches!(target, Some(VNode::Dir(_))) {
                target_parent.links.fetch_add(1, Ordering::Release);
            }
        }
        ok(0)
    }

    unsafe fn link(&self, from: *const c_char, to: *const c_char) -> Option<FsResult> {
        let from_absolute = match unsafe { self.absolute(from) } {
            Ok(path) => path?,
            Err(error) => return err(error),
        };
        let from = from_absolute.as_ptr();
        let to_absolute = match unsafe { self.absolute(to) } {
            Ok(path) => path?,
            Err(error) => return err(error),
        };
        let to = to_absolute.as_ptr();
        let source = unsafe { path_of(from) }?;
        let target = unsafe { path_of(to) }?;
        if Self::matches(&self.deny, &source) || Self::matches(&self.deny, &target) {
            return err(libc::EACCES);
        }
        let mut tree = self.tree.lock().unwrap();
        let source_claimed =
            self.claims(&tree, &source) && !Self::matches(&self.passthrough, &source);
        let target_claimed =
            self.claims(&tree, &target) && !Self::matches(&self.passthrough, &target);
        if !source_claimed && !target_claimed {
            return None;
        }
        if !source_claimed {
            return err(libc::EXDEV);
        }
        let source = match unsafe { self.traversal(&tree, from, &source, true, false) } {
            Ok(path) => path,
            Err(error) => return err(error),
        };
        let target = match unsafe { self.traversal(&tree, to, &target, true, false) } {
            Ok(path) => path,
            Err(error) => return err(error),
        };
        let node = match tree.get(&source) {
            Some(node @ (VNode::File(_) | VNode::Symlink(..))) => node.clone(),
            Some(VNode::Dir(_)) => return err(libc::EPERM),
            None => return err(libc::ENOENT),
        };
        if unsafe { CStr::from_ptr(from) }.to_bytes().ends_with(b"/") {
            return err(libc::ENOTDIR);
        }
        if !target_claimed {
            return err(libc::EXDEV);
        }
        if unsafe { CStr::from_ptr(to) }.to_bytes().ends_with(b"/") {
            return err(match tree.get(&target) {
                #[cfg(target_os = "macos")]
                Some(VNode::File(_) | VNode::Symlink(..)) => libc::ENOTDIR,
                #[cfg(target_os = "linux")]
                Some(VNode::File(_) | VNode::Symlink(..)) => libc::EEXIST,
                Some(VNode::Dir(_)) => libc::EEXIST,
                None => libc::ENOENT,
            });
        }
        if tree.contains_key(&target) {
            return err(libc::EEXIST);
        }
        if let Err(error) = Self::parent(&tree, &target) {
            return err(error);
        }
        node.inode().links.fetch_add(1, Ordering::AcqRel);
        tree.insert(target, node);
        ok(0)
    }

    unsafe fn linkat(
        &self,
        fromfd: c_int,
        from: *const c_char,
        tofd: c_int,
        to: *const c_char,
        flags: c_int,
    ) -> Option<FsResult> {
        let from = match unsafe { self.resolve_at(fromfd, from) } {
            Ok(path) => path?,
            Err(error) => return err(error),
        };
        let to = match unsafe { self.resolve_at(tofd, to) } {
            Ok(path) => path?,
            Err(error) => return err(error),
        };
        if flags & !libc::AT_SYMLINK_FOLLOW != 0 {
            return err(libc::EINVAL);
        }
        let from = if flags & libc::AT_SYMLINK_FOLLOW != 0 {
            let absolute = match unsafe { self.absolute(from.as_ptr()) } {
                Ok(path) => path?,
                Err(error) => return err(error),
            };
            let path = unsafe { path_of(absolute.as_ptr()) }?;
            let tree = self.tree.lock().unwrap();
            let path = match unsafe { self.traversal(&tree, absolute.as_ptr(), &path, true, true) }
            {
                Ok(path) => path,
                Err(error) => return err(error),
            };
            CString::new(path.as_os_str().as_bytes()).unwrap()
        } else {
            from
        };
        unsafe { self.link(from.as_ptr(), to.as_ptr()) }
    }

    unsafe fn stat(&self, path: *const c_char, buf: *mut u8) -> Option<FsResult> {
        unsafe { self.stat_path(path, buf, true) }
    }

    unsafe fn lstat(&self, path: *const c_char, buf: *mut u8) -> Option<FsResult> {
        unsafe { self.stat_path(path, buf, false) }
    }

    /// `realpath(3)` of a declared path. The
    /// `deny` globs are not consulted. Returns the result buffer's address as the call's value.
    // man 3 realpath: canonicalizes `path`; when `resolved` is NULL it mallocs the buffer (freed by
    // the caller), otherwise it writes into a PATH_MAX buffer the caller supplies.
    unsafe fn realpath(&self, path: *const c_char, resolved: *mut c_char) -> Option<FsResult> {
        let path_absolute = match unsafe { self.absolute(path) } {
            Ok(path) => path?,
            Err(error) => return err(error),
        };
        let path = path_absolute.as_ptr();
        let raw = path;
        let path = unsafe { path_of(path) }?;
        if Self::matches(&self.passthrough, &path) {
            return None;
        }
        let tree = self.tree.lock().unwrap();
        let path =
            match unsafe { self.traversal(&tree, raw, &path, !cfg!(target_os = "macos"), true) } {
                Ok(path) => path,
                Err(error) => return err(error),
            };
        if !tree.contains_key(&path) {
            return if self.owned(&path) {
                err(libc::ENOENT)
            } else {
                None
            };
        }
        drop(tree);
        let bytes = path.as_os_str().as_encoded_bytes();
        let out = if resolved.is_null() {
            let buf = unsafe { libc::malloc(bytes.len() + 1) } as *mut c_char;
            if buf.is_null() {
                return err(libc::ENOMEM);
            }
            buf
        } else {
            resolved
        };
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr().cast::<c_char>(), out, bytes.len());
            *out.add(bytes.len()) = 0;
        }
        ok(out as i64)
    }

    unsafe fn fstatat(
        &self,
        dirfd: c_int,
        path: *const c_char,
        buf: *mut u8,
        flags: c_int,
    ) -> Option<FsResult> {
        #[cfg(target_os = "macos")]
        let allowed = libc::AT_SYMLINK_NOFOLLOW;
        #[cfg(target_os = "linux")]
        let allowed = libc::AT_SYMLINK_NOFOLLOW | libc::AT_EMPTY_PATH | libc::AT_NO_AUTOMOUNT;
        if flags & !allowed != 0 {
            let claimed = self.owns(dirfd)
                || unsafe { path_of(path) }.is_some_and(|path| {
                    self.claims(&self.tree.lock().unwrap(), &path)
                        && !Self::matches(&self.passthrough, &path)
                });
            return if claimed { err(libc::EINVAL) } else { None };
        }
        #[cfg(target_os = "linux")]
        if flags & libc::AT_EMPTY_PATH != 0
            && (path.is_null() || unsafe { CStr::from_ptr(path) }.to_bytes().is_empty())
        {
            return unsafe { self.fstat(dirfd, buf) };
        }
        if let Some(inode) = unsafe { self.retained_directory(dirfd, path) } {
            return fill_stat(
                buf,
                dir_mode(),
                0,
                inode.number,
                inode.links.load(Ordering::Acquire),
            );
        }
        let path = match unsafe { self.resolve_at(dirfd, path) } {
            Ok(path) => path?,
            Err(error) => return err(error),
        };
        unsafe { self.stat_path(path.as_ptr(), buf, flags & libc::AT_SYMLINK_NOFOLLOW == 0) }
    }

    /// `fstat(2)` reports the inode's current size.
    unsafe fn fstat(&self, fd: c_int, buf: *mut u8) -> Option<FsResult> {
        let (mode, size, nlink, ino) = self.fd_meta(fd)?;
        let result = fill_stat(buf, mode, size, ino, nlink);
        if matches!(result, Some(FsResult::Ok(_))) {
            let blocks = self.open.lock().unwrap().get(&fd).map_or(0, |file| {
                file.inode.data.lock().unwrap().pages.len() as u64 * 8
            });
            unsafe { (*buf.cast::<libc::stat>()).st_blocks = blocks as _ };
        }
        result
    }

    unsafe fn statfs(&self, path: *const c_char, buf: *mut u8) -> Option<FsResult> {
        let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
        match unsafe { self.stat(path, std::ptr::from_mut(&mut metadata).cast()) }? {
            FsResult::Ok(_) => self.volume_stats(buf),
            error => Some(error),
        }
    }

    unsafe fn fstatfs(&self, fd: c_int, buf: *mut u8) -> Option<FsResult> {
        if !self.owns(fd) {
            return None;
        }
        self.volume_stats(buf)
    }

    /// `statx(2)` (Linux): `AT_EMPTY_PATH` on an owned fd is served as [`fstat`](Fs::fstat), a
    /// path as [`stat`](Fs::stat). `mask` is ignored: the same fields are always filled and the
    /// same bits reported in `stx_mask`, which man 2 statx permits ("the kernel may return fields
    /// that weren't requested").
    #[cfg(target_os = "linux")]
    unsafe fn statx(
        &self,
        dirfd: c_int,
        path: *const c_char,
        flags: c_int,
        _mask: u32,
        buf: *mut u8,
    ) -> Option<FsResult> {
        let empty = path.is_null() || unsafe { path.read() } == 0;
        if empty {
            // man 2 statx: an empty pathname with AT_EMPTY_PATH stats `dirfd` itself. std's
            // `File::metadata` is exactly `statx(fd, "", AT_EMPTY_PATH)`.
            if flags & libc::AT_EMPTY_PATH != 0
                && let Some((mode, size, nlink, ino)) = self.fd_meta(dirfd)
            {
                let blocks = self.open.lock().unwrap().get(&dirfd).map_or(0, |file| {
                    file.inode.data.lock().unwrap().pages.len() as u64 * 8
                });
                return allocated_blocks(
                    buf,
                    fill_statx(buf, mode, size, ino, nlink),
                    blocks,
                    true,
                );
            }
            return None;
        }
        if let Some(inode) = unsafe { self.retained_directory(dirfd, path) } {
            return fill_statx(
                buf,
                dir_mode(),
                0,
                inode.number,
                inode.links.load(Ordering::Acquire),
            );
        }
        let resolved = match unsafe { self.resolve_at(dirfd, path) } {
            Ok(path) => path?,
            Err(error) => return err(error),
        };
        let absolute = match unsafe { self.absolute(resolved.as_ptr()) } {
            Ok(path) => path?,
            Err(error) => return err(error),
        };
        let path = absolute.as_ptr();
        let trailing_slash = unsafe { CStr::from_ptr(path) }.to_bytes().ends_with(b"/");
        let raw = path;
        let path = unsafe { path_of(path) }?;
        if Self::matches(&self.deny, &path) {
            return err(libc::EACCES);
        }
        if Self::matches(&self.passthrough, &path) {
            return None;
        }
        let tree = self.tree.lock().unwrap();
        let path = match unsafe {
            self.traversal(
                &tree,
                raw,
                &path,
                true,
                flags & libc::AT_SYMLINK_NOFOLLOW == 0 || trailing_slash,
            )
        } {
            Ok(path) => path,
            Err(error) => return err(error),
        };
        match tree.get(&path) {
            Some(node) => {
                if trailing_slash && matches!(node, VNode::File(_)) {
                    return err(libc::ENOTDIR);
                }
                let (mode, size, nlink) = mode_size_nlink(node);
                let blocks = node.inode().data.lock().unwrap().pages.len() as u64 * 8;
                allocated_blocks(
                    buf,
                    fill_statx(buf, mode, size, node.inode().number, nlink),
                    blocks,
                    true,
                )
            }
            None if self.owned(&path) => err(libc::ENOENT),
            None => None,
        }
    }

    /// Snapshots a directory listing and reserves its descriptor. Files return `ENOTDIR`.
    unsafe fn opendir(&self, path: *const c_char) -> Option<FsResult> {
        let fd = match unsafe {
            self.open(
                path,
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                0,
            )
        }? {
            FsResult::Ok(fd) => fd as c_int,
            error => return Some(error),
        };
        unsafe { self.fdopendir(fd) }
    }

    unsafe fn fdopendir(&self, fd: c_int) -> Option<FsResult> {
        let open = self.open.lock().unwrap();
        let file = open.get(&fd)?;
        let Some(stream) = &file.directory else {
            return err(libc::ENOTDIR);
        };
        self.dirs.lock().unwrap().insert(fd, stream.clone());
        set_cloexec(fd, libc::O_CLOEXEC);
        ok(fd as i64)
    }

    /// `readdir(3)` on a virtual stream.
    // man 3 readdir: returns a pointer to the next struct dirent, or NULL at end of stream (here a
    // null pointer encoded as 0). The returned storage is owned by the stream and reused per call.
    unsafe fn readdir(&self, fd: c_int) -> Option<FsResult> {
        let mut dirs = self.dirs.lock().unwrap();
        let mut d = dirs.get_mut(&fd)?.lock().unwrap();
        let Some(entry) = d.entries.get(d.cursor) else {
            return ok(0); // end of stream: readdir returns NULL
        };
        let (name, ino, dtype) = (entry.name.clone(), entry.ino, entry.dtype);
        d.cursor += 1;
        fill_dirent(&mut d.scratch, &name, ino, dtype);
        let ptr = (&*d.scratch as *const Dirent) as i64;
        ok(ptr)
    }

    /// `readdir_r(3)` on a virtual stream.
    // man 3 readdir_r: writes the entry into the caller's `entry` buffer and stores its address in
    // `*result` (NULL at end of stream); returns 0 on success.
    unsafe fn readdir_r(
        &self,
        fd: c_int,
        entry: *mut u8,
        result: *mut *mut u8,
    ) -> Option<FsResult> {
        let mut dirs = self.dirs.lock().unwrap();
        let mut d = dirs.get_mut(&fd)?.lock().unwrap();
        match d.entries.get(d.cursor) {
            Some(e) => {
                let (name, ino, dtype) = (e.name.clone(), e.ino, e.dtype);
                d.cursor += 1;
                // SAFETY: `entry` points to a caller `struct dirent`.
                fill_dirent(unsafe { &mut *entry.cast::<Dirent>() }, &name, ino, dtype);
                // SAFETY: `result` is a writable `*mut dirent`.
                unsafe { *result = entry };
            }
            None => {
                // SAFETY: as above.
                unsafe { *result = std::ptr::null_mut() };
            }
        }
        ok(0)
    }

    /// `closedir(3)`: forgets the stream and closes its reserved fd.
    unsafe fn closedir(&self, fd: c_int) -> Option<FsResult> {
        if !self.dirs.lock().unwrap().contains_key(&fd) {
            return None;
        }
        unsafe { self.close(fd) }
    }

    unsafe fn getdents64(&self, fd: c_int, buf: *mut u8, len: usize) -> Option<FsResult> {
        let open = self.open.lock().unwrap();
        let file = open.get(&fd)?;
        let Some(stream) = &file.directory else {
            return err(libc::ENOTDIR);
        };
        pack_directory(&mut stream.lock().unwrap(), buf, len)
    }

    /// `read(2)` at the cursor; 0 at or past the end. `EISDIR` on a directory
    /// (man 2 read).
    unsafe fn read(&self, fd: c_int, buf: *mut u8, len: usize) -> Option<FsResult> {
        let mut open = self.open.lock().unwrap();
        let file = open.get_mut(&fd)?;
        if file.flags & libc::O_ACCMODE == libc::O_WRONLY {
            return err(libc::EBADF);
        }
        if file.is_dir {
            return err(libc::EISDIR);
        }
        let data = file.inode.data.lock().unwrap();
        let n = unsafe { data.read(file.cursor, buf, len) };
        file.cursor += n;
        ok(n as i64)
    }

    /// `write(2)` at the cursor, zero-filling any gap a seek past the end left
    /// (man 2 lseek, holes). `EBADF` when not open for writing (man 2 write). Always writes all
    /// `len` bytes.
    unsafe fn write(&self, fd: c_int, buf: *const u8, len: usize) -> Option<FsResult> {
        let mut open = self.open.lock().unwrap();
        let file = open.get_mut(&fd)?;
        if !file.writable {
            return err(libc::EBADF);
        }
        if len == 0 {
            return ok(0);
        }
        // SAFETY: caller's buffer holds `len` readable bytes.
        let bytes = unsafe { std::slice::from_raw_parts(buf, len) };
        let mut data = file.inode.data.lock().unwrap();
        if file.append {
            file.cursor = data.len();
        }
        match data.write(file.cursor, bytes) {
            Ok(written) => {
                file.cursor += written;
                ok(written as i64)
            }
            Err(error) => err(error),
        }
    }

    unsafe fn pread(&self, fd: c_int, buf: *mut u8, len: usize, offset: i64) -> Option<FsResult> {
        let open = self.open.lock().unwrap();
        let file = open.get(&fd)?;
        #[cfg(target_os = "macos")]
        if file.flags & libc::O_ACCMODE == libc::O_WRONLY {
            return err(libc::EBADF);
        }
        if offset < 0 {
            return err(libc::EINVAL);
        }
        if file.flags & libc::O_ACCMODE == libc::O_WRONLY {
            return err(libc::EBADF);
        }
        if file.is_dir {
            return err(libc::EISDIR);
        }
        let data = file.inode.data.lock().unwrap();
        let n = unsafe { data.read(offset as usize, buf, len) };
        ok(n as i64)
    }

    unsafe fn pwrite(
        &self,
        fd: c_int,
        buf: *const u8,
        len: usize,
        offset: i64,
    ) -> Option<FsResult> {
        let mut open = self.open.lock().unwrap();
        let file = open.get_mut(&fd)?;
        if offset < 0 {
            return err(libc::EINVAL);
        }
        if !file.writable {
            return err(libc::EBADF);
        }
        if len == 0 {
            return ok(0);
        }
        let mut data = file.inode.data.lock().unwrap();
        let start = if cfg!(target_os = "linux") && file.append {
            data.len()
        } else {
            offset as usize
        };
        let bytes = unsafe { std::slice::from_raw_parts(buf, len) };
        match data.write(start, bytes) {
            Ok(written) => ok(written as i64),
            Err(error) => err(error),
        }
    }

    unsafe fn ftruncate(&self, fd: c_int, len: i64) -> Option<FsResult> {
        let mut open = self.open.lock().unwrap();
        let file = open.get_mut(&fd)?;
        if !file.writable {
            return err(libc::EINVAL);
        }
        if len < 0 {
            return err(libc::EINVAL);
        }
        let len = len as usize;
        let mut data = file.inode.data.lock().unwrap();
        data.resize(len);
        ok(0)
    }

    unsafe fn fsync(&self, fd: c_int) -> Option<FsResult> {
        self.open.lock().unwrap().get(&fd)?;
        ok(0)
    }

    /// `lseek(2)` on an open virtual file. Any `whence` other than `SEEK_SET`/`SEEK_CUR`/`SEEK_END`
    /// is `EINVAL`, including `SEEK_DATA`/`SEEK_HOLE`, which Linux and macOS do support.
    unsafe fn lseek(&self, fd: c_int, offset: i64, whence: c_int) -> Option<FsResult> {
        let mut open = self.open.lock().unwrap();
        let file = open.get_mut(&fd)?;
        if let Some(stream) = &file.directory {
            let mut stream = stream.lock().unwrap();
            let base = match whence {
                libc::SEEK_SET => 0,
                libc::SEEK_CUR => stream.cursor as i64,
                _ => return err(libc::EINVAL),
            };
            let Some(target) = base.checked_add(offset).filter(|target| *target >= 0) else {
                return err(libc::EINVAL);
            };
            stream.cursor = target as usize;
            return ok(target);
        }
        // man 2 lseek: SEEK_SET/CUR/END measure the new offset from the start / current position /
        // end of file; a resulting negative offset is EINVAL.
        let base = match whence {
            libc::SEEK_SET => 0,
            libc::SEEK_CUR => file.cursor as i64,
            libc::SEEK_END => file.inode.data.lock().unwrap().len() as i64,
            _ => return err(libc::EINVAL),
        };
        let Some(target) = base.checked_add(offset) else {
            return err(libc::EINVAL);
        };
        if target < 0 {
            return err(libc::EINVAL);
        }
        file.cursor = target as usize;
        ok(target)
    }

    unsafe fn fd_replaced(&self, fd: c_int) -> Option<FsResult> {
        let mut open = self.open.lock().unwrap();
        let file = open.remove(&fd);
        let stream = self.dirs.lock().unwrap().remove(&fd);
        if file.is_none() && stream.is_none() {
            return None;
        }
        drop(file);
        ok(0)
    }

    /// `close(2)` releases the descriptor and closes its reserved fd.
    unsafe fn close(&self, fd: c_int) -> Option<FsResult> {
        unsafe { self.fd_replaced(fd) }?;
        let ret = unsafe { libc::close(fd) };
        ok(ret as i64)
    }

    unsafe fn dup(&self, oldfd: c_int, newfd: c_int) -> Option<FsResult> {
        let mut open = self.open.lock().unwrap();
        let mut dirs = self.dirs.lock().unwrap();
        let released = if open.contains_key(&oldfd) {
            dirs.remove(&newfd);
            open.alias(oldfd, newfd)?
        } else {
            if !dirs.contains_key(&oldfd) {
                return None;
            }
            let released = open.remove(&newfd).flatten();
            dirs.alias(oldfd, newfd)?;
            released
        };
        drop(dirs);
        drop(open);
        drop(released);
        ok(newfd as i64)
    }

    unsafe fn dup_to(&self, oldfd: c_int, newfd: c_int, flags: Option<c_int>) -> Option<FsResult> {
        let mut open = self.open.lock().unwrap();
        let mut dirs = self.dirs.lock().unwrap();
        let is_file = open.contains_key(&oldfd);
        if !is_file && !dirs.contains_key(&oldfd) {
            return None;
        }
        let result = crate::fabric::duplicate_to(oldfd, newfd, flags);
        if result < 0 {
            return err(std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EBADF));
        }
        let released = if is_file {
            dirs.remove(&newfd);
            open.alias(oldfd, newfd).flatten()
        } else {
            let released = open.remove(&newfd).flatten();
            dirs.alias(oldfd, newfd);
            released
        };
        drop(dirs);
        drop(open);
        drop(released);
        ok(result as i64)
    }

    unsafe fn fcntl(&self, fd: c_int, cmd: c_int, arg: i64) -> Option<FsResult> {
        let mut open = self.open.lock().unwrap();
        let mut dirs = self.dirs.lock().unwrap();
        let is_file = open.contains_key(&fd);
        if !is_file && !dirs.contains_key(&fd) {
            return None;
        }
        match cmd {
            #[cfg(target_os = "macos")]
            libc::F_FULLFSYNC | libc::F_BARRIERFSYNC if is_file => ok(0),
            libc::F_DUPFD | libc::F_DUPFD_CLOEXEC => {
                let result = descriptor_fcntl(fd, cmd, arg)?;
                if let FsResult::Ok(newfd) = result {
                    if is_file {
                        open.alias(fd, newfd as c_int);
                    } else {
                        dirs.alias(fd, newfd as c_int);
                    }
                }
                Some(result)
            }
            libc::F_GETFD | libc::F_SETFD => descriptor_fcntl(fd, cmd, arg),
            libc::F_GETFL => ok(open.get(&fd).map_or(libc::O_RDONLY, |file| file.flags) as i64),
            libc::F_SETFL => {
                if let Some(file) = open.get_mut(&fd) {
                    let mask = libc::O_APPEND | libc::O_NONBLOCK;
                    file.flags = (file.flags & !mask) | (arg as c_int & mask);
                    file.append = file.flags & libc::O_APPEND != 0;
                }
                ok(0)
            }
            _ => err(libc::EINVAL),
        }
    }
}

/// Whether `open` flags grant write access.
fn writable(flags: c_int) -> bool {
    // man 2 open: the access mode is the low bits masked by O_ACCMODE (O_RDONLY/O_WRONLY/O_RDWR).
    let mode = flags & libc::O_ACCMODE;
    mode == libc::O_WRONLY || mode == libc::O_RDWR
}

pub(crate) fn pack_directory(stream: &mut DirStream, buf: *mut u8, len: usize) -> Option<FsResult> {
    let mut written = 0;
    while let Some(entry) = stream.entries.get(stream.cursor) {
        let record: Dirent = unsafe { std::mem::zeroed() };
        if entry.name.len() >= record.d_name.len() {
            return if written == 0 {
                err(libc::ENAMETOOLONG)
            } else {
                ok(written as i64)
            };
        }
        let header = std::mem::offset_of!(Dirent, d_name);
        #[cfg(target_os = "linux")]
        let alignment = 8;
        #[cfg(target_os = "macos")]
        let alignment = 4;
        let record_len = (header + entry.name.len() + 1).next_multiple_of(alignment);
        if record_len > len.saturating_sub(written) {
            return if written == 0 {
                err(libc::EINVAL)
            } else {
                ok(written as i64)
            };
        }
        if buf.is_null() {
            return if written == 0 {
                err(libc::EFAULT)
            } else {
                ok(written as i64)
            };
        }
        unsafe {
            let out = buf.add(written).cast::<Dirent>();
            out.cast::<u8>().write_bytes(0, record_len);
            std::ptr::addr_of_mut!((*out).d_ino).write_unaligned(entry.ino as _);
            std::ptr::addr_of_mut!((*out).d_reclen).write_unaligned(record_len as _);
            std::ptr::addr_of_mut!((*out).d_type).write_unaligned(entry.dtype);
            #[cfg(target_os = "linux")]
            std::ptr::addr_of_mut!((*out).d_off).write_unaligned((stream.cursor + 1) as _);
            #[cfg(target_os = "macos")]
            {
                std::ptr::addr_of_mut!((*out).d_seekoff).write_unaligned((stream.cursor + 1) as _);
                std::ptr::addr_of_mut!((*out).d_namlen).write_unaligned(entry.name.len() as _);
            }
            std::ptr::copy_nonoverlapping(
                entry.name.as_ptr(),
                buf.add(written + header),
                entry.name.len(),
            );
        }
        stream.cursor += 1;
        written += record_len;
    }
    ok(written as i64)
}

fn allocated_blocks(
    buf: *mut u8,
    result: Option<FsResult>,
    blocks: u64,
    statx: bool,
) -> Option<FsResult> {
    if matches!(result, Some(FsResult::Ok(_))) {
        unsafe {
            if statx {
                buf.add(48).cast::<u64>().write_unaligned(blocks);
            } else {
                (*buf.cast::<libc::stat>()).st_blocks = blocks as _;
            }
        }
    }
    result
}

/// Fills a caller `struct stat` for a virtual node. `st_mode`/`st_size`/… are field names common
/// to macOS and Linux `libc::stat` (man 2 stat, inode(7)); `as _` absorbs the u16-vs-u32 `st_mode`
/// and off_t width splits.
pub(crate) fn fill_stat(
    buf: *mut u8,
    mode: u32,
    size: u64,
    ino: u64,
    nlink: u64,
) -> Option<FsResult> {
    if buf.is_null() {
        return err(libc::EFAULT);
    }
    // SAFETY: an all-zero `struct stat` is valid (every field is an integer).
    let mut st: libc::stat = unsafe { core::mem::zeroed() };
    st.st_mode = mode as _;
    st.st_size = size as _;
    st.st_ino = ino as _;
    st.st_nlink = nlink as _;
    st.st_uid = unsafe { libc::getuid() };
    st.st_gid = unsafe { libc::getgid() };
    // 4096 is a snare choice: st_blksize is only 'the "preferred" blocksize for efficient
    // filesystem I/O' (inode(7)), a hint to buffered readers.
    st.st_blksize = 4096 as _;
    // inode(7): st_blocks counts 512-byte units regardless of st_blksize.
    st.st_blocks = size.div_ceil(512) as _;
    // SAFETY: the caller's `struct stat*` is sized and aligned for one stat.
    unsafe { buf.cast::<libc::stat>().write(st) };
    ok(0)
}

/// A stable synthesized inode for a declared path: a hash of the path, so the same path always
/// gets the same number within a process. Forced odd, hence never 0: glibc before 2.37 skipped
/// every dirent with `d_ino == 0` as deleted (2.36 sysdeps/unix/sysv/linux/readdir.c, "Skip
/// deleted files"; dropped in 2.37 for glibc bug 12165), and code walking dirents itself may
/// still do so. Collisions are possible but vanishingly rare.
pub(crate) fn ino_of(path: &Path) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    path.hash(&mut hasher);
    hasher.finish() | 1
}

/// inode(7): st_mode packs the file-type bits (S_IFREG / S_IFDIR, under S_IFMT) with the
/// permission bits. `S_IF*` are `mode_t` (u16 on macOS, u32 on Linux); widen without a per-OS cast
/// lint.
///
/// Regular files are `0644` and directories `0755`: a snare choice, matching what a `0666` file
/// and a `0777` directory get under "the typical default value for the process umask", 022
/// (man 2 umask).
#[allow(clippy::unnecessary_cast)]
fn reg_mode() -> u32 {
    (libc::S_IFREG | 0o644) as u32
}
/// `st_mode` of a virtual directory; see [`reg_mode`].
#[allow(clippy::unnecessary_cast)]
fn dir_mode() -> u32 {
    (libc::S_IFDIR | 0o755) as u32
}

/// Lists `.` and `..`, then direct children in path order. Scans the whole tree.
fn snapshot(tree: &BTreeMap<PathBuf, VNode>, dir: &Path) -> Vec<DirEntry> {
    // readdir(3): a directory always lists "." and ".."; d_type is DT_DIR / DT_REG (man 2
    // getdents64 documents the DT_* set).
    let mut entries = vec![
        DirEntry {
            name: b".".to_vec(),
            ino: tree
                .get(dir)
                .map_or_else(|| ino_of(dir), |node| node.inode().number),
            dtype: libc::DT_DIR,
        },
        DirEntry {
            name: b"..".to_vec(),
            ino: dir
                .parent()
                .and_then(|parent| tree.get(parent))
                .or_else(|| tree.get(dir))
                .map_or_else(|| ino_of(dir), |node| node.inode().number),
            dtype: libc::DT_DIR,
        },
    ];
    for (path, node) in tree.iter() {
        if path.parent() == Some(dir)
            && let Some(name) = path.file_name()
        {
            let dtype = match node {
                VNode::Dir(_) => libc::DT_DIR,
                VNode::File(_) => libc::DT_REG,
                VNode::Symlink(..) => libc::DT_LNK,
            };
            entries.push(DirEntry {
                name: name.as_encoded_bytes().to_vec(),
                ino: node.inode().number,
                dtype,
            });
        }
    }
    entries
}

/// Writes one directory entry into `dst`, truncating a name longer than `d_name` (256 bytes on
/// Linux, glibc bits/dirent.h `struct dirent64`; 1024 (`__DARWIN_MAXPATHLEN`) on macOS,
/// `<sys/dirent.h>` 64-bit-inode `struct dirent`; NUL included) and zeroing the rest of the
/// buffer.
pub(crate) fn fill_dirent(dst: &mut Dirent, name: &[u8], ino: u64, dtype: u8) {
    // man 2 getdents / macOS dir(5): d_ino is the inode, d_reclen the record length, d_type the
    // file type, d_name the NUL-terminated name. d_off (Linux) / d_seekoff (macOS) is an opaque
    // resume cookie, and macOS also carries d_namlen. We hand back one fixed-size record at a time,
    // so d_reclen is the whole struct and the cookie is unused (0).
    dst.d_ino = ino as _;
    dst.d_reclen = core::mem::size_of::<Dirent>() as u16;
    dst.d_type = dtype;
    let n = name.len().min(dst.d_name.len() - 1);
    for slot in dst.d_name.iter_mut() {
        *slot = 0;
    }
    for (i, &b) in name.iter().take(n).enumerate() {
        dst.d_name[i] = b as _;
    }
    #[cfg(target_os = "linux")]
    {
        dst.d_off = 0;
    }
    #[cfg(not(target_os = "linux"))]
    {
        dst.d_seekoff = 0;
        dst.d_namlen = n as u16;
    }
}

fn symlink_mode() -> u32 {
    #[cfg(target_os = "macos")]
    {
        u32::from(libc::S_IFLNK) | 0o777
    }
    #[cfg(not(target_os = "macos"))]
    {
        libc::S_IFLNK | 0o777
    }
}

fn mode_size_nlink(node: &VNode) -> (u32, u64, u64) {
    match node {
        VNode::File(inode) => (
            reg_mode(),
            inode.data.lock().unwrap().len() as u64,
            inode.links.load(Ordering::Acquire),
        ),
        VNode::Dir(inode) => (dir_mode(), 0, inode.links.load(Ordering::Acquire)),
        VNode::Symlink(inode, target) => (
            symlink_mode(),
            target.len() as u64,
            inode.links.load(Ordering::Acquire),
        ),
    }
}

/// Fills a caller `struct statx` by writing the fixed kernel-ABI field offsets directly, so it is
/// correct regardless of which `libc` version std was built against (the crate's `libc::statx` can
/// disagree with std's). Layout and the STATX_* result-mask bits are from man 2 statx /
/// `<linux/stat.h>`: `struct statx` is 256 bytes (the header's closing `/* 0x100 */`); the
/// buffer std passes is that size.
///
/// Offsets, from `include/uapi/linux/stat.h` `struct statx`: `stx_mask` u32 @0, `stx_blksize`
/// u32 @4, `stx_attributes` u64 @8, `stx_nlink` u32 @16, `stx_uid` u32 @20, `stx_gid` u32 @24,
/// `stx_mode` u16 @28, `stx_ino` u64 @32, `stx_size` u64 @40, `stx_blocks` u64 @48 (512-byte
/// units, man 2 statx). `stx_mask` claims type, mode, size, inode and link count only: uid,
/// gid and blocks are written but unclaimed, and timestamps and the device fields stay zero.
#[cfg(target_os = "linux")]
pub(crate) fn fill_statx(
    buf: *mut u8,
    mode: u32,
    size: u64,
    ino: u64,
    nlink: u64,
) -> Option<FsResult> {
    if buf.is_null() {
        return err(libc::EFAULT);
    }
    // SAFETY (whole block): `buf` points to a 256-byte `struct statx` the kernel/std would fill.
    unsafe {
        std::ptr::write_bytes(buf, 0, 256);
        let put_u16 = |off: usize, v: u16| buf.add(off).cast::<u16>().write_unaligned(v);
        let put_u32 = |off: usize, v: u32| buf.add(off).cast::<u32>().write_unaligned(v);
        let put_u64 = |off: usize, v: u64| buf.add(off).cast::<u64>().write_unaligned(v);
        put_u32(
            0,
            libc::STATX_TYPE
                | libc::STATX_MODE
                | libc::STATX_SIZE
                | libc::STATX_INO
                | libc::STATX_NLINK
                | libc::STATX_UID
                | libc::STATX_GID
                | libc::STATX_BLOCKS,
        );
        put_u32(4, 4096); // stx_blksize, as st_blksize in fill_stat
        put_u32(16, nlink as u32); // stx_nlink
        put_u32(20, libc::getuid()); // stx_uid
        put_u32(24, libc::getgid()); // stx_gid
        put_u16(28, mode as u16); // stx_mode
        put_u64(32, ino); // stx_ino
        put_u64(40, size); // stx_size
        put_u64(48, size.div_ceil(512)); // stx_blocks
    }
    ok(0)
}
