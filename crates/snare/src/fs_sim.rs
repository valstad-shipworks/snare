//! An in-memory file system behind [`snare_interpose::Fs`]. The code under test uses ordinary
//! `std::fs` / `open`; declared paths are served from process memory, and glob passthrough lets
//! specific real paths reach the OS.

use std::collections::{BTreeMap, HashMap};
use std::ffi::{CStr, c_char, c_int};
use std::path::{Component, Path, PathBuf};
use std::sync::Mutex;

use glob::Pattern;
use snare_interpose::{Fs, NetResult as FsResult};

#[derive(Clone)]
enum VNode {
    File(Vec<u8>),
    Dir,
}

struct OpenFile {
    path: PathBuf,
    data: Vec<u8>,
    cursor: usize,
    writable: bool,
    is_dir: bool,
}

/// Builds a [`VirtualFs`]: declare virtual files and directories, the prefixes it owns, and glob
/// patterns to pass through to (or deny at) the real OS.
#[derive(Default)]
pub struct FsBuilder {
    tree: BTreeMap<PathBuf, VNode>,
    owned_prefixes: Vec<PathBuf>,
    passthrough: Vec<Pattern>,
    deny: Vec<Pattern>,
}

impl FsBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a virtual file with `contents`, creating its parent directories.
    pub fn file(mut self, path: impl AsRef<Path>, contents: impl Into<Vec<u8>>) -> Self {
        let path = normalize(path.as_ref().to_string_lossy().as_ref());
        let mut dir = path.clone();
        while dir.pop() {
            self.tree.entry(dir.clone()).or_insert(VNode::Dir);
        }
        self.tree.insert(path, VNode::File(contents.into()));
        self
    }

    /// Adds a virtual directory.
    pub fn dir(mut self, path: impl AsRef<Path>) -> Self {
        self.tree.insert(
            normalize(path.as_ref().to_string_lossy().as_ref()),
            VNode::Dir,
        );
        self
    }

    /// Marks a path prefix as owned: an undeclared path under it fails with `ENOENT` rather than
    /// reaching the real OS (default-deny within owned prefixes).
    pub fn own_prefix(mut self, path: impl AsRef<Path>) -> Self {
        self.owned_prefixes
            .push(normalize(path.as_ref().to_string_lossy().as_ref()));
        self
    }

    /// A glob whose matching paths are passed through to the real OS.
    pub fn passthrough(mut self, glob: &str) -> Self {
        if let Ok(pattern) = Pattern::new(glob) {
            self.passthrough.push(pattern);
        }
        self
    }

    /// A glob whose matching paths are denied (`EACCES`) even if declared.
    pub fn deny(mut self, glob: &str) -> Self {
        if let Ok(pattern) = Pattern::new(glob) {
            self.deny.push(pattern);
        }
        self
    }

    pub fn build(self) -> std::sync::Arc<VirtualFs> {
        std::sync::Arc::new(VirtualFs::new(self))
    }
}

pub struct VirtualFs {
    tree: Mutex<BTreeMap<PathBuf, VNode>>,
    open: Mutex<HashMap<c_int, OpenFile>>,
    dirs: Mutex<HashMap<c_int, DirStream>>,
    owned_prefixes: Vec<PathBuf>,
    passthrough: Vec<Pattern>,
    deny: Vec<Pattern>,
    devnull: c_int,
}

/// A directory the code under test has open. `DIR*` is opaque, so we hand back the reserved fd cast
/// to a pointer and keep the snapshot here. `scratch` is a stable heap address `readdir` returns.
pub(crate) struct DirStream {
    pub(crate) entries: Vec<DirEntry>,
    pub(crate) cursor: usize,
    pub(crate) scratch: Box<Dirent>,
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
        }
    }
}

pub(crate) struct DirEntry {
    pub(crate) name: Vec<u8>,
    pub(crate) ino: u64,
    pub(crate) dtype: u8,
}

// glibc readdir(3) hands back a struct dirent64 on Linux (the getdents64(2) record: d_ino, d_off,
// d_reclen, d_type, d_name); BSD/macOS readdir(3) uses struct dirent (d_ino, d_seekoff, d_reclen,
// d_namlen, d_type, d_name).
#[cfg(target_os = "linux")]
pub(crate) type Dirent = libc::dirent64;
#[cfg(not(target_os = "linux"))]
pub(crate) type Dirent = libc::dirent;

impl VirtualFs {
    fn new(b: FsBuilder) -> Self {
        let devnull = snare_interpose::real(|| unsafe {
            libc::open(c"/dev/null".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC)
        });
        VirtualFs {
            tree: Mutex::new(b.tree),
            open: Mutex::new(HashMap::new()),
            dirs: Mutex::new(HashMap::new()),
            owned_prefixes: b.owned_prefixes,
            passthrough: b.passthrough,
            deny: b.deny,
            devnull,
        }
    }

    fn reserve_fd(&self) -> std::io::Result<c_int> {
        if self.devnull < 0 {
            return Err(std::io::Error::from_raw_os_error(libc::EMFILE));
        }
        let fd = unsafe { libc::dup(self.devnull) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if fd < 3 {
            // Never hand out a stdio fd; return it and fail rather than panic across the hook.
            unsafe { libc::close(fd) };
            return Err(std::io::Error::from_raw_os_error(libc::EMFILE));
        }
        Ok(fd)
    }

    fn owned(&self, path: &Path) -> bool {
        self.owned_prefixes
            .iter()
            .any(|prefix| path.starts_with(prefix))
    }

    /// (mode, size, nlink) for an owned fd, for `fstat` and `statx(AT_EMPTY_PATH)`.
    fn fd_meta(&self, fd: c_int) -> Option<(u32, u64, u64)> {
        let open = self.open.lock().unwrap();
        let file = open.get(&fd)?;
        Some(if file.is_dir {
            (dir_mode(), 0, 2)
        } else {
            (reg_mode(), file.data.len() as u64, 1)
        })
    }

    fn matches(patterns: &[Pattern], path: &Path) -> bool {
        patterns.iter().any(|p| p.matches_path(path))
    }
}

pub(crate) fn ok(n: i64) -> Option<FsResult> {
    Some(FsResult::Ok(n))
}

pub(crate) fn err(errno: c_int) -> Option<FsResult> {
    Some(FsResult::Err(errno))
}

/// Lexically normalizes an absolute path (no syscalls, so it never re-enters our own hooks).
pub(crate) fn normalize(raw: &str) -> PathBuf {
    let mut out = PathBuf::from("/");
    for component in Path::new(raw).components() {
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

/// # Safety
/// `path` must be a valid C string.
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
    Some(normalize(&String::from_utf8_lossy(bytes)))
}

impl Fs for VirtualFs {
    fn owns(&self, fd: c_int) -> bool {
        self.open.lock().unwrap().contains_key(&fd) || self.dirs.lock().unwrap().contains_key(&fd)
    }

    unsafe fn open(&self, path: *const c_char, flags: c_int, _mode: u32) -> Option<FsResult> {
        let path = unsafe { path_of(path) }?;
        if Self::matches(&self.deny, &path) {
            return err(libc::EACCES);
        }
        if Self::matches(&self.passthrough, &path) {
            return None; // a real, un-owned fd opens; later calls on it decline (fs never minted it)
        }

        let mut tree = self.tree.lock().unwrap();
        let node = tree.get(&path).cloned();
        let (data, is_dir, writable) = match node {
            Some(VNode::File(bytes)) => {
                let mut data = bytes;
                // man 2 open: O_TRUNC empties an existing regular file opened for writing.
                if flags & libc::O_TRUNC != 0 {
                    data.clear();
                }
                (data, false, writable(flags))
            }
            Some(VNode::Dir) => (Vec::new(), true, false),
            None => {
                // man 2 open: O_CREAT creates the file if it does not exist.
                if flags & libc::O_CREAT != 0
                    && (self.owned(&path) || path.parent().is_some_and(|p| tree.contains_key(p)))
                {
                    tree.insert(path.clone(), VNode::File(Vec::new()));
                    (Vec::new(), false, true)
                } else if self.owned(&path) {
                    return err(libc::ENOENT); // default-deny within owned prefixes
                } else {
                    return None; // default-pass outside owned prefixes
                }
            }
        };
        drop(tree);

        let fd = match self.reserve_fd() {
            Ok(fd) => fd,
            Err(e) => return err(e.raw_os_error().unwrap_or(libc::EMFILE)),
        };
        self.open.lock().unwrap().insert(
            fd,
            OpenFile {
                path,
                data,
                cursor: 0,
                writable,
                is_dir,
            },
        );
        ok(fd as i64)
    }

    unsafe fn openat(
        &self,
        dirfd: c_int,
        path: *const c_char,
        flags: c_int,
        mode: u32,
    ) -> Option<FsResult> {
        // man 2 openat: with AT_FDCWD the path is resolved against the cwd (like open); otherwise a
        // relative path is resolved against `dirfd`, which we do not model, and an absolute path
        // ignores dirfd. So we handle AT_FDCWD and absolute paths and decline the rest.
        if dirfd != libc::AT_FDCWD {
            let is_absolute = unsafe { path.as_ref() }.is_some_and(|p| *p == b'/' as c_char);
            if !is_absolute {
                return None; // decline: let the OS resolve against the real dir
            }
        }
        unsafe { self.open(path, flags, mode) }
    }

    unsafe fn stat(&self, path: *const c_char, buf: *mut u8) -> Option<FsResult> {
        let path = unsafe { path_of(path) }?;
        if Self::matches(&self.deny, &path) {
            return err(libc::EACCES);
        }
        if Self::matches(&self.passthrough, &path) {
            return None;
        }
        let tree = self.tree.lock().unwrap();
        match tree.get(&path) {
            Some(node) => {
                let (mode, size, nlink) = mode_size_nlink(node);
                fill_stat(buf, mode, size, ino_of(&path), nlink)
            }
            None if self.owned(&path) => err(libc::ENOENT),
            None => None,
        }
    }

    unsafe fn lstat(&self, path: *const c_char, buf: *mut u8) -> Option<FsResult> {
        // man 2 lstat: identical to stat except it does not follow a final symlink; no symlinks
        // modelled, so lstat == stat.
        unsafe { self.stat(path, buf) }
    }

    // man 3 realpath: canonicalizes `path`; when `resolved` is NULL it mallocs the buffer (freed by
    // the caller), otherwise it writes into a PATH_MAX buffer the caller supplies.
    unsafe fn realpath(&self, path: *const c_char, resolved: *mut c_char) -> Option<FsResult> {
        let path = unsafe { path_of(path) }?;
        if Self::matches(&self.passthrough, &path) {
            return None;
        }
        if !self.tree.lock().unwrap().contains_key(&path) {
            return if self.owned(&path) { err(libc::ENOENT) } else { None };
        }
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
        _flags: c_int,
    ) -> Option<FsResult> {
        if dirfd != libc::AT_FDCWD {
            let absolute = unsafe { path.as_ref() }.is_some_and(|p| *p == b'/' as c_char);
            if !absolute {
                return None;
            }
        }
        unsafe { self.stat(path, buf) }
    }

    unsafe fn fstat(&self, fd: c_int, buf: *mut u8) -> Option<FsResult> {
        let (mode, size, nlink) = self.fd_meta(fd)?;
        fill_stat(buf, mode, size, fd as u64 | 1, nlink)
    }

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
                && let Some((mode, size, nlink)) = self.fd_meta(dirfd)
            {
                return fill_statx(buf, mode, size, dirfd as u64 | 1, nlink);
            }
            return None;
        }
        if dirfd != libc::AT_FDCWD {
            let absolute = unsafe { path.as_ref() }.is_some_and(|p| *p == b'/' as c_char);
            if !absolute {
                return None; // relative path against a real dirfd we do not model
            }
        }
        let path = unsafe { path_of(path) }?;
        if Self::matches(&self.deny, &path) {
            return err(libc::EACCES);
        }
        if Self::matches(&self.passthrough, &path) {
            return None;
        }
        let tree = self.tree.lock().unwrap();
        match tree.get(&path) {
            Some(node) => {
                let (mode, size, nlink) = mode_size_nlink(node);
                fill_statx(buf, mode, size, ino_of(&path), nlink)
            }
            None if self.owned(&path) => err(libc::ENOENT),
            None => None,
        }
    }

    unsafe fn opendir(&self, path: *const c_char) -> Option<FsResult> {
        let path = unsafe { path_of(path) }?;
        if Self::matches(&self.deny, &path) {
            return err(libc::EACCES);
        }
        if Self::matches(&self.passthrough, &path) {
            return None;
        }
        let tree = self.tree.lock().unwrap();
        match tree.get(&path) {
            Some(VNode::Dir) => {}
            Some(VNode::File(_)) => return err(libc::ENOTDIR),
            None if self.owned(&path) => return err(libc::ENOENT),
            None => return None,
        }
        let entries = snapshot(&tree, &path);
        drop(tree);
        let fd = match self.reserve_fd() {
            Ok(fd) => fd,
            Err(e) => return err(e.raw_os_error().unwrap_or(libc::EMFILE)),
        };
        self.dirs.lock().unwrap().insert(fd, DirStream::new(entries));
        ok(fd as i64)
    }

    // man 3 readdir: returns a pointer to the next struct dirent, or NULL at end of stream (here a
    // null pointer encoded as 0). The returned storage is owned by the stream and reused per call.
    unsafe fn readdir(&self, fd: c_int) -> Option<FsResult> {
        let mut dirs = self.dirs.lock().unwrap();
        let d = dirs.get_mut(&fd)?;
        let Some(entry) = d.entries.get(d.cursor) else {
            return ok(0); // end of stream: readdir returns NULL
        };
        let (name, ino, dtype) = (entry.name.clone(), entry.ino, entry.dtype);
        d.cursor += 1;
        fill_dirent(&mut d.scratch, &name, ino, dtype);
        let ptr = (&*d.scratch as *const Dirent) as i64;
        ok(ptr)
    }

    // man 3 readdir_r: writes the entry into the caller's `entry` buffer and stores its address in
    // `*result` (NULL at end of stream); returns 0 on success.
    unsafe fn readdir_r(
        &self,
        fd: c_int,
        entry: *mut u8,
        result: *mut *mut u8,
    ) -> Option<FsResult> {
        let mut dirs = self.dirs.lock().unwrap();
        let d = dirs.get_mut(&fd)?;
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

    unsafe fn closedir(&self, fd: c_int) -> Option<FsResult> {
        self.dirs.lock().unwrap().remove(&fd)?;
        let ret = unsafe { libc::close(fd) };
        ok(ret as i64)
    }

    unsafe fn read(&self, fd: c_int, buf: *mut u8, len: usize) -> Option<FsResult> {
        let mut open = self.open.lock().unwrap();
        let file = open.get_mut(&fd)?;
        if file.is_dir {
            return err(libc::EISDIR);
        }
        // Clamp the start: `lseek` can put the cursor past the end, and indexing `data[cursor..]`
        // would panic — a panic across the C ABI boundary aborts the process and poisons the lock.
        let start = file.cursor.min(file.data.len());
        let n = len.min(file.data.len() - start);
        // SAFETY: caller's buffer holds `len` writable bytes.
        unsafe { std::ptr::copy_nonoverlapping(file.data[start..].as_ptr(), buf, n) };
        file.cursor = start + n;
        ok(n as i64)
    }

    unsafe fn write(&self, fd: c_int, buf: *const u8, len: usize) -> Option<FsResult> {
        let mut open = self.open.lock().unwrap();
        let file = open.get_mut(&fd)?;
        if !file.writable {
            return err(libc::EBADF);
        }
        // SAFETY: caller's buffer holds `len` readable bytes.
        let bytes = unsafe { std::slice::from_raw_parts(buf, len) };
        let end = file.cursor + len;
        if file.data.len() < end {
            file.data.resize(end, 0);
        }
        file.data[file.cursor..end].copy_from_slice(bytes);
        file.cursor = end;
        ok(len as i64)
    }

    unsafe fn lseek(&self, fd: c_int, offset: i64, whence: c_int) -> Option<FsResult> {
        let mut open = self.open.lock().unwrap();
        let file = open.get_mut(&fd)?;
        // man 2 lseek: SEEK_SET/CUR/END measure the new offset from the start / current position /
        // end of file; a resulting negative offset is EINVAL.
        let base = match whence {
            libc::SEEK_SET => 0,
            libc::SEEK_CUR => file.cursor as i64,
            libc::SEEK_END => file.data.len() as i64,
            _ => return err(libc::EINVAL),
        };
        let target = base + offset;
        if target < 0 {
            return err(libc::EINVAL);
        }
        file.cursor = target as usize;
        ok(target)
    }

    unsafe fn close(&self, fd: c_int) -> Option<FsResult> {
        if self.dirs.lock().unwrap().remove(&fd).is_some() {
            let ret = unsafe { libc::close(fd) };
            return ok(ret as i64);
        }
        let file = self.open.lock().unwrap().remove(&fd)?;
        if file.writable {
            self.tree
                .lock()
                .unwrap()
                .insert(file.path, VNode::File(file.data));
        }
        let ret = unsafe { libc::close(fd) };
        ok(ret as i64)
    }
}

fn writable(flags: c_int) -> bool {
    // man 2 open: the access mode is the low bits masked by O_ACCMODE (O_RDONLY/O_WRONLY/O_RDWR).
    let mode = flags & libc::O_ACCMODE;
    mode == libc::O_WRONLY || mode == libc::O_RDWR
}

/// Fills a caller `struct stat` for a virtual node. `st_mode`/`st_size`/… are field names common
/// to macOS and Linux `libc::stat` (man 2 stat, inode(7)); `as _` absorbs the u16-vs-u32 `st_mode`
/// and off_t width splits.
pub(crate) fn fill_stat(buf: *mut u8, mode: u32, size: u64, ino: u64, nlink: u64) -> Option<FsResult> {
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
    st.st_blksize = 4096 as _;
    // inode(7): st_blocks counts 512-byte units regardless of st_blksize.
    st.st_blocks = size.div_ceil(512) as _;
    // SAFETY: the caller's `struct stat*` is sized and aligned for one stat.
    unsafe { buf.cast::<libc::stat>().write(st) };
    ok(0)
}

/// A stable synthesized inode for a declared path (never 0; some callers treat 0 as "no entry").
pub(crate) fn ino_of(path: &Path) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    path.hash(&mut hasher);
    hasher.finish() | 1
}

/// inode(7): st_mode packs the file-type bits (S_IFREG / S_IFDIR, under S_IFMT) with the
/// permission bits. `S_IF*` are `mode_t` (u16 on macOS, u32 on Linux); widen without a per-OS cast
/// lint.
#[allow(clippy::unnecessary_cast)]
fn reg_mode() -> u32 {
    (libc::S_IFREG | 0o644) as u32
}
#[allow(clippy::unnecessary_cast)]
fn dir_mode() -> u32 {
    (libc::S_IFDIR | 0o755) as u32
}

fn snapshot(tree: &BTreeMap<PathBuf, VNode>, dir: &Path) -> Vec<DirEntry> {
    // readdir(3): a directory always lists "." and ".."; d_type is DT_DIR / DT_REG (man 2
    // getdents64 documents the DT_* set).
    let mut entries = vec![
        DirEntry {
            name: b".".to_vec(),
            ino: ino_of(dir),
            dtype: libc::DT_DIR,
        },
        DirEntry {
            name: b"..".to_vec(),
            ino: ino_of(dir),
            dtype: libc::DT_DIR,
        },
    ];
    for (path, node) in tree.iter() {
        if path.parent() == Some(dir)
            && let Some(name) = path.file_name()
        {
            let dtype = match node {
                VNode::Dir => libc::DT_DIR,
                VNode::File(_) => libc::DT_REG,
            };
            entries.push(DirEntry {
                name: name.as_encoded_bytes().to_vec(),
                ino: ino_of(path),
                dtype,
            });
        }
    }
    entries
}

pub(crate) fn fill_dirent(dst: &mut Dirent, name: &[u8], ino: u64, dtype: u8) {
    // man 2 getdents64 / dirent(5): d_ino is the inode, d_reclen the record length, d_type the
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

fn mode_size_nlink(node: &VNode) -> (u32, u64, u64) {
    match node {
        VNode::File(bytes) => (reg_mode(), bytes.len() as u64, 1),
        VNode::Dir => (dir_mode(), 0, 2),
    }
}

/// Fills a caller `struct statx` by writing the fixed kernel-ABI field offsets directly, so it is
/// correct regardless of which `libc` version std was built against (the crate's `libc::statx` can
/// disagree with std's). Layout and the STATX_* result-mask bits are from man 2 statx /
/// `<linux/stat.h>`: `struct statx` is 256 bytes; the buffer std passes is that size.
#[cfg(target_os = "linux")]
pub(crate) fn fill_statx(buf: *mut u8, mode: u32, size: u64, ino: u64, nlink: u64) -> Option<FsResult> {
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
                | libc::STATX_NLINK,
        );
        put_u32(4, 4096); // stx_blksize
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
