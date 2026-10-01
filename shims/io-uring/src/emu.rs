//! In-process emulation of the three kernel touchpoints the crate uses: `io_uring_setup`, the
//! ring `mmap`, and `io_uring_enter`. Everything else in the crate — the submission and completion
//! queues, the opcode builders, the types — runs unchanged against plain memory these functions
//! hand out.
//!
//! On `io_uring_enter`, each submitted SQE is executed synchronously through `libc` (so an
//! interposer sees an ordinary `read`/`recv`/`accept`/… call) and a completion is written back.
//! This makes `io-uring`-based code runnable and observable under the harness. It is not a faithful
//! kernel: submission is synchronous, and the coverage below is the common file and socket
//! opcodes. Unsupported opcodes complete with `-EINVAL`, and registration returns `-ENOSYS`.
//!
//! Not emulated: SQPOLL, IOPOLL, registered buffers/files (Fixed), multishot, linked SQEs,
//! provided-buffer rings, and `IORING_OP_*` beyond the set in `execute`.

use std::collections::HashMap;
use std::ffi::{c_int, c_uint, c_void};
use std::io;
use std::sync::Mutex;

use crate::sys;

/// Our chosen ring layout. We fill `io_uring_params` with these, so the crate's queues read and
/// write exactly where we expect.
const HEAD: u32 = 0;
const TAIL: u32 = 4;
const RING_MASK: u32 = 8;
const RING_ENTRIES: u32 = 12;
const SQ_FLAGS: u32 = 16;
const SQ_DROPPED: u32 = 20;
const CQ_OVERFLOW: u32 = 16;
const CQ_FLAGS: u32 = 20;
const ARRAY: u32 = 64;
const CQES: u32 = 64;

const SQE_SIZE: usize = 64;
const CQE_SIZE: usize = 16;

/// A fixed view over the 64-byte `io_uring_sqe`, avoiding the bindgen unions. The offsets are the
/// stable kernel ABI.
#[repr(C)]
#[derive(Clone, Copy)]
struct Sqe {
    opcode: u8,
    flags: u8,
    ioprio: u16,
    fd: i32,
    off: u64,
    addr: u64,
    len: u32,
    op_flags: u32,
    user_data: u64,
    buf: u16,
    personality: u16,
    splice_fd_in: i32,
    addr3: u64,
    _pad2: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Cqe {
    user_data: u64,
    res: i32,
    flags: u32,
}

struct Ring {
    sq: Box<[u8]>,
    cq: Box<[u8]>,
    sqes: Box<[u8]>,
    cq_entries: u32,
    sq_mask: u32,
    cq_mask: u32,
    /// The passthrough mode the ring was set up in. Submitting on it in the other mode would mix
    /// the emulated ring with real-OS I/O (or vice versa), so it panics instead.
    real: bool,
}

static RINGS: Mutex<Option<HashMap<c_int, Ring>>> = Mutex::new(None);

fn with_rings<R>(f: impl FnOnce(&mut HashMap<c_int, Ring>) -> R) -> R {
    let mut guard = RINGS.lock().unwrap_or_else(|e| e.into_inner());
    f(guard.get_or_insert_with(HashMap::new))
}

unsafe fn store_u32(buf: &mut [u8], off: u32, value: u32) {
    let bytes = value.to_ne_bytes();
    buf[off as usize..off as usize + 4].copy_from_slice(&bytes);
}

unsafe fn load_u32(buf: &[u8], off: u32) -> u32 {
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&buf[off as usize..off as usize + 4]);
    u32::from_ne_bytes(bytes)
}

pub(crate) unsafe fn io_uring_setup(
    entries: c_uint,
    p: *mut sys::io_uring_params,
) -> io::Result<c_int> {
    // SAFETY: the crate always passes a valid, writable params pointer.
    let params = unsafe { &mut *p };
    let sq_entries = entries.max(1).next_power_of_two();
    let cq_entries = if params.flags & sys::IORING_SETUP_CQSIZE != 0 && params.cq_entries != 0 {
        params.cq_entries.next_power_of_two()
    } else {
        sq_entries * 2
    };

    let mut sq = vec![0u8; ARRAY as usize + sq_entries as usize * 4].into_boxed_slice();
    let cq = vec![0u8; CQES as usize + cq_entries as usize * CQE_SIZE].into_boxed_slice();
    let sqes = vec![0u8; sq_entries as usize * SQE_SIZE].into_boxed_slice();

    // SAFETY: offsets are within the buffer sized just above.
    unsafe {
        store_u32(&mut sq, RING_MASK, sq_entries - 1);
        store_u32(&mut sq, RING_ENTRIES, sq_entries);
    }
    let mut cq_init = cq;
    // SAFETY: as above for the CQ buffer.
    unsafe {
        store_u32(&mut cq_init, RING_MASK, cq_entries - 1);
        store_u32(&mut cq_init, RING_ENTRIES, cq_entries);
    }

    params.sq_entries = sq_entries;
    params.cq_entries = cq_entries;
    params.features = sys::IORING_FEAT_NODROP | sys::IORING_FEAT_SUBMIT_STABLE;
    params.sq_off = sys::io_sqring_offsets {
        head: HEAD,
        tail: TAIL,
        ring_mask: RING_MASK,
        ring_entries: RING_ENTRIES,
        flags: SQ_FLAGS,
        dropped: SQ_DROPPED,
        array: ARRAY,
        ..Default::default()
    };
    params.cq_off = sys::io_cqring_offsets {
        head: HEAD,
        tail: TAIL,
        ring_mask: RING_MASK,
        ring_entries: RING_ENTRIES,
        overflow: CQ_OVERFLOW,
        cqes: CQES,
        flags: CQ_FLAGS,
        ..Default::default()
    };

    // A real fd so the crate's `OwnedFd` and its eventual `close` behave; we key the ring on it and
    // never actually io_uring it.
    // SAFETY: eventfd with valid flags.
    let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    with_rings(|rings| {
        rings.insert(
            fd,
            Ring {
                sq,
                cq: cq_init,
                sqes,
                cq_entries,
                sq_mask: sq_entries - 1,
                cq_mask: cq_entries - 1,
                real: snare_interpose::in_passthrough(),
            },
        );
    });
    Ok(fd)
}

/// Returns a pointer into the ring's backing memory for the region the crate asks to map.
pub(crate) fn map(fd: c_int, offset: i64) -> io::Result<*mut c_void> {
    with_rings(|rings| {
        let ring = rings
            .get_mut(&fd)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))?;
        let buf = match offset as u32 {
            sys::IORING_OFF_SQ_RING => &mut ring.sq,
            sys::IORING_OFF_CQ_RING => &mut ring.cq,
            sys::IORING_OFF_SQES => &mut ring.sqes,
            _ => return Err(io::Error::from_raw_os_error(libc::EINVAL)),
        };
        Ok(buf.as_mut_ptr().cast())
    })
}

pub(crate) unsafe fn io_uring_enter(
    fd: c_int,
    _to_submit: c_uint,
    _min_complete: c_uint,
    _flags: c_uint,
    _arg: *const c_void,
    _size: usize,
) -> io::Result<c_int> {
    with_rings(|rings| {
        let ring = rings
            .get_mut(&fd)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))?;
        assert_eq!(
            ring.real,
            snare_interpose::in_passthrough(),
            "io_uring ring used in a different passthrough mode than it was created in \
             (snare::real mismatch): the emulated ring and real-OS I/O would be mixed"
        );

        // SAFETY: the SQ/CQ buffers are laid out at the offsets we reported in params.
        let submitted = unsafe { drain(ring) };
        Ok(submitted as c_int)
    })
}

pub(crate) fn register(_fd: c_int, _opcode: c_uint) -> io::Result<c_int> {
    Err(io::Error::from_raw_os_error(libc::ENOSYS))
}

/// Consumes every pending SQE, executes it, and posts a completion. Returns the count consumed.
unsafe fn drain(ring: &mut Ring) -> u32 {
    // SAFETY (whole function): the ring buffers are sized and laid out by `io_uring_setup`, and the
    // SQE/CQE views match the kernel ABI.
    unsafe {
        let sq_head = load_u32(&ring.sq, HEAD);
        let sq_tail = load_u32(&ring.sq, TAIL);
        let sq_mask = ring.sq_mask;
        let array = ring.sq.as_ptr().add(ARRAY as usize).cast::<u32>();

        let mut count = 0u32;
        let mut pos = sq_head;
        while pos != sq_tail {
            let idx = array.add((pos & sq_mask) as usize).read_volatile() & sq_mask;
            let sqe = ring
                .sqes
                .as_ptr()
                .add(idx as usize * SQE_SIZE)
                .cast::<Sqe>()
                .read();
            let res = execute(&sqe);
            post(ring, sqe.user_data, res);
            pos = pos.wrapping_add(1);
            count += 1;
        }
        store_u32(&mut ring.sq, HEAD, sq_tail);
        count
    }
}

/// Writes one completion into the CQ ring.
unsafe fn post(ring: &mut Ring, user_data: u64, res: i32) {
    // SAFETY: CQ layout as reported in params; we drop completions past capacity (NODROP is a
    // best-effort claim here).
    unsafe {
        let cq_head = load_u32(&ring.cq, HEAD);
        let cq_tail = load_u32(&ring.cq, TAIL);
        if cq_tail.wrapping_sub(cq_head) >= ring.cq_entries {
            let overflow = load_u32(&ring.cq, CQ_OVERFLOW).wrapping_add(1);
            store_u32(&mut ring.cq, CQ_OVERFLOW, overflow);
            return;
        }
        let slot = (cq_tail & ring.cq_mask) as usize;
        let cqe = Cqe {
            user_data,
            res,
            flags: 0,
        };
        let base = ring
            .cq
            .as_mut_ptr()
            .add(CQES as usize + slot * CQE_SIZE)
            .cast::<Cqe>();
        base.write(cqe);
        store_u32(&mut ring.cq, TAIL, cq_tail.wrapping_add(1));
    }
}

/// Maps a libc return (`-1` + errno, or a value) to io_uring's completion convention: a negative
/// errno on failure, the value on success.
fn result(ret: isize) -> i32 {
    if ret == -1 {
        // SAFETY: valid on the calling thread.
        -(unsafe { *libc::__errno_location() })
    } else {
        ret as i32
    }
}

/// Executes one SQE via libc. Opcode numbers are the stable `IORING_OP_*` ABI.
unsafe fn execute(sqe: &Sqe) -> i32 {
    let fd = sqe.fd;
    let addr = sqe.addr as *mut c_void;
    let len = sqe.len as usize;
    let off = sqe.off;
    // SAFETY (whole function): the submitting code owns the buffers and fds an SQE points at,
    // exactly as it would for a real ring.
    unsafe {
        match sqe.opcode {
            0 => 0, // NOP
            22 => {
                // READ
                if off == u64::MAX {
                    result(libc::read(fd, addr, len))
                } else {
                    result(libc::pread(fd, addr, len, off as libc::off_t))
                }
            }
            23 => {
                // WRITE
                if off == u64::MAX {
                    result(libc::write(fd, addr, len))
                } else {
                    result(libc::pwrite(fd, addr, len, off as libc::off_t))
                }
            }
            1 => {
                // READV
                let iov = addr.cast::<libc::iovec>();
                if off == u64::MAX {
                    result(libc::readv(fd, iov, sqe.len as c_int))
                } else {
                    result(libc::preadv(fd, iov, sqe.len as c_int, off as libc::off_t))
                }
            }
            2 => {
                // WRITEV
                let iov = addr.cast::<libc::iovec>();
                if off == u64::MAX {
                    result(libc::writev(fd, iov, sqe.len as c_int))
                } else {
                    result(libc::pwritev(fd, iov, sqe.len as c_int, off as libc::off_t))
                }
            }
            3 => {
                // FSYNC (op_flags bit 0 = datasync)
                if sqe.op_flags & 1 != 0 {
                    result(libc::fdatasync(fd) as isize)
                } else {
                    result(libc::fsync(fd) as isize)
                }
            }
            26 => result(libc::send(fd, addr, len, sqe.op_flags as c_int)), // SEND
            27 => result(libc::recv(fd, addr, len, sqe.op_flags as c_int)), // RECV
            9 => result(libc::sendmsg(fd, addr.cast(), sqe.op_flags as c_int)), // SENDMSG
            10 => result(libc::recvmsg(fd, addr.cast(), sqe.op_flags as c_int)), // RECVMSG
            13 => {
                // ACCEPT: addr = sockaddr*, off = socklen_t*, op_flags = accept4 flags
                result(libc::accept4(
                    fd,
                    addr.cast(),
                    off as *mut libc::socklen_t,
                    sqe.op_flags as c_int,
                ) as isize)
            }
            16 => {
                // CONNECT: addr = sockaddr*, off = addrlen
                result(libc::connect(fd, addr.cast(), off as libc::socklen_t) as isize)
            }
            19 => result(libc::close(fd) as isize), // CLOSE
            34 => result(libc::shutdown(fd, sqe.len as c_int) as isize), // SHUTDOWN (how in len)
            6 => {
                // POLL_ADD: a real ring registers the poll and completes asynchronously. Emulation
                // is synchronous, so check readiness with a zero timeout and report it now — a
                // blocking (-1) poll here would hang enter() and, since it runs under the RINGS
                // lock, deadlock every other ring.
                let mut pfd = libc::pollfd {
                    fd,
                    events: sqe.op_flags as i16,
                    revents: 0,
                };
                let ret = libc::poll(&mut pfd, 1, 0);
                if ret < 0 {
                    result(-1)
                } else {
                    pfd.revents as i32
                }
            }
            11 => {
                // TIMEOUT: addr = *timespec (kernel_timespec is two i64, same layout as timespec).
                let ts = addr.cast::<libc::timespec>();
                if !ts.is_null() {
                    libc::nanosleep(ts, std::ptr::null_mut());
                }
                -libc::ETIME
            }
            _ => -libc::EINVAL,
        }
    }
}
