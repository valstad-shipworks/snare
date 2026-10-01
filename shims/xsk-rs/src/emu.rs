//! The in-process replacement for the kernel side of AF_XDP, and the libc seam every frame
//! crosses.
//!
//! [`Region`] is the UMEM: one heap allocation, divided into equal frames, addressed by the byte
//! offsets carried in a [`FrameDesc`](crate::FrameDesc). It never moves, so the read/write views
//! the [`Umem`](crate::Umem) hands out from `&self` stay valid — the same soundness contract the
//! real crate relies on for its `mmap`'d region: a frame must not be touched between submission to
//! a queue and its return.
//!
//! [`Fabric`] stands in for the kernel's four rings plus the NIC. `produce`/`produce_one` on the
//! TX side enqueue descriptors; [`Fabric::flush_tx`] is where a frame leaves this process — it
//! reads the frame's bytes out of the UMEM and hands them to `libc::send`. RX is the mirror:
//! [`Fabric::poll_consume`] pulls bytes in with `libc::recv` and copies them into a frame drawn
//! from the fill queue. An interposer that hooks `send`/`recv` sees exactly these frames.
//!
//! The backing fd is a `socketpair`, so with no interposer present a frame sent on the TX fd is
//! delivered to the RX fd: frames round-trip in-process. There is no ordering or timing fidelity
//! beyond FIFO, and a frame larger than the socket buffer, or a flush with a full buffer, is
//! reported like the real `wakeup` reports it — the transient errno is swallowed and the frame is
//! treated as handed off.

use std::alloc::{self, Layout};
use std::collections::VecDeque;
use std::ffi::c_void;
use std::io;
use std::os::unix::io::RawFd;
use std::ptr::NonNull;
use std::slice;

use crate::frame::FrameDesc;

const SOCKET_BUF_BYTES: libc::c_int = 16 * 1024 * 1024;

pub(crate) struct Region {
    ptr: NonNull<u8>,
    len: usize,
    layout: Layout,
}

unsafe impl Send for Region {}
unsafe impl Sync for Region {}

impl Region {
    pub(crate) fn new(len: usize) -> Self {
        let layout = Layout::from_size_align(len.max(1), 64).expect("valid UMEM layout");
        // SAFETY: layout has non-zero size.
        let raw = unsafe { alloc::alloc_zeroed(layout) };
        let ptr = NonNull::new(raw).unwrap_or_else(|| alloc::handle_alloc_error(layout));
        Self { ptr, len, layout }
    }

    /// # Safety
    /// `addr + len` must lie within the region.
    pub(crate) unsafe fn slice(&self, addr: usize, len: usize) -> &[u8] {
        unsafe { slice::from_raw_parts(self.ptr.as_ptr().add(addr), len) }
    }

    /// # Safety
    /// `addr + len` must lie within the region, and no other reference to these bytes may be live.
    #[allow(clippy::mut_from_ref)]
    pub(crate) unsafe fn slice_mut(&self, addr: usize, len: usize) -> &mut [u8] {
        unsafe { slice::from_raw_parts_mut(self.ptr.as_ptr().add(addr), len) }
    }
}

impl Drop for Region {
    fn drop(&mut self) {
        // SAFETY: `ptr`/`layout` are the pair returned by the matching `alloc_zeroed`.
        unsafe { alloc::dealloc(self.ptr.as_ptr(), self.layout) }
    }
}

impl std::fmt::Debug for Region {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Region").field("len", &self.len).finish()
    }
}

/// The four rings and the fd every frame crosses.
#[derive(Debug)]
pub(crate) struct Fabric {
    tx_fd: RawFd,
    rx_fd: RawFd,
    tx_pending: VecDeque<(usize, usize)>,
    comp: VecDeque<usize>,
    fill: VecDeque<usize>,
    /// The passthrough mode the socket was created in; TX/RX in the other mode would mix the
    /// emulated rings with real-OS I/O, so it panics instead.
    real: bool,
}

impl Fabric {
    fn check_mode(&self) {
        assert_eq!(
            self.real,
            snare_interpose::in_passthrough(),
            "AF_XDP socket used in a different passthrough mode than it was created in \
             (snare::real mismatch): the emulated rings and real-OS I/O would be mixed"
        );
    }

    pub(crate) fn new() -> io::Result<Self> {
        let mut fds = [0 as RawFd; 2];
        // SAFETY: `fds` is a valid array of two fds.
        let ret = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) };
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }

        set_buffers(fds[0]);
        set_buffers(fds[1]);

        Ok(Self {
            tx_fd: fds[0],
            rx_fd: fds[1],
            tx_pending: VecDeque::new(),
            comp: VecDeque::new(),
            fill: VecDeque::new(),
            real: snare_interpose::in_passthrough(),
        })
    }

    pub(crate) fn queue_tx(&mut self, addr: usize, len: usize) {
        self.tx_pending.push_back((addr, len));
    }

    pub(crate) fn has_pending_tx(&self) -> bool {
        !self.tx_pending.is_empty()
    }

    /// Drains the TX queue through `libc::send`, moving each frame's address to the completion
    /// queue once handed off.
    pub(crate) fn flush_tx(&mut self, region: &Region) -> io::Result<()> {
        self.check_mode();
        while let Some((addr, len)) = self.tx_pending.pop_front() {
            // SAFETY: `addr`/`len` describe a frame within this UMEM, written by the caller.
            let bytes = unsafe { region.slice(addr, len) };
            let ret = unsafe {
                libc::send(
                    self.tx_fd,
                    bytes.as_ptr() as *const c_void,
                    bytes.len(),
                    libc::MSG_DONTWAIT,
                )
            };
            if ret < 0 {
                let err = io::Error::last_os_error();
                match err.raw_os_error() {
                    Some(libc::ENOBUFS) | Some(libc::EAGAIN) | Some(libc::EBUSY)
                    | Some(libc::ENETDOWN) => {}
                    _ => return Err(err),
                }
            }
            self.comp.push_back(addr);
        }
        Ok(())
    }

    pub(crate) fn consume_comp(&mut self, descs: &mut [FrameDesc]) -> usize {
        let mut count = 0;
        for desc in descs.iter_mut() {
            match self.comp.pop_front() {
                Some(addr) => {
                    desc.addr = addr;
                    desc.lengths.data = 0;
                    desc.lengths.headroom = 0;
                    desc.options = 0;
                    count += 1;
                }
                None => break,
            }
        }
        count
    }

    pub(crate) fn queue_fill(&mut self, addr: usize) {
        self.fill.push_back(addr);
    }

    /// Reads frames in through `libc::recv`, placing each into a frame address taken from the fill
    /// queue. Stops at the first empty read or when the fill queue is exhausted.
    pub(crate) fn poll_consume(
        &mut self,
        region: &Region,
        descs: &mut [FrameDesc],
        poll_timeout: i32,
    ) -> io::Result<usize> {
        self.check_mode();
        if descs.is_empty() {
            return Ok(0);
        }

        if poll_timeout != 0 && !self.poll_readable(poll_timeout)? {
            return Ok(0);
        }

        let mut scratch = vec![0u8; 65536];
        let mut count = 0;

        for desc in descs.iter_mut() {
            if self.fill.is_empty() {
                break;
            }

            let ret = unsafe {
                libc::recv(
                    self.rx_fd,
                    scratch.as_mut_ptr() as *mut c_void,
                    scratch.len(),
                    libc::MSG_DONTWAIT,
                )
            };

            if ret < 0 {
                let err = io::Error::last_os_error();
                match err.raw_os_error() {
                    Some(libc::EAGAIN) => break,
                    _ => return Err(err),
                }
            }

            if ret == 0 {
                break;
            }

            let n = ret as usize;
            let addr = self.fill.pop_front().expect("fill queue checked non-empty");
            // SAFETY: `addr` is a frame in this UMEM; `n` bytes fit within a frame's data segment.
            let dst = unsafe { region.slice_mut(addr, n) };
            dst.copy_from_slice(&scratch[..n]);

            desc.addr = addr;
            desc.lengths.data = n;
            desc.lengths.headroom = 0;
            desc.options = 0;
            count += 1;
        }

        Ok(count)
    }

    fn poll_readable(&self, poll_timeout: i32) -> io::Result<bool> {
        let mut pfd = libc::pollfd {
            fd: self.rx_fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let ret = unsafe { libc::poll(&mut pfd, 1, poll_timeout) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(ret > 0 && (pfd.revents & libc::POLLIN) != 0)
    }
}

impl Drop for Fabric {
    fn drop(&mut self) {
        // SAFETY: both fds were created by `socketpair` and are owned here.
        unsafe {
            libc::close(self.tx_fd);
            libc::close(self.rx_fd);
        }
    }
}

fn set_buffers(fd: RawFd) {
    for opt in [libc::SO_SNDBUF, libc::SO_RCVBUF] {
        // Best-effort: larger buffers keep the in-process loopback from stalling under bursts.
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                opt,
                &SOCKET_BUF_BYTES as *const libc::c_int as *const c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }
}

#[cfg(test)]
mod passthrough_guard {
    use super::{Fabric, Region};

    #[test]
    #[should_panic(expected = "different passthrough mode")]
    fn tx_on_a_sim_socket_under_real_panics() {
        let region = Region::new(4096);
        let mut fabric = Fabric::new().unwrap(); // created in sim mode (not under real)
        fabric.queue_tx(0, 0);
        // Using it under `real` mixes the emulated ring with real-OS I/O → must panic.
        snare_interpose::real(|| fabric.flush_tx(&region)).unwrap();
    }
}
