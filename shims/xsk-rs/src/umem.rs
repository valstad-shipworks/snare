//! The UMEM and the fill / completion queues.

use std::{
    borrow::Borrow,
    error::Error,
    fmt, io,
    num::NonZeroU32,
    sync::{Arc, Mutex},
};

use crate::config::UmemConfig;
use crate::emu::{Fabric, Region};
use crate::frame::{Data, DataMut, FrameDesc};

#[derive(Debug)]
struct UmemInner {
    region: Region,
    data_offset: usize,
    mtu: usize,
}

/// A region of contiguous memory divided into equal-sized frames, backing an AF_XDP
/// [`Socket`](crate::Socket).
#[derive(Debug, Clone)]
pub struct Umem {
    inner: Arc<UmemInner>,
}

impl Umem {
    /// Create a new `Umem` and the descriptors for each of its frames.
    ///
    /// `use_huge_pages` is accepted for API compatibility and ignored; the backing store is an
    /// ordinary heap allocation.
    pub fn new(
        config: UmemConfig,
        frame_count: NonZeroU32,
        _use_huge_pages: bool,
    ) -> Result<(Self, Vec<FrameDesc>), UmemCreateError> {
        let frame_size = config.frame_size().get() as usize;
        let data_offset = (config.xdp_headroom() + config.frame_headroom()) as usize;
        let mtu = config.mtu() as usize;
        let count = frame_count.get() as usize;

        let region = Region::new(count * frame_size);

        let mut descs = Vec::with_capacity(count);
        for i in 0..count {
            descs.push(FrameDesc::new(i * frame_size + data_offset));
        }

        let umem = Umem {
            inner: Arc::new(UmemInner {
                region,
                data_offset,
                mtu,
            }),
        };

        Ok((umem, descs))
    }

    /// The read-only packet data segment of the frame pointed at by `desc`.
    ///
    /// # Safety
    /// `desc` must describe a frame belonging to this `Umem`, and the frame must not be mutably
    /// accessed elsewhere while the returned view is live.
    pub unsafe fn data<'a>(&'a self, desc: &'a FrameDesc) -> Data<'a> {
        // SAFETY: `desc.addr` is a valid frame offset; `lengths.data` bytes were written there.
        let buf = unsafe { self.inner.region.slice(desc.addr, desc.lengths.data) };
        Data::new(buf)
    }

    /// The writeable packet data segment of the frame pointed at by `desc`.
    ///
    /// # Safety
    /// `desc` must describe a frame belonging to this `Umem`, and the frame must not be accessed
    /// elsewhere while the returned view is live.
    pub unsafe fn data_mut<'a>(&'a self, desc: &'a mut FrameDesc) -> DataMut<'a> {
        // SAFETY: `[addr, addr + mtu)` is this frame's data segment, exclusively borrowed here for
        // the lifetime of `desc`.
        let buf = unsafe { self.inner.region.slice_mut(desc.addr, self.inner.mtu) };
        DataMut::new(&mut desc.lengths.data, buf)
    }

    pub(crate) fn region(&self) -> &Region {
        &self.inner.region
    }

    #[allow(dead_code)]
    pub(crate) fn data_offset(&self) -> usize {
        self.inner.data_offset
    }
}

/// Transfers ownership of frames from user-space to the receive path, so they may be used to
/// receive packets.
#[derive(Debug)]
pub struct FillQueue {
    fabric: Arc<Mutex<Fabric>>,
}

impl FillQueue {
    pub(crate) fn new(fabric: Arc<Mutex<Fabric>>) -> Self {
        Self { fabric }
    }

    /// Offer the frames described by `descs` for receiving. Returns the number submitted.
    ///
    /// # Safety
    /// The frames must belong to the same [`Umem`] as the socket this queue came from, and must
    /// not be in use elsewhere.
    pub unsafe fn produce(&mut self, descs: &[FrameDesc]) -> usize {
        let mut fabric = self.fabric.lock().unwrap_or_else(|e| e.into_inner());
        for desc in descs {
            fabric.queue_fill(desc.addr);
        }
        descs.len()
    }

    /// Same as [`produce`](Self::produce) but for a single frame.
    ///
    /// # Safety
    /// See [`produce`](Self::produce).
    pub unsafe fn produce_one(&mut self, desc: &FrameDesc) -> usize {
        let mut fabric = self.fabric.lock().unwrap_or_else(|e| e.into_inner());
        fabric.queue_fill(desc.addr);
        1
    }
}

/// Transfers ownership of transmitted frames back to user-space once they have been sent.
#[derive(Debug)]
pub struct CompQueue {
    fabric: Arc<Mutex<Fabric>>,
}

impl CompQueue {
    pub(crate) fn new(fabric: Arc<Mutex<Fabric>>) -> Self {
        Self { fabric }
    }

    /// Update `descs` with the frames whose contents have been sent and may be reused. Returns the
    /// number of entries updated.
    ///
    /// # Safety
    /// The frames must belong to the same [`Umem`] as the socket this queue came from.
    pub unsafe fn consume(&mut self, descs: &mut [FrameDesc]) -> usize {
        let mut fabric = self.fabric.lock().unwrap_or_else(|e| e.into_inner());
        fabric.consume_comp(descs)
    }

    /// Same as [`consume`](Self::consume) but for a single frame.
    ///
    /// # Safety
    /// See [`consume`](Self::consume).
    pub unsafe fn consume_one(&mut self, desc: &mut FrameDesc) -> usize {
        let mut fabric = self.fabric.lock().unwrap_or_else(|e| e.into_inner());
        fabric.consume_comp(std::slice::from_mut(desc))
    }
}

/// Error detailing why [`Umem`] creation failed.
#[derive(Debug)]
pub struct UmemCreateError {
    reason: &'static str,
    err: io::Error,
}

impl fmt::Display for UmemCreateError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.reason)
    }
}

impl Error for UmemCreateError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.err.borrow())
    }
}
