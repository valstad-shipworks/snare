//! The AF_XDP socket and its transmit / receive queues.

use std::{
    borrow::Borrow,
    error::Error,
    fmt, io,
    sync::{Arc, Mutex},
};

use crate::config::{Interface, SocketConfig};
use crate::emu::Fabric;
use crate::frame::FrameDesc;
use crate::umem::{CompQueue, FillQueue, Umem};

/// An AF_XDP socket.
#[derive(Debug)]
pub struct Socket;

impl Socket {
    /// Create and bind a new socket to a given interface and queue id using the underlying UMEM.
    ///
    /// The interface name and `queue_id` are accepted for API compatibility and ignored; the
    /// socket is backed by a `socketpair` that carries frames through libc `send`/`recv`. The
    /// fill/completion pair is always returned as `Some` (shared-UMEM binds are not modelled).
    ///
    /// # Safety
    /// Mirrors the real crate's contract: frames submitted to the returned queues must belong to
    /// `umem` and must not be used again until reclaimed.
    #[allow(clippy::new_ret_no_self)]
    #[allow(clippy::type_complexity)]
    pub unsafe fn new(
        _config: SocketConfig,
        umem: &Umem,
        _if_name: &Interface,
        _queue_id: u32,
    ) -> Result<(TxQueue, RxQueue, Option<(FillQueue, CompQueue)>), SocketCreateError> {
        let fabric = Fabric::new().map_err(|err| SocketCreateError {
            reason: "failed to create backing socketpair for AF_XDP shim",
            err,
        })?;
        let fabric = Arc::new(Mutex::new(fabric));

        let tx_q = TxQueue {
            umem: umem.clone(),
            fabric: fabric.clone(),
        };
        let rx_q = RxQueue {
            umem: umem.clone(),
            fabric: fabric.clone(),
        };
        let fq = FillQueue::new(fabric.clone());
        let cq = CompQueue::new(fabric);

        Ok((tx_q, rx_q, Some((fq, cq))))
    }
}

/// The transmitting side of an AF_XDP [`Socket`].
#[derive(Debug)]
pub struct TxQueue {
    umem: Umem,
    fabric: Arc<Mutex<Fabric>>,
}

impl TxQueue {
    /// Queue the frames described by `descs` for transmission. Returns the number queued.
    ///
    /// Frames are sent when [`wakeup`](Self::wakeup) is next called.
    ///
    /// # Safety
    /// The frames must belong to the same [`Umem`] as this queue and must not be in use elsewhere.
    pub unsafe fn produce(&mut self, descs: &[FrameDesc]) -> usize {
        let mut fabric = self.fabric.lock().unwrap_or_else(|e| e.into_inner());
        for desc in descs {
            fabric.queue_tx(desc.addr, desc.lengths.data);
        }
        descs.len()
    }

    /// Same as [`produce`](Self::produce) but for a single frame.
    ///
    /// # Safety
    /// See [`produce`](Self::produce).
    pub unsafe fn produce_one(&mut self, desc: &FrameDesc) -> usize {
        let mut fabric = self.fabric.lock().unwrap_or_else(|e| e.into_inner());
        fabric.queue_tx(desc.addr, desc.lengths.data);
        1
    }

    /// Same as [`produce`](Self::produce) but also flush the queued frames.
    ///
    /// # Safety
    /// See [`produce`](Self::produce).
    pub unsafe fn produce_and_wakeup(&mut self, descs: &[FrameDesc]) -> io::Result<usize> {
        let cnt = unsafe { self.produce(descs) };
        self.wakeup()?;
        Ok(cnt)
    }

    /// Flush queued frames to the kernel — here, out through `libc::send`.
    pub fn wakeup(&self) -> io::Result<()> {
        let mut fabric = self.fabric.lock().unwrap_or_else(|e| e.into_inner());
        fabric.flush_tx(self.umem.region())
    }

    /// Whether a [`wakeup`](Self::wakeup) is needed to continue processing queued frames. True
    /// while frames remain queued for transmission.
    pub fn needs_wakeup(&self) -> bool {
        let fabric = self.fabric.lock().unwrap_or_else(|e| e.into_inner());
        fabric.has_pending_tx()
    }
}

/// The receiving side of an AF_XDP [`Socket`].
#[derive(Debug)]
pub struct RxQueue {
    umem: Umem,
    fabric: Arc<Mutex<Fabric>>,
}

impl RxQueue {
    /// Update `descs` with frames that have received packets. Returns the number updated.
    ///
    /// # Safety
    /// The frames must belong to the same [`Umem`] as this queue.
    pub unsafe fn consume(&mut self, descs: &mut [FrameDesc]) -> usize {
        self.poll_and_consume(descs, 0).unwrap_or(0)
    }

    /// Poll for readability, then consume any received frames into `descs`.
    ///
    /// # Safety
    /// See [`consume`](Self::consume).
    pub unsafe fn poll_and_consume(
        &mut self,
        descs: &mut [FrameDesc],
        poll_timeout: i32,
    ) -> io::Result<usize> {
        let mut fabric = self.fabric.lock().unwrap_or_else(|e| e.into_inner());
        fabric.poll_consume(self.umem.region(), descs, poll_timeout)
    }
}

/// Error detailing why [`Socket`] creation failed.
#[derive(Debug)]
pub struct SocketCreateError {
    reason: &'static str,
    err: io::Error,
}

impl fmt::Display for SocketCreateError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.reason)
    }
}

impl Error for SocketCreateError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.err.borrow())
    }
}
