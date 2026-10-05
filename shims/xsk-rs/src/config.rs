//! [`Umem`](crate::Umem) and [`Socket`](crate::Socket) configuration.

use bitflags::bitflags;
use std::{
    convert::TryFrom,
    error, fmt,
    ffi::{CStr, CString, NulError},
    str::FromStr,
};

pub const XDP_UMEM_MIN_CHUNK_SIZE: u32 = 2048;

const DEFAULT_FRAME_SIZE: u32 = 4096;
const XDP_PACKET_HEADROOM: u32 = 256;
const DEFAULT_FRAME_HEADROOM: u32 = 0;
const DEFAULT_PROD_NUM_DESCS: u32 = 2048;
const DEFAULT_CONS_NUM_DESCS: u32 = 2048;

bitflags! {
    /// Libbpf flags.
    #[derive(Debug, Clone, Copy)]
    pub struct LibxdpFlags: u32 {
        /// Set to avoid loading of default XDP program on socket creation.
        const XSK_LIBXDP_FLAGS_INHIBIT_PROG_LOAD = 1;
    }
}

bitflags! {
    /// XDP flags.
    #[derive(Debug, Clone, Copy)]
    pub struct XdpFlags: u32 {
        /// Fail if an XDP program is already loaded on the target interface.
        const XDP_FLAGS_UPDATE_IF_NOEXIST = 1;
        /// Force generic/SKB mode.
        const XDP_FLAGS_SKB_MODE = 2;
        /// Force driver mode.
        const XDP_FLAGS_DRV_MODE = 4;
        /// Offload to hardware.
        const XDP_FLAGS_HW_MODE = 8;
    }
}

bitflags! {
    /// Bind flags.
    #[derive(Debug, Clone, Copy)]
    pub struct BindFlags: u16 {
        /// Forces copy-mode.
        const XDP_COPY = 2;
        /// Forces zero-copy mode.
        const XDP_ZEROCOPY = 4;
        /// If set, the fill and TX queues need waking up to continue processing frames.
        const XDP_USE_NEED_WAKEUP = 8;
    }
}

/// A device interface name.
#[derive(Debug, Clone)]
pub struct Interface(CString);

impl Interface {
    /// Creates a new `Interface` instance.
    pub fn new(name: CString) -> Self {
        Self(name)
    }

    #[allow(dead_code)]
    pub(crate) fn as_cstr(&self) -> &CStr {
        &self.0
    }
}

impl FromStr for Interface {
    type Err = NulError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.as_bytes().try_into()
    }
}

impl TryFrom<&[u8]> for Interface {
    type Error = NulError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        CString::new(bytes).map(Self)
    }
}

impl TryFrom<Vec<u8>> for Interface {
    type Error = NulError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        CString::new(bytes).map(Self)
    }
}

/// A ring's buffer size. Must be a power of two.
#[derive(Debug, Clone, Copy)]
pub struct QueueSize(u32);

impl QueueSize {
    /// Create a new `QueueSize` instance. Fails if `size` is not a power of two.
    pub fn new(size: u32) -> Result<Self, QueueSizeError> {
        if size == 0 || !size.is_power_of_two() {
            Err(QueueSizeError(size))
        } else {
            Ok(Self(size))
        }
    }

    /// The queue size.
    pub fn get(&self) -> u32 {
        self.0
    }
}

impl TryFrom<u32> for QueueSize {
    type Error = QueueSizeError;

    fn try_from(size: u32) -> Result<Self, Self::Error> {
        QueueSize::new(size)
    }
}

/// Error signifying incorrect queue size.
#[derive(Debug)]
pub struct QueueSizeError(u32);

impl fmt::Display for QueueSizeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "expected a power of two as queue size, got {}", self.0)
    }
}

impl error::Error for QueueSizeError {}

/// The size of a [`Umem`](crate::Umem) frame.
#[derive(Debug, Clone, Copy)]
pub struct FrameSize(u32);

impl FrameSize {
    /// Create a new `FrameSize`. Fails if smaller than [`XDP_UMEM_MIN_CHUNK_SIZE`].
    pub fn new(size: u32) -> Result<Self, FrameSizeError> {
        if size < XDP_UMEM_MIN_CHUNK_SIZE {
            Err(FrameSizeError(size))
        } else {
            Ok(Self(size))
        }
    }

    /// The frame size.
    pub fn get(&self) -> u32 {
        self.0
    }
}

impl TryFrom<u32> for FrameSize {
    type Error = FrameSizeError;

    fn try_from(size: u32) -> Result<Self, Self::Error> {
        FrameSize::new(size)
    }
}

/// Error signifying incorrect frame size.
#[derive(Debug)]
pub struct FrameSizeError(u32);

impl fmt::Display for FrameSizeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "expected frame size >= {}, got {}",
            XDP_UMEM_MIN_CHUNK_SIZE, self.0
        )
    }
}

impl error::Error for FrameSizeError {}

/// Builder for a [`SocketConfig`](SocketConfig).
#[derive(Debug, Default, Clone, Copy)]
pub struct SocketConfigBuilder {
    config: SocketConfig,
}

impl SocketConfigBuilder {
    /// Creates a new builder with no flags set and libbpf default queue sizes.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the [`RxQueue`](crate::RxQueue) size.
    pub fn rx_queue_size(&mut self, size: QueueSize) -> &mut Self {
        self.config.rx_queue_size = size;
        self
    }

    /// Set the [`TxQueue`](crate::TxQueue) size.
    pub fn tx_queue_size(&mut self, size: QueueSize) -> &mut Self {
        self.config.tx_queue_size = size;
        self
    }

    /// Set the [`LibxdpFlags`].
    pub fn libxdp_flags(&mut self, flags: LibxdpFlags) -> &mut Self {
        self.config.libxdp_flags = flags;
        self
    }

    /// Set the [`XdpFlags`].
    pub fn xdp_flags(&mut self, flags: XdpFlags) -> &mut Self {
        self.config.xdp_flags = flags;
        self
    }

    /// Set the socket [`BindFlags`].
    pub fn bind_flags(&mut self, flags: BindFlags) -> &mut Self {
        self.config.bind_flags = flags;
        self
    }

    /// Build a [`SocketConfig`] from the values set in this builder.
    pub fn build(&self) -> SocketConfig {
        self.config
    }
}

/// Config for an AF_XDP [`Socket`](crate::Socket).
#[derive(Debug, Clone, Copy)]
pub struct SocketConfig {
    rx_queue_size: QueueSize,
    tx_queue_size: QueueSize,
    libxdp_flags: LibxdpFlags,
    xdp_flags: XdpFlags,
    bind_flags: BindFlags,
}

impl SocketConfig {
    /// Creates a [`SocketConfigBuilder`].
    pub fn builder() -> SocketConfigBuilder {
        SocketConfigBuilder::new()
    }

    /// The socket's [`RxQueue`](crate::RxQueue) size.
    pub fn rx_queue_size(&self) -> QueueSize {
        self.rx_queue_size
    }

    /// The socket's [`TxQueue`](crate::TxQueue) size.
    pub fn tx_queue_size(&self) -> QueueSize {
        self.tx_queue_size
    }

    /// The [`LibxdpFlags`] set.
    pub fn libxdp_flags(&self) -> &LibxdpFlags {
        &self.libxdp_flags
    }

    /// The [`XdpFlags`] set.
    pub fn xdp_flags(&self) -> &XdpFlags {
        &self.xdp_flags
    }

    /// The [`BindFlags`] set.
    pub fn bind_flags(&self) -> &BindFlags {
        &self.bind_flags
    }
}

impl Default for SocketConfig {
    fn default() -> Self {
        Self {
            rx_queue_size: QueueSize(DEFAULT_CONS_NUM_DESCS),
            tx_queue_size: QueueSize(DEFAULT_PROD_NUM_DESCS),
            libxdp_flags: LibxdpFlags::empty(),
            xdp_flags: XdpFlags::empty(),
            bind_flags: BindFlags::empty(),
        }
    }
}

/// Builder for a [`UmemConfig`](UmemConfig).
#[derive(Debug, Default, Clone, Copy)]
pub struct UmemConfigBuilder {
    config: UmemConfig,
}

impl UmemConfigBuilder {
    /// Creates a new builder with libbpf default sizes.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the frame size.
    pub fn frame_size(&mut self, size: FrameSize) -> &mut Self {
        self.config.frame_size = size;
        self
    }

    /// Set the [`FillQueue`](crate::FillQueue) size.
    pub fn fill_queue_size(&mut self, size: QueueSize) -> &mut Self {
        self.config.fill_queue_size = size;
        self
    }

    /// Set the [`CompQueue`](crate::CompQueue) size.
    pub fn comp_queue_size(&mut self, size: QueueSize) -> &mut Self {
        self.config.comp_queue_size = size;
        self
    }

    /// Set the frame headroom available to the user.
    pub fn frame_headroom(&mut self, headroom: u32) -> &mut Self {
        self.config.frame_headroom = headroom;
        self
    }

    /// Build a [`UmemConfig`], failing if the total headroom exceeds the frame size.
    pub fn build(&self) -> Result<UmemConfig, UmemConfigBuilderError> {
        let frame_size = self.config.frame_size.get();
        let total_headroom = XDP_PACKET_HEADROOM + self.config.frame_headroom;

        if total_headroom > frame_size {
            Err(UmemConfigBuilderError {
                frame_size,
                total_headroom,
            })
        } else {
            Ok(self.config)
        }
    }
}

/// Config for a [`Umem`](crate::Umem).
#[derive(Debug, Clone, Copy)]
pub struct UmemConfig {
    frame_size: FrameSize,
    fill_queue_size: QueueSize,
    comp_queue_size: QueueSize,
    frame_headroom: u32,
}

impl UmemConfig {
    /// Creates a new [`UmemConfigBuilder`] with libbpf default sizes.
    pub fn builder() -> UmemConfigBuilder {
        UmemConfigBuilder::new()
    }

    /// The size of each frame in the [`Umem`](crate::Umem).
    pub fn frame_size(&self) -> FrameSize {
        self.frame_size
    }

    /// The [`FillQueue`](crate::FillQueue) size.
    pub fn fill_queue_size(&self) -> QueueSize {
        self.fill_queue_size
    }

    /// The [`CompQueue`](crate::CompQueue) size.
    pub fn comp_queue_size(&self) -> QueueSize {
        self.comp_queue_size
    }

    /// The frame headroom reserved for the XDP program.
    pub fn xdp_headroom(&self) -> u32 {
        XDP_PACKET_HEADROOM
    }

    /// The frame headroom available to the user.
    pub fn frame_headroom(&self) -> u32 {
        self.frame_headroom
    }

    /// The length of the packet data segment of the frame.
    pub fn mtu(&self) -> u32 {
        self.frame_size.get() - (self.xdp_headroom() + self.frame_headroom)
    }
}

impl Default for UmemConfig {
    fn default() -> Self {
        Self {
            frame_size: FrameSize(DEFAULT_FRAME_SIZE),
            fill_queue_size: QueueSize(DEFAULT_PROD_NUM_DESCS),
            comp_queue_size: QueueSize(DEFAULT_CONS_NUM_DESCS),
            frame_headroom: DEFAULT_FRAME_HEADROOM,
        }
    }
}

/// Error detailing why [`UmemConfig`] creation failed.
#[derive(Debug)]
pub struct UmemConfigBuilderError {
    frame_size: u32,
    total_headroom: u32,
}

impl fmt::Display for UmemConfigBuilderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "total headroom {} cannot be greater than frame size {}",
            self.total_headroom, self.frame_size
        )
    }
}

impl error::Error for UmemConfigBuilderError {}
