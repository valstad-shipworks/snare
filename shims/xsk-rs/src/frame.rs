//! Frame descriptor and the read/write views over a frame's data segment.

use std::{
    io::{self, IoSlice, Write},
    ops::{Deref, DerefMut},
};

/// The length (in bytes) of data in a frame's packet data and headroom segments.
#[derive(Debug, Default, Clone, Copy)]
pub struct SegmentLengths {
    pub(crate) headroom: usize,
    pub(crate) data: usize,
}

impl SegmentLengths {
    /// Current length of the headroom segment.
    pub fn headroom(&self) -> usize {
        self.headroom
    }

    /// Current length of the packet data segment.
    pub fn data(&self) -> usize {
        self.data
    }
}

/// A [`Umem`](crate::Umem) frame descriptor.
///
/// `addr` is the byte offset from the start of the UMEM to the frame's packet data segment;
/// `lengths` records how much has been written to the frame.
#[derive(Debug, Clone, Copy, Default)]
pub struct FrameDesc {
    pub(crate) addr: usize,
    pub(crate) options: u32,
    pub(crate) lengths: SegmentLengths,
}

impl FrameDesc {
    pub(crate) fn new(addr: usize) -> Self {
        Self {
            addr,
            options: 0,
            lengths: SegmentLengths::default(),
        }
    }

    /// The starting address of the packet data segment of this frame.
    pub fn addr(&self) -> usize {
        self.addr
    }

    /// Current headroom and packet data lengths for this frame.
    pub fn lengths(&self) -> &SegmentLengths {
        &self.lengths
    }

    /// Frame options.
    pub fn options(&self) -> u32 {
        self.options
    }

    /// Set the frame options.
    pub fn set_options(&mut self, options: u32) {
        self.options = options
    }
}

/// Read-only packet data segment of a [`Umem`](crate::Umem) frame.
#[derive(Debug)]
pub struct Data<'umem> {
    contents: &'umem [u8],
}

impl<'umem> Data<'umem> {
    pub(crate) fn new(contents: &'umem [u8]) -> Self {
        Self { contents }
    }

    /// This segment's contents, up to its current length.
    pub fn contents(&self) -> &'umem [u8] {
        self.contents
    }
}

impl AsRef<[u8]> for Data<'_> {
    fn as_ref(&self) -> &[u8] {
        self.contents
    }
}

impl Deref for Data<'_> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.contents
    }
}

/// Writeable packet data segment of a [`Umem`](crate::Umem) frame.
#[derive(Debug)]
pub struct DataMut<'umem> {
    len: &'umem mut usize,
    buf: &'umem mut [u8],
}

impl<'umem> DataMut<'umem> {
    pub(crate) fn new(len: &'umem mut usize, buf: &'umem mut [u8]) -> Self {
        Self { len, buf }
    }

    /// This segment's contents, up to its current length.
    pub fn contents(&self) -> &[u8] {
        &self.buf[..*self.len]
    }

    /// A mutable view of this segment's contents, up to its current length.
    pub fn contents_mut(&mut self) -> &mut [u8] {
        &mut self.buf[..*self.len]
    }

    /// A cursor for writing to this segment. Writes advance the data length of the frame.
    pub fn cursor(&mut self) -> Cursor<'_> {
        Cursor::new(self.len, self.buf)
    }
}

impl AsRef<[u8]> for DataMut<'_> {
    fn as_ref(&self) -> &[u8] {
        self.contents()
    }
}

impl AsMut<[u8]> for DataMut<'_> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.contents_mut()
    }
}

impl Deref for DataMut<'_> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.contents()
    }
}

impl DerefMut for DataMut<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.contents_mut()
    }
}

/// Wraps a buffer and a write position, providing a [`Write`] impl that keeps the frame's data
/// length in step with what has been written.
#[derive(Debug)]
pub struct Cursor<'a> {
    pos: &'a mut usize,
    buf: &'a mut [u8],
}

impl<'a> Cursor<'a> {
    pub(crate) fn new(pos: &'a mut usize, buf: &'a mut [u8]) -> Self {
        Self { pos, buf }
    }

    /// The cursor's current write position.
    pub fn pos(&self) -> usize {
        *self.pos
    }

    /// Sets the cursor's write position, clamped to the buffer length.
    pub fn set_pos(&mut self, pos: usize) {
        *self.pos = pos.min(self.buf.len());
    }

    /// The length of the underlying buffer.
    pub fn buf_len(&mut self) -> usize {
        self.buf.len()
    }

    /// Fills the buffer with zeroes and resets the write position.
    pub fn zero_out(&mut self) {
        self.buf.fill(0);
        self.set_pos(0);
    }
}

impl Write for Cursor<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let pos = (*self.pos).min(self.buf.len());
        let amt = (&mut self.buf[pos..]).write(buf)?;
        *self.pos += amt;
        Ok(amt)
    }

    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        let mut nwritten = 0;
        for buf in bufs {
            let n = self.write(buf)?;
            nwritten += n;
            if n < buf.len() {
                break;
            }
        }
        Ok(nwritten)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
