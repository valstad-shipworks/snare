//! How the tester frames the byte stream into messages.

/// A message type the tester reads from and writes to the code under test.
///
/// [`parse`](Packet::parse) pulls one message off the front of `buf` and removes its bytes,
/// returning `None` when a whole message is not yet present. Over TCP `buf` accumulates the byte
/// stream; over UDP it holds one datagram, parsed until `parse` returns `None` (any remainder is
/// dropped with the datagram). [`to_bytes`](Packet::to_bytes) renders a message for sending.
///
/// `Clone` lets several handlers each see a message and a tester record it.
pub trait Packet: Clone + Sized + Send + 'static {
    /// Removes one whole message from the front of `buf` and returns it; `None`, leaving `buf`
    /// untouched, while the message is still incomplete.
    fn parse(buf: &mut Vec<u8>) -> Option<Self>;
    /// The message's bytes on the wire, ready to send.
    fn to_bytes(&self) -> Vec<u8>;
}

/// Every readable byte as one message, and back. A tester using this sees whatever chunks the
/// stream delivers, with no framing of its own.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bytes(pub Vec<u8>);

impl Packet for Bytes {
    /// Takes everything buffered; `None` only when nothing is.
    fn parse(buf: &mut Vec<u8>) -> Option<Self> {
        if buf.is_empty() {
            None
        } else {
            Some(Bytes(std::mem::take(buf)))
        }
    }

    /// The bytes as they are.
    fn to_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }
}

/// A newline-delimited text message (the trailing `\n` is not part of the value).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Line(pub String);

impl Packet for Line {
    /// Takes bytes up to and including the first `\n`, dropping it; invalid UTF-8 becomes
    /// U+FFFD. A `\r` before the `\n` is kept as part of the value.
    fn parse(buf: &mut Vec<u8>) -> Option<Self> {
        let end = buf.iter().position(|&b| b == b'\n')?;
        let line: Vec<u8> = buf.drain(..=end).collect();
        Some(Line(
            String::from_utf8_lossy(&line[..line.len() - 1]).into_owned(),
        ))
    }

    /// The text followed by one `\n`.
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.0.clone().into_bytes();
        bytes.push(b'\n');
        bytes
    }
}

/// The byte string that ends each [`Delimited`] frame. Implement it on a marker type for a
/// delimiter snare does not provide:
///
/// ```
/// struct Etx;
/// impl snare::Delimiter for Etx {
///     const DELIMITER: &'static [u8] = b"\x03";
/// }
/// type EtxFrame = snare::Delimited<Etx>;
/// ```
pub trait Delimiter: Send + 'static {
    /// The delimiter's bytes; never empty.
    const DELIMITER: &'static [u8];
}

/// Frames end with `\n`.
#[derive(Debug)]
pub struct Lf;
impl Delimiter for Lf {
    const DELIMITER: &'static [u8] = b"\n";
}

/// Frames end with `\r`, as a Wenglor weCat3D scanner's text commands do.
#[derive(Debug)]
pub struct Cr;
impl Delimiter for Cr {
    const DELIMITER: &'static [u8] = b"\r";
}

/// Frames end with `\r\n`, as FANUC Remote Motion Interface JSON packets do (B-84184EN/03 §2.2,
/// "Communication packets").
#[derive(Debug)]
pub struct CrLf;
impl Delimiter for CrLf {
    const DELIMITER: &'static [u8] = b"\r\n";
}

/// A frame ended by `D`'s delimiter, kept as the raw bytes it crossed the wire as, delimiter
/// included.
///
/// [`parse`](Packet::parse) takes everything up to and including the first occurrence of the
/// delimiter, so a frame split across reads waits for the rest and several frames in one read come
/// out one by one; over UDP a datagram may hold several frames, and a tail without a delimiter is
/// dropped with it. [`to_bytes`](Packet::to_bytes) sends the frame as it is, so a frame built with
/// [`new`](Delimited::new) carries exactly one delimiter.
pub struct Delimited<D: Delimiter = Lf> {
    frame: Vec<u8>,
    delimiter: std::marker::PhantomData<fn() -> D>,
}

impl<D: Delimiter> Delimited<D> {
    /// A frame of `body` followed by the delimiter.
    pub fn new(body: impl Into<Vec<u8>>) -> Self {
        let mut frame = body.into();
        frame.extend_from_slice(D::DELIMITER);
        Self::from_frame(frame)
    }

    /// A frame of exactly these bytes, sent as they are; they need not end with the delimiter.
    pub fn from_frame(frame: impl Into<Vec<u8>>) -> Self {
        Delimited {
            frame: frame.into(),
            delimiter: std::marker::PhantomData,
        }
    }

    /// The raw frame, delimiter included.
    pub fn frame(&self) -> &[u8] {
        &self.frame
    }

    /// The frame without its trailing delimiter.
    pub fn body(&self) -> &[u8] {
        self.frame.strip_suffix(D::DELIMITER).unwrap_or(&self.frame)
    }

    /// The body as text; invalid UTF-8 becomes U+FFFD.
    pub fn text(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(self.body())
    }

    /// Takes the raw frame.
    pub fn into_frame(self) -> Vec<u8> {
        self.frame
    }
}

impl<D: Delimiter> Clone for Delimited<D> {
    fn clone(&self) -> Self {
        Self::from_frame(self.frame.clone())
    }
}

impl<D: Delimiter> PartialEq for Delimited<D> {
    fn eq(&self, other: &Self) -> bool {
        self.frame == other.frame
    }
}

impl<D: Delimiter> Eq for Delimited<D> {}

impl<D: Delimiter> std::fmt::Debug for Delimited<D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Delimited")
            .field(&self.frame.escape_ascii().to_string())
            .finish()
    }
}

impl<D: Delimiter> Packet for Delimited<D> {
    /// Takes bytes up to and including the first delimiter. Panics if the delimiter is empty.
    fn parse(buf: &mut Vec<u8>) -> Option<Self> {
        let delimiter = D::DELIMITER;
        assert!(!delimiter.is_empty(), "a Delimiter must not be empty");
        let start = buf.windows(delimiter.len()).position(|w| w == delimiter)?;
        Some(Self::from_frame(
            buf.drain(..start + delimiter.len()).collect::<Vec<u8>>(),
        ))
    }

    /// The raw frame.
    fn to_bytes(&self) -> Vec<u8> {
        self.frame.clone()
    }
}

/// Byte order of a multi-byte length field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Endian {
    /// Most significant byte first (network byte order).
    Big,
    /// Least significant byte first.
    Little,
}

/// Where a [`LengthPrefixed`] frame's length field sits and how it gives the frame's length.
///
/// The field is the unsigned integer of `width` bytes (1, 2, 4 or 8) at byte `offset` of the frame,
/// in `endian` order; the whole frame, header included, is `field + adjust` bytes. So `adjust` is
/// the header and trailer size when the field counts the payload only, and 0 when it counts the
/// whole frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LengthField {
    /// Byte offset of the field from the start of the frame.
    pub offset: usize,
    /// Size of the field in bytes: 1, 2, 4 or 8.
    pub width: usize,
    /// Byte order of the field.
    pub endian: Endian,
    /// Signed amount added to the field's value to give the total frame length.
    pub adjust: i64,
}

impl LengthField {
    /// The total length of the frame at the front of `buf`, once enough of it is there to read
    /// the field. Panics on a width other than 1, 2, 4 or 8, or a field giving a frame shorter
    /// than the field's own end (the code under test sent a malformed frame).
    pub fn frame_len(&self, buf: &[u8]) -> Option<usize> {
        assert!(
            matches!(self.width, 1 | 2 | 4 | 8),
            "LengthField width must be 1, 2, 4 or 8 bytes, not {}",
            self.width
        );
        let end = self.offset + self.width;
        let field = buf.get(self.offset..end)?;
        let mut bytes = [0u8; 8];
        let value = match self.endian {
            Endian::Big => {
                bytes[8 - self.width..].copy_from_slice(field);
                u64::from_be_bytes(bytes)
            }
            Endian::Little => {
                bytes[..self.width].copy_from_slice(field);
                u64::from_le_bytes(bytes)
            }
        };
        let total = i128::from(value) + i128::from(self.adjust);
        assert!(
            total >= end as i128,
            "length field {value} at offset {} gives a {total}-byte frame, shorter than the \
             {end} bytes up to the end of the field",
            self.offset
        );
        Some(usize::try_from(total).unwrap_or(usize::MAX))
    }
}

/// Where the length field of `L`'s frames sits; see [`LengthPrefixed`].
pub trait FrameLength: Send + 'static {
    /// The length field.
    const FIELD: LengthField;
}

/// A frame whose length is read from a field in its header, kept as the raw bytes it crossed the
/// wire as, header included.
///
/// [`parse`](Packet::parse) waits until the field has arrived, then until the whole frame has, so a
/// frame split across reads is put back together and several frames in one read come out one by
/// one. Over UDP a datagram may hold several frames, and a frame never spans datagrams: an
/// incomplete tail is dropped with its datagram. [`to_bytes`](Packet::to_bytes) sends the frame
/// as it is; the length field is not rewritten.
///
/// Two framings from the driver crates, each declared once and then used as a tester's message
/// type. GE Fanuc SNP-X (FANUC HMI device option) as the `fanuc_ucl` client frames it: a 56-byte
/// message, little-endian, whose `u16` text length at byte 4 counts the text that follows it. And a
/// Leica AT960 GCOM socket frame as the `atlink` client frames it, `[0x02][type][len: u16 LE]
/// [payload][0x03]`, where the length counts the payload only, so the 4-byte header and the ETX
/// are added:
///
/// ```
/// use snare::{Endian, FrameLength, LengthField, LengthPrefixed};
///
/// struct Gcom;
/// impl FrameLength for Gcom {
///     const FIELD: LengthField =
///         LengthField { offset: 2, width: 2, endian: Endian::Little, adjust: 5 };
/// }
///
/// struct Snpx;
/// impl FrameLength for Snpx {
///     const FIELD: LengthField =
///         LengthField { offset: 4, width: 2, endian: Endian::Little, adjust: 56 };
/// }
///
/// type GcomFrame = LengthPrefixed<Gcom>;
/// type SnpxFrame = LengthPrefixed<Snpx>;
/// ```
pub struct LengthPrefixed<L: FrameLength> {
    frame: Vec<u8>,
    field: std::marker::PhantomData<fn() -> L>,
}

impl<L: FrameLength> LengthPrefixed<L> {
    /// A frame of exactly these bytes, sent as they are.
    pub fn new(frame: impl Into<Vec<u8>>) -> Self {
        LengthPrefixed {
            frame: frame.into(),
            field: std::marker::PhantomData,
        }
    }

    /// The raw frame, header included.
    pub fn frame(&self) -> &[u8] {
        &self.frame
    }

    /// The value of the frame's length field.
    pub fn length_field(&self) -> u64 {
        let f = L::FIELD;
        let total = f
            .frame_len(&self.frame)
            .expect("frame shorter than its length field");
        (total as i128 - i128::from(f.adjust)) as u64
    }

    /// Takes the raw frame.
    pub fn into_frame(self) -> Vec<u8> {
        self.frame
    }
}

impl<L: FrameLength> Clone for LengthPrefixed<L> {
    fn clone(&self) -> Self {
        Self::new(self.frame.clone())
    }
}

impl<L: FrameLength> PartialEq for LengthPrefixed<L> {
    fn eq(&self, other: &Self) -> bool {
        self.frame == other.frame
    }
}

impl<L: FrameLength> Eq for LengthPrefixed<L> {}

impl<L: FrameLength> std::fmt::Debug for LengthPrefixed<L> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("LengthPrefixed").field(&self.frame).finish()
    }
}

impl<L: FrameLength> Packet for LengthPrefixed<L> {
    /// Takes the whole frame once `L::FIELD` says it has arrived; panics as
    /// [`LengthField::frame_len`] does.
    fn parse(buf: &mut Vec<u8>) -> Option<Self> {
        let total = L::FIELD.frame_len(buf)?;
        if buf.len() < total {
            return None;
        }
        Some(Self::new(buf.drain(..total).collect::<Vec<u8>>()))
    }

    /// The raw frame.
    fn to_bytes(&self) -> Vec<u8> {
        self.frame.clone()
    }
}
