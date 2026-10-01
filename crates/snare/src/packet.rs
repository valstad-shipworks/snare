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
    fn parse(buf: &mut Vec<u8>) -> Option<Self>;
    fn to_bytes(&self) -> Vec<u8>;
}

/// Every readable byte as one message, and back. A tester using this sees whatever chunks the
/// stream delivers, with no framing of its own.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bytes(pub Vec<u8>);

impl Packet for Bytes {
    fn parse(buf: &mut Vec<u8>) -> Option<Self> {
        if buf.is_empty() {
            None
        } else {
            Some(Bytes(std::mem::take(buf)))
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }
}

/// A newline-delimited text message (the trailing `\n` is not part of the value).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Line(pub String);

impl Packet for Line {
    fn parse(buf: &mut Vec<u8>) -> Option<Self> {
        let end = buf.iter().position(|&b| b == b'\n')?;
        let line: Vec<u8> = buf.drain(..=end).collect();
        Some(Line(
            String::from_utf8_lossy(&line[..line.len() - 1]).into_owned(),
        ))
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.0.clone().into_bytes();
        bytes.push(b'\n');
        bytes
    }
}
