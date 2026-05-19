use crate::framing::{self, FrameError};

// TODO: drbg for size sampling
//common::drbg,
//
// use futures::sink::{Sink, SinkExt};

use ptrs::trace;
use tokio_util::bytes::{Buf, BufMut};

pub(crate) const MESSAGE_OVERHEAD: usize = 2 + 1;
pub(crate) const MAX_MESSAGE_PAYLOAD_LENGTH: usize =
    framing::MAX_FRAME_PAYLOAD_LENGTH - MESSAGE_OVERHEAD;
// pub(crate) const MAX_MESSAGE_PADDING_LENGTH: usize = MAX_MESSAGE_PAYLOAD_LENGTH;

pub type MessageType = u8;
pub trait Message {
    type Output;
    fn as_pt(&self) -> MessageType;

    fn marshall<T: BufMut>(&self, dst: &mut T) -> Result<(), FrameError>;

    fn try_parse<T: BufMut + Buf>(buf: &mut T) -> Result<Self::Output, FrameError>;
}

/// Frames are:
/// ```txt
///   type      u8;               // MessageType
///   length    u16               // Length of the payload (Big Endian).
///   payload   [u8; length];     // Data payload.
///   padding   [0_u8; pad_len];  // Padding.
/// ```
pub fn build_and_marshall<T: BufMut>(
    dst: &mut T,
    pt: MessageType,
    data: impl AsRef<[u8]>,
    pad_len: usize,
) -> Result<(), FrameError> {
    // is the provided pad_len too long?
    if pad_len > u16::MAX as usize {
        Err(FrameError::InvalidPayloadLength(pad_len))?
    }

    // is the provided data a reasonable size?
    let buf = data.as_ref();
    let total_size = buf.len() + pad_len;
    trace!(
        "building: total size = {}+{}={} / {MAX_MESSAGE_PAYLOAD_LENGTH}",
        buf.len(),
        pad_len,
        total_size,
    );
    if total_size >= MAX_MESSAGE_PAYLOAD_LENGTH {
        Err(FrameError::InvalidPayloadLength(total_size))?
    }

    dst.put_u8(pt);
    dst.put_u16(buf.len() as u16);
    dst.put(buf);
    if pad_len != 0 {
        dst.put_bytes(0_u8, pad_len);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    #[test]
    fn build_basic_payload() {
        let mut buf = BytesMut::new();
        build_and_marshall(&mut buf, 0x01, &[0xAA, 0xBB], 0).unwrap();
        // type(1) + length(2) + payload(2) = 5
        assert_eq!(buf.len(), 5);
        assert_eq!(buf[0], 0x01); // type
        assert_eq!(buf[1], 0x00); // length high byte
        assert_eq!(buf[2], 0x02); // length low byte
        assert_eq!(buf[3], 0xAA);
        assert_eq!(buf[4], 0xBB);
    }

    #[test]
    fn build_with_padding() {
        let mut buf = BytesMut::new();
        build_and_marshall(&mut buf, 0x02, &[0xFF], 3).unwrap();
        // type(1) + length(2) + payload(1) + padding(3) = 7
        assert_eq!(buf.len(), 7);
        assert_eq!(buf[0], 0x02);
        assert_eq!(buf[3], 0xFF); // payload
        assert_eq!(&buf[4..7], &[0, 0, 0]); // padding is zeros
    }

    #[test]
    fn build_empty_payload_no_padding() {
        let mut buf = BytesMut::new();
        build_and_marshall(&mut buf, 0x00, &[], 0).unwrap();
        assert_eq!(buf.len(), 3); // type + length(0)
        assert_eq!(buf[1], 0x00);
        assert_eq!(buf[2], 0x00);
    }

    #[test]
    fn build_empty_payload_with_padding() {
        let mut buf = BytesMut::new();
        build_and_marshall(&mut buf, 0x00, &[], 5).unwrap();
        assert_eq!(buf.len(), 8); // type(1) + length(2) + padding(5)
    }

    #[test]
    fn build_rejects_oversized_total() {
        let mut buf = BytesMut::new();
        let big_payload = vec![0u8; MAX_MESSAGE_PAYLOAD_LENGTH];
        let result = build_and_marshall(&mut buf, 0x01, &big_payload, 0);
        assert!(result.is_err());
    }

    #[test]
    fn build_rejects_oversized_padding() {
        let mut buf = BytesMut::new();
        let result = build_and_marshall(&mut buf, 0x01, &[], u16::MAX as usize + 1);
        assert!(result.is_err());
    }

    #[test]
    fn build_max_valid_payload() {
        let mut buf = BytesMut::new();
        let payload = vec![0u8; MAX_MESSAGE_PAYLOAD_LENGTH - 1];
        build_and_marshall(&mut buf, 0x01, &payload, 0).unwrap();
        assert_eq!(buf.len(), 3 + MAX_MESSAGE_PAYLOAD_LENGTH - 1);
    }

    #[test]
    fn build_boundary_total_equals_max() {
        let mut buf = BytesMut::new();
        let payload = vec![0u8; MAX_MESSAGE_PAYLOAD_LENGTH / 2];
        let pad_len = MAX_MESSAGE_PAYLOAD_LENGTH - payload.len();
        // total == MAX_MESSAGE_PAYLOAD_LENGTH should fail (uses >=)
        let result = build_and_marshall(&mut buf, 0x01, &payload, pad_len);
        assert!(result.is_err());
    }
}
