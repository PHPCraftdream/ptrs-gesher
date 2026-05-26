//! Version 1 of the Protocol Messagess to be included in constructed frames.
//!
//! ## Compatibility concerns:
//!
//! Server - when operating as a server we may want to support clients using v0
//! as well as clients using v1. In order to accomplish this the server can
//! look for the presence of the [`ClientParams`] message. If it is included as
//! a part of the clients handshake we can affirmatively assign protocol message
//! set v1 to the clients session. If we complete the handshake without
//! receiving a [`ClientParams`] messsage then we default to v0 (if the server
//! enables support).
//!
//! Client - When operating as a client we want to support the option to connect
//! with either v0 or v1 servers. when running as a v1 client the server will
//! ignore the unknown frames including [`ClientParams`] and [`CryptoOffer`].
//! This means that the `SevrerHandshake` will not include [`ServerParams`] or
//! [`CryptoAccept`] frames which indicates to a v1 client that it is speaking
//! with a server unwilling or incapable of speaking v1. This should allow
//! cross compatibility.

// mod crypto;
// use crypto::CryptoExtension;

use crate::{
    constants::*,
    framing::{FrameError, MESSAGE_OVERHEAD},
};

use ptrs::trace;
use tokio_util::bytes::{Buf, BufMut};

const PAD: [u8; MAX_MESSAGE_PADDING_LENGTH] = [0u8; MAX_MESSAGE_PADDING_LENGTH];

#[derive(Debug, PartialEq)]
pub enum MessageTypes {
    Payload,
    PrngSeed,
}

impl MessageTypes {
    // Steady state message types (and required backwards compatibility messages)
    const PAYLOAD: u8 = 0x00;
    const PRNG_SEED: u8 = 0x01;
}

impl From<MessageTypes> for u8 {
    fn from(value: MessageTypes) -> Self {
        match value {
            MessageTypes::Payload => MessageTypes::PAYLOAD,
            MessageTypes::PrngSeed => MessageTypes::PRNG_SEED,
        }
    }
}

impl TryFrom<u8> for MessageTypes {
    type Error = FrameError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            MessageTypes::PAYLOAD => Ok(MessageTypes::Payload),
            MessageTypes::PRNG_SEED => Ok(MessageTypes::PrngSeed),
            _ => Err(FrameError::UnknownMessageType(value)),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum Messages {
    Payload(Vec<u8>),
    PrngSeed([u8; SEED_LENGTH]),
    Padding(usize),
}

impl Messages {
    pub(crate) fn as_pt(&self) -> MessageTypes {
        match self {
            Messages::Payload(_) => MessageTypes::Payload,
            Messages::PrngSeed(_) => MessageTypes::PrngSeed,
            Messages::Padding(_) => MessageTypes::Payload,
        }
    }

    pub(crate) fn marshall<T: BufMut>(&self, dst: &mut T) -> Result<(), FrameError> {
        dst.put_u8(self.as_pt().into());
        match self {
            Messages::Payload(buf) => {
                dst.put_u16(buf.len() as u16);
                dst.put(&buf[..]);
            }
            Messages::PrngSeed(buf) => {
                dst.put_u16(buf.len() as u16);
                dst.put(&buf[..SEED_LENGTH]);
            }
            Messages::Padding(pad_len) => {
                if *pad_len > MAX_MESSAGE_PADDING_LENGTH {
                    return Err(FrameError::InvalidPayloadLength(*pad_len));
                }
                dst.put_u16(0u16);
                if *pad_len > 0 {
                    dst.put(&PAD[..*pad_len]);
                }
            }
        }
        Ok(())
    }

    pub(crate) fn try_parse<T: BufMut + Buf>(buf: &mut T) -> Result<Self, FrameError> {
        if buf.remaining() < MESSAGE_OVERHEAD {
            Err(FrameError::InvalidMessage)?
        }

        let _r: usize = buf.remaining();
        let type_u8 = buf.get_u8();
        let pt: MessageTypes = type_u8.try_into()?;
        let length = buf.get_u16() as usize;
        trace!("parsing msg: type:{type_u8} frame_len={_r} msg_len={length}");

        match pt {
            MessageTypes::Payload => {
                let mut dst = vec![];
                if length == 0 {
                    // this "packet" is all padding -> get rid of it
                    trace!("padding payload len={_r}");
                    let n = buf.remaining();
                    buf.advance(n);
                    return Ok(Messages::Padding(n));
                }
                trace!("content payload len={_r}");

                dst.put(buf.take(length));
                trace!("{}B remainng", buf.remaining());
                Ok(Messages::Payload(dst))
            }

            MessageTypes::PrngSeed => {
                if buf.remaining() < SEED_LENGTH {
                    return Err(FrameError::InvalidMessage);
                }
                let mut seed = [0_u8; SEED_LENGTH];
                buf.copy_to_slice(&mut seed[..]);
                Ok(Messages::PrngSeed(seed))
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::framing::*;
    use crate::test_utils::init_subscriber;

    use rand::prelude::*;
    use tokio_util::bytes::BytesMut;

    #[test]
    fn prngseed() -> Result<(), FrameError> {
        init_subscriber();

        let mut buf = BytesMut::new();
        let mut rng = rand::thread_rng();
        let pad_len = rng.gen_range(0..100);
        let mut seed = [0_u8; SEED_LENGTH];
        rng.fill_bytes(&mut seed);

        build_and_marshall(&mut buf, MessageTypes::PrngSeed.into(), seed, pad_len)?;

        let pkt = Messages::try_parse(&mut buf)?;
        assert_eq!(Messages::PrngSeed(seed), pkt);

        Ok(())
    }

    #[test]
    fn payload() -> Result<(), FrameError> {
        init_subscriber();

        let mut buf = BytesMut::new();
        let mut rng = rand::thread_rng();
        let pad_len = rng.gen_range(0..100);
        let mut payload = [0_u8; 1000];
        rng.fill_bytes(&mut payload);

        build_and_marshall(&mut buf, MessageTypes::Payload.into(), payload, pad_len)?;

        let pkt = Messages::try_parse(&mut buf)?;
        assert_eq!(Messages::Payload(payload.to_vec()), pkt);

        Ok(())
    }

    #[test]
    fn padding_marshall_and_parse() -> Result<(), FrameError> {
        init_subscriber();

        let mut buf = BytesMut::new();
        let msg = Messages::Padding(50);
        msg.marshall(&mut buf)?;

        // Padding has type=Payload(0x00), length=0, then pad bytes
        assert_eq!(buf[0], 0x00); // type = Payload
        assert_eq!(buf[1], 0x00); // length high
        assert_eq!(buf[2], 0x00); // length low = 0

        let parsed = Messages::try_parse(&mut buf)?;
        assert!(matches!(parsed, Messages::Padding(_)));
        Ok(())
    }

    #[test]
    fn padding_oversized_returns_error() {
        let msg = Messages::Padding(MAX_MESSAGE_PADDING_LENGTH + 1);
        let mut buf = BytesMut::new();
        let result = msg.marshall(&mut buf);
        assert!(result.is_err());
    }

    #[test]
    fn padding_zero_length() -> Result<(), FrameError> {
        let msg = Messages::Padding(0);
        let mut buf = BytesMut::new();
        msg.marshall(&mut buf)?;
        // type(1) + length(2) = 3 bytes, no padding
        assert_eq!(buf.len(), 3);
        Ok(())
    }

    #[test]
    fn unknown_message_type() {
        let mut buf = BytesMut::new();
        buf.put_u8(0xFF); // unknown type
        buf.put_u16(0);
        let result = Messages::try_parse(&mut buf);
        assert!(matches!(result, Err(FrameError::UnknownMessageType(0xFF))));
    }

    #[test]
    fn try_parse_too_short() {
        let mut buf = BytesMut::new();
        buf.put_u8(0x00); // only 1 byte, need 3
        let result = Messages::try_parse(&mut buf);
        assert!(matches!(result, Err(FrameError::InvalidMessage)));
    }

    #[test]
    fn message_types_conversion_roundtrip() {
        assert_eq!(u8::from(MessageTypes::Payload), 0x00);
        assert_eq!(u8::from(MessageTypes::PrngSeed), 0x01);
        assert_eq!(MessageTypes::try_from(0x00).unwrap(), MessageTypes::Payload);
        assert_eq!(
            MessageTypes::try_from(0x01).unwrap(),
            MessageTypes::PrngSeed
        );
        assert!(MessageTypes::try_from(0x02).is_err());
    }

    #[test]
    fn messages_as_pt() {
        assert_eq!(Messages::Payload(vec![]).as_pt(), MessageTypes::Payload);
        assert_eq!(
            Messages::PrngSeed([0; SEED_LENGTH]).as_pt(),
            MessageTypes::PrngSeed
        );
        assert_eq!(Messages::Padding(0).as_pt(), MessageTypes::Payload);
    }

    mod proptest_msgs {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn payload_marshall_roundtrip(data in prop::collection::vec(any::<u8>(), 1..1400)) {
                let msg = Messages::Payload(data.clone());
                let mut buf = BytesMut::new();
                msg.marshall(&mut buf).unwrap();
                let parsed = Messages::try_parse(&mut buf).unwrap();
                prop_assert_eq!(parsed, Messages::Payload(data));
            }

            #[test]
            fn prng_seed_marshall_roundtrip(seed in any::<[u8; SEED_LENGTH]>()) {
                let mut buf = BytesMut::new();
                build_and_marshall(&mut buf, MessageTypes::PrngSeed.into(), seed, 0).unwrap();
                let parsed = Messages::try_parse(&mut buf).unwrap();
                prop_assert_eq!(parsed, Messages::PrngSeed(seed));
            }

            #[test]
            fn try_parse_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..500)) {
                let mut buf = BytesMut::from(&bytes[..]);
                let _ = Messages::try_parse(&mut buf);
            }
        }
    }
}
