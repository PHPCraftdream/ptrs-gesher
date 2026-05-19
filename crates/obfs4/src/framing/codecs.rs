use crate::{
    common::drbg::{self, Drbg, Seed},
    constants::MESSAGE_OVERHEAD,
    framing::{FrameError, Messages},
};

use bytes::{Buf, BufMut, BytesMut};
use crypto_secretbox::{
    aead::{generic_array::GenericArray, Aead, KeyInit},
    XSalsa20Poly1305,
};
use ptrs::{debug, error, trace};
use rand::prelude::*;
use tokio_util::codec::{Decoder, Encoder};

/// MaximumSegmentLength is the length of the largest possible segment
/// including overhead.
pub(crate) const MAX_SEGMENT_LENGTH: usize = 1500 - (40 + 12);

/// secret box overhead is fixed length prefix and counter
const SECRET_BOX_OVERHEAD: usize = TAG_SIZE;

/// FrameOverhead is the length of the framing overhead.
pub(crate) const FRAME_OVERHEAD: usize = LENGTH_LENGTH + SECRET_BOX_OVERHEAD;

/// MaximumFramePayloadLength is the length of the maximum allowed payload
/// per frame.
pub(crate) const MAX_FRAME_PAYLOAD_LENGTH: usize = MAX_SEGMENT_LENGTH - FRAME_OVERHEAD;

pub(crate) const MAX_FRAME_LENGTH: usize = MAX_SEGMENT_LENGTH - LENGTH_LENGTH;
pub(crate) const MIN_FRAME_LENGTH: usize = FRAME_OVERHEAD - LENGTH_LENGTH;

pub(crate) const NONCE_PREFIX_LENGTH: usize = 16;
pub(crate) const NONCE_COUNTER_LENGTH: usize = 8;
pub(crate) const NONCE_LENGTH: usize = NONCE_PREFIX_LENGTH + NONCE_COUNTER_LENGTH;

pub(crate) const LENGTH_LENGTH: usize = 2;

/// KEY_LENGTH is the length of the Encoder/Decoder secret key.
pub(crate) const KEY_LENGTH: usize = 32;

pub(crate) const TAG_SIZE: usize = 16;

pub(crate) const KEY_MATERIAL_LENGTH: usize = KEY_LENGTH + NONCE_PREFIX_LENGTH + drbg::SEED_LENGTH;

// TODO: make this (Codec) threadsafe
pub struct EncryptingCodec {
    // key: [u8; KEY_LENGTH],
    encoder: EncryptingEncoder,
    decoder: EncryptingDecoder,

    pub(crate) handshake_complete: bool,
}

impl EncryptingCodec {
    pub fn new(
        encoder_key_material: [u8; KEY_MATERIAL_LENGTH],
        decoder_key_material: [u8; KEY_MATERIAL_LENGTH],
    ) -> Self {
        // let mut key: [u8; KEY_LENGTH] =  key_material[..KEY_LENGTH].try_into().unwrap();
        Self {
            // key,
            encoder: EncryptingEncoder::new(encoder_key_material),
            decoder: EncryptingDecoder::new(decoder_key_material),
            handshake_complete: false,
        }
    }

    pub(crate) fn handshake_complete(&mut self) {
        self.handshake_complete = true;
    }
}

///Decoder is a frame decoder instance.
struct EncryptingDecoder {
    key: [u8; KEY_LENGTH],
    nonce: NonceBox,
    drbg: Drbg,

    next_nonce: [u8; NONCE_LENGTH],
    next_length: u16,
    next_length_invalid: bool,
}

impl EncryptingDecoder {
    // Creates a new Decoder instance.  It must be supplied a slice
    // containing exactly KeyLength bytes of keying material.
    fn new(key_material: [u8; KEY_MATERIAL_LENGTH]) -> Self {
        trace!("new decoder key_material: {}", hex::encode(key_material));
        let key: [u8; KEY_LENGTH] = key_material[..KEY_LENGTH].try_into().unwrap();
        let nonce = NonceBox::new(&key_material[KEY_LENGTH..(KEY_LENGTH + NONCE_PREFIX_LENGTH)]);
        let seed = Seed::try_from(&key_material[(KEY_LENGTH + NONCE_PREFIX_LENGTH)..]).unwrap();
        let d = Drbg::new(Some(seed)).unwrap();

        Self {
            key,
            drbg: d,
            nonce,

            next_nonce: [0_u8; NONCE_LENGTH],
            next_length: 0,
            next_length_invalid: false,
        }
    }
}

impl Decoder for EncryptingCodec {
    type Item = Messages;
    type Error = FrameError;

    // Decode decodes a stream of data and returns the length if any.  ErrAgain is
    // a temporary failure, all other errors MUST be treated as fatal and the
    // session aborted.
    fn decode(
        &mut self,
        src: &mut BytesMut,
    ) -> std::result::Result<Option<Self::Item>, Self::Error> {
        trace!(
            "decoding src:{}B {} {}",
            src.remaining(),
            self.decoder.next_length,
            self.decoder.next_length_invalid
        );
        // A length of 0 indicates that we do not know the expected size of
        // the next frame. we use this to store the length of a packet when we
        // receive the length at the beginning, but not the whole packet, since
        // future reads may not have the who packet (including length) available
        if self.decoder.next_length == 0 {
            // Attempt to pull out the next frame length
            if LENGTH_LENGTH > src.remaining() {
                return Ok(None);
            }

            // derive the nonce that the peer would have used
            self.decoder.next_nonce = self.decoder.nonce.next()?;

            // Remove the field length from the buffer
            // let mut len_buf: [u8; LENGTH_LENGTH] = src[..LENGTH_LENGTH].try_into().unwrap();
            let mut length = src.get_u16();

            // De-obfuscate the length field
            let length_mask = self.decoder.drbg.length_mask();
            trace!(
                "decoding {length:04x}^{length_mask:04x} {:04x}B",
                length ^ length_mask
            );
            length ^= length_mask;
            if MAX_FRAME_LENGTH < length as usize || MIN_FRAME_LENGTH > length as usize {
                // Per "Plaintext Recovery Attacks Against SSH" by
                // Martin R. Albrecht, Kenneth G. Paterson and Gaven J. Watson,
                // there are a class of attacks againt protocols that use similar
                // sorts of framing schemes.
                //
                // While obfs4 should not allow plaintext recovery (CBC mode is
                // not used), attempt to mitigate out of bound frame length errors
                // by pretending that the length was a random valid range as pe
                // the countermeasure suggested by Denis Bider in section 6 of the
                // paper.

                let invalid_length = length;
                self.decoder.next_length_invalid = true;

                length = rand::thread_rng().gen::<u16>()
                    % (MAX_FRAME_LENGTH - MIN_FRAME_LENGTH) as u16
                    + MIN_FRAME_LENGTH as u16;
                error!(
                    "invalid length {invalid_length} {length} {}",
                    self.decoder.next_length_invalid
                );
            }

            self.decoder.next_length = length;
        }

        let next_len = self.decoder.next_length as usize;

        if next_len > src.len() {
            // The full string has not yet arrived.
            //
            // We reserve more space in the buffer. This is not strictly
            // necessary, but is a good idea performance-wise.
            if !self.decoder.next_length_invalid {
                src.reserve(next_len - src.len());
            }

            trace!(
                "next_len > src.len --> reading more {} {}",
                self.decoder.next_length,
                self.decoder.next_length_invalid
            );

            // We inform the Framed that we need more bytes to form the next
            // frame.
            return Ok(None);
        }

        // Use advance to modify src such that it no longer contains this frame.
        let data = src.get(..next_len).unwrap().to_vec();

        // Unseal the frame
        let key = GenericArray::from_slice(&self.decoder.key);
        let cipher = XSalsa20Poly1305::new(key);
        let nonce = GenericArray::from_slice(&self.decoder.next_nonce); // unique per message

        let plaintext = match cipher.decrypt(nonce, data.as_ref()) {
            Ok(p) => p,
            Err(e) => {
                trace!("failed to decrypt result: {e}");
                return Err(e.into());
            }
        };
        if plaintext.len() < MESSAGE_OVERHEAD {
            return Err(FrameError::InvalidMessage);
        }

        // Clean up and prepare for the next frame
        //
        // we read a whole frame, we no longer know the size of the next pkt
        self.decoder.next_length = 0;
        src.advance(next_len);

        debug!("decoding {next_len}B src:{}B", src.remaining());
        match Messages::try_parse(&mut BytesMut::from(plaintext.as_slice())) {
            Ok(Messages::Padding(_)) => Ok(None),
            Ok(m) => Ok(Some(m)),
            Err(FrameError::UnknownMessageType(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

/// Encoder is a frame encoder instance.
struct EncryptingEncoder {
    key: [u8; KEY_LENGTH],
    nonce: NonceBox,
    drbg: Drbg,
}

impl EncryptingEncoder {
    /// Creates a new Encoder instance. It must be supplied a slice
    /// containing exactly KeyLength bytes of keying material
    fn new(key_material: [u8; KEY_MATERIAL_LENGTH]) -> Self {
        trace!("new encoder key_material: {}", hex::encode(key_material));
        let key: [u8; KEY_LENGTH] = key_material[..KEY_LENGTH].try_into().unwrap();
        let nonce = NonceBox::new(&key_material[KEY_LENGTH..(KEY_LENGTH + NONCE_PREFIX_LENGTH)]);
        let seed = Seed::try_from(&key_material[(KEY_LENGTH + NONCE_PREFIX_LENGTH)..]).unwrap();
        let d = Drbg::new(Some(seed)).unwrap();

        Self {
            key,
            nonce,
            drbg: d,
        }
    }
}

impl<T: Buf> Encoder<T> for EncryptingCodec {
    type Error = FrameError;

    /// Encode encodes a single frame worth of payload and returns. Plaintext
    /// should either be a handshake message OR a buffer containing one or more
    /// [`Message`]s already properly marshalled. The proided plaintext can
    /// be no longer than [`MAX_FRAME_PAYLOAD_LENGTH`].
    ///
    /// [`InvalidPayloadLength`] is recoverable, all other errors MUST be
    /// treated as fatal and the session aborted.
    fn encode(&mut self, plaintext: T, dst: &mut BytesMut) -> std::result::Result<(), Self::Error> {
        trace!(
            "encoding {}/{MAX_FRAME_PAYLOAD_LENGTH}",
            plaintext.remaining()
        );

        // Don't send a frame if it is longer than the other end will accept.
        if plaintext.remaining() > MAX_FRAME_PAYLOAD_LENGTH {
            return Err(FrameError::InvalidPayloadLength(plaintext.remaining()));
        }

        let mut plaintext_frame = BytesMut::new();

        plaintext_frame.put(plaintext);

        // Generate a new nonce
        let nonce_bytes = self.encoder.nonce.next()?;

        // Encrypt and MAC payload
        let key = GenericArray::from_slice(&self.encoder.key);
        let cipher = XSalsa20Poly1305::new(key);
        let nonce = GenericArray::from_slice(&nonce_bytes); // unique per message

        let ciphertext = cipher.encrypt(nonce, plaintext_frame.as_ref())?;

        // Obfuscate the length
        let mut length = ciphertext.len() as u16;
        let length_mask: u16 = self.encoder.drbg.length_mask();
        debug!(
            "encoding➡️ {length}B, {length:04x}^{length_mask:04x} {:04x}",
            length ^ length_mask
        );
        length ^= length_mask;

        trace!(
            "prng_ciphertext: {}{}",
            hex::encode(length.to_be_bytes()),
            hex::encode(&ciphertext)
        );

        // Write the length and payload to the buffer.
        dst.extend_from_slice(&length.to_be_bytes()[..]);
        dst.extend_from_slice(&ciphertext);
        Ok(())
    }
}

/// internal nonce management for NaCl secret boxes
pub(crate) struct NonceBox {
    prefix: [u8; NONCE_PREFIX_LENGTH],
    counter: u64,
}

impl NonceBox {
    pub fn new(prefix: impl AsRef<[u8]>) -> Self {
        assert!(
            prefix.as_ref().len() >= NONCE_PREFIX_LENGTH,
            "prefix too short: {} < {NONCE_PREFIX_LENGTH}",
            prefix.as_ref().len()
        );
        Self {
            prefix: prefix.as_ref()[..NONCE_PREFIX_LENGTH].try_into().unwrap(),
            counter: 1,
        }
    }

    pub fn next(&mut self) -> std::result::Result<[u8; NONCE_LENGTH], FrameError> {
        // The security guarantee of Poly1305 is broken if a nonce is ever reused
        // for a given key.  Detect this by checking for counter wraparound since
        // we start each counter at 1.  If it ever happens that more than 2^64 - 1
        // frames are transmitted over a given connection, support for rekeying
        // will be neccecary, but that's unlikely to happen.

        if self.counter == u64::MAX {
            return Err(FrameError::NonceCounterWrapped);
        }
        let mut nonce = self.prefix.clone().to_vec();
        nonce.append(&mut self.counter.to_be_bytes().to_vec());

        let nonce_l: [u8; NONCE_LENGTH] = nonce[..].try_into().unwrap();

        trace!("fresh nonce: {}", hex::encode(nonce_l));
        self.inc();
        Ok(nonce_l)
    }

    fn inc(&mut self) {
        self.counter += 1;
    }
}

#[cfg(test)]
mod testing {
    use super::*;
    use crate::Result;

    #[test]
    fn nonce_wrap() -> Result<()> {
        let mut nb = NonceBox::new([0_u8; NONCE_PREFIX_LENGTH]);
        nb.counter = u64::MAX;

        assert_eq!(nb.next().unwrap_err(), FrameError::NonceCounterWrapped);
        Ok(())
    }

    #[test]
    fn nonce_box_new_and_increment() {
        let prefix = [0xAA_u8; NONCE_PREFIX_LENGTH];
        let mut nb = NonceBox::new(prefix);
        assert_eq!(nb.counter, 1);

        let n1 = nb.next().unwrap();
        assert_eq!(&n1[..NONCE_PREFIX_LENGTH], &prefix);
        assert_eq!(nb.counter, 2);

        let n2 = nb.next().unwrap();
        assert_ne!(n1, n2);
        assert_eq!(&n2[..NONCE_PREFIX_LENGTH], &prefix);
    }

    #[test]
    fn nonce_box_counter_in_nonce() {
        let mut nb = NonceBox::new([0_u8; NONCE_PREFIX_LENGTH]);
        let n = nb.next().unwrap();
        // counter starts at 1, big-endian
        assert_eq!(&n[NONCE_PREFIX_LENGTH..], &1u64.to_be_bytes());
    }

    #[test]
    fn codec_roundtrip() -> Result<()> {
        let enc_km = [0x42u8; KEY_MATERIAL_LENGTH];
        let dec_km = [0x42u8; KEY_MATERIAL_LENGTH];
        let mut codec_enc = EncryptingCodec::new(enc_km, dec_km);
        let mut codec_dec = EncryptingCodec::new(dec_km, enc_km);

        // Must marshall a proper Message into the plaintext
        let payload_data = b"hello world test";
        let msg = Messages::Payload(payload_data.to_vec());
        let mut marshalled = BytesMut::new();
        msg.marshall(&mut marshalled).unwrap();

        let mut encrypted = BytesMut::new();
        codec_enc.encode(marshalled, &mut encrypted)?;

        assert!(!encrypted.is_empty());

        let decoded = codec_dec.decode(&mut encrypted)?;
        assert!(decoded.is_some());
        if let Some(Messages::Payload(data)) = decoded {
            assert_eq!(&data[..], &payload_data[..]);
        } else {
            panic!("expected Payload message, got {:?}", decoded);
        }
        Ok(())
    }

    #[test]
    fn codec_encode_oversized_payload() {
        let enc_km = [0x11u8; KEY_MATERIAL_LENGTH];
        let dec_km = [0x22u8; KEY_MATERIAL_LENGTH];
        let mut codec = EncryptingCodec::new(enc_km, dec_km);
        let big = BytesMut::from(vec![0u8; MAX_FRAME_PAYLOAD_LENGTH + 1].as_slice());
        let mut dst = BytesMut::new();
        let result = codec.encode(big, &mut dst);
        assert!(result.is_err());
    }

    #[test]
    fn codec_decode_empty_buffer() {
        let enc_km = [0x33u8; KEY_MATERIAL_LENGTH];
        let dec_km = [0x44u8; KEY_MATERIAL_LENGTH];
        let mut codec = EncryptingCodec::new(enc_km, dec_km);
        let mut buf = BytesMut::new();
        let result = codec.decode(&mut buf).unwrap();
        assert!(result.is_none()); // needs more data
    }

    #[test]
    fn codec_decode_short_buffer() {
        let enc_km = [0x55u8; KEY_MATERIAL_LENGTH];
        let dec_km = [0x66u8; KEY_MATERIAL_LENGTH];
        let mut codec = EncryptingCodec::new(enc_km, dec_km);
        let mut buf = BytesMut::from(&[0x00][..]);
        let result = codec.decode(&mut buf).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn codec_handshake_complete_flag() {
        let km = [0x77u8; KEY_MATERIAL_LENGTH];
        let mut codec = EncryptingCodec::new(km, km);
        assert!(!codec.handshake_complete);
        codec.handshake_complete();
        assert!(codec.handshake_complete);
    }

    #[test]
    fn codec_tampered_ciphertext_rejected() -> Result<()> {
        let km = [0x42u8; KEY_MATERIAL_LENGTH];
        let mut enc = EncryptingCodec::new(km, km);
        let mut dec = EncryptingCodec::new(km, km);

        let msg = Messages::Payload(b"secret data".to_vec());
        let mut marshalled = BytesMut::new();
        msg.marshall(&mut marshalled).unwrap();

        let mut encrypted = BytesMut::new();
        enc.encode(marshalled, &mut encrypted)?;

        // Flip a byte in the encrypted payload (after 2-byte length header)
        if encrypted.len() > 4 {
            encrypted[4] ^= 0xFF;
        }

        let result = dec.decode(&mut encrypted);
        assert!(result.is_err(), "tampered ciphertext must be rejected");
        Ok(())
    }

    #[test]
    fn codec_mismatched_keys_fails_decrypt() -> Result<()> {
        let km_enc = [0x11u8; KEY_MATERIAL_LENGTH];
        let km_dec_wrong = [0x99u8; KEY_MATERIAL_LENGTH];
        let mut enc = EncryptingCodec::new(km_enc, km_enc);
        // Decoder uses wrong key material — cannot decrypt
        let mut dec = EncryptingCodec::new(km_dec_wrong, km_dec_wrong);

        let msg = Messages::Payload(b"test".to_vec());
        let mut marshalled = BytesMut::new();
        msg.marshall(&mut marshalled).unwrap();

        let mut encrypted = BytesMut::new();
        enc.encode(marshalled, &mut encrypted)?;

        // The decode will fail: either the deobfuscated length is invalid
        // (random-looking) or the decryption will fail with TagMismatch.
        // In both cases it must not silently return data.
        let mut attempts = encrypted.clone();
        // Feed enough extra bytes to avoid the "waiting for more data" path
        attempts.extend_from_slice(&[0u8; 2048]);
        let result = dec.decode(&mut attempts);
        // Either Err (crypto) or Ok(None) with next_length_invalid — never Ok(Some(..))
        match result {
            Ok(Some(m)) => panic!("mismatched keys produced plaintext: {m:?}"),
            _ => {} // Err or Ok(None) — both acceptable
        }
        Ok(())
    }

    #[test]
    fn codec_truncated_frame_returns_none() -> Result<()> {
        let km = [0xBB; KEY_MATERIAL_LENGTH];
        let mut enc = EncryptingCodec::new(km, km);
        let mut dec = EncryptingCodec::new(km, km);

        let msg = Messages::Payload(b"data that will be truncated".to_vec());
        let mut marshalled = BytesMut::new();
        msg.marshall(&mut marshalled).unwrap();

        let mut encrypted = BytesMut::new();
        enc.encode(marshalled, &mut encrypted)?;

        // Truncate: keep length header but only half the payload
        let half = 2 + (encrypted.len() - 2) / 2;
        encrypted.truncate(half);

        // Decoder should return None (needs more data), not panic or corrupt
        let result = dec.decode(&mut encrypted)?;
        assert!(result.is_none(), "truncated frame must request more data");
        Ok(())
    }

    #[test]
    fn codec_multiple_frames() -> Result<()> {
        let km1 = [0xAAu8; KEY_MATERIAL_LENGTH];
        let km2 = [0xAAu8; KEY_MATERIAL_LENGTH];
        let mut enc = EncryptingCodec::new(km1, km2);
        let mut dec = EncryptingCodec::new(km2, km1);

        for i in 0..5u8 {
            let payload = vec![i; 100];
            let msg = Messages::Payload(payload.clone());
            let mut marshalled = BytesMut::new();
            msg.marshall(&mut marshalled).unwrap();

            let mut encrypted = BytesMut::new();
            enc.encode(marshalled, &mut encrypted)?;

            let decoded = dec.decode(&mut encrypted)?;
            assert!(decoded.is_some(), "frame {i} decoded to None");
            if let Some(Messages::Payload(data)) = decoded {
                assert_eq!(data, payload);
            }
        }
        Ok(())
    }

    mod proptest_codec {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn decode_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..3000)) {
                let km = [0x42u8; KEY_MATERIAL_LENGTH];
                let mut codec = EncryptingCodec::new(km, km);
                let mut buf = BytesMut::from(&bytes[..]);
                for _ in 0..3 {
                    match codec.decode(&mut buf) {
                        Ok(None) => break,
                        Ok(Some(_)) => break,
                        Err(_) => break,
                    }
                }
            }
        }
    }
}
