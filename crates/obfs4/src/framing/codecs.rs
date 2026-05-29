use crate::{
    common::drbg::{self, Drbg, Seed},
    constants::MESSAGE_OVERHEAD,
    framing::{FrameError, Messages},
};

use bytes::{Buf, BufMut, BytesMut};
use crypto_secretbox::{
    aead::{generic_array::GenericArray, AeadInPlace, KeyInit},
    XSalsa20Poly1305,
};
use ptrs::{debug, error, trace};
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

/// XSalsa20-Poly1305 frame encoder/decoder for the obfs4 data channel.
// TODO: make this (Codec) threadsafe
pub struct EncryptingCodec {
    // key: [u8; KEY_LENGTH],
    encoder: EncryptingEncoder,
    decoder: EncryptingDecoder,

    pub(crate) handshake_complete: bool,
}

impl EncryptingCodec {
    /// Construct a new codec from separate encoder and decoder KDF-extracted key material.
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
    /// The session key is fixed for the lifetime of the codec, so the AEAD
    /// cipher is constructed once here instead of on every frame. `SecretBox`
    /// (the type behind `XSalsa20Poly1305`) zeroizes its key on drop, so this
    /// also preserves the key-zeroization the old `key: [u8; 32]` + `Drop`
    /// provided.
    cipher: XSalsa20Poly1305,
    nonce: NonceBox,
    drbg: Drbg,

    /// Reusable working buffer for in-place AEAD open. Each frame's ciphertext
    /// is copied here once and decrypted in place, avoiding the per-frame
    /// allocate-and-copy that the old `src.get(..n).to_vec()` + `decrypt -> Vec`
    /// + `BytesMut::from(plaintext)` chain incurred.
    scratch: BytesMut,

    next_nonce: [u8; NONCE_LENGTH],
    next_length: u16,
}

impl EncryptingDecoder {
    // Creates a new Decoder instance.  It must be supplied a slice
    // containing exactly KeyLength bytes of keying material.
    fn new(key_material: [u8; KEY_MATERIAL_LENGTH]) -> Self {
        trace!("new decoder key_material: {}", hex::encode(key_material));
        let key = GenericArray::from_slice(&key_material[..KEY_LENGTH]);
        let cipher = XSalsa20Poly1305::new(key);
        let nonce = NonceBox::new(&key_material[KEY_LENGTH..(KEY_LENGTH + NONCE_PREFIX_LENGTH)]);
        let seed = Seed::try_from(&key_material[(KEY_LENGTH + NONCE_PREFIX_LENGTH)..]).unwrap();
        let d = Drbg::new(Some(seed)).unwrap();

        Self {
            cipher,
            drbg: d,
            nonce,

            scratch: BytesMut::with_capacity(MAX_SEGMENT_LENGTH),
            next_nonce: [0_u8; NONCE_LENGTH],
            next_length: 0,
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
            "decoding src:{}B next_length={}",
            src.remaining(),
            self.decoder.next_length,
        );
        // `next_length == 0` is the marker for "no frame length parsed yet";
        // a real frame always has length >= MIN_FRAME_LENGTH > 0, so this is
        // not ambiguous with a valid in-progress frame.
        if self.decoder.next_length == 0 {
            // Attempt to pull out the next frame length
            if LENGTH_LENGTH > src.remaining() {
                return Ok(None);
            }

            // derive the nonce that the peer would have used
            self.decoder.next_nonce = self.decoder.nonce.next()?;

            let mut length = src.get_u16();

            // De-obfuscate the length field
            let length_mask = self.decoder.drbg.length_mask();
            trace!(
                "decoding {length:04x}^{length_mask:04x} {:04x}B",
                length ^ length_mask
            );
            length ^= length_mask;
            if MAX_FRAME_LENGTH < length as usize || MIN_FRAME_LENGTH > length as usize {
                // The obfs4 data channel is AEAD-protected (XSalsa20-Poly1305),
                // so the Albrecht/Paterson/Watson SSH-CBC plaintext-recovery
                // attack and the Bider countermeasure do not apply. An
                // out-of-range length here can only mean a corrupted, tampered,
                // or desynchronised stream. We must reject immediately: the
                // nonce counter has already been consumed for this frame, so
                // any attempt to keep reading would desynchronise the AEAD
                // nonces for the remainder of the session.
                error!("invalid frame length after demask: {length}");
                return Err(FrameError::InvalidFrame);
            }

            self.decoder.next_length = length;
        }

        let next_len = self.decoder.next_length as usize;

        if next_len > src.len() {
            // The full frame has not yet arrived. Reserve space and ask the
            // caller for more bytes.
            src.reserve(next_len - src.len());

            trace!(
                "next_len > src.len --> reading more {}",
                self.decoder.next_length,
            );

            return Ok(None);
        }

        // Copy exactly this frame's bytes into the reusable working buffer and
        // unseal it in place. The NaCl secretbox layout is `[tag(16) ||
        // ciphertext]`, so the Poly1305 tag is the 16-byte prefix and the
        // sealed payload is everything after it. `next_len >= MIN_FRAME_LENGTH
        // == TAG_SIZE` is guaranteed by the length-range check above, so the
        // `[TAG_SIZE..]` slice below is always in bounds.
        let dec = &mut self.decoder;
        dec.scratch.clear();
        dec.scratch.extend_from_slice(&src[..next_len]);

        let nonce = GenericArray::from_slice(&dec.next_nonce); // unique per message
        let tag = crypto_secretbox::Tag::clone_from_slice(&dec.scratch[..TAG_SIZE]);

        // Authenticate + decrypt in place. A tamper anywhere in the frame
        // (header length is already validated; here it is the ciphertext or
        // tag) makes the constant-time Poly1305 comparison fail and we return
        // the crypto error without consuming `src`, exactly as before. We MUST
        // NOT advance the nonce/`next_length` further on failure — the session
        // is fatal at that point.
        if let Err(e) = dec
            .cipher
            .decrypt_in_place_detached(nonce, b"", &mut dec.scratch[TAG_SIZE..], &tag)
        {
            trace!("failed to decrypt result: {e}");
            return Err(e.into());
        }

        // Drop the tag prefix so the buffer now begins at the recovered
        // plaintext; `scratch[TAG_SIZE..next_len]` is the message.
        dec.scratch.advance(TAG_SIZE);
        if dec.scratch.remaining() < MESSAGE_OVERHEAD {
            return Err(FrameError::InvalidMessage);
        }

        // Clean up and prepare for the next frame
        //
        // we read a whole frame, we no longer know the size of the next pkt
        dec.next_length = 0;
        src.advance(next_len);

        debug!("decoding {next_len}B src:{}B", src.remaining());
        // `try_parse` consumes the plaintext out of the working buffer; the
        // owned `Vec` it builds for a `Payload` is the message's own storage
        // and is unavoidable here.
        match Messages::try_parse(&mut self.decoder.scratch) {
            Ok(Messages::Padding(_)) => Ok(None),
            Ok(m) => Ok(Some(m)),
            Err(FrameError::UnknownMessageType(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

/// Encoder is a frame encoder instance.
struct EncryptingEncoder {
    /// Session-fixed AEAD cipher, constructed once (see `EncryptingDecoder` for
    /// the same rationale, including key zeroization on drop).
    cipher: XSalsa20Poly1305,
    nonce: NonceBox,
    drbg: Drbg,
}

impl EncryptingEncoder {
    /// Creates a new Encoder instance. It must be supplied a slice
    /// containing exactly KeyLength bytes of keying material
    fn new(key_material: [u8; KEY_MATERIAL_LENGTH]) -> Self {
        trace!("new encoder key_material: {}", hex::encode(key_material));
        let key = GenericArray::from_slice(&key_material[..KEY_LENGTH]);
        let cipher = XSalsa20Poly1305::new(key);
        let nonce = NonceBox::new(&key_material[KEY_LENGTH..(KEY_LENGTH + NONCE_PREFIX_LENGTH)]);
        let seed = Seed::try_from(&key_material[(KEY_LENGTH + NONCE_PREFIX_LENGTH)..]).unwrap();
        let d = Drbg::new(Some(seed)).unwrap();

        Self {
            cipher,
            nonce,
            drbg: d,
        }
    }
}

impl<T: Buf> Encoder<T> for EncryptingCodec {
    type Error = FrameError;

    /// Encode encodes a single frame worth of payload and returns. Plaintext
    /// should either be a handshake message OR a buffer containing one or more
    /// Messages already properly marshalled. The proided plaintext can
    /// be no longer than `MAX_FRAME_PAYLOAD_LENGTH`.
    ///
    /// [`FrameError::InvalidPayloadLength`] is recoverable, all other errors MUST be
    /// treated as fatal and the session aborted.
    fn encode(&mut self, plaintext: T, dst: &mut BytesMut) -> std::result::Result<(), Self::Error> {
        trace!(
            "encoding {}/{MAX_FRAME_PAYLOAD_LENGTH}",
            plaintext.remaining()
        );

        // Don't send a frame if it is longer than the other end will accept.
        let pt_len = plaintext.remaining();
        if pt_len > MAX_FRAME_PAYLOAD_LENGTH {
            return Err(FrameError::InvalidPayloadLength(pt_len));
        }

        // Generate a new nonce (consumes one counter value, fatal on wrap).
        let nonce_bytes = self.encoder.nonce.next()?;

        // The NaCl secretbox output is `[tag(16) || ciphertext(pt_len)]`, so the
        // sealed frame length is fixed at `pt_len + TAG_SIZE`. We build the wire
        // frame `[len(2) || tag(16) || ciphertext]` directly inside `dst` and
        // seal the payload region in place, removing the previous two
        // allocations (the staging `BytesMut` and the `encrypt -> Vec`). The
        // resulting bytes are byte-for-byte identical to the old path.
        let ct_len = pt_len + TAG_SIZE;

        // Obfuscate the length
        let mut length = ct_len as u16;
        let length_mask: u16 = self.encoder.drbg.length_mask();
        debug!("encoding➡️ {length}B, {length:04x}^{length_mask:04x} {:04x}", length ^ length_mask);
        length ^= length_mask;

        dst.reserve(LENGTH_LENGTH + ct_len);
        let frame_start = dst.len();
        dst.extend_from_slice(&length.to_be_bytes()[..]);
        // Tag slot (filled after the payload is sealed) followed by the
        // plaintext copied straight from the caller's `Buf`.
        let tag_start = frame_start + LENGTH_LENGTH;
        dst.extend_from_slice(&[0u8; TAG_SIZE]);
        dst.put(plaintext);

        let nonce = GenericArray::from_slice(&nonce_bytes); // unique per message
        let payload_start = tag_start + TAG_SIZE;
        let tag = self.encoder.cipher.encrypt_in_place_detached(
            nonce,
            b"",
            &mut dst[payload_start..payload_start + pt_len],
        )?;
        dst[tag_start..payload_start].copy_from_slice(tag.as_slice());

        trace!(
            "prng_ciphertext: {}{}",
            hex::encode(length.to_be_bytes()),
            hex::encode(&dst[tag_start..payload_start + pt_len])
        );
        Ok(())
    }
}

/// internal nonce management for NaCl secret boxes
pub(crate) struct NonceBox {
    prefix: [u8; NONCE_PREFIX_LENGTH],
    counter: u64,
}

impl Drop for NonceBox {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.prefix.zeroize();
    }
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
        // Assemble the 24-byte nonce on the stack: 16-byte fixed prefix followed
        // by the big-endian counter. The wire layout and counter semantics are
        // identical to the previous heap-built version; only the two per-frame
        // allocations are gone. The counter is consumed (incremented) exactly
        // once per produced nonce so uniqueness per key is preserved.
        let mut nonce = [0u8; NONCE_LENGTH];
        nonce[..NONCE_PREFIX_LENGTH].copy_from_slice(&self.prefix);
        nonce[NONCE_PREFIX_LENGTH..].copy_from_slice(&self.counter.to_be_bytes());

        trace!("fresh nonce: {}", hex::encode(nonce));
        self.inc();
        Ok(nonce)
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
        if let Ok(Some(m)) = result {
            panic!("mismatched keys produced plaintext: {m:?}")
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

    /// T1 regression: an out-of-range frame length after DRBG demasking must
    /// fail synchronously with `FrameError::InvalidFrame`. The session is
    /// permanently desynchronised at this point (the nonce counter has been
    /// consumed), so subsequent decode calls on the same codec must keep
    /// returning errors instead of silently re-buffering bytes.
    #[test]
    fn codec_invalid_length_rejected_immediately() {
        let km = [0xC3u8; KEY_MATERIAL_LENGTH];
        let mut codec = EncryptingCodec::new(km, km);

        // Recreate the decoder-side DRBG locally so we know the first mask
        // the codec will XOR onto the length bytes.
        let seed = Seed::try_from(&km[KEY_LENGTH + NONCE_PREFIX_LENGTH..]).unwrap();
        let mut shadow_drbg = Drbg::new(Some(seed)).unwrap();
        let mask = shadow_drbg.length_mask();

        // Pick a wire length that becomes 0 after demasking — 0 is below
        // MIN_FRAME_LENGTH=16 so it must be rejected.
        let wire_bytes = mask.to_be_bytes();
        let mut buf = BytesMut::from(&wire_bytes[..]);
        // Feed plenty of trailing bytes to make sure we are not hitting the
        // "need more data" path: that path is for valid-length frames.
        buf.extend_from_slice(&[0u8; 2048]);

        let first = codec.decode(&mut buf);
        match first {
            Err(FrameError::InvalidFrame) => {}
            other => panic!("expected InvalidFrame on out-of-range length, got {other:?}"),
        }

        // After a fatal frame error the codec must not silently resynchronise
        // on the remaining stream bytes — every further decode must keep
        // failing (either InvalidFrame again or a crypto error from an AEAD
        // attempt with a wrong nonce). Notably it must never return Ok(Some).
        for _ in 0..3 {
            match codec.decode(&mut buf) {
                Ok(None) => {}
                Err(_) => {}
                Ok(Some(m)) => panic!("codec resynced after fatal frame error: {m:?}"),
            }
        }
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
                let _ = codec.decode(&mut buf);
            }

            #[test]
            fn encode_decode_roundtrip_arbitrary_key(
                km in any::<[u8; KEY_MATERIAL_LENGTH]>(),
                payload in prop::collection::vec(any::<u8>(), 1..1400)
            ) {
                let mut enc = EncryptingCodec::new(km, km);
                let mut dec = EncryptingCodec::new(km, km);
                let msg = Messages::Payload(payload.clone());
                let mut marshalled = BytesMut::new();
                msg.marshall(&mut marshalled).unwrap();
                let mut encrypted = BytesMut::new();
                enc.encode(marshalled, &mut encrypted).unwrap();
                let decoded = dec.decode(&mut encrypted).unwrap();
                match decoded {
                    Some(Messages::Payload(data)) => prop_assert_eq!(data, payload),
                    other => panic!("expected Payload, got {:?}", other),
                }
            }
        }
    }
}
