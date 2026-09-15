use crate::{
    common::drbg::{Drbg, Seed},
    framing::{FrameError, Messages},
};

use bytes::{Buf, BufMut, BytesMut};
use crypto_secretbox::{
    aead::{generic_array::GenericArray, AeadInPlace, KeyInit},
    XSalsa20Poly1305,
};
use ptrs::{debug, error, trace};
use tokio_util::codec::{Decoder, Encoder};

use super::{
    KEY_LENGTH, KEY_MATERIAL_LENGTH, LENGTH_LENGTH, MAX_FRAME_LENGTH, MAX_FRAME_PAYLOAD_LENGTH,
    MAX_MESSAGE_PAYLOAD_LENGTH, MAX_SEGMENT_LENGTH, MESSAGE_OVERHEAD, MIN_FRAME_LENGTH,
    NONCE_PREFIX_LENGTH, TAG_SIZE,
};

pub(crate) const NONCE_COUNTER_LENGTH: usize = 8;
pub(crate) const NONCE_LENGTH: usize = NONCE_PREFIX_LENGTH + NONCE_COUNTER_LENGTH;

const ZERO_PADDING: [u8; MAX_MESSAGE_PAYLOAD_LENGTH] = [0; MAX_MESSAGE_PAYLOAD_LENGTH];

/// A borrowed payload frame represented as a zero-copy `Buf`.
pub(crate) struct PayloadFrame<'a> {
    header: [u8; MESSAGE_OVERHEAD],
    header_pos: usize,
    payload: &'a [u8],
    payload_pos: usize,
}

impl<'a> PayloadFrame<'a> {
    pub(crate) fn new(payload: &'a [u8]) -> Self {
        Self {
            header: [0, (payload.len() >> 8) as u8, payload.len() as u8],
            header_pos: 0,
            payload,
            payload_pos: 0,
        }
    }
}

impl Buf for PayloadFrame<'_> {
    fn remaining(&self) -> usize {
        (MESSAGE_OVERHEAD - self.header_pos).saturating_add(self.payload.len() - self.payload_pos)
    }

    fn chunk(&self) -> &[u8] {
        if self.header_pos < MESSAGE_OVERHEAD {
            &self.header[self.header_pos..]
        } else {
            &self.payload[self.payload_pos..]
        }
    }

    fn advance(&mut self, count: usize) {
        assert!(count <= self.remaining(), "payload frame advanced too far");
        let header_remaining = MESSAGE_OVERHEAD - self.header_pos;
        if count < header_remaining {
            self.header_pos += count;
        } else {
            self.header_pos = MESSAGE_OVERHEAD;
            self.payload_pos += count - header_remaining;
        }
    }
}

/// A zero-copy padding frame represented as a `Buf`.
pub(crate) struct PaddingFrame {
    header_pos: usize,
    padding_len: usize,
    padding_pos: usize,
}

impl PaddingFrame {
    pub(crate) fn new(padding_len: usize) -> Self {
        Self {
            header_pos: 0,
            padding_len,
            padding_pos: 0,
        }
    }
}

impl Buf for PaddingFrame {
    fn remaining(&self) -> usize {
        (MESSAGE_OVERHEAD - self.header_pos).saturating_add(self.padding_len - self.padding_pos)
    }

    fn chunk(&self) -> &[u8] {
        static HEADER: [u8; MESSAGE_OVERHEAD] = [0; MESSAGE_OVERHEAD];
        if self.header_pos < MESSAGE_OVERHEAD {
            &HEADER[self.header_pos..]
        } else {
            &ZERO_PADDING[..(self.padding_len - self.padding_pos).min(ZERO_PADDING.len())]
        }
    }

    fn advance(&mut self, count: usize) {
        assert!(count <= self.remaining(), "padding frame advanced too far");
        let header_remaining = MESSAGE_OVERHEAD - self.header_pos;
        if count < header_remaining {
            self.header_pos += count;
        } else {
            self.header_pos = MESSAGE_OVERHEAD;
            self.padding_pos += count - header_remaining;
        }
    }
}

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
        trace!("new decoder initialized");
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
        // obfs4 spec §5: ignored packets must not hide the next buffered frame.
        // https://github.com/Yawning/obfs4/blob/master/doc/obfs4-spec.txt
        loop {
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
            if let Err(e) =
                dec.cipher
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
                Ok(Messages::Padding(_)) | Err(FrameError::UnknownMessageType(_)) => continue,
                Ok(m) => return Ok(Some(m)),
                Err(e) => return Err(e),
            }
        }
    }

    /// Handle end-of-stream. `tokio_util`'s default `decode_eof` returns a hard
    /// `"bytes remaining on stream"` IO error whenever the peer closes the
    /// connection while any bytes that do not form a complete frame are still
    /// buffered. For obfs4 that is the normal way a connection ends: the peer
    /// (or an intermediary, e.g. a relay tearing the TLS-over-obfs4 channel
    /// down) closes the TCP socket and a partial trailing frame — or leftover
    /// inter-frame padding — is left behind. A truncated final frame carries no
    /// recoverable message, so the correct action is to drain any *complete*
    /// frames still buffered and then signal a clean end of stream, instead of
    /// surfacing an error that arti reports as an unexpected-EOF and uses to
    /// tear the whole channel (and its circuits) down mid-bootstrap.
    fn decode_eof(
        &mut self,
        src: &mut BytesMut,
    ) -> std::result::Result<Option<Self::Item>, Self::Error> {
        // Deliver any remaining whole frame; once `decode` can no longer parse
        // a complete frame, treat the leftover (if any) as a truncated tail and
        // report clean EOF rather than erroring on it.
        self.decode(src)
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
        trace!("new encoder initialized");
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
        debug!(
            "encoding➡️ {length}B, {length:04x}^{length_mask:04x} {:04x}",
            length ^ length_mask
        );
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
mod testing;
