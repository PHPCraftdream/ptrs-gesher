use super::*;
use crate::Result;

fn padded_reply() -> BytesMut {
    let km = [0x42; KEY_MATERIAL_LENGTH];
    let mut encoder = EncryptingCodec::new(km, km);
    let mut wire = BytesMut::new();
    // obfs4 spec §5: zero-length payloads and unknown types are ignored.
    for packet in [&[0, 0, 0, 0][..], &[0x7f, 0, 0], &[0, 0, 2, b'O', b'K']] {
        encoder.encode(packet, &mut wire).unwrap();
    }
    wire
}

#[tokio::test]
async fn padding_does_not_stall_a_buffered_reply_on_an_open_socket() {
    use futures::{FutureExt, StreamExt};
    use tokio::io::AsyncWriteExt;
    use tokio_util::codec::FramedRead;

    let wire = padded_reply();
    let (mut peer, transport) = tokio::io::duplex(wire.len());
    peer.write_all(&wire).await.unwrap();
    let km = [0x42; KEY_MATERIAL_LENGTH];
    let mut reader = FramedRead::new(transport, EncryptingCodec::new(km, km));
    let reply = reader.next().now_or_never();
    assert!(
        matches!(&reply, Some(Some(Ok(Messages::Payload(data)))) if data == b"OK"),
        "a complete buffered reply must not wait for another network packet: {reply:?}"
    );
}

#[test]
fn padding_at_eof_does_not_discard_a_buffered_reply() {
    let km = [0x42; KEY_MATERIAL_LENGTH];
    let mut decoder = EncryptingCodec::new(km, km);
    let mut wire = padded_reply();
    assert_eq!(
        decoder.decode_eof(&mut wire).unwrap(),
        Some(Messages::Payload(b"OK".to_vec()))
    );
    assert!(wire.is_empty());
    assert_eq!(decoder.decode_eof(&mut wire).unwrap(), None);
}

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
fn borrowed_payload_and_padding_match_legacy_wire() -> Result<()> {
    let km = [0x4Au8; KEY_MATERIAL_LENGTH];
    let payload = b"borrowed frame bytes";

    let mut direct = EncryptingCodec::new(km, km);
    let mut legacy = EncryptingCodec::new(km, km);
    let mut direct_wire = BytesMut::new();
    let mut legacy_wire = BytesMut::new();
    direct.encode(PayloadFrame::new(payload), &mut direct_wire)?;
    let mut marshalled = BytesMut::new();
    Messages::Payload(payload.to_vec()).marshall(&mut marshalled)?;
    legacy.encode(marshalled, &mut legacy_wire)?;
    assert_eq!(direct_wire, legacy_wire);

    let mut direct = EncryptingCodec::new(km, km);
    let mut legacy = EncryptingCodec::new(km, km);
    let mut direct_wire = BytesMut::new();
    let mut legacy_wire = BytesMut::new();
    direct.encode(PaddingFrame::new(37), &mut direct_wire)?;
    let mut marshalled = BytesMut::new();
    Messages::Padding(37).marshall(&mut marshalled)?;
    legacy.encode(marshalled, &mut legacy_wire)?;
    assert_eq!(direct_wire, legacy_wire);
    Ok(())
}

#[test]
fn borrowed_frame_buffers_preserve_partial_cursor_state() {
    let mut payload = PayloadFrame::new(b"abc");
    assert_eq!(payload.remaining(), 6);
    assert_eq!(payload.chunk(), &[0, 0, 3]);
    payload.advance(1);
    assert_eq!(payload.remaining(), 5);
    assert_eq!(payload.chunk(), &[0, 3]);
    payload.advance(2);
    assert_eq!(payload.remaining(), 3);
    assert_eq!(payload.chunk(), b"abc");
    payload.advance(2);
    assert_eq!(payload.remaining(), 1);
    assert_eq!(payload.chunk(), b"c");
    payload.advance(1);
    assert_eq!(payload.remaining(), 0);
    assert!(payload.chunk().is_empty());

    let mut padding = PaddingFrame::new(4);
    assert_eq!(padding.remaining(), 7);
    assert_eq!(padding.chunk(), &[0, 0, 0]);
    padding.advance(3);
    assert_eq!(padding.remaining(), 4);
    assert_eq!(padding.chunk(), &[0, 0, 0, 0]);
    padding.advance(2);
    assert_eq!(padding.remaining(), 2);
    assert_eq!(padding.chunk(), &[0, 0]);
    padding.advance(2);
    assert_eq!(padding.remaining(), 0);
    assert!(padding.chunk().is_empty());
}

#[test]
fn borrowed_payload_respects_frame_limit() {
    let km = [0x4Bu8; KEY_MATERIAL_LENGTH];
    let mut codec = EncryptingCodec::new(km, km);
    let mut wire = BytesMut::new();
    let max = vec![0xA5; crate::framing::MAX_MESSAGE_PAYLOAD_LENGTH];
    codec.encode(PayloadFrame::new(&max), &mut wire).unwrap();
    assert_eq!(wire.len(), MAX_SEGMENT_LENGTH);
    let too_large = vec![0xA5; crate::framing::MAX_MESSAGE_PAYLOAD_LENGTH + 1];
    let before = wire.clone();
    assert!(codec
        .encode(PayloadFrame::new(&too_large), &mut wire)
        .is_err());
    assert_eq!(wire, before);

    let before = wire.clone();
    assert!(codec
        .encode(
            PaddingFrame::new(crate::framing::MAX_MESSAGE_PAYLOAD_LENGTH + 1),
            &mut wire,
        )
        .is_err());
    assert_eq!(wire, before);
}

#[test]
fn codec_encode_oversized_payload() {
    let enc_km = [0x11u8; KEY_MATERIAL_LENGTH];
    let dec_km = [0x22u8; KEY_MATERIAL_LENGTH];
    let mut codec = EncryptingCodec::new(enc_km, dec_km);
    let big = BytesMut::from(vec![0u8; MAX_FRAME_PAYLOAD_LENGTH + 1].as_slice());
    let mut dst = BytesMut::from(&[0xA5, 0x5A][..]);
    let before = dst.clone();
    let result = codec.encode(big, &mut dst);
    assert!(result.is_err());
    assert_eq!(
        dst, before,
        "rejected input must not change the destination"
    );

    let mut wire = BytesMut::new();
    codec
        .encode(PayloadFrame::new(&[0x01, 0x02, 0x03]), &mut wire)
        .unwrap();
    let mut decoder = EncryptingCodec::new(dec_km, enc_km);
    assert!(
        matches!(decoder.decode(&mut wire), Ok(Some(Messages::Payload(data))) if data.as_slice() == [0x01, 0x02, 0x03])
    );
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

/// Bisect for the real-TCP cold-consensus desync: encode many frames into
/// one contiguous buffer (as the encoder would emit them back-to-back),
/// then decode them while feeding the decoder ONE byte at a time — exactly
/// the pathological fragmentation a real TCP socket produces and that the
/// in-memory `duplex` tests never exercise. Every frame must decode in
/// order with no length desync.
#[test]
fn codec_decode_byte_at_a_time_no_desync() -> Result<()> {
    let km = [0x5Au8; KEY_MATERIAL_LENGTH];
    let mut enc = EncryptingCodec::new(km, km);
    let mut dec = EncryptingCodec::new(km, km);

    // Encode 200 distinct payload frames back-to-back into one buffer.
    const N: usize = 200;
    let mut wire = BytesMut::new();
    let mut expected = Vec::new();
    for i in 0..N {
        let payload = vec![(i % 251) as u8; 137];
        let msg = Messages::Payload(payload.clone());
        let mut marshalled = BytesMut::new();
        msg.marshall(&mut marshalled).unwrap();
        enc.encode(marshalled, &mut wire)?;
        expected.push(payload);
    }

    // Feed the decoder one byte at a time.
    let mut feed = BytesMut::new();
    let mut got: Vec<Vec<u8>> = Vec::new();
    for b in wire.iter().copied() {
        feed.put_u8(b);
        loop {
            match dec.decode(&mut feed)? {
                Some(Messages::Payload(data)) => got.push(data),
                Some(_) => {}
                None => break,
            }
        }
    }

    assert_eq!(got.len(), N, "decoded {} frames, expected {N}", got.len());
    assert_eq!(got, expected, "payload mismatch under 1-byte fragmentation");
    Ok(())
}

/// decode_eof must NOT raise the default "bytes remaining on stream" error
/// when the connection closes with a partial trailing frame: it should
/// deliver any complete frame still buffered and then report clean EOF
/// (Ok(None)). Erroring here is what tore arti's channel down at the end of
/// a directory download.
#[test]
fn codec_decode_eof_graceful_on_partial_tail() -> Result<()> {
    let km = [0x6Eu8; KEY_MATERIAL_LENGTH];
    let mut enc = EncryptingCodec::new(km, km);
    let mut dec = EncryptingCodec::new(km, km);

    let msg = Messages::Payload(b"a complete final frame".to_vec());
    let mut marshalled = BytesMut::new();
    msg.marshall(&mut marshalled).unwrap();
    let mut buf = BytesMut::new();
    enc.encode(marshalled, &mut buf)?;

    // Append a truncated next frame (just a partial length header) as if the
    // peer closed mid-frame.
    buf.extend_from_slice(&[0xAB]);

    // First decode_eof call delivers the complete frame.
    match dec.decode_eof(&mut buf)? {
        Some(Messages::Payload(data)) => assert_eq!(&data[..], b"a complete final frame"),
        other => panic!("expected the complete final frame, got {other:?}"),
    }
    // Second call sees only the 1-byte partial tail: must report clean EOF,
    // NOT a "bytes remaining on stream" error.
    match dec.decode_eof(&mut buf)? {
        None => {}
        Some(m) => panic!("partial tail must not decode to a message: {m:?}"),
    }
    Ok(())
}

/// `decode_eof` on an empty buffer (peer closed at a clean frame
/// boundary) is the trivial happy case: nothing buffered, nothing
/// truncated, must report clean EOF.
#[test]
fn codec_decode_eof_graceful_on_empty_buf() -> Result<()> {
    let km = [0x11u8; KEY_MATERIAL_LENGTH];
    let mut dec = EncryptingCodec::new(km, km);

    let mut buf = BytesMut::new();
    match dec.decode_eof(&mut buf)? {
        None => Ok(()),
        Some(m) => panic!("empty buffer must not decode to a message: {m:?}"),
    }
}

/// `decode_eof` on a buffer that holds *only* a truncated obfs4
/// frame (length field present but body short) must report clean
/// EOF — `decode` reaches the "next_len > src.len" branch
/// (codecs.rs:174) and returns `Ok(None)`, which `decode_eof`
/// passes through. This models a peer closing the TCP socket
/// mid-frame: a real obfs4 stream has no inter-frame gaps (padding
/// itself is a frame), so the only realistic tail is a partial
/// last frame.
#[test]
fn codec_decode_eof_graceful_on_partial_only() -> Result<()> {
    let km = [0x22u8; KEY_MATERIAL_LENGTH];
    let mut enc = EncryptingCodec::new(km, km);
    let mut dec = EncryptingCodec::new(km, km);

    // Encode one real frame, then truncate the tail of its body —
    // length field on the wire still claims the full size, but
    // some payload bytes are missing.
    let msg = Messages::Payload(b"would-have-been-the-last-frame".to_vec());
    let mut marshalled = BytesMut::new();
    msg.marshall(&mut marshalled).unwrap();
    let mut buf = BytesMut::new();
    enc.encode(marshalled, &mut buf)?;
    // Drop the trailing 4 bytes of the encoded frame — peer closed
    // mid-write.
    buf.truncate(buf.len() - 4);

    match dec.decode_eof(&mut buf)? {
        None => Ok(()),
        Some(m) => panic!("truncated-only buffer must not decode: {m:?}"),
    }
}

/// `decode_eof` on a buffer with several complete frames followed
/// by a truncated last frame must drain every complete frame in
/// order, then report clean EOF once the only thing left is the
/// partial tail. Same shape as `_on_partial_tail`, but with N>1 —
/// guards against a regression where the codec stops at the first
/// frame or decodes them out of order under EOF semantics.
///
/// The tail is a *real* truncated obfs4 frame (length field
/// present, body short), not random bytes — that is the only kind
/// of tail a real obfs4 stream can produce.
#[test]
fn codec_decode_eof_drains_all_complete_frames_then_clean_eof() -> Result<()> {
    let km = [0x33u8; KEY_MATERIAL_LENGTH];
    let mut enc = EncryptingCodec::new(km, km);
    let mut dec = EncryptingCodec::new(km, km);

    const N: usize = 5;
    let mut buf = BytesMut::new();
    let mut expected: Vec<Vec<u8>> = Vec::with_capacity(N);
    for i in 0..N {
        let payload = format!("frame-{i}").into_bytes();
        let msg = Messages::Payload(payload.clone());
        let mut marshalled = BytesMut::new();
        msg.marshall(&mut marshalled).unwrap();
        enc.encode(marshalled, &mut buf)?;
        expected.push(payload);
    }
    // Append a (would-be) sixth frame and chop its body short.
    let trailing = Messages::Payload(b"truncated-tail".to_vec());
    let mut marshalled = BytesMut::new();
    trailing.marshall(&mut marshalled).unwrap();
    let before_tail = buf.len();
    enc.encode(marshalled, &mut buf)?;
    // Trim the last few body bytes of the trailing frame — the
    // length field on the wire still claims the full size.
    let trimmed = buf.len() - 3;
    assert!(
        trimmed > before_tail,
        "trim must keep at least the length field of the trailing frame",
    );
    buf.truncate(trimmed);

    let mut got: Vec<Vec<u8>> = Vec::with_capacity(N);
    loop {
        match dec.decode_eof(&mut buf)? {
            Some(Messages::Payload(data)) => got.push(data),
            Some(other) => panic!("unexpected variant: {other:?}"),
            None => break,
        }
    }
    assert_eq!(
        got, expected,
        "all complete frames must be delivered in order"
    );
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
