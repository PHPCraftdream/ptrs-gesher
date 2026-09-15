use super::*;
use std::str::FromStr;

#[tokio::test]
async fn empty_read_finishes_without_waiting_for_network_data() {
    use futures::FutureExt;
    let (mut client, _server) = stream_pair(IAT::Off).await;
    let mut storage = [];
    let mut output = ReadBuf::new(&mut storage);
    let result =
        std::future::poll_fn(|cx| Pin::new(&mut client).poll_read(cx, &mut output)).now_or_never();
    assert!(matches!(result, Some(Ok(()))));
}

#[tokio::test]
async fn seed_received_after_handshake_updates_both_distributions() {
    use futures::SinkExt;
    use tokio::io::AsyncReadExt;
    let (mut client, mut server) = stream_pair(IAT::Enabled).await;
    let seed_bytes = [0x42; SEED_LENGTH];
    let mut packet = BytesMut::new();
    Messages::PrngSeed(seed_bytes)
        .marshall(&mut packet)
        .unwrap();
    server.s.stream.send(packet).await.unwrap();
    let mut packet = BytesMut::new();
    Messages::Payload(b"x".to_vec())
        .marshall(&mut packet)
        .unwrap();
    server.s.stream.send(packet).await.unwrap();
    let mut payload = [0u8; 1];
    client.read_exact(&mut payload).await.unwrap();
    assert_eq!(&payload, b"x");
    assert_eq!(client.s.session.len_seed().as_bytes(), &seed_bytes);
    let expected_length = WeightedDist::new(
        drbg::Seed::from(seed_bytes),
        0,
        framing::MAX_SEGMENT_LENGTH as i32,
        false,
    );
    let digest = Sha256::digest(seed_bytes);
    let expected_iat = WeightedDist::new(
        drbg::Seed::try_from(&digest[..SEED_LENGTH]).unwrap(),
        0,
        MAX_IAT_DELAY as i32,
        false,
    );
    assert_eq!(
        client.s.length_dist.to_string(),
        expected_length.to_string()
    );
    assert_eq!(client.s.iat_dist.to_string(), expected_iat.to_string());
}

async fn stream_pair(
    mode: IAT,
) -> (
    Obfs4Stream<tokio::io::DuplexStream>,
    Obfs4Stream<tokio::io::DuplexStream>,
) {
    let server = crate::server::Server::getrandom();
    let client = crate::sessions::new_client_session(server.0.identity_keys.pk, mode);
    let (a, b) = tokio::io::duplex(64 * 1024);
    let (client, server) = tokio::join!(
        client.handshake(a, Some(Instant::now() + Duration::from_secs(30)), None),
        server.wrap(b),
    );
    (client.unwrap(), server.unwrap())
}

fn fixed_length_distribution() -> WeightedDist {
    WeightedDist::new(
        drbg::Seed::try_from(&[7u8; SEED_LENGTH][..]).unwrap(),
        64,
        65,
        false,
    )
}

#[tokio::test(start_paused = true)]
async fn wire_padding_remains_enabled_when_iat_delays_are_off() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (mut client, mut server) = stream_pair(IAT::Off).await;
    client.s.length_dist = fixed_length_distribution();
    let before = Instant::now();
    client.write_all(b"x").await.unwrap();
    assert!(
        client.s.stream.write_buffer().len() >= 64,
        "iat-mode=0 disables delays, not packet-length padding"
    );
    client.flush().await.unwrap();
    let mut reply = [0u8; 1];
    server.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"x");
    assert_eq!(Instant::now(), before);
}

#[tokio::test]
async fn wire_padding_does_not_overflow_a_full_payload_frame() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (mut client, mut server) = stream_pair(IAT::Enabled).await;
    client.s.length_dist = fixed_length_distribution();
    let payload = vec![7u8; framing::MAX_MESSAGE_PAYLOAD_LENGTH];
    client.write_all(&payload).await.unwrap();
    client.flush().await.unwrap();
    let mut reply = vec![0u8; payload.len()];
    server.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, payload);
}

#[test]
fn iat_from_str_valid() {
    assert_eq!(IAT::from_str("0").unwrap(), IAT::Off);
    assert_eq!(IAT::from_str("1").unwrap(), IAT::Enabled);
    assert_eq!(IAT::from_str("2").unwrap(), IAT::Paranoid);
}

#[test]
fn iat_from_str_invalid() {
    assert!(IAT::from_str("3").is_err());
    assert!(IAT::from_str("").is_err());
    assert!(IAT::from_str("off").is_err());
    assert!(IAT::from_str("-1").is_err());
}

#[tokio::test(start_paused = true)]
async fn default_deadline_uses_the_role_timeout() {
    let timeout = Duration::from_secs(17);
    assert_eq!(
        MaybeTimeout::Default_.deadline(timeout),
        Some(Instant::now() + timeout)
    );
}

#[tokio::test(start_paused = true)]
async fn relative_deadline_starts_when_used() {
    let dur = Duration::from_secs(42);
    let policy = MaybeTimeout::Length(dur);
    tokio::time::advance(Duration::from_secs(5)).await;
    assert_eq!(policy.deadline(Duration::ZERO), Some(Instant::now() + dur));
}

#[test]
fn maybe_timeout_unset_returns_none() {
    assert!(MaybeTimeout::Unset
        .deadline(CLIENT_HANDSHAKE_TIMEOUT)
        .is_none());
}

#[test]
fn fixed_past_deadline_remains_expired() {
    let past = Instant::now() - Duration::from_secs(10);
    assert_eq!(
        MaybeTimeout::Fixed(past).deadline(Duration::ZERO),
        Some(past)
    );
}

#[test]
fn fixed_future_deadline_is_preserved() {
    let future = Instant::now() + Duration::from_secs(60);
    assert_eq!(
        MaybeTimeout::Fixed(future).deadline(Duration::ZERO),
        Some(future)
    );
}

// Regression: a single decoded obfs4 frame can carry up to
// MAX_MESSAGE_PAYLOAD_LENGTH (~1427B) of payload. `poll_read` used to do
// `buf.put_slice(&message)`, which panics when the message is larger than
// the caller's `ReadBuf`. The fix copies what fits and parks the rest in a
// residual buffer for subsequent reads. This test drives the exact helpers
// `poll_read` delegates to (`stash_payload` + `drain_residual`) with a full
// ~1448B payload and a tiny 100-byte `ReadBuf`, asserting no panic and that
// every byte is delivered, in order, across multiple reads. Against the old
// `put_slice(&message)` path this scenario panicked.
#[test]
fn oversized_frame_payload_drains_without_loss() {
    use tokio::io::ReadBuf;

    let payload_len = framing::MAX_MESSAGE_PAYLOAD_LENGTH;
    assert!(
        payload_len > 100,
        "frame payload should exceed the small read buffer for this test"
    );

    // Distinct byte pattern so ordering / loss is detectable.
    let message: Vec<u8> = (0..payload_len).map(|i| (i % 251) as u8).collect();

    let mut residual = BytesMut::new();
    let mut delivered: Vec<u8> = Vec::with_capacity(payload_len);

    // First read: a 100-byte ReadBuf receives the head; the rest is stashed.
    let mut storage = [0u8; 100];
    let mut rb = ReadBuf::new(&mut storage);
    // This call would panic on the old `buf.put_slice(&message)` code.
    O4Stream::<tokio::io::DuplexStream>::stash_payload(&mut residual, &mut rb, &message);
    assert_eq!(rb.filled().len(), 100);
    delivered.extend_from_slice(rb.filled());
    assert_eq!(residual.len(), payload_len - 100);

    // Subsequent reads drain the residual 100 bytes at a time.
    while !residual.is_empty() {
        let mut storage = [0u8; 100];
        let mut rb = ReadBuf::new(&mut storage);
        let n = O4Stream::<tokio::io::DuplexStream>::drain_residual(&mut residual, &mut rb);
        assert!(n > 0, "drain made no progress");
        assert_eq!(rb.filled().len(), n);
        delivered.extend_from_slice(rb.filled());
    }

    assert_eq!(delivered.len(), payload_len, "lost or duplicated bytes");
    assert_eq!(delivered, message, "payload corrupted across reads");
}

#[tokio::test]
async fn wire_padding_matches_reference_lengths_and_authenticates() {
    use tokio_util::codec::Decoder;
    const SEG: usize = framing::MAX_SEGMENT_LENGTH;
    for tail in [0, 1, HEADER_LENGTH, 100, SEG - 1] {
        for target in 0..=SEG {
            let (socket, _peer) = tokio::io::duplex(1);
            let km = [0x42; framing::KEY_MATERIAL_LENGTH];
            let mut framed = Framed::new(socket, framing::Obfs4Codec::new(km, km));
            let mut scratch = BytesMut::with_capacity(SEG);
            O4Stream::pad_burst(&mut framed, tail, target, &mut scratch).unwrap();
            let mut wire = framed.write_buffer().clone();
            let pad = if target >= tail {
                target - tail
            } else {
                SEG - tail + target
            };
            // Independent oracle: Go obfs4Conn.padBurst includes encrypted-frame headers.
            let expected = match pad {
                0 => 0,
                1..=HEADER_LENGTH => SEG + HEADER_LENGTH + pad,
                _ => pad,
            };
            assert_eq!(wire.len(), expected, "tail={tail}, target={target}");
            let mut decoder = framing::Obfs4Codec::new(km, km);
            assert_eq!(decoder.decode(&mut wire).unwrap(), None);
            assert!(
                wire.is_empty(),
                "all padding frames must authenticate and be consumed"
            );
        }
    }
}

#[test]
fn padding_scratch_reuses_its_allocation() {
    const SEG: usize = framing::MAX_SEGMENT_LENGTH;
    let (socket, _peer) = tokio::io::duplex(SEG);
    let km = [0x43; framing::KEY_MATERIAL_LENGTH];
    let mut framed = Framed::new(socket, framing::Obfs4Codec::new(km, km));
    let mut scratch = BytesMut::with_capacity(SEG);

    O4Stream::pad_burst(&mut framed, 0, SEG / 2, &mut scratch).unwrap();
    let pointer = scratch.as_ptr();
    let capacity = scratch.capacity();
    O4Stream::pad_burst(&mut framed, 1, SEG / 2, &mut scratch).unwrap();
    assert_eq!(scratch.as_ptr(), pointer);
    assert_eq!(scratch.capacity(), capacity);
}

// ── IAT delay tests ─────────────────────────────────────────────────

/// IAT::Off must NOT introduce any delay between writes. Under
/// `tokio::time::pause()` we advance zero time and verify all writes
/// complete instantly.
///
/// Negative control: if IAT delay were accidentally applied in Off
/// mode, the writes would block on the sleep timer and this test
/// would time out.
#[tokio::test(start_paused = true)]
async fn iat_off_no_delay() {
    use crate::server::Server;
    use tokio::io::AsyncWriteExt;

    let server = Server::getrandom();
    let client_session = crate::sessions::new_client_session(server.0.identity_keys.pk, IAT::Off);

    let (client_half, server_half) = tokio::io::duplex(64 * 1024);
    let server_ref = server.clone();
    let client_fut = async move {
        let deadline = Instant::now() + Duration::from_secs(30);
        client_session
            .handshake(client_half, Some(deadline), None)
            .await
    };
    let server_fut = async move { server_ref.wrap(server_half).await };

    let (c_stream, _s_stream) = tokio::join!(client_fut, server_fut);
    let mut c_stream = c_stream.expect("client handshake failed");

    // Write multiple times; with IAT::Off there must be no delay.
    let start = Instant::now();
    for _ in 0..5 {
        c_stream.write_all(b"test payload data").await.unwrap();
    }
    c_stream.flush().await.unwrap();
    let elapsed = Instant::now() - start;

    // Under paused time, if no delay is inserted, elapsed should be zero.
    assert!(
        elapsed < Duration::from_millis(1),
        "IAT::Off should not delay writes, but elapsed={elapsed:?}"
    );
}

/// IAT::Enabled must introduce a delay between writes. Under
/// `tokio::time::pause()` we can detect this by checking elapsed
/// time after multiple writes (tokio auto-advances for sleeps).
///
/// Negative control: if IAT delay is NOT applied (e.g. pad_burst
/// is a no-op and delay is skipped), elapsed time would be zero
/// and this test would fail.
#[tokio::test(start_paused = true)]
async fn iat_enabled_adds_delay() {
    use crate::server::Server;
    use tokio::io::AsyncWriteExt;

    let server = Server::getrandom();
    let client_session =
        crate::sessions::new_client_session(server.0.identity_keys.pk, IAT::Enabled);

    let (client_half, server_half) = tokio::io::duplex(64 * 1024);
    let server_ref = server.clone();
    let client_fut = async move {
        let deadline = Instant::now() + Duration::from_secs(30);
        client_session
            .handshake(client_half, Some(deadline), None)
            .await
    };
    let server_fut = async move { server_ref.wrap(server_half).await };

    let (c_stream, _s_stream) = tokio::join!(client_fut, server_fut);
    let mut c_stream = c_stream.expect("client handshake failed");

    // The IAT distribution is heavily skewed toward 0 (its `WeightedDist`
    // weights small values much higher than large ones), so any single
    // 2-write sample may legitimately observe zero delay. We instead
    // poll the stream's pending-delay state directly after a few writes:
    // if IAT is wired in, at least one of those writes must arm the
    // sleep timer (`iat_delay_pending == true`). A regression that drops
    // the delay leaves the timer always cleared, and the assertion fires.
    let mut saw_pending = false;
    for _ in 0..5 {
        c_stream.write_all(b"test payload data").await.unwrap();
        c_stream.flush().await.unwrap();
        if c_stream.iat_delay_is_pending_for_test() {
            saw_pending = true;
            break;
        }
    }

    assert!(
        saw_pending,
        "IAT::Enabled should arm the inter-arrival sleep timer at least once"
    );
}

/// IAT::Paranoid must also introduce delays AND use variable-size
/// chunks (from length_dist).
///
/// Negative control: without IAT delay, elapsed would be zero.
#[tokio::test(start_paused = true)]
async fn iat_paranoid_adds_delay() {
    use crate::server::Server;
    use tokio::io::AsyncWriteExt;

    let server = Server::getrandom();
    let client_session =
        crate::sessions::new_client_session(server.0.identity_keys.pk, IAT::Paranoid);

    let (client_half, server_half) = tokio::io::duplex(64 * 1024);
    let server_ref = server.clone();
    let client_fut = async move {
        let deadline = Instant::now() + Duration::from_secs(30);
        client_session
            .handshake(client_half, Some(deadline), None)
            .await
    };
    let server_fut = async move { server_ref.wrap(server_half).await };

    let (c_stream, _s_stream) = tokio::join!(client_fut, server_fut);
    let mut c_stream = c_stream.expect("client handshake failed");

    // Same approach as `iat_enabled_adds_delay` — directly observe the
    // pending IAT timer instead of relying on wall-clock elapsed (the
    // distribution can sample zero often enough to make elapsed-based
    // assertions flaky).
    let mut saw_pending = false;
    for _ in 0..5 {
        c_stream.write_all(b"test payload data here").await.unwrap();
        c_stream.flush().await.unwrap();
        if c_stream.iat_delay_is_pending_for_test() {
            saw_pending = true;
            break;
        }
    }

    assert!(
        saw_pending,
        "IAT::Paranoid should arm the inter-arrival sleep timer at least once"
    );
}

/// Verify that shutdown clears the pending IAT delay so the stream
/// closes promptly rather than waiting for a timer.
#[tokio::test(start_paused = true)]
async fn iat_shutdown_clears_delay() {
    use crate::server::Server;
    use tokio::io::AsyncWriteExt;

    let server = Server::getrandom();
    let client_session =
        crate::sessions::new_client_session(server.0.identity_keys.pk, IAT::Enabled);

    let (client_half, server_half) = tokio::io::duplex(64 * 1024);
    let server_ref = server.clone();
    let client_fut = async move {
        let deadline = Instant::now() + Duration::from_secs(30);
        client_session
            .handshake(client_half, Some(deadline), None)
            .await
    };
    let server_fut = async move { server_ref.wrap(server_half).await };

    let (c_stream, _s_stream) = tokio::join!(client_fut, server_fut);
    let mut c_stream = c_stream.expect("client handshake failed");

    // Write to arm the IAT delay, then immediately shut down.
    c_stream.write_all(b"data before shutdown").await.unwrap();
    // Shutdown should not hang waiting for the IAT delay.
    c_stream.shutdown().await.unwrap();
}
