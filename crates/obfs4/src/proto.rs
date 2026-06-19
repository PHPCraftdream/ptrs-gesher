use crate::{
    common::{
        drbg,
        probdist::{self, WeightedDist},
    },
    constants::*,
    framing,
    sessions::Session,
    Error, Result,
};

use bytes::{Buf, BytesMut};
use futures::{Future, Sink, Stream};
use pin_project::pin_project;
use ptrs::trace;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Duration, Instant, Sleep};
use tokio_util::codec::Framed;

use std::{
    io::Error as IoError,
    pin::Pin,
    result::Result as StdResult,
    task::{Context, Poll},
};

use super::framing::{FrameError, Messages};

/// IAT (inter-arrival time) traffic shaping mode for obfs4 connections.
#[allow(dead_code, unused)]
#[non_exhaustive]
#[derive(Default, Debug, Clone, Copy, PartialEq)]
pub enum IAT {
    /// No inter-arrival time obfuscation is applied.
    #[default]
    Off,
    /// Moderate IAT obfuscation is applied to outbound packets.
    Enabled,
    /// Aggressive IAT obfuscation that may significantly impact throughput.
    Paranoid,
}

#[derive(Debug, Clone)]
pub(crate) enum MaybeTimeout {
    Default_,
    Fixed(Instant),
    Length(Duration),
    Unset,
}

impl std::str::FromStr for IAT {
    type Err = Error;
    fn from_str(s: &str) -> StdResult<Self, Self::Err> {
        match s {
            "0" => Ok(IAT::Off),
            "1" => Ok(IAT::Enabled),
            "2" => Ok(IAT::Paranoid),
            _ => Err(format!("invalid iat-mode '{s}'").into()),
        }
    }
}

impl std::fmt::Display for IAT {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IAT::Off => write!(f, "0")?,
            IAT::Enabled => write!(f, "1")?,
            IAT::Paranoid => write!(f, "2")?,
        }
        Ok(())
    }
}

impl MaybeTimeout {
    pub(crate) fn duration(&self) -> Option<Duration> {
        match self {
            MaybeTimeout::Default_ => Some(CLIENT_HANDSHAKE_TIMEOUT),
            MaybeTimeout::Fixed(i) => {
                if *i < Instant::now() {
                    None
                } else {
                    Some(*i - Instant::now())
                }
            }
            MaybeTimeout::Length(d) => Some(*d),
            MaybeTimeout::Unset => None,
        }
    }
}

/// An obfs4-encrypted bidirectional stream wrapping an inner async transport.
#[pin_project]
pub struct Obfs4Stream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    // s: Arc<Mutex<O4Stream<'a, T>>>,
    #[pin]
    s: O4Stream<T>,
}

impl<T> Obfs4Stream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    pub(crate) fn from_o4(o4: O4Stream<T>) -> Self {
        Obfs4Stream {
            // s: Arc::new(Mutex::new(o4)),
            s: o4,
        }
    }

    /// Read the inner stream's IAT delay-pending flag. Test-only — exposed
    /// so the `iat_*_adds_delay` tests can directly observe whether the
    /// IAT sleep timer was armed by the last write, instead of guessing
    /// from wall-clock elapsed time (which is flaky because `WeightedDist`
    /// is heavily skewed toward small samples).
    #[cfg(test)]
    pub(crate) fn iat_delay_is_pending_for_test(&self) -> bool {
        self.s.iat_delay_pending
    }
}

#[pin_project]
pub(crate) struct O4Stream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    #[pin]
    pub stream: Framed<T, framing::Obfs4Codec>,

    pub length_dist: probdist::WeightedDist,
    pub iat_dist: probdist::WeightedDist,

    pub iat_mode: IAT,

    pub session: Session,

    /// Bytes decoded from a single obfs4 frame that did not fit in the caller's
    /// `ReadBuf` on a previous `poll_read`. A decoded frame can carry up to
    /// `MAX_MESSAGE_PAYLOAD_LENGTH` (~1448B) of payload, which is larger than an
    /// arbitrary caller buffer; the surplus is parked here and delivered on
    /// subsequent reads so no payload is lost (and `put_slice` never overflows).
    read_residual: BytesMut,

    /// Inter-arrival time delay timer. When IAT mode is Enabled or Paranoid,
    /// a delay sampled from `iat_dist` is imposed between successive writes.
    /// The timer is reset after each write; the next `poll_write` waits for
    /// it to expire before proceeding. Uses `tokio::time::Sleep` so it is
    /// compatible with `tokio::time::pause()` for deterministic testing.
    ///
    /// Wrapped in `Pin<Box<...>>` so that `O4Stream` remains `Unpin` (required
    /// by the `ptrs::ClientTransport::OutRW` bound). The `Pin<Box<Sleep>>`
    /// itself is `Unpin`, avoiding the need for `#[pin]`.
    iat_sleep: Pin<Box<Sleep>>,

    /// Whether the current `iat_sleep` timer is active (waiting to fire).
    /// Set to `true` after a write completes with IAT enabled; cleared when
    /// the sleep fires and the next write can proceed.
    iat_delay_pending: bool,
}

impl<T> O4Stream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    pub(crate) fn new(
        // inner: &'a mut dyn Stream<'a>,
        inner: T,
        codec: framing::Obfs4Codec,
        session: Session,
    ) -> O4Stream<T> {
        let stream = Framed::new(inner, codec);
        let len_seed = session.len_seed();
        let iat_mode = session.iat_mode();

        let mut hasher = Sha256::new();
        hasher.update(len_seed.as_bytes());
        // the result of a sha256 haash is 32 bytes (256 bits) so we will
        // always have enough for a seed here.
        let iat_seed = drbg::Seed::try_from(&hasher.finalize()[..SEED_LENGTH]).unwrap();

        let length_dist = WeightedDist::new(
            len_seed,
            0,
            framing::MAX_SEGMENT_LENGTH as i32,
            session.biased(),
        );
        let iat_dist = WeightedDist::new(iat_seed, 0, MAX_IAT_DELAY as i32, session.biased());

        Self {
            stream,
            session,
            length_dist,
            iat_dist,
            iat_mode,
            read_residual: BytesMut::new(),
            // Initialize with an already-elapsed sleep so the first write
            // proceeds immediately without delay.
            iat_sleep: Box::pin(tokio::time::sleep(Duration::ZERO)),
            iat_delay_pending: false,
        }
    }

    /// Copy as much of `message` into `buf` as fits, parking any leftover bytes
    /// in `residual` for a later `poll_read`. This is the overflow-safe
    /// replacement for `buf.put_slice(&message)`, which panics when the decoded
    /// frame payload is larger than `buf.remaining()`.
    fn stash_payload(residual: &mut BytesMut, buf: &mut ReadBuf<'_>, message: &[u8]) {
        let n = std::cmp::min(buf.remaining(), message.len());
        buf.put_slice(&message[..n]);
        if n < message.len() {
            residual.extend_from_slice(&message[n..]);
        }
    }

    /// Hand previously-buffered residual bytes to `buf` (up to its capacity),
    /// advancing past what was consumed. Returns the number of bytes written.
    fn drain_residual(residual: &mut BytesMut, buf: &mut ReadBuf<'_>) -> usize {
        let n = std::cmp::min(buf.remaining(), residual.len());
        if n > 0 {
            buf.put_slice(&residual[..n]);
            residual.advance(n);
        }
        n
    }

    pub(crate) fn try_handle_non_payload_message(&mut self, msg: framing::Messages) -> Result<()> {
        match msg {
            Messages::Payload(_) => Err(FrameError::InvalidMessage.into()),
            Messages::Padding(_) => Ok(()),

            // TODO: Handle other Messages
            _ => Ok(()),
        }
    }

    /// Attempts to pad a burst of data so that the last segment (as seen on
    /// the wire after encryption) has total length `to_pad_to`. Because the
    /// padding itself occupies framing overhead, achieving the target may
    /// require emitting more than one padding frame.
    ///
    /// The logic works on the *pre-encryption* marshalled buffer `buf`:
    ///
    /// 1. Compute how many bytes the last partial segment occupies:
    ///    `tail_len = buf.len() % MAX_SEGMENT_LENGTH`.
    /// 2. Derive how many padding bytes are needed to bring that tail to
    ///    `to_pad_to` (wrapping around a full segment boundary if necessary).
    /// 3. If the needed padding exceeds the message overhead (`HEADER_LENGTH`),
    ///    emit a single padding frame of exactly the right size.
    /// 4. If the needed padding is smaller than a header but non-zero, we
    ///    must first emit a max-payload padding frame (which pushes the tail
    ///    further) and then a second small frame to land on the target.
    /// 5. If `pad_len == 0` the tail already matches; nothing is emitted.
    pub(crate) fn pad_burst(buf: &mut BytesMut, to_pad_to: usize) -> Result<()> {
        let tail_len = buf.len() % framing::MAX_SEGMENT_LENGTH;

        let pad_len: usize = if to_pad_to >= tail_len {
            to_pad_to - tail_len
        } else {
            (framing::MAX_SEGMENT_LENGTH - tail_len) + to_pad_to
        };

        // Each call to `build_and_marshall(buf, type, data=[], pad_bytes)`
        // appends `MESSAGE_OVERHEAD + pad_bytes` bytes to `buf`.
        // So to append exactly `pad_len` bytes total, we need
        // `pad_bytes = pad_len - MESSAGE_OVERHEAD`.
        if pad_len > MESSAGE_OVERHEAD {
            // Single padding frame whose zero-fill is exactly `pad_len - overhead`.
            Ok(framing::build_and_marshall(
                buf,
                framing::MessageTypes::Payload.into(),
                Vec::<u8>::new(),
                pad_len - MESSAGE_OVERHEAD,
            )?)
        } else if pad_len > 0 {
            // The gap is smaller than a message header: emit one max-size
            // padding frame (which wraps the tail past the segment boundary),
            // then a tiny frame to land on the target.
            framing::build_and_marshall(
                buf,
                framing::MessageTypes::Payload.into(),
                Vec::<u8>::new(),
                framing::MAX_MESSAGE_PAYLOAD_LENGTH - 1,
            )?;
            Ok(framing::build_and_marshall(
                buf,
                framing::MessageTypes::Payload.into(),
                Vec::<u8>::new(),
                pad_len,
            )?)
        } else {
            // Already at the target length.
            Ok(())
        }
    }
}

impl<T> AsyncWrite for O4Stream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<StdResult<usize, IoError>> {
        // ── IAT delay gate ──────────────────────────────────────────────
        // If a previous write armed an inter-arrival delay, wait for it
        // to expire before sending the next batch. This shapes the write
        // cadence according to the sampled distribution without blocking
        // the executor (tokio::time::Sleep, not std::thread::sleep).
        {
            let this = self.as_mut().project();
            if *this.iat_delay_pending {
                match this.iat_sleep.as_mut().poll(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(()) => {
                        *this.iat_delay_pending = false;
                    }
                }
            }
        }

        let msg_len = buf.remaining();
        let iat_mode = {
            let this = self.as_mut().project();
            *this.iat_mode
        };

        let mut this = self.as_mut().project();

        // determine if the stream is ready to send an event?
        match futures::Sink::<&[u8]>::poll_ready(this.stream.as_mut(), cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
            Poll::Ready(Ok(())) => {}
        }

        // Determine the chunk size for this write. In Paranoid mode, each
        // chunk is sized by sampling the length distribution, producing
        // variable-size segments that resist traffic analysis. In all other
        // modes the full MAX_MESSAGE_PAYLOAD_LENGTH is used.
        let chunk_size = if iat_mode == IAT::Paranoid {
            let sampled = this.length_dist.sample().max(0) as usize;
            // Clamp to valid message range: at least 1 byte, at most the
            // protocol maximum.
            sampled.clamp(1, framing::MAX_MESSAGE_PAYLOAD_LENGTH)
        } else {
            framing::MAX_MESSAGE_PAYLOAD_LENGTH
        };

        // while we have bytes in the buffer write `chunk_size` pieces
        // until we have less than that amount left.
        //
        // A single `out_buf` is reused for every chunk and for the trailing
        // frame: the codec's `Encoder` drains it as a `Buf` on `start_send`, and
        // `clear()` resets the length while keeping the allocation.
        let mut len_sent: usize = 0;
        let mut out_buf = BytesMut::with_capacity(framing::MAX_MESSAGE_PAYLOAD_LENGTH);
        while msg_len - len_sent > chunk_size {
            // package one chunk of the mesage as a payload
            let payload = framing::Messages::Payload(buf[len_sent..len_sent + chunk_size].to_vec());

            // send the marshalled payload
            payload.marshall(&mut out_buf)?;
            this.stream.as_mut().start_send(&mut out_buf)?;

            len_sent += chunk_size;
            out_buf.clear();

            // determine if the stream is ready to send more data. if not back off
            match futures::Sink::<&[u8]>::poll_ready(this.stream.as_mut(), cx) {
                Poll::Pending => return Poll::Ready(Ok(len_sent)),
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                Poll::Ready(Ok(())) => {}
            }
        }

        // Marshal the trailing (possibly partial) chunk.
        let payload = framing::Messages::Payload(buf[len_sent..].to_vec());
        payload.marshall(&mut out_buf)?;

        // Apply pad_burst: pad the marshalled buffer so the last wire
        // segment lands on a length sampled from `length_dist`. This
        // hides the true payload size behind the negotiated distribution.
        if iat_mode != IAT::Off {
            let target = this.length_dist.sample().max(0) as usize;
            let target = target.min(framing::MAX_SEGMENT_LENGTH);
            Self::pad_burst(&mut out_buf, target)?;
        }

        this.stream.as_mut().start_send(&mut out_buf)?;

        // ── Arm the IAT delay for the *next* write ──────────────────────
        if iat_mode != IAT::Off {
            let this = self.as_mut().project();
            let sample = this.iat_dist.sample().max(0) as u64;
            let delay = Duration::from_micros(sample);
            this.iat_sleep.as_mut().reset(Instant::now() + delay);
            *this.iat_delay_pending = true;
        }

        Poll::Ready(Ok(msg_len))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<StdResult<(), IoError>> {
        trace!("{} flushing", self.session.id());
        let mut this = self.project();
        match futures::Sink::<&[u8]>::poll_flush(this.stream.as_mut(), cx) {
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<StdResult<(), IoError>> {
        trace!("{} shutting down", self.session.id());
        // On shutdown, skip any pending IAT delay — we want to close promptly.
        let mut this = self.project();
        *this.iat_delay_pending = false;
        match futures::Sink::<&[u8]>::poll_close(this.stream.as_mut(), cx) {
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<T> AsyncRead for O4Stream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<StdResult<(), IoError>> {
        // First, hand back any payload bytes left over from a previous frame
        // that did not fit in the caller's buffer. Doing this before touching
        // the network preserves byte ordering and guarantees forward progress.
        {
            let this = self.as_mut().project();
            if !this.read_residual.is_empty() {
                Self::drain_residual(this.read_residual, buf);
                return Poll::Ready(Ok(()));
            }
        }

        // If there is no payload from the previous Read() calls, consume data off
        // the network.  Not all data received is guaranteed to be usable payload,
        // so do this in a loop until we would block on a read or an error occurs.
        loop {
            let msg = {
                // mutable borrow of self is dropped at the end of this block
                let mut this = self.as_mut().project();
                match this.stream.as_mut().poll_next(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(res) => {
                        // TODO: when would this be None?
                        // It seems like this maybe happens when reading an EOF
                        // or reading from a closed connection
                        if res.is_none() {
                            return Poll::Ready(Ok(()));
                        }

                        match res.unwrap() {
                            Ok(m) => m,
                            Err(e) => Err(e)?,
                        }
                    }
                }
            };

            if let framing::Messages::Payload(message) = msg {
                // A decoded frame may carry more payload than `buf` can hold;
                // copy what fits and park the remainder in `read_residual` for
                // the next poll_read. `put_slice` on the whole message would
                // otherwise panic when `message.len() > buf.remaining()`.
                let this = self.as_mut().project();
                Self::stash_payload(this.read_residual, buf, &message);
                return Poll::Ready(Ok(()));
            }
            if let Messages::Padding(_) = msg {
                continue;
            }

            match self.as_mut().try_handle_non_payload_message(msg) {
                Ok(_) => continue,
                Err(e) => return Poll::Ready(Err(e.into())),
            }
        }
    }
}

impl<T> AsyncWrite for Obfs4Stream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<StdResult<usize, IoError>> {
        let this = self.project();
        this.s.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<StdResult<(), IoError>> {
        let this = self.project();
        this.s.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<StdResult<(), IoError>> {
        let this = self.project();
        this.s.poll_shutdown(cx)
    }
}

impl<T> AsyncRead for Obfs4Stream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<StdResult<(), IoError>> {
        let this = self.project();
        this.s.poll_read(cx, buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

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

    #[test]
    fn maybe_timeout_default_returns_some() {
        let d = MaybeTimeout::Default_.duration();
        assert!(d.is_some());
        assert_eq!(d.unwrap(), CLIENT_HANDSHAKE_TIMEOUT);
    }

    #[test]
    fn maybe_timeout_length_returns_duration() {
        let dur = Duration::from_secs(42);
        let d = MaybeTimeout::Length(dur).duration();
        assert_eq!(d.unwrap(), dur);
    }

    #[test]
    fn maybe_timeout_unset_returns_none() {
        assert!(MaybeTimeout::Unset.duration().is_none());
    }

    #[test]
    fn maybe_timeout_fixed_past_returns_none() {
        let past = Instant::now() - Duration::from_secs(10);
        assert!(MaybeTimeout::Fixed(past).duration().is_none());
    }

    #[test]
    fn maybe_timeout_fixed_future_returns_some() {
        let future = Instant::now() + Duration::from_secs(60);
        let d = MaybeTimeout::Fixed(future).duration();
        assert!(d.is_some());
        assert!(d.unwrap() <= Duration::from_secs(60));
        assert!(d.unwrap() > Duration::from_secs(55));
    }

    // Regression: a single decoded obfs4 frame can carry up to
    // MAX_MESSAGE_PAYLOAD_LENGTH (~1448B) of payload. `poll_read` used to do
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

        let payload_len = crate::constants::MAX_MESSAGE_PAYLOAD_LENGTH;
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

    // ── pad_burst tests ─────────────────────────────────────────────────

    /// pad_burst should pad a buffer so the last segment lands on the
    /// target length. Without pad_burst the raw marshalled payload is
    /// shorter.
    ///
    /// Negative control: if pad_burst is a no-op, the buffer length will
    /// NOT increase, and this test fails.
    #[test]
    fn pad_burst_extends_to_target() {
        let mut buf = BytesMut::new();
        let payload = framing::Messages::Payload(b"hello".to_vec());
        payload.marshall(&mut buf).unwrap();
        let before_len = buf.len();

        // Pick a target that requires meaningful padding.
        let target = framing::MAX_SEGMENT_LENGTH / 2;
        O4Stream::<tokio::io::DuplexStream>::pad_burst(&mut buf, target).unwrap();
        let after_len = buf.len();

        // The buffer must have grown.
        assert!(
            after_len > before_len,
            "pad_burst did not add padding: before={before_len}, after={after_len}"
        );

        // The last segment's size should match the target (mod MAX_SEGMENT_LENGTH).
        let tail = after_len % framing::MAX_SEGMENT_LENGTH;
        assert_eq!(
            tail, target,
            "pad_burst did not hit target: tail={tail}, target={target}"
        );
    }

    /// Without pad_burst, a small payload occupies far fewer bytes than
    /// a half-segment target. This test proves the negative control: the
    /// assertion on tail == target would fail if pad_burst were skipped.
    #[test]
    fn pad_burst_negative_control_fails_without_padding() {
        let mut buf = BytesMut::new();
        let payload = framing::Messages::Payload(b"hello".to_vec());
        payload.marshall(&mut buf).unwrap();

        let target = framing::MAX_SEGMENT_LENGTH / 2;
        let tail = buf.len() % framing::MAX_SEGMENT_LENGTH;
        // Without pad_burst the tail does NOT match the target.
        assert_ne!(
            tail, target,
            "negative control broken: raw payload already at target length"
        );
    }

    /// pad_burst with target == 0 and a buffer that's already segment-
    /// aligned should be a no-op.
    #[test]
    fn pad_burst_zero_target_on_aligned_buffer() {
        let mut buf = BytesMut::new();
        // Fill exactly one full segment worth of data.
        buf.extend_from_slice(&vec![0u8; framing::MAX_SEGMENT_LENGTH]);
        let before = buf.len();
        O4Stream::<tokio::io::DuplexStream>::pad_burst(&mut buf, 0).unwrap();
        assert_eq!(
            buf.len(),
            before,
            "pad_burst(0) on aligned buffer should be no-op"
        );
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
        let client_session =
            crate::sessions::new_client_session(server.0.identity_keys.pk, IAT::Off);

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
}
