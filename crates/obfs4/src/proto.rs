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
use futures::{Future, Stream};
use pin_project::pin_project;
use ptrs::trace;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Duration, Instant, Sleep};
use tokio_util::codec::{Decoder, Encoder, Framed};

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
    pub(crate) fn deadline(&self, default: Duration) -> Option<Instant> {
        match self {
            MaybeTimeout::Default_ => Some(Instant::now() + default),
            MaybeTimeout::Fixed(i) => Some(*i),
            MaybeTimeout::Length(d) => Some(Instant::now() + *d),
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
    /// `MAX_MESSAGE_PAYLOAD_LENGTH` (~1427B) of payload, which is larger than an
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

    /// Reusable plaintext/wire staging for padding added after backpressure.
    padding_scratch: BytesMut,
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
        // Bytes already read off the wire during the handshake that belong to
        // the data stream (e.g. the client over-read past the server hello when
        // the peer coalesced its handshake reply with the first data frames
        // into one TCP segment). These MUST seed the `Framed` read buffer or
        // they are lost and the codec desynchronises on the next frame length.
        handshake_residual: BytesMut,
    ) -> Result<O4Stream<T>> {
        let mut stream = Framed::new(inner, codec);
        if !handshake_residual.is_empty() {
            // Prepend the handshake over-read into the decode buffer so the
            // first `poll_next` sees the data frames that arrived alongside the
            // server hello, instead of starting from an empty buffer and
            // desynchronising the frame decoder.
            stream
                .read_buffer_mut()
                .extend_from_slice(&handshake_residual);
        }
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

        let mut transport = Self {
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
            padding_scratch: BytesMut::with_capacity(framing::MAX_SEGMENT_LENGTH),
        };
        let mut buffered = std::mem::take(transport.stream.read_buffer_mut());
        while let Some(message) = transport.stream.codec_mut().decode(&mut buffered)? {
            match message {
                Messages::Payload(bytes) => transport.read_residual.extend_from_slice(&bytes),
                message => transport.try_handle_non_payload_message(message)?,
            }
        }
        *transport.stream.read_buffer_mut() = buffered;
        Ok(transport)
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

            Messages::PrngSeed(bytes) => {
                if let Session::Client(client) = &mut self.session {
                    let seed = drbg::Seed::from(bytes);
                    client.set_len_seed(seed.clone());
                    self.length_dist.reseed(seed);
                    let digest = Sha256::digest(bytes);
                    self.iat_dist
                        .reseed(drbg::Seed::try_from(&digest[..SEED_LENGTH])?);
                }
                Ok(())
            }
        }
    }

    /// Append independently encrypted padding packets, as in obfs4proxy's padBurst.
    /// https://github.com/Yawning/obfs4/blob/master/transports/obfs4/obfs4.go
    fn pad_burst(
        stream: &mut Framed<T, framing::Obfs4Codec>,
        burst_len: usize,
        target: usize,
        scratch: &mut BytesMut,
    ) -> Result<()> {
        let tail = burst_len % framing::MAX_SEGMENT_LENGTH;
        let pad = if target >= tail {
            target - tail
        } else {
            framing::MAX_SEGMENT_LENGTH - tail + target
        };
        let lengths = if pad == 0 {
            [None, None]
        } else if pad > HEADER_LENGTH {
            [Some(pad - HEADER_LENGTH), None]
        } else {
            [Some(framing::MAX_MESSAGE_PAYLOAD_LENGTH), Some(pad)]
        };
        scratch.clear();
        for length in lengths.into_iter().flatten() {
            stream
                .codec_mut()
                .encode(framing::PaddingFrame::new(length), scratch)?;
            stream.write_buffer_mut().extend_from_slice(scratch);
            scratch.clear();
        }
        // At most two extra frames; the next poll_ready applies backpressure.
        Ok(())
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
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
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
        match futures::Sink::<framing::PayloadFrame<'_>>::poll_ready(this.stream.as_mut(), cx) {
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
        let mut len_sent: usize = 0;
        let mut burst_len = 0;
        while msg_len - len_sent > chunk_size {
            let payload = &buf[len_sent..len_sent + chunk_size];
            burst_len += framing::FRAME_OVERHEAD + framing::MESSAGE_OVERHEAD + payload.len();
            futures::Sink::<framing::PayloadFrame<'_>>::start_send(
                this.stream.as_mut(),
                framing::PayloadFrame::new(payload),
            )?;

            len_sent += chunk_size;

            // determine if the stream is ready to send more data. if not back off
            match futures::Sink::<framing::PayloadFrame<'_>>::poll_ready(this.stream.as_mut(), cx) {
                Poll::Pending => {
                    let target = this.length_dist.sample().max(0) as usize;
                    Self::pad_burst(
                        this.stream.as_mut().get_mut(),
                        burst_len,
                        target,
                        this.padding_scratch,
                    )?;
                    if iat_mode != IAT::Off {
                        let delay =
                            Duration::from_micros(this.iat_dist.sample().max(0) as u64 * 100);
                        this.iat_sleep.as_mut().reset(Instant::now() + delay);
                        *this.iat_delay_pending = true;
                    }
                    return Poll::Ready(Ok(len_sent));
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                Poll::Ready(Ok(())) => {}
            }
        }

        // Length padding remains enabled independently of IAT delays.
        let payload = &buf[len_sent..];
        burst_len += framing::FRAME_OVERHEAD + framing::MESSAGE_OVERHEAD + payload.len();
        futures::Sink::<framing::PayloadFrame<'_>>::start_send(
            this.stream.as_mut(),
            framing::PayloadFrame::new(payload),
        )?;
        let target = this.length_dist.sample().max(0) as usize;
        Self::pad_burst(
            this.stream.as_mut().get_mut(),
            burst_len,
            target,
            this.padding_scratch,
        )?;

        // ── Arm the IAT delay for the *next* write ──────────────────────
        if iat_mode != IAT::Off {
            let this = self.as_mut().project();
            let sample = this.iat_dist.sample().max(0) as u64;
            let delay = Duration::from_micros(sample * 100);
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
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
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
mod tests;
