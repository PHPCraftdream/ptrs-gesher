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
use futures::{Sink, Stream};
use pin_project::pin_project;
use ptrs::trace;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Duration, Instant};
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

    pub session: Session,

    /// Bytes decoded from a single obfs4 frame that did not fit in the caller's
    /// `ReadBuf` on a previous `poll_read`. A decoded frame can carry up to
    /// `MAX_MESSAGE_PAYLOAD_LENGTH` (~1448B) of payload, which is larger than an
    /// arbitrary caller buffer; the surplus is parked here and delivered on
    /// subsequent reads so no payload is lost (and `put_slice` never overflows).
    read_residual: BytesMut,
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
        let iat_dist = WeightedDist::new(
            iat_seed,
            0,
            framing::MAX_SEGMENT_LENGTH as i32,
            session.biased(),
        );

        Self {
            stream,
            session,
            length_dist,
            iat_dist,
            read_residual: BytesMut::new(),
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

    /*// TODO Apply pad_burst logic and IAT policy to packet assembly (probably as part of AsyncRead / AsyncWrite impl)
    /// Attempts to pad a burst of data so that the last packet is of the length
    /// `to_pad_to`. This can involve creating multiple packets, making this
    /// slightly complex.
    ///
    /// TODO: document logic more clearly
    pub(crate) fn pad_burst(&self, buf: &mut BytesMut, to_pad_to: usize) -> Result<()> {
        let tail_len = buf.len() % framing::MAX_SEGMENT_LENGTH;

        let pad_len: usize = if to_pad_to >= tail_len {
            to_pad_to - tail_len
        } else {
            (framing::MAX_SEGMENT_LENGTH - tail_len) + to_pad_to
        };

        if pad_len > HEADER_LENGTH {
            // pad_len > 19
            Ok(framing::build_and_marshall(
                buf,
                MessageTypes::Payload.into(),
                vec![],
                pad_len - HEADER_LENGTH,
            )?)
        } else if pad_len > 0 {
            framing::build_and_marshall(
                buf,
                MessageTypes::Payload.into(),
                vec![],
                framing::MAX_MESSAGE_PAYLOAD_LENGTH,
            )?;
            // } else {
            Ok(framing::build_and_marshall(
                buf,
                MessageTypes::Payload.into(),
                vec![],
                pad_len,
            )?)
        } else {
            Ok(())
        }
    } */
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
        let msg_len = buf.remaining();
        let mut this = self.as_mut().project();

        // determine if the stream is ready to send an event?
        if futures::Sink::<&[u8]>::poll_ready(this.stream.as_mut(), cx) == Poll::Pending {
            return Poll::Pending;
        }

        // while we have bytes in the buffer write MAX_MESSAGE_PAYLOAD_LENGTH
        // chunks until we have less than that amount left.
        // TODO: asyncwrite - apply length_dist instead of just full payloads
        let mut len_sent: usize = 0;
        let mut out_buf = BytesMut::with_capacity(framing::MAX_MESSAGE_PAYLOAD_LENGTH);
        while msg_len - len_sent > framing::MAX_MESSAGE_PAYLOAD_LENGTH {
            // package one chunk of the mesage as a payload
            let payload = framing::Messages::Payload(
                buf[len_sent..len_sent + framing::MAX_MESSAGE_PAYLOAD_LENGTH].to_vec(),
            );

            // send the marshalled payload
            payload.marshall(&mut out_buf)?;
            this.stream.as_mut().start_send(&mut out_buf)?;

            len_sent += framing::MAX_MESSAGE_PAYLOAD_LENGTH;
            out_buf.clear();

            // determine if the stream is ready to send more data. if not back off
            if futures::Sink::<&[u8]>::poll_ready(this.stream.as_mut(), cx) == Poll::Pending {
                return Poll::Ready(Ok(len_sent));
            }
        }

        let payload = framing::Messages::Payload(buf[len_sent..].to_vec());

        let mut out_buf = BytesMut::new();
        payload.marshall(&mut out_buf)?;
        this.stream.as_mut().start_send(out_buf)?;

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
        let mut this = self.project();
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
}
