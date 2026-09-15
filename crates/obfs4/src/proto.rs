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

#[pin_project]
pub(crate) struct IatCarrier<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    #[pin]
    inner: T,
    mode: IAT,
    iat_dist: probdist::WeightedDist,
    length_dist: probdist::WeightedDist,
    iat_sleep: Pin<Box<Sleep>>,
    delay_pending: bool,
    shutdown_requested: bool,
    scheduled_target: Option<usize>,
    pad_target: Option<usize>,
}

impl<T> IatCarrier<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn new(
        inner: T,
        mode: IAT,
        iat_dist: probdist::WeightedDist,
        length_dist: probdist::WeightedDist,
    ) -> Self {
        Self {
            inner,
            mode,
            iat_dist,
            length_dist,
            iat_sleep: Box::pin(tokio::time::sleep(Duration::ZERO)),
            delay_pending: false,
            shutdown_requested: false,
            scheduled_target: None,
            pad_target: None,
        }
    }

    fn clear_delay(&mut self) {
        self.delay_pending = false;
        self.shutdown_requested = true;
    }

    fn take_pad_target(&mut self) -> Option<usize> {
        self.pad_target.take()
    }

    fn padding_added(&mut self, buffer_len: usize) {
        if self.scheduled_target != Some(buffer_len) {
            self.scheduled_target = None;
        }
    }
}

impl<T> AsyncRead for IatCarrier<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<StdResult<(), IoError>> {
        self.project().inner.poll_read(cx, buf)
    }
}

impl<T> AsyncWrite for IatCarrier<T>
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

        let scheduled = self.as_ref().get_ref().scheduled_target;
        if self.as_ref().get_ref().mode == IAT::Paranoid && scheduled.is_none() {
            let target = self.as_ref().get_ref().length_dist.sample().max(1) as usize;
            let target = target.min(framing::MAX_SEGMENT_LENGTH);
            if buf.len() < target {
                let this = self.as_mut().project();
                *this.scheduled_target = Some(target);
                *this.pad_target = Some(target);
                return Poll::Pending;
            }
            self.as_mut().project().scheduled_target.replace(target);
        } else if self.as_ref().get_ref().mode != IAT::Off && scheduled.is_none() {
            self.as_mut()
                .project()
                .scheduled_target
                .replace(buf.len().min(framing::MAX_SEGMENT_LENGTH));
        }

        if self.as_ref().get_ref().mode != IAT::Off && self.as_ref().get_ref().delay_pending {
            let this = self.as_mut().project();
            match this.iat_sleep.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(()) => *this.delay_pending = false,
            }
        }

        let write_len = self
            .as_ref()
            .get_ref()
            .scheduled_target
            .map_or(buf.len(), |target| target.min(buf.len()));
        let result = self
            .as_mut()
            .project()
            .inner
            .poll_write(cx, &buf[..write_len]);
        if let Poll::Ready(Ok(written)) = result {
            if written > 0 && self.as_ref().get_ref().mode != IAT::Off {
                let this = self.as_mut().project();
                let target = this.scheduled_target.as_mut().expect("scheduled target");
                *target -= written;
                if *target == 0 {
                    *this.scheduled_target = None;
                    if !*this.shutdown_requested {
                        let delay =
                            Duration::from_micros(this.iat_dist.sample().max(0) as u64 * 100);
                        this.iat_sleep.as_mut().reset(Instant::now() + delay);
                        *this.delay_pending = true;
                    }
                }
            }
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<StdResult<(), IoError>> {
        if self.as_ref().get_ref().mode != IAT::Off && self.as_ref().get_ref().delay_pending {
            let this = self.as_mut().project();
            match this.iat_sleep.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(()) => *this.delay_pending = false,
            }
        }
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<StdResult<(), IoError>> {
        self.project().inner.poll_shutdown(cx)
    }
}

#[derive(Clone, Debug)]
struct StoredIoError {
    message: String,
    kind: std::io::ErrorKind,
    raw_os_error: Option<i32>,
}

impl StoredIoError {
    fn from_error(error: &IoError) -> Self {
        Self {
            message: error.to_string(),
            kind: error.kind(),
            raw_os_error: error.raw_os_error(),
        }
    }

    fn into_error(self) -> IoError {
        self.raw_os_error.map_or_else(
            || IoError::new(self.kind, self.message),
            IoError::from_raw_os_error,
        )
    }
}

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
    pub(crate) fn deadline(&self, default: Duration) -> std::io::Result<Option<Instant>> {
        match self {
            MaybeTimeout::Default_ => {
                Instant::now()
                    .checked_add(default)
                    .map(Some)
                    .ok_or_else(|| {
                        IoError::new(
                            std::io::ErrorKind::InvalidInput,
                            "handshake timeout overflows the monotonic clock",
                        )
                    })
            }
            MaybeTimeout::Fixed(i) => Ok(Some(*i)),
            MaybeTimeout::Length(d) => Instant::now().checked_add(*d).map(Some).ok_or_else(|| {
                IoError::new(
                    std::io::ErrorKind::InvalidInput,
                    "handshake timeout overflows the monotonic clock",
                )
            }),
            MaybeTimeout::Unset => Ok(None),
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
        self.s.stream.get_ref().delay_pending
    }

    #[cfg(test)]
    pub(crate) fn set_iat_dist_for_test(&mut self, dist: probdist::WeightedDist) {
        self.s.stream.get_mut().iat_dist = dist;
    }

    #[cfg(test)]
    pub(crate) fn iat_dist_for_test(&self) -> &probdist::WeightedDist {
        &self.s.stream.get_ref().iat_dist
    }
}

#[pin_project]
pub(crate) struct O4Stream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    #[pin]
    pub stream: Framed<IatCarrier<T>, framing::Obfs4Codec>,

    pub length_dist: probdist::WeightedDist,

    pub iat_mode: IAT,

    pub session: Session,

    /// Bytes decoded from a single obfs4 frame that did not fit in the caller's
    /// `ReadBuf` on a previous `poll_read`. A decoded frame can carry up to
    /// `MAX_MESSAGE_PAYLOAD_LENGTH` (~1427B) of payload, which is larger than an
    /// arbitrary caller buffer; the surplus is parked here and delivered on
    /// subsequent reads so no payload is lost (and `put_slice` never overflows).
    read_residual: BytesMut,

    /// Reusable plaintext/wire staging for padding added after backpressure.
    padding_scratch: BytesMut,

    /// A non-retryable carrier error observed after a prefix was accepted.
    /// It is reported by the next operation without replaying that prefix.
    terminal_error: Option<StoredIoError>,

    /// Whether the carrier has completed its close operation.
    shutdown_complete: bool,
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
        let mut stream = Framed::new(
            IatCarrier::new(inner, iat_mode, iat_dist, length_dist.clone()),
            codec,
        );
        if !handshake_residual.is_empty() {
            // Prepend the handshake over-read into the decode buffer so the
            // first `poll_next` sees the data frames that arrived alongside the
            // server hello, instead of starting from an empty buffer and
            // desynchronising on the next frame length.
            stream
                .read_buffer_mut()
                .extend_from_slice(&handshake_residual);
        }

        let mut transport = Self {
            stream,
            session,
            length_dist,
            iat_mode,
            read_residual: BytesMut::new(),
            padding_scratch: BytesMut::with_capacity(framing::MAX_SEGMENT_LENGTH),
            terminal_error: None,
            shutdown_complete: false,
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
                    self.stream
                        .get_mut()
                        .iat_dist
                        .reseed(drbg::Seed::try_from(&digest[..SEED_LENGTH])?);
                }
                Ok(())
            }
        }
    }

    /// Append independently encrypted padding packets, as in obfs4proxy's padBurst.
    /// https://github.com/Yawning/obfs4/blob/master/transports/obfs4/obfs4.go
    fn pad_burst<W>(
        stream: &mut Framed<W, framing::Obfs4Codec>,
        burst_len: usize,
        target: usize,
        scratch: &mut BytesMut,
    ) -> Result<()>
    where
        W: AsyncRead + AsyncWrite + Unpin,
    {
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

    fn poll_ready_with_iat(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<StdResult<(), IoError>> {
        loop {
            let mut this = self.as_mut().project();
            match futures::Sink::<framing::PayloadFrame<'_>>::poll_ready(this.stream.as_mut(), cx) {
                Poll::Pending => {
                    let target = this.stream.as_mut().get_mut().get_mut().take_pad_target();
                    let Some(target) = target else {
                        return Poll::Pending;
                    };
                    let stream = this.stream.as_mut().get_mut();
                    let burst_len = stream.write_buffer().len();
                    if let Err(error) =
                        Self::pad_burst(stream, burst_len, target, this.padding_scratch)
                    {
                        return Poll::Ready(Err(error.into()));
                    }
                    let buffer_len = stream.write_buffer().len();
                    stream.get_mut().padding_added(buffer_len);
                }
                Poll::Ready(Ok(())) => return Poll::Ready(Ok(())),
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
            }
        }
    }

    fn poll_flush_with_iat(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<StdResult<(), IoError>> {
        loop {
            let mut this = self.as_mut().project();
            match futures::Sink::<&[u8]>::poll_flush(this.stream.as_mut(), cx) {
                Poll::Pending => {
                    let target = this.stream.as_mut().get_mut().get_mut().take_pad_target();
                    let Some(target) = target else {
                        return Poll::Pending;
                    };
                    let stream = this.stream.as_mut().get_mut();
                    let burst_len = stream.write_buffer().len();
                    if let Err(error) =
                        Self::pad_burst(stream, burst_len, target, this.padding_scratch)
                    {
                        return Poll::Ready(Err(error.into()));
                    }
                    let buffer_len = stream.write_buffer().len();
                    stream.get_mut().padding_added(buffer_len);
                }
                Poll::Ready(Ok(())) => return Poll::Ready(Ok(())),
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
            }
        }
    }

    fn poll_close_with_iat(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<StdResult<(), IoError>> {
        loop {
            let mut this = self.as_mut().project();
            match futures::Sink::<&[u8]>::poll_close(this.stream.as_mut(), cx) {
                Poll::Pending => {
                    let target = this.stream.as_mut().get_mut().get_mut().take_pad_target();
                    let Some(target) = target else {
                        return Poll::Pending;
                    };
                    let stream = this.stream.as_mut().get_mut();
                    let burst_len = stream.write_buffer().len();
                    if let Err(error) =
                        Self::pad_burst(stream, burst_len, target, this.padding_scratch)
                    {
                        return Poll::Ready(Err(error.into()));
                    }
                    let buffer_len = stream.write_buffer().len();
                    stream.get_mut().padding_added(buffer_len);
                }
                Poll::Ready(Ok(())) => return Poll::Ready(Ok(())),
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
            }
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
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.as_ref().get_ref().shutdown_complete {
            return Poll::Ready(Err(IoError::new(
                std::io::ErrorKind::NotConnected,
                "obfs4 stream is already shut down",
            )));
        }
        if let Some(error) = self.as_ref().get_ref().terminal_error.as_ref().cloned() {
            return Poll::Ready(Err(error.into_error()));
        }
        let msg_len = buf.remaining();
        let iat_mode = {
            let this = self.as_mut().project();
            *this.iat_mode
        };

        match self.as_mut().poll_ready_with_iat(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => {
                if error.kind() != std::io::ErrorKind::Interrupted {
                    *self.as_mut().project().terminal_error =
                        Some(StoredIoError::from_error(&error));
                } else {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                return Poll::Ready(Err(error));
            }
            Poll::Ready(Ok(())) => {}
        }

        let chunk_size = framing::MAX_MESSAGE_PAYLOAD_LENGTH;

        // while we have bytes in the buffer write `chunk_size` pieces
        // until we have less than that amount left.
        //
        let mut len_sent: usize = 0;
        let mut burst_len = 0;
        while msg_len - len_sent > chunk_size {
            let mut this = self.as_mut().project();
            let payload = &buf[len_sent..len_sent + chunk_size];
            burst_len += framing::FRAME_OVERHEAD + framing::MESSAGE_OVERHEAD + payload.len();
            if let Err(e) = futures::Sink::<framing::PayloadFrame<'_>>::start_send(
                this.stream.as_mut(),
                framing::PayloadFrame::new(payload),
            ) {
                let error: IoError = e.into();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    if len_sent == 0 {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                    return Poll::Ready(Ok(len_sent));
                }
                *this.terminal_error = Some(StoredIoError::from_error(&error));
                return Poll::Ready(if len_sent == 0 {
                    Err(error)
                } else {
                    Ok(len_sent)
                });
            }

            len_sent += chunk_size;

            // determine if the stream is ready to send more data. if not back off
            match self.as_mut().poll_ready_with_iat(cx) {
                Poll::Pending => {
                    if iat_mode != IAT::Paranoid {
                        let mut this = self.as_mut().project();
                        let target = this.length_dist.sample().max(0) as usize;
                        if let Err(e) = Self::pad_burst(
                            this.stream.as_mut().get_mut(),
                            burst_len,
                            target,
                            this.padding_scratch,
                        ) {
                            let error: IoError = e.into();
                            *this.terminal_error = Some(StoredIoError::from_error(&error));
                        }
                    }
                    return Poll::Ready(Ok(len_sent));
                }
                Poll::Ready(Err(error)) => {
                    if error.kind() == std::io::ErrorKind::Interrupted {
                        if iat_mode != IAT::Paranoid {
                            let mut this = self.as_mut().project();
                            let target = this.length_dist.sample().max(0) as usize;
                            if let Err(padding_error) = Self::pad_burst(
                                this.stream.as_mut().get_mut(),
                                burst_len,
                                target,
                                this.padding_scratch,
                            ) {
                                let padding_error: IoError = padding_error.into();
                                *this.terminal_error =
                                    Some(StoredIoError::from_error(&padding_error));
                            }
                        }
                        return Poll::Ready(Ok(len_sent));
                    }
                    *self.as_mut().project().terminal_error =
                        Some(StoredIoError::from_error(&error));
                    return Poll::Ready(Ok(len_sent));
                }
                Poll::Ready(Ok(())) => {}
            }
        }

        let mut this = self.as_mut().project();
        // Length padding remains enabled independently of IAT delays.
        let payload = &buf[len_sent..];
        burst_len += framing::FRAME_OVERHEAD + framing::MESSAGE_OVERHEAD + payload.len();
        if let Err(e) = futures::Sink::<framing::PayloadFrame<'_>>::start_send(
            this.stream.as_mut(),
            framing::PayloadFrame::new(payload),
        ) {
            let error: IoError = e.into();
            if error.kind() == std::io::ErrorKind::Interrupted {
                if len_sent == 0 {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                return Poll::Ready(Ok(len_sent));
            }
            *this.terminal_error = Some(StoredIoError::from_error(&error));
            return Poll::Ready(if len_sent == 0 {
                Err(error)
            } else {
                Ok(len_sent)
            });
        }
        if iat_mode != IAT::Paranoid {
            let target = this.length_dist.sample().max(0) as usize;
            if let Err(e) = Self::pad_burst(
                this.stream.as_mut().get_mut(),
                burst_len,
                target,
                this.padding_scratch,
            ) {
                let error: IoError = e.into();
                *this.terminal_error = Some(StoredIoError::from_error(&error));
                return Poll::Ready(Ok(msg_len));
            }
        }

        Poll::Ready(Ok(msg_len))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<StdResult<(), IoError>> {
        trace!("{} flushing", self.session.id());
        if self.as_ref().get_ref().shutdown_complete {
            return Poll::Ready(Ok(()));
        }
        if let Some(error) = self.as_ref().get_ref().terminal_error.as_ref().cloned() {
            return Poll::Ready(Err(error.into_error()));
        }
        match self.as_mut().poll_flush_with_iat(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(error)) => {
                if error.kind() != std::io::ErrorKind::Interrupted {
                    *self.project().terminal_error = Some(StoredIoError::from_error(&error));
                } else {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                Poll::Ready(Err(error))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<StdResult<(), IoError>> {
        trace!("{} shutting down", self.session.id());
        if self.as_ref().get_ref().shutdown_complete {
            return Poll::Ready(Ok(()));
        }
        if let Some(error) = self.as_ref().get_ref().terminal_error.as_ref().cloned() {
            return Poll::Ready(Err(error.into_error()));
        }
        self.as_mut()
            .project()
            .stream
            .as_mut()
            .get_mut()
            .get_mut()
            .clear_delay();
        match self.as_mut().poll_close_with_iat(cx) {
            Poll::Ready(Ok(_)) => {
                *self.project().shutdown_complete = true;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => {
                if error.kind() != std::io::ErrorKind::Interrupted {
                    *self.project().terminal_error = Some(StoredIoError::from_error(&error));
                } else {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                Poll::Ready(Err(error))
            }
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
