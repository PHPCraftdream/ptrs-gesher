#![allow(unused)]

use crate::{
    common::{
        colorize,
        x25519_elligator2::{EphemeralSecret, Keys},
        HmacSha256,
    },
    constants::*,
    framing::{FrameError, Marshall, Obfs4Codec, TryParse, KEY_LENGTH, KEY_MATERIAL_LENGTH},
    handshake::Obfs4NtorPublicKey,
    proto::{MaybeTimeout, Obfs4Stream, IAT},
    sessions, Error, Result,
};

use bytes::{Buf, BufMut, BytesMut};
use hmac::{Hmac, Mac};
use ptrs::{debug, info, trace, warn};
use rand::prelude::*;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::{Duration, Instant};

use std::{
    fmt,
    io::{Error as IoError, ErrorKind as IoErrorKind},
    pin::Pin,
    sync::{Arc, Mutex},
};

/// Builder for constructing an obfs4 [`Client`] with connection parameters.
///
/// Fields are private; configure the builder through its `with_*` setters.
#[derive(Clone, Debug)]
pub struct ClientBuilder {
    /// IAT (inter-arrival time) obfuscation mode for the client.
    pub(crate) iat_mode: IAT,
    /// The server's 32-byte x25519 public key (elligator2 representative).
    pub(crate) station_pubkey: [u8; KEY_LENGTH],
    /// The server's 20-byte node ID (RSA identity fingerprint).
    pub(crate) station_id: [u8; NODE_ID_LENGTH],
    /// Optional path to a persistent state file for this client.
    pub(crate) statefile_path: Option<String>,
    pub(crate) handshake_timeout: MaybeTimeout,
}

impl Default for ClientBuilder {
    fn default() -> Self {
        Self {
            iat_mode: IAT::Off,
            station_pubkey: [0u8; KEY_LENGTH],
            station_id: [0_u8; NODE_ID_LENGTH],
            statefile_path: None,
            handshake_timeout: MaybeTimeout::Default_,
        }
    }
}

impl ClientBuilder {
    /// Construct a `ClientBuilder` from a persistent state file on disk.
    pub fn from_statefile(location: &str) -> Result<Self> {
        Ok(Self {
            iat_mode: IAT::Off,
            station_pubkey: [0_u8; KEY_LENGTH],
            station_id: [0_u8; NODE_ID_LENGTH],
            statefile_path: Some(location.into()),
            handshake_timeout: MaybeTimeout::Default_,
        })
    }

    /// Construct a `ClientBuilder` from a list of raw parameter byte strings.
    pub fn from_params(param_strs: Vec<impl AsRef<[u8]>>) -> Result<Self> {
        Ok(Self {
            iat_mode: IAT::Off,
            station_pubkey: [0_u8; KEY_LENGTH],
            station_id: [0_u8; NODE_ID_LENGTH],
            statefile_path: None,
            handshake_timeout: MaybeTimeout::Default_,
        })
    }

    /// Set the server's x25519 public key on this builder.
    pub fn with_node_pubkey(&mut self, pubkey: [u8; KEY_LENGTH]) -> &mut Self {
        self.station_pubkey = pubkey;
        self
    }

    /// Set the path to the client's persistent state file.
    pub fn with_statefile_path(&mut self, path: &str) -> &mut Self {
        self.statefile_path = Some(path.into());
        self
    }

    /// Set the server's node ID (RSA identity fingerprint) on this builder.
    pub fn with_node_id(&mut self, id: [u8; NODE_ID_LENGTH]) -> &mut Self {
        self.station_id = id;
        self
    }

    /// Set the IAT (inter-arrival time) obfuscation mode on this builder.
    pub fn with_iat_mode(&mut self, iat: IAT) -> &mut Self {
        self.iat_mode = iat;
        self
    }

    /// Set a fixed duration after which the handshake will be aborted.
    pub fn with_handshake_timeout(&mut self, d: Duration) -> &mut Self {
        self.handshake_timeout = MaybeTimeout::Length(d);
        self
    }

    /// Set an absolute deadline after which the handshake will be aborted.
    pub fn with_handshake_deadline(&mut self, deadline: Instant) -> &mut Self {
        self.handshake_timeout = MaybeTimeout::Fixed(deadline);
        self
    }

    /// Disable the handshake timeout so the handshake fails immediately on error.
    pub fn fail_fast(&mut self) -> &mut Self {
        self.handshake_timeout = MaybeTimeout::Unset;
        self
    }

    /// Consume this builder and produce a [`Client`] ready to perform a handshake.
    pub fn build(&self) -> Client {
        Client {
            iat_mode: self.iat_mode,
            station_pubkey: Obfs4NtorPublicKey {
                id: self.station_id.into(),
                pk: self.station_pubkey.into(),
            },
            handshake_timeout: self.handshake_timeout.clone(),
        }
    }

    /// Encode the builder's current parameters as a command-line options string.
    pub fn as_opts(&self) -> String {
        //TODO: String self as command line options
        "".into()
    }
}

impl fmt::Display for ClientBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        //TODO: string self
        write!(f, "")
    }
}

/// Client implementing the obfs4 protocol.
pub struct Client {
    iat_mode: IAT,
    station_pubkey: Obfs4NtorPublicKey,
    handshake_timeout: MaybeTimeout,
}

impl Client {
    /// Extract transport arguments and update this client's configuration.
    pub fn get_args(&mut self, _args: &dyn std::any::Any) {}

    /// On a failed handshake the client will read for the remainder of the
    /// handshake timeout and then close the connection.
    ///
    /// # Cancel safety
    ///
    /// Cancellation drops an owned stream. If the stream is borrowed, discard
    /// it after cancellation because its handshake may be partial.
    pub async fn wrap<'a, T>(self, mut stream: T) -> Result<Obfs4Stream<T>>
    where
        T: AsyncRead + AsyncWrite + Unpin + 'a,
    {
        let deadline = self.handshake_timeout.deadline(CLIENT_HANDSHAKE_TIMEOUT);
        if deadline.is_some_and(|deadline| deadline <= Instant::now()) {
            return Err(Error::HandshakeTimeout);
        }
        let session = sessions::new_client_session(self.station_pubkey, self.iat_mode);

        // The stream is already connected here, so there is no dial→keygen gap
        // to worry about: let `Session::handshake` generate the ephemeral key
        // through the normal `client1()` path (see issue #15 / `establish`).
        session.handshake(stream, deadline, None).await
    }

    /// On a failed handshake the client will read for the remainder of the
    /// handshake timeout and then close the connection.
    ///
    /// # Cancel safety
    ///
    /// Cancellation drops an owned stream. If the stream is borrowed, discard
    /// it after cancellation because its handshake may be partial.
    pub async fn establish<'a, T, E>(
        self,
        stream_fut: Pin<ptrs::FutureResult<T, E>>,
    ) -> Result<Obfs4Stream<T>>
    where
        T: AsyncRead + AsyncWrite + Unpin + 'a,
        E: std::error::Error + Send + Sync + 'static,
    {
        self.establish_with_keygen(Keys::ephemeral_from_rng, stream_fut)
            .await
    }

    /// Variant of [`Client::establish`] parameterised by the keygen closure.
    /// Production callers go through `establish`, which fixes the closure to
    /// `Keys::ephemeral_from_rng(rand::thread_rng())`. The seam exists so the
    /// order invariant (keygen MUST run before `stream_fut.await`) is testable
    /// without instrumenting `rand::thread_rng` itself — a test can pass a
    /// counting closure and a `stream_fut` that records its first poll, then
    /// assert keygen completed before the dial began.
    pub(crate) async fn establish_with_keygen<'a, T, E, F>(
        self,
        keygen: F,
        mut stream_fut: Pin<ptrs::FutureResult<T, E>>,
    ) -> Result<Obfs4Stream<T>>
    where
        T: AsyncRead + AsyncWrite + Unpin + 'a,
        E: std::error::Error + Send + Sync + 'static,
        F: FnOnce(rand::rngs::ThreadRng) -> Result<EphemeralSecret>,
    {
        let deadline = self.handshake_timeout.deadline(CLIENT_HANDSHAKE_TIMEOUT);
        let budget = deadline.unwrap_or_else(|| Instant::now() + CLIENT_HANDSHAKE_TIMEOUT);
        if budget <= Instant::now() {
            return Err(Error::HandshakeTimeout);
        }

        // Issue #15: generate the elligator2-representable ephemeral key
        // BEFORE awaiting the TCP dial. The elligator2 retry loop has ~50%
        // success per iteration, so doing it after the dial inserts a
        // variable, network-observable gap between TCP handshake and the
        // first byte that a censor can fingerprint. Pre-generating moves
        // that variance entirely before the wire is touched.
        let ephem = keygen(rand::thread_rng())?;

        tokio::time::timeout_at(budget, async {
            let stream = stream_fut.await.map_err(|e| Error::Other(Box::new(e)))?;
            let session = sessions::new_client_session(self.station_pubkey, self.iat_mode);
            session.handshake(stream, deadline, Some(ephem)).await
        })
        .await
        .map_err(|_| Error::HandshakeTimeout)?
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn builder_with_methods() {
        let mut b = ClientBuilder::default();
        let pk = [0xAA; KEY_LENGTH];
        let id = [0xBB; NODE_ID_LENGTH];

        b.with_node_pubkey(pk)
            .with_node_id(id)
            .with_iat_mode(IAT::Paranoid)
            .with_statefile_path("/tmp/test");

        assert_eq!(b.station_pubkey, pk);
        assert_eq!(b.station_id, id);
        assert_eq!(b.iat_mode, IAT::Paranoid);
        assert_eq!(b.statefile_path.as_deref(), Some("/tmp/test"));
    }

    #[test]
    fn builder_timeout_modes() {
        let mut b = ClientBuilder::default();

        b.with_handshake_timeout(Duration::from_secs(30));
        assert!(matches!(b.handshake_timeout, MaybeTimeout::Length(_)));

        b.fail_fast();
        assert!(matches!(b.handshake_timeout, MaybeTimeout::Unset));

        let deadline = Instant::now() + Duration::from_secs(60);
        b.with_handshake_deadline(deadline);
        assert!(matches!(b.handshake_timeout, MaybeTimeout::Fixed(_)));
    }

    // Issue #15 regression: `Client::establish` MUST generate the ephemeral
    // key before awaiting the stream future, so the elligator2 retry loop
    // (~50% miss rate per iteration) cannot insert a network-observable gap
    // between TCP dial and the first byte on the wire.
    //
    // We exercise `establish_with_keygen` with:
    //   * an instrumented `keygen` closure that bumps `keygen_calls`, and
    //   * a `stream_fut` whose first poll bumps `dial_first_poll`.
    //
    // The order assertion is: at the moment the dial begins, keygen has
    // already happened (`keygen_calls == 1` strictly before
    // `dial_first_poll == 1`).
    //
    // Negative control: if the implementation regresses to awaiting the
    // stream BEFORE keygen, then at the moment `dial_first_poll` flips to
    // 1, `keygen_calls` is still 0 and the inner assertion below fires.
    #[tokio::test(start_paused = true)]
    async fn establish_runs_keygen_before_stream_fut() {
        use std::future::poll_fn;
        use std::pin::Pin;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use std::task::Poll;

        let keygen_calls = Arc::new(AtomicUsize::new(0));
        let dial_first_poll = Arc::new(AtomicUsize::new(0));
        let keygen_at_dial = Arc::new(AtomicUsize::new(usize::MAX));

        let keygen_calls_c = Arc::clone(&keygen_calls);
        let keygen = move |rng: rand::rngs::ThreadRng| -> Result<EphemeralSecret> {
            keygen_calls_c.fetch_add(1, Ordering::SeqCst);
            Keys::ephemeral_from_rng(rng)
        };

        let dial_first_poll_c = Arc::clone(&dial_first_poll);
        let keygen_at_dial_c = Arc::clone(&keygen_at_dial);
        let keygen_calls_for_dial = Arc::clone(&keygen_calls);
        let stream_fut: Pin<
            Box<dyn std::future::Future<Output = std::io::Result<tokio::io::DuplexStream>> + Send>,
        > = Box::pin(poll_fn(move |_cx| {
            // Record on the FIRST poll how many keygen calls had already
            // completed; that is the exact "dial moment" we care about.
            if dial_first_poll_c.fetch_add(1, Ordering::SeqCst) == 0 {
                keygen_at_dial_c.store(
                    keygen_calls_for_dial.load(Ordering::SeqCst),
                    Ordering::SeqCst,
                );
            }
            // Resolve immediately to a throwaway duplex half — the handshake
            // that follows is expected to time out (the other half is dropped),
            // which is fine: we only assert the keygen↔dial order, not a
            // successful handshake.
            let (a, _b) = tokio::io::duplex(64);
            Poll::Ready(Ok(a))
        }));

        let client = ClientBuilder::default()
            .with_node_pubkey([0xAA; KEY_LENGTH])
            .with_node_id([0xBB; NODE_ID_LENGTH])
            .with_handshake_timeout(Duration::from_millis(5))
            .build();

        // The handshake will fail (duplex half is dropped). We only care
        // about the keygen↔dial ordering recorded above.
        let _ = client.establish_with_keygen(keygen, stream_fut).await;

        assert_eq!(
            keygen_calls.load(Ordering::SeqCst),
            1,
            "keygen closure must run exactly once"
        );
        assert_eq!(
            dial_first_poll.load(Ordering::SeqCst),
            1,
            "stream_fut must be polled exactly once"
        );
        assert_eq!(
            keygen_at_dial.load(Ordering::SeqCst),
            1,
            "keygen MUST complete before stream_fut is first polled (issue #15)"
        );
    }
}
