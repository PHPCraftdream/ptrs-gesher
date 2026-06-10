//! obfs4 session details and construction
//!
/// Session state management as a way to organize session establishment and
/// steady state transfer.
use crate::{
    common::{
        colorize, discard, drbg,
        ntor_arti::{ClientHandshake, RelayHandshakeError, ServerHandshake},
    },
    constants::*,
    framing,
    handshake::{
        CHSMaterials, Obfs4Keygen, Obfs4NtorHandshake, Obfs4NtorPublicKey, Obfs4NtorSecretKey,
        SHSMaterials,
    },
    proto::{O4Stream, Obfs4Stream, IAT},
    server::Server,
    Error, Result,
};

use std::io::{Error as IoError, ErrorKind as IoErrorKind};

use bytes::BytesMut;
use ptrs::{debug, info, trace};
use rand_core::RngCore;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;
use tokio_util::codec::Decoder;

/// Initial state for a Session, created with any params.
pub(crate) struct Initialized;

/// A session has completed the handshake and made it to steady state transfer.
pub(crate) struct Established;

/// The session broke due to something like a timeout, reset, lost connection, etc.
trait Fault {}

pub(crate) enum Session {
    Client(ClientSession<Established>),
    Server(ServerSession<Established>),
}

impl Session {
    #[allow(unused)]
    pub fn id(&self) -> String {
        match self {
            Session::Client(cs) => format!("c{}", cs.session_id()),
            Session::Server(ss) => format!("s{}", ss.session_id()),
        }
    }

    pub fn biased(&self) -> bool {
        match self {
            Session::Client(cs) => cs.biased,
            Session::Server(ss) => ss.biased, //biased,
        }
    }

    pub fn len_seed(&self) -> drbg::Seed {
        match self {
            Session::Client(cs) => cs.len_seed.clone(),
            Session::Server(ss) => ss.len_seed.clone(),
        }
    }
}

// ================================================================ //
//                       Client States                              //
// ================================================================ //

pub(crate) struct ClientSession<S: ClientSessionState> {
    node_pubkey: Obfs4NtorPublicKey,
    session_id: [u8; SESSION_ID_LEN],
    iat_mode: IAT, // TODO: add IAT normal / paranoid writing modes
    epoch_hour: String,

    biased: bool,

    len_seed: drbg::Seed,

    _state: S,
}

#[allow(unused)]
struct ClientHandshakeFailed {
    details: String,
}

struct ClientHandshaking {}

pub(crate) trait ClientSessionState {}
impl ClientSessionState for Initialized {}
impl ClientSessionState for ClientHandshaking {}
impl ClientSessionState for Established {}

impl ClientSessionState for ClientHandshakeFailed {}
impl Fault for ClientHandshakeFailed {}

impl<S: ClientSessionState> ClientSession<S> {
    pub fn session_id(&self) -> String {
        String::from("c-") + &colorize(self.session_id)
    }

    pub(crate) fn set_session_id(&mut self, id: [u8; SESSION_ID_LEN]) {
        debug!(
            "{} -> {} client updating session id",
            colorize(self.session_id),
            colorize(id)
        );
        self.session_id = id;
    }

    /// Helper function to perform state transitions.
    fn transition<T: ClientSessionState>(self, t: T) -> ClientSession<T> {
        ClientSession {
            node_pubkey: self.node_pubkey,
            session_id: self.session_id,
            iat_mode: self.iat_mode,
            epoch_hour: self.epoch_hour,
            biased: self.biased,

            len_seed: self.len_seed,
            _state: t,
        }
    }

    /// Helper function to perform state transitions.
    fn fault<F: Fault + ClientSessionState>(self, f: F) -> ClientSession<F> {
        ClientSession {
            node_pubkey: self.node_pubkey,
            session_id: self.session_id,
            iat_mode: self.iat_mode,
            epoch_hour: self.epoch_hour,
            biased: self.biased,

            len_seed: self.len_seed,
            _state: f,
        }
    }
}

pub(crate) fn new_client_session(
    station_pubkey: Obfs4NtorPublicKey,
    iat_mode: IAT,
) -> ClientSession<Initialized> {
    new_client_session_with_rng(station_pubkey, iat_mode, &mut rand::thread_rng())
}

pub(crate) fn new_client_session_with_rng<R: RngCore>(
    station_pubkey: Obfs4NtorPublicKey,
    iat_mode: IAT,
    rng: &mut R,
) -> ClientSession<Initialized> {
    let mut session_id = [0u8; SESSION_ID_LEN];
    rng.fill_bytes(&mut session_id);
    ClientSession {
        node_pubkey: station_pubkey,
        session_id,
        iat_mode,
        epoch_hour: "".into(),
        biased: false,

        len_seed: drbg::Seed::new().unwrap(),
        _state: Initialized,
    }
}

impl ClientSession<Initialized> {
    /// Perform a Handshake over the provided stream.
    ///
    /// TODO: make sure failure modes align with golang obfs4
    /// - FIN/RST based on buffered data.
    /// - etc.
    ///
    /// # Cancel safety
    ///
    /// This function is **not cancel-safe**. Dropping the returned future
    /// mid-handshake may leave the underlying stream in a partially-written
    /// state. Wrap in `tokio::spawn` if cancellation is possible.
    pub async fn handshake<T>(
        self,
        mut stream: T,
        deadline: Option<Instant>,
    ) -> Result<Obfs4Stream<T>>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        // set up for handshake
        let mut session = self.transition(ClientHandshaking {});

        let materials = CHSMaterials::new(session.node_pubkey, session.session_id());

        // default deadline
        let d_def = Instant::now() + CLIENT_HANDSHAKE_TIMEOUT;
        let handshake_fut = Self::complete_handshake(&mut stream, materials, deadline);
        let (mut remainder, mut keygen) =
            match tokio::time::timeout_at(deadline.unwrap_or(d_def), handshake_fut).await {
                Ok(result) => match result {
                    Ok(handshake) => handshake,
                    Err(e) => {
                        // non-timeout error,
                        let id = session.session_id();
                        let _ = session.fault(ClientHandshakeFailed {
                            details: format!("{id} handshake failed {e}"),
                        });
                        return Err(e);
                    }
                },
                Err(_) => {
                    let id = session.session_id();
                    let _ = session.fault(ClientHandshakeFailed {
                        details: format!("{id} timed out"),
                    });
                    return Err(Error::HandshakeTimeout);
                }
            };

        // post-handshake state updates
        session.set_session_id(keygen.session_id());
        let mut codec: framing::Obfs4Codec = keygen.into();

        let res = codec.decode(&mut remainder);
        if let Ok(Some(framing::Messages::PrngSeed(seed))) = res {
            // try to parse the remainder of the server hello packet as a
            // PrngSeed since it should be there.
            let len_seed = drbg::Seed::from(seed);
            session.set_len_seed(len_seed);
        } else {
            debug!("NOPE {res:?}");
        }

        // mark session as Established
        let session_state: ClientSession<Established> = session.transition(Established {});
        info!("{} handshake complete", session_state.session_id());

        codec.handshake_complete();
        let o4 = O4Stream::new(stream, codec, Session::Client(session_state));

        Ok(Obfs4Stream::from_o4(o4))
    }

    async fn complete_handshake<T>(
        mut stream: T,
        materials: CHSMaterials,
        deadline: Option<Instant>,
    ) -> Result<(BytesMut, impl Obfs4Keygen)>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let (state, chs_message) = Obfs4NtorHandshake::client1(&materials, &())?;
        // let mut file = tokio::fs::File::create("message.hex").await?;
        // file.write_all(&chs_message).await?;
        stream.write_all(&chs_message).await?;

        debug!(
            "{} handshake sent {}B, waiting for sever response",
            materials.session_id,
            chs_message.len()
        );

        let mut buf = [0u8; MAX_HANDSHAKE_LENGTH];
        let mut filled = 0usize;
        loop {
            let n = stream.read(&mut buf[filled..]).await?;
            if n == 0 {
                Err(Error::IOError(IoError::new(
                    IoErrorKind::UnexpectedEof,
                    "read 0B in client handshake",
                )))?
            }
            filled += n;
            debug!(
                "{} read {filled}/{}B of server handshake",
                materials.session_id,
                buf.len()
            );

            match Obfs4NtorHandshake::client2(state.clone(), &buf[..filled]) {
                Ok(r) => return Ok(r),
                Err(Error::HandshakeErr(RelayHandshakeError::EAgain)) => {
                    if filled == buf.len() {
                        // Buffer full but parser still needs more data — bad handshake.
                        stream.shutdown().await?;
                        return Err(RelayHandshakeError::BadServerHandshake.into());
                    }
                    continue;
                }
                Err(e) => {
                    // if a deadline was set and has not passed already, discard
                    // from the stream until the deadline, then close.
                    if deadline.is_some_and(|d| d > Instant::now()) {
                        debug!("{} discarding due to: {e}", materials.session_id);
                        discard(&mut stream, deadline.unwrap() - Instant::now()).await?;
                    }
                    stream.shutdown().await?;
                    return Err(e);
                }
            }
        }
    }
}

impl ClientSession<ClientHandshaking> {
    pub(crate) fn set_len_seed(&mut self, seed: drbg::Seed) {
        debug!("{} setting length seed", self.session_id());
        self.len_seed = seed;
    }
}

impl<S: ClientSessionState> std::fmt::Debug for ClientSession<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[ id:{}, ident_pk:{}, iat:{:?}, epoch_hr:{} ]",
            hex::encode(self.node_pubkey.id.as_bytes()),
            hex::encode(self.node_pubkey.pk.as_bytes()),
            self.iat_mode,
            self.epoch_hour,
        )
    }
}

// ================================================================ //
//                   Server Sessions States                         //
// ================================================================ //

pub(crate) struct ServerSession<S: ServerSessionState> {
    // fixed by server
    pub(crate) identity_keys: Obfs4NtorSecretKey,
    pub(crate) biased: bool,
    // pub(crate) server: &'a Server,

    // generated per session
    pub(crate) session_id: [u8; SESSION_ID_LEN],
    pub(crate) len_seed: drbg::Seed,
    pub(crate) iat_seed: drbg::Seed,

    pub(crate) _state: S,
}

pub(crate) struct ServerHandshaking {}

#[allow(unused)]
pub(crate) struct ServerHandshakeFailed {
    details: String,
}

pub(crate) trait ServerSessionState {}
impl ServerSessionState for Initialized {}
impl ServerSessionState for ServerHandshaking {}
impl ServerSessionState for Established {}

impl ServerSessionState for ServerHandshakeFailed {}
impl Fault for ServerHandshakeFailed {}

impl<S: ServerSessionState> ServerSession<S> {
    pub fn session_id(&self) -> String {
        String::from("s-") + &colorize(self.session_id)
    }

    pub(crate) fn set_session_id(&mut self, id: [u8; SESSION_ID_LEN]) {
        debug!(
            "{} -> {} server updating session id",
            colorize(self.session_id),
            colorize(id)
        );
        self.session_id = id;
    }

    /// Helper function to perform state transitions.
    fn transition<T: ServerSessionState>(self, _state: T) -> ServerSession<T> {
        ServerSession {
            // fixed by server
            identity_keys: self.identity_keys,
            biased: self.biased,

            // generated per session
            session_id: self.session_id,
            len_seed: self.len_seed,
            iat_seed: self.iat_seed,

            _state,
        }
    }

    /// Helper function to perform state transition on error.
    fn fault<F: Fault + ServerSessionState>(self, f: F) -> ServerSession<F> {
        ServerSession {
            // fixed by server
            identity_keys: self.identity_keys,
            biased: self.biased,

            // generated per session
            session_id: self.session_id,
            len_seed: self.len_seed,
            iat_seed: self.iat_seed,

            _state: f,
        }
    }
}

impl ServerSession<Initialized> {
    /// Attempt to complete the handshake with a new client connection.
    ///
    /// # Cancel safety
    ///
    /// This function is **not cancel-safe**. Dropping the returned future
    /// mid-handshake may leave the underlying stream in a partially-written
    /// state. Wrap in `tokio::spawn` if cancellation is possible.
    pub async fn handshake<T>(
        self,
        server: &Server,
        mut stream: T,
        deadline: Option<Instant>,
    ) -> Result<Obfs4Stream<T>>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        // set up for handshake
        let mut session = self.transition(ServerHandshaking {});

        let materials = SHSMaterials::new(
            &session.identity_keys,
            session.session_id(),
            session.len_seed.to_bytes(),
        );

        // default deadline
        let d_def = Instant::now() + SERVER_HANDSHAKE_TIMEOUT;
        let handshake_fut = server.complete_handshake(&mut stream, materials, deadline);

        let mut keygen =
            match tokio::time::timeout_at(deadline.unwrap_or(d_def), handshake_fut).await {
                Ok(result) => match result {
                    Ok(handshake) => handshake,
                    Err(e) => {
                        // non-timeout error,
                        let id = session.session_id();
                        let _ = session.fault(ServerHandshakeFailed {
                            details: format!("{id} handshake failed {e}"),
                        });
                        return Err(e);
                    }
                },
                Err(_) => {
                    let id = session.session_id();
                    let _ = session.fault(ServerHandshakeFailed {
                        details: format!("{id} timed out"),
                    });
                    return Err(Error::HandshakeTimeout);
                }
            };

        // post handshake state updates
        session.set_session_id(keygen.session_id());
        let mut codec: framing::Obfs4Codec = keygen.into();

        // mark session as Established
        let session_state: ServerSession<Established> = session.transition(Established {});

        codec.handshake_complete();
        let o4 = O4Stream::new(stream, codec, Session::Server(session_state));

        Ok(Obfs4Stream::from_o4(o4))
    }
}

impl Server {
    /// Complete the handshake with the client. This function assumes that the
    /// client has already sent a message and that we do not know yet if the
    /// message is valid.
    async fn complete_handshake<T>(
        &self,
        mut stream: T,
        materials: SHSMaterials,
        deadline: Option<Instant>,
    ) -> Result<impl Obfs4Keygen>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let session_id = materials.session_id.clone();

        // wait for and attempt to consume the client hello message
        let mut buf = [0_u8; MAX_HANDSHAKE_LENGTH];
        let mut filled = 0usize;
        loop {
            let n = stream.read(&mut buf[filled..]).await?;
            if n == 0 {
                stream.shutdown().await?;
                return Err(IoError::from(IoErrorKind::UnexpectedEof).into());
            }
            filled += n;
            trace!(
                "{} successful read, total {}B accumulated",
                session_id,
                filled
            );

            match self.server(
                &mut |_: &()| Some(()),
                std::slice::from_ref(&materials),
                &buf[..filled],
            ) {
                Ok((keygen, response)) => {
                    stream.write_all(&response).await?;
                    info!("{} handshake complete", session_id);
                    return Ok(keygen);
                }
                Err(RelayHandshakeError::EAgain) => {
                    trace!("{} reading more", session_id);
                    if filled == buf.len() {
                        // Buffer full but parser still needs more data — bad handshake.
                        stream.shutdown().await?;
                        return Err(RelayHandshakeError::BadClientHandshake.into());
                    }
                    continue;
                }
                Err(e) => {
                    trace!("{} failed to parse client handshake: {e}", session_id);
                    // if a deadline was set and has not passed already, discard
                    // from the stream until the deadline, then close.
                    if deadline.is_some_and(|d| d > Instant::now()) {
                        debug!("{} discarding due to: {e}", session_id);
                        discard(&mut stream, deadline.unwrap() - Instant::now()).await?
                    }
                    stream.shutdown().await?;
                    return Err(e.into());
                }
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_pubkey() -> Obfs4NtorPublicKey {
        Obfs4NtorPublicKey::new([0x01; NODE_PUBKEY_LENGTH], [0x02; NODE_ID_LENGTH])
    }

    #[test]
    fn new_client_session_has_random_id() {
        let s1 = new_client_session(test_pubkey(), IAT::Off);
        let s2 = new_client_session(test_pubkey(), IAT::Off);
        assert_ne!(s1.session_id, s2.session_id);
    }

    #[test]
    fn client_session_id_format() {
        let s = new_client_session(test_pubkey(), IAT::Off);
        let id = s.session_id();
        assert!(id.starts_with("c-"));
    }

    #[test]
    fn client_set_session_id() {
        let mut s = new_client_session(test_pubkey(), IAT::Off);
        let new_id = [0xFF; SESSION_ID_LEN];
        s.set_session_id(new_id);
        assert_eq!(s.session_id, new_id);
    }

    #[test]
    fn client_transition_preserves_fields() {
        let s = new_client_session(test_pubkey(), IAT::Enabled);
        let original_id = s.session_id;
        let s2 = s.transition(ClientHandshaking {});
        assert_eq!(s2.session_id, original_id);
    }

    #[test]
    fn client_fault_preserves_fields() {
        let s = new_client_session(test_pubkey(), IAT::Off);
        let original_id = s.session_id;
        let sf = s.fault(ClientHandshakeFailed {
            details: "test".into(),
        });
        assert_eq!(sf.session_id, original_id);
    }

    #[test]
    fn session_enum_client_accessors() {
        let cs = new_client_session(test_pubkey(), IAT::Off);
        let seed = cs.len_seed.clone();
        let established = cs
            .transition(ClientHandshaking {})
            .transition(Established {});
        let session = Session::Client(established);

        assert!(session.id().starts_with("c"));
        assert!(!session.biased());
        assert_eq!(session.len_seed().as_bytes(), seed.as_bytes());
    }

    #[test]
    fn deterministic_rng_produces_same_session_id() {
        use rand::rngs::mock::StepRng;
        let mut rng1 = StepRng::new(42, 1);
        let mut rng2 = StepRng::new(42, 1);
        let s1 = new_client_session_with_rng(test_pubkey(), IAT::Off, &mut rng1);
        let s2 = new_client_session_with_rng(test_pubkey(), IAT::Off, &mut rng2);
        assert_eq!(s1.session_id, s2.session_id);
    }

    #[test]
    fn different_rng_produces_different_session_id() {
        use rand::rngs::mock::StepRng;
        let mut rng1 = StepRng::new(1, 1);
        let mut rng2 = StepRng::new(999, 1);
        let s1 = new_client_session_with_rng(test_pubkey(), IAT::Off, &mut rng1);
        let s2 = new_client_session_with_rng(test_pubkey(), IAT::Off, &mut rng2);
        assert_ne!(s1.session_id, s2.session_id);
    }

    #[test]
    fn server_session_set_id() {
        let server = Server::getrandom();
        let mut ss = server.new_server_session().unwrap();
        let new_id = [0xAA; SESSION_ID_LEN];
        ss.set_session_id(new_id);
        assert_eq!(ss.session_id, new_id);
    }

    #[test]
    fn server_transition_preserves_fields() {
        let server = Server::getrandom();
        let ss = server.new_server_session().unwrap();
        let orig_id = ss.session_id;
        let ss2 = ss.transition(ServerHandshaking {});
        assert_eq!(ss2.session_id, orig_id);
    }

    #[test]
    fn server_fault_preserves_fields() {
        let server = Server::getrandom();
        let ss = server.new_server_session().unwrap();
        let orig_id = ss.session_id;
        let sf = ss.fault(ServerHandshakeFailed {
            details: "test".into(),
        });
        assert_eq!(sf.session_id, orig_id);
    }

    // ── H3 regression: fragmented-handshake accumulation ───────────────────
    //
    // Before the `filled` fix, `buf` was reused from index 0 each iteration:
    //
    //   let n = stream.read(&mut buf).await?;   // always writes to buf[0..n]
    //   client2(state.clone(), &buf[..n])        // only ever sees the latest chunk
    //
    // When TCP delivers the server response in small fragments, `client2` sees
    // a fresh partial message on each iteration and never accumulates the full
    // handshake. It returns `EAgain` every time and the loop spins until the
    // outer `timeout_at` fires.
    //
    // With the fix (`filled` accumulates across iterations) the parser sees the
    // growing buffer and succeeds once enough bytes have arrived.
    //
    // Implementation note: a strict byte-at-a-time shim requires hundreds of
    // async round-trips for a ~200B handshake message. Under the debug executor
    // this races the `CLIENT_HANDSHAKE_TIMEOUT` (5s non-test / 60s test). We
    // therefore use a 32-byte-per-read shim — small enough to guarantee multiple
    // `EAgain` cycles and thus a real test of accumulation, but fast enough to
    // complete in well under a second.
    #[tokio::test]
    async fn handshake_completes_fragmented() {
        use std::pin::Pin;
        use std::task::{Context, Poll};
        use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

        const CHUNK: usize = 32;

        /// Wrapper that returns at most `CHUNK` bytes per `poll_read` call.
        struct ChunkedPoll<S>(S);

        impl<S: AsyncRead + Unpin> AsyncRead for ChunkedPoll<S> {
            fn poll_read(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> Poll<std::io::Result<()>> {
                if buf.remaining() == 0 {
                    return Poll::Ready(Ok(()));
                }
                // Restrict to at most CHUNK bytes
                let cap = buf.remaining().min(CHUNK);
                let mut tmp = vec![0u8; cap];
                let mut tmp_buf = ReadBuf::new(&mut tmp);
                let result = Pin::new(&mut self.0).poll_read(cx, &mut tmp_buf);
                if let Poll::Ready(Ok(())) = &result {
                    buf.put_slice(tmp_buf.filled());
                }
                result
            }
        }

        impl<S: AsyncWrite + Unpin> AsyncWrite for ChunkedPoll<S> {
            fn poll_write(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<std::io::Result<usize>> {
                Pin::new(&mut self.0).poll_write(cx, buf)
            }
            fn poll_flush(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<std::io::Result<()>> {
                Pin::new(&mut self.0).poll_flush(cx)
            }
            fn poll_shutdown(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<std::io::Result<()>> {
                Pin::new(&mut self.0).poll_shutdown(cx)
            }
        }

        // Build server + matching client session materials
        let server = Server::getrandom();
        let server_pubkey = server.0.identity_keys.pk;
        let client_session = new_client_session(server_pubkey, IAT::Off);

        // Create a connected pair of duplex streams (generous pipe buffer so
        // writes never block)
        let (client_half, server_half) = tokio::io::duplex(64 * 1024);

        let client_stream = ChunkedPoll(client_half);
        let server_stream = ChunkedPoll(server_half);

        // Drive client and server concurrently. Each side reads at most CHUNK
        // bytes per poll, so the server handshake message (~200+ bytes) requires
        // at least 7 read calls before client2 can succeed. This proves the
        // accumulation fix: without `filled`, client2 would see only the latest
        // 32-byte fragment and return EAgain indefinitely.
        let server_ref = server.clone();
        let client_fut = async move {
            // Use a generous deadline so the test doesn't race the timeout.
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
            client_session
                .handshake(client_stream, Some(deadline))
                .await
        };
        let server_fut = async move { server_ref.wrap(server_stream).await };

        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let (c_res, s_res) = tokio::join!(client_fut, server_fut);
            c_res.expect("client handshake must succeed under fragmented delivery");
            s_res.expect("server handshake must succeed under fragmented delivery");
        })
        .await
        .expect("handshake must complete under fragmented (32-byte-chunk) delivery");
    }
}
