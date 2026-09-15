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
    path::Path,
    pin::Pin,
    str::FromStr,
    sync::{Arc, Mutex},
};

use hex::FromHex;
use ptrs::args::Args;

const CLIENT_STATE_FILENAME: &str = "obfs4_client_state.json";

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct JsonClientState {
    #[serde(default)]
    cert: Option<String>,
    #[serde(rename = "private-key", default)]
    private_key: Option<String>,
    #[serde(rename = "node-id", default)]
    node_id: Option<String>,
    #[serde(rename = "public-key", default)]
    public_key: Option<String>,
    #[serde(rename = "iat-mode", default)]
    #[serde(with = "crate::iat_mode_json")]
    iat_mode: Option<IAT>,
}

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
    pub(crate) node_pubkey_override: bool,
    pub(crate) node_id_override: bool,
    pub(crate) iat_override: bool,
    pub(crate) statefile_required: bool,
    pub(crate) statefile_read_only: bool,
    pub(crate) persist_statefile: bool,
}

impl Default for ClientBuilder {
    fn default() -> Self {
        Self {
            iat_mode: IAT::Off,
            station_pubkey: [0u8; KEY_LENGTH],
            station_id: [0_u8; NODE_ID_LENGTH],
            statefile_path: None,
            handshake_timeout: MaybeTimeout::Default_,
            node_pubkey_override: false,
            node_id_override: false,
            iat_override: false,
            statefile_required: false,
            statefile_read_only: false,
            persist_statefile: false,
        }
    }
}

impl ClientBuilder {
    /// Construct a `ClientBuilder` from an explicit client state file.
    ///
    /// A server `obfs4_state.json` may be imported for its public parameters;
    /// it is treated as read-only by client persistence.
    pub fn from_statefile(location: &str) -> Result<Self> {
        let mut builder = Self {
            iat_mode: IAT::Off,
            station_pubkey: [0_u8; KEY_LENGTH],
            station_id: [0_u8; NODE_ID_LENGTH],
            statefile_path: Some(location.into()),
            handshake_timeout: MaybeTimeout::Default_,
            node_pubkey_override: false,
            node_id_override: false,
            iat_override: false,
            statefile_required: true,
            statefile_read_only: true,
            persist_statefile: false,
        };
        builder.load_statefile(Path::new(location))?;
        Ok(builder)
    }

    /// Construct a `ClientBuilder` from a list of raw parameter byte strings.
    pub fn from_params(param_strs: Vec<impl AsRef<[u8]>>) -> Result<Self> {
        let mut builder = Self {
            iat_mode: IAT::Off,
            station_pubkey: [0_u8; KEY_LENGTH],
            station_id: [0_u8; NODE_ID_LENGTH],
            statefile_path: None,
            handshake_timeout: MaybeTimeout::Default_,
            node_pubkey_override: false,
            node_id_override: false,
            iat_override: false,
            statefile_required: false,
            statefile_read_only: false,
            persist_statefile: false,
        };
        let mut args = Args::new();
        for raw in param_strs {
            let value = std::str::from_utf8(raw.as_ref()).map_err(|e| Error::Other(Box::new(e)))?;
            let parsed =
                Args::parse_client_parameters(value).map_err(|e| Error::Other(Box::new(e)))?;
            for (key, values) in parsed.iter() {
                for value in values {
                    args.add(key, value);
                }
            }
        }
        builder.apply_args(&args)?;
        Ok(builder)
    }

    /// Set the server's x25519 public key on this builder.
    pub fn with_node_pubkey(&mut self, pubkey: [u8; KEY_LENGTH]) -> &mut Self {
        self.station_pubkey = pubkey;
        self.node_pubkey_override = true;
        self
    }

    /// Set an explicit client state-file path. The file is loaded when present
    /// and created after a complete manual configuration.
    pub fn with_statefile_path(&mut self, path: &str) -> &mut Self {
        self.statefile_path = Some(path.into());
        self.statefile_required = true;
        self.statefile_read_only = false;
        self.persist_statefile = true;
        self
    }

    pub(crate) fn with_statefile_directory(&mut self, path: &str) -> &mut Self {
        self.statefile_path = Some(path.into());
        self.statefile_required = false;
        self.statefile_read_only = false;
        self.persist_statefile = true;
        self
    }

    /// Set the server's node ID (RSA identity fingerprint) on this builder.
    pub fn with_node_id(&mut self, id: [u8; NODE_ID_LENGTH]) -> &mut Self {
        self.station_id = id;
        self.node_id_override = true;
        self
    }

    /// Set the IAT (inter-arrival time) obfuscation mode on this builder.
    pub fn with_iat_mode(&mut self, iat: IAT) -> &mut Self {
        self.iat_mode = iat;
        self.iat_override = true;
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
        match self.try_build() {
            Ok(client) => client,
            Err(error) => Client {
                iat_mode: self.iat_mode,
                station_pubkey: Obfs4NtorPublicKey {
                    id: self.station_id.into(),
                    pk: self.station_pubkey.into(),
                },
                handshake_timeout: self.handshake_timeout.clone(),
                configuration_error: Some(error.to_string()),
            },
        }
    }

    /// Build a client after validating its optional state file.
    pub fn try_build(&self) -> Result<Client> {
        let mut builder = self.clone();
        if let Some(path) = builder.statefile_path.clone() {
            let path = if builder.statefile_required {
                Path::new(&path).to_path_buf()
            } else {
                Path::new(&path).join(CLIENT_STATE_FILENAME)
            };
            let needs_state =
                !(builder.node_pubkey_override && builder.node_id_override && builder.iat_override);
            if needs_state {
                if path.exists() {
                    builder.load_statefile(&path)?;
                } else if !(builder.node_pubkey_override && builder.node_id_override) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "obfs4 state file is missing and the client identity is incomplete",
                    )
                    .into());
                }
            } else if path.is_file() {
                let bytes = std::fs::read(&path)?;
                let state: JsonClientState =
                    serde_json::from_slice(&bytes).map_err(|e| Error::Other(Box::new(e)))?;
                builder.statefile_read_only = state.private_key.is_some();
            }
        }
        let client = Client {
            iat_mode: builder.iat_mode,
            station_pubkey: Obfs4NtorPublicKey {
                id: builder.station_id.into(),
                pk: builder.station_pubkey.into(),
            },
            handshake_timeout: builder.handshake_timeout.clone(),
            configuration_error: None,
        };
        if builder.persist_statefile && !builder.statefile_read_only {
            if let Some(path) = builder.statefile_path.as_deref() {
                let target = if builder.statefile_required {
                    Path::new(path).to_path_buf()
                } else {
                    Path::new(path).join(CLIENT_STATE_FILENAME)
                };
                builder.write_statefile_target(&target)?;
            }
        }
        Ok(client)
    }

    /// Encode the builder's current parameters as a command-line options string.
    pub fn as_opts(&self) -> String {
        let mut args = Args::new();
        let cert = Obfs4NtorPublicKey {
            id: self.station_id.into(),
            pk: self.station_pubkey.into(),
        };
        args.add(CERT_ARG, &cert.to_string());
        args.add(IAT_ARG, &self.iat_mode.to_string());
        args.encode_client_parameters()
    }
}

impl fmt::Display for ClientBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.as_opts())
    }
}

impl ClientBuilder {
    pub(crate) fn apply_args(&mut self, args: &Args) -> Result<()> {
        let (station_pubkey, station_id) = match args.retrieve(CERT_ARG) {
            Some(cert) => {
                let key = Obfs4NtorPublicKey::from_str(&cert)?;
                (
                    *key.pk.as_bytes(),
                    key.id
                        .as_bytes()
                        .try_into()
                        .map_err(|_| Error::from("invalid obfs4 node id length"))?,
                )
            }
            None => {
                let id = args
                    .retrieve(NODE_ID_ARG)
                    .ok_or_else(|| Error::from(format!("missing argument '{NODE_ID_ARG}'")))?;
                let pk = args
                    .retrieve(PUBLIC_KEY_ARG)
                    .ok_or_else(|| Error::from(format!("missing argument '{PUBLIC_KEY_ARG}'")))?;
                (
                    <[u8; KEY_LENGTH]>::from_hex(pk)?,
                    <[u8; NODE_ID_LENGTH]>::from_hex(id)?,
                )
            }
        };
        let iat_mode = args
            .retrieve(IAT_ARG)
            .ok_or_else(|| Error::from(format!("missing argument '{IAT_ARG}'")))?
            .parse()?;
        self.station_pubkey = station_pubkey;
        self.station_id = station_id;
        self.iat_mode = iat_mode;
        self.node_pubkey_override = true;
        self.node_id_override = true;
        self.iat_override = true;
        Ok(())
    }

    pub(crate) fn load_statefile(&mut self, path: &Path) -> Result<()> {
        let state_path = if path.is_dir() {
            path.join(CLIENT_STATE_FILENAME)
        } else {
            path.to_path_buf()
        };
        let bytes = std::fs::read(state_path)?;
        let state: JsonClientState =
            serde_json::from_slice(&bytes).map_err(|e| Error::Other(Box::new(e)))?;
        let server_import = state.private_key.is_some();
        let mut args = Args::new();
        if let Some(cert) = state.cert {
            args.add(CERT_ARG, &cert);
        }
        if let Some(node_id) = state.node_id {
            args.add(NODE_ID_ARG, &node_id);
        }
        if let Some(public_key) = state.public_key {
            args.add(PUBLIC_KEY_ARG, &public_key);
        }
        if let Some(iat_mode) = state.iat_mode {
            args.add(IAT_ARG, &iat_mode.to_string());
        }
        let mut loaded = ClientBuilder::default();
        loaded.apply_args(&args)?;
        if !self.node_pubkey_override {
            self.station_pubkey = loaded.station_pubkey;
        }
        if !self.node_id_override {
            self.station_id = loaded.station_id;
        }
        if !self.iat_override {
            self.iat_mode = loaded.iat_mode;
        }
        self.statefile_read_only = server_import;
        Ok(())
    }

    /// Persist the client parameters as an atomic JSON state-file update.
    pub fn write_statefile(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        let target = if path.is_dir() {
            path.join(CLIENT_STATE_FILENAME)
        } else {
            path.to_path_buf()
        };
        self.write_statefile_target(&target)
    }

    fn write_statefile_target(&self, target: &Path) -> Result<()> {
        let parent = target
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        std::fs::create_dir_all(parent)?;
        let state = JsonClientState {
            cert: Some(
                Obfs4NtorPublicKey {
                    id: self.station_id.into(),
                    pk: self.station_pubkey.into(),
                }
                .to_string(),
            ),
            private_key: None,
            node_id: None,
            public_key: None,
            iat_mode: Some(self.iat_mode),
        };
        crate::atomic_write_json(target, &state)
    }
}

/// Client implementing the obfs4 protocol.
pub struct Client {
    iat_mode: IAT,
    station_pubkey: Obfs4NtorPublicKey,
    handshake_timeout: MaybeTimeout,
    configuration_error: Option<String>,
}

impl Client {
    /// Extract transport arguments and update this client's configuration.
    pub fn try_get_args(&mut self, args: &dyn std::any::Any) -> Result<()> {
        let args = args.downcast_ref::<Args>().ok_or(Error::NotSupported)?;
        let mut builder = ClientBuilder {
            iat_mode: self.iat_mode,
            station_pubkey: *self.station_pubkey.pk.as_bytes(),
            station_id: self
                .station_pubkey
                .id
                .as_bytes()
                .try_into()
                .map_err(|_| Error::from("invalid obfs4 node id length"))?,
            statefile_path: None,
            handshake_timeout: self.handshake_timeout.clone(),
            node_pubkey_override: true,
            node_id_override: true,
            iat_override: true,
            statefile_required: false,
            statefile_read_only: false,
            persist_statefile: false,
        };
        builder.apply_args(args)?;
        self.iat_mode = builder.iat_mode;
        self.station_pubkey = Obfs4NtorPublicKey {
            id: builder.station_id.into(),
            pk: builder.station_pubkey.into(),
        };
        self.configuration_error = None;
        Ok(())
    }

    /// Apply transport arguments using the legacy infallible API.
    ///
    /// Invalid arguments are retained as a deferred configuration error and
    /// are reported by the first handshake operation before any I/O occurs.
    pub fn get_args(&mut self, args: &dyn std::any::Any) {
        if let Err(error) = self.try_get_args(args) {
            self.configuration_error = Some(error.to_string());
        }
    }

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
        if let Some(error) = self.configuration_error {
            return Err(error.into());
        }
        let deadline = self.handshake_timeout.deadline(CLIENT_HANDSHAKE_TIMEOUT)?;
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
        if let Some(error) = self.configuration_error {
            return Err(error.into());
        }
        let deadline = self.handshake_timeout.deadline(CLIENT_HANDSHAKE_TIMEOUT)?;
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

    #[test]
    fn params_and_statefile_roundtrip() {
        let server = crate::Server::getrandom();
        let mut builder = server.client_params();
        builder.with_iat_mode(IAT::Paranoid);
        let encoded = builder.as_opts();
        let restored = ClientBuilder::from_params(vec![encoded.as_bytes()]).unwrap();
        assert_eq!(restored.station_pubkey, builder.station_pubkey);
        assert_eq!(restored.station_id, builder.station_id);
        assert_eq!(restored.iat_mode, IAT::Paranoid);

        let path = std::env::temp_dir().join(format!(
            "ptrs-gesher-obfs4-client-state-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        builder.write_statefile(&path).unwrap();
        let encoded: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(encoded["iat-mode"].as_u64(), Some(2));
        let from_state = ClientBuilder::from_statefile(path.to_string_lossy().as_ref()).unwrap();
        assert_eq!(from_state.station_pubkey, builder.station_pubkey);
        assert_eq!(from_state.iat_mode, builder.iat_mode);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn client_imports_numeric_server_state_without_rewriting_it() {
        let temporary = tempfile::tempdir().unwrap();
        let state = temporary.path().join("server-state.json");
        let mut server_builder = crate::ServerBuilder::<tokio::net::TcpStream>::default();
        server_builder.iat_mode(IAT::Paranoid);
        let server = server_builder.try_build().unwrap();
        server.write_statefile_to(&state).unwrap();
        let original = std::fs::read(&state).unwrap();

        let mut importing = ClientBuilder::default();
        importing.with_statefile_path(state.to_string_lossy().as_ref());
        let client = importing.try_build().unwrap();

        assert_eq!(client.iat_mode, IAT::Paranoid);
        assert_eq!(std::fs::read(&state).unwrap(), original);
    }

    #[test]
    fn client_accepts_legacy_string_iat_mode() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("client-state.json");
        let server = crate::Server::getrandom();
        let builder = server.client_params();
        builder.write_statefile(&path).unwrap();
        let mut state: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        state["iat-mode"] = serde_json::Value::String("2".into());
        std::fs::write(&path, serde_json::to_vec(&state).unwrap()).unwrap();

        let restored = ClientBuilder::from_statefile(path.to_string_lossy().as_ref()).unwrap();
        assert_eq!(restored.iat_mode, IAT::Paranoid);
    }

    #[test]
    fn client_iat_mode_json_rejects_invalid_values() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("client-state.json");
        let server = crate::Server::getrandom();
        server.client_params().write_statefile(&path).unwrap();
        let original: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();

        for value in [
            serde_json::json!(true),
            serde_json::json!(3),
            serde_json::json!(-1),
            serde_json::json!(1.5),
        ] {
            let mut state = original.clone();
            state["iat-mode"] = value;
            std::fs::write(&path, serde_json::to_vec(&state).unwrap()).unwrap();
            assert!(
                ClientBuilder::from_statefile(path.to_string_lossy().as_ref()).is_err(),
                "{state}"
            );
        }
    }

    #[test]
    fn statefile_path_is_required_and_manual_values_take_precedence() {
        let missing = std::env::temp_dir().join(format!(
            "ptrs-gesher-obfs4-missing-client-state-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&missing);
        let mut missing_builder = ClientBuilder::default();
        missing_builder.with_statefile_path(missing.to_string_lossy().as_ref());
        assert!(missing_builder.try_build().is_err());

        let server = crate::Server::getrandom();
        let state = std::env::temp_dir().join(format!(
            "ptrs-gesher-obfs4-client-precedence-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&state);
        server.client_params().write_statefile(&state).unwrap();
        let mut builder = ClientBuilder::default();
        builder
            .with_statefile_path(state.to_string_lossy().as_ref())
            .with_node_pubkey([1; KEY_LENGTH])
            .with_node_id([2; NODE_ID_LENGTH])
            .with_iat_mode(IAT::Paranoid);
        let client = builder.try_build().unwrap();
        assert_eq!(client.station_pubkey.pk.as_bytes(), &[1; KEY_LENGTH]);
        assert_eq!(client.station_pubkey.id.as_bytes(), &[2; NODE_ID_LENGTH]);
        assert_eq!(client.iat_mode, IAT::Paranoid);
        let _ = std::fs::remove_file(state);

        let server_state = std::env::temp_dir().join(format!(
            "ptrs-gesher-obfs4-client-import-server-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&server_state);
        server.write_statefile_to(&server_state).unwrap();
        let original_server_state = std::fs::read(&server_state).unwrap();
        let mut importing = ClientBuilder::default();
        importing
            .with_statefile_path(server_state.to_string_lossy().as_ref())
            .with_iat_mode(IAT::Enabled);
        importing.try_build().unwrap();
        assert_eq!(std::fs::read(&server_state).unwrap(), original_server_state);
        let _ = std::fs::remove_file(server_state);

        let created = std::env::temp_dir().join(format!(
            "ptrs-gesher-obfs4-client-created-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&created);
        let mut configured = ClientBuilder::default();
        configured
            .with_statefile_path(created.to_string_lossy().as_ref())
            .with_node_pubkey([3; KEY_LENGTH])
            .with_node_id([4; NODE_ID_LENGTH])
            .with_iat_mode(IAT::Enabled);
        configured.try_build().unwrap();
        assert!(created.is_file());
        let restored = ClientBuilder::default()
            .with_statefile_path(created.to_string_lossy().as_ref())
            .try_build()
            .unwrap();
        assert_eq!(
            restored.station_pubkey.pk.as_bytes(),
            &configured.station_pubkey
        );
        assert_eq!(
            restored.station_pubkey.id.as_bytes(),
            &configured.station_id
        );
        assert_eq!(restored.iat_mode, configured.iat_mode);
        let _ = std::fs::remove_file(created);
    }

    #[test]
    fn get_args_rejects_invalid_update_transactionally() {
        let server = crate::Server::getrandom();
        let mut client = server.client_params().build();
        let before = client.station_pubkey;
        let mut args = Args::new();
        args.add(CERT_ARG, "invalid");
        args.add(IAT_ARG, "2");
        assert!(client.try_get_args(&args).is_err());
        assert_eq!(client.station_pubkey, before);
        client.get_args(&args);
        assert!(client.configuration_error.is_some());
        let valid = Args::parse_client_parameters(&server.client_params().as_opts()).unwrap();
        client.try_get_args(&valid).unwrap();
        assert!(client.configuration_error.is_none());
    }

    #[test]
    fn client_state_directory_creates_and_reloads_its_file() {
        let temporary = tempfile::tempdir().unwrap();
        let directory = temporary.path().join("client");
        let server = crate::Server::getrandom();
        let mut builder = server.client_params();
        builder.with_statefile_directory(directory.to_str().unwrap());
        let original = builder.try_build().unwrap();
        assert!(directory.join(CLIENT_STATE_FILENAME).is_file());
        assert!(!directory.join("obfs4_state.json").exists());
        let mut restored = ClientBuilder::default();
        restored.with_statefile_directory(directory.to_str().unwrap());
        restored.with_iat_mode(IAT::Paranoid);
        let restored = restored.try_build().unwrap();
        assert_eq!(restored.station_pubkey, original.station_pubkey);
        assert_eq!(restored.iat_mode, IAT::Paranoid);
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
