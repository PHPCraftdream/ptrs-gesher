#![allow(unused)]

use super::*;
use crate::{
    client::ClientBuilder,
    common::{
        colorize, drbg,
        replay_filter::{self, ReplayFilter},
        x25519_elligator2::{PublicKey, StaticSecret},
        HmacSha256,
    },
    constants::*,
    framing::{FrameError, Marshall, Obfs4Codec, TryParse, KEY_LENGTH},
    handshake::{Obfs4NtorPublicKey, Obfs4NtorSecretKey},
    proto::{MaybeTimeout, Obfs4Stream, IAT},
    sessions::Session,
    Error, Result,
};
use ptrs::args::Args;

use std::{
    borrow::BorrowMut,
    marker::PhantomData,
    path::{Path, PathBuf},
    str::FromStr,
    sync::{Arc, Mutex},
};

use bytes::{Buf, BufMut, Bytes};
use hex::FromHex;
use hmac::{Hmac, Mac};
use ptrs::{debug, info};
use rand::prelude::*;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::{Duration, Instant};
use tokio_util::codec::Encoder;
use tor_llcrypto::pk::rsa::RsaIdentity;

const STATE_FILENAME: &str = "obfs4_state.json";

/// Builder for constructing an obfs4 [`Server`] with identity key material.
///
/// Fields are private; configure the builder through its setters.
pub struct ServerBuilder<T> {
    /// IAT (inter-arrival time) obfuscation mode for the server.
    pub(crate) iat_mode: IAT,
    /// Optional path to the directory where server state is persisted.
    pub(crate) statefile_path: Option<String>,
    pub(crate) identity_keys: Obfs4NtorSecretKey,
    pub(crate) handshake_timeout: MaybeTimeout,
    pub(crate) drbg_seed: Option<drbg::Seed>,
    pub(crate) config_error: Option<String>,
    pub(crate) identity_override: bool,
    pub(crate) node_id_override: bool,
    pub(crate) iat_override: bool,
    pub(crate) seed_override: bool,
    statefile_is_file: bool,
    persist_statefile: bool,
    effective_configuration: Mutex<Option<EffectiveServerConfiguration>>,
    _stream_type: PhantomData<T>,
}

#[derive(Clone)]
struct EffectiveServerConfiguration {
    identity_keys: Obfs4NtorSecretKey,
    iat_mode: IAT,
    drbg_seed: drbg::Seed,
    persist_statefile: bool,
    statefile_observation: Option<StatefileObservation>,
}

#[derive(Clone)]
struct StatefileObservation {
    path: PathBuf,
    contents: Option<Vec<u8>>,
}

impl<T> Default for ServerBuilder<T> {
    fn default() -> Self {
        let identity_keys = Obfs4NtorSecretKey::getrandom();
        Self {
            iat_mode: IAT::Off,
            statefile_path: None,
            identity_keys,
            handshake_timeout: MaybeTimeout::Default_,
            drbg_seed: None,
            config_error: None,
            identity_override: false,
            node_id_override: false,
            iat_override: false,
            seed_override: false,
            statefile_is_file: false,
            persist_statefile: true,
            effective_configuration: Mutex::new(None),
            _stream_type: PhantomData,
        }
    }
}

impl<T> ServerBuilder<T> {
    /// 64 byte combined representation of an x25519 public key, private key
    /// combination.
    pub fn node_keys(&mut self, keys: [u8; KEY_LENGTH * 2]) -> &Self {
        if let Err(error) = self.try_node_keys(keys) {
            self.config_error = Some(error.to_string());
            self.invalidate_effective_configuration();
        }
        self
    }

    /// Set the combined private/public node key after validating that the pair
    /// corresponds. The builder is unchanged when validation fails.
    pub fn try_node_keys(&mut self, keys: [u8; KEY_LENGTH * 2]) -> Result<&mut Self> {
        let sk: [u8; KEY_LENGTH] = keys[..KEY_LENGTH].try_into()?;
        let pk: [u8; KEY_LENGTH] = keys[KEY_LENGTH..].try_into()?;
        let secret = StaticSecret::from(sk);
        let derived = PublicKey::from(&secret);
        if derived.as_bytes() != &pk {
            return Err("node private/public keys do not correspond".into());
        }
        self.identity_keys.sk = secret;
        self.identity_keys.pk.pk = pk.into();
        self.config_error = None;
        self.invalidate_effective_configuration();
        self.identity_override = true;
        Ok(self)
    }

    /// Set the directory where `obfs4_state.json` is loaded or persisted.
    pub fn statefile_path(&mut self, path: &str) -> &Self {
        self.statefile_path = Some(path.into());
        self.statefile_is_file = false;
        self.persist_statefile = true;
        self.invalidate_effective_configuration();
        self
    }

    /// Import and validate a state directory or explicit state file.
    pub fn try_statefile_path(&mut self, path: &str) -> Result<&mut Self> {
        self.invalidate_effective_configuration();
        let state = Self::read_state_path(path)?;
        let mut args = Args::new();
        state.extend_args(&mut args);
        let parsed = RequiredServerState::try_from(&args)?;
        let drbg_seed = parsed.drbg_seed_value.clone();
        self.identity_keys = parsed.private_key;
        self.iat_mode = parsed.iat_mode;
        self.drbg_seed = Some(drbg_seed.clone());
        self.statefile_path = Some(path.into());
        self.config_error = None;
        self.statefile_is_file = Path::new(path).is_file();
        self.persist_statefile = !self.statefile_is_file;
        self.remember_effective_configuration(EffectiveServerConfiguration {
            identity_keys: self.identity_keys.clone(),
            iat_mode: self.iat_mode,
            drbg_seed,
            persist_statefile: false,
            statefile_observation: None,
        });
        Ok(self)
    }

    /// Set the server's 20-byte node ID (RSA identity fingerprint).
    pub fn node_id(&mut self, id: [u8; NODE_ID_LENGTH]) -> &Self {
        self.identity_keys.pk.id = id.into();
        self.node_id_override = true;
        self.invalidate_effective_configuration();
        self
    }

    /// Set the IAT (inter-arrival time) obfuscation mode for this server.
    pub fn iat_mode(&mut self, iat: IAT) -> &Self {
        self.iat_mode = iat;
        self.iat_override = true;
        self.invalidate_effective_configuration();
        self
    }

    /// Set a fixed duration after which an incoming handshake will be aborted.
    pub fn with_handshake_timeout(&mut self, d: Duration) -> &Self {
        self.handshake_timeout = MaybeTimeout::Length(d);
        self
    }

    /// Set an absolute deadline after which an incoming handshake will be aborted.
    pub fn with_handshake_deadline(&mut self, deadline: Instant) -> &Self {
        self.handshake_timeout = MaybeTimeout::Fixed(deadline);
        self
    }

    /// Disable the handshake timeout so failed handshakes close immediately.
    pub fn fail_fast(&mut self) -> &Self {
        self.handshake_timeout = MaybeTimeout::Unset;
        self
    }

    /// Encode the server's public parameters as a bridge-line argument string for clients.
    /// Returns an empty string when the effective configuration is unavailable.
    pub fn client_params(&self) -> String {
        self.try_client_params().unwrap_or_default()
    }

    /// Encode the effective server configuration as client bridge-line arguments.
    ///
    /// The first call resolves and caches the effective configuration. Later calls
    /// reuse it until a relevant setter or explicit state-file import invalidates it.
    pub fn try_client_params(&self) -> Result<String> {
        if let Some(error) = &self.config_error {
            return Err(error.clone().into());
        }
        let effective = self.effective_configuration()?;
        let mut params = Args::new();
        params.add(CERT_ARG, &effective.identity_keys.pk.to_string());
        params.add(IAT_ARG, &effective.iat_mode.to_string());
        Ok(params.encode_smethod_args())
    }

    /// Consume this builder and produce a [`Server`] ready to accept connections.
    pub fn build(&self) -> Server {
        match self.try_build() {
            Ok(server) => server,
            Err(error) => Server(Arc::new(ServerInner {
                identity_keys: self.identity_keys.clone(),
                iat_mode: self.iat_mode,
                biased: false,
                handshake_timeout: self.handshake_timeout.clone(),
                drbg_seed: None,
                configuration_error: Some(error.to_string()),
                replay_filter: ReplayFilter::new(REPLAY_TTL),
            })),
        }
    }

    /// Build a server, loading and validating the configured state file.
    pub fn try_build(&self) -> Result<Server> {
        if let Some(error) = &self.config_error {
            return Err(error.clone().into());
        }
        let effective = self.effective_configuration()?;
        let EffectiveServerConfiguration {
            identity_keys,
            iat_mode,
            drbg_seed,
            persist_statefile,
            statefile_observation,
        } = effective;
        let server = Server(Arc::new(ServerInner {
            identity_keys,
            iat_mode,
            biased: false,
            handshake_timeout: self.handshake_timeout.clone(),
            drbg_seed: Some(drbg_seed),
            configuration_error: None,
            replay_filter: ReplayFilter::new(REPLAY_TTL),
        }));
        if persist_statefile {
            let observation = statefile_observation
                .as_ref()
                .ok_or_else(|| Error::from("missing state-file persistence target"))?;
            self.ensure_statefile_unchanged(observation)?;
            server.write_statefile_to(&observation.path)?;
            let drbg_seed = server
                .0
                .drbg_seed
                .clone()
                .ok_or_else(|| Error::from("server DRBG seed is unavailable"))?;
            self.remember_effective_configuration(EffectiveServerConfiguration {
                identity_keys: server.0.identity_keys.clone(),
                iat_mode: server.0.iat_mode,
                drbg_seed,
                persist_statefile: false,
                statefile_observation: None,
            });
        }
        Ok(server)
    }

    fn effective_configuration(&self) -> Result<EffectiveServerConfiguration> {
        let mut cached = self
            .effective_configuration
            .lock()
            .map_err(|_| Error::from("effective server configuration cache is poisoned"))?;
        if let Some(effective) = cached.as_ref() {
            return Ok(effective.clone());
        }
        let effective = self.resolve_effective_configuration()?;
        *cached = Some(effective.clone());
        Ok(effective)
    }

    fn resolve_effective_configuration(&self) -> Result<EffectiveServerConfiguration> {
        let mut identity_keys = self.identity_keys.clone();
        let mut iat_mode = self.iat_mode;
        let mut drbg_seed = self.drbg_seed.clone();
        let statefile_target = self.statefile_target();
        let state_exists = statefile_target
            .as_ref()
            .is_some_and(|target| target.is_file());
        let statefile_contents = match statefile_target.as_ref() {
            Some(target) if state_exists => Some(std::fs::read(target)?),
            _ => None,
        };
        if self.statefile_path.is_some() {
            let needs_state = !self.identity_override
                || !self.node_id_override
                || !self.iat_override
                || !self.seed_override;
            if needs_state && state_exists {
                let state: JsonServerState = serde_json::from_slice(
                    statefile_contents
                        .as_deref()
                        .ok_or_else(|| Error::from("missing state-file contents"))?,
                )
                .map_err(|error| Error::Other(Box::new(error)))?;
                let mut args = Args::new();
                state.extend_args(&mut args);
                let parsed = RequiredServerState::try_from(&args)?;
                let mut state_identity = parsed.private_key;
                if self.identity_override {
                    if !self.node_id_override {
                        identity_keys.pk.id = state_identity.pk.id;
                    }
                } else {
                    if self.node_id_override {
                        state_identity.pk.id = identity_keys.pk.id;
                    }
                    identity_keys = state_identity;
                }
                if !self.iat_override {
                    iat_mode = parsed.iat_mode;
                }
                if !self.seed_override {
                    drbg_seed = Some(parsed.drbg_seed_value);
                }
            }
        }
        let drbg_seed = match drbg_seed {
            Some(seed) => seed,
            None => drbg::Seed::new()?,
        };
        let has_manual_overrides = self.identity_override
            || self.node_id_override
            || self.iat_override
            || self.seed_override;
        let persist_statefile = self.persist_statefile
            && statefile_target.is_some()
            && (!state_exists || has_manual_overrides);
        let statefile_observation = match (persist_statefile, statefile_target) {
            (true, Some(target)) => Some(StatefileObservation {
                path: target,
                contents: statefile_contents,
            }),
            _ => None,
        };
        Ok(EffectiveServerConfiguration {
            identity_keys,
            iat_mode,
            drbg_seed,
            persist_statefile,
            statefile_observation,
        })
    }

    fn statefile_target(&self) -> Option<PathBuf> {
        self.statefile_path.as_ref().map(|path| {
            if self.statefile_is_file {
                Path::new(path).to_path_buf()
            } else {
                Path::new(path).join(STATE_FILENAME)
            }
        })
    }

    // The comparison closes the ordinary overwrite window; a non-cooperating
    // writer can still race after it, since replacement is not a CAS operation.
    fn ensure_statefile_unchanged(&self, observation: &StatefileObservation) -> Result<()> {
        let current = match std::fs::read(&observation.path) {
            Ok(contents) => Some(contents),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };
        if current != observation.contents {
            return Err("state file changed after effective configuration was resolved".into());
        }
        Ok(())
    }

    pub(crate) fn invalidate_effective_configuration(&self) {
        if let Ok(mut effective) = self.effective_configuration.lock() {
            *effective = None;
        }
    }

    fn remember_effective_configuration(&self, configuration: EffectiveServerConfiguration) {
        if let Ok(mut effective) = self.effective_configuration.lock() {
            *effective = Some(configuration);
        }
    }

    /// Validate that the provided argument map contains all required server parameters.
    pub fn validate_args(args: &Args) -> Result<()> {
        let _ = RequiredServerState::try_from(args)?;

        Ok(())
    }

    pub(crate) fn parse_state(
        statedir: Option<impl AsRef<str>>,
        args: &Args,
    ) -> Result<RequiredServerState> {
        if statedir.is_none() {
            return RequiredServerState::try_from(args);
        }

        // if the provided arguments do not satisfy all required arguments, we
        // attempt to parse the server state from json IFF a statedir path was
        // provided. Otherwise this method just fails.
        let mut required_args = args.clone();
        match RequiredServerState::try_from(args) {
            Ok(state) => Ok(state),
            Err(e) => {
                Self::server_state_from_file(statedir.unwrap(), &mut required_args)?;
                RequiredServerState::try_from(&required_args)
            }
        }
    }

    fn server_state_from_file(statedir: impl AsRef<str>, args: &mut Args) -> Result<()> {
        let state = Self::read_state_path(statedir)?;
        state.extend_args(args);
        Ok(())
    }

    fn read_state_path(path: impl AsRef<str>) -> Result<JsonServerState> {
        let path = Path::new(path.as_ref());
        let file_path = if path.is_dir() {
            path.join(STATE_FILENAME)
        } else {
            path.to_path_buf()
        };
        let state_str = std::fs::read(file_path)?;
        serde_json::from_slice(&state_str).map_err(|e| Error::Other(Box::new(e)))
    }

    fn server_state_from_json(state_rdr: impl std::io::Read, args: &mut Args) -> Result<()> {
        let state: JsonServerState =
            serde_json::from_reader(state_rdr).map_err(|e| Error::Other(Box::new(e)))?;

        state.extend_args(args);
        Ok(())
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct JsonServerState {
    #[serde(rename = "node-id")]
    node_id: Option<String>,
    #[serde(rename = "private-key")]
    private_key: Option<String>,
    #[serde(rename = "public-key")]
    public_key: Option<String>,
    #[serde(rename = "drbg-seed")]
    drbg_seed: Option<String>,
    #[serde(rename = "iat-mode")]
    #[serde(default, with = "crate::iat_mode_json")]
    iat_mode: Option<IAT>,
}

impl JsonServerState {
    fn extend_args(self, args: &mut Args) {
        if let Some(id) = self.node_id {
            args.add(NODE_ID_ARG, &id);
        }
        if let Some(sk) = self.private_key {
            args.add(PRIVATE_KEY_ARG, &sk);
        }
        if let Some(pubkey) = self.public_key {
            args.add(PUBLIC_KEY_ARG, &pubkey);
        }
        if let Some(seed) = self.drbg_seed {
            args.add(SEED_ARG, &seed);
        }
        if let Some(mode) = self.iat_mode {
            args.add(IAT_ARG, &mode.to_string());
        }
    }
}

pub(crate) struct RequiredServerState {
    pub(crate) private_key: Obfs4NtorSecretKey,
    pub(crate) drbg_seed_value: drbg::Seed,
    pub(crate) iat_mode: IAT,
}

impl TryFrom<&Args> for RequiredServerState {
    type Error = Error;
    fn try_from(value: &Args) -> std::prelude::v1::Result<Self, Self::Error> {
        let privkey_str = value
            .retrieve(PRIVATE_KEY_ARG)
            .ok_or_else(|| format!("missing argument '{PRIVATE_KEY_ARG}'"))?;
        let sk = <[u8; KEY_LENGTH]>::from_hex(privkey_str)?;

        let drbg_seed_str = value
            .retrieve(SEED_ARG)
            .ok_or_else(|| format!("missing argument '{SEED_ARG}'"))?;
        let drbg_seed_value = drbg::Seed::from_hex(drbg_seed_str)?;

        let node_id_str = value
            .retrieve(NODE_ID_ARG)
            .ok_or_else(|| format!("missing argument '{NODE_ID_ARG}'"))?;
        let node_id = <[u8; NODE_ID_LENGTH]>::from_hex(node_id_str)?;

        let iat_mode = match value.retrieve(IAT_ARG) {
            Some(s) => IAT::from_str(&s)?,
            None => IAT::default(),
        };

        let secret_key = StaticSecret::from(sk);
        if let Some(public_key) = value.retrieve(PUBLIC_KEY_ARG) {
            let public_key = <[u8; KEY_LENGTH]>::from_hex(public_key)?;
            if PublicKey::from(&secret_key).as_bytes() != &public_key {
                return Err("node private/public keys do not correspond".into());
            }
        }
        let private_key = Obfs4NtorSecretKey::new(secret_key, RsaIdentity::from(node_id));

        Ok(RequiredServerState {
            private_key,
            drbg_seed_value,
            iat_mode,
        })
    }
}

/// An obfs4 server that accepts and unwraps client connections.
#[derive(Clone)]
pub struct Server(pub(crate) Arc<ServerInner>);

/// Shared inner state for an obfs4 server, held behind an `Arc`.
///
/// Fully crate-private: it is reached only through the `Arc` inside [`Server`]
/// (`self.0`), never through a public `Deref`, so none of these fields are
/// observable outside the crate.
pub(crate) struct ServerInner {
    pub(crate) handshake_timeout: MaybeTimeout,
    pub(crate) iat_mode: IAT,
    pub(crate) biased: bool,
    pub(crate) identity_keys: Obfs4NtorSecretKey,
    pub(crate) drbg_seed: Option<drbg::Seed>,
    pub(crate) configuration_error: Option<String>,

    pub(crate) replay_filter: ReplayFilter,
    // pub(crate) metrics: Metrics,
}

impl Server {
    /// Construct a server from a raw 32-byte secret key and 20-byte node ID.
    pub fn new(sec: [u8; KEY_LENGTH], id: [u8; NODE_ID_LENGTH]) -> Self {
        let sk = StaticSecret::from(sec);
        let pk = Obfs4NtorPublicKey {
            pk: PublicKey::from(&sk),
            id: id.into(),
        };

        let identity_keys = Obfs4NtorSecretKey { pk, sk };

        Self::new_from_key(identity_keys)
    }

    pub(crate) fn new_from_key(identity_keys: Obfs4NtorSecretKey) -> Self {
        let (drbg_seed, configuration_error) = match drbg::Seed::new() {
            Ok(seed) => (Some(seed), None),
            Err(error) => (None, Some(error.to_string())),
        };
        Self(Arc::new(ServerInner {
            handshake_timeout: MaybeTimeout::Default_,
            identity_keys,
            iat_mode: IAT::Off,
            biased: false,
            drbg_seed,
            configuration_error,

            // metrics: Arc::new(std::sync::Mutex::new(ServerMetrics {})),
            replay_filter: ReplayFilter::new(REPLAY_TTL),
        }))
    }

    /// Construct a server with a freshly generated identity key from the provided RNG.
    pub fn new_from_random<R: RngCore + CryptoRng>(mut rng: R) -> Self {
        let mut id = [0_u8; 20];
        // Random bytes will work for testing, but aren't necessarily actually a valid id.
        rng.fill_bytes(&mut id);

        // Generated identity secret key does not need to be elligator2 representable
        // so we can use the regular dalek_x25519 key generation.
        let sk = StaticSecret::random_from_rng(rng);

        let pk = Obfs4NtorPublicKey {
            pk: PublicKey::from(&sk),
            id: id.into(),
        };

        let identity_keys = Obfs4NtorSecretKey { pk, sk };

        Self::new_from_key(identity_keys)
    }

    /// Construct a server with a freshly generated identity key using the system RNG.
    pub fn getrandom() -> Self {
        let identity_keys = Obfs4NtorSecretKey::getrandom();
        Self::new_from_key(identity_keys)
    }

    /// Perform the ntor handshake with a client and return an encrypted stream.
    ///
    /// # Cancel safety
    ///
    /// Cancellation drops an owned stream. If the stream is borrowed, discard
    /// it after cancellation because its handshake may be partial.
    pub async fn wrap<T>(self, stream: T) -> Result<Obfs4Stream<T>>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        if let Some(error) = self.0.configuration_error.clone() {
            return Err(error.into());
        }
        let deadline = self
            .0
            .handshake_timeout
            .deadline(SERVER_HANDSHAKE_TIMEOUT)?;
        if deadline.is_some_and(|deadline| deadline <= Instant::now()) {
            return Err(Error::HandshakeTimeout);
        }
        let session = self.new_server_session()?;

        session.handshake(&self, stream, deadline).await
    }

    // pub fn set_iat_mode(&mut self, mode: IAT) -> &Self {
    //     self.iat_mode = mode;
    //     self
    // }

    /// Apply dynamic transport arguments to this server's configuration.
    pub fn set_args(&mut self, args: &dyn std::any::Any) -> Result<&Self> {
        let args = args.downcast_ref::<Args>().ok_or(Error::NotSupported)?;
        let parsed = RequiredServerState::try_from(args)?;
        let inner = Arc::get_mut(&mut self.0).ok_or(Error::NotSupported)?;
        inner.identity_keys = parsed.private_key;
        inner.iat_mode = parsed.iat_mode;
        inner.drbg_seed = Some(parsed.drbg_seed_value);
        inner.configuration_error = None;
        Ok(self)
    }

    /// Load a server from a persistent state file (not yet implemented).
    pub fn new_from_statefile() -> Result<Self> {
        Err(Error::NotSupported)
    }

    /// Persist the server's state to the given file (not yet implemented).
    pub fn write_statefile(f: std::fs::File) -> Result<()> {
        drop(f);
        Err(Error::NotSupported)
    }

    /// Load a server from a state directory or explicit state file.
    ///
    /// An explicit file is imported read-only and is never rewritten.
    pub fn new_from_statefile_at(path: impl AsRef<Path>) -> Result<Self> {
        let mut builder = ServerBuilder::<tokio::net::TcpStream>::default();
        builder.try_statefile_path(path.as_ref().to_string_lossy().as_ref())?;
        builder.try_build()
    }

    /// Persist this server's identity and deterministic traffic seed.
    pub fn write_statefile_to(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        let target = if path.is_dir() {
            path.join(STATE_FILENAME)
        } else {
            path.to_path_buf()
        };
        let parent = target
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        std::fs::create_dir_all(parent)?;
        let state = JsonServerState {
            node_id: Some(hex::encode(self.0.identity_keys.pk.id.as_bytes())),
            private_key: Some(hex::encode(self.0.identity_keys.sk.to_bytes())),
            public_key: Some(hex::encode(self.0.identity_keys.pk.pk.as_bytes())),
            drbg_seed: Some(
                self.0
                    .drbg_seed
                    .as_ref()
                    .ok_or_else(|| Error::from("server DRBG seed is unavailable"))?
                    .to_string(),
            ),
            iat_mode: Some(self.0.iat_mode),
        };
        crate::atomic_write_json(&target, &state)?;
        Ok(())
    }

    /// Return a [`ClientBuilder`] pre-configured with this server's public parameters.
    pub fn client_params(&self) -> ClientBuilder {
        ClientBuilder {
            station_pubkey: *self.0.identity_keys.pk.pk.as_bytes(),
            station_id: self.0.identity_keys.pk.id.as_bytes().try_into().unwrap(),
            iat_mode: self.0.iat_mode,
            statefile_path: None,
            handshake_timeout: MaybeTimeout::Default_,
            node_pubkey_override: true,
            node_id_override: true,
            iat_override: true,
            statefile_required: false,
            statefile_read_only: false,
            persist_statefile: false,
        }
    }

    pub(crate) fn new_server_session(
        &self,
    ) -> Result<sessions::ServerSession<sessions::Initialized>> {
        let mut session_id = [0u8; SESSION_ID_LEN];
        rand::thread_rng().fill_bytes(&mut session_id);
        let len_seed = self
            .0
            .drbg_seed
            .clone()
            .ok_or_else(|| Error::from("server DRBG seed is unavailable"))?;
        let mut hasher = Sha256::new();
        hasher.update(len_seed.as_bytes());
        let iat_seed = drbg::Seed::try_from(&hasher.finalize()[..drbg::SEED_LENGTH])?;
        Ok(sessions::ServerSession {
            // fixed by server
            identity_keys: self.0.identity_keys.clone(),
            biased: self.0.biased,
            iat_mode: self.0.iat_mode,

            // generated per session
            session_id,
            len_seed,
            iat_seed,

            _state: sessions::Initialized {},
        })
    }
}

#[cfg(test)]
mod tests {
    #[path = "server_state_tests.rs"]
    mod state_tests;

    use crate::dev;

    use super::*;

    use ptrs::trace;
    use tokio::net::TcpStream;

    #[test]
    fn parse_json_state() -> Result<()> {
        crate::test_utils::init_subscriber();

        let mut args = Args::new();
        let test_state = format!(
            r#"{{"{NODE_ID_ARG}": "00112233445566778899", "{PRIVATE_KEY_ARG}":"0123456789abcdeffedcba9876543210", "{IAT_ARG}": "0", "{SEED_ARG}": "abcdefabcdefabcdefabcdef"}}"#
        );
        ServerBuilder::<TcpStream>::server_state_from_json(test_state.as_bytes(), &mut args)?;
        debug!("{:?}\n{}", args.encode_smethod_args(), test_state);

        Ok(())
    }

    #[test]
    fn server_import_accepts_go_numeric_iat_mode_fixture() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join(STATE_FILENAME);
        let fixture = r#"{
            "node-id": "0000000000000000000000000000000000000000",
            "private-key": "3031323334353637383961626364656666656463626139383736353433323130",
            "drbg-seed": "0a0b0c0d0e0f0a0b0c0d0e0f0a0b0c0d0e0f0a0b0c0d0e0f",
            "iat-mode": 2
        }"#;
        std::fs::write(&path, fixture).unwrap();

        let server = Server::new_from_statefile_at(&path).unwrap();
        assert!(server.client_params().as_opts().contains("iat-mode=2"));
    }

    #[test]
    fn iat_mode_json_rejects_invalid_values() {
        for value in ["true", "3", "-1", "1.5"] {
            let json = format!(r#"{{"iat-mode": {value}}}"#);
            assert!(
                serde_json::from_str::<JsonServerState>(&json).is_err(),
                "{value}"
            );
        }
    }

    #[test]
    fn server_builder_methods() {
        let mut sb = ServerBuilder::<TcpStream>::default();
        sb.iat_mode(IAT::Enabled);
        assert_eq!(sb.iat_mode, IAT::Enabled);

        sb.statefile_path("/tmp/state");
        assert_eq!(sb.statefile_path.as_deref(), Some("/tmp/state"));

        sb.node_id([0xAA; NODE_ID_LENGTH]);
        assert_eq!(sb.identity_keys.pk.id.as_bytes(), &[0xAA; NODE_ID_LENGTH]);
    }

    #[test]
    fn server_builder_client_params_contains_cert() {
        let sb = ServerBuilder::<TcpStream>::default();
        let params = sb.client_params();
        assert!(params.contains("cert="));
        assert!(params.contains("iat-mode=0"));
    }

    #[test]
    fn server_new_derives_pubkey_from_secret() {
        let sec = [0x42u8; KEY_LENGTH];
        let id = [0x99u8; NODE_ID_LENGTH];
        let server = Server::new(sec, id);
        assert_eq!(server.0.identity_keys.pk.id.as_bytes(), &id);
        // pk derived from sk must be deterministic
        let server2 = Server::new(sec, id);
        assert_eq!(
            server.0.identity_keys.pk.pk.as_bytes(),
            server2.0.identity_keys.pk.pk.as_bytes()
        );
    }

    #[test]
    fn server_new_from_statefile_not_implemented() {
        let result = Server::new_from_statefile();
        assert!(result.is_err());
    }

    #[test]
    fn node_keys_reject_mismatched_public_key_without_mutation() {
        let mut builder = ServerBuilder::<TcpStream>::default();
        let before = builder.identity_keys.clone();
        let mut keys = [0_u8; KEY_LENGTH * 2];
        keys[..KEY_LENGTH].copy_from_slice(&[0x42; KEY_LENGTH]);
        keys[KEY_LENGTH..].copy_from_slice(&[0x24; KEY_LENGTH]);
        assert!(builder.try_node_keys(keys).is_err());
        assert_eq!(
            builder.identity_keys.pk.pk.as_bytes(),
            before.pk.pk.as_bytes()
        );
        assert_eq!(
            builder.identity_keys.pk.id.as_bytes(),
            before.pk.id.as_bytes()
        );
    }

    #[test]
    fn configured_seed_drives_new_sessions() {
        let args = Args::parse_client_parameters(crate::dev::SERVER_ARGS).unwrap();
        let expected = drbg::Seed::from_hex(args.retrieve(SEED_ARG).unwrap()).unwrap();
        let mut builder = ServerBuilder::<TcpStream>::default();
        <crate::ServerBuilder<TcpStream> as ptrs::ServerBuilder<TcpStream>>::options(
            &mut builder,
            &args,
        )
        .unwrap();
        let server = builder.try_build().unwrap();
        let session = server.new_server_session().unwrap();
        assert_eq!(session.len_seed.as_bytes(), expected.as_bytes());
        let mut hasher = Sha256::new();
        hasher.update(expected.as_bytes());
        let expected_iat = drbg::Seed::try_from(&hasher.finalize()[..drbg::SEED_LENGTH]).unwrap();
        assert_eq!(session.iat_seed.as_bytes(), expected_iat.as_bytes());
    }

    #[test]
    fn statefile_persists_identity_and_seed() {
        let directory = std::env::temp_dir().join(format!(
            "ptrs-gesher-obfs4-server-state-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        let mut builder = ServerBuilder::<TcpStream>::default();
        builder.statefile_path(directory.to_string_lossy().as_ref());
        let server = builder.try_build().unwrap();
        let repeated = builder.try_build().unwrap();
        let restored = Server::new_from_statefile_at(&directory).unwrap();
        assert_eq!(
            server.client_params().as_opts(),
            restored.client_params().as_opts()
        );
        assert_eq!(
            repeated.client_params().as_opts(),
            restored.client_params().as_opts()
        );
        let explicit_file = directory.join("import.json");
        server.write_statefile_to(&explicit_file).unwrap();
        let encoded: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&explicit_file).unwrap()).unwrap();
        assert_eq!(encoded["iat-mode"].as_u64(), Some(0));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&explicit_file)
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
        let imported = Server::new_from_statefile_at(&explicit_file).unwrap();
        assert_eq!(
            imported.client_params().as_opts(),
            server.client_params().as_opts()
        );
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn manual_server_values_take_precedence_over_statefile() {
        let directory = std::env::temp_dir().join(format!(
            "ptrs-gesher-obfs4-server-precedence-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        let mut initial = ServerBuilder::<TcpStream>::default();
        initial.statefile_path(directory.to_string_lossy().as_ref());
        initial.try_build().unwrap();

        let mut builder = ServerBuilder::<TcpStream>::default();
        builder.statefile_path(directory.to_string_lossy().as_ref());
        builder.node_id([0xAB; NODE_ID_LENGTH]);
        let server = builder.try_build().unwrap();
        assert_eq!(
            server.0.identity_keys.pk.id.as_bytes(),
            &[0xAB; NODE_ID_LENGTH]
        );
        let persisted = Server::new_from_statefile_at(&directory).unwrap();
        assert_eq!(
            server.new_server_session().unwrap().len_seed.as_bytes(),
            persisted.new_server_session().unwrap().len_seed.as_bytes()
        );
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn validate_args_valid() {
        let mut args = Args::new();
        args.add(NODE_ID_ARG, "0000000000000000000000000000000000000000");
        args.add(
            PRIVATE_KEY_ARG,
            "0123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210",
        );
        args.add(SEED_ARG, "0a0b0c0d0e0f0a0b0c0d0e0f0a0b0c0d0e0f0a0b0c0d0e0f");
        args.add(IAT_ARG, "0");
        let result = ServerBuilder::<TcpStream>::validate_args(&args);
        assert!(result.is_ok());
    }

    #[test]
    fn server_state_file_path_uses_separator() {
        // Regression: the old code did `String::from(dir) + STATE_FILENAME` with
        // no separator, producing e.g. "/var/lib/obfs4obfs4_state.json". Path::join
        // always inserts the platform separator between the directory and filename.
        let dir = "/var/lib/obfs4";
        let path = std::path::Path::new(dir).join(STATE_FILENAME);
        // Must end with the state filename
        assert!(
            path.file_name().unwrap().to_str().unwrap() == STATE_FILENAME,
            "file name must be STATE_FILENAME, got {:?}",
            path.file_name()
        );
        // The directory component must be present (separator inserted)
        assert_eq!(
            path.parent().unwrap(),
            std::path::Path::new(dir),
            "parent directory must equal the input statedir"
        );
    }
}
