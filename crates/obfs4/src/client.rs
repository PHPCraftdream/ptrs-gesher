#![allow(unused)]

use crate::{
    common::{colorize, HmacSha256},
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
#[derive(Clone, Debug)]
pub struct ClientBuilder {
    /// IAT (inter-arrival time) obfuscation mode for the client.
    pub iat_mode: IAT,
    /// The server's 32-byte x25519 public key (elligator2 representative).
    pub station_pubkey: [u8; KEY_LENGTH],
    /// The server's 20-byte node ID (RSA identity fingerprint).
    pub station_id: [u8; NODE_ID_LENGTH],
    /// Optional path to a persistent state file for this client.
    pub statefile_path: Option<String>,
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
            handshake_timeout: self.handshake_timeout.duration(),
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
    handshake_timeout: Option<tokio::time::Duration>,
}

impl Client {
    /// Extract transport arguments and update this client's configuration.
    pub fn get_args(&mut self, _args: &dyn std::any::Any) {}

    /// On a failed handshake the client will read for the remainder of the
    /// handshake timeout and then close the connection.
    ///
    /// # Cancel safety
    ///
    /// This function is **not cancel-safe**. Dropping the returned future
    /// mid-handshake may leave the underlying stream in a partially-written
    /// state. Wrap in `tokio::spawn` if cancellation is possible.
    pub async fn wrap<'a, T>(self, mut stream: T) -> Result<Obfs4Stream<T>>
    where
        T: AsyncRead + AsyncWrite + Unpin + 'a,
    {
        let session = sessions::new_client_session(self.station_pubkey, self.iat_mode);

        let deadline = self.handshake_timeout.map(|d| Instant::now() + d);

        session.handshake(stream, deadline).await
    }

    /// On a failed handshake the client will read for the remainder of the
    /// handshake timeout and then close the connection.
    ///
    /// # Cancel safety
    ///
    /// This function is **not cancel-safe**. Dropping the returned future
    /// mid-handshake may leave the underlying stream in a partially-written
    /// state. Wrap in `tokio::spawn` if cancellation is possible.
    pub async fn establish<'a, T, E>(
        self,
        mut stream_fut: Pin<ptrs::FutureResult<T, E>>,
    ) -> Result<Obfs4Stream<T>>
    where
        T: AsyncRead + AsyncWrite + Unpin + 'a,
        E: std::error::Error + Send + Sync + 'static,
    {
        let stream = stream_fut.await.map_err(|e| Error::Other(Box::new(e)))?;

        let session = sessions::new_client_session(self.station_pubkey, self.iat_mode);

        let deadline = self.handshake_timeout.map(|d| Instant::now() + d);

        session.handshake(stream, deadline).await
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::Result;

    #[test]
    fn parse_params() -> Result<()> {
        let test_args = [["", "", ""]];

        for (i, test_case) in test_args.iter().enumerate() {
            let cb = ClientBuilder::from_params(test_case.to_vec())?;
        }
        Ok(())
    }

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
}
