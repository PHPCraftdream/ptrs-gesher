#![deny(missing_docs)]
#![doc = include_str!("../README.md")]

/// obfs4 client types.
pub mod client;
// Internal cryptographic primitives. Kept `pub` only so the crate's own
// benches and integration tests can reach them; not part of the stable API.
#[doc(hidden)]
pub mod common;
/// obfs4 server types.
pub mod server;

// Internal framing codec and message types. Kept `pub` only for the crate's
// own benches and integration tests; not part of the stable API.
#[doc(hidden)]
pub mod framing;
// Internal stream and timeout machinery. The public-facing types it defines
// (`Obfs4Stream`, `IAT`) are re-exported from the crate root below; the module
// itself stays `pub` only so benches/tests can address it by path.
#[doc(hidden)]
pub mod proto;
pub use client::{Client, ClientBuilder};
pub use proto::{Obfs4Stream, IAT};
pub use server::{Server, ServerBuilder};

pub(crate) mod iat_mode_json {
    use super::IAT;
    use serde::{de, Deserializer, Serializer};
    use std::fmt;
    use std::str::FromStr;

    pub fn serialize<S>(value: &Option<IAT>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            None => serializer.serialize_none(),
            Some(mode) => serializer.serialize_u8(match mode {
                IAT::Off => 0,
                IAT::Enabled => 1,
                IAT::Paranoid => 2,
            }),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<IAT>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct IatModeVisitor;

        impl<'de> de::Visitor<'de> for IatModeVisitor {
            type Value = Option<IAT>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("iat-mode as an integer 0, 1, or 2, or a legacy string")
            }

            fn visit_none<E>(self) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(None)
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(None)
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                IAT::from_str(value)
                    .map(Some)
                    .map_err(|error| E::custom(error.to_string()))
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                self.visit_str(&value)
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                match value {
                    0 => Ok(Some(IAT::Off)),
                    1 => Ok(Some(IAT::Enabled)),
                    2 => Ok(Some(IAT::Paranoid)),
                    _ => Err(E::custom("iat-mode must be one of 0, 1, or 2")),
                }
            }

            fn visit_u128<E>(self, value: u128) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if value <= 2 {
                    self.visit_u64(value as u64)
                } else {
                    Err(E::custom("iat-mode must be one of 0, 1, or 2"))
                }
            }

            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if value < 0 {
                    Err(E::custom("iat-mode cannot be negative"))
                } else {
                    self.visit_u64(value as u64)
                }
            }

            fn visit_i128<E>(self, value: i128) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if value < 0 {
                    Err(E::custom("iat-mode cannot be negative"))
                } else {
                    self.visit_u128(value as u128)
                }
            }

            fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Err(E::custom("iat-mode must be an integer 0, 1, or 2"))
            }
        }

        deserializer.deserialize_any(IatModeVisitor)
    }
}

pub(crate) mod constants;
pub(crate) mod handshake;
pub(crate) mod sessions;

#[cfg(test)]
mod testing;

#[cfg(test)]
mod deadline_tests;

mod pt;
pub use pt::{Obfs4PT, Transport};

mod error;
pub use error::{Error, Result};

/// Why an atomic state-file write failed, and what that leaves on disk.
///
/// After `persist` replaced the target, the new contents are what every
/// reader observes — an error from the parent-directory sync that follows is
/// a durability-confirmation failure, not a failed write: only the rename's
/// survival across a crash is unconfirmed. The two cases must not be
/// conflated:
///
/// * [`AtomicWriteError::NotPublished`] — the target was never replaced;
///   on-disk state is unchanged, so pre-write expectations (a cached
///   observation of the previous contents) stay valid and a plain retry
///   redoes the whole write.
/// * [`AtomicWriteError::PublishedButNotDurable`] — the target now holds the
///   bytes this call published. A caller that keeps stale pre-write
///   expectations would misread its own file as an external change. It must
///   adopt the publication: record the published bytes as its own
///   observation, keep the rest of any cached configuration verbatim (for
///   `ServerBuilder::try_build`: resolved identity, DRBG seed and manual
///   overrides are NOT re-resolved, so client parameters already published
///   from them stay valid), and leave persistence pending so a retry
///   re-validates against the builder's own file and re-attempts the
///   durability sync. The error is still propagated: until the directory
///   sync succeeds a crash may lose the rename, so the operation has not
///   succeeded.
#[derive(Debug)]
pub(crate) enum AtomicWriteError {
    /// The target name was never replaced: on-disk state is unchanged, so
    /// pre-write expectations (a cached observation of the previous
    /// contents) remain valid and a plain retry redoes the whole write.
    NotPublished(Error),
    /// `persist` already replaced the target with the bytes this call
    /// published; only the parent-directory durability sync failed. The
    /// new contents are what every reader now observes; a crash before a
    /// successful directory sync may still lose the rename.
    PublishedButNotDurable {
        /// The durability-sync error.
        error: Error,
        /// The exact bytes published to the target path.
        published_contents: Vec<u8>,
    },
}

impl From<std::io::Error> for AtomicWriteError {
    fn from(error: std::io::Error) -> Self {
        AtomicWriteError::NotPublished(error.into())
    }
}

/// Any failure a caller hits while *preparing* the write -- serialising the
/// state, resolving a missing field -- happens before `persist` replaces the
/// target, so it is `NotPublished` by construction. Only the directory sync
/// inside `atomic_write_json` can produce the published-but-not-durable case,
/// and it builds that variant directly.
impl From<Error> for AtomicWriteError {
    fn from(error: Error) -> Self {
        AtomicWriteError::NotPublished(error)
    }
}

impl From<AtomicWriteError> for Error {
    fn from(failure: AtomicWriteError) -> Self {
        match failure {
            AtomicWriteError::NotPublished(error)
            | AtomicWriteError::PublishedButNotDurable { error, .. } => error,
        }
    }
}

pub(crate) fn atomic_write_json<T: serde::Serialize>(
    path: &std::path::Path,
    value: &T,
) -> std::result::Result<(), AtomicWriteError> {
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|e| AtomicWriteError::NotPublished(Error::Other(Box::new(e))))?;
    let parent = parent_directory_of(path);
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    std::io::Write::write_all(&mut temporary, &bytes)?;
    temporary.as_file().sync_all()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temporary
            .as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    // persist() is the publication point: past this call the target name is
    // replaced by our bytes, so any later failure is post-publication.
    temporary
        .persist(path)
        .map_err(|error| AtomicWriteError::NotPublished(Error::IOError(error.error)))?;
    // Directory-sync failures after publication propagate as errors on
    // purpose: persist() has replaced the target name, but until the parent
    // directory is synced a crash may still lose the rename. They are typed
    // as `PublishedButNotDurable` carrying the published bytes, so the caller
    // can adopt its own write instead of mistaking it for an external change.
    if let Err(error) = sync_parent_directory(parent) {
        return Err(AtomicWriteError::PublishedButNotDurable {
            error,
            published_contents: bytes,
        });
    }
    Ok(())
}

/// Resolve the directory backing `path`'s parent for atomic-write durability.
///
/// `Path::parent` returns `Some("")` for a bare filename (not `None`), and an
/// empty path is rejected by `File::open` and `NamedTempFile::new_in`;
/// normalize it to the process's current directory.
fn parent_directory_of(path: &std::path::Path) -> &std::path::Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."))
}

/// Flush a directory entry so a just-persisted rename survives a crash.
///
/// The file contents are already durable (`sync_all` on the temporary file
/// before persist); this covers the rename itself. Supported on Unix, where a
/// directory can be opened as a file and fsynced. On Windows a directory
/// cannot be opened through `std::fs` (it requires
/// `FILE_FLAG_BACKUP_SEMANTICS` via FFI), so directory-entry durability is
/// NOT guaranteed by this mechanism there — a documented platform limitation,
/// not a silent no-op: file data stays durable, only the rename does not.
fn sync_parent_directory(directory: &std::path::Path) -> Result<()> {
    // Recorded on every platform, not just where the fsync happens: the seam
    // also has to prove that this call site is wired into atomic_write_json at
    // all, and that the parent path handed to it was normalized. For the same
    // reason the injected one-shot failure below must fire on every platform:
    // on Windows the real fsync is a documented no-op, and the durability step
    // still has to be failable for the post-publication regression test.
    #[cfg(test)]
    {
        record_synced_parent_directory(directory);
        if take_pending_parent_directory_sync_failure(directory) {
            return Err(std::io::Error::other("injected parent-directory sync failure").into());
        }
    }
    #[cfg(unix)]
    {
        let handle = std::fs::File::open(directory)?;
        handle.sync_all()?;
    }
    #[cfg(not(any(unix, test)))]
    {
        let _ = directory;
    }
    Ok(())
}

#[cfg(test)]
static SYNCED_PARENT_DIRECTORIES: std::sync::Mutex<Vec<std::path::PathBuf>> =
    std::sync::Mutex::new(Vec::new());

#[cfg(test)]
fn record_synced_parent_directory(directory: &std::path::Path) {
    SYNCED_PARENT_DIRECTORIES
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .push(directory.to_path_buf());
}

#[cfg(test)]
pub(crate) fn synced_parent_directories() -> Vec<std::path::PathBuf> {
    SYNCED_PARENT_DIRECTORIES
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

#[cfg(test)]
static PENDING_PARENT_DIRECTORY_SYNC_FAILURES: std::sync::Mutex<Vec<std::path::PathBuf>> =
    std::sync::Mutex::new(Vec::new());

/// Arm a one-shot failure for the next `sync_parent_directory` call on
/// `directory`: it returns an injected error instead of syncing. Consumed on
/// first use. Armed by exact path, so tests using distinct temp directories
/// do not interfere.
#[cfg(test)]
pub(crate) fn fail_next_parent_directory_sync(directory: &std::path::Path) {
    PENDING_PARENT_DIRECTORY_SYNC_FAILURES
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .push(directory.to_path_buf());
}

#[cfg(test)]
fn take_pending_parent_directory_sync_failure(directory: &std::path::Path) -> bool {
    let mut pending = PENDING_PARENT_DIRECTORY_SYNC_FAILURES
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    match pending
        .iter()
        .position(|pending_path| pending_path == directory)
    {
        Some(position) => {
            pending.remove(position);
            true
        }
        None => false,
    }
}

/// The transport name string.
pub const OBFS4_NAME: &str = "obfs4";

#[cfg(test)]
pub(crate) mod test_utils;

// Pre-generated key material and argument strings for the crate's own tests.
// Gated to `test` so these never enter the published API or release binaries.
#[cfg(test)]
#[allow(missing_docs)]
pub(crate) mod dev {
    /// Pre-generated / shared key for use while running in debug mode.
    pub const DEV_PRIV_KEY: &[u8; 32] = b"0123456789abcdeffedcba9876543210";

    /// Client obfs4 arguments based on pre-generated dev key `DEV_PRIV_KEY`.
    pub const CLIENT_ARGS: &str =
        "cert=AAAAAAAAAAAAAAAAAAAAAAAAAADTSFvsGKxNFPBcGdOCBSgpEtJInG9zCYZezBPVBuBWag;iat-mode=0";

    /// Server obfs4 arguments based on pre-generated dev key `DEV_PRIV_KEY`.
    pub const SERVER_ARGS: &str = "drbg-seed=0a0b0c0d0e0f0a0b0c0d0e0f0a0b0c0d0e0f0a0b0c0d0e0f;node-id=0000000000000000000000000000000000000000;private-key=3031323334353637383961626364656666656463626139383736353433323130;iat-mode=0";

    #[cfg(test)]
    mod test {
        use super::*;
        use crate::common::x25519_elligator2::StaticSecret;
        use crate::constants::*;
        use crate::handshake::Obfs4NtorSecretKey;
        use crate::{ClientBuilder, ServerBuilder};
        use ptrs::ServerBuilder as _;

        use ptrs::args::Args;
        use ptrs::trace;
        use tokio::net::TcpStream;
        use tor_llcrypto::pk::rsa::RsaIdentity;

        pub fn trace_print_dev_args() {
            let static_secret = StaticSecret::from(*DEV_PRIV_KEY);
            let sk =
                Obfs4NtorSecretKey::new(static_secret, RsaIdentity::from([0u8; NODE_ID_LENGTH]));
            let mut client_args = Args::new();
            client_args.add(CERT_ARG, &sk.pk.to_string());
            client_args.add(IAT_ARG, "0");
            trace!("{}", client_args.encode_smethod_args());
        }

        #[test]
        fn test_parse() {
            trace_print_dev_args();

            let args = Args::parse_client_parameters(CLIENT_ARGS).unwrap();
            let mut builder = ClientBuilder::default();
            <ClientBuilder as ptrs::ClientBuilder<TcpStream>>::options(&mut builder, &args)
                .unwrap();

            let server_params = Args::parse_client_parameters(SERVER_ARGS).unwrap();
            let mut server_builder = ServerBuilder::<TcpStream>::default();
            server_builder.options(&server_params).unwrap();
        }
    }
}
