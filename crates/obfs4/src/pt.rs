use crate::{
    proto::{MaybeTimeout, Obfs4Stream},
    Error, OBFS4_NAME,
};
use ptrs::{args::Args, FutureResult as F};

use std::{
    marker::PhantomData,
    net::{SocketAddrV4, SocketAddrV6},
    pin::Pin,
    time::Duration,
};

use ptrs::trace;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};

/// Concrete obfs4 pluggable transport bound to [`TcpStream`].
pub type Obfs4PT = Transport<TcpStream>;

/// Generic obfs4 pluggable transport parameterised over an underlying stream type.
#[derive(Debug, Default)]
pub struct Transport<T> {
    _p: PhantomData<T>,
}
impl<T> Transport<T> {
    /// The canonical name of this pluggable transport protocol.
    pub const NAME: &'static str = OBFS4_NAME;
}

impl<T> ptrs::PluggableTransport<T> for Transport<T>
where
    T: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    type ClientBuilder = crate::ClientBuilder;
    type ServerBuilder = crate::ServerBuilder<T>;

    fn name() -> String {
        OBFS4_NAME.into()
    }

    fn client_builder() -> <Self as ptrs::PluggableTransport<T>>::ClientBuilder {
        crate::ClientBuilder::default()
    }

    fn server_builder() -> <Self as ptrs::PluggableTransport<T>>::ServerBuilder {
        crate::ServerBuilder::default()
    }
}

impl<T> ptrs::ServerBuilder<T> for crate::ServerBuilder<T>
where
    T: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    type ServerPT = crate::Server;
    type Error = Error;
    type Transport = Transport<T>;

    fn build(&self) -> Self::ServerPT {
        crate::ServerBuilder::build(self)
    }

    fn method_name() -> String {
        OBFS4_NAME.into()
    }

    fn options(&mut self, opts: &Args) -> Result<&mut Self, Self::Error> {
        let state = Self::parse_state(self.statefile_path.as_deref(), opts)?;
        self.identity_keys = state.private_key;
        self.identity_override = true;
        self.iat_mode(state.iat_mode);
        self.drbg_seed = Some(state.drbg_seed_value);
        self.seed_override = true;
        self.config_error = None;
        self.invalidate_effective_configuration();

        trace!(
            "node_pubkey: {}, node_id: {}, iat: {}",
            hex::encode(self.identity_keys.pk.pk.as_bytes()),
            hex::encode(self.identity_keys.pk.id.as_bytes()),
            self.iat_mode,
        );
        Ok(self)
    }

    fn get_client_params(&self) -> String {
        self.client_params()
    }

    fn statefile_location(&mut self, _path: &str) -> Result<&mut Self, Self::Error> {
        self.statefile_path(_path);
        Ok(self)
    }

    fn timeout(&mut self, timeout: Option<Duration>) -> Result<&mut Self, Self::Error> {
        self.handshake_timeout = timeout.map_or(MaybeTimeout::Default_, MaybeTimeout::Length);
        Ok(self)
    }

    fn v4_bind_addr(&mut self, _addr: SocketAddrV4) -> Result<&mut Self, Self::Error> {
        Err(Error::NotSupported)
    }

    fn v6_bind_addr(&mut self, _addr: SocketAddrV6) -> Result<&mut Self, Self::Error> {
        Err(Error::NotSupported)
    }
}

impl<T> ptrs::ClientBuilder<T> for crate::ClientBuilder
where
    T: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    type ClientPT = crate::Client;
    type Error = Error;
    type Transport = Transport<T>;

    fn method_name() -> String {
        OBFS4_NAME.into()
    }

    /// Builds a new PtCommonParameters.
    ///
    /// **Errors**
    /// If a required field has not been initialized.
    fn build(&self) -> Self::ClientPT {
        crate::ClientBuilder::build(self)
    }

    /// Pluggable transport attempts to parse and validate options from a string,
    /// typically using ['parse_smethod_args'].
    fn options(&mut self, opts: &Args) -> Result<&mut Self, Self::Error> {
        if opts.is_empty() {
            if let Some(path) = self.statefile_path.clone() {
                self.load_statefile(std::path::Path::new(&path))?;
                return Ok(self);
            }
        }
        self.apply_args(opts)?;
        trace!(
            "node_pubkey: {}, node_id: {}, iat: {}",
            hex::encode(self.station_pubkey),
            hex::encode(self.station_id),
            self.iat_mode
        );
        Ok(self)
    }

    /// A path where the launched PT can store state.
    fn statefile_location(&mut self, _path: &str) -> Result<&mut Self, Self::Error> {
        self.with_statefile_directory(_path);
        Ok(self)
    }

    /// The maximum time we should wait for a pluggable transport binary to
    /// report successful initialization. If `None`, a default value is used.
    fn timeout(&mut self, timeout: Option<Duration>) -> Result<&mut Self, Self::Error> {
        self.handshake_timeout = timeout.map_or(MaybeTimeout::Default_, MaybeTimeout::Length);
        Ok(self)
    }

    /// An IPv4 address to bind outgoing connections to (if specified).
    ///
    /// Leaving this out will mean the PT uses a sane default.
    fn v4_bind_addr(&mut self, _addr: SocketAddrV4) -> Result<&mut Self, Self::Error> {
        Err(Error::NotSupported)
    }

    /// An IPv6 address to bind outgoing connections to (if specified).
    ///
    /// Leaving this out will mean the PT uses a sane default.
    fn v6_bind_addr(&mut self, _addr: SocketAddrV6) -> Result<&mut Self, Self::Error> {
        Err(Error::NotSupported)
    }
}

/// Example wrapping transport that just passes the incoming connection future through
/// unmodified as a proof of concept.
impl<InRW, InErr> ptrs::ClientTransport<InRW, InErr> for crate::Client
where
    InRW: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
    InErr: std::error::Error + Send + Sync + 'static,
{
    type OutRW = Obfs4Stream<InRW>;
    type OutErr = Error;
    type Builder = crate::ClientBuilder;

    fn establish(self, input: Pin<F<InRW, InErr>>) -> Pin<F<Self::OutRW, Self::OutErr>> {
        Box::pin(crate::Client::establish(self, input))
    }

    fn wrap(self, io: InRW) -> Pin<F<Self::OutRW, Self::OutErr>> {
        Box::pin(crate::Client::wrap(self, io))
    }

    fn method_name() -> String {
        OBFS4_NAME.into()
    }
}

impl<InRW> ptrs::ServerTransport<InRW> for crate::Server
where
    InRW: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    type OutRW = Obfs4Stream<InRW>;
    type OutErr = Error;
    type Builder = crate::ServerBuilder<InRW>;

    /// Use something that can be accessed reference (Arc, Rc, etc.)
    fn reveal(self, io: InRW) -> Pin<F<Self::OutRW, Self::OutErr>> {
        Box::pin(crate::Server::wrap(self, io))
    }

    fn method_name() -> String {
        OBFS4_NAME.into()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{constants::*, proto::IAT};

    #[test]
    fn client_options_with_cert_parses_pubkey_and_iat() {
        let mut cb = crate::ClientBuilder::default();
        let mut args = Args::new();
        let cert = crate::dev::CLIENT_ARGS
            .split("cert=")
            .nth(1)
            .unwrap()
            .split(";")
            .next()
            .unwrap();
        args.add(CERT_ARG, cert);
        args.add(IAT_ARG, "2");
        <crate::ClientBuilder as ptrs::ClientBuilder<TcpStream>>::options(&mut cb, &args).unwrap();
        // cert parsing must produce non-zero pubkey (dev cert has all-zero node_id but non-zero pk)
        assert_ne!(cb.station_pubkey, [0u8; NODE_PUBKEY_LENGTH]);
        // IAT must be parsed from "2"
        assert_eq!(cb.iat_mode, IAT::Paranoid);
    }

    #[test]
    fn client_options_invalid_iat_rejected() {
        let mut cb = crate::ClientBuilder::default();
        let mut args = Args::new();
        let cert = crate::dev::CLIENT_ARGS
            .split("cert=")
            .nth(1)
            .unwrap()
            .split(";")
            .next()
            .unwrap();
        args.add(CERT_ARG, cert);
        args.add(IAT_ARG, "99");
        let result =
            <crate::ClientBuilder as ptrs::ClientBuilder<TcpStream>>::options(&mut cb, &args);
        assert!(result.is_err());
    }

    #[test]
    fn client_options_invalid_cert_rejected() {
        let mut cb = crate::ClientBuilder::default();
        let mut args = Args::new();
        args.add(CERT_ARG, "totally-invalid-base64");
        args.add(IAT_ARG, "0");
        let result =
            <crate::ClientBuilder as ptrs::ClientBuilder<TcpStream>>::options(&mut cb, &args);
        assert!(result.is_err());
    }

    #[test]
    fn client_options_missing_cert_and_node_id() {
        let mut cb = crate::ClientBuilder::default();
        let mut args = Args::new();
        args.add(IAT_ARG, "0");
        let result =
            <crate::ClientBuilder as ptrs::ClientBuilder<TcpStream>>::options(&mut cb, &args);
        assert!(result.is_err());
    }

    #[test]
    fn client_options_missing_iat() {
        let mut cb = crate::ClientBuilder::default();
        let mut args = Args::new();
        args.add(NODE_ID_ARG, "0000000000000000000000000000000000000000");
        args.add(
            PUBLIC_KEY_ARG,
            "0000000000000000000000000000000000000000000000000000000000000000",
        );
        let result =
            <crate::ClientBuilder as ptrs::ClientBuilder<TcpStream>>::options(&mut cb, &args);
        assert!(result.is_err());
    }

    #[test]
    fn server_options_populates_identity_keys() {
        let mut sb = crate::ServerBuilder::<TcpStream>::default();
        let original_id = sb.identity_keys.pk.id;
        let args = Args::parse_client_parameters(crate::dev::SERVER_ARGS).unwrap();
        <crate::ServerBuilder<TcpStream> as ptrs::ServerBuilder<TcpStream>>::options(
            &mut sb, &args,
        )
        .unwrap();
        // identity_keys must have been overwritten from the dev key
        assert_ne!(sb.identity_keys.pk.id, original_id);
    }

    #[test]
    fn server_options_missing_args() {
        let mut sb = crate::ServerBuilder::<TcpStream>::default();
        let args = Args::new();
        let result = <crate::ServerBuilder<TcpStream> as ptrs::ServerBuilder<TcpStream>>::options(
            &mut sb, &args,
        );
        assert!(result.is_err());
    }

    #[test]
    fn check_name() {
        let pt_name = <Obfs4PT as ptrs::PluggableTransport<TcpStream>>::name();
        assert_eq!(pt_name, Obfs4PT::NAME);

        let cb_name = <crate::ClientBuilder as ptrs::ClientBuilder<TcpStream>>::method_name();
        assert_eq!(cb_name, Obfs4PT::NAME);

        let sb_name =
            <crate::ServerBuilder<TcpStream> as ptrs::ServerBuilder<TcpStream>>::method_name();
        assert_eq!(sb_name, Obfs4PT::NAME);

        let ct_name =
            <crate::Client as ptrs::ClientTransport<TcpStream, crate::Error>>::method_name();
        assert_eq!(ct_name, Obfs4PT::NAME);

        let st_name = <crate::Server as ptrs::ServerTransport<TcpStream>>::method_name();
        assert_eq!(st_name, Obfs4PT::NAME);
    }

    #[test]
    fn bind_addresses_are_explicitly_unsupported() {
        let mut client = crate::ClientBuilder::default();
        assert!(
            <crate::ClientBuilder as ptrs::ClientBuilder<TcpStream>>::v4_bind_addr(
                &mut client,
                "127.0.0.1:0".parse().unwrap(),
            )
            .is_err()
        );
        let mut server = crate::ServerBuilder::<TcpStream>::default();
        assert!(
            <crate::ServerBuilder<TcpStream> as ptrs::ServerBuilder<TcpStream>>::v6_bind_addr(
                &mut server,
                "[::1]:0".parse().unwrap(),
            )
            .is_err()
        );
    }
}
