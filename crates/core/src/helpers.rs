use crate::{
    args::{Args, Opts},
    debug,
};

#[cfg(unix)]
use std::os::unix::fs::DirBuilderExt;
use std::{env, fs::DirBuilder, io::Error, net::SocketAddr, str::FromStr};

use itertools::Itertools;
use tokio::net::TcpStream;
use url::Url;

/// PT-spec environment variable names and current protocol version.
pub mod constants {
    /// The only managed-transport protocol version we support.
    pub const CURRENT_TRANSPORT_VER: &str = "1";

    /// `TOR_PT_MANAGED_TRANSPORT_VER`
    pub const MANAGED_VER: &str = "TOR_PT_MANAGED_TRANSPORT_VER";
    /// `TOR_PT_STATE_LOCATION`
    pub const STATE_LOCATION: &str = "TOR_PT_STATE_LOCATION";
    /// `TOR_PT_CLIENT_TRANSPORTS`
    pub const CLIENT_TRANSPORTS: &str = "TOR_PT_CLIENT_TRANSPORTS";
    /// `TOR_PT_PROXY`
    pub const PROXY: &str = "TOR_PT_PROXY";
    /// `TOR_PT_SERVER_TRANSPORTS`
    pub const SERVER_TRANSPORTS: &str = "TOR_PT_SERVER_TRANSPORTS";
    /// `TOR_PT_SERVER_TRANSPORT_OPTIONS`
    pub const SERVER_TRANSPORT_OPTIONS: &str = "TOR_PT_SERVER_TRANSPORT_OPTIONS";
    /// `TOR_PT_SERVER_BINDADDR`
    pub const SERVER_BINDADDR: &str = "TOR_PT_SERVER_BINDADDR";
    /// `TOR_PT_AUTH_COOKIE_FILE`
    pub const AUTH_COOKIE_FILE: &str = "TOR_PT_AUTH_COOKIE_FILE";
    /// `TOR_PT_ORPORT`
    pub const ORPORT: &str = "TOR_PT_ORPORT";
    /// `TOR_PT_EXTENDED_SERVER_PORT`
    pub const EXTENDED_SERVER_PORT: &str = "TOR_PT_EXTENDED_SERVER_PORT";
    /// `TOR_PT_EXIT_ON_STDIN_CLOSE`
    pub const EXIT_ON_STDIN_CLOSE: &str = "TOR_PT_EXIT_ON_STDIN_CLOSE";
}

/// Get a pluggable transports version offered by Tor and understood by us, if
/// any. The only version we understand is "1". This function reads the
/// environment variable `TOR_PT_MANAGED_TRANSPORT_VER`.
pub(crate) fn get_managed_transport_ver() -> Result<String, Error> {
    let managed_transport_ver = env::var(constants::MANAGED_VER).map_err(to_io_other)?;
    for segment in managed_transport_ver.split(',') {
        if segment == constants::CURRENT_TRANSPORT_VER {
            return Ok(segment.into());
        }
    }

    Err(to_io_other("no-version"))
}

/// Determines if the current program should be running as a client or server
/// by checking the `TOR_PT_CLIENT_TRANSPORTS` and `TOR_PT_SERVER_TRANSPORTS`
/// environment variables.
pub fn is_client() -> Result<bool, Error> {
    let is_client = env::var_os(constants::CLIENT_TRANSPORTS);
    let is_server = env::var_os(constants::SERVER_TRANSPORTS);

    match (is_client, is_server) {
        (Some(_), Some(_)) => Err(to_io_other(
            "ENV-ERROR TOR_PT_[CLIENT,SERVER]_TRANSPORTS both set",
        )),
        (Some(_), None) => Ok(true),
        (None, Some(_)) => Ok(false),
        (None, None) => Err(to_io_other("not launched as a managed transport")),
    }
}

/// Get the state directory from env, create if it doesnt exist.
///
/// Return the directory name in the TOR_PT_STATE_LOCATION environment variable, creating it
/// if it doesn't exist. Returns non-nil error if `TOR_PT_STATE_LOCATION` is not set or if
/// there is an error creating the directory.
pub fn make_state_dir() -> Result<String, Error> {
    let path = env::var(constants::STATE_LOCATION)
        .map_err(|_| to_io_other("missing required TOR_PT_STATE_LOCATION env var"))?;

    let mut builder = DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    builder.mode(0o700);
    builder.create(&path)?;
    Ok(path)
}

/// Feature #15435 adds a new env var for determining if Tor keeps stdin
/// open for use in termination detection.
pub fn pt_should_exit_on_stdin_close() -> bool {
    if let Ok(v) = env::var(constants::EXIT_ON_STDIN_CLOSE) {
        v == "1"
    } else {
        false
    }
}

/// Block until the process's stdin reaches EOF (parent closed it) or an
/// read error occurs, then return.
///
/// This implements the parent-died-detection behavior from PT-spec §3.4
/// ("Feature #15435"): when a Tor PT parent process wants to terminate
/// its managed PT child by closing the child's stdin, it sets
/// `TOR_PT_EXIT_ON_STDIN_CLOSE=1` in the child's environment. The PT
/// detects this by reading stdin until EOF and then exiting cleanly.
///
/// The read runs on a `tokio::task::spawn_blocking` thread, so it does
/// not occupy a tokio worker while blocked in the read syscall.
///
/// Callers SHOULD gate this on [`pt_should_exit_on_stdin_close`] — when
/// the env var is not set the parent keeps stdin open for the process's
/// entire lifetime and this future never resolves. A typical use is to
/// build it into a `tokio::select!` branch that is inert (pending
/// forever) when [`pt_should_exit_on_stdin_close`] is false.
///
/// # Cancel safety
///
/// This future is **not cancel-safe**: dropping it abandons the
/// underlying blocking read, which keeps consuming the `spawn_blocking`
/// thread until stdin actually reaches EOF. In a PT process this is
/// acceptable because the future is dropped only as part of process
/// shutdown.
pub async fn wait_stdin_close() {
    wait_reader_close(std::io::stdin()).await
}

/// Block until `reader` reaches EOF or errors, draining any bytes it
/// produces first.
///
/// This is the reader-generic core of [`wait_stdin_close`], exposed so
/// that callers (notably tests) can substitute a non-stdin reader — a
/// `Cursor`, an in-memory pipe, or a deliberately-failing reader —
/// instead of consuming the real process stdin.
///
/// Like [`wait_stdin_close`], the read loop runs on a
/// `tokio::task::spawn_blocking` thread and shares the same
/// (lack of) cancel-safety.
pub async fn wait_reader_close<R>(reader: R)
where
    R: std::io::Read + Send + 'static,
{
    let join = tokio::task::spawn_blocking(move || {
        let mut buf = [0u8; 1024];
        let mut reader = reader;
        loop {
            match reader.read(&mut buf) {
                // 0-byte read is EOF; an error is treated the same way
                // — either way the parent is no longer producing stdin
                // and the PT should exit.
                Ok(0) | Err(_) => return,
                Ok(_) => continue,
            }
        }
    });
    // Best-effort: a panic inside the blocking task (none is reachable
    // here) should not propagate as a JoinError that the caller can't
    // distinguish from a clean EOF.
    let _ = join.await;
}

// ================================================================ //
//                            Client                                //
// ================================================================ //

/// Client-side PT configuration read from the environment.
pub struct ClientInfo {
    /// Transport names requested by the parent process.
    pub methods: Vec<String>,
    /// Optional upstream proxy URL.
    pub uri: Option<Url>,
}

impl ClientInfo {
    /// Read client info from `TOR_PT_*` environment variables.
    pub fn new() -> Result<Self, Error> {
        let _ver = get_managed_transport_ver()?;
        debug!("VERSION {_ver}");

        Ok(Self {
            methods: get_client_transports()?,
            uri: get_proxy_url()?,
        })
    }
}

pub(crate) fn get_client_transports() -> Result<Vec<String>, Error> {
    let client_transports = env::var(constants::CLIENT_TRANSPORTS).map_err(to_io_other)?;
    Ok(client_transports.split(',').map(String::from).collect_vec())
}

pub(crate) fn get_proxy_url() -> Result<Option<Url>, Error> {
    let url_str = match env::var(constants::PROXY) {
        Ok(s) if s.is_empty() => return Ok(None),
        Ok(s) => s,
        Err(env::VarError::NotPresent) => return Ok(None),
        Err(e) => return Err(to_io_other(format!("failed to parse proxy config: {e}"))),
    };

    // Url::parse() only works for absolute urls so we do not need to check for relative
    let uri = Url::parse(&url_str)
        .map_err(|e| to_io_other(format!("failed to parse proxy config \"{url_str}\": {e}")))?;

    validate_proxy_url(&uri)?;

    Ok(Some(uri))
}

/// When a client connects to the client side of the pluggable transport proxy
/// they can optionally provide a proxy url in the `TOR_PT_PROXY` environment
/// variable that will be used as a proxy dialer underneath the pluggable
/// transport connection.
///
/// This function validates that a provided url:
/// - uses one of `socks4a`, `socks5`, `http` protocols.
/// - has a defined host field that DOES NOT require dns resolution. (i.e. an IP address)
/// - DOES NOT have defined `path`, `query`, or `fragment` fields.
/// - socks5 urls must have non-empty username and password fields.
/// - if socks4 urls have a password they must have a username.
///
/// From `pt-spec.txt 3.5`:
///
/// ```txt
///    On the client side, arguments are passed via the authentication
///    fields that are part of the SOCKS protocol.
///
///    ... The arguments are transmitted when making the outgoing
///    connection using the authentication mechanism specific to the
///    SOCKS protocol version.
///
///     - In the case of SOCKS 4, the concatenated argument list is
///       transmitted in the "USERID" field of the "CONNECT" request.
///
///     - In the case of SOCKS 5, the parent process must negotiate
///       "Username/Password" authentication [RFC1929], and transmit
///       the arguments encoded in the "UNAME" and "PASSWD" fields.
///
///       If the encoded argument list is less than 255 bytes in
///       length, the "PLEN" field must be set to "1" and the "PASSWD"
///       field must contain a single NUL character.
/// ```
#[allow(clippy::collapsible_if)]
pub(crate) fn validate_proxy_url(spec: &Url) -> Result<(), Error> {
    const SCHEMES: [&str; 3] = ["socks5", "socks4a", "http"];
    if !SCHEMES.contains(&spec.scheme()) {
        return Err(to_io_other(format!(
            "proxy URI has invalid scheme: {}",
            spec.scheme()
        )));
    }

    // when spec = http the path defaults to "/" instead of empty -_-
    if !spec.path().is_empty() {
        if !(spec.scheme() == "http" && spec.path() == "/") {
            return Err(to_io_other("proxy URI has a path defined "));
        }
    }
    if spec.query().is_some() {
        if !spec.query().unwrap().is_empty() {
            return Err(to_io_other("proxy URI has a query defined"));
        }
    }
    if spec.fragment().is_some() {
        if !spec.fragment().unwrap().is_empty() {
            return Err(to_io_other("proxy URI has a fragment defined"));
        }
    }
    if spec.port().is_none() {
        return Err(to_io_other("proxy URI lacks a port"));
    }

    match spec.scheme() {
        "socks5" => {
            let username = spec.username();
            let passwd = spec.password();

            // if either password or username is specified, then both must be non-empty
            if !username.is_empty() || passwd.is_some() {
                if username.is_empty() || username.len() > 255 {
                    return Err(to_io_other("proxy URI specified a invalid SOCKS5 username"));
                }
                if passwd.is_none() {
                    return Err(to_io_other("proxy URI specified a invalid SOCKS5 password"));
                } else if let Some(p) = passwd {
                    if p.is_empty() || p.len() > 255 {
                        return Err(to_io_other("proxy URI specified a invalid SOCKS5 password"));
                    }
                }
            }
        }
        "socks4a" => {
            if spec.password().is_some() {
                return Err(to_io_other("proxy URI specified SOCKS4a and a password"));
            }
        }
        "http" => {}
        _ => {
            return Err(to_io_other(format!(
                "proxy URI has invalid scheme: {}",
                spec.scheme()
            )));
        }
    }

    if spec.host_str().is_none() {
        return Err(to_io_other("proxy URI has missing host"));
    }

    // not sure how better to combine host port.
    let mut sockaddr_string = String::from(spec.host_str().unwrap());
    sockaddr_string.push(':');
    sockaddr_string.push_str(&format!("{}", spec.port().unwrap()));
    let _ = resolve_addr(&sockaddr_string)
        .map_err(|e| to_io_other(format!("proxy URI has invalid host: {e}")))?;

    Ok(())
}

// ================================================================ //
//                            Server                                //
// ================================================================ //

/// Tor OR Server Information
///
/// Check the server pluggable transports environment, emitting an error message
/// and returning a non-nil error if any error is encountered. Resolves the
/// various requested bind addresses, the server ORPort and extended ORPort, and
/// reads the auth cookie file. Returns a ServerInfo struct.
///
/// If your program needs to know whether to call ClientSetup or ServerSetup
/// (i.e., if the same program can be run as either a client or a server), check
/// whether the `TOR_PT_CLIENT_TRANSPORTS` environment variable is set:
///
/// ```text
/// match std::env::var_os("TOR_PT_CLIENT_TRANSPORTS") {
///     Some(_) => {
///         // Client mode; call pt.ClientSetup.
///     }
///     None => {
///         // Server mode; call pt.ServerSetup.
///     }
/// }
///```
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ServerInfo {
    /// Parsed bind addresses for each server transport.
    pub bind_addrs: Vec<Bindaddr>,
    /// Tor ORPort address.
    pub or_addr: Option<SocketAddr>,
    /// Extended ORPort address.
    pub extended_or_addr: Option<SocketAddr>,
    /// Path to the auth cookie file.
    pub auth_cookie_path: Option<String>,
}

impl ServerInfo {
    /// Connect to the Tor ORPort (or extended ORPort if set).
    pub async fn connect_to_or(&self) -> Result<TcpStream, Error> {
        let conn = match self.or_addr {
            Some(addr) => TcpStream::connect(addr).await?,
            None => {
                // Unify the None-check and the use into a single expression so
                // there is no code path where `unwrap()` could theoretically panic.
                let addr = self
                    .extended_or_addr
                    .ok_or_else(|| to_io_other("no OR addr provided"))?;
                TcpStream::connect(addr).await?
            }
        };

        Ok(conn)
    }
}

impl ServerInfo {
    /// Read server info from `TOR_PT_*` environment variables.
    pub fn new() -> Result<Self, Error> {
        let _ver = get_managed_transport_ver()?;
        debug!("VERSION {_ver}");

        let bind_addrs = Bindaddr::get_server_bindaddrs()?;

        let or_addr = match env::var(constants::ORPORT) {
            Ok(or_add_env) => Some(
                resolve_addr(or_add_env)
                    .map_err(|e| to_io_other(format!("cannot resolve TOR_PT_ORPORT: {e}")))?,
            ),
            Err(_) => None, // TOR_PT_ORPORT was not defined
        };

        let auth_cookie_path = env::var(constants::AUTH_COOKIE_FILE).ok();

        let extended_or_addr = match env::var(constants::EXTENDED_SERVER_PORT) {
            Ok(ext_or_addr_env) => Some(resolve_addr(ext_or_addr_env).map_err(|e| {
                to_io_other(format!("cannot resolve TOR_PT_EXTENDED_SERVER_PORT: {e}"))
            })?),
            Err(_) => None, // TOR_PT_EXTENDED_SERVER_PORT was not defined
        };

        if extended_or_addr.is_some() && auth_cookie_path.is_none() {
            return Err(to_io_other("need TOR_PT_AUTH_COOKIE_FILE environment variable with TOR_PT_EXTENDED_SERVER_PORT"));
        }

        // Need either OrAddr or ExtendedOrAddr.
        if or_addr.is_none() && extended_or_addr.is_none() {
            return Err(to_io_other(
                "need TOR_PT_ORPORT or TOR_PT_EXTENDED_SERVER_PORT environment variable",
            ));
        }

        Ok(Self {
            bind_addrs,
            or_addr,
            extended_or_addr,
            auth_cookie_path,
        })
    }
}

/// A combination of a method name and an address, as extracted from `TOR_PT_SERVER_BINDADDR`.
#[derive(Clone, Debug, PartialEq)]
pub struct Bindaddr {
    /// Transport method name (e.g. `obfs4`).
    pub method_name: String,
    /// Address to bind/listen on.
    pub addr: SocketAddr,
    /// Per-transport options from `TOR_PT_SERVER_TRANSPORT_OPTIONS`.
    pub options: Args,
}

impl Bindaddr {
    /// Construct a new `Bindaddr` from its components.
    pub fn new(method: &str, addr: SocketAddr, options: Args) -> Self {
        Self {
            method_name: method.into(),
            addr,
            options,
        }
    }

    /// Return an array of Bindaddrs, being the contents of TOR_PT_SERVER_BINDADDR
    /// with keys filtered by TOR_PT_SERVER_TRANSPORTS. Transport-specific options
    /// from TOR_PT_SERVER_TRANSPORT_OPTIONS are assigned to the Options member.
    pub(crate) fn get_server_bindaddrs() -> Result<Vec<Self>, Error> {
        // parse the list of server transport options
        let server_transport_opts =
            env::var(constants::SERVER_TRANSPORT_OPTIONS).unwrap_or_default();

        let mut options_map = Opts::parse_server_transport_options(&server_transport_opts)
            .map_err(|e| {
                to_io_other(format!(
                    "TOR_PT_SERVER_TRANSPORT_OPTIONS: {server_transport_opts}: \"{e}\""
                ))
            })?;

        // get the list of all requested bindaddrs
        let server_bindaddr = env::var(constants::SERVER_BINDADDR).map_err(to_io_other)?;
        if server_bindaddr.is_empty() {
            return Err(to_io_other(format!(
                "no \"{}\" environment variable value",
                constants::SERVER_BINDADDR
            )));
        }

        let mut results = Vec::new();
        let mut seen_methods = Vec::new();
        for spec in server_bindaddr.split(',') {
            let parts = spec.split_once('-');
            if parts.is_none() {
                return Err(to_io_other(format!(
                    "TPR_PT_SERVER_BINDADDR: {spec} doesn't contain \"-\""
                )));
            }
            let (method_name, addr) = parts.unwrap();

            // Check for duplicate method names: "Application MUST NOT set more
            // than one <address>:<port> pair per PT name."
            if seen_methods.contains(&method_name) {
                return Err(to_io_other(format!(
                    "TPR_PT_SERVER_BINDADDR: {spec} duplicate method name {method_name}"
                )));
            }
            seen_methods.push(method_name);
            let address = resolve_addr(addr)
                .map_err(|e| to_io_other(format!("TOR_PT_SERVER_BINDADDR: {spec}: {e}")))?;

            results.push(Bindaddr::new(
                method_name,
                address,
                options_map.remove(method_name).unwrap_or_default(),
            ));
        }
        let server_transports = env::var(constants::SERVER_TRANSPORTS).map_err(to_io_other)?;
        if server_transports.is_empty() {
            return Err(to_io_other(format!(
                "no \"{}\" environment variable value",
                constants::SERVER_TRANSPORTS
            )));
        }

        let result = filter_bindaddrs(results, &server_transports.split(',').collect_vec());
        Ok(result)
    }
}

fn filter_bindaddrs(addrs: Vec<Bindaddr>, methods: &[&str]) -> Vec<Bindaddr> {
    if methods.is_empty() {
        return Vec::new();
    }
    addrs
        .into_iter()
        .filter(|b| methods.contains(&b.method_name.as_str()))
        .collect()
}

/// Parse a `host:port` string into a `SocketAddr`, rejecting unspecified hosts and port 0.
pub fn resolve_addr(addr: impl AsRef<str>) -> Result<SocketAddr, Error> {
    let a = addr.as_ref();
    match SocketAddr::from_str(a) {
        Ok(sock_addr) => {
            if sock_addr.ip().is_unspecified() {
                return Err(to_io_other(format!("address string {a} lacks a host")));
            }

            if sock_addr.port() == 0 {
                return Err(to_io_other(format!("address string {a} lacks a port")));
            }
            Ok(sock_addr)
        }
        Err(e) => Err(to_io_other(format!("\"{a}\" - {e}"))),
    }
}

fn to_io_other(e: impl std::fmt::Display) -> Error {
    Error::other(format!("{e}"))
}

#[cfg(test)]
mod test;
