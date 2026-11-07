use std::io::Write;
use std::net::SocketAddr;

const VERSION: &str = "1";

pub fn print_version() {
    emit(format!("VERSION {VERSION}"));
}

/// PT-spec §3.1: no protocol version offered by the parent is supported.
pub fn print_version_error() {
    emit("VERSION-ERROR no-version".to_owned());
}

/// PT-spec §3.2: the parent's environment is unusable. `reason` must be a
/// static description: it is written to the control channel verbatim.
pub fn print_env_error(reason: &str) {
    emit(format!("ENV-ERROR {reason}"));
}

/// PT-spec §3.1/§3.2: validate the parent's environment, announce the chosen
/// protocol version, and report whether this is a client (`true`) launch.
///
/// Failures are reported on the control channel (`VERSION-ERROR` /
/// `ENV-ERROR`) before the error is returned, so the parent can tell a bad
/// launch from a crash.
pub fn negotiate() -> anyhow::Result<bool> {
    use ptrs::constants::{CURRENT_TRANSPORT_VER, MANAGED_VER};

    let Some(offered) = std::env::var_os(MANAGED_VER) else {
        print_env_error("TOR_PT_MANAGED_TRANSPORT_VER is not set");
        anyhow::bail!("TOR_PT_MANAGED_TRANSPORT_VER is not set");
    };
    let supported = offered
        .to_str()
        .is_some_and(|list| list.split(',').any(|v| v == CURRENT_TRANSPORT_VER));
    if !supported {
        print_version_error();
        anyhow::bail!("no supported managed transport protocol version");
    }
    print_version();
    let client = ptrs::is_client().map_err(|error| {
        print_env_error(&error.to_string());
        anyhow::Error::from(error)
    })?;
    // `is_client` only checks presence; setup later reads the value as UTF-8.
    if client && std::env::var(ptrs::constants::CLIENT_TRANSPORTS).is_err() {
        print_env_error("TOR_PT_CLIENT_TRANSPORTS is not valid unicode");
        anyhow::bail!("TOR_PT_CLIENT_TRANSPORTS is not valid unicode");
    }
    Ok(client)
}

pub fn print_cmethod(transport: &str, proto: &str, addr: SocketAddr) {
    emit(format!("CMETHOD {transport} {proto} {addr}"));
}

pub fn print_cmethod_error(transport: &str, reason: &str) {
    emit(format!("CMETHOD-ERROR {transport} {reason}"));
}

pub fn print_cmethods_done() {
    emit("CMETHODS DONE".to_string());
}

/// PT-spec §3.3.2: tell the parent process that the upstream proxy given
/// in `TOR_PT_PROXY` is malformed/unsupported/unusable.
///
/// Setup terminates before initializing a transport or binding a listener.
pub fn print_proxy_error(reason: &str) {
    emit(format!("PROXY-ERROR {reason}"));
}

/// PT-spec section 3.3.2: configured transports use the validated upstream proxy.
pub fn print_proxy_done() {
    emit("PROXY DONE".to_owned());
}

fn emit(line: String) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{line}");
    let _ = out.flush();
}
