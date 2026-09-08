use std::io::Write;
use std::net::SocketAddr;

const VERSION: &str = "1";

pub fn print_version() {
    emit(format!("VERSION {VERSION}"));
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
/// The spec requires the PT to terminate immediately after emitting this
/// line; `client_setup` enforces that by aborting before any transport is
/// initialized and no listener is bound. A matching `print_proxy_done`
/// does NOT exist on purpose: there is no upstream proxy dialer below
/// (`dial_bridge` always connects directly), so this transport must never
/// claim `PROXY DONE` — that would promise a route the code does not use.
pub fn print_proxy_error(reason: &str) {
    emit(format!("PROXY-ERROR {reason}"));
}

fn emit(line: String) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{line}");
    let _ = out.flush();
}
