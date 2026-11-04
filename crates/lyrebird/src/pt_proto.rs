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
