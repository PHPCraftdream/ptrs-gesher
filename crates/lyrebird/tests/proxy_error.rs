//! End-to-end control-channel tests for the PT-spec §3.3.2 upstream-proxy
//! (`TOR_PT_PROXY`) contract: the real `lyrebird` binary must answer a
//! configured `TOR_PT_PROXY` with `PROXY-ERROR` and terminate BEFORE any
//! `CMETHOD*` line or transport initialization, and must never claim
//! `PROXY DONE` — there is no upstream proxy dialer, so continuing would
//! mean silently dialing the bridge directly and bypassing the configured
//! route.

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError};
use std::time::Duration;

/// Kill the child on drop so a failing assertion cannot leak a running PT
/// process (with live listeners) past the test.
struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Spawn the lyrebird binary as a managed PT client with the given extra
/// `TOR_PT_*` environment, forwarding each line of its stdout (the PT
/// control channel) to the returned receiver.
fn spawn_pt(extra_env: &[(&str, &str)]) -> (ChildGuard, Receiver<String>) {
    let thread_id = std::thread::current()
        .name()
        .unwrap_or("t")
        .replace([' ', '/'], "_");
    let statedir = std::env::temp_dir().join(format!(
        "lyrebird-proxy-error-test-{}-{thread_id}",
        std::process::id()
    ));

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_lyrebird"));
    cmd.arg("--log-level")
        .arg("ERROR")
        .env("TOR_PT_STATE_LOCATION", statedir)
        .env("TOR_PT_MANAGED_TRANSPORT_VER", "1")
        .env("TOR_PT_CLIENT_TRANSPORTS", "obfs4")
        // Scrub anything the surrounding environment might set that could
        // change the protocol flow under test.
        .env_remove("TOR_PT_PROXY")
        .env_remove("TOR_PT_SERVER_TRANSPORTS")
        .env_remove("TOR_PT_EXIT_ON_STDIN_CLOSE")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .stdout(Stdio::piped());
    for (key, value) in extra_env {
        cmd.env(key, value);
    }

    let mut child = cmd.spawn().expect("spawn lyrebird binary");
    let stdout = child.stdout.take().expect("piped stdout");
    let (tx, rx) = channel();
    std::thread::spawn(move || {
        let reader = BufReader::new(stdout);
        for line in reader.lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    (ChildGuard(child), rx)
}

/// Receive the next control-channel line, failing with context on timeout
/// or premature EOF.
fn next_line(rx: &Receiver<String>, what: &str) -> String {
    rx.recv_timeout(Duration::from_secs(30))
        .unwrap_or_else(|e| panic!("expected {what} on the control channel: {e:?}"))
}

#[test]
fn configured_proxy_is_rejected_with_proxy_error_before_transports() {
    let (_child, rx) = spawn_pt(&[("TOR_PT_PROXY", "socks5://user:pass@127.0.0.1:9050")]);

    // Spec order (§3.3.1/§3.3.2 and Appendix A): VERSION first, then the
    // upstream-proxy verdict, and nothing else.
    assert_eq!(next_line(&rx, "VERSION"), "VERSION 1");
    let proxy_line = next_line(&rx, "PROXY-ERROR");
    assert!(
        proxy_line.starts_with("PROXY-ERROR "),
        "a configured TOR_PT_PROXY must be answered with PROXY-ERROR, got: {proxy_line}"
    );
    assert!(
        proxy_line.contains("127.0.0.1:9050"),
        "the PROXY-ERROR reason must name the refused proxy URI, got: {proxy_line}"
    );

    // "PT proxies MUST terminate immediately after outputting a
    // PROXY-ERROR message" (§3.3.2): stdout reaches EOF with no further
    // lines — in particular no CMETHOD / CMETHODS DONE, so no transport
    // was ever initialized and no direct bridge dial can happen.
    let after = rx.recv_timeout(Duration::from_secs(30));
    assert!(
        matches!(after, Err(RecvTimeoutError::Disconnected)),
        "the PT must terminate right after PROXY-ERROR; got {after:?}"
    );
}

#[test]
fn without_proxy_transports_are_still_configured() {
    let (mut child, rx) = spawn_pt(&[]);

    // Without TOR_PT_PROXY the fail-closed path must not trigger: the
    // normal obfs4 setup flow (VERSION -> CMETHOD -> CMETHODS DONE) runs.
    assert_eq!(next_line(&rx, "VERSION"), "VERSION 1");
    let cmethod = next_line(&rx, "CMETHOD obfs4");
    assert!(
        cmethod.starts_with("CMETHOD obfs4 socks5 127.0.0.1:"),
        "obfs4 must still be offered without TOR_PT_PROXY, got: {cmethod}"
    );
    assert_eq!(next_line(&rx, "CMETHODS DONE"), "CMETHODS DONE");

    // No PROXY line at all may appear without TOR_PT_PROXY.
    let extra = rx.recv_timeout(Duration::from_secs(1));
    assert!(
        matches!(extra, Err(RecvTimeoutError::Timeout)),
        "unexpected extra control-channel output without TOR_PT_PROXY: {extra:?}"
    );

    // And the PT keeps serving: the transport is up, not exited.
    std::thread::sleep(Duration::from_millis(500));
    assert!(
        matches!(child.0.try_wait(), Ok(None)),
        "without TOR_PT_PROXY the PT must stay up serving the transport"
    );
}

#[test]
fn malformed_proxy_is_rejected_with_proxy_error_before_transports() {
    let (_child, rx) = spawn_pt(&[("TOR_PT_PROXY", "not a proxy uri at all")]);

    // Even a TOR_PT_PROXY the URI parser would reject must get the
    // control-channel verdict: a bare process exit would leave the parent
    // without an attributable reason (and is exactly the regression this
    // guards against, since the verdict is produced before the core
    // reader ever validates the value).
    assert_eq!(next_line(&rx, "VERSION"), "VERSION 1");
    let proxy_line = next_line(&rx, "PROXY-ERROR");
    assert!(
        proxy_line.starts_with("PROXY-ERROR "),
        "a malformed TOR_PT_PROXY must also be answered with PROXY-ERROR, got: {proxy_line}"
    );

    // Same §3.3.2 termination rule: EOF right after the verdict, with no
    // CMETHOD* lines (no transport was initialized, so no direct bridge
    // dial is possible).
    let after = rx.recv_timeout(Duration::from_secs(30));
    assert!(
        matches!(after, Err(RecvTimeoutError::Disconnected)),
        "the PT must terminate right after PROXY-ERROR; got {after:?}"
    );
}
