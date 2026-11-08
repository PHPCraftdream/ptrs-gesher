//! End-to-end tests for the PT-spec §3.3.2 `TOR_PT_PROXY` contract.

use std::ffi::OsString;
use std::io;
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader, Lines};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};

static NEXT_STATE_ID: AtomicU64 = AtomicU64::new(0);

/// Own the subprocess and all handles needed to tear it down.
struct ChildGuard {
    child: Child,
    // Keep this alive while `Child::wait` runs; taking it out of `Child`
    // prevents wait from closing the parent's write end.
    _stdin: Option<ChildStdin>,
    stdout: Option<Lines<BufReader<ChildStdout>>>,
    stderr: Option<tokio::process::ChildStderr>,
}

impl ChildGuard {
    fn stdout(&mut self) -> Lines<BufReader<ChildStdout>> {
        self.stdout.take().expect("piped stdout")
    }

    fn stderr(&mut self) -> tokio::process::ChildStderr {
        self.stderr.take().expect("piped stderr")
    }

    async fn kill_and_wait(&mut self) -> std::process::ExitStatus {
        let _ = self.child.kill().await;
        self.child.wait().await.expect("wait for killed lyrebird")
    }
}

fn spawn_pt(proxy: Option<OsString>) -> ChildGuard {
    spawn_pt_with(proxy, |_| {})
}

/// Like [`spawn_pt`], with a hook to break the parent environment further.
fn spawn_pt_with(proxy: Option<OsString>, customize: impl FnOnce(&mut Command)) -> ChildGuard {
    let state_id = NEXT_STATE_ID.fetch_add(1, Ordering::Relaxed);
    let statedir = std::env::temp_dir().join(format!(
        "lyrebird-proxy-error-test-{}-{state_id}",
        std::process::id()
    ));

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_lyrebird"));
    cmd.arg("--log-level")
        .arg("ERROR")
        .env("TOR_PT_STATE_LOCATION", statedir)
        .env("TOR_PT_MANAGED_TRANSPORT_VER", "1")
        .env("TOR_PT_CLIENT_TRANSPORTS", "obfs4")
        .env_remove("TOR_PT_PROXY")
        .env_remove("TOR_PT_SERVER_TRANSPORTS")
        // Keep stdin open: proxy rejection must still terminate while the
        // lifecycle watcher is enabled.
        .env("TOR_PT_EXIT_ON_STDIN_CLOSE", "1")
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .kill_on_drop(true);
    if let Some(proxy) = proxy {
        cmd.env("TOR_PT_PROXY", proxy);
    }
    customize(&mut cmd);

    let mut child = cmd.spawn().expect("spawn lyrebird binary");
    let stdin = child.stdin.take();
    let stdout = child
        .stdout
        .take()
        .map(|stdout| BufReader::new(stdout).lines());
    let stderr = child.stderr.take();
    ChildGuard {
        child,
        _stdin: stdin,
        stdout,
        stderr,
    }
}

async fn read_stdout(mut reader: Lines<BufReader<ChildStdout>>) -> io::Result<Vec<String>> {
    let mut lines = Vec::new();
    while let Some(line) = reader.next_line().await? {
        lines.push(line);
    }
    Ok(lines)
}

async fn read_stderr(mut reader: tokio::process::ChildStderr) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).await?;
    Ok(bytes)
}

async fn next_line(reader: &mut Lines<BufReader<ChildStdout>>, what: &str) -> String {
    tokio::time::timeout(Duration::from_secs(5), reader.next_line())
        .await
        .unwrap_or_else(|e| panic!("expected {what} on the control channel: {e}"))
        .unwrap_or_else(|e| panic!("reading {what} from the control channel: {e}"))
        .unwrap_or_else(|| panic!("control channel closed before {what}"))
}

fn assert_no_proxy_data(text: &str, proxy_data: &[&str]) {
    assert!(text.is_ascii(), "control output must be ASCII: {text:?}");
    assert!(!text.contains('\r') && !text.contains('\n'));
    for secret in proxy_data {
        assert!(!text.contains(secret), "proxy data leaked in {text:?}");
    }
}

fn assert_stderr_no_proxy_data(bytes: &[u8], proxy_data: &[&str]) {
    let text = String::from_utf8_lossy(bytes);
    assert!(!text.contains('\r'));
    for secret in proxy_data {
        assert!(
            !text.contains(secret),
            "proxy data leaked in stderr: {text:?}"
        );
    }
}

async fn assert_rejected(process: &mut ChildGuard, proxy_data: &[&str]) {
    let stdout = process.stdout();
    let stderr = process.stderr();
    let joined = tokio::time::timeout(Duration::from_secs(5), async {
        let status = process.child.wait();
        let stdout = read_stdout(stdout);
        let stderr = read_stderr(stderr);
        tokio::join!(status, stdout, stderr)
    })
    .await
    .expect("proxy rejection must terminate while stdin remains open");

    let status = joined.0.expect("wait for proxy rejection");
    assert!(
        !status.success(),
        "proxy rejection must return an error status"
    );
    let stdout = joined.1.expect("read proxy control channel");
    assert_eq!(
        stdout,
        [
            "VERSION 1".to_string(),
            "PROXY-ERROR invalid or unsupported upstream proxy".to_string(),
        ]
    );
    assert_no_proxy_data(&stdout[1], proxy_data);
    let stderr = joined.2.expect("read proxy stderr");
    assert_stderr_no_proxy_data(&stderr, proxy_data);
}

async fn assert_transport_configured(process: &mut ChildGuard) {
    assert_transport_configured_with_proxy(process, false, &[]).await;
}

async fn assert_transport_configured_with_proxy(
    process: &mut ChildGuard,
    expect_proxy: bool,
    proxy_data: &[&str],
) {
    let mut stdout = process.stdout();
    assert_eq!(next_line(&mut stdout, "VERSION").await, "VERSION 1");
    if expect_proxy {
        let acknowledgement = next_line(&mut stdout, "PROXY DONE").await;
        assert_eq!(acknowledgement, "PROXY DONE");
        assert_no_proxy_data(&acknowledgement, proxy_data);
    }
    let cmethod = next_line(&mut stdout, "CMETHOD obfs4").await;
    assert!(cmethod.starts_with("CMETHOD obfs4 socks5 127.0.0.1:"));
    assert_eq!(
        next_line(&mut stdout, "CMETHODS DONE").await,
        "CMETHODS DONE"
    );
    let extra = tokio::time::timeout(Duration::from_secs(1), stdout.next_line()).await;
    if extra.is_ok() {
        let stderr = read_stderr(process.stderr()).await.expect("startup stderr");
        panic!(
            "unexpected extra control output: {extra:?}; stderr: {}",
            String::from_utf8_lossy(&stderr)
        );
    }

    let status = process.kill_and_wait().await;
    assert!(!status.success(), "test cleanup must terminate the PT");
    let stderr = read_stderr(process.stderr())
        .await
        .expect("read cleanup stderr");
    assert_stderr_no_proxy_data(&stderr, proxy_data);
}

#[tokio::test(flavor = "multi_thread")]
async fn configured_proxy_is_acknowledged_without_disclosing_credentials_or_host() {
    let mut process = spawn_pt(Some(OsString::from(
        "socks5://acct_copper:pw_quartz@198.51.100.10:19050",
    )));
    // Control-plane acknowledgement only; carrier routing is checked separately.
    assert_transport_configured_with_proxy(
        &mut process,
        true,
        &["acct_copper", "pw_quartz", "198.51.100.10", "19050"],
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn without_proxy_transports_are_still_configured() {
    let mut process = spawn_pt(None);
    assert_transport_configured(&mut process).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn empty_proxy_is_treated_as_unset() {
    let mut process = spawn_pt(Some(OsString::new()));
    assert_transport_configured(&mut process).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn malformed_proxy_is_rejected_without_control_channel_injection() {
    let mut process = spawn_pt(Some(OsString::from(
        "socks5://acct_copper:pw_quartz@host:9\nINJECTED",
    )));
    assert_rejected(
        &mut process,
        &["socks5", "acct_copper", "pw_quartz", "host", "INJECTED"],
    )
    .await;
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn non_unicode_proxy_is_rejected_without_echoing_bytes() {
    use std::os::unix::ffi::OsStringExt;

    let proxy = OsString::from_vec(b"socks5://user:secret@bad.example:9050\xff\nINJECTED".to_vec());
    let mut process = spawn_pt(Some(proxy));
    assert_rejected(
        &mut process,
        &[
            "socks5",
            "user",
            "secret",
            "bad.example",
            "9050",
            "INJECTED",
        ],
    )
    .await;
}

/// The PT must exit with an error status after exactly these control lines.
async fn assert_control_failure(process: &mut ChildGuard, expected: &[&str]) {
    let stdout = process.stdout();
    let stderr = process.stderr();
    let joined = tokio::time::timeout(Duration::from_secs(5), async {
        let status = process.child.wait();
        let stdout = read_stdout(stdout);
        let stderr = read_stderr(stderr);
        tokio::join!(status, stdout, stderr)
    })
    .await
    .expect("a bad launch must terminate while stdin remains open");
    assert!(
        !joined.0.expect("wait for the PT").success(),
        "a bad launch must return an error status"
    );
    let lines = joined.1.expect("read control channel");
    assert_eq!(lines, expected);
}

#[tokio::test(flavor = "multi_thread")]
async fn version_mismatch_is_reported_as_version_error() {
    for offered in ["2", "2,3", "", "1x", "v1"] {
        let mut process = spawn_pt_with(None, |cmd| {
            cmd.env("TOR_PT_MANAGED_TRANSPORT_VER", offered);
        });
        // No `VERSION 1` may precede the error: nothing was negotiated.
        assert_control_failure(&mut process, &["VERSION-ERROR no-version"]).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn version_list_containing_one_is_accepted() {
    let mut process = spawn_pt_with(None, |cmd| {
        cmd.env("TOR_PT_MANAGED_TRANSPORT_VER", "2,1");
    });
    assert_transport_configured(&mut process).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn missing_version_variable_is_reported_as_env_error() {
    let mut process = spawn_pt_with(None, |cmd| {
        cmd.env_remove("TOR_PT_MANAGED_TRANSPORT_VER");
    });
    assert_control_failure(
        &mut process,
        &["ENV-ERROR TOR_PT_MANAGED_TRANSPORT_VER is not set"],
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn conflicting_or_missing_transport_variables_are_env_errors() {
    let mut both = spawn_pt_with(None, |cmd| {
        cmd.env("TOR_PT_SERVER_TRANSPORTS", "obfs4");
    });
    assert_control_failure(
        &mut both,
        &[
            "VERSION 1",
            "ENV-ERROR TOR_PT_CLIENT_TRANSPORTS and TOR_PT_SERVER_TRANSPORTS both set",
        ],
    )
    .await;

    let mut neither = spawn_pt_with(None, |cmd| {
        cmd.env_remove("TOR_PT_CLIENT_TRANSPORTS");
    });
    assert_control_failure(
        &mut neither,
        &["VERSION 1", "ENV-ERROR not launched as a managed transport"],
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn missing_state_location_is_reported_as_env_error() {
    let mut process = spawn_pt_with(None, |cmd| {
        cmd.env_remove("TOR_PT_STATE_LOCATION");
    });
    assert_control_failure(
        &mut process,
        &["ENV-ERROR TOR_PT_STATE_LOCATION is not set"],
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn set_but_unusable_state_location_is_reported_without_echoing_it() {
    // A regular file cannot be a state directory.
    let file = std::env::temp_dir().join(format!(
        "lyrebird-state-is-a-file-{}-secret-path",
        std::process::id()
    ));
    std::fs::write(&file, b"not a directory").expect("create blocker file");
    let blocker = file.clone().into_os_string();
    let mut process = spawn_pt_with(None, |cmd| {
        cmd.env("TOR_PT_STATE_LOCATION", blocker);
    });
    assert_control_failure(
        &mut process,
        &["ENV-ERROR TOR_PT_STATE_LOCATION is unusable"],
    )
    .await;
    let _ = std::fs::remove_file(&file);

    let mut empty = spawn_pt_with(None, |cmd| {
        cmd.env("TOR_PT_STATE_LOCATION", "");
    });
    assert_control_failure(&mut empty, &["ENV-ERROR TOR_PT_STATE_LOCATION is unusable"]).await;
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn non_unicode_transports_are_reported_without_echoing_bytes() {
    use std::os::unix::ffi::OsStringExt;

    let mut process = spawn_pt_with(None, |cmd| {
        cmd.env(
            "TOR_PT_CLIENT_TRANSPORTS",
            OsString::from_vec(b"obfs4\xffSECRET".to_vec()),
        );
    });
    assert_control_failure(
        &mut process,
        &[
            "VERSION 1",
            "ENV-ERROR TOR_PT_CLIENT_TRANSPORTS is not valid unicode",
        ],
    )
    .await;
}
