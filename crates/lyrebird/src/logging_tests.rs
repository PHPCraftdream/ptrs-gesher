use super::*;

use std::{
    ffi::OsString,
    io::{self, Write},
    sync::{Arc, Mutex},
};

static LOGGING_TEST_LOCK: Mutex<()> = Mutex::new(());

#[derive(Clone)]
struct CaptureWriter(Arc<Mutex<Vec<u8>>>);

impl Write for CaptureWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .expect("capture lock")
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn capture_events(filter: tracing_subscriber::EnvFilter, emit: impl FnOnce()) -> String {
    let output = Arc::new(Mutex::new(Vec::new()));
    let writer_output = Arc::clone(&output);
    let subscriber = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_writer(move || CaptureWriter(Arc::clone(&writer_output)))
            .with_filter(filter),
    );
    tracing::subscriber::with_default(subscriber, emit);
    let bytes = output.lock().expect("capture lock").clone();
    String::from_utf8(bytes).expect("UTF-8 logs")
}

struct RustLogGuard(Option<OsString>);

impl RustLogGuard {
    fn set(value: Option<&str>) -> Self {
        let previous = std::env::var_os("RUST_LOG");
        match value {
            Some(value) => std::env::set_var("RUST_LOG", value),
            None => std::env::remove_var("RUST_LOG"),
        }
        Self(previous)
    }
}

impl Drop for RustLogGuard {
    fn drop(&mut self) {
        match self.0.take() {
            Some(value) => std::env::set_var("RUST_LOG", value),
            None => std::env::remove_var("RUST_LOG"),
        }
    }
}

#[test]
fn logging_filters_levels_targets_and_rust_log_override() {
    let _lock = LOGGING_TEST_LOCK.lock().expect("logging test lock");
    let default_env = RustLogGuard::set(None);
    let error_output = capture_events(default_log_filter(Level::ERROR), || {
        tracing::error!(target: "ordinary", "error-visible");
        tracing::warn!(target: "ordinary", "warn-hidden");
        tracing::info!(target: "fast_socks5", "info-hidden");
    });
    assert!(error_output.contains("error-visible"));
    assert!(!error_output.contains("warn-hidden"));
    assert!(!error_output.contains("info-hidden"));

    let debug_output = capture_events(default_log_filter(Level::DEBUG), || {
        tracing::debug!(target: "ordinary", "debug-visible");
        tracing::info!(target: "fast_socks5", "info-visible");
    });
    assert!(debug_output.contains("debug-visible"));
    assert!(debug_output.contains("info-visible"));

    drop(default_env);
    let _override_env = RustLogGuard::set(Some("error,fast_socks5=debug"));
    let override_output = capture_events(default_log_filter(Level::ERROR), || {
        tracing::debug!(target: "fast_socks5", "target-override-visible");
        tracing::debug!(target: "ordinary", "ordinary-debug-hidden");
    });
    assert!(override_output.contains("target-override-visible"));
    assert!(!override_output.contains("ordinary-debug-hidden"));
}

#[test]
fn logging_guard_preserves_host_and_does_not_truncate_file() {
    let _lock = LOGGING_TEST_LOCK.lock().expect("logging test lock");
    assert!(!has_logging_subscriber());
    let host_output = Arc::new(Mutex::new(Vec::new()));
    let writer_output = Arc::clone(&host_output);
    let host = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_writer(move || CaptureWriter(Arc::clone(&writer_output))),
    );
    tracing::subscriber::set_global_default(host).expect("install host subscriber");

    let statedir = std::env::temp_dir().join(format!("lyrebird-logging-{}", std::process::id()));
    std::fs::create_dir_all(&statedir).expect("create logging test directory");
    let log_path = statedir.join("obfs4proxy.log");
    std::fs::write(&log_path, b"sentinel\n").expect("seed log file");

    let guard = init_logging_recvr(
        true,
        false,
        "ERROR",
        statedir.to_str().expect("state directory is UTF-8"),
    )
    .expect("host subscriber should be preserved");
    tracing::error!("host-event");
    assert_eq!(
        std::fs::read(&log_path).expect("read log file"),
        b"sentinel\n"
    );
    assert!(
        String::from_utf8(host_output.lock().expect("capture lock").clone())
            .expect("UTF-8 logs")
            .contains("host-event")
    );
    assert_eq!(format!("{}", sensitive("secret")), "secret");
    drop(guard);
    assert_eq!(format!("{}", sensitive("secret")), "[scrubbed]");

    tracing::subscriber::with_default(tracing::subscriber::NoSubscriber::default(), || {
        let guard = init_logging_recvr(false, true, "ERROR", statedir.to_str().unwrap())
            .expect("an explicitly disabled subscriber must be preserved");
        assert_eq!(format!("{}", sensitive("secret")), "[scrubbed]");
        drop(guard);
    });

    let safe_guard = safelog::enforce_safe_logging().expect("safe guard");
    let incompatible = init_logging_recvr(
        false,
        false,
        "ERROR",
        statedir.to_str().expect("state directory is UTF-8"),
    );
    assert!(incompatible.is_err(), "incompatible safelog mode must fail");
    drop(safe_guard);
    std::fs::remove_dir_all(statedir).expect("remove logging test directory");
}
