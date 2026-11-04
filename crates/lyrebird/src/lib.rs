//! # Lyrebird - Pluggable Transport Proxy Applications
//!
//! This crate provides a PT-manager loop usable as a library
//! (`lyrebird::run_from_env()`) or as a standalone binary that implements the
//! Tor pluggable-transport spec on top of the [`ptrs`] interface.
//!
//! **Stability**: the public API is unstable and subject to change
//! without notice; do not rely on this crate for security-critical
//! applications. The server-side path is incomplete and gated behind
//! the `experimental-server` cargo feature — it must not be enabled in
//! production.
//!
//! ## Lyrebird Pluggable Transport Bridge
//!
//! ['lyrebird'] provides an executable program designed to manage the calling
//! interface used by the Tor libraries when launching pluggable transports (see `pt-spec.txt`).
//!
//! `... [tor_client] <---> [pt_client] <====> [pt_bridge] <---> [tor_orport] ...`
//!
//! Usage info:
//!
//! ```txt
//! Tunnel Tor SOCKS5 traffic through pluggable transport connections
//!
//! Usage: lyrebird [OPTIONS]
//!
//! Options:
//!       --enable-logging         Log to {TOR_PT_STATE_LOCATION}/obfs4proxy.log
//!       --log-level <LOG_LEVEL>  Log Level (ERROR/WARN/INFO/DEBUG/TRACE) [default: ERROR]
//!       --unsafe-logging         Disable the address scrubber on logging
//!   -h, --help                   Print help
//!   -V, --version                Print version
//! ```
//!
//! ### Installation
//!
//! To install:
//!
//! `cargo install ptrs-gesher-lyrebird`
//!
//! This installs the `lyrebird` executable in the configured Rust location
//! (i.e. `$HOME/.cargo/bin`). You may wish to copy it to a permanent location
//! (e.g. `/usr/local/bin`).
//!
//! Client side torrc configuration:
//! ```text
//! ClientTransportPlugin obfs4 exec /usr/local/bin/lyrebird
//! ```
//!
//! Bridge-side torrc configuration (experimental; incomplete and not suitable
//! for production):
//! ```text
//! # Act as a bridge relay.
//! BridgeRelay 1
//!
//! # Enable the Extended ORPort
//! ExtORPort auto
//!
//! # Use lyrebird to provide the obfs4 protocol.
//! ServerTransportPlugin obfs4 exec /usr/local/bin/lyrebird
//!
//! # (Optional) Listen on the specified address/port for obfs4 connections as
//! # opposed to picking a port automatically.
//! #ServerTransportListenAddr obfs4 0.0.0.0:443
//! ```
//!
//! ### Tips and tricks
//!
//!  * On modern Linux systems it is possible to have lyrebird bind to reserved
//!    ports (<=1024) even when not running as root by granting the
//!    `CAP_NET_BIND_SERVICE` capability with setcap:
//!
//!    `# setcap 'cap_net_bind_service=+ep' /usr/local/bin/lyrebird`
//!
//!  * obfs4 state-file paths are configured by the caller; Lyrebird does not
//!    automatically create `obfs4_state.json` or `obfs4_bridgeline.txt`.
//!
// Follow-up work tracked in the issue tracker, not in rustdoc:
//   - tunnel-level metrics (failures, byte counters).
//   - rate-limiting for the bidirectional copy.
//   - replace `tokio::io::copy_bidirectional` with an interactive copy
//     that flushes only when the reader stalls.

#![deny(missing_docs)]

use obfs4::Obfs4PT;
use ptrs::{error, info, warn, PluggableTransport};

use anyhow::{anyhow, Context, Result};
use clap::Parser;
#[path = "client/connection.rs"]
mod connection;
#[cfg(test)]
use connection::client_handle_connection;
use connection::client_handle_connection_with_proxy;
#[path = "client/proxy.rs"]
mod proxy;
use safelog::{sensitive, Guard};
#[cfg(test)]
use tokio::io::AsyncWriteExt;
use tokio::task::JoinSet;
use tokio::{
    io::{copy_bidirectional, AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream},
};
use tokio_util::sync::CancellationToken;
use tracing::Level;
use tracing_subscriber::prelude::*;

use std::{
    future::Future,
    net::SocketAddr,
    pin::Pin,
    str::FromStr,
    sync::{Arc, Mutex, OnceLock, RwLock},
};

/// Client Socks address to listen on.
const CLIENT_SOCKS_ADDR: &str = "127.0.0.1:0";

/// Maximum time allowed for the SOCKS5 method, authentication, and request
/// negotiation before a connection is discarded.
const SOCKS5_SETUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

const ACCEPT_RETRY_BASE_MS: u64 = 50;
const ACCEPT_RETRY_MAX_MS: u64 = 1_000;

fn is_transient_accept_error(error: &std::io::Error) -> bool {
    if matches!(
        error.kind(),
        std::io::ErrorKind::Interrupted
            | std::io::ErrorKind::WouldBlock
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::TimedOut
    ) {
        return true;
    }

    match error.raw_os_error() {
        #[cfg(unix)]
        Some(code) => matches!(
            code,
            libc::EAGAIN
                | libc::EINTR
                | libc::ECONNABORTED
                | libc::ECONNRESET
                | libc::EMFILE
                | libc::ENFILE
                | libc::ENOBUFS
                | libc::ENOMEM
        ),
        // WSAEINTR, WSAEMFILE, WSAEWOULDBLOCK, WSAECONNABORTED,
        // WSAECONNRESET, WSAENOBUFS.
        #[cfg(windows)]
        Some(code) => matches!(code, 10004 | 10024 | 10035 | 10053 | 10054 | 10055),
        #[cfg(not(any(unix, windows)))]
        Some(_) => false,
        None => false,
    }
}

fn accept_retry_delay(consecutive_failures: u32) -> std::time::Duration {
    let factor = 1_u64 << consecutive_failures.min(5);
    std::time::Duration::from_millis(
        ACCEPT_RETRY_BASE_MS
            .saturating_mul(factor)
            .min(ACCEPT_RETRY_MAX_MS),
    )
}

#[derive(Parser)]
#[command(author, version, long_about = None, about="Tunnel Tor SOCKS5 traffic through pluggable transport connections")]
struct Args {
    /// Log to {TOR_PT_STATE_LOCATION}/obfs4proxy.log
    #[arg(long, default_value_t = false)]
    enable_logging: bool,

    /// Log Level (ERROR/WARN/INFO/DEBUG/TRACE)
    #[arg(long, default_value_t=String::from("ERROR"))]
    log_level: String,

    /// Disable the address scrubber on logging
    #[arg(long, default_value_t = false)]
    unsafe_logging: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum LoggingMode {
    Safe,
    Unsafe,
}

struct OwnedSubscriber {
    inner: Arc<RwLock<LogConfig>>,
    callsites: Arc<Mutex<Vec<&'static tracing::Metadata<'static>>>>,
}

struct LoggingState {
    subscriber: Option<OwnedSubscriber>,
    active_guards: usize,
    mode: Option<LoggingMode>,
}

static LOGGING_STATE: OnceLock<Mutex<LoggingState>> = OnceLock::new();

fn logging_state() -> &'static Mutex<LoggingState> {
    LOGGING_STATE.get_or_init(|| {
        Mutex::new(LoggingState {
            subscriber: None,
            active_guards: 0,
            mode: None,
        })
    })
}

struct LoggingGuard {
    guard: Option<Guard>,
}

impl Drop for LoggingGuard {
    fn drop(&mut self) {
        self.guard.take();
        if let Ok(mut state) = logging_state().lock() {
            state.active_guards = state.active_guards.saturating_sub(1);
            if state.active_guards == 0 {
                state.mode = None;
            }
        }
    }
}

/// initialize the logging receiver(s) for things to be logged into using the
/// tracing / tracing_subscriber libraries
// TODO: GeoIP. Json for file log writer.
fn init_logging_recvr(
    enable: bool,
    should_scrub: bool,
    level_str: &str,
    statedir: &str,
) -> Result<LoggingGuard> {
    // The PT protocol owns stdout for the parent ↔ PT control channel.
    // Logs go to stderr; the file layer below (when enabled) writes
    // separately into the state directory.
    //
    // Compact (single-line) layout matches the parent process's
    // tracing-subscriber default — we share a terminal with it when
    // launched via the busybox dispatch, so consistent formatting
    // matters more than the pretty multi-line output.
    let level = Level::from_str(level_str).context("invalid log level")?;
    let mode = if should_scrub {
        LoggingMode::Safe
    } else {
        LoggingMode::Unsafe
    };
    let safelog_guard = if should_scrub {
        safelog::enforce_safe_logging().context("enabling safe logging")?
    } else {
        safelog::disable_safe_logging().context("disabling safe logging")?
    };
    let state = logging_state()
        .lock()
        .map_err(|_| anyhow!("logging state lock poisoned"))?;
    if state.active_guards > 0 && state.mode != Some(mode) {
        drop(safelog_guard);
        return Err(anyhow!(
            "cannot change safelog policy while a run is active"
        ));
    }
    drop(state);
    if foreign_subscriber_installed() {
        let mut state = logging_state()
            .lock()
            .map_err(|_| anyhow!("logging state lock poisoned"))?;
        state.active_guards += 1;
        state.mode = Some(mode);
        drop(state);
        return Ok(LoggingGuard {
            guard: Some(safelog_guard),
        });
    }
    let mut state = logging_state()
        .lock()
        .map_err(|_| anyhow!("logging state lock poisoned"))?;
    let filter = default_log_filter(level);
    // Honor the https://no-color.org convention: any (even empty) NO_COLOR
    // disables ANSI. We're normally launched as a PT child by the parent
    // process's busybox dispatch and inherit its environment, so the parent
    // can propagate its own color preference by setting NO_COLOR before
    // spawning us — without that, this layer defaulted to ANSI-always-on
    // regardless of the parent's own logging config.
    let ansi = std::env::var_os("NO_COLOR").is_none();
    let console_layer = tracing_subscriber::fmt::layer()
        .with_ansi(ansi)
        .with_writer(std::io::stderr);

    let log_layers = if enable {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(format!("{statedir}/obfs4proxy.log"))?;

        let state_dir_layer = tracing_subscriber::fmt::layer().with_writer(file);

        LogConfig {
            filter: Arc::new(filter),
            sink: Arc::new(console_layer.and_then(state_dir_layer).boxed()),
        }
    } else {
        LogConfig {
            filter: Arc::new(filter),
            sink: Arc::new(console_layer.boxed()),
        }
    };

    if let Some(owned) = &state.subscriber {
        let callsites = owned
            .callsites
            .lock()
            .map_err(|_| anyhow!("logging callsite lock poisoned"))?;
        for metadata in callsites.iter() {
            let _ = <tracing_subscriber::EnvFilter as tracing_subscriber::Layer<
                tracing_subscriber::Registry,
            >>::register_callsite(&*log_layers.filter, metadata);
        }
        match owned.inner.write() {
            Ok(mut current) => *current = log_layers,
            Err(_) => {
                drop(safelog_guard);
                return Err(anyhow!("reloading logging configuration: lock poisoned"));
            }
        }
        drop(callsites);
    } else {
        let inner = Arc::new(RwLock::new(log_layers));
        let subscriber = OwnedDispatcher::new(Arc::clone(&inner));
        let callsites = Arc::clone(&subscriber.callsites);
        if let Err(error) = tracing::subscriber::set_global_default(subscriber) {
            tracing::debug!("preserving process-owned logging: {error}");
        } else {
            state.subscriber = Some(OwnedSubscriber { inner, callsites });
            let _ = tracing_log::LogTracer::builder()
                .with_max_level(log::LevelFilter::Trace)
                .init();
        }
    }
    state.active_guards += 1;
    state.mode = Some(mode);
    drop(state);
    Ok(LoggingGuard {
        guard: Some(safelog_guard),
    })
}

#[cfg(test)]
fn has_logging_subscriber() -> bool {
    logging_state()
        .lock()
        .map(|state| state.subscriber.is_some())
        .unwrap_or(false)
}

fn foreign_subscriber_installed() -> bool {
    let owned_inner = logging_state().lock().ok().and_then(|state| {
        state
            .subscriber
            .as_ref()
            .map(|owned| Arc::clone(&owned.inner))
    });
    let own_is_active = owned_inner.is_some();
    tracing::dispatcher::get_default(|dispatch| {
        if dispatch.is::<OwnedDispatcher>() {
            if let Some(owned) = dispatch.downcast_ref::<OwnedDispatcher>() {
                return owned_inner
                    .as_ref()
                    .is_none_or(|inner| !Arc::ptr_eq(inner, &owned.inner));
            }
        }
        if own_is_active {
            return true;
        }
        !dispatch.is::<tracing::subscriber::NoSubscriber>()
    })
}

fn default_log_filter(level: Level) -> tracing_subscriber::EnvFilter {
    default_log_filter_from_env(level, std::env::var_os("RUST_LOG").as_deref())
}

fn default_log_filter_from_env(
    level: Level,
    rust_log: Option<&std::ffi::OsStr>,
) -> tracing_subscriber::EnvFilter {
    rust_log
        .and_then(|value| value.to_str())
        .and_then(|value| tracing_subscriber::EnvFilter::try_new(value).ok())
        .unwrap_or_else(|| tracing_subscriber::EnvFilter::new(default_filter_directives(level)))
}

fn default_filter_directives(level: Level) -> String {
    level.to_string()
}

/// Parse an IP-literal target without performing DNS resolution.
/// Hostnames are rejected: resolving bridge targets is the Tor client's responsibility.
pub fn resolve_target_addr(addr: impl std::fmt::Display) -> Result<SocketAddr> {
    ptrs::resolve_addr(addr.to_string()).context("PT target must be an IP address")
}

/// Dial a bridge's OR-port and apply socket options that keep the obfs4
/// carrier connection healthy:
///   * `TCP_NODELAY` — obfs4 frames are small and latency-sensitive; Nagle
///     coalescing only hurts.
///   * TCP keepalive — an obfs4 carrier can sit briefly idle (e.g. while a
///     one-hop directory circuit for a bridge descriptor is being built).
///     Without keepalive such an idle carrier is liable to be silently reaped
///     by the OS, a NAT, or a local LSP/proxy shim, surfacing as os error
///     10053 ("connection aborted by the software in your host machine") and
///     tearing the bridge channel down mid-bootstrap. C-tor keeps its single
///     bridge connection alive at the Tor layer; we make the carrier itself
///     resilient instead.
async fn dial_bridge(remote_addr: SocketAddr) -> std::io::Result<TcpStream> {
    let stream = TcpStream::connect(remote_addr).await?;
    // Best-effort: failure to set an option must not abort the dial.
    let _ = stream.set_nodelay(true);
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(std::time::Duration::from_secs(15))
        .with_interval(std::time::Duration::from_secs(15));
    let _ = socket2::SockRef::from(&stream).set_tcp_keepalive(&keepalive);
    Ok(stream)
}

/// Run the lyrebird pluggable transport. Expects the standard
/// `TOR_PT_*` environment variables set by the parent process (arti /
/// tor) and speaks the PT-managed-transport protocol on stdin/stdout.
///
/// # Upstream proxies
///
/// `TOR_PT_PROXY` supports SOCKS5 or HTTP CONNECT IP endpoints with optional credentials.
/// Invalid or unsupported configurations fail before any transport starts.
/// When configured, every carrier uses that proxy; dialing errors never fall back.
///
/// # Shutdown semantics
///
/// In the client path, `run()` owns the accept loops and every
/// per-connection task, and does not return while any of them is still alive
/// in the ambient runtime. The incomplete `experimental-server` path remains
/// separately gated and retains its legacy task ownership while it is enabled
/// for development only:
///
/// * terminate (`SIGTERM` / Ctrl+Break) or parent EOF
///   (`TOR_PT_EXIT_ON_STDIN_CLOSE=1`): in-flight connections are
///   cancelled immediately and awaited, bounded by a short internal grace
///   period.
/// * interrupt (`SIGINT` / Ctrl+C): accepting stops first, then in-flight
///   connections get a grace period to finish on their own; whatever is
///   still alive after the budget is cancelled and awaited. A second
///   interrupt or a parent EOF during the drain escalates to the
///   immediate teardown.
/// * all listeners ended on their own ("proxy closed"): handled like an
///   interrupt, so tunnel tasks are never left behind.
/// * a declared transport is lost — a listener accept loop ends with a
///   fatal (non-transient) accept error or its task panics: the
///   remaining listeners and in-flight connections are shut down as in
///   the "proxy closed" case, and `run()` then returns `Err` carrying
///   the original cause. A lost transport is never restored in-process:
///   client listeners bind ephemeral ports already announced to the
///   parent via `CMETHOD`, and the PT spec provides no
///   re-announcement, so failing loudly lets the parent restart the
///   transport with a fresh setup.
///
/// When stdin monitoring is enabled, this call requires exclusive access to
/// stdin until it returns.
///
/// An existing tracing subscriber is preserved. CLI logging filters apply
/// only when this call installs its own subscriber; the safelog guard remains
/// active until shutdown completes.
///
/// # Cancel safety
///
/// This function is **not cancel-safe**. It manages long-lived server
/// state and open connections. The guarantees above hold only when the
/// future is driven to completion; dropping it abandons all active
/// tunnels without any shutdown.
pub async fn run() -> Result<()> {
    let args = Args::parse();

    // Make state directory
    let statedir = ptrs::make_state_dir()?;

    // launch tracing subscriber with filter level
    let _logging_guard = init_logging_recvr(
        args.enable_logging,
        !args.unsafe_logging,
        &args.log_level,
        &statedir,
    )?;

    run_managed(&statedir).await
}

/// Run the managed PT loop using `TOR_PT_*` environment variables.
///
/// This entry point does not parse process arguments or initialize logging.
/// The embedding application owns its tracing subscriber and safelog policy.
/// Shutdown and exclusive stdin requirements are the same as for [`run`].
///
/// # Cancel safety
///
/// Not cancel-safe: drive the future to completion to join owned tasks.
pub async fn run_from_env() -> Result<()> {
    let statedir = ptrs::make_state_dir()?;
    run_managed(&statedir).await
}

async fn run_managed(statedir: &str) -> Result<()> {
    // Everything this run() invocation owns hangs off `ctx`: the shutdown
    // tokens for the two teardown phases and the lifecycle permit pool
    // every connection task holds a permit from.
    let owner = RunOwner::new();
    let ctx = owner.tasks();

    // PT-spec §3.4 ("Feature #15435"): when the parent process sets
    // `TOR_PT_EXIT_ON_STDIN_CLOSE=1` it signals "stop" by closing our
    // stdin — that's the canonical managed-PT shutdown path arti's
    // ptmgr uses when a transport is removed/reconfigured. Watch stdin
    // in the background and fire shutdown on EOF so the main loop below can
    // exit promptly. The env var remains opt-in: otherwise this future is
    // permanently pending and stdin is ignored.
    // Keep stdin watching as a directly owned future. This avoids a
    // detached blocking task on setup errors and keeps EOF observable during
    // graceful drain.
    let stdin_enabled = ptrs::pt_should_exit_on_stdin_close();
    let stdin_wait = async move {
        if stdin_enabled {
            stdin_watch::wait_stdin_close().await
        } else {
            std::future::pending::<std::io::Result<()>>().await
        }
    };
    let setup = setup_listeners(statedir, ctx.clone());
    lifecycle::run_with_setup(ctx, stdin_wait, setup, lifecycle::shutdown_signal).await
}

async fn setup_listeners(statedir: &str, ctx: RunTasks) -> Result<JoinSet<Result<()>>> {
    if ptrs::is_client()? {
        client_setup(statedir, ctx).await
    } else {
        #[cfg(feature = "experimental-server")]
        {
            // This path is intentionally legacy and incomplete; the public
            // lifecycle ownership guarantee is for the client path only.
            let rx = server_setup(statedir, ctx.accept.clone()).await?;
            let mut set = JoinSet::new();
            set.spawn(async move {
                rx.await
                    .map_err(|e| anyhow!("server exit channel closed: {e}"))?;
                Ok(())
            });
            Ok(set)
        }
        #[cfg(not(feature = "experimental-server"))]
        {
            Err(anyhow!(
                "lyrebird server-side is not implemented; rebuild with \
                 `--features experimental-server` for development use only"
            ))
        }
    }
}

// ================================================================ //
//                            Client                                //
// ================================================================ //

async fn client_setup(_statedir: &str, ctx: RunTasks) -> Result<JoinSet<Result<()>>> {
    let obfs4_name = Obfs4PT::name();
    let webtunnel_name = webtunnel::WEBTUNNEL_NAME.to_string();

    // PT spec §3.3.1: announce our protocol version to the parent before
    // anything else the parent parses on the control channel.
    pt_proto::print_version();

    // PT-spec section 3.3.2: refuse unsupported proxy configurations before binding.
    let proxy = match proxy::Proxy::from_env() {
        Ok(proxy) => proxy,
        Err(()) => {
            pt_proto::print_proxy_error("invalid or unsupported upstream proxy");
            return Err(anyhow!("invalid or unsupported upstream proxy"));
        }
    };
    let methods = if proxy.is_none() {
        ptrs::ClientInfo::new()?.methods
    } else {
        // Core's legacy reader rejects proxies; retain its version/method validation.
        let versions = std::env::var(ptrs::constants::MANAGED_VER)?;
        if !versions.split(',').any(|version| version == "1") {
            return Err(anyhow!("unsupported managed transport version"));
        }
        std::env::var(ptrs::constants::CLIENT_TRANSPORTS)?
            .split(',')
            .map(str::to_owned)
            .collect::<Vec<_>>()
    };
    if proxy.is_some() {
        pt_proto::print_proxy_done();
    }

    // Build all accept futures before spawning any of them. If a later bind
    // or local-address lookup fails, no earlier listener task needs cleanup.
    type AcceptTask = Pin<Box<dyn Future<Output = Result<()>> + Send + 'static>>;
    let mut accept_tasks: Vec<AcceptTask> = Vec::new();

    for name in methods {
        info!(name);

        if name == obfs4_name {
            let builder = Obfs4PT::client_builder();
            let listener = tokio::net::TcpListener::bind(CLIENT_SOCKS_ADDR).await?;
            let local_addr = listener.local_addr()?;
            pt_proto::print_cmethod(&name, "socks5", local_addr);
            accept_tasks.push(Box::pin(client_accept_loop_with_proxy(
                listener,
                builder,
                ctx.clone(),
                proxy.clone(),
            )));
        } else if name == webtunnel_name {
            let builder = webtunnel::WebTunnelBuilder::default();
            let listener = tokio::net::TcpListener::bind(CLIENT_SOCKS_ADDR).await?;
            let local_addr = listener.local_addr()?;
            pt_proto::print_cmethod(&name, "socks5", local_addr);
            accept_tasks.push(Box::pin(client_accept_loop_with_proxy(
                listener,
                builder,
                ctx.clone(),
                proxy.clone(),
            )));
        } else {
            pt_proto::print_cmethod_error(&name, "no such transport is supported");
            warn!("no such transport is supported");
            continue;
        }
    }

    // PT spec §3.3.3: end of method announcements.
    pt_proto::print_cmethods_done();

    let mut listeners = JoinSet::new();
    for task in accept_tasks {
        listeners.spawn(task);
    }
    Ok(listeners)
}

async fn connection_permit(
    semaphore: Arc<tokio::sync::Semaphore>,
    cancel: &CancellationToken,
) -> Option<tokio::sync::OwnedSemaphorePermit> {
    tokio::select! {
        biased;
        _ = cancel.cancelled() => None,
        permit = semaphore.acquire_owned() => permit.ok(),
    }
}

#[cfg(test)]
async fn client_accept_loop<C>(
    listener: TcpListener,
    builder: impl ptrs::ClientBuilder<TcpStream, ClientPT = C> + Send + 'static,
    ctx: RunTasks,
) -> Result<()>
where
    C: ManagedClient,
{
    client_accept_loop_with_proxy(listener, builder, ctx, None).await
}

async fn client_accept_loop_with_proxy<C>(
    listener: TcpListener,
    builder: impl ptrs::ClientBuilder<TcpStream, ClientPT = C> + Send + 'static,
    ctx: RunTasks,
    proxy: Option<Arc<proxy::Proxy>>,
) -> Result<()>
where
    C: ManagedClient,
{
    let pt_name = C::method_name();
    let mut transient_failures = 0_u32;
    'accept: loop {
        tokio::select! {
            _ = ctx.accept.cancelled() => {
                info!("{pt_name} received shutdown signal");
                break; // exit the loop so graceful shutdown actually stops accepting
            }
            res = listener.accept() => {
                let (conn, client_addr) = match res {
                    Ok(c) => {
                        transient_failures = 0;
                        c
                    }
                    Err(e) if !is_transient_accept_error(&e) => {
                        error!("{pt_name} stopping listener after fatal accept error: {e}");
                        return Err(e.into());
                    }
                    Err(e) => {
                        let delay = accept_retry_delay(transient_failures);
                        transient_failures = transient_failures.saturating_add(1);
                        warn!(
                            "{pt_name} transient accept error: {e}; retrying in {delay:?}"
                        );
                        let retry = tokio::select! {
                            _ = ctx.accept.cancelled() => false,
                            _ = tokio::time::sleep(delay) => true,
                        };
                        if !retry {
                            break 'accept;
                        }
                        continue 'accept;
                    }
                };
                // Acquire a lifecycle permit before spawning: it doubles as
                // the concurrency cap and the task-lifetime marker that
                // `RunTasks::wait_idle` counts, so shutdown always knows
                // exactly how many connections are still in flight.
                let permit = match connection_permit(Arc::clone(&ctx.lifecycle), &ctx.accept).await {
                    Some(p) => p,
                    None => break,
                };
                if ctx.accept.is_cancelled() {
                    drop(permit);
                    break;
                }
                let builder_clone = builder.clone();
                let proxy = proxy.clone();
                let conns = ctx.conns.clone();
                ctx.spawn_connection(async move {
                    let _permit = permit; // held for the task's lifetime, freed on drop
                    tokio::select! {
                        biased;
                        // Forced teardown: dropping this future drops both
                        // halves of the tunnel. Runs only once the graceful
                        // drain budget expired (or on terminate/EOF).
                        _ = conns.cancelled() => {}
                        res = client_handle_connection_with_proxy(conn, builder_clone, client_addr, proxy) => {
                            if let Err(e) = res {
                                warn!(
                                    address = sensitive(client_addr).to_string(),
                                    "connection task failed: {e:#}"
                                );
                            }
                        }
                    }
                }).await;
            }
        }
    }

    Ok(())
}

// Internal, statically dispatched transport adapter; no public trait surface.
trait ManagedClient: ptrs::ClientTransport<TcpStream, std::io::Error> + Sized + Send + 'static {
    type ManagedOut: AsyncRead + AsyncWrite + Send + Unpin + 'static;

    #[cfg(test)]
    fn managed_connect(
        self,
        target_addr: String,
        client_addr: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = Result<Self::ManagedOut>> + Send>> {
        self.managed_connect_with_proxy(target_addr, client_addr, None)
    }

    fn managed_connect_with_proxy(
        self,
        target_addr: String,
        client_addr: SocketAddr,
        proxy: Option<Arc<proxy::Proxy>>,
    ) -> Pin<Box<dyn Future<Output = Result<Self::ManagedOut>> + Send>>;
}

impl ManagedClient for obfs4::Client {
    type ManagedOut = <Self as ptrs::ClientTransport<TcpStream, std::io::Error>>::OutRW;

    fn managed_connect_with_proxy(
        self,
        target_addr: String,
        client_addr: SocketAddr,
        proxy: Option<Arc<proxy::Proxy>>,
    ) -> Pin<Box<dyn Future<Output = Result<Self::ManagedOut>> + Send>> {
        Box::pin(async move {
            let remote_addr = resolve_target_addr(&target_addr).context("no remote address")?;
            let remote: Pin<ptrs::FutureResult<TcpStream, std::io::Error>> = Box::pin(async move {
                match proxy {
                    Some(proxy) => {
                        proxy
                            .connect(&remote_addr.ip().to_string(), remote_addr.port())
                            .await
                    }
                    None => dial_bridge(remote_addr).await,
                }
            });
            establish_pt_conn(self, remote, client_addr).await
        })
    }
}

impl ManagedClient for webtunnel::WebTunnelClient {
    type ManagedOut = <Self as ptrs::ClientTransport<TcpStream, std::io::Error>>::OutRW;

    fn managed_connect_with_proxy(
        self,
        _target_addr: String,
        client_addr: SocketAddr,
        proxy: Option<Arc<proxy::Proxy>>,
    ) -> Pin<Box<dyn Future<Output = Result<Self::ManagedOut>> + Send>> {
        Box::pin(async move {
            match proxy {
                Some(proxy) => {
                    let (host, port) = self
                        .carrier_destination()
                        .map_err(|_| anyhow!("invalid WebTunnel destination"))?;
                    let remote: Pin<ptrs::FutureResult<TcpStream, std::io::Error>> =
                        Box::pin(async move { proxy.connect(&host, port).await });
                    establish_pt_conn(self, remote, client_addr).await
                }
                None => self
                    .connect_url()
                    .await
                    .map_err(|error| anyhow!("WebTunnel URL connection failed: {error}")),
            }
        })
    }
}

/// Drive a built pluggable-transport client to completion against a dial
/// future, returning the wrapped tunnel stream.
///
/// This is the outgoing-connection seam carved out of
/// `client_handle_connection_with_proxy`. The dial is supplied as an already-pinned
/// [`ptrs::FutureResult`] (the same shape `establish` consumes) rather than
/// being created inline with `TcpStream::connect`, so tests can inject an
/// in-memory `tokio::io::duplex()` half — or a future that fails — and
/// observe the handshake behaviour without touching the network.
///
/// On handshake failure the client address is logged (scrubbed) and a typed
/// error is returned; the function never panics on a dial or handshake
/// error reachable from the network.
///
/// # Cancel safety
///
/// cancel-safe: NO — `establish` runs the obfs4/webtunnel handshake, which
/// writes to the underlying socket. Dropping this future mid-handshake can
/// leave the peer expecting bytes that were never sent. The caller
/// (`client_handle_connection`) is selected against the connection
/// cancellation token, so forced shutdown may drop this future mid-handshake.
pub(crate) async fn establish_pt_conn<In2, C2>(
    pt_client: C2,
    dial: Pin<ptrs::FutureResult<In2, std::io::Error>>,
    client_addr: SocketAddr,
) -> Result<C2::OutRW>
where
    // The dialed socket must be usable as an async connection. These are the
    // same bounds the transport traits require of their `InRW` parameter.
    In2: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
    C2: ptrs::ClientTransport<In2, std::io::Error> + Send,
{
    match ptrs::ClientTransport::<In2, std::io::Error>::establish(pt_client, dial).await {
        Err(e) => {
            warn!(
                address = sensitive(client_addr).to_string(),
                "handshake failed: {e:#?}"
            );
            Err(obfs4::Error::from(e.to_string())).context("handshake failed")
        }
        Ok(c) => Ok(c),
    }
}

mod logging_layer;
use logging_layer::{LogConfig, OwnedDispatcher};

mod lifecycle;
#[cfg(test)]
use lifecycle::{
    cancel_connections, drain_connections, drive, join_accept_loops, run_with_setup, Shutdown,
    MAX_CONCURRENT_CONNS,
};
use lifecycle::{RunOwner, RunTasks};

mod server;
mod stdin_watch;
#[cfg(feature = "experimental-server")]
use server::server_setup;

#[cfg(test)]
mod logging_tests;
#[cfg(test)]
#[path = "client/socks_tests.rs"]
mod socks_tests;

// ================================================================ //
//        PT-spec helpers (auth, args, parent-channel messages)     //
// ================================================================ //

/// Reconstruct the PT-spec argument string from the SOCKS5
/// USERNAME/PASSWORD fields, mirroring Go lyrebird `rfc1929.go:88-100`.
///
/// PT spec §3.5 mandates this peculiar split when the arg string
/// exceeds 255 bytes: the parent process packs it into
/// `(username, password)` with `username` capped at 255 bytes.
///
/// * `passwd == [0x00]` is the "no passwd; uname is the whole arg list"
///   marker — return just `uname`.
/// * Otherwise concatenate `uname` and `passwd` as raw bytes, no
///   separator.
/// * `None` means the client connected via NO_AUTH (no args).
pub fn arg_string_from_creds(creds: Option<(String, String)>) -> String {
    match creds {
        None => String::new(),
        Some((uname, passwd)) if passwd.as_bytes() == [0x00] => uname,
        Some((uname, passwd)) => {
            let mut s = uname;
            s.push_str(&passwd);
            s
        }
    }
}

/// Minimal subset of the PT spec's parent-channel protocol (the lines
/// the PT prints on stdout for `tor`/`arti` to read). Without these
/// arti waits forever and reports "PT binary gone".
mod pt_proto;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod lifecycle_tests;
