//! Diagnostic: probe webtunnel bridges by performing the real webtunnel
//! client handshake (TLS + HTTP-Upgrade to the `url=` host; the cosmetic
//! bridge addr is ignored). Reads bridge lines from the file given as
//! argv[1] (one per line; non-webtunnel lines are skipped), probes
//! concurrently, and prints the live ones — config-ready on stdout.
//!
//! No bridges are hard-coded — pass your own list file.
//!
//! Run: `cargo run -p ptrs-gesher-examples --example connect_real_webtunnel -- <file>`

use std::pin::Pin;
use std::time::Duration;

use ptrs_gesher::{Args, BridgeLine, WebTunnelBuilder, WebTunnelClient};
use tokio::net::TcpStream;

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("usage: connect_real_webtunnel <bridge-list-file>");
    let text = std::fs::read_to_string(&path).expect("read bridge list");

    let lines: Vec<String> = text
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("webtunnel "))
        .map(String::from)
        .collect();
    eprintln!("probing {} webtunnel bridges from {path}", lines.len());

    let handles: Vec<_> = lines
        .into_iter()
        .map(|raw| {
            tokio::spawn(async move {
                let bridge: BridgeLine = raw.parse().ok()?;
                let mut args = Args::new();
                for (k, v) in &bridge.params {
                    args.add(k, v);
                }
                let mut builder = WebTunnelBuilder::default();
                <WebTunnelBuilder as ptrs::ClientBuilder<TcpStream>>::options(&mut builder, &args)
                    .ok()?;
                let client = <WebTunnelBuilder as ptrs::ClientBuilder<TcpStream>>::build(&builder);

                // webtunnel drops this dial future un-awaited and dials the
                // url host itself; the placeholder bridge addr is unused.
                let dial: Pin<ptrs::FutureResult<TcpStream, std::io::Error>> =
                    Box::pin(TcpStream::connect("127.0.0.1:9"));

                let ok = tokio::time::timeout(
                    Duration::from_secs(20),
                    <WebTunnelClient as ptrs::ClientTransport<TcpStream, std::io::Error>>::establish(
                        client, dial,
                    ),
                )
                .await
                .ok()
                .and_then(Result::ok)
                .is_some();

                if ok {
                    Some(raw)
                } else {
                    None
                }
            })
        })
        .collect();

    let mut live = 0usize;
    for h in handles {
        if let Ok(Some(raw)) = h.await {
            live += 1;
            println!("{raw}");
        }
    }
    eprintln!("=== {live} live webtunnel bridges ===");
}
