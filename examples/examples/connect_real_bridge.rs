//! Diagnostic: probe obfs4 bridges by performing the real obfs4 client
//! handshake (no arti). Reads bridge lines from the file given as argv[1]
//! (one per line; non-obfs4 lines are skipped), probes concurrently, and
//! prints the live ones sorted fastest-first — ready to paste into a
//! config.
//!
//! Run: `cargo run -p ptrs-gesher-examples --example connect_real_bridge -- <file>`

use std::time::{Duration, Instant};

use ptrs_gesher::{Args, BridgeLine};
use tokio::net::TcpStream;

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("usage: connect_real_bridge <bridge-list-file>");
    let text = std::fs::read_to_string(&path).expect("read bridge list");

    let lines: Vec<String> = text
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("obfs4 "))
        .map(String::from)
        .collect();
    eprintln!("probing {} obfs4 bridges from {path}", lines.len());

    let handles: Vec<_> = lines
        .into_iter()
        .map(|raw| {
            tokio::spawn(async move {
                let bridge: BridgeLine = raw.parse().ok()?;
                let mut args = Args::new();
                for (k, v) in &bridge.params {
                    args.add(k, v);
                }
                let mut builder = obfs4::ClientBuilder::default();
                <obfs4::ClientBuilder as ptrs::ClientBuilder<TcpStream>>::options(
                    &mut builder,
                    &args,
                )
                .ok()?;
                let client = builder.build();

                let t0 = Instant::now();
                let ok = tokio::time::timeout(Duration::from_secs(12), async {
                    let tcp = TcpStream::connect(bridge.addr).await.ok()?;
                    client.wrap(tcp).await.ok()
                })
                .await
                .ok()
                .flatten()
                .is_some();

                if ok {
                    Some((t0.elapsed().as_millis() as u64, raw))
                } else {
                    None
                }
            })
        })
        .collect();

    let mut live: Vec<(u64, String)> = Vec::new();
    for h in handles {
        if let Ok(Some(pair)) = h.await {
            live.push(pair);
        }
    }
    live.sort_by_key(|(ms, _)| *ms);

    eprintln!("=== {} live obfs4 bridges (fastest first) ===", live.len());
    for (ms, raw) in &live {
        // stderr: human summary; stdout: raw line (so `> file` yields a config-ready list)
        eprintln!(
            "{ms:>5}ms  {}",
            raw.split_whitespace().nth(1).unwrap_or("?")
        );
        println!("{raw}");
    }
}
