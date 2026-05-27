//! Parse a bridge line and dispatch to the correct transport builder based on
//! the transport name. This is the pattern a multi-transport PT client (like
//! lyrebird) uses to route incoming bridge configurations to the right handler.
//!
//! No network I/O -- just parsing, dispatch, and configuration.
//!
//! Run with: `cargo run -p ptrs-gesher-examples --example dispatch_bridge`

use ptrs_gesher::{Args, BridgeLine};

/// Simulated bridge lines a user might paste from BridgeDB or a torrc file.
const BRIDGES: &[&str] = &[
    // obfs4 bridge
    "obfs4 65.108.147.195:8089 DFF8DBF20F8980C4B74EDBAA9695104D613978CE \
     cert=ICnTRGYXX2V63J9ev8XkvXsRJ+Y68XnZGOWW2LCdPIK/sOW8zcunp2gB4qSfelcUVxZDSA \
     iat-mode=0",
    // webtunnel bridge
    "webtunnel 192.0.2.3:1 ABCDEF0123456789ABCDEF0123456789ABCDEF01 \
     url=https://example.com/secret ver=0.0.3",
    // plain (no PT) bridge
    "192.0.2.100:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01",
];

fn main() {
    for (i, raw) in BRIDGES.iter().enumerate() {
        println!("--- Bridge #{} ---", i + 1);
        let bridge: BridgeLine = raw.parse().expect("bridge line should parse");

        // Convert bridge params to Args for whichever transport we pick.
        let mut args = Args::new();
        for (k, v) in &bridge.params {
            args.add(k, v);
        }

        match bridge.transport.as_deref() {
            Some("obfs4") => {
                println!("  Transport: obfs4");
                println!("  Address  : {}", bridge.addr);
                let mut builder = obfs4::ClientBuilder::default();
                <obfs4::ClientBuilder as ptrs::ClientBuilder<tokio::net::TcpStream>>::options(
                    &mut builder,
                    &args,
                )
                .expect("obfs4 options");
                println!("  IAT mode : {:?}", builder.iat_mode);
                println!("  -> obfs4 client configured OK");
            }
            Some("webtunnel") => {
                println!("  Transport: webtunnel");
                println!("  Address  : {}", bridge.addr);
                let config = webtunnel::WebTunnelConfig::from_args(&args)
                    .expect("webtunnel config from args");
                println!("  URL      : {}", config.url);
                println!(
                    "  Version  : {}",
                    config.version.as_deref().unwrap_or("(unset)")
                );
                println!("  -> webtunnel client configured OK");
            }
            Some(other) => {
                println!("  Transport: {other} (unsupported -- skipping)");
            }
            None => {
                println!("  Transport: (plain bridge, no PT)");
                println!("  Address  : {}", bridge.addr);
                println!("  -> would connect directly via TCP (no obfuscation)");
            }
        }
        println!();
    }

    println!(
        "OK: dispatched {} bridge lines to the correct transport.",
        BRIDGES.len()
    );
}
