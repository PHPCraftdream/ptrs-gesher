//! Umbrella crate demo: parse a BridgeLine, build Args, look up Obfs4PT name.

use ptrs::PluggableTransport;
use ptrs_gesher::{Args, BridgeLine, Obfs4PT};
use tokio::net::TcpStream;

fn main() {
    // Parse a bridge line.
    let bridge: BridgeLine =
        "obfs4 1.2.3.4:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=AAA iat-mode=0"
            .parse()
            .expect("bridge line should parse");
    println!("transport: {:?}", bridge.transport);
    println!("addr: {}", bridge.addr);

    // Convert bridge params to Args.
    let mut args = Args::new();
    for (k, v) in &bridge.params {
        args.add(k, v);
    }
    println!("args: {args:?}");

    // Look up the obfs4 transport name.
    let name = <Obfs4PT as PluggableTransport<TcpStream>>::name();
    assert_eq!(name, "obfs4");
    println!("Obfs4PT::name() = {name}");
}
