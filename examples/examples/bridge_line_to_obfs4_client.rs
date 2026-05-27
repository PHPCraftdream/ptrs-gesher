//! Parse a real obfs4 bridge line, extract its parameters, and configure
//! an obfs4 client builder -- all without touching the network.
//!
//! This is the first thing most users will do: take a bridge line from a
//! torrc file or BridgeDB, turn it into an `Args` bag, and feed it to the
//! obfs4 `ClientBuilder`. The example prints every intermediate step so
//! you can see exactly what each API call produces.

use ptrs_gesher::{Args, BridgeLine};

fn main() {
    // A realistic obfs4 bridge line copied from BridgeDB.
    let raw = "obfs4 65.108.147.195:8089 \
               DFF8DBF20F8980C4B74EDBAA9695104D613978CE \
               cert=ICnTRGYXX2V63J9ev8XkvXsRJ+Y68XnZGOWW2LCdPIK/sOW8zcunp2gB4qSfelcUVxZDSA \
               iat-mode=0";

    // --- Step 1: parse the bridge line ---
    let bridge: BridgeLine = raw.parse().expect("bridge line should parse");
    println!("--- Bridge Line ---");
    println!("  transport : {:?}", bridge.transport);
    println!("  address   : {}", bridge.addr);
    println!(
        "  fingerprint: {}",
        bridge.fingerprint.as_deref().unwrap_or("(none)")
    );
    println!("  params    :");
    for (k, v) in &bridge.params {
        // Truncate long values for readability.
        let display = if v.len() > 40 {
            format!("{}...", &v[..40])
        } else {
            v.clone()
        };
        println!("    {k} = {display}");
    }
    assert_eq!(bridge.transport.as_deref(), Some("obfs4"));

    // --- Step 2: convert params into Args ---
    let mut args = Args::new();
    for (k, v) in &bridge.params {
        args.add(k, v);
    }
    println!("\n--- Args ---");
    println!("  encoded: {}", args.encode_smethod_args());

    // Verify cert and iat-mode are present.
    assert!(
        args.retrieve("cert").is_some(),
        "cert must be present in args"
    );
    assert_eq!(
        args.retrieve("iat-mode").as_deref(),
        Some("0"),
        "iat-mode must be 0"
    );

    // --- Step 3: configure the obfs4 ClientBuilder ---
    let mut builder = obfs4::ClientBuilder::default();
    <obfs4::ClientBuilder as ptrs::ClientBuilder<tokio::net::TcpStream>>::options(
        &mut builder,
        &args,
    )
    .expect("builder should accept these args");

    println!("\n--- obfs4 ClientBuilder ---");
    println!("  iat_mode       : {:?}", builder.iat_mode);
    println!("  station_pubkey : {:02x?}", &builder.station_pubkey[..8]);
    println!("  station_id     : {:02x?}", &builder.station_id[..8]);

    // The builder is now ready. In a real app you would call:
    //   let client = builder.build();
    //   let stream = client.wrap(tcp_stream).await?;

    println!("\nOK: bridge line parsed and obfs4 client configured successfully.");
}
