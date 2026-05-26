//! Parse two bridge lines and demonstrate Display roundtrip.

use bridge_line::BridgeLine;

fn main() {
    // obfs4 bridge line with certificate and IAT mode.
    let obfs4_line = "obfs4 65.108.147.195:8089 DFF8DBF20F8980C4B74EDBAA9695104D613978CE cert=ICnTRGYXX2V63J9ev8XkvXsRJ+Y68XnZGOWW2LCdPIK/sOW8zcunp2gB4qSfelcUVxZDSA iat-mode=0";
    let bridge: BridgeLine = obfs4_line.parse().expect("obfs4 line should parse");
    println!("obfs4 bridge: {bridge:#?}");
    assert_eq!(bridge.transport.as_deref(), Some("obfs4"));
    assert_eq!(bridge.params.get("iat-mode").map(String::as_str), Some("0"));

    // Display roundtrip.
    let rendered = bridge.to_string();
    let roundtrip: BridgeLine = rendered.parse().expect("roundtrip should parse");
    assert_eq!(bridge, roundtrip, "Display roundtrip must match");
    println!("obfs4 roundtrip OK.");

    // Plain (non-PT) bridge line.
    let plain_line = "192.0.2.3:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01";
    let plain: BridgeLine = plain_line.parse().expect("plain line should parse");
    println!("plain bridge: {plain:#?}");
    assert!(plain.transport.is_none());
    println!("plain roundtrip: {}", plain);
}
