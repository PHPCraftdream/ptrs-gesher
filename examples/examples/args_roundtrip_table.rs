//! Table-driven demonstration of `Args` parse-encode roundtrip.
//!
//! This is the pattern you would use when handling SMETHOD args strings
//! coming from a Tor parent process: parse them, inspect individual keys,
//! re-encode, and verify the roundtrip. The table format makes it easy to
//! add new test vectors as you encounter real-world bridge configurations.
//!
//! Run with: `cargo run -p ptrs-gesher-examples --example args_roundtrip_table`

use ptrs_gesher::Args;

/// Each entry is a (description, input_string) pair.
const TABLE: &[(&str, &str)] = &[
    ("simple cert + iat", "cert=ABC;iat-mode=0"),
    (
        "multiple keys",
        "shared-secret=rahasia;secrets-file=/tmp/blob",
    ),
    (
        "real obfs4 cert",
        "cert=ICnTRGYXX2V63J9ev8XkvXsRJ+Y68XnZGOWW2LCdPIK/sOW8zcunp2gB4qSfelcUVxZDSA;iat-mode=0",
    ),
    ("single key-value", "url=https://example.com/secret"),
    ("numeric values", "rocks=20;height=5.6"),
    ("empty value", "key="),
    ("value with equals", "key=a=b=c"),
];

fn main() {
    let mut pass_count = 0;

    let header_desc = "Description";
    let header_enc = "Encoded (first 50 chars)";
    let header_rt = "Roundtrip";
    println!("{header_desc:<25} {header_enc:<50} {header_rt}");
    println!("{}", "-".repeat(90));

    for (desc, input) in TABLE {
        // Parse.
        let args = Args::parse_client_parameters(input).unwrap_or_else(|e| {
            panic!("failed to parse {desc}: {e}");
        });

        // Re-encode.
        let encoded = args.encode_smethod_args();

        // Parse the re-encoded string.
        let roundtrip = Args::parse_client_parameters(&encoded).unwrap_or_else(|e| {
            panic!("roundtrip parse failed for {desc}: {e}");
        });

        // Verify equality.
        let ok = args == roundtrip;
        let display_encoded = if encoded.len() > 50 {
            format!("{}...", &encoded[..47])
        } else {
            encoded.clone()
        };
        let status = if ok { "OK" } else { "FAIL" };
        println!("{desc:<25} {display_encoded:<50} {status}");

        assert!(ok, "roundtrip mismatch for {desc}");
        pass_count += 1;
    }

    println!("{}", "-".repeat(90));
    println!(
        "\nOK: {pass_count}/{} roundtrip checks passed.",
        TABLE.len()
    );
}
