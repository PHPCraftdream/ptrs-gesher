//! Parse obfs4-style client-args, encode back, and verify roundtrip equality.

use ptrs::args::Args;

fn main() {
    let input = "cert=ABC;iat-mode=0";

    // Parse the parameter string.
    let args = Args::parse_client_parameters(input).expect("parse should succeed");
    println!("Parsed args: {args:?}");

    // Encode back to SMETHOD-args format.
    let encoded = args.encode_smethod_args();
    println!("Encoded: {encoded}");

    // Parse the encoded string again and verify equality.
    let roundtrip = Args::parse_client_parameters(&encoded).expect("roundtrip parse");
    assert_eq!(args, roundtrip, "roundtrip must be equal");
    println!("Roundtrip OK.");
}
