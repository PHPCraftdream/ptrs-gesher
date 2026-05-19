use proptest::prelude::*;
use ptrs::args::Args;

fn arb_key() -> impl Strategy<Value = String> {
    "[a-z][a-z0-9-]{0,15}"
}

fn arb_value() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9/+.]{0,60}"
}

proptest! {
    #[test]
    fn encode_then_parse_roundtrip(
        kvs in prop::collection::vec((arb_key(), arb_value()), 1..5)
    ) {
        let mut args = Args::new();
        for (k, v) in &kvs {
            args.add(k, v);
        }
        let encoded = args.encode_smethod_args();
        let decoded = Args::parse_client_parameters(&encoded)
            .unwrap_or_else(|e| panic!("failed to parse encoded args {encoded:?}: {e}"));

        for (k, v) in &kvs {
            let got = decoded.retrieve(k);
            prop_assert_eq!(
                got.as_deref(),
                Some(v.as_str()),
                "roundtrip failed for key",
            );
        }
    }

    #[test]
    fn parse_never_panics(s in "\\PC{0,200}") {
        let _ = Args::parse_client_parameters(&s);
    }
}
