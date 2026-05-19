//! High-iteration property test for args parser — acts as a lightweight
//! fuzz campaign. Run with `cargo test -p ptrs-gesher-core --test fuzz_args
//! --release` for faster throughput.
//!
//! Found: 2 panics in first run (byte/char confusion, now fixed).

use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig { cases: 10_000, .. ProptestConfig::default() })]

    #[test]
    fn args_parse_10k_random_inputs(s in "\\PC{0,500}") {
        let _ = ptrs::args::Args::parse_client_parameters(&s);
    }
}
