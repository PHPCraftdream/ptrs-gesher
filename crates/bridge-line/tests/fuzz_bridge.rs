//! High-iteration property test for bridge line parser — lightweight fuzz.
//! Run with `cargo test -p ptrs-gesher-bridge-line --test fuzz_bridge --release`.

use bridge_line::BridgeLine;
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig { cases: 10_000, .. ProptestConfig::default() })]

    #[test]
    fn bridge_parse_10k(s in "\\PC{0,500}") {
        let _ = s.parse::<BridgeLine>();
    }
}
