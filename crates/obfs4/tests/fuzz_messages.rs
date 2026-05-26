//! High-iteration property test for codec decode — lightweight fuzz.
//! Run with `cargo test -p ptrs-gesher-obfs4 --test fuzz_messages --release`.

use bytes::BytesMut;
use obfs4::framing::{Obfs4Codec, KEY_MATERIAL_LENGTH};
use proptest::prelude::*;
use tokio_util::codec::Decoder;

proptest! {
    #![proptest_config(ProptestConfig { cases: 10_000, .. ProptestConfig::default() })]

    #[test]
    fn codec_decode_10k(bytes in prop::collection::vec(any::<u8>(), 0..3000)) {
        let km = [0x42u8; KEY_MATERIAL_LENGTH];
        let mut codec = Obfs4Codec::new(km, km);
        let mut buf = BytesMut::from(&bytes[..]);
        let _ = codec.decode(&mut buf);
    }
}
