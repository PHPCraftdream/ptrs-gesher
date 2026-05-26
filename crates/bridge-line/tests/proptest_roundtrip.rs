use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use bridge_line::BridgeLine;
use proptest::prelude::*;

fn arb_transport() -> impl Strategy<Value = Option<String>> {
    prop_oneof![Just(None), "[a-z][a-z0-9_-]{0,15}".prop_map(Some),]
}

fn arb_socket_addr() -> impl Strategy<Value = SocketAddr> {
    (1u8..=254, 1u16..=65534).prop_map(|(host, port)| {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(host, 1, 1, 1), port))
    })
}

fn arb_fingerprint() -> impl Strategy<Value = Option<String>> {
    prop_oneof![Just(None), "[0-9A-F]{40}".prop_map(Some),]
}

fn arb_params() -> impl Strategy<Value = BTreeMap<String, String>> {
    prop::collection::btree_map("[a-z][a-z0-9-]{0,10}", "[a-zA-Z0-9/+]{1,50}", 0..5)
}

fn arb_bridge_line() -> impl Strategy<Value = BridgeLine> {
    (
        arb_transport(),
        arb_socket_addr(),
        arb_fingerprint(),
        arb_params(),
    )
        .prop_map(|(transport, addr, fingerprint, params)| BridgeLine {
            transport,
            addr,
            fingerprint,
            params,
        })
}

proptest! {
    #[test]
    fn parse_display_roundtrip(bridge in arb_bridge_line()) {
        let displayed = bridge.to_string();
        let reparsed: BridgeLine = displayed.parse()
            .unwrap_or_else(|e| panic!("failed to reparse {displayed:?}: {e}"));
        prop_assert_eq!(bridge, reparsed);
    }

    #[test]
    fn parser_never_panics(s in "\\PC{0,500}") {
        let _ = s.parse::<BridgeLine>();
    }
}
