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

/// Render the components into a bridge-line string using the documented
/// grammar order. Built independently of `BridgeLine`'s own `Display` so the
/// roundtrip property is an end-to-end check rather than a tautology, and so
/// `BridgeLine` can stay `#[non_exhaustive]` (no struct-literal construction
/// from this external test crate).
fn render(
    transport: &Option<String>,
    addr: &SocketAddr,
    fingerprint: &Option<String>,
    params: &BTreeMap<String, String>,
) -> String {
    let mut out = String::new();
    if let Some(t) = transport {
        out.push_str(t);
        out.push(' ');
    }
    out.push_str(&addr.to_string());
    if let Some(fp) = fingerprint {
        out.push(' ');
        out.push_str(fp);
    }
    for (k, v) in params {
        out.push(' ');
        out.push_str(k);
        out.push('=');
        out.push_str(v);
    }
    out
}

/// Strategy yielding a canonical `BridgeLine` obtained by parsing a rendered
/// line. The generators only produce grammar-valid tokens, so the parse is
/// infallible; parsing (rather than a struct literal) gives us the canonical
/// form the parser would always hand a caller.
fn arb_bridge_line() -> impl Strategy<Value = BridgeLine> {
    (
        arb_transport(),
        arb_socket_addr(),
        arb_fingerprint(),
        arb_params(),
    )
        .prop_map(|(transport, addr, fingerprint, params)| {
            let line = render(&transport, &addr, &fingerprint, &params);
            line.parse::<BridgeLine>()
                .unwrap_or_else(|e| panic!("generated line must parse {line:?}: {e}"))
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
