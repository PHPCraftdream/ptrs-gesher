#![deny(missing_docs)]
//! # ptrs-gesher
//!
//! Umbrella crate for the
//! [ptrs-gesher](https://github.com/PHPCraftdream/ptrs-gesher) framework
//! for Rust pluggable transports. Re-exports a flat top-level API plus
//! the per-crate modules for deeper access.
//!
//! ## Examples
//!
//! ```text
//! use ptrs_gesher::{Args, BridgeLine};
//!
//! // Parse a torrc bridge line:
//! let bridge: BridgeLine = "192.0.2.1:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01"
//!     .parse()
//!     .unwrap();
//! assert_eq!(bridge.addr.port(), 443);
//!
//! // Build a PT argument bag:
//! let mut args = Args::new();
//! args.add("cert", "AAA");
//! assert_eq!(args.retrieve("cert").as_deref(), Some("AAA"));
//! ```
//!
//! ## Components
//!
//! - [`ptrs`] — core traits and helpers (`ClientBuilder`,
//!   `ClientTransport`, `PluggableTransport`, `Args`, …).
//! - [`obfs4`] (feature `obfs4`, default) — obfs4 transport.
//! - [`webtunnel`] (feature `webtunnel`, default) — TLS + HTTP/1.1
//!   Upgrade transport.
//! - [`bridge_line`] (feature `bridge-line`, default) — torrc `Bridge`
//!   directive parser.
//! - [`lyrebird`] (feature `lyrebird`, off by default) — PT-manager
//!   loop usable as a library or busybox-style binary.
//!
//! ## Provenance
//!
//! Forked from [jmwample/ptrs](https://github.com/jmwample/ptrs)
//! (MIT/Apache 2.0), developed independently. See `NOTICE`.

// -- Module re-exports (deep access) ---------------------------------------

pub use ptrs;

#[cfg(feature = "obfs4")]
pub use obfs4;

#[cfg(feature = "webtunnel")]
pub use webtunnel;

#[cfg(feature = "bridge-line")]
pub use bridge_line;

#[cfg(feature = "lyrebird")]
pub use lyrebird;

// -- Flat top-level API (common types lifted out of the modules) ----------

pub use ptrs::args::{self, Args};
pub use ptrs::Error as PtrsError;
pub use ptrs::{
    ClientBuilder, ClientTransport, PluggableTransport, ServerBuilder, ServerTransport,
};

#[cfg(feature = "obfs4")]
pub use obfs4::Obfs4PT;

#[cfg(feature = "webtunnel")]
pub use webtunnel::{WebTunnelBuilder, WebTunnelClient, WebTunnelConfig, WEBTUNNEL_NAME};

#[cfg(feature = "bridge-line")]
pub use bridge_line::{BridgeLine, ParseError as BridgeLineParseError};

#[cfg(feature = "lyrebird")]
pub use lyrebird::{arg_string_from_creds, resolve_target_addr};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flat_args_accessible() {
        let mut args = Args::new();
        args.add("k", "v");
        assert_eq!(args.retrieve("k").as_deref(), Some("v"));
    }

    #[cfg(feature = "obfs4")]
    #[test]
    fn flat_obfs4_pt_accessible() {
        let name = <Obfs4PT as PluggableTransport<tokio::net::TcpStream>>::name();
        assert_eq!(name, "obfs4");
    }

    #[cfg(feature = "webtunnel")]
    #[test]
    fn flat_webtunnel_constant_accessible() {
        assert_eq!(WEBTUNNEL_NAME, "webtunnel");
    }

    #[cfg(feature = "webtunnel")]
    #[test]
    fn flat_webtunnel_config_accessible() {
        let mut args = Args::new();
        args.add("url", "https://example.com/x");
        let cfg = WebTunnelConfig::from_args(&args).unwrap();
        assert_eq!(cfg.url, "https://example.com/x");
    }

    #[cfg(feature = "bridge-line")]
    #[test]
    fn flat_bridge_line_accessible() {
        let b: BridgeLine = "192.0.2.1:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01"
            .parse()
            .unwrap();
        assert_eq!(b.addr.port(), 443);
    }

    #[cfg(feature = "bridge-line")]
    #[test]
    fn flat_bridge_line_error_is_eq() {
        // ParseError must be reachable as BridgeLineParseError via umbrella.
        let err1 = "".parse::<BridgeLine>().unwrap_err();
        let err2: BridgeLineParseError = "".parse::<BridgeLine>().unwrap_err();
        assert_eq!(err1, err2);
    }

    #[cfg(feature = "lyrebird")]
    #[test]
    fn flat_lyrebird_arg_string_accessible() {
        let s = arg_string_from_creds(Some(("cert=AAA".into(), ";iat-mode=0".into())));
        assert_eq!(s, "cert=AAA;iat-mode=0");
    }
}
