//! # ptrs-gesher
//!
//! Umbrella crate re-exporting the components of the
//! [ptrs-gesher](https://github.com/PHPCraftdream/ptrs-gesher) framework
//! for Rust pluggable transports.
//!
//! ## Components
//!
//! - [`ptrs`] — core traits: [`ptrs::ClientBuilder`], [`ptrs::ClientTransport`],
//!   [`ptrs::args::Args`].
//! - [`obfs4`] (feature `obfs4`, default) — obfs4 transport.
//! - [`webtunnel`] (feature `webtunnel`, default) — TLS + HTTP/1.1 Upgrade
//!   transport.
//! - [`bridge_line`] (feature `bridge-line`, default) — torrc `Bridge`
//!   directive parser.
//! - [`lyrebird`] (feature `lyrebird`, off by default) — PT-manager
//!   binary/library suitable for in-process or busybox-style use.
//!
//! ## Provenance
//!
//! Forked from [jmwample/ptrs](https://github.com/jmwample/ptrs) (MIT/Apache 2.0),
//! developed independently. See `NOTICE` at the repo root.

pub use ptrs;

#[cfg(feature = "obfs4")]
pub use obfs4;

#[cfg(feature = "webtunnel")]
pub use webtunnel;

#[cfg(feature = "bridge-line")]
pub use bridge_line;

#[cfg(feature = "lyrebird")]
pub use lyrebird;
