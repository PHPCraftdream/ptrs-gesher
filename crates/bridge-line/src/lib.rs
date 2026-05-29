#![deny(missing_docs)]
//! Parser for Tor bridge lines (the `torrc` Bridge directive format).
//!
//! Grammar (informal):
//!
//! ```text
//! ["Bridge"] [TRANSPORT] HOST:PORT [FINGERPRINT] (KEY=VALUE)*
//! ```
//!
//! * `TRANSPORT` is a pluggable-transport name (e.g. `obfs4`, `snowflake`).
//!   It is absent for plain bridges. We detect its absence by the first
//!   non-`Bridge` token containing `:` (i.e. looking like `host:port`).
//! * `FINGERPRINT` is 40 ASCII hex characters (RSA identity fingerprint).
//!   May be omitted for some PTs; we accept its absence.
//! * Settings are space-separated `key=value` tokens; `value` may not
//!   contain whitespace (this matches the standard torrc form).
//!
//! Examples:
//!
//! ```text
//! obfs4 65.108.147.195:8089 DFF8DBF20F8980C4B74EDBAA9695104D613978CE cert=ICn... iat-mode=0
//! 192.0.2.3:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01
//! ```

use std::collections::BTreeMap;
use std::fmt;
use std::net::SocketAddr;
use std::str::FromStr;

/// A parsed Tor bridge line.
///
/// # Examples
///
/// ```text
/// use bridge_line::BridgeLine;
///
/// let bridge: BridgeLine = "obfs4 1.2.3.4:80 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=AAA iat-mode=0"
///     .parse()
///     .unwrap();
/// assert_eq!(bridge.transport.as_deref(), Some("obfs4"));
/// assert_eq!(bridge.addr.to_string(), "1.2.3.4:80");
///
/// // Display roundtrips back to a parseable string.
/// let s = bridge.to_string();
/// let b2: BridgeLine = s.parse().unwrap();
/// assert_eq!(bridge, b2);
/// ```
///
/// `#[non_exhaustive]`: this is the crate's central data type and the torrc
/// Bridge grammar may grow first-class fields in a future revision. Today the
/// only construction path is [`FromStr`], so the attribute costs callers
/// nothing while leaving room to add fields without a breaking change.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct BridgeLine {
    /// Pluggable-transport name. `None` for plain bridges.
    pub transport: Option<String>,
    /// Bridge ORPort address.
    pub addr: SocketAddr,
    /// 40-hex-char RSA fingerprint (uppercase), if present.
    pub fingerprint: Option<String>,
    /// Extra `key=value` settings (transport-specific).
    pub params: BTreeMap<String, String>,
}

/// Errors produced when parsing a bridge line.
///
/// `#[non_exhaustive]`: the set of parse failures is expected to grow as the
/// torrc Bridge grammar gains stricter validation, so downstream `match`es
/// must keep a wildcard arm.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseError {
    /// The input string was empty.
    #[error("empty bridge line")]
    Empty,
    /// No host:port token was found.
    #[error("missing host:port")]
    MissingAddress,
    /// The host:port token could not be parsed.
    #[error("invalid host:port {addr:?}")]
    InvalidAddress {
        /// The token that failed to parse.
        addr: String,
    },
    /// The fingerprint is not 40 hex characters.
    #[error("invalid fingerprint {value:?}: must be 40 hex characters")]
    InvalidFingerprint {
        /// The token that was rejected.
        value: String,
    },
    /// A parameter token does not contain `=`.
    #[error("invalid parameter {token:?}: expected key=value")]
    InvalidParam {
        /// The token that failed to parse.
        token: String,
    },
    /// The transport name contains disallowed characters.
    #[error("invalid transport name {name:?}")]
    InvalidTransport {
        /// The name that was rejected.
        name: String,
    },
    /// More than one fingerprint was found in a single line.
    #[error("multiple fingerprints in one line")]
    DuplicateFingerprint,
}

impl FromStr for BridgeLine {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut tokens = s.split_ascii_whitespace().peekable();

        let first = *tokens.peek().ok_or(ParseError::Empty)?;
        if first.eq_ignore_ascii_case("bridge") {
            tokens.next();
        }

        let (transport, addr_token) = {
            let word = tokens.next().ok_or(ParseError::MissingAddress)?;
            if looks_like_address(word) {
                (None, word.to_string())
            } else {
                if !is_valid_transport_name(word) {
                    return Err(ParseError::InvalidTransport {
                        name: word.to_string(),
                    });
                }
                let addr = tokens.next().ok_or(ParseError::MissingAddress)?;
                (Some(word.to_string()), addr.to_string())
            }
        };

        let addr: SocketAddr = addr_token
            .parse()
            .map_err(|_| ParseError::InvalidAddress { addr: addr_token })?;

        let mut fingerprint: Option<String> = None;
        let mut params = BTreeMap::new();

        for tok in tokens {
            if let Some((k, v)) = tok.split_once('=') {
                if k.is_empty() {
                    return Err(ParseError::InvalidParam {
                        token: tok.to_string(),
                    });
                }
                params.insert(k.to_string(), v.to_string());
            } else if is_hex_fingerprint(tok) {
                if fingerprint.is_some() {
                    return Err(ParseError::DuplicateFingerprint);
                }
                fingerprint = Some(tok.to_ascii_uppercase());
            } else {
                return Err(ParseError::InvalidParam {
                    token: tok.to_string(),
                });
            }
        }

        Ok(BridgeLine {
            transport,
            addr,
            fingerprint,
            params,
        })
    }
}

impl fmt::Display for BridgeLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut sep = "";
        if let Some(t) = &self.transport {
            write!(f, "{t}")?;
            sep = " ";
        }
        write!(f, "{sep}{}", self.addr)?;
        if let Some(fp) = &self.fingerprint {
            write!(f, " {fp}")?;
        }
        for (k, v) in &self.params {
            write!(f, " {k}={v}")?;
        }
        Ok(())
    }
}

fn looks_like_address(s: &str) -> bool {
    // Heuristic from the torrc parser: an address token contains a colon
    // (IPv4 `host:port` or IPv6 in brackets `[::1]:port`).
    s.contains(':')
}

fn is_valid_transport_name(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

fn is_hex_fingerprint(s: &str) -> bool {
    s.len() == 40 && s.chars().all(|c| c.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_obfs4() {
        let line = "obfs4 65.108.147.195:8089 DFF8DBF20F8980C4B74EDBAA9695104D613978CE cert=ICnTRGYXX2V63J9ev8XkvXsRJ+Y68XnZGOWW2LCdPIK/sOW8zcunp2gB4qSfelcUVxZDSA iat-mode=0";
        let b: BridgeLine = line.parse().unwrap();
        assert_eq!(b.transport.as_deref(), Some("obfs4"));
        assert_eq!(b.addr.to_string(), "65.108.147.195:8089");
        assert_eq!(
            b.fingerprint.as_deref(),
            Some("DFF8DBF20F8980C4B74EDBAA9695104D613978CE")
        );
        assert_eq!(b.params.get("iat-mode").map(String::as_str), Some("0"));
        assert!(b.params.contains_key("cert"));
    }

    #[test]
    fn parses_plain_bridge() {
        let line = "192.0.2.3:443 abcdef0123456789abcdef0123456789abcdef01";
        let b: BridgeLine = line.parse().unwrap();
        assert!(b.transport.is_none());
        assert_eq!(
            b.fingerprint.as_deref(),
            Some("ABCDEF0123456789ABCDEF0123456789ABCDEF01")
        );
    }

    #[test]
    fn accepts_bridge_prefix() {
        let line = "Bridge obfs4 1.2.3.4:80 ABCDEF0123456789ABCDEF0123456789ABCDEF01";
        let b: BridgeLine = line.parse().unwrap();
        assert_eq!(b.transport.as_deref(), Some("obfs4"));
    }

    #[test]
    fn roundtrips_via_display() {
        let line = "obfs4 1.2.3.4:80 ABCDEF0123456789ABCDEF0123456789ABCDEF01 iat-mode=0";
        let b: BridgeLine = line.parse().unwrap();
        let again: BridgeLine = b.to_string().parse().unwrap();
        assert_eq!(b, again);
    }

    #[test]
    fn rejects_empty() {
        assert_eq!("".parse::<BridgeLine>(), Err(ParseError::Empty));
    }

    #[test]
    fn rejects_bad_fingerprint() {
        let line = "obfs4 1.2.3.4:80 NOT_HEX_AT_ALL";
        assert!(matches!(
            line.parse::<BridgeLine>(),
            Err(ParseError::InvalidParam { .. })
        ));
    }

    #[test]
    fn parses_ipv6_with_transport() {
        let line = "obfs4 [2001:db8::1]:443 ABCDEF0123456789ABCDEF0123456789ABCDEF01 iat-mode=0";
        let b: BridgeLine = line.parse().unwrap();
        assert_eq!(b.transport.as_deref(), Some("obfs4"));
        assert_eq!(b.addr.to_string(), "[2001:db8::1]:443");
        assert_eq!(b.params.get("iat-mode").map(String::as_str), Some("0"));
    }

    #[test]
    fn parses_plain_ipv6_bridge() {
        let line = "[::1]:9001 ABCDEF0123456789ABCDEF0123456789ABCDEF01";
        let b: BridgeLine = line.parse().unwrap();
        assert!(b.transport.is_none());
        assert_eq!(b.addr.to_string(), "[::1]:9001");
    }

    #[test]
    fn fingerprint_normalised_to_uppercase() {
        let line = "obfs4 1.2.3.4:80 abcdef0123456789abcdef0123456789abcdef01";
        let b: BridgeLine = line.parse().unwrap();
        assert_eq!(
            b.fingerprint.as_deref(),
            Some("ABCDEF0123456789ABCDEF0123456789ABCDEF01")
        );
    }

    #[test]
    fn rejects_duplicate_fingerprint() {
        let line = "obfs4 1.2.3.4:80 ABCDEF0123456789ABCDEF0123456789ABCDEF01 0123456789ABCDEF0123456789ABCDEF01234567";
        assert!(matches!(
            line.parse::<BridgeLine>(),
            Err(ParseError::DuplicateFingerprint)
        ));
    }

    #[test]
    fn rejects_param_without_key() {
        let line = "obfs4 1.2.3.4:80 ABCDEF0123456789ABCDEF0123456789ABCDEF01 =broken";
        assert!(matches!(
            line.parse::<BridgeLine>(),
            Err(ParseError::InvalidParam { .. })
        ));
    }

    #[test]
    fn param_value_may_be_empty() {
        // `cert=` is rejected nowhere — it parses as an empty value. We
        // intentionally do not validate transport-specific semantics here.
        let line = "obfs4 1.2.3.4:80 ABCDEF0123456789ABCDEF0123456789ABCDEF01 cert=";
        let b: BridgeLine = line.parse().unwrap();
        assert_eq!(b.params.get("cert").map(String::as_str), Some(""));
    }

    // -- Fingerprint edge cases --

    #[test]
    fn rejects_39_char_fingerprint() {
        let line = "obfs4 1.2.3.4:80 ABCDEF0123456789ABCDEF0123456789ABCDEF0"; // 39 chars
        assert!(line.parse::<BridgeLine>().is_err());
    }

    #[test]
    fn rejects_41_char_fingerprint() {
        let line = "obfs4 1.2.3.4:80 ABCDEF0123456789ABCDEF0123456789ABCDEF012"; // 41 chars
        assert!(line.parse::<BridgeLine>().is_err());
    }

    // -- Transport name validation --

    #[test]
    fn single_char_transport_accepted() {
        let line = "x 1.2.3.4:80 ABCDEF0123456789ABCDEF0123456789ABCDEF01";
        let b: BridgeLine = line.parse().unwrap();
        assert_eq!(b.transport.as_deref(), Some("x"));
    }

    #[test]
    fn transport_with_underscore_and_digits() {
        let line = "my_transport_2 1.2.3.4:80 ABCDEF0123456789ABCDEF0123456789ABCDEF01";
        let b: BridgeLine = line.parse().unwrap();
        assert_eq!(b.transport.as_deref(), Some("my_transport_2"));
    }

    #[test]
    fn webtunnel_transport_parses() {
        let line = "webtunnel 192.0.2.3:1 ABCDEF0123456789ABCDEF0123456789ABCDEF01 url=https://example.com/secret ver=0.0.3";
        let b: BridgeLine = line.parse().unwrap();
        assert_eq!(b.transport.as_deref(), Some("webtunnel"));
        assert_eq!(
            b.params.get("url").map(String::as_str),
            Some("https://example.com/secret")
        );
    }

    #[test]
    fn compressed_ipv6_roundtrip() {
        let line = "[::1]:9050 ABCDEF0123456789ABCDEF0123456789ABCDEF01";
        let b: BridgeLine = line.parse().unwrap();
        let s = b.to_string();
        let b2: BridgeLine = s.parse().unwrap();
        assert_eq!(b, b2);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    fn arb_ipv4_addr() -> impl Strategy<Value = String> {
        (1u8..=254, 0u8..=255, 0u8..=255, 1u8..=254, 1u16..=65534)
            .prop_map(|(a, b, c, d, port)| format!("{a}.{b}.{c}.{d}:{port}"))
    }

    fn arb_fingerprint() -> impl Strategy<Value = String> {
        proptest::collection::vec(proptest::string::string_regex("[0-9A-F]").unwrap(), 40..=40)
            .prop_map(|v| v.join(""))
    }

    fn arb_transport() -> impl Strategy<Value = String> {
        prop_oneof![
            Just("obfs4".to_string()),
            Just("webtunnel".to_string()),
            Just("snowflake".to_string()),
            proptest::string::string_regex("[a-z][a-z0-9_-]{0,15}").unwrap(),
        ]
    }

    proptest! {
        #[test]
        fn parse_display_roundtrip_plain(
            addr in arb_ipv4_addr(),
            fp in arb_fingerprint(),
        ) {
            let line = format!("{addr} {fp}");
            if let Ok(b) = line.parse::<BridgeLine>() {
                let s = b.to_string();
                let b2: BridgeLine = s.parse().expect("roundtrip must parse");
                prop_assert_eq!(b, b2);
            }
        }

        #[test]
        fn parse_display_roundtrip_with_transport(
            transport in arb_transport(),
            addr in arb_ipv4_addr(),
            fp in arb_fingerprint(),
        ) {
            let line = format!("{transport} {addr} {fp}");
            if let Ok(b) = line.parse::<BridgeLine>() {
                let s = b.to_string();
                let b2: BridgeLine = s.parse().expect("roundtrip must parse");
                prop_assert_eq!(b, b2);
            }
        }

        #[test]
        fn parse_never_panics(s in ".*") {
            let _ = s.parse::<BridgeLine>();
        }
    }
}
