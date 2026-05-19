//! Errors that can occur during Pluggable Transport establishment.

use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum Error {
    // #[error("No proxy requested in TOR_PT_PROXY")]
    // NoProxyRequested,
    #[error("PROXY-ERROR {0}")]
    ProxyError(String),
    #[error("error parsing client params: {0}")]
    ParseError(String),
    #[error("unknown data store error")]
    Unknown,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_error_display() {
        let e = Error::ProxyError("SOCKS5 not supported".into());
        assert_eq!(format!("{e}"), "PROXY-ERROR SOCKS5 not supported");
    }

    #[test]
    fn parse_error_display() {
        let e = Error::ParseError("missing key".into());
        assert!(format!("{e}").contains("missing key"));
    }

    #[test]
    fn unknown_display() {
        let e = Error::Unknown;
        assert_eq!(format!("{e}"), "unknown data store error");
    }

    #[test]
    fn error_is_eq() {
        assert_eq!(Error::Unknown, Error::Unknown);
        assert_ne!(
            Error::ProxyError("a".into()),
            Error::ProxyError("b".into()),
        );
    }
}
