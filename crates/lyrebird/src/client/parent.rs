//! The PT parent's inbound negotiation (PT-spec section 3.5).
//!
//! The parent (tor/arti) reaches lyrebird over loopback and carries the bridge
//! arguments in the SOCKS5 USERNAME/PASSWORD fields (RFC 1929) or in an HTTP
//! `Proxy-Authorization: Basic` header. Those bytes are transport
//! configuration, not a login: nothing is verified, they go to the transport's
//! `options` and nowhere else, and they are wiped when dropped.
//! `resocks5-net` deliberately has no clear-text credential support, so this
//! small parser owns that one spec-mandated channel.

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use resocks5_net::connect::HostPort;
use resocks5_net::server::Reply;
use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt,
};
use zeroize::Zeroizing;

/// An HTTP head over this size is refused (431).
const MAX_HEAD_BYTES: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Protocol {
    Socks5,
    Http,
}

/// The two RFC 1929 fields, or the halves of a Basic `user:pass`, as sent.
pub(super) struct Credentials {
    pub(super) username: Zeroizing<Vec<u8>>,
    pub(super) password: Zeroizing<Vec<u8>>,
}

/// A negotiated CONNECT: the target and the parent's credentials, if any.
pub(super) struct ParentRequest {
    pub(super) protocol: Protocol,
    pub(super) target: String,
    pub(super) credentials: Option<Credentials>,
}

impl ParentRequest {
    /// Send the final reply. Cancel-safe: NO — a partial reply is terminal.
    pub(super) async fn reply<S: AsyncWrite + Unpin>(
        &self,
        stream: &mut S,
        reply: Reply,
    ) -> std::io::Result<()> {
        stream.write_all(reply_bytes(self.protocol, reply)).await?;
        stream.flush().await
    }
}

/// Read the parent's request: SOCKS5 or HTTP CONNECT, no DNS, no dial, no
/// success reply. Bytes read past the request stay in `stream`'s buffer.
///
/// cancel-safe: NO — the caller discards the stream on error or timeout.
pub(super) async fn accept<S>(stream: &mut S) -> Result<ParentRequest>
where
    S: AsyncBufRead + AsyncWrite + Unpin,
{
    match stream.read_u8().await? {
        5 => socks5(stream).await,
        byte if byte.is_ascii_alphabetic() => http(stream, byte).await,
        _ => Err(anyhow!("unrecognised first byte from the PT parent")),
    }
}

async fn socks5<S>(stream: &mut S) -> Result<ParentRequest>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let count = stream.read_u8().await?;
    let mut methods = vec![0; usize::from(count)];
    stream.read_exact(&mut methods).await?;
    // Password first: it is how a parent carries PT arguments.
    let credentials = if methods.contains(&2) {
        stream.write_all(&[5, 2]).await?;
        stream.flush().await?;
        Some(rfc1929(stream).await?)
    } else if methods.contains(&0) {
        stream.write_all(&[5, 0]).await?;
        stream.flush().await?;
        None
    } else {
        stream.write_all(&[5, 255]).await?;
        stream.flush().await?;
        return Err(anyhow!("no acceptable SOCKS5 method"));
    };

    let mut head = [0; 4];
    stream.read_exact(&mut head).await?;
    if head[0] != 5 {
        return Err(anyhow!("invalid SOCKS5 request version"));
    }
    if head[1] != 1 {
        // RFC 1928: command not supported.
        write_rep(stream, 7).await?;
        return Err(anyhow!("only SOCKS5 CONNECT is supported"));
    }
    let target = match head[3] {
        1 => {
            let mut ip = [0; 4];
            stream.read_exact(&mut ip).await?;
            format!(
                "{}:{}",
                std::net::Ipv4Addr::from(ip),
                stream.read_u16().await?
            )
        }
        4 => {
            let mut ip = [0; 16];
            stream.read_exact(&mut ip).await?;
            format!(
                "[{}]:{}",
                std::net::Ipv6Addr::from(ip),
                stream.read_u16().await?
            )
        }
        3 => {
            let mut name = vec![0; usize::from(stream.read_u8().await?)];
            stream.read_exact(&mut name).await?;
            let port = stream.read_u16().await?;
            let target = String::from_utf8(name).map(|name| format!("{name}:{port}"));
            match target {
                Ok(target) if valid_target(&target) => target,
                _ => {
                    write_rep(stream, 4).await?;
                    return Err(anyhow!("invalid SOCKS5 domain target"));
                }
            }
        }
        _ => {
            // RFC 1928: address type not supported.
            write_rep(stream, 8).await?;
            return Err(anyhow!("unknown SOCKS5 address type"));
        }
    };
    Ok(ParentRequest {
        protocol: Protocol::Socks5,
        target,
        credentials,
    })
}

/// RFC 1929 sub-negotiation. Always accepted: nothing here is a login.
async fn rfc1929<S>(stream: &mut S) -> Result<Credentials>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if stream.read_u8().await? != 1 {
        stream.write_all(&[1, 1]).await?;
        stream.flush().await?;
        return Err(anyhow!("invalid RFC 1929 version"));
    }
    let mut username = Zeroizing::new(vec![0; usize::from(stream.read_u8().await?)]);
    stream.read_exact(&mut username).await?;
    let mut password = Zeroizing::new(vec![0; usize::from(stream.read_u8().await?)]);
    stream.read_exact(&mut password).await?;
    stream.write_all(&[1, 0]).await?;
    stream.flush().await?;
    Ok(Credentials { username, password })
}

async fn write_rep<S: AsyncWrite + Unpin>(stream: &mut S, rep: u8) -> std::io::Result<()> {
    stream.write_all(&[5, rep, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
    stream.flush().await
}

async fn http<S>(stream: &mut S, first: u8) -> Result<ParentRequest>
where
    S: AsyncBufRead + AsyncWrite + Unpin,
{
    match http_head(stream, first).await {
        Ok(request) => Ok(request),
        Err((status, reason)) => {
            // Best effort: the connection is dropped right after.
            let _ = stream.write_all(http_error(status)).await;
            let _ = stream.flush().await;
            Err(anyhow!(reason))
        }
    }
}

type HttpFailure = (u16, &'static str);

async fn http_head<S>(stream: &mut S, first: u8) -> Result<ParentRequest, HttpFailure>
where
    S: AsyncBufRead + Unpin,
{
    let mut line = vec![first];
    let mut total = 1;
    let mut request_line = None;
    let mut authorization: Option<Zeroizing<Vec<u8>>> = None;
    loop {
        // `read_until` keeps the delimiter; the cap bounds every line read.
        let read = (&mut *stream)
            .take((MAX_HEAD_BYTES + 1 - total) as u64)
            .read_until(b'\n', &mut line)
            .await
            .map_err(|_| (400, "HTTP head unreadable"))?;
        total += read;
        if total > MAX_HEAD_BYTES {
            return Err((431, "HTTP head too large"));
        }
        if !line.ends_with(b"\n") {
            return Err((400, "HTTP head truncated"));
        }
        let text = line
            .strip_suffix(b"\r\n")
            .ok_or((400, "bare LF in HTTP head"))?;
        if request_line.is_none() {
            request_line = Some(
                std::str::from_utf8(text)
                    .map_err(|_| (400, "non-UTF-8 HTTP request line"))?
                    .to_owned(),
            );
        } else if text.is_empty() {
            break;
        } else {
            let colon = text
                .iter()
                .position(|&b| b == b':')
                .ok_or((400, "malformed HTTP header"))?;
            let (name, value) = text.split_at(colon);
            if name.eq_ignore_ascii_case(b"proxy-authorization") {
                if authorization.is_some() {
                    return Err((400, "duplicate Proxy-Authorization"));
                }
                authorization = Some(Zeroizing::new(value[1..].trim_ascii().to_vec()));
            }
        }
        line.clear();
    }
    let request_line = request_line.unwrap_or_default();
    let mut parts = request_line.splitn(3, ' ');
    let (method, target, version) = (
        parts.next().unwrap_or(""),
        parts.next().unwrap_or(""),
        parts.next().unwrap_or(""),
    );
    if target.is_empty() || !version.starts_with("HTTP/") {
        return Err((400, "malformed HTTP request line"));
    }
    if method != "CONNECT" {
        return Err((501, "only HTTP CONNECT is supported"));
    }
    if !valid_target(target) {
        return Err((400, "invalid HTTP CONNECT target"));
    }
    let credentials = authorization.map(|value| basic(&value)).transpose()?;
    Ok(ParentRequest {
        protocol: Protocol::Http,
        target: target.to_owned(),
        credentials,
    })
}

/// `Basic base64(user:pass)`, split at the first `:` (RFC 7617).
fn basic(value: &[u8]) -> Result<Credentials, HttpFailure> {
    let space = value.iter().position(|&b| b == b' ');
    let encoded = space
        .filter(|&at| value[..at].eq_ignore_ascii_case(b"basic"))
        .map(|at| value[at + 1..].trim_ascii())
        .ok_or((400, "unsupported Proxy-Authorization scheme"))?;
    let decoded = Zeroizing::new(
        STANDARD
            .decode(encoded)
            .map_err(|_| (400, "invalid Proxy-Authorization encoding"))?,
    );
    let (username, password) = match decoded.iter().position(|&b| b == b':') {
        Some(colon) => (&decoded[..colon], &decoded[colon + 1..]),
        None => (&decoded[..], &[][..]),
    };
    Ok(Credentials {
        username: Zeroizing::new(username.to_vec()),
        password: Zeroizing::new(password.to_vec()),
    })
}

/// A `host:port` the transport can parse, free of control and space bytes.
fn valid_target(target: &str) -> bool {
    !target
        .bytes()
        .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
        && HostPort::parse(target).is_some()
}

fn http_error(status: u16) -> &'static [u8] {
    match status {
        400 => b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
        403 => b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
        431 => b"HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
        501 => b"HTTP/1.1 501 Not Implemented\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
        502 => b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
        503 => b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
        504 => b"HTTP/1.1 504 Gateway Timeout\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
        _ => b"HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
    }
}

/// Wire bytes of one reply on the parent's protocol.
fn reply_bytes(protocol: Protocol, reply: Reply) -> &'static [u8] {
    fn rep(code: u8) -> &'static [u8] {
        match code {
            0 => &[5, 0, 0, 1, 0, 0, 0, 0, 0, 0],
            2 => &[5, 2, 0, 1, 0, 0, 0, 0, 0, 0],
            3 => &[5, 3, 0, 1, 0, 0, 0, 0, 0, 0],
            4 => &[5, 4, 0, 1, 0, 0, 0, 0, 0, 0],
            5 => &[5, 5, 0, 1, 0, 0, 0, 0, 0, 0],
            6 => &[5, 6, 0, 1, 0, 0, 0, 0, 0, 0],
            _ => &[5, 1, 0, 1, 0, 0, 0, 0, 0, 0],
        }
    }
    match (protocol, reply) {
        (Protocol::Socks5, Reply::Established) => rep(0),
        (Protocol::Socks5, Reply::Forbidden) => rep(2),
        (Protocol::Socks5, Reply::NetworkUnreachable) => rep(3),
        (Protocol::Socks5, Reply::UpstreamUnavailable) => rep(4),
        (Protocol::Socks5, Reply::ConnectionRefused) => rep(5),
        (Protocol::Socks5, Reply::TimedOut) => rep(6),
        // GeneralFailure, Overloaded and any reply added later.
        (Protocol::Socks5, _) => rep(1),
        (Protocol::Http, Reply::Established) => b"HTTP/1.1 200 Connection Established\r\n\r\n",
        (Protocol::Http, Reply::Forbidden) => http_error(403),
        (Protocol::Http, Reply::TimedOut) => http_error(504),
        (Protocol::Http, Reply::Overloaded) => http_error(503),
        (Protocol::Http, _) => http_error(502),
    }
}

#[cfg(test)]
#[path = "parent_tests.rs"]
mod tests;
