//! The proxy abstraction — mirrors `proxy/proxy.go` + `proxy/socks5/socks5.go`.
//!
//! tun2socks defines a `proxy.Proxy` interface with `DialContext(metadata)`.
//! Here we expose an async [`Proxy`] trait and a [`ProxyUrl`] parser that turns a
//! `socks5://[user:pass@]host:port` URL into a concrete dialer. Only SOCKS5 is
//! wired in the scaffold; the factory mirrors tun2socks' `proxy.RegisterProtocol`
//! registry so adding more protocols later is a matter of a new match arm.

use std::net::SocketAddr;

use async_trait::async_trait;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::socks5;

/// A duplex byte stream that is also dyn-compatible. `AsyncRead` and `AsyncWrite`
/// can't both appear on a single `dyn` trait object (each is a first non-auto
/// trait), so we group them under one object-safe supertrait the proxy returns.
pub trait DynStream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T> DynStream for T where T: AsyncRead + AsyncWrite + Send + Unpin {}

/// The upstream end of a proxied connection: a duplex byte stream plus the
/// bound local address (for logging/statistics, as tun2socks records `MidIP`).
pub struct Upstream {
    pub stream: Box<dyn DynStream>,
    pub local_addr: SocketAddr,
}

/// A proxy dialer. The async analogue of tun2socks' `proxy.Proxy` interface.
///
/// The return type is boxed so the trait stays dyn-compatible — we hand a
/// `Arc<dyn Proxy>` to the relay dispatcher, exactly as tun2socks passes a
/// `proxy.Proxy` interface around.
#[async_trait]
pub trait Proxy: Send + Sync {
    /// Connect to `target` through the proxy and return a duplex stream.
    ///
    /// `target` is the original destination the TUN connection wanted to reach —
    /// i.e. the smoltcp virtual connection's `(local_addr, local_port)` tuple,
    /// which is exactly what tun2socks passes as `metadata.DestinationAddress()`.
    async fn connect(&self, target: SocketAddr) -> std::io::Result<Upstream>;
}

/// Errors from parsing a proxy URL.
#[derive(Debug, Error)]
pub enum ProxyUrlError {
    #[error("unsupported proxy scheme: {0}")]
    UnsupportedScheme(String),
    #[error("missing proxy host")]
    MissingHost,
    #[error("invalid proxy url: {0}")]
    BadUrl(String),
}

/// A parsed proxy URL, split into the bits a dialer needs.
pub struct ProxyUrl {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
}

impl ProxyUrl {
    /// Parse `socks5://[user:pass@]host:port`.
    ///
    /// Mirrors tun2socks' per-package `Parse(url.URL)` constructors
    /// (e.g. `proxy/socks5.Parse`).
    pub fn parse(raw: &str) -> Result<Self, ProxyUrlError> {
        // Self-contained parse — only the schemes we support are accepted.
        let (scheme, rest) = raw
            .split_once("://")
            .ok_or_else(|| ProxyUrlError::UnsupportedScheme(raw.to_string()))?;
        let scheme = scheme.to_ascii_lowercase();

        match scheme.as_str() {
            "socks5" | "socks5h" => {}
            other => return Err(ProxyUrlError::UnsupportedScheme(other.to_string())),
        }

        let (userinfo, hostport) = match rest.rsplit_once('@') {
            Some((u, h)) => (Some(u), h),
            None => (None, rest),
        };

        let (username, password) = match userinfo {
            Some(ui) => {
                let (u, p) = ui.split_once(':').unwrap_or((ui, ""));
                (
                    (!u.is_empty()).then(|| u.to_string()),
                    (!p.is_empty()).then(|| p.to_string()),
                )
            }
            None => (None, None),
        };

        let (host, port) = parse_host_port(hostport)?;
        if host.is_empty() {
            return Err(ProxyUrlError::MissingHost);
        }

        Ok(Self { scheme, host, port, username, password })
    }

    /// Build a concrete dialer from the parsed URL. This is the async analogue
    /// of tun2socks' `proxy.RegisterProtocol` dispatch table.
    pub fn into_proxy(self) -> socks5::Socks5Proxy {
        // Currently only socks5 is implemented; the match arm mirrors the
        // registry pattern and makes adding protocols straightforward.
        socks5::Socks5Proxy::new(self.host, self.port, self.username, self.password)
    }
}

/// Split `host:port` / `[v6]:port` into its parts.
fn parse_host_port(s: &str) -> Result<(String, u16), ProxyUrlError> {
    if let Some(stripped) = s.strip_prefix('[') {
        // IPv6 literal form: [addr]:port
        let (addr, port) = stripped
            .split_once("]:")
            .ok_or_else(|| ProxyUrlError::BadUrl("malformed ipv6".into()))?;
        let port: u16 = port
            .parse()
            .map_err(|_| ProxyUrlError::BadUrl("invalid port".into()))?;
        return Ok((addr.to_string(), port));
    }
    let (host, port) = s
        .rsplit_once(':')
        .ok_or_else(|| ProxyUrlError::BadUrl("missing port".into()))?;
    let port: u16 = port
        .parse()
        .map_err(|_| ProxyUrlError::BadUrl("invalid port".into()))?;
    Ok((host.to_string(), port))
}
