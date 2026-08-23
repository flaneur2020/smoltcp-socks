//! SOCKS5 client — mirrors `transport/socks5/socks5.go`.
//!
//! Implements RFC 1928 (greeting + CONNECT) and RFC 1929 (username/password
//! auth) as a client, with the same wire layout tun2socks' `ClientHandshake`
//! uses. The function returns once the SOCKS server has accepted the CONNECT,
//! leaving the stream ready for bidirectional relay.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use anyhow::{Result, anyhow, bail};
use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::debug;

use crate::proxy::{Proxy, Upstream};

// ---- Protocol constants (RFC 1928 / 1929) ---------------------------------

pub const VERSION: u8 = 0x05;

/// Authentication methods (RFC 1928 §3).
mod method {
    pub const NO_AUTH: u8 = 0x00;
    pub const USER_PASS: u8 = 0x02;
    pub const NONE_ACCEPTABLE: u8 = 0xff;
}

/// Commands (RFC 1928 §4).
mod cmd {
    pub const CONNECT: u8 = 0x01;
}

/// Address types (RFC 1928 §5).
mod atyp {
    pub const IPV4: u8 = 0x01;
    pub const DOMAIN: u8 = 0x03;
    pub const IPV6: u8 = 0x04;
}

/// RFC 1928 §5 bind-address, serialised for the request/reply.
/// RFC 1928 §5 address. Requests here always carry a resolved IP (`Ip`); the
/// `Domain` arm is kept for parity with the full SOCKS5 address space and the
/// `write_request` match, but the scaffold never receives a domain destination
/// (the TUN layer hands us concrete `SocketAddr`s).
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
enum BindAddr {
    Ip(IpAddr),
    Domain(&'static str), // scaffold: domains unsupported on the request side here
}

impl BindAddr {
    /// Serialise as DST.ADDR (no port). tun2socks writes the same bytes via `Addr`.
    fn write_request(&self, w: &mut Vec<u8>, port: u16) {
        match self {
            BindAddr::Ip(IpAddr::V4(v4)) => {
                w.push(atyp::IPV4);
                w.extend_from_slice(&v4.octets());
            }
            BindAddr::Ip(IpAddr::V6(v6)) => {
                w.push(atyp::IPV6);
                w.extend_from_slice(&v6.octets());
            }
            BindAddr::Domain(d) => {
                w.push(atyp::DOMAIN);
                w.push(d.len() as u8);
                w.extend_from_slice(d.as_bytes());
            }
        }
        w.extend_from_slice(&port.to_be_bytes());
    }
}

/// SOCKS5 username/password auth credentials.
#[derive(Debug, Clone)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}

/// A dialer that connects a plain TCP stream to an upstream SOCKS5 server.
///
/// Mirrors tun2socks' `proxy/socks5.Socks5`; the `connect` method is the async
/// equivalent of `Socks5.DialContext` → `socks5.ClientHandshake`.
#[derive(Debug, Clone)]
pub struct Socks5Proxy {
    pub host: String,
    pub port: u16,
    pub creds: Option<Credentials>,
}

impl Socks5Proxy {
    pub fn new(
        host: String,
        port: u16,
        username: Option<String>,
        password: Option<String>,
    ) -> Self {
        let creds = match (username, password) {
            (Some(u), Some(p)) => Some(Credentials {
                username: u,
                password: p,
            }),
            _ => None,
        };
        Self { host, port, creds }
    }

    /// The SOCKS5 server's TCP endpoint.
    pub fn server_addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    /// Perform the full handshake on an already-connected stream and return the
    /// stream ready for relay. `target` is the destination the original TUN
    /// connection wanted to reach.
    pub async fn handshake<S>(&self, stream: &mut S, target: SocketAddr) -> Result<()>
    where
        S: AsyncReadExt + AsyncWriteExt + Unpin,
    {
        client_handshake(stream, target, self.creds.as_ref()).await
    }
}

#[async_trait]
impl Proxy for Socks5Proxy {
    /// The async analogue of tun2socks' `Socks5.DialContext`: dial the SOCKS5
    /// server over TCP, perform the handshake, and return a boxed duplex stream.
    async fn connect(&self, target: SocketAddr) -> std::io::Result<Upstream> {
        let addr = self.server_addr();
        let mut stream = TcpStream::connect(&addr)
            .await
            .map_err(|e| std::io::Error::other(format!("connect socks5 {addr}: {e}")))?;
        // Keepalive / nodelay, mirroring tun2socks' `utils.SetKeepAlive`.
        let _ = stream.set_nodelay(true);
        let local_addr = stream
            .local_addr()
            .unwrap_or_else(|_| SocketAddr::new(target.ip(), 0));

        self.handshake(&mut stream, target)
            .await
            .map_err(|e| std::io::Error::other(format!("socks5 handshake: {e}")))?;

        Ok(Upstream {
            stream: Box::new(stream),
            local_addr,
        })
    }
}

/// The core client handshake — a near line-for-line port of tun2socks'
/// `transport/socks5.ClientHandshake`.
pub async fn client_handshake<S>(
    rw: &mut S,
    target: SocketAddr,
    user: Option<&Credentials>,
) -> Result<()>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let method = match user {
        Some(_) => method::USER_PASS,
        None => method::NO_AUTH,
    };

    // 1. Greeting: VER, NMETHODS, METHODS
    debug!("socks5: sending greeting, method={:#04x}", method);
    rw.write_all(&[VERSION, 0x01, method]).await?;

    // 2. Server method selection: VER, METHOD
    let mut greeting = [0u8; 2];
    rw.read_exact(&mut greeting).await?;
    if greeting[0] != VERSION {
        bail!("socks5: version mismatched (got {:#04x})", greeting[0]);
    }

    match greeting[1] {
        method::USER_PASS => {
            let creds = user.ok_or_else(|| anyhow!("socks5: auth required but no credentials"))?;
            auth_userpass(rw, creds).await?;
        }
        method::NO_AUTH => {}
        method::NONE_ACCEPTABLE => bail!("socks5: no acceptable auth method"),
        other => bail!("socks5: unsupported method {:#04x}", other),
    }

    // 3. CONNECT request: VER, CMD, RSV, DST.ADDR, DST.PORT
    let mut req = Vec::with_capacity(3 + 26);
    req.extend_from_slice(&[VERSION, cmd::CONNECT, 0x00]);
    let bind = BindAddr::Ip(target.ip());
    bind.write_request(&mut req, target.port());
    debug!("socks5: sending CONNECT for {}", target);
    rw.write_all(&req).await?;

    // 4. Reply: VER, REP, RSV, BND.ADDR, BND.PORT
    let mut rep = [0u8; 3];
    rw.read_exact(&mut rep).await?;
    if rep[1] != 0x00 {
        bail!("socks5: CONNECT rejected: {}", reply_str(rep[1]));
    }

    // Consume (and discard) the bind address. We must read it so the stream is
    // positioned at the start of proxied data, exactly like tun2socks'
    // `ReadAddr` call.
    read_bind_addr(rw).await?;

    debug!("socks5: CONNECT established to {}", target);
    Ok(())
}

/// RFC 1929 username/password sub-negotiation.
async fn auth_userpass<S>(rw: &mut S, creds: &Credentials) -> Result<()>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let u = &creds.username;
    let p = &creds.password;
    if u.is_empty() || p.is_empty() {
        bail!("socks5: auth username/password empty");
    }
    if u.len() > 255 || p.len() > 255 {
        bail!("socks5: auth username/password too long");
    }

    let mut msg = Vec::with_capacity(3 + u.len() + p.len());
    msg.push(0x01); // sub-negotiation version
    msg.push(u.len() as u8);
    msg.extend_from_slice(u.as_bytes());
    msg.push(p.len() as u8);
    msg.extend_from_slice(p.as_bytes());
    rw.write_all(&msg).await?;

    let mut status = [0u8; 2];
    rw.read_exact(&mut status).await?;
    if status[1] != 0x00 {
        bail!("socks5: rejected username/password");
    }
    Ok(())
}

/// Read and discard the BND.ADDR/BND.PORT from a successful reply.
/// Mirrors tun2socks' `ReadAddr`.
async fn read_bind_addr<S>(rw: &mut S) -> Result<()>
where
    S: AsyncReadExt + Unpin,
{
    let mut atyp = [0u8; 1];
    rw.read_exact(&mut atyp).await?;
    let skip = match atyp[0] {
        atyp::IPV4 => 4,
        atyp::IPV6 => 16,
        atyp::DOMAIN => {
            let mut len = [0u8; 1];
            rw.read_exact(&mut len).await?;
            len[0] as usize
        }
        other => bail!("socks5: unsupported reply atyp {:#04x}", other),
    };
    // address bytes + 2 bytes port
    let mut rest = vec![0u8; skip + 2];
    rw.read_exact(&mut rest).await?;
    Ok(())
}

impl BindAddr {
    #[allow(dead_code)] // kept for parity with tun2socks' Addr helpers
    fn from_ip(ip: IpAddr) -> Self {
        BindAddr::Ip(ip)
    }
    #[allow(dead_code)]
    fn _v4_unspecified() -> Self {
        BindAddr::Ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
    }
    #[allow(dead_code)]
    fn _v6_unspecified() -> Self {
        BindAddr::Ip(IpAddr::V6(Ipv6Addr::UNSPECIFIED))
    }
}

fn reply_str(rep: u8) -> &'static str {
    match rep {
        0x00 => "succeeded",
        0x01 => "general SOCKS server failure",
        0x02 => "connection not allowed by ruleset",
        0x03 => "network unreachable",
        0x04 => "host unreachable",
        0x05 => "connection refused",
        0x06 => "TTL expired",
        0x07 => "command not supported",
        0x08 => "address type not supported",
        _ => "unassigned",
    }
}
