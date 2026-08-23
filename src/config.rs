//! Configuration — mirrors tun2socks' `engine/key.go`.
//!
//! Everything the rest of the program needs is derived from this struct. The
//! field set intentionally tracks tun2socks' flags so the behaviour is familiar.

use std::time::Duration;

/// Runtime configuration, populated from CLI flags (see `main.rs`).
///
/// The field set mirrors tun2socks' `engine.Key` one-to-one. A few fields
/// (`fwmark`, `interface`, `udp_timeout`, `log_level`) are parsed and stored but
/// not yet consumed by a wired code path in the scaffold — they ride along so
/// the struct stays a faithful translation of the Go config and is ready as
/// those features land.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Config {
    /// TUN device to use, e.g. `tun://tun0`. Mirrors `engine.Key.Device`.
    pub device: String,

    /// Upstream proxy URL, e.g. `socks5://user:pass@127.0.0.1:1080`.
    /// Mirrors `engine.Key.Proxy`.
    pub proxy: String,

    /// Device MTU. 0 ⇒ use the TUN device default. Mirrors `engine.Key.MTU`.
    pub mtu: u16,

    /// Firewall mark (Linux/BSD). Mirrors `engine.Key.Mark`.
    pub fwmark: u32,

    /// Outbound bind interface. Mirrors `engine.Key.Interface`.
    pub interface: Option<String>,

    /// UDP session idle timeout. Mirrors `engine.Key.UDPTimeout`.
    pub udp_timeout: Duration,

    /// Log level: `trace|debug|info|warn|error`. Mirrors `engine.Key.LogLevel`.
    pub log_level: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            device: String::new(),
            proxy: String::new(),
            mtu: 0,
            fwmark: 0,
            interface: None,
            udp_timeout: Duration::from_secs(60),
            log_level: "info".to_string(),
        }
    }
}
