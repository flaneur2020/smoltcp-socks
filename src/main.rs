//! smoltcp-socks — userspace TCP/IP stack forwarding TUN connections to SOCKS5.
//!
//! Entry point, mirroring tun2socks' `main.go`:
//!  * parse flags (`Key`),
//!  * `engine.Insert(key)` + `engine.Start()` (here: `Runtime::start`),
//!  * wait for SIGINT/SIGTERM, then `engine.Stop()`.

mod config;
mod device;
mod netstack;
mod proxy;
mod relay;
mod runtime;
mod socks5;

use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use tracing_subscriber::EnvFilter;

use crate::config::Config;
use crate::runtime::Runtime;

/// Userspace TCP/IP stack forwarding TUN connections to a SOCKS5 proxy.
#[derive(Parser, Debug)]
#[command(name = "smoltcp-socks", version, about)]
struct Args {
    /// Use this device [tun://]name
    #[arg(short, long)]
    device: String,

    /// Upstream proxy, e.g. socks5://[user:pass@]host:port
    #[arg(short, long)]
    proxy: String,

    /// Device MTU (0 = default)
    #[arg(long, default_value_t = 0)]
    mtu: u16,

    /// Firewall mark (Linux/BSD)
    #[arg(long, default_value_t = 0)]
    fwmark: u32,

    /// Outbound bind interface
    #[arg(long)]
    interface: Option<String>,

    /// UDP session idle timeout
    #[arg(long, default_value = "60s")]
    udp_timeout: HumantimeDuration,

    /// Log level [trace|debug|info|warn|error]
    #[arg(long, default_value = "info")]
    log_level: String,
}

/// A tiny duration parser so we don't pull a clap-duration helper crate.
#[derive(Clone, Debug)]
struct HumantimeDuration(Duration);

impl std::str::FromStr for HumantimeDuration {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        // Accept plain seconds ("60") or "Ns" form ("60s").
        let s = s.trim();
        if let Some(num) = s.strip_suffix('s') {
            let v: u64 = num.parse().map_err(|e: std::num::ParseIntError| e.to_string())?;
            return Ok(Self(Duration::from_secs(v)));
        }
        let v: u64 = s.parse().map_err(|e: std::num::ParseIntError| e.to_string())?;
        Ok(Self(Duration::from_secs(v)))
    }
}

impl Args {
    fn into_config(self) -> Config {
        Config {
            device: self.device,
            proxy: self.proxy,
            mtu: self.mtu,
            fwmark: self.fwmark,
            interface: self.interface,
            udp_timeout: self.udp_timeout.0,
            log_level: self.log_level,
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new(&args.log_level)),
        )
        .init();

    let cfg = args.into_config();
    let rt = Runtime::start(&cfg)?;
    let _ = rt;

    // Wait for Ctrl-C / SIGTERM — mirrors tun2socks' signal.Notify loop.
    tokio::signal::ctrl_c().await?;
    tracing::info!("[MAIN] received interrupt, shutting down");

    Ok(())
}
