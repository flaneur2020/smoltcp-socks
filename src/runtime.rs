//! Runtime orchestration — mirrors tun2socks' `engine/engine.go`.
//!
//! Wires the three pieces the gVisor version assembles in `start()`:
//!
//! * the TUN device + smoltcp interface (gVisor's `CreateStack`),
//! * the netstack actor that accepts virtual TCP connections (`tunnel`), and
//! * the proxy dialer the relay uses (`proxy`).
//!
//! Because smoltcp is single-owner, the wiring here is the Rust-appropriate
//! twin of the goroutine-heavy original: an actor task owns the stack, a pump
//! task funnels the TUN fd into the stack's `phy`, and the relay dispatcher
//! fans accepted connections out to per-connection tasks.

use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{info, warn};

use tun::AbstractDevice as _;

use crate::config::Config;
use crate::device::{DeviceHandles, Phy};
use crate::netstack::{NetstackActor, NetstackHandle, build_interface, resolve_mtu};
use crate::proxy::{Proxy, ProxyUrl};

/// The running program. `shutdown` stops everything cleanly.
pub struct Runtime {
    handle: NetstackHandle,
}

impl Runtime {
    /// Assemble and start everything. Mirrors `engine.start()`.
    pub fn start(cfg: &Config) -> Result<Self> {
        if cfg.device.is_empty() {
            return Err(anyhow!("empty device"));
        }
        if cfg.proxy.is_empty() {
            return Err(anyhow!("empty proxy"));
        }

        let mtu = resolve_mtu(cfg);

        // 1. Parse the proxy URL into a concrete dialer — tun2socks' `parseProxy`.
        let proxy_url = ProxyUrl::parse(&cfg.proxy).context("parse proxy url")?;
        let s5 = proxy_url.into_proxy();
        let proxy: Arc<dyn Proxy> = Arc::new(s5);

        // 2. Create the phy/device bridge that smoltcp will poll.
        let (mut phy, device_handles) = Phy::new(mtu);

        // 3. Build the smoltcp interface — tun2socks' `core.CreateStack`.
        let iface = build_interface(&mut phy);

        // 4. Accept arbitrary destinations and relay each connection through SOCKS5.
        let handle = NetstackActor::spawn(iface, phy, proxy.clone());

        // 5. Spawn the TUN pump: read packets from the fd → `inbound`, and write
        //    `outbound` packets back to the fd. This is the async counterpart of
        //    gVisor tying its link endpoint to the TUN fd.
        tokio::spawn(tun_pump(cfg.device.clone(), mtu, device_handles));

        info!("[ENGINE] {} <-> {}", cfg.device, cfg.proxy);
        Ok(Self { handle })
    }

    /// Stop the netstack and wait for it to drain. Mirrors `engine.Stop()`.
    pub async fn shutdown(self) {
        self.handle.stop().await;
        info!("[ENGINE] stopped");
    }
}

/// Background task bridging the async TUN fd and the sync smoltcp `phy`.
///
/// Inbound: `tun.read() → inbound.send()`. Outbound: `outbound.recv() → tun.write()`.
async fn tun_pump(device_spec: String, mtu: usize, handles: DeviceHandles) {
    let DeviceHandles {
        inbound,
        mut outbound,
    } = handles;

    // Open the TUN device (Linux tun / macOS utun) via the `tun` crate's async
    // backend. `open_tun` logs the real (kernel-assigned) name on success.
    let mut dev = match open_tun(&device_spec, mtu) {
        Ok(d) => d,
        Err(e) => {
            warn!("[TUN] failed to open {device_spec}: {e:#}; pump exiting");
            return;
        }
    };

    let mut buf = vec![0u8; 65535];
    loop {
        // Read from the TUN fd, send to smoltcp; and flush any pending
        // outbound packets to the fd. We interleave both with tokio::select.
        tokio::select! {
            res = dev.read(&mut buf) => match res {
                Ok(n) => {
                    let pkt = buf[..n].to_vec();
                    if inbound.try_send(pkt).is_err() {
                        warn!("[TUN] inbound queue full, dropping packet");
                    }
                }
                Err(e) => {
                    warn!("[TUN] read error: {e}");
                    break;
                }
            },
            pkt = outbound.recv() => match pkt {
                Some(p) => {
                    if let Err(e) = dev.write_all(&p).await {
                        warn!("[TUN] write error: {e}");
                    }
                }
                None => break,
            },
        }
    }
}

/// Type alias for the async TUN device the `tun` crate gives us.
type AsyncTun = tun::AsyncDevice;

/// Parse the device spec into an optional TUN name.
///
/// Accepts `tun://name`, `utun://name`, or a bare `name`. An empty name
/// (after stripping the prefix) returns `None`, letting the kernel pick a
/// free interface.
///
/// On Apple platforms the kernel only speaks utun: an explicit name must
/// start with `utun` and carry a numeric suffix (e.g. `utun3`), otherwise
/// we fail fast with a clear message instead of the crate's opaque
/// `InvalidName`. On Linux any name passes straight through.
fn parse_tun_name(spec: &str) -> Result<Option<String>> {
    let name = spec
        .strip_prefix("tun://")
        .or_else(|| spec.strip_prefix("utun://"))
        .unwrap_or(spec);
    if name.is_empty() {
        return Ok(None);
    }
    #[cfg(target_vendor = "apple")]
    {
        if !name.starts_with("utun") || name[4..].parse::<u32>().is_err() {
            return Err(anyhow!(
                "macOS requires a utun name like `utun3` (got `{name}`); \
                 pass `utun://` to let the kernel pick"
            ));
        }
    }
    Ok(Some(name.to_string()))
}

/// Open a TUN device from a `tun://name` / `utun://name` / bare-name spec,
/// wiring the resolved MTU and normalizing utun naming on Apple platforms.
fn open_tun(spec: &str, mtu: usize) -> Result<AsyncTun> {
    let name = parse_tun_name(spec)?;

    let mut cfg = tun::Configuration::default();
    cfg.up().mtu(mtu as u16);

    // Apple: the `tun` crate's `PlatformConfig::default()` sets
    // `packet_information = true` and `enable_routing = true`, which is exactly
    // what utun needs — the 4-byte PI header is stripped on read and prepended
    // on write, so smoltcp sees raw IP. Linux defaults to
    // `packet_information = false` (IFF_TUN), also correct. No explicit
    // platform_config overrides needed on either side.
    if let Some(name) = name.as_deref() {
        cfg.tun_name(name);
    }

    let dev = tun::create_as_async(&cfg).map_err(|e| anyhow!("create tun: {e}"))?;
    // `AsyncDevice` derefs to the platform `Device`, so `AbstractDevice::tun_name`
    // gives the real (possibly kernel-assigned) interface name.
    info!(
        "[TUN] opened {} (mtu {mtu})",
        dev.tun_name().unwrap_or_else(|_| spec.into())
    );
    Ok(dev)
}
