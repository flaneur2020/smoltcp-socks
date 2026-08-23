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

use crate::config::Config;
use crate::device::{DeviceHandles, Phy};
use crate::netstack::{
    DEFAULT_LISTEN_PORT, NetstackActor, NetstackHandle, build_interface, resolve_mtu,
};
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

        // 4. Spawn the netstack actor + relay dispatcher.
        let handle = NetstackActor::spawn(iface, phy, proxy.clone(), DEFAULT_LISTEN_PORT);

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
async fn tun_pump(device_spec: String, _mtu: usize, handles: DeviceHandles) {
    let DeviceHandles {
        inbound,
        mut outbound,
    } = handles;

    // Open the TUN device. The `tun` crate exposes an async device behind its
    // `async` feature; this scaffold leaves the concrete create call as a
    // clearly-marked TODO so the platform-specific bits (Linux tun vs macOS
    // utun vs Windows wintun) can be filled in without disturbing the data flow.
    let mut dev = match open_tun(&device_spec) {
        Ok(d) => d,
        Err(e) => {
            warn!("[TUN] failed to open {device_spec}: {e:#}; pump exiting");
            return;
        }
    };
    info!("[TUN] device {} opened", device_spec);

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

/// Open a TUN device from a `tun://name` spec.
///
/// TODO(platform): fill in per-OS. On Linux `tun::Configuration` + `create_as_async`
/// works directly; on macOS the fd is utun-style and needs the same `tun` crate's
///Darwin backend. The signature matches what the pump expects.
fn open_tun(spec: &str) -> Result<AsyncTun> {
    let name = spec
        .strip_prefix("tun://")
        .or_else(|| spec.strip_prefix("utun://"))
        .unwrap_or(spec);
    let mut cfg = tun::Configuration::default();
    cfg.up().tun_name(name).mtu(1500);

    tun::create_as_async(&cfg).map_err(|e| anyhow!("create tun: {e}"))
}
