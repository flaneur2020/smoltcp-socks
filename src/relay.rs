//! Bidirectional relay — mirrors tun2socks' `tunnel/tcp.go`.
//!
//! tun2socks' `handleTCPConn`: dial the proxy, then `pipe(originConn, remoteConn)`,
//! two goroutines each calling `io.CopyBuffer` in one direction, half-closing
//! their write side when done. We reproduce the same shape with tokio tasks:
//!
//!  * one task copies bytes from the virtual (TUN) connection to the upstream,
//!  * one task copies bytes from the upstream back to the virtual connection,
//!  * each half-closes its write side on exit (the equivalent of
//!    `CloseWrite` / `CloseRead`), then we wait for both.

use std::sync::Arc;

use anyhow::{Result, anyhow};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{info, warn};

use crate::netstack::vconn::{ConnMeta, VConn};
use crate::proxy::{Proxy, Upstream};

/// Relay buffer size, matching tun2socks' `buffer.RelayBufferSize`.
const RELAY_BUF: usize = 32 * 1024;

/// Drive one proxied connection end to end.
///
/// This is the async port of tun2socks' `Tunnel.handleTCPConn`:
///   1. dial the upstream through the proxy,
///   2. `pipe` the two directions, and
///   3. close both ends.
///
/// `vconn` is the TUN-side virtual socket; `meta.dst` is the real destination
/// the SOCKS5 CONNECT names.
pub async fn pipe(vconn: VConn, meta: ConnMeta, proxy: Arc<dyn Proxy>) -> Result<()> {
    let dst = vconn.destination();
    info!("[TCP] {} <-> {}", meta.src, dst);

    // 1. Dial through the proxy. tun2socks wraps this in a 5s `tcpConnectTimeout`.
    let Upstream {
        stream: mut upstream,
        local_addr: _,
    } = proxy
        .connect(dst)
        .await
        .map_err(|e| anyhow!("dial proxy for {dst}: {e}"))?;

    // Split the boxed duplex stream into its read and write halves so the two
    // copy directions can run concurrently. `tokio::io::split` works on any
    // AsyncRead+AsyncWrite, including our `Box<dyn ...>`.
    let (mut ro, mut wo) = tokio::io::split(&mut upstream);

    // 2. Bidirectional copy + half-close, mirroring tun2socks' `pipe`, which
    //    spawns two goroutines and `wg.Wait()`s. We mirror with two futures run
    //    concurrently via `tokio::join!` so both directions share one task and
    //    there are no borrow-lifetime issues across `tokio::spawn`.
    let vconn_r = vconn.clone();
    let vconn_w = vconn.clone();

    let up = copy_vconn_to(&vconn_r, &mut wo);
    let down = copy_to_vconn(&mut ro, &vconn_w);

    let (up_res, down_res) = tokio::join!(up, down);
    if let Err(e) = up_res {
        warn!("[TCP] origin->remote: {e:#}");
    }
    if let Err(e) = down_res {
        warn!("[TCP] remote->origin: {e:#}");
    }

    let _ = vconn.close().await;
    drop(upstream);
    Ok(())
}

/// Copy bytes from the virtual connection to an upstream writer.
/// Mirrors `unidirectional_stream(origin, remote, "origin->remote")`.
async fn copy_vconn_to<W>(vconn: &VConn, dst: &mut W) -> Result<()>
where
    W: AsyncWriteExt + Unpin,
{
    loop {
        let data = vconn.read(RELAY_BUF).await?;
        if data.is_empty() {
            break;
        }
        dst.write_all(&data).await?;
    }
    // Half-close the write side, as tun2socks does.
    let _ = dst.flush().await;
    Ok(())
}

/// Copy bytes from an upstream reader into the virtual connection.
/// Mirrors `unidirectional_stream(remote, origin, "remote->origin")`.
async fn copy_to_vconn<R>(src: &mut R, vconn: &VConn) -> Result<()>
where
    R: AsyncReadExt + Unpin,
{
    let mut buf = vec![0u8; RELAY_BUF];
    loop {
        let n = src.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        let mut written = 0;
        while written < n {
            let w = vconn.write(&buf[written..n]).await?;
            if w == 0 {
                return Err(anyhow!("vconn write returned 0"));
            }
            written += w;
        }
    }
    // Half-close the TUN write side, mirroring tun2socks' CloseWrite.
    let _ = vconn.close_write().await;
    Ok(())
}
