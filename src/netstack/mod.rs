//! Userspace TCP/IP stack — mirrors tun2socks' `core/` package.
//!
//! The split mirrors gVisor's structure:
//!
//! | Rust file             | tun2socks (Go)            | Role                               |
//! |-----------------------|---------------------------|------------------------------------|
//! | `mod.rs`              | `core/stack.go`           | Interface setup (NIC, routes).     |
//! | `actor.rs`            | `core/tcp.go` + `tunnel`  | Poll loop + TCP accept forwarder.  |
//! | `vconn.rs`            | `core/adapter/adapter.go` | Virtual connection handle.         |
//!
//! The central design difference from tun2socks: gVisor + `gonet` yields a
//! blocking `net.Conn` per virtual connection, freely passed across goroutines.
//! smoltcp is single-owner and poll-driven — there is no per-connection thread
//! that can block on `read`. So:
//!
//! * the **actor task** owns the `Interface` + `SocketSet` and runs the poll loop,
//! * each accepted virtual connection is represented by a socket handle inside
//!   that set, and
//! * the [`VConn`] the relay tasks hold is a channel-backed façade: `read`/`write`
//!   requests go to the actor, which performs the actual smoltcp socket I/O
//!   during `poll` and replies with bytes / acks.
//!
//! This keeps all smoltcp mutation on one task (its hard requirement) while
//! letting relay tasks present a normal async read/write interface — the
//! functional equivalent of tun2socks' `gonet.TCPConn` over the gVisor endpoint.

use std::time::Duration;

use smoltcp::iface::{Config as IfaceConfig, Interface};
use smoltcp::phy::Device;
use smoltcp::socket::tcp::{Socket as TcpSocket, SocketBuffer};
use smoltcp::wire::HardwareAddress;
use tracing::info;

use crate::{config::Config, device::Phy};

pub mod actor;
pub mod vconn;

pub use actor::{NetstackActor, NetstackHandle};
#[allow(unused_imports)]
pub use vconn::{VConn, VConnError};

/// Build the smoltcp `Interface` — the async analogue of tun2socks'
/// `core.CreateStack`.
///
/// Like gVisor's setup we:
///  * use the IP medium (TUN = raw IP packets),
///  * accept traffic for any destination (gVisor achieves this via promiscuous
///    mode + spoofing; smoltcp has no NIC promiscuous flag but the IP medium
///    already delivers all packets to `poll`, and `set_any_ip(true)` lets the
///    stack match any local address), and
///  * install default routes for v4 and v6.
pub fn build_interface(phy: &mut Phy) -> Interface {
    // Tun2socks operates on raw IP packets, so there is no hardware address.
    let config = IfaceConfig::new(HardwareAddress::Ip);
    let mut iface = Interface::new(config, phy, smoltcp::time::Instant::now());

    // Accept packets addressed to any local IP — the smoltcp equivalent of the
    // gVisor promiscuous + spoofing behaviour. (No explicit address is bound on
    // purpose, so the interface forwards by route.)
    iface.set_any_ip(true);

    // Default routes for v4 and v6 — mirrors tun2socks' withRouteTable().
    // smoltcp 0.14 uses core::net::Ipv4Addr/Ipv6Addr as its address types, so we
    // pass the std unspecified addresses directly.
    iface
        .routes_mut()
        .add_default_ipv4_route(std::net::Ipv4Addr::UNSPECIFIED)
        .ok();
    iface
        .routes_mut()
        .add_default_ipv6_route(std::net::Ipv6Addr::UNSPECIFIED)
        .ok();

    info!("[STACK] smoltcp interface ready (medium=ip, any_ip=true)");
    iface
}

/// How often the actor polls even when no timer is pending, as a safety net.
pub const IDLE_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Resolve the effective MTU, defaulting to the standard Ethernet MTU when the
/// caller leaves it at 0 (mirrors tun2socks' MTU default handling).
pub fn resolve_mtu(cfg: &Config) -> usize {
    if cfg.mtu == 0 { 1500 } else { cfg.mtu as usize }
}

/// A TCP socket allocated with heap-backed send/receive buffers. This is the
/// constructor shape used throughout smoltcp's own examples
/// (`tcp::SocketBuffer::new(vec![0; n])`).
pub fn new_tcp_socket(rx_buf: usize, tx_buf: usize) -> TcpSocket<'static> {
    let rx = SocketBuffer::new(vec![0u8; rx_buf]);
    let tx = SocketBuffer::new(vec![0u8; tx_buf]);
    TcpSocket::new(rx, tx)
}

// Phantom use to keep the `Device` import live for doc clarity.
#[allow(dead_code)]
fn _device_bound<D: Device>(_d: &D) {}
