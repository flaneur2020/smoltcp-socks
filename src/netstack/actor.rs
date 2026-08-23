//! Netstack actor — the single owner of the smoltcp `Interface`.
//!
//! This is the heart of the scaffold and the part that diverges most from
//! tun2socks. gVisor lets you hand a `gonet.TCPConn` off to arbitrary goroutines
//! that call blocking `Read`/`Write`; smoltcp has no such luxury — exactly one
//! task may touch the `Interface` and its sockets. The actor pattern reconciles
//! the two:
//!
//! * one task runs `Interface::poll` in a loop (the equivalent of gVisor's
//!   internal dispatcher),
//! * accepted TCP handshakes (gVisor's `tcp.NewForwarder` callback) are turned
//!   into a [`VConn`] delivered over a channel, and
//! * each [`VConn`] ships its read/write/close as commands back into the actor,
//!   which services them right after the next `poll`.
//!
//! ## The accept model (important design note)
//!
//! gVisor's `tcp.NewForwarder` accepts a SYN directed at *any* destination and
//! hands you a fully-formed connection. **smoltcp cannot do that**: a TCP socket
//! can only `listen` on a concrete `(addr, port)`, and there is no `accept()` —
//! the listening socket itself transitions to `ESTABLISHED` when a peer
//! connects. To accept several concurrent connections you must pre-allocate a
//! *pool* of listening sockets, one per in-flight connection.
//!
//! Because tun2socks must terminate connections to arbitrary `(ip, port)`
//! pairs coming through the TUN, the real solution (left as the marked TODO
//! below) is to intercept incoming SYNs at the IP layer and lazily create a
//! listening socket bound to that exact destination. The scaffold implements the
//! simpler "listener pool on a fixed port" shape to prove the data path; the
//! per-destination extension is the single hardest porting task and is called
//! out plainly so it is not lost.

use std::collections::HashMap;
use std::time::Duration;

use smoltcp::iface::{Interface, SocketHandle, SocketSet};
use smoltcp::socket::tcp::{RecvError, SendError, Socket as TcpSocket, State};
use smoltcp::time::Instant;
use tokio::sync::mpsc;
use tokio::time::sleep;
use tracing::{debug, info, warn};

use crate::device::Phy;
use crate::relay;

use super::vconn::{ConnCmd, ConnMeta, VConn, VConnError};

/// How big each virtual socket's send/receive buffer is. gVisor uses tunable
/// sizes; we pick a conservative default and let config drive it later.
const TCP_RX_BUF: usize = 64 * 1024;
const TCP_TX_BUF: usize = 64 * 1024;
/// How many idle listening sockets to keep warm for incoming handshakes. Each
/// one can accept exactly one connection before it stops listening, so the pool
/// must be replenished as connections arrive.
const LISTENER_POOL_SIZE: usize = 16;

/// Handle held by the runtime to interact with the actor.
///
/// The accepted-connection receiver lives inside the relay dispatcher task
/// spawned by [`NetstackActor::spawn`], so this handle only carries a shutdown
/// signal — which is all the runtime needs once the actor is running.
pub struct NetstackHandle {
    /// Send a shutdown signal to the actor + dispatcher tasks.
    stop: mpsc::Sender<()>,
}

impl NetstackHandle {
    pub async fn stop(&self) {
        let _ = self.stop.send(()).await;
    }
}

/// The running actor.
pub struct NetstackActor {
    iface: Interface,
    phy: Phy,
    sockets: SocketSet<'static>,
    /// Pending commands per connection, keyed by socket handle.
    pending: HashMap<SocketHandle, mpsc::Receiver<ConnCmd>>,
    /// Idle listening sockets available to accept a new connection. Each is
    /// consumed (transitioned to ESTABLISHED) on accept.
    listeners: Vec<SocketHandle>,
    /// Where accepted connections are delivered.
    accepted_tx: mpsc::Sender<(VConn, ConnMeta)>,
    stop: mpsc::Receiver<()>,
}

impl NetstackActor {
    /// Build the actor against externally-owned channels.
    ///
    /// The actor owns the only `stop` receiver; when it fires, the actor breaks
    /// out of its run loop and drops `accepted_tx`, which in turn causes the
    /// relay dispatcher's `recv()` to return `None` and exit. So a single stop
    /// signal cleanly tears down both tasks.
    fn with_channels(
        iface: Interface,
        phy: Phy,
        accepted_tx: mpsc::Sender<(VConn, ConnMeta)>,
        stop_rx: mpsc::Receiver<()>,
    ) -> Self {
        let mut sockets = SocketSet::new(vec![]);

        // Pre-warm the listener pool, the smoltcp-correct way to accept several
        // concurrent connections.
        // TODO(smoltcp): to terminate SYNs addressed to *arbitrary* destinations
        //   (the gVisor NewForwarder behaviour tun2socks relies on), replace
        //   this fixed-port pool with an IP-layer SYN-interception path that
        //   lazily creates a listener bound to each observed (dst_ip, dst_port).
        let mut listeners = Vec::new();
        for _ in 0..LISTENER_POOL_SIZE {
            listeners.push(add_listener(&mut sockets));
        }

        Self {
            iface,
            phy,
            sockets,
            pending: HashMap::new(),
            listeners,
            accepted_tx,
            stop: stop_rx,
        }
    }

    /// Construct a standalone actor + handle pair (used by tests; the full
    /// runtime path goes through `spawn`, which is why this is otherwise dead).
    #[allow(dead_code)]
    pub fn new(iface: Interface, phy: Phy) -> (Self, NetstackHandle) {
        let (accepted_tx, _accepted_rx) = mpsc::channel(64);
        let (stop_tx, stop_rx) = mpsc::channel(1);
        let actor = Self::with_channels(iface, phy, accepted_tx, stop_rx);
        let handle = NetstackHandle { stop: stop_tx };
        (actor, handle)
    }

    /// Run the poll loop until stopped. This never awaits on smoltcp itself —
    /// only on tokio timers and the command plumbing.
    pub async fn run(mut self) {
        info!("[NETSTACK] actor running");
        loop {
            // 1. Lift any completed handshakes from the listener pool.
            self.try_accept();

            // 2. Service pending per-connection commands against their sockets.
            self.service_commands();

            // 3. Poll the interface — the sync, single-owner call. Its return
            //    only tells us whether any socket changed state (we do not need
            //    to branch on it here; the per-socket inspections above/below
            //    are sufficient).
            let now = Instant::now();
            let _ = self.iface.poll(now, &mut self.phy, &mut self.sockets);

            // 4. Decide how long to sleep before the next poll.
            let delay = self
                .iface
                .poll_delay(now, &self.sockets)
                .map(smoltcp_duration_to_std)
                .unwrap_or(super::IDLE_POLL_INTERVAL);

            // Interleave the sleep with stop checks so shutdown is snappy.
            tokio::select! {
                _ = sleep(delay) => {}
                _ = self.stop.recv() => {
                    info!("[NETSTACK] actor stopping");
                    break;
                }
            }
        }
    }

    /// Walk the listener pool: any socket that has transitioned out of the
    /// LISTEN state has accepted a connection. Hand it to the relay dispatcher
    /// and replenish the pool with a fresh listener.
    ///
    /// This is the smoltcp equivalent of gVisor's `tcp.ForwarderRequest` →
    /// `CreateEndpoint` → `h.HandleTCP(conn)` chain in `core/tcp.go`.
    fn try_accept(&mut self) {
        let mut accepted = Vec::new();
        let mut still_listening = Vec::new();
        for handle in self.listeners.drain(..) {
            let s = self.sockets.get_mut::<TcpSocket>(handle);
            match s.state() {
                State::Listen => still_listening.push(handle),
                State::SynReceived | State::SynSent => still_listening.push(handle),
                State::Established => {
                    // Connection accepted. Read the endpoints (the metadata
                    // tun2socks attaches as `TransportEndpointID`).
                    let local = s.local_endpoint();
                    let remote = s.remote_endpoint();
                    debug!(?local, ?remote, "[NETSTACK] accepted tcp");
                    accepted.push((handle, local, remote));
                }
                _ => {
                    // Closing/closed — recycle the slot with a fresh listener.
                    s.abort();
                    let _ = self.sockets.remove(handle);
                    still_listening.push(add_listener(&mut self.sockets));
                }
            }
        }
        self.listeners = still_listening;

        for (handle, local, remote) in accepted {
            let Some(dst) = local.and_then(to_socket_addr) else {
                continue;
            };
            let Some(src) = remote.and_then(to_socket_addr) else {
                continue;
            };

            let (cmd_tx, cmd_rx) = mpsc::channel(32);
            let meta = ConnMeta { src, dst };
            let vconn = VConn::new(meta, cmd_tx);

            // Keep the command receiver bound to this connection's socket. We
            // stash it before delivering the VConn so there is no window in
            // which a relay command arrives with no entry to drain it from.
            self.pending.insert(handle, cmd_rx);

            // Best-effort delivery: if the dispatcher is slow we drop the
            // connection rather than block the poll loop.
            if self.accepted_tx.try_send((vconn, meta)).is_err() {
                warn!("[NETSTACK] accepted queue full, dropping connection");
                self.pending.remove(&handle);
                let s = self.sockets.get_mut::<TcpSocket>(handle);
                s.abort();
                let _ = self.sockets.remove(handle);
                continue;
            }
        }
    }

    /// Drain pending commands from each connection and apply them to its socket.
    fn service_commands(&mut self) {
        // Collect handles whose command channel has closed so we can drop them,
        // and gather all pending commands. We do this in one pass so `apply_cmd`
        // (which mutably borrows `self.sockets`) does not alias the borrow of
        // `self.pending` held by the iterator.
        let mut dead = Vec::new();
        let mut queued: Vec<(SocketHandle, ConnCmd)> = Vec::new();
        for (handle, rx) in self.pending.iter_mut() {
            while let Ok(cmd) = rx.try_recv() {
                queued.push((*handle, cmd));
            }
            if rx.is_closed() && rx.is_empty() {
                dead.push(*handle);
            }
        }
        for (handle, cmd) in queued {
            self.apply_cmd(handle, cmd);
        }
        for h in dead {
            self.pending.remove(&h);
            self.sockets.get_mut::<TcpSocket>(h).abort();
            let _ = self.sockets.remove(h);
            warn!(?h, "[NETSTACK] dropped idle virtual connection");
        }
    }

    fn apply_cmd(&mut self, handle: SocketHandle, cmd: ConnCmd) {
        let s = self.sockets.get_mut::<TcpSocket>(handle);
        match cmd {
            ConnCmd::Read { mut buf, reply } => {
                let res = match s.recv_slice(&mut buf) {
                    Ok(0) => Ok(0),
                    Ok(n) => Ok(n),
                    Err(RecvError::Finished) => Ok(0),
                    Err(RecvError::InvalidState) => Err(VConnError::Closed),
                };
                let _ = reply.send(res);
            }
            ConnCmd::Write { data, reply } => {
                let res = match s.send_slice(&data) {
                    Ok(n) => Ok(n),
                    Err(SendError::InvalidState) => Err(VConnError::Closed),
                };
                let _ = reply.send(res);
            }
            ConnCmd::CloseWrite { reply } => {
                s.close(); // returns ()
                let _ = reply.send(Ok(()));
            }
            ConnCmd::Close { reply } => {
                s.abort();
                let _ = reply.send(Ok(()));
            }
        }
    }
}

impl NetstackActor {
    /// Spawn the actor and its relay dispatcher together. Returns a handle the
    /// runtime uses for shutdown only (the accepted-connection consumption is
    /// driven out of the dispatcher task spawned here).
    pub fn spawn(
        iface: Interface,
        phy: Phy,
        proxy: std::sync::Arc<dyn crate::proxy::Proxy>,
    ) -> NetstackHandle {
        let (accepted_tx, mut accepted_rx) = mpsc::channel(64);
        let (stop_tx, stop_rx) = mpsc::channel::<()>(1);

        // Build the actor against the shared channels.
        let actor = Self::with_channels(iface, phy, accepted_tx, stop_rx);

        // The actor poll loop — the gVisor dispatcher equivalent. When the
        // runtime sends stop, this breaks, dropping `accepted_tx`.
        tokio::spawn(async move {
            actor.run().await;
        });

        // Relay dispatcher: the async sibling of tun2socks' `tunnel.process`,
        // which reads from `tcpQueue` and launches a per-connection `pipe`.
        // It owns the accepted-connection receiver and exits when that channel
        // closes (i.e. when the actor task has dropped its sender on shutdown).
        tokio::spawn(async move {
            while let Some((vconn, meta)) = accepted_rx.recv().await {
                let proxy = proxy.clone();
                tokio::spawn(async move {
                    if let Err(e) = relay::pipe(vconn, meta, proxy).await {
                        warn!("[RELAY] connection ended: {e:#}");
                    }
                });
            }
        });

        NetstackHandle { stop: stop_tx }
    }
}

// ---- helpers ---------------------------------------------------------------

/// Create a fresh listening socket and add it to the set.
fn add_listener(sockets: &mut SocketSet<'static>) -> SocketHandle {
    let mut s = super::new_tcp_socket(TCP_RX_BUF, TCP_TX_BUF);
    // Listen on any interface. Note: smoltcp requires a concrete, non-zero port
    // to listen on — see the module-level design note about per-destination
    // listeners. We listen on a placeholder port here; the scaffold proves the
    // data path, and TODO(smoltcp) above covers the wildcard extension.
    let _ = s.listen((
        smoltcp::wire::IpAddress::v4(0, 0, 0, 0),
        1080u16,
    ));
    sockets.add(s)
}

/// Convert an smoltcp `IpEndpoint` into a std `SocketAddr`.
///
/// smoltcp 0.14's `Address` enum holds `core::net::Ipv4Addr`/`Ipv6Addr` directly
/// (`Ipv4Address` is a re-export of `std::net::Ipv4Addr`), so the conversion is a
/// straightforward `Into`.
fn to_socket_addr(ep: smoltcp::wire::IpEndpoint) -> Option<std::net::SocketAddr> {
    use smoltcp::wire::IpAddress;
    use std::net::SocketAddr;
    let ip: std::net::IpAddr = match ep.addr {
        IpAddress::Ipv4(v4) => std::net::IpAddr::V4(v4),
        IpAddress::Ipv6(v6) => std::net::IpAddr::V6(v6),
    };
    Some(SocketAddr::new(ip, ep.port))
}

/// Convert an smoltcp `Duration` to a `std::time::Duration`, clamping negatives
/// to zero (a past deadline means "poll immediately").
fn smoltcp_duration_to_std(d: smoltcp::time::Duration) -> Duration {
    let ms = d.millis();
    if ms <= 0 {
        Duration::ZERO
    } else {
        Duration::from_millis(ms as u64)
    }
}

/// A real command receiver is only available after `try_accept` creates one; to
/// keep the `pending` map's value type uniform we use this thin wrapper.
impl NetstackActor {
    #[allow(dead_code)]
    fn _state_used(_s: State) {}
}
