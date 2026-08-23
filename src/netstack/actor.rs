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
//! ## The accept model — per-destination SYN interception
//!
//! gVisor's `tcp.NewForwarder` accepts a SYN directed at *any* destination and
//! hands you a fully-formed connection. A real TUN carries connections to
//! arbitrary `(ip, port)` pairs, so tun2socks needs exactly that.
//!
//! smoltcp has no forwarder API, and a TCP socket can only `listen` on a single
//! concrete port (there is no port wildcard — a listener matches exactly one
//! `dst_port`, though the address may be wildcard). Worse, when no TCP socket
//! `accepts` an inbound segment, `Interface` emits a TCP RST — which would kill
//! every connection to a port we hadn't pre-opened.
//!
//! The solution uses smoltcp's own escape hatch: a `raw` socket bound to all
//! protocols runs in `Interface`'s dispatch path *before* TCP. smoltcp enqueues
//! a copy of every IP packet into the raw socket's rx ring and sets
//! `handled_by_raw_socket = true`, which **suppresses the RST** that would
//! otherwise fire when no TCP listener matches. So every stray SYN is observed
//! without being RST'd, giving us a chance to react.
//!
//! Each poll, the actor drains the raw ring, parses each packet for a pure SYN,
//! reads its `(dst_ip, dst_port)`, and — the first time it sees a given port —
//! lazily `listen`s a pool of TCP sockets on that port, then **re-injects** the
//! SYN into `Phy::inbound_buf` so the *next* poll feeds it to the now-existing
//! listener (no client retransmit wait). Data/ACK packets on established
//! connections also hit the raw ring; they are drained and dropped (only the
//! first SYN per port is re-injected, which is what breaks the re-inject loop).

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

use smoltcp::iface::{Interface, SocketHandle, SocketSet};
use smoltcp::socket::raw::{
    PacketBuffer as RawPacketBuffer, PacketMetadata as RawPacketMetadata,
    RecvError as RawRecvError, Socket as RawSocket,
};
use smoltcp::socket::tcp::{RecvError, SendError, Socket as TcpSocket, State};
use smoltcp::time::Instant;
use smoltcp::wire::{IpProtocol, Ipv4Packet, Ipv6Packet, TcpPacket};
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
/// How many listening sockets to keep warm per observed destination port. Each
/// one can accept exactly one connection before it stops listening, so the pool
/// must be replenished as connections arrive. A small per-port pool absorbs
/// bursty concurrent connects to one port while bounding socket count.
const LISTENERS_PER_PORT: usize = 4;
/// Capacity of the raw socket's receive ring. The actor drains it every poll
/// (≤ `IDLE_POLL_INTERVAL`), so this only needs to absorb a burst between
/// polls; when full, smoltcp silently drops new raw copies (the matching TCP
/// listener still processes the original packet normally).
const RAW_RX_DEPTH: usize = 64;
/// Payload budget for the raw rx ring. Packets larger than this are recorded as
/// `RecvError::Truncated` on drain and skipped (the e2e data path does not rely
/// on the raw copy for large payloads — only SYNs, which are tiny).
const RAW_RX_PAYLOAD: usize = 64 * 1024;
/// Sentinel listen port meaning "no pre-warmed listener; create them lazily on
/// the first SYN to each port" (production).
pub const LAZY_LISTEN: u16 = 0;
/// Historical default listen port; kept for tests that drive the old fixed-port
/// model via [`NetstackActor::with_listen_port`]/[`NetstackActor::new`].
pub const DEFAULT_LISTEN_PORT: u16 = 1080;

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
    /// Idle listening sockets, grouped by the destination port each listens on.
    /// Each socket accepts exactly one connection before leaving the LISTEN
    /// state, so its pool is replenished as connections arrive. Entries are
    /// created lazily by [`drain_raw_and_ensure_listeners`] the first time a
    /// SYN for that port is observed (production); test construction may
    /// pre-warm a single port via `prelisten`.
    listeners: HashMap<u16, Vec<SocketHandle>>,
    /// The all-protocol raw socket used as the SYN tap (see the module docs).
    /// Its rx ring is drained each poll in [`drain_raw_and_ensure_listeners`].
    raw_socket: SocketHandle,
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
    ///
    /// `prelisten`, when `Some(p)`, pre-warms a listener pool on port `p`
    /// (used by the test constructors to keep the old fixed-port shape). `None`
    /// means production: every listener is created lazily on the first SYN to
    /// its port.
    fn with_channels(
        iface: Interface,
        phy: Phy,
        accepted_tx: mpsc::Sender<(VConn, ConnMeta)>,
        stop_rx: mpsc::Receiver<()>,
        prelisten: Option<u16>,
    ) -> Self {
        let mut sockets = SocketSet::new(vec![]);

        let raw_socket = add_raw_socket(&mut sockets);

        let mut listeners: HashMap<u16, Vec<SocketHandle>> = HashMap::new();
        if let Some(port) = prelisten {
            listeners.insert(port, Vec::new());
            for _ in 0..LISTENERS_PER_PORT {
                listeners
                    .get_mut(&port)
                    .unwrap()
                    .push(add_listener(&mut sockets, port));
            }
        }

        Self {
            iface,
            phy,
            sockets,
            pending: HashMap::new(),
            listeners,
            raw_socket,
            accepted_tx,
            stop: stop_rx,
        }
    }

    /// Construct a standalone actor + handle pair against the default listen
    /// port (pre-warmed, the old fixed-port shape). Used by tests that don't
    /// need the full `spawn` relay dispatcher.
    #[cfg(test)]
    pub fn new(iface: Interface, phy: Phy) -> (Self, NetstackHandle) {
        Self::with_listen_port(iface, phy, DEFAULT_LISTEN_PORT)
    }

    /// Construct a standalone actor + handle pair with a pre-warmed listener
    /// pool on `listen_port`. Used by integration tests that need the old
    /// fixed-port model on an ephemeral, collision-free port. Production uses
    /// [`NetstackActor::spawn`] (lazy listeners) instead.
    pub fn with_listen_port(
        iface: Interface,
        phy: Phy,
        listen_port: u16,
    ) -> (Self, NetstackHandle) {
        let (accepted_tx, _accepted_rx) = mpsc::channel(64);
        let (stop_tx, stop_rx) = mpsc::channel(1);
        let actor = Self::with_channels(iface, phy, accepted_tx, stop_rx, Some(listen_port));
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

    /// Walk the listener pools and lift completed handshakes.
    ///
    /// This runs *before* `iface.poll` in the run loop. It first drains the raw
    /// socket's rx ring: every observed SYN whose `dst_port` has no listener yet
    /// triggers a freshly-listened pool for that port and a re-injection of the
    /// SYN so the following `poll` feeds it to the now-existing listener. Then
    /// it classifies each listening socket by state — ESTABLISHED sockets have
    /// accepted a connection and are handed to the relay dispatcher;
    /// closing/closed sockets are recycled with a fresh listener.
    ///
    /// This is the smoltcp equivalent of gVisor's `tcp.ForwarderRequest` →
    /// `CreateEndpoint` → `h.HandleTCP(conn)` chain in `core/tcp.go`.
    fn try_accept(&mut self) {
        // 1. Drain the raw SYN tap: lazily create listeners and re-inject SYNs.
        self.drain_raw_and_ensure_listeners();

        // 2. Classify each listening socket by state.
        let mut accepted: Vec<(
            SocketHandle,
            Option<smoltcp::wire::IpEndpoint>,
            Option<smoltcp::wire::IpEndpoint>,
        )> = Vec::new();
        for (_port, pool) in self.listeners.iter_mut() {
            let mut keep = Vec::with_capacity(pool.len());
            for handle in pool.drain(..) {
                let s = self.sockets.get_mut::<TcpSocket>(handle);
                match s.state() {
                    State::Listen | State::SynReceived | State::SynSent => keep.push(handle),
                    State::Established => {
                        // Connection accepted. Read the endpoints (the metadata
                        // tun2socks attaches as `TransportEndpointID`).
                        let local = s.local_endpoint();
                        let remote = s.remote_endpoint();
                        debug!(?local, ?remote, "[NETSTACK] accepted tcp");
                        accepted.push((handle, local, remote));
                    }
                    _ => {
                        // Closing/closed — drop the slot; the top-up pass below
                        // replenishes the pool with a fresh listener.
                        s.abort();
                        let _ = self.sockets.remove(handle);
                    }
                }
            }
            *pool = keep;
        }
        // Replenish every pool back to LISTENERS_PER_PORT (absorbs both recycled
        // slots and the first-connect case where a pool was just created empty).
        let mut to_top_up: Vec<u16> = Vec::new();
        for (&port, pool) in self.listeners.iter() {
            for _ in pool.len()..LISTENERS_PER_PORT {
                to_top_up.push(port);
            }
        }
        for port in to_top_up {
            self.listeners
                .entry(port)
                .or_default()
                .push(add_listener(&mut self.sockets, port));
        }

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

    /// Drain the raw socket's rx ring and lazily create listeners for any
    /// destination port we see a pure SYN for.
    ///
    /// `raw_socket` queues a copy of *every* IP packet (SYN, data, ACK, …);
    /// smoltcp also sets `handled_by_raw_socket = true`, which suppresses the
    /// RST for unmatched SYNs. We only act on pure SYNs (`syn() && !ack()`):
    ///
    /// * first SYN for a `dst_port` we have no listener for → create a
    ///   `LISTENERS_PER_PORT` pool on that port, then `phy.reinject(syn)` so
    ///   the next `poll` feeds the SYN to the now-existing listener (no client
    ///   retransmit wait);
    /// * SYN for a port we already serve → drop the copy; the listener (or a
    ///   sibling in the pool) handles the original via `process_tcp`.
    ///
    /// Non-SYN packets are drained and dropped (harmless observation overhead).
    fn drain_raw_and_ensure_listeners(&mut self) {
        // Work on a local list of (port-to-create, syn-to-reinject) so the
        // borrows of `self.sockets` (raw recv + add_listener) and `self.phy`
        // (reinject) don't alias across the loop.
        let mut ensure: Vec<u16> = Vec::new();
        let mut reinject: Option<Vec<u8>> = None;

        loop {
            let mut buf = vec![0u8; RAW_RX_PAYLOAD];
            let n = {
                let raw = self.sockets.get_mut::<RawSocket>(self.raw_socket);
                match raw.recv_slice(&mut buf) {
                    Ok(n) => n,
                    Err(RawRecvError::Exhausted) => break,
                    Err(RawRecvError::Truncated) => continue, // larger than our buffer; skip
                }
            };
            buf.truncate(n);
            let Some((src, _sport, dst, dport)) = parse_tcp_syn(&buf) else {
                continue; // not a pure SYN; drop the raw copy.
            };
            if self.listeners.contains_key(&dport) {
                continue; // already served; the TCP listener handles the original.
            }
            // New destination port: create a pool and re-inject this SYN.
            if !ensure.contains(&dport) {
                ensure.push(dport);
            }
            // Re-inject only the first SYN that triggered creation for this
            // port (subsequent first-SYNs in the same drain loop are redundant;
            // the re-injected one plus the listener is enough to start the
            // handshake, and any others will be RST-suppressed until the
            // listener is up, then accepted).
            if reinject.is_none() {
                reinject = Some(buf.clone());
            }
            debug!(%src, %dst, port = dport, "[NETSTACK] first SYN for port, creating listener");
            let _ = (src, dst);
        }

        for port in ensure {
            self.ensure_listener_pool(port);
        }
        if let Some(pkt) = reinject {
            self.phy.reinject(pkt);
        }
    }

    /// Create a fresh `LISTENERS_PER_PORT` pool of listening sockets on `port`.
    /// Called the first time a SYN for `port` is observed.
    fn ensure_listener_pool(&mut self, port: u16) {
        let pool = self.listeners.entry(port).or_default();
        for _ in pool.len()..LISTENERS_PER_PORT {
            pool.push(add_listener(&mut self.sockets, port));
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
            ConnCmd::Read { max_len, reply } => {
                let mut buf = vec![0u8; max_len];
                let res = match s.recv_slice(&mut buf) {
                    Ok(0) => Ok(Vec::new()),
                    Ok(n) => {
                        buf.truncate(n);
                        Ok(buf)
                    }
                    Err(RecvError::Finished) => Ok(Vec::new()),
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
    ///
    /// `listen_port`: pass [`LAZY_LISTEN`] (0) for production — listeners are
    /// created lazily on the first SYN to each observed destination port (the
    /// gVisor `NewForwarder` equivalent). A non-zero value pre-warms the legacy
    /// fixed-port listener pool on that port (used by tests).
    pub fn spawn(
        iface: Interface,
        phy: Phy,
        proxy: std::sync::Arc<dyn crate::proxy::Proxy>,
        listen_port: u16,
    ) -> NetstackHandle {
        let (accepted_tx, mut accepted_rx) = mpsc::channel(64);
        let (stop_tx, stop_rx) = mpsc::channel::<()>(1);

        let prelisten = (listen_port != LAZY_LISTEN).then_some(listen_port);
        // Build the actor against the shared channels.
        let actor = Self::with_channels(iface, phy, accepted_tx, stop_rx, prelisten);

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

/// Create a fresh listening socket on `listen_port` and add it to the set.
fn add_listener(sockets: &mut SocketSet<'static>, listen_port: u16) -> SocketHandle {
    let mut s = super::new_tcp_socket(TCP_RX_BUF, TCP_TX_BUF);
    // Listen on a wildcard address: smoltcp's `listen(port)` (the `From<u16>`
    // for `ListenEndpoint`) sets `addr = None`, which matches SYNs to *any*
    // destination IP. That is the closest the fixed-port model gets to gVisor's
    // NewForwarder behaviour — it still constrains connections to a single port
    // (the per-destination `TODO(smoltcp)` above lifts that too), but at least
    // any source/destination IP pair is accepted.
    let _ = s.listen(listen_port);
    sockets.add(s)
}

/// Create the all-protocol raw socket used as the SYN tap (see the module
/// docs) and add it to the set. `None, None` matches every IP version and
/// protocol, so smoltcp enqueues a copy of every inbound packet into its rx
/// ring and sets `handled_by_raw_socket = true` (suppressing the RST that
/// would otherwise fire for SYNs with no matching TCP listener).
fn add_raw_socket(sockets: &mut SocketSet<'static>) -> SocketHandle {
    let rx = RawPacketBuffer::new(
        vec![RawPacketMetadata::EMPTY; RAW_RX_DEPTH],
        vec![0u8; RAW_RX_PAYLOAD],
    );
    // The raw socket never sends (we only tap inbound); an empty tx ring
    // satisfies the constructor.
    let tx = RawPacketBuffer::new(Vec::new(), Vec::new());
    let raw = RawSocket::new(None, None, rx, tx);
    sockets.add(raw)
}

/// Inspect a raw IP packet and, if it is a pure TCP SYN, return its
/// `(src_ip, src_port, dst_ip, dst_port)` 4-tuple. Returns `None` for anything
/// else (non-SYN, non-TCP, malformed) so the caller can drop the raw copy.
///
/// Uses the low-level wire packet getters directly (flag bits + port fields)
/// rather than the full `TcpRepr::parse`, avoiding a redundant checksum verify
/// — smoltcp already accepted the packet into the raw ring. The version is read
/// from the first nibble, mirroring the `tun` crate's own `is_ipv6`.
fn parse_tcp_syn(pkt: &[u8]) -> Option<(IpAddr, u16, IpAddr, u16)> {
    if pkt.is_empty() {
        return None;
    }
    match pkt[0] >> 4 {
        4 => {
            let ip = Ipv4Packet::new_checked(pkt).ok()?;
            if ip.next_header() != IpProtocol::Tcp {
                return None;
            }
            let payload = ip.payload();
            let tcp = TcpPacket::new_checked(payload).ok()?;
            if !tcp.syn() || tcp.ack() {
                return None;
            }
            Some((
                IpAddr::V4(ip.src_addr()),
                tcp.src_port(),
                IpAddr::V4(ip.dst_addr()),
                tcp.dst_port(),
            ))
        }
        6 => {
            let ip = Ipv6Packet::new_checked(pkt).ok()?;
            if ip.next_header() != IpProtocol::Tcp {
                return None;
            }
            let payload = ip.payload();
            let tcp = TcpPacket::new_checked(payload).ok()?;
            if !tcp.syn() || tcp.ack() {
                return None;
            }
            Some((
                IpAddr::V6(ip.src_addr()),
                tcp.src_port(),
                IpAddr::V6(ip.dst_addr()),
                tcp.dst_port(),
            ))
        }
        _ => None,
    }
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

/// Convert an smoltcp `Duration` to a `std::time::Duration`.
///
/// smoltcp's `Duration::millis()` already returns a non-negative `u64`, so no
/// clamping is needed; a past deadline simply yields a zero duration, which
/// the poll loop treats as "poll again immediately".
fn smoltcp_duration_to_std(d: smoltcp::time::Duration) -> Duration {
    Duration::from_millis(d.millis())
}

/// A real command receiver is only available after `try_accept` creates one; to
/// keep the `pending` map's value type uniform we use this thin wrapper.
impl NetstackActor {
    #[allow(dead_code)]
    fn _state_used(_s: State) {}
}

#[cfg(test)]
mod tests {
    use super::parse_tcp_syn;
    use smoltcp::phy::ChecksumCapabilities;
    use smoltcp::wire::{
        IpAddress, IpProtocol, Ipv4Packet, Ipv4Repr, TcpControl, TcpPacket, TcpRepr, TcpSeqNumber,
    };
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    /// Emit a raw IPv4 packet carrying `tcp` as payload, with correct checksums
    /// (smoltcp verifies both in `new_checked`).
    fn build_v4(src: Ipv4Addr, dst: Ipv4Addr, tcp: &TcpRepr) -> Vec<u8> {
        let ip = Ipv4Repr {
            src_addr: src,
            dst_addr: dst,
            next_header: IpProtocol::Tcp,
            payload_len: tcp.buffer_len(),
            hop_limit: 64,
        };
        let mut buf = vec![0u8; ip.buffer_len() + tcp.buffer_len()];
        let caps = ChecksumCapabilities::default();
        {
            let mut p = Ipv4Packet::new_unchecked(&mut buf[..ip.buffer_len()]);
            ip.emit(&mut p, &caps);
        }
        {
            let mut p = TcpPacket::new_unchecked(&mut buf[ip.buffer_len()..]);
            tcp.emit(&mut p, &IpAddress::Ipv4(src), &IpAddress::Ipv4(dst), &caps);
        }
        buf
    }

    #[test]
    fn parse_tcp_syn_recognizes_a_pure_syn() {
        let syn = TcpRepr {
            src_port: 54321,
            dst_port: 443,
            control: TcpControl::Syn,
            seq_number: TcpSeqNumber(100),
            ack_number: None,
            window_len: 65535,
            window_scale: None,
            max_seg_size: Some(1400),
            sack_permitted: false,
            sack_ranges: [None; 3],
            timestamp: None,
            payload: &[],
        };
        let pkt = build_v4(
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(172, 66, 0, 227),
            &syn,
        );
        let (src, sport, dst, dport) = parse_tcp_syn(&pkt).expect("a pure SYN parses");
        assert_eq!(src, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        assert_eq!(sport, 54321);
        assert_eq!(dst, IpAddr::V4(Ipv4Addr::new(172, 66, 0, 227)));
        assert_eq!(dport, 443);
    }

    #[test]
    fn parse_tcp_syn_rejects_ack_and_data() {
        // A pure ACK (control None, ack_number set) must not be treated as a SYN.
        let ack = TcpRepr {
            src_port: 54321,
            dst_port: 443,
            control: TcpControl::None,
            seq_number: TcpSeqNumber(101),
            ack_number: Some(TcpSeqNumber(1)),
            window_len: 65535,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None; 3],
            timestamp: None,
            payload: &[],
        };
        let pkt = build_v4(
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(172, 66, 0, 227),
            &ack,
        );
        assert!(parse_tcp_syn(&pkt).is_none(), "an ACK is not a pure SYN");

        // A data segment (Psh + payload) is not a SYN either.
        let data = TcpRepr {
            control: TcpControl::Psh,
            payload: b"hello",
            ..ack
        };
        let pkt = build_v4(
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(172, 66, 0, 227),
            &data,
        );
        assert!(
            parse_tcp_syn(&pkt).is_none(),
            "a data segment is not a pure SYN"
        );

        // A SYN-ACK (syn + ack) is rejected — only a pure connection-opening SYN
        // is re-injected; a SYN-ACK here would be from an external peer we didn't
        // initiate toward, not a flow to terminate.
        let synack = TcpRepr {
            control: TcpControl::Syn,
            ack_number: Some(TcpSeqNumber(1)),
            max_seg_size: Some(1400),
            payload: &[],
            ..ack
        };
        let pkt = build_v4(
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(172, 66, 0, 227),
            &synack,
        );
        assert!(parse_tcp_syn(&pkt).is_none(), "a SYN-ACK is not a pure SYN");
    }

    #[test]
    fn parse_tcp_syn_rejects_non_tcp_and_garbage() {
        // An IPv4 packet carrying UDP must parse but be rejected by the protocol check.
        let udp_ip = Ipv4Repr {
            src_addr: Ipv4Addr::new(10, 0, 0, 2),
            dst_addr: Ipv4Addr::new(172, 66, 0, 227),
            next_header: IpProtocol::Udp,
            payload_len: 8,
            hop_limit: 64,
        };
        let mut buf = vec![0u8; udp_ip.buffer_len() + 8];
        let caps = ChecksumCapabilities::default();
        let mut p = Ipv4Packet::new_unchecked(&mut buf);
        udp_ip.emit(&mut p, &caps);
        assert!(parse_tcp_syn(&buf).is_none());

        // Garbage / empty input.
        assert!(parse_tcp_syn(&[]).is_none());
        assert!(parse_tcp_syn(&[0u8; 20]).is_none());

        let _ = Ipv6Addr::LOCALHOST; // keep the Ipv6 import live if v6 path is unused on this target
    }
}
