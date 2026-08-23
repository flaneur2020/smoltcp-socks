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
//! ## The accept model — wildcard-port listening
//!
//! gVisor's `tcp.NewForwarder` accepts a SYN directed at *any* destination and
//! hands you a fully-formed connection. A real TUN carries connections to
//! arbitrary `(ip, port)` pairs, so tun2socks needs exactly that.
//!
//! smoltcp (with the `allow-listen-any-port` addition) lets a TCP socket
//! `listen` on [`IpListenPort::Any`], matching an inbound SYN regardless of
//! its destination port. The local endpoint reported after `accept` then
//! carries the `(dst_ip, dst_port)` the SYN actually targeted — which is the
//! original-destination the relay hands to SOCKS5. No port has to be known in
//! advance, and no SYN is ever RST'd for lacking a listener.
//!
//! A single listener accepts exactly one connection before leaving LISTEN, so
//! the actor keeps a small pool of wildcard listeners warm and replenishes it
//! as connections arrive (bounded headroom for bursty concurrent connects).

use std::collections::HashMap;
use std::time::Duration;

use smoltcp::iface::{Interface, SocketHandle, SocketSet};
use smoltcp::socket::tcp::{RecvError, SendError, Socket as TcpSocket, State};
use smoltcp::time::Instant;
use smoltcp::wire::IpListenPort;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::time::sleep;
use tracing::{debug, info, warn};

use crate::device::Phy;
use crate::relay;

use super::vconn::{ConnCmd, ConnMeta, VConn, VConnError};

/// How big each virtual socket's send/receive buffer is. gVisor uses tunable
/// sizes; we pick a conservative default and let config drive it later.
const TCP_RX_BUF: usize = 64 * 1024;
const TCP_TX_BUF: usize = 64 * 1024;
/// How many wildcard-port listening sockets to keep warm. Each one accepts
/// exactly one connection before it stops listening, so the pool is
/// replenished as connections arrive. A small pool absorbs bursty concurrent
/// connects while bounding socket count.
const LISTENERS_PER_PORT: usize = 4;
/// Historical default listen port; kept for tests that drive the old fixed-port
/// model via [`NetstackActor::with_listen_port`]/[`NetstackActor::new`].
/// Production uses wildcard-port listening (see [`NetstackActor::spawn`]).
/// Sentinel passed to [`NetstackActor::spawn`] meaning "use wildcard-port
/// listeners" (production): sockets `listen` on [`IpListenPort::Any`] and
/// accept a SYN to any `(ip, port)` without pre-warming. Any other value keeps
/// the legacy fixed-port model for tests.
pub const LAZY_LISTEN: u16 = 0;
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
    /// Every accepted connection's routing state, keyed by socket handle.
    ///
    /// This unifies what used to be two maps: the command channel (`cmd_rx`)
    /// and the at-most-one parked read/write request (`parked`). The relay
    /// serializes its read loop and its write loop, so `parked` is a single
    /// optional slot per connection, not a queue — enforced structurally by
    /// the `Option` rather than as a cross-map invariant.
    ///
    /// `parked` holds Read/Write requests that could not be completed this
    /// cycle because the smoltcp socket had nothing to dequeue (read) or no
    /// free tx space (write). smoltcp's `recv_slice`/`send_slice` return
    /// `Ok(0)` when the buffer is empty/full but the connection is still open
    /// — that is **not** EOF, so we must not reply to the relay yet. Instead
    /// we stash the reply here and retry it on subsequent [`service_commands`]
    /// cycles until the socket delivers (or closes). This makes
    /// `VConn::read`/`write` block as the relay expects, instead of
    /// spuriously truncating the stream.
    conns: HashMap<SocketHandle, ConnState>,
    /// Idle wildcard-port listening sockets. Each accepts exactly one
    /// connection (to any `(ip, port)` — see the module docs) before leaving
    /// the LISTEN state, so they are classified and replenished back to
    /// [`LISTENERS_PER_PORT`] each poll in [`try_accept`].
    listeners: Vec<SocketHandle>,
    /// `None` (production): `listeners` are wildcard-port sockets. `Some(p)`
    /// (tests): they listen on the fixed port `p`. Recorded so [`try_accept`]
    /// replenishes the pool with the right kind after recycling a slot.
    prelisten: Option<u16>,
    /// Where accepted connections are delivered.
    accepted_tx: mpsc::Sender<(VConn, ConnMeta)>,
    stop: mpsc::Receiver<()>,
}

/// Routing state for one accepted virtual connection.
///
/// `cmd_rx` is the mailbox the relay sends commands into; `parked` is the
/// at-most-one read/write request that couldn't complete this cycle (see
/// [`NetstackActor::conns`]). Keeping them in one struct makes the "one parked
/// IO per connection" invariant structural instead of a cross-map convention.
struct ConnState {
    cmd_rx: mpsc::Receiver<ConnCmd>,
    parked: Option<PendingIo>,
}

/// A relay read/write request parked until the smoltcp socket can satisfy it
/// (see [`ConnState::parked`]).
enum PendingIo {
    /// Waiting for `recv_slice` to return >0 bytes (or the socket to close).
    Read {
        max_len: usize,
        reply: oneshot::Sender<Result<Vec<u8>, VConnError>>,
    },
    /// Waiting for `send_slice` to enqueue >0 bytes (or the socket to close).
    /// `offset` is how many bytes of `data` have already been accepted; the
    /// relay retries the unsent tail until it's fully written, so we keep the
    /// whole buffer and the running offset.
    Write {
        data: Vec<u8>,
        offset: usize,
        reply: oneshot::Sender<Result<usize, VConnError>>,
    },
}

impl PendingIo {
    /// Resolve a parked request with an error (connection closed/dropped).
    fn fail(self, err: VConnError) {
        match self {
            PendingIo::Read { reply, .. } => {
                let _ = reply.send(Err(err));
            }
            PendingIo::Write { reply, .. } => {
                let _ = reply.send(Err(err));
            }
        }
    }
}

impl NetstackActor {
    /// Build the actor against externally-owned channels.
    ///
    /// The actor owns the only `stop` receiver; when it fires, the actor breaks
    /// out of its run loop and drops `accepted_tx`, which in turn causes the
    /// relay dispatcher's `recv()` to return `None` and exit. So a single stop
    /// signal cleanly tears down both tasks.
    ///
    /// `prelisten`, when `Some(p)`, pre-warms a fixed-port listener pool on port
    /// `p` (used by the test constructors to keep the old fixed-port shape).
    /// `None` means production: a wildcard-port pool (`listen` on
    /// [`IpListenPort::Any`]) that accepts a SYN to any `(ip, port)`.
    fn with_channels(
        iface: Interface,
        phy: Phy,
        accepted_tx: mpsc::Sender<(VConn, ConnMeta)>,
        stop_rx: mpsc::Receiver<()>,
        prelisten: Option<u16>,
    ) -> Self {
        let mut sockets = SocketSet::new(vec![]);

        // Production (prelisten == None) listens on a wildcard port: a small
        // pool of sockets each `listen` on `IpListenPort::Any`, so a SYN to any
        // (ip, port) finds a taker. Tests pass `Some(port)` to keep the old
        // fixed-port model on a collision-free ephemeral port.
        let mut listeners: Vec<SocketHandle> = Vec::new();
        match prelisten {
            None => {
                for _ in 0..LISTENERS_PER_PORT {
                    listeners.push(add_wildcard_listener(&mut sockets));
                }
            }
            Some(port) => {
                for _ in 0..LISTENERS_PER_PORT {
                    listeners.push(add_fixed_listener(&mut sockets, port));
                }
            }
        }

        Self {
            iface,
            phy,
            sockets,
            conns: HashMap::new(),
            listeners,
            prelisten,
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

    /// Walk the wildcard listener pool and lift completed handshakes.
    ///
    /// This runs *before* `iface.poll` in the run loop. It classifies each
    /// listening socket by state — ESTABLISHED sockets have accepted a
    /// connection (covering any `(ip, port)`, since they `listen`ed on
    /// [`IpListenPort::Any`]) and are handed to the relay dispatcher;
    /// closing/closed sockets are recycled with a fresh wildcard listener, and
    /// the pool is replenished back to [`LISTENERS_PER_PORT`]. No SYN is ever
    /// RST'd for lacking a matching listener, so there is no packet tap or
    /// re-injection here — smoltcp dispatches each SYN straight to a wildcard
    /// listener during `poll`.
    ///
    /// This is the smoltcp equivalent of gVisor's `tcp.ForwarderRequest` →
    /// `CreateEndpoint` → `h.HandleTCP(conn)` chain in `core/tcp.go`.
    fn try_accept(&mut self) {
        // Classify each listening socket by state. Established → accept;
        // closing/closed → recycle; still-listening → keep. Replenish the pool
        // back to LISTENERS_PER_PORT afterwards. Work over a fresh Vec so the
        // &mut self.sockets borrow ends before we touch self.conns below.
        let mut accepted: Vec<(
            SocketHandle,
            Option<smoltcp::wire::IpEndpoint>,
            Option<smoltcp::wire::IpEndpoint>,
        )> = Vec::new();
        let mut keep: Vec<SocketHandle> = Vec::with_capacity(self.listeners.len());
        for handle in self.listeners.drain(..) {
            let s = self.sockets.get_mut::<TcpSocket>(handle);
            match s.state() {
                State::Listen | State::SynReceived | State::SynSent => keep.push(handle),
                State::Established => {
                    let local = s.local_endpoint();
                    let remote = s.remote_endpoint();
                    debug!(?local, ?remote, "[NETSTACK] accepted tcp");
                    accepted.push((handle, local, remote));
                }
                _ => {
                    s.abort();
                    let _ = self.sockets.remove(handle);
                }
            }
        }
        // Replenish back to LISTENERS_PER_PORT with fresh wildcard listeners
        // (absorbs both recycled slots and the steady-state top-up).
        let is_wildcard = self.prelisten.is_none();
        for _ in keep.len()..LISTENERS_PER_PORT {
            keep.push(if is_wildcard {
                add_wildcard_listener(&mut self.sockets)
            } else {
                add_fixed_listener(&mut self.sockets, self.prelisten.unwrap())
            });
        }
        self.listeners = keep;

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
            self.conns.insert(
                handle,
                ConnState {
                    cmd_rx,
                    parked: None,
                },
            );

            // Best-effort delivery: if the dispatcher is slow we drop the
            // connection rather than block the poll loop.
            if self.accepted_tx.try_send((vconn, meta)).is_err() {
                warn!("[NETSTACK] accepted queue full, dropping connection");
                self.conns.remove(&handle);
                let s = self.sockets.get_mut::<TcpSocket>(handle);
                s.abort();
                let _ = self.sockets.remove(handle);
                continue;
            }
        }
    }

    /// Drain pending commands from each connection and apply them to its socket.
    fn service_commands(&mut self) {
        // 1. Retry IO parked on a previous cycle (read-no-data / write-no-room).
        // `poll` has just delivered fresh bytes / freed tx space, so a parked
        // request may now complete. We drive each parked IO through the same
        // two-phase `do_read`/`do_write` as a fresh command: a socket-borrowing
        // block computes an outcome, the borrow ends, then we either reply or
        // re-park — so the `&mut self.sockets` and the `&mut self.conns` borrows
        // never overlap.
        //
        // Collect the parked IO out of the map first so the retry pass can
        // freely mutate `conns` (re-park / reply) without holding a borrow over
        // the iteration.
        let parked: Vec<(SocketHandle, PendingIo)> = self
            .conns
            .iter_mut()
            .filter_map(|(h, st)| st.parked.take().map(|io| (*h, io)))
            .collect();
        for (handle, io) in parked {
            self.attempt_parked(handle, io);
        }

        // 2. Collect handles whose command channel has closed so we can drop
        // them, and gather all newly-arrived commands. One pass so `apply_cmd`
        // (which mutably borrows `self.sockets`) does not alias the borrow of
        // `self.conns` held by the iterator.
        let mut dead = Vec::new();
        let mut queued: Vec<(SocketHandle, ConnCmd)> = Vec::new();
        for (handle, st) in self.conns.iter_mut() {
            while let Ok(cmd) = st.cmd_rx.try_recv() {
                queued.push((*handle, cmd));
            }
            if st.cmd_rx.is_closed() && st.cmd_rx.is_empty() {
                dead.push(*handle);
            }
        }
        for (handle, cmd) in queued {
            self.apply_cmd(handle, cmd);
        }
        for h in dead {
            // Fail any still-parked IO for this connection before removing it.
            if let Some(st) = self.conns.remove(&h)
                && let Some(io) = st.parked
            {
                io.fail(VConnError::Closed);
            }
            self.sockets.get_mut::<TcpSocket>(h).abort();
            let _ = self.sockets.remove(h);
            warn!(?h, "[NETSTACK] dropped idle virtual connection");
        }
    }

    /// Re-attempt a parked read/write against its socket. If it still can't be
    /// satisfied (no data / no room, socket still open), re-park it. If the
    /// socket closed, reply with EOF/error. Otherwise complete the request.
    fn attempt_parked(&mut self, handle: SocketHandle, io: PendingIo) {
        match io {
            PendingIo::Read { max_len, reply } => {
                self.do_read(handle, max_len, reply);
            }
            PendingIo::Write {
                data,
                offset,
                reply,
            } => {
                self.do_write(handle, data, offset, reply);
            }
        }
    }

    fn apply_cmd(&mut self, handle: SocketHandle, cmd: ConnCmd) {
        // The relay serializes its read loop and its write loop, but a brand-new
        // command can still arrive for a connection that has a parked request of
        // the other kind. A parked request of the *same* kind should never
        // happen (the relay awaits each reply before issuing the next); if it
        // somehow does, fail the old one rather than silently dropping a reply.
        if let Some(st) = self.conns.get_mut(&handle)
            && let Some(existing) = st.parked.take()
        {
            let same_kind = matches!(
                (&existing, &cmd),
                (PendingIo::Read { .. }, ConnCmd::Read { .. })
                    | (PendingIo::Write { .. }, ConnCmd::Write { .. })
            );
            if same_kind {
                existing.fail(VConnError::Closed);
            } else {
                st.parked = Some(existing);
            }
        }

        match cmd {
            ConnCmd::Read { max_len, reply } => self.do_read(handle, max_len, reply),
            ConnCmd::Write { data, reply } => self.do_write(handle, data, 0, reply),
            ConnCmd::CloseWrite { reply } => {
                self.sockets.get_mut::<TcpSocket>(handle).close();
                let _ = reply.send(Ok(()));
            }
            ConnCmd::Close { reply } => {
                if let Some(st) = self.conns.get_mut(&handle)
                    && let Some(io) = st.parked.take()
                {
                    io.fail(VConnError::Closed);
                }
                self.sockets.get_mut::<TcpSocket>(handle).abort();
                let _ = reply.send(Ok(()));
            }
        }
    }

    /// Serve one read. Completes the `reply` immediately if data is available or
    /// the socket is EOF/closed; otherwise parks it in `conns[handle].parked`
    /// to retry next cycle. See [`PendingIo`] for why `Ok(0)` is not EOF.
    ///
    /// Two-phase to dodge the borrow split: the socket borrow that computes the
    /// outcome ends before we touch `self.conns` to park.
    fn do_read(
        &mut self,
        handle: SocketHandle,
        max_len: usize,
        reply: oneshot::Sender<Result<Vec<u8>, VConnError>>,
    ) {
        // Phase 1: borrow only `self.sockets`, produce an outcome.
        enum ReadOutcome {
            Data(Vec<u8>),
            Park,
            Eof,
            Closed,
        }
        let outcome = {
            let s = self.sockets.get_mut::<TcpSocket>(handle);
            let mut buf = vec![0u8; max_len];
            match s.recv_slice(&mut buf) {
                Ok(0) => {
                    // No data buffered right now. If the socket can still
                    // receive, this is a "would block", not EOF — park and
                    // retry. If it can't (e.g. half-closed), `recv_slice` would
                    // have returned `Err(Finished)` instead, so reaching here
                    // means still-open.
                    if s.may_recv() {
                        ReadOutcome::Park
                    } else {
                        ReadOutcome::Eof
                    }
                }
                Ok(n) => {
                    buf.truncate(n);
                    ReadOutcome::Data(buf)
                }
                Err(RecvError::Finished) => ReadOutcome::Eof,
                Err(RecvError::InvalidState) => ReadOutcome::Closed,
            }
        };
        // Phase 2: socket borrow is over; reply or park into `self.conns`.
        match outcome {
            ReadOutcome::Data(buf) => {
                let _ = reply.send(Ok(buf));
            }
            ReadOutcome::Eof => {
                let _ = reply.send(Ok(Vec::new()));
            }
            ReadOutcome::Closed => {
                let _ = reply.send(Err(VConnError::Closed));
            }
            ReadOutcome::Park => {
                if let Some(st) = self.conns.get_mut(&handle) {
                    st.parked = Some(PendingIo::Read { max_len, reply });
                } else {
                    // Connection was reaped between dispatch and now; the reply
                    // must still complete so the relay doesn't hang.
                    let _ = reply.send(Err(VConnError::Closed));
                }
            }
        }
    }

    /// Serve one write of `data[offset..]`. Completes the `reply` with the count
    /// once at least one byte is enqueued (the relay retries the remainder), or
    /// parks it if the tx buffer is full but the socket is still sendable.
    ///
    /// Two-phase like [`do_read`]: the socket borrow that computes the write
    /// result ends before we touch `self.conns` to park.
    fn do_write(
        &mut self,
        handle: SocketHandle,
        data: Vec<u8>,
        offset: usize,
        reply: oneshot::Sender<Result<usize, VConnError>>,
    ) {
        // Phase 1: borrow only `self.sockets`, produce the outcome.
        enum WriteOutcome {
            Written(usize),
            Park,
            Closed,
        }
        let outcome = {
            let s = self.sockets.get_mut::<TcpSocket>(handle);
            match s.send_slice(&data[offset..]) {
                Ok(0) => {
                    // Tx buffer full. If we can still send, park and retry once
                    // `poll` drains it; otherwise the connection is closing.
                    if s.may_send() {
                        WriteOutcome::Park
                    } else {
                        WriteOutcome::Closed
                    }
                }
                Ok(n) => WriteOutcome::Written(n),
                Err(SendError::InvalidState) => WriteOutcome::Closed,
            }
        };
        // Phase 2: socket borrow is over; reply or park into `self.conns`.
        match outcome {
            WriteOutcome::Written(n) => {
                // Reply with the number of freshly-accepted bytes. If only part
                // of the tail was accepted, the relay will issue another Write
                // for the remainder; we don't park-and-continue here because the
                // relay already handles partial writes by retrying, and keeping
                // ownership of `data` across cycles would complicate the
                // contract. The single-cycle `Ok(n>0)` reply is enough.
                let _ = reply.send(Ok(n));
            }
            WriteOutcome::Closed => {
                let _ = reply.send(Err(VConnError::Closed));
            }
            WriteOutcome::Park => {
                if let Some(st) = self.conns.get_mut(&handle) {
                    st.parked = Some(PendingIo::Write {
                        data,
                        offset,
                        reply,
                    });
                } else {
                    let _ = reply.send(Err(VConnError::Closed));
                }
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
    /// wildcard-port sockets (`listen` on [`IpListenPort::Any`]) that accept a
    /// SYN to any `(ip, port)`, the gVisor `NewForwarder` equivalent. A non-zero
    /// value pre-warms the legacy fixed-port listener pool on that port (tests).
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

/// Create a fresh wildcard-port listening socket and add it to the set.
///
/// `listen` on `IpListenPort::Any` (with a wildcard address) matches an inbound
/// SYN regardless of its destination `(ip, port)` — the gVisor
/// `NewForwarder` equivalent. The local endpoint reported after `accept`
/// carries the SYN's real destination, which the relay hands to SOCKS5 as the
/// original destination. No port has to be known in advance, and no SYN is
/// ever RST'd for lacking a matching listener.
fn add_wildcard_listener(sockets: &mut SocketSet<'static>) -> SocketHandle {
    use smoltcp::wire::IpListenEndpoint;
    let mut s = super::new_tcp_socket(TCP_RX_BUF, TCP_TX_BUF);
    let _ = s.listen(IpListenEndpoint {
        addr: None,
        port: IpListenPort::Any,
    });
    sockets.add(s)
}

/// Create a fresh listening socket on a fixed `port` and add it to the set
/// (the legacy single-port model, kept for tests that need a collision-free
/// ephemeral port).
fn add_fixed_listener(sockets: &mut SocketSet<'static>, listen_port: u16) -> SocketHandle {
    let mut s = super::new_tcp_socket(TCP_RX_BUF, TCP_TX_BUF);
    // `listen(port)` (the `From<u16>` for `ListenEndpoint`) sets `addr = None`,
    // matching SYNs to *any* destination IP on this one port.
    let _ = s.listen(listen_port);
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

/// Convert an smoltcp `Duration` to a `std::time::Duration`.
///
/// smoltcp's `Duration::millis()` already returns a non-negative `u64`, so no
/// clamping is needed; a past deadline simply yields a zero duration, which
/// the poll loop treats as "poll again immediately".
fn smoltcp_duration_to_std(d: smoltcp::time::Duration) -> Duration {
    Duration::from_millis(d.millis())
}
