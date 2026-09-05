//! Owns the interface and sockets on one task. Wildcard listeners retain each
//! connection's original destination for SOCKS5. Relays access sockets through
//! VConn commands, with independent pending reads and writes for full duplex I/O.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

use smoltcp::iface::{Interface, SocketHandle, SocketSet};
use smoltcp::socket::tcp::{RecvError, Socket as TcpSocket, State};
use smoltcp::time::Instant;
use smoltcp::wire::IpListenEndpoint;
use tokio::sync::{mpsc, oneshot};
use tokio::time::sleep;
use tracing::{debug, info, warn};

use super::vconn::{ConnCmd, ConnMeta, VConn, VConnError};
use crate::device::Phy;
use crate::relay;

const TCP_RX_BUF: usize = 64 * 1024;
const TCP_TX_BUF: usize = 64 * 1024;
/// Maximum simultaneous pending handshakes.
const LISTENER_POOL_SIZE: usize = 4;

pub struct NetstackHandle {
    stop: mpsc::Sender<()>,
}

impl NetstackHandle {
    pub async fn stop(&self) {
        let _ = self.stop.send(()).await;
    }
}

pub struct NetstackActor {
    iface: Interface,
    phy: Phy,
    sockets: SocketSet<'static>,
    conns: HashMap<SocketHandle, ConnState>,
    listeners: Vec<SocketHandle>,
    accepted_tx: mpsc::Sender<(VConn, ConnMeta)>,
    stop: mpsc::Receiver<()>,
}

struct PendingRead {
    max_len: usize,
    reply: oneshot::Sender<Result<Vec<u8>, VConnError>>,
}

struct PendingWrite {
    data: Vec<u8>,
    reply: oneshot::Sender<Result<usize, VConnError>>,
}

struct ConnState {
    cmd_rx: mpsc::Receiver<ConnCmd>,
    read: Option<PendingRead>,
    write: Option<PendingWrite>,
}

impl ConnState {
    fn new(cmd_rx: mpsc::Receiver<ConnCmd>) -> Self {
        Self {
            cmd_rx,
            read: None,
            write: None,
        }
    }

    /// Each relay has at most one read and one write outstanding.
    fn service(&mut self, socket: &mut TcpSocket<'_>) {
        self.service_io(socket);
        while let Ok(cmd) = self.cmd_rx.try_recv() {
            match cmd {
                ConnCmd::Read { max_len, reply } => {
                    if self.read.is_some() {
                        let _ = reply.send(Err(std::io::Error::new(
                            std::io::ErrorKind::WouldBlock,
                            "a read is already pending",
                        )
                        .into()));
                    } else {
                        self.read = Some(PendingRead { max_len, reply });
                    }
                }
                ConnCmd::Write { data, reply } => {
                    if self.write.is_some() {
                        let _ = reply.send(Err(std::io::Error::new(
                            std::io::ErrorKind::WouldBlock,
                            "a write is already pending",
                        )
                        .into()));
                    } else {
                        self.write = Some(PendingWrite { data, reply });
                    }
                }
                ConnCmd::CloseWrite { reply } => {
                    socket.close();
                    let _ = reply.send(Ok(()));
                }
                ConnCmd::Close { reply } => {
                    socket.abort();
                    let _ = reply.send(Ok(()));
                }
            }
            self.service_io(socket);
        }
    }

    fn service_io(&mut self, socket: &mut TcpSocket<'_>) {
        if let Some(read) = self.read.take() {
            if read.reply.is_closed() {
                // The caller canceled the read; leave buffered data untouched.
            } else if read.max_len == 0 {
                let _ = read.reply.send(Ok(Vec::new()));
            } else if !socket.can_recv() && socket.may_recv() {
                self.read = Some(read);
            } else {
                let mut data = vec![0; read.max_len.min(socket.recv_queue())];
                let result = match socket.recv_slice(&mut data) {
                    Ok(n) => {
                        data.truncate(n);
                        Ok(data)
                    }
                    Err(RecvError::Finished) => Ok(Vec::new()),
                    Err(RecvError::InvalidState) => Err(VConnError::Closed),
                };
                let _ = read.reply.send(result);
            }
        }
        if let Some(write) = self.write.take() {
            if write.reply.is_closed() {
                // The caller canceled the write; do not enqueue its data.
            } else if write.data.is_empty() {
                let _ = write.reply.send(Ok(0));
            } else if !socket.can_send() && socket.may_send() {
                self.write = Some(write);
            } else {
                // The relay retries any unwritten tail.
                let result = socket
                    .send_slice(&write.data)
                    .map_err(|_| VConnError::Closed);
                let _ = write.reply.send(result);
            }
        }
    }

    fn fail_pending(&mut self) {
        if let Some(read) = self.read.take() {
            let _ = read.reply.send(Err(VConnError::Closed));
        }
        if let Some(write) = self.write.take() {
            let _ = write.reply.send(Err(VConnError::Closed));
        }
    }
}

impl NetstackActor {
    fn with_channels(
        iface: Interface,
        phy: Phy,
        accepted_tx: mpsc::Sender<(VConn, ConnMeta)>,
        stop: mpsc::Receiver<()>,
    ) -> Self {
        let mut sockets = SocketSet::new(vec![]);
        let listeners = (0..LISTENER_POOL_SIZE)
            .map(|_| add_wildcard_listener(&mut sockets))
            .collect();
        Self {
            iface,
            phy,
            sockets,
            conns: HashMap::new(),
            listeners,
            accepted_tx,
            stop,
        }
    }

    pub async fn run(mut self) {
        info!("[NETSTACK] actor running");
        loop {
            let now = Instant::now();
            self.iface.poll(now, &mut self.phy, &mut self.sockets);
            self.try_accept();
            self.service_commands();
            self.iface
                .poll_egress(now, &mut self.phy, &mut self.sockets);

            // TUN packets and relay commands arrive through channels, so a
            // distant TCP timer must not postpone checking them.
            let delay = self
                .iface
                .poll_delay(now, &self.sockets)
                .map(|delay| Duration::from_millis(delay.millis()))
                .unwrap_or(super::IDLE_POLL_INTERVAL)
                .min(super::IDLE_POLL_INTERVAL);
            tokio::select! {
                _ = sleep(delay) => {}
                _ = self.stop.recv() => break,
            }
        }
        info!("[NETSTACK] actor stopping");
    }

    fn try_accept(&mut self) {
        for slot in &mut self.listeners {
            let handle = *slot;
            let socket = self.sockets.get_mut::<TcpSocket>(handle);
            match socket.state() {
                State::Listen | State::SynReceived => continue,
                // A FIN may arrive in the same poll as the final handshake ACK.
                State::Established | State::CloseWait => {
                    if let (Some(local), Some(remote)) =
                        (socket.local_endpoint(), socket.remote_endpoint())
                    {
                        let meta = ConnMeta {
                            src: SocketAddr::new(remote.addr.into(), remote.port),
                            dst: SocketAddr::new(local.addr.into(), local.port),
                        };
                        let (cmd_tx, cmd_rx) = mpsc::channel(32);
                        let vconn = VConn::new(meta, cmd_tx);
                        if self.accepted_tx.try_send((vconn, meta)).is_ok() {
                            debug!(?meta, "[NETSTACK] accepted tcp");
                            self.conns.insert(handle, ConnState::new(cmd_rx));
                            *slot = add_wildcard_listener(&mut self.sockets);
                            continue;
                        }
                        warn!("[NETSTACK] accepted queue full or closed");
                    }
                }
                _ => {}
            }
            socket.abort();
            self.sockets.remove(handle);
            *slot = add_wildcard_listener(&mut self.sockets);
        }
    }

    fn service_commands(&mut self) {
        self.conns.retain(|handle, conn| {
            let socket = self.sockets.get_mut::<TcpSocket>(*handle);
            conn.service(socket);
            if conn.cmd_rx.is_closed() && conn.cmd_rx.is_empty() {
                conn.fail_pending();
                socket.abort();
                self.sockets.remove(*handle);
                false
            } else {
                true
            }
        });
    }
}

impl NetstackActor {
    /// Spawn the poll loop and relay dispatcher; return a shutdown handle.
    pub fn spawn(
        iface: Interface,
        phy: Phy,
        proxy: std::sync::Arc<dyn crate::proxy::Proxy>,
    ) -> NetstackHandle {
        let (accepted_tx, mut accepted_rx) = mpsc::channel(64);
        let (stop_tx, stop_rx) = mpsc::channel::<()>(1);

        let actor = Self::with_channels(iface, phy, accepted_tx, stop_rx);

        tokio::spawn(actor.run());

        // Stopping the actor closes accepted_tx and ends this dispatcher.
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

/// Add a listener that preserves each connection's original destination.
fn add_wildcard_listener(sockets: &mut SocketSet<'static>) -> SocketHandle {
    let mut socket = super::new_tcp_socket(TCP_RX_BUF, TCP_TX_BUF);
    socket
        .listen(IpListenEndpoint::ANY_PORT)
        .expect("a fresh TCP socket can listen on any port");
    sockets.add(socket)
}

#[cfg(test)]
mod tests;
