//! Virtual TCP connection — mirrors tun2socks' `core/adapter.TCPConn`.
//!
//! A [`VConn`] is the relay-facing façade over a smoltcp TCP socket that lives
//! inside the actor's `SocketSet`. Because smoltcp forbids sharing the socket
//! across threads, every read/write/close is a message to the actor, which
//! services it during its poll loop and replies.

use std::net::SocketAddr;

use thiserror::Error;
use tokio::sync::{mpsc, oneshot};

/// The original-destination metadata, equivalent to the
/// `stack.TransportEndpointID` tun2socks attaches to each connection.
#[derive(Debug, Clone, Copy)]
pub struct ConnMeta {
    /// Where the in-TUN client connected *from* (its address:port).
    pub src: SocketAddr,
    /// Where the in-TUN client connected *to* (the local addr:port the stack
    /// accepted on). This is the destination the relay asks SOCKS5 to reach.
    pub dst: SocketAddr,
}

/// Requests the relay sends to the actor for a given virtual connection.
pub enum ConnCmd {
    /// Read up to `max_len` bytes from the virtual socket. The actor returns the
    /// *bytes actually read* (not just a count): because the smoltcp socket
    /// lives in the actor, the data can't be written back into the caller's
    /// buffer, so it travels through the reply channel instead.
    Read {
        max_len: usize,
        reply: oneshot::Sender<Result<Vec<u8>, VConnError>>,
    },
    Write {
        data: Vec<u8>,
        reply: oneshot::Sender<Result<usize, VConnError>>,
    },
    /// Half-close the write side, mirroring tun2socks' `CloseWrite` in
    /// `unidirectional_stream`.
    CloseWrite {
        reply: oneshot::Sender<Result<(), VConnError>>,
    },
    Close {
        reply: oneshot::Sender<Result<(), VConnError>>,
    },
}

/// Errors surfaced to the relay through a [`VConn`].
#[derive(Debug, Error)]
pub enum VConnError {
    #[error("connection closed")]
    Closed,
    /// Distinct from [`VConnError::Closed`] for a hard RST/abort. The current
    /// actor maps smoltcp's `InvalidState` to `Closed`; a fuller impl that
    /// inspects the TCP state would return `Reset` on an RST. Kept so the relay
    /// can branch on it without an API change later.
    #[error("connection reset")]
    #[allow(dead_code)]
    Reset,
    #[error("actor stopped")]
    ActorGone,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// A handle giving a relay task async read/write access to its virtual socket.
///
/// Cloneable so the two directions of the bidirectional relay (origin→remote,
/// remote→origin, as in tun2socks' `pipe`) can each hold a copy.
/// One read and one write may wait concurrently; another request in the same
/// direction returns `WouldBlock`.
#[derive(Clone)]
pub struct VConn {
    pub meta: ConnMeta,
    cmd: mpsc::Sender<ConnCmd>,
}

impl VConn {
    pub fn new(meta: ConnMeta, cmd: mpsc::Sender<ConnCmd>) -> Self {
        Self { meta, cmd }
    }

    /// The destination the original TUN connection wanted to reach — this is
    /// what gets handed to the SOCKS5 `CONNECT`.
    pub fn destination(&self) -> SocketAddr {
        self.meta.dst
    }

    pub async fn read(&self, max_len: usize) -> Result<Vec<u8>, VConnError> {
        let (tx, rx) = oneshot::channel();
        self.cmd
            .send(ConnCmd::Read { max_len, reply: tx })
            .await
            .map_err(|_| VConnError::ActorGone)?;
        rx.await.map_err(|_| VConnError::ActorGone)?
    }

    pub async fn write(&self, data: &[u8]) -> Result<usize, VConnError> {
        let (tx, rx) = oneshot::channel();
        self.cmd
            .send(ConnCmd::Write {
                data: data.to_vec(),
                reply: tx,
            })
            .await
            .map_err(|_| VConnError::ActorGone)?;
        rx.await.map_err(|_| VConnError::ActorGone)?
    }

    pub async fn close_write(&self) -> Result<(), VConnError> {
        let (tx, rx) = oneshot::channel();
        self.cmd
            .send(ConnCmd::CloseWrite { reply: tx })
            .await
            .map_err(|_| VConnError::ActorGone)?;
        rx.await.map_err(|_| VConnError::ActorGone)?
    }

    pub async fn close(&self) -> Result<(), VConnError> {
        let (tx, rx) = oneshot::channel();
        self.cmd
            .send(ConnCmd::Close { reply: tx })
            .await
            .map_err(|_| VConnError::ActorGone)?;
        rx.await.map_err(|_| VConnError::ActorGone)?
    }
}
