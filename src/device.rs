//! TUN ↔ smoltcp device adapter — mirrors tun2socks' `core/device/*`.
//!
//! smoltcp wants a `phy::Device` (a token-based `receive`/`transmit` model) while
//! the `tun` crate gives an async `AsyncDevice` (AsyncRead/AsyncWrite of raw IP
//! packets). This module bridges them.
//!
//! smoltcp's `phy::Device` trait is synchronous, so we cannot poll the tokio TUN
//! handle directly from inside it. The scaffold therefore uses a pair of tokio
//! mpsc channels between the async TUN pump task and the synchronous `Phy` impl
//! that smoltcp polls: the TUN task pushes inbound packets in and drains
//! outbound packets out. This keeps the single sync `Interface::poll` loop free
//! of await points.

use std::collections::VecDeque;

use smoltcp::phy::{self, DeviceCapabilities, Medium};
use tokio::sync::mpsc;
use tracing::trace;

/// Maximum number of packets buffered between the async TUN pump and the sync
/// smoltcp poll loop. Mirrors the implicit queueing in gVisor's link endpoint.
const QUEUE_DEPTH: usize = 1024;

/// Owned packet buffer passed around the channels. We copy out of the TUN fd's
/// buffer because smoltcp and the `tun` crate have disjoint lifetimes.
pub type Packet = Vec<u8>;

/// The link-layer medium handed to smoltcp. tun2socks operates at the IP layer
/// (raw IP packets on the TUN fd), so we use `medium-ip`.
pub const MEDIUM: Medium = Medium::Ip;

/// Bridges the async TUN device to smoltcp's synchronous `phy::Device`.
///
/// `Phy` is what gets passed to `Interface::new` / `Interface::poll`. It pulls
/// from `inbound` (packets the TUN pump read) during `receive`, and pushes into
/// `outbound` (packets smoltcp wants to send) during a `transmit` token's
/// `consume`.
pub struct Phy {
    /// Inbound packets (TUN → stack): drained by smoltcp during `receive`.
    inbound_rx: mpsc::Receiver<Packet>,
    /// Inbound packets buffered locally so the sync `receive` does not await.
    inbound_buf: VecDeque<Packet>,
    /// Outbound packets (stack → TUN): handed off to the TUN pump.
    outbound_tx: mpsc::Sender<Packet>,
    /// MTU for the capabilities smoltcp queries.
    mtu: usize,
}

impl Phy {
    pub fn new(mtu: usize) -> (Self, DeviceHandles) {
        let (inbound_tx, inbound_rx) = mpsc::channel(QUEUE_DEPTH);
        let (outbound_tx, outbound_rx) = mpsc::channel(QUEUE_DEPTH);
        (
            Self {
                inbound_rx,
                inbound_buf: VecDeque::new(),
                outbound_tx,
                mtu,
            },
            DeviceHandles {
                inbound: inbound_tx,
                outbound: outbound_rx,
            },
        )
    }

    /// Push a packet to the *front* of the inbound queue so the very next
    /// `receive()` returns it before any channel-buffered packet. Used by the
    /// netstack actor to re-inject an observed SYN after lazily creating a
    /// listener for its destination port (see `actor.rs`).
    pub fn reinject(&mut self, pkt: Packet) {
        self.inbound_buf.push_front(pkt);
    }
}

/// The async side of the bridge: what the TUN pump task holds.
pub struct DeviceHandles {
    /// Push inbound packets here (read from the TUN fd).
    pub inbound: mpsc::Sender<Packet>,
    /// Drain outbound packets here (write to the TUN fd).
    pub outbound: mpsc::Receiver<Packet>,
}

/// smoltcp receive token: hands the inbound packet to the stack.
pub struct RxToken {
    buffer: Packet,
}

impl phy::RxToken for RxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.buffer)
    }
}

/// smoltcp transmit token: collects the packet the stack wants to send and
/// pushes it to the outbound channel for the TUN pump to write.
pub struct TxToken<'a> {
    outbound: &'a mpsc::Sender<Packet>,
}

impl<'a> phy::TxToken for TxToken<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        // smoltcp only writes `len` bytes; allocate exactly that.
        let mut buffer = vec![0u8; len];
        let r = f(&mut buffer);
        trace!(len, "phy: transmit");
        // best-effort: if the pump has fallen behind we drop the packet rather
        // than block the (sync) poll loop. Production would apply backpressure.
        let _ = self.outbound.try_send(buffer);
        r
    }
}

impl phy::Device for Phy {
    type RxToken<'a> = RxToken;
    type TxToken<'a> = TxToken<'a>;

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = MEDIUM;
        caps.max_transmission_unit = self.mtu;
        caps
    }

    fn receive(
        &mut self,
        _timestamp: smoltcp::time::Instant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        // Refill the sync buffer from the channel without blocking: try_recv
        // drains whatever has arrived so far.
        while let Ok(pkt) = self.inbound_rx.try_recv() {
            self.inbound_buf.push_back(pkt);
        }
        let pkt = self.inbound_buf.pop_front()?;
        trace!(len = pkt.len(), "phy: receive");
        Some((
            RxToken { buffer: pkt },
            TxToken {
                outbound: &self.outbound_tx,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: smoltcp::time::Instant) -> Option<Self::TxToken<'_>> {
        Some(TxToken {
            outbound: &self.outbound_tx,
        })
    }
}
