//! End-to-end tests through a mocked TUN device and a real SOCKS5 server.
//!
//! This is the mirror image of `socks5_e2e.rs`: there the proxy side was
//! mocked and the TUN side was real; here the **TUN side is mocked** (a `Phy`
//! driven by hand-built IP/TCP packets) and the **proxy and target are real**
//! — a genuine SOCKS5 server proxying to a genuine echo service.
//!
//! No `CAP_NET_ADMIN` or `/dev/net/tun` is required: the `Phy` is fed raw IP
//! packets over its inbound channel and drained over its outbound channel, so
//! the test plays the role a real TUN fd + kernel TCP stack would normally
//! play: it completes a 3-way handshake against the smoltcp listener, then
//! shuttles application data through it.
//!
//! Two cases:
//!  * `tun_to_socks5_echo_e2e` — the actor is pre-warmed on the destination
//!    port (the legacy fixed-port model).
//!  * `lazy_syn_to_arbitrary_port_is_accepted` — the actor is started with
//!    `LAZY_LISTEN` (no pre-warmed port) and must create a listener on demand
//!    when it observes the SYN, proving the per-destination SYN interception.
//!
//! The data path exercised end to end is:
//!
//! ```text
//!   test (TCP client)  →  mocked TUN  →  smoltcp actor  →  VConn
//!                                                            ↓ relay::pipe
//!                                                     real SOCKS5 server
//!                                                            ↓ CONNECT
//!                                                       real echo target
//! ```
//!
//! Because the real SOCKS5 CONNECT must dial a host that actually exists, the
//! echo target is bound to a real loopback address and the TUN SYN is addressed
//! to it. The smoltcp listener is virtual, so it never clashes with the OS
//! socket on the same `(ip, port)`.

use std::net::Ipv4Addr;
use std::time::Duration;

use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{
    IpAddress, IpProtocol, Ipv4Packet, Ipv4Repr, TcpControl, TcpPacket, TcpRepr, TcpSeqNumber,
};
use smoltcp_socks::device::{DeviceHandles, Phy};
use smoltcp_socks::netstack::{LAZY_LISTEN, NetstackActor, build_interface};
use smoltcp_socks::proxy::ProxyUrl;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, timeout};

/// Install a tracing subscriber (once) so debug! logs from the actor surface
/// under `--nocapture`. No-op after the first call.
fn init_tracing() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .with_test_writer()
            .try_init();
    });
}

/// smoltcp 0.14's `Ipv4Address` *is* `core::net::Ipv4Addr`, so an `Ipv4Addr`
/// lifts directly into an `IpAddress`.
fn ip4(addr: Ipv4Addr) -> IpAddress {
    IpAddress::Ipv4(addr)
}

/// A toy TCP endpoint that talks raw IP/TCP to the smoltcp actor over the `Phy`
/// channels. It implements just enough of a TCP client to establish a
/// connection and exchange one round of application data.
struct TcpClient {
    src: Ipv4Addr,
    src_port: u16,
    dst: Ipv4Addr,
    dst_port: u16,
    send_next: TcpSeqNumber,
    recv_next: TcpSeqNumber,
    mss: usize,
}

impl TcpClient {
    fn new(src: Ipv4Addr, src_port: u16, dst: Ipv4Addr, dst_port: u16) -> Self {
        Self {
            src,
            src_port,
            dst,
            dst_port,
            send_next: TcpSeqNumber(100),
            recv_next: TcpSeqNumber(0),
            mss: 1400,
        }
    }

    /// Build a raw IPv4 packet carrying `repr` as its TCP payload, with correct
    /// IP and TCP checksums (smoltcp verifies both on `poll`).
    fn build(&self, repr: &TcpRepr<'_>) -> Vec<u8> {
        let ip_repr = Ipv4Repr {
            src_addr: self.src,
            dst_addr: self.dst,
            next_header: IpProtocol::Tcp,
            payload_len: repr.buffer_len(),
            hop_limit: 64,
        };
        let ip_len = ip_repr.buffer_len();
        let total = ip_len + repr.buffer_len();
        let mut buf = vec![0u8; total];
        let caps = ChecksumCapabilities::default();

        {
            let mut ip = Ipv4Packet::new_unchecked(&mut buf[..ip_len]);
            ip_repr.emit(&mut ip, &caps);
        }
        {
            let mut tcp = TcpPacket::new_unchecked(&mut buf[ip_len..]);
            repr.emit(&mut tcp, &ip4(self.src), &ip4(self.dst), &caps);
        }
        buf
    }

    /// A SYN segment (consumes one sequence number).
    fn syn(&mut self) -> Vec<u8> {
        let repr = TcpRepr {
            src_port: self.src_port,
            dst_port: self.dst_port,
            control: TcpControl::Syn,
            seq_number: self.send_next,
            ack_number: None,
            window_len: 65535,
            window_scale: None,
            max_seg_size: Some(self.mss as u16),
            sack_permitted: false,
            sack_ranges: [None; 3],
            timestamp: None,
            payload: &[],
        };
        let pkt = self.build(&repr);
        self.send_next += 1;
        pkt
    }

    /// An ACK / data segment. `payload` empty ⇒ pure ACK. Advances our send
    /// sequence by the payload length and acknowledges everything received so
    /// far via `recv_next`.
    fn segment(&mut self, payload: &[u8]) -> Vec<u8> {
        let repr = TcpRepr {
            src_port: self.src_port,
            dst_port: self.dst_port,
            control: if payload.is_empty() {
                TcpControl::None
            } else {
                TcpControl::Psh
            },
            seq_number: self.send_next,
            ack_number: Some(self.recv_next),
            window_len: 65535,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None; 3],
            timestamp: None,
            payload,
        };
        let pkt = self.build(&repr);
        self.send_next += payload.len();
        pkt
    }
}

/// Parse the TCP segment out of an IPv4 packet the actor emitted.
fn parse(pkt: &[u8]) -> TcpRepr<'_> {
    let ip = Ipv4Packet::new_checked(pkt).expect("valid ipv4 from actor");
    let hlen = ip.header_len() as usize;
    let tcp = TcpPacket::new_checked(&pkt[hlen..]).expect("valid tcp from actor");
    TcpRepr::parse(
        &tcp,
        &IpAddress::Ipv4(ip.src_addr()),
        &IpAddress::Ipv4(ip.dst_addr()),
        &ChecksumCapabilities::default(),
    )
    .expect("parseable tcp repr from actor")
}

/// Wait for the actor to emit the next outbound packet.
async fn recv_outbound(outbound: &mut tokio::sync::mpsc::Receiver<Vec<u8>>) -> Vec<u8> {
    timeout(Duration::from_millis(1000), outbound.recv())
        .await
        .expect("actor did not emit a packet in time")
        .expect("outbound channel closed")
}

/// A real SOCKS5 server: NO_AUTH, CONNECT to `target`, then splice bytes.
async fn run_socks5_server(listener: TcpListener, target: std::net::SocketAddr) {
    let (mut sock, _) = listener.accept().await.unwrap();

    // Greeting.
    let mut hdr = [0u8; 2];
    sock.read_exact(&mut hdr).await.unwrap();
    let mut methods = vec![0u8; hdr[1] as usize];
    sock.read_exact(&mut methods).await.unwrap();
    sock.write_all(&[0x05, 0x00]).await.unwrap(); // NO_AUTH

    // CONNECT request: VER, CMD, RSV, then DST.ADDR/PORT.
    let mut req_hdr = [0u8; 3];
    sock.read_exact(&mut req_hdr).await.unwrap();
    let mut atyp = [0u8; 1];
    sock.read_exact(&mut atyp).await.unwrap();
    let addr_len = match atyp[0] {
        0x01 => 4,
        0x04 => 16,
        _ => 0,
    };
    let mut addr = vec![0u8; addr_len];
    sock.read_exact(&mut addr).await.unwrap();
    let mut port = [0u8; 2];
    sock.read_exact(&mut port).await.unwrap();

    match TcpStream::connect(target).await {
        Ok(mut up) => {
            sock.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            let (mut sr, mut sw) = sock.split();
            let (mut ur, mut uw) = up.split();
            let _ = tokio::join!(
                tokio::io::copy(&mut sr, &mut uw),
                tokio::io::copy(&mut ur, &mut sw)
            );
        }
        Err(_) => {
            sock.write_all(&[0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        }
    }
}

/// A real echo target: echo every received byte back to the sender.
async fn run_echo_target(listener: TcpListener) {
    let (mut sock, _) = listener.accept().await.unwrap();
    let (mut r, mut w) = sock.split();
    let _ = tokio::io::copy(&mut r, &mut w).await;
}

#[tokio::test(flavor = "current_thread")]
async fn tun_to_socks5_echo_e2e() {
    // This case uses the legacy fixed-port model: the actor is pre-warmed on
    // `listen_port`. Bind the echo target first, take its ephemeral port, and
    // use that as both the actor listen port and the TUN destination. The
    // smoltcp listener is virtual, so it does not clash with the OS socket.
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();
    let listen_port = echo_addr.port();

    // Start the real echo target now; it must be accepting by the time the
    // SOCKS5 server CONNECTs to it (after our handshake completes).
    tokio::spawn(run_echo_target(echo_listener));

    // Real SOCKS5 server on an ephemeral port, started before the handshake so
    // the actor's relay can dial it the moment our VConn is accepted.
    let socks_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socks_addr = socks_listener.local_addr().unwrap();
    tokio::spawn(run_socks5_server(
        socks_listener,
        std::net::SocketAddr::new(echo_addr.ip(), echo_addr.port()),
    ));

    // Build the mocked TUN via the production `Phy` and spawn the actor with a
    // proxy pointing at the real SOCKS5 server.
    let (mut phy, device_handles) = Phy::new(1500);
    let iface = build_interface(&mut phy);
    let proxy_url = ProxyUrl::parse(&format!("socks5://127.0.0.1:{}", socks_addr.port())).unwrap();
    let proxy = std::sync::Arc::new(proxy_url.into_proxy());
    let _handle = NetstackActor::spawn(iface, phy, proxy, listen_port);

    let DeviceHandles { inbound, outbound } = device_handles;
    let inbound = inbound;
    let mut outbound = outbound;

    // Our TUN client: src 10.0.0.2:54321, dst = the real echo address/port.
    let dst = match echo_addr.ip() {
        std::net::IpAddr::V4(v4) => v4,
        v6 => panic!("expected ipv4 echo target, got {v6}"),
    };
    let mut client = TcpClient::new(Ipv4Addr::new(10, 0, 0, 2), 54321, dst, listen_port);

    // --- 3-way handshake ---
    inbound.send(client.syn()).await.unwrap();
    sleep(Duration::from_millis(150)).await;

    let synack = recv_outbound(&mut outbound).await;
    let synack_repr = parse(&synack);
    assert_eq!(synack_repr.control, TcpControl::Syn);
    assert_eq!(synack_repr.src_port, listen_port);
    assert_eq!(synack_repr.dst_port, 54321);
    if let Some(mss) = synack_repr.max_seg_size {
        client.mss = mss as usize;
    }
    client.recv_next = synack_repr.seq_number + 1; // SYN consumes one seq

    // ACK the SYN-ACK, completing the handshake.
    inbound.send(client.segment(&[])).await.unwrap();
    sleep(Duration::from_millis(150)).await;

    // --- Send application data through TUN → relay → proxy → echo ---
    let payload = b"hello, tun2socks!";
    inbound.send(client.segment(payload)).await.unwrap();

    // Collect the echoed response. The actor emits data segments; we ACK each
    // so its send buffer can drain. Loop until we have the full payload back.
    let mut got = Vec::new();
    let result = timeout(Duration::from_millis(8000), async {
        loop {
            let pkt = recv_outbound(&mut outbound).await;
            let repr = parse(&pkt);
            if !repr.payload.is_empty() {
                client.recv_next += repr.payload.len();
                got.extend_from_slice(repr.payload);
                inbound.send(client.segment(&[])).await.unwrap();
                if got.len() >= payload.len() {
                    return;
                }
            } else if repr.control == TcpControl::Fin {
                // Peer half-closed; ACK it.
                client.recv_next += 1;
                inbound.send(client.segment(&[])).await.unwrap();
            }
        }
    })
    .await;
    assert!(result.is_ok(), "timed out waiting for echo; got {got:?}");

    assert_eq!(&got[..payload.len()], payload, "echo round-trip mismatch");
}

/// The actor is started with `LAZY_LISTEN` (no pre-warmed port) and must create
/// a TCP listener on demand when it observes the first SYN for a destination
/// port it has never seen — the per-destination SYN interception path.
///
/// The SYN is addressed to an arbitrary port (the echo target's ephemeral port)
/// that the actor was never told about. Proving the SYN-ACK comes back with
/// `src_port == dst_port` shows a listener was created lazily; the echo
/// round-trip proves the lazily-accepted connection relays end to end.
#[tokio::test(flavor = "current_thread")]
async fn lazy_syn_to_arbitrary_port_is_accepted() {
    init_tracing();
    // The actor will never be told this port — it must discover it from the SYN.
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();
    let dst_port = echo_addr.port();

    tokio::spawn(run_echo_target(echo_listener));

    let socks_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socks_addr = socks_listener.local_addr().unwrap();
    tokio::spawn(run_socks5_server(
        socks_listener,
        std::net::SocketAddr::new(echo_addr.ip(), echo_addr.port()),
    ));

    let (mut phy, device_handles) = Phy::new(1500);
    let iface = build_interface(&mut phy);
    let proxy_url = ProxyUrl::parse(&format!("socks5://127.0.0.1:{}", socks_addr.port())).unwrap();
    let proxy = std::sync::Arc::new(proxy_url.into_proxy());
    // LAZY_LISTEN (0): no pre-warmed listener, no hint about dst_port.
    let _handle = NetstackActor::spawn(iface, phy, proxy, LAZY_LISTEN);

    let DeviceHandles { inbound, outbound } = device_handles;
    let inbound = inbound;
    let mut outbound = outbound;

    let dst = match echo_addr.ip() {
        std::net::IpAddr::V4(v4) => v4,
        v6 => panic!("expected ipv4 echo target, got {v6}"),
    };
    let mut client = TcpClient::new(Ipv4Addr::new(10, 0, 0, 2), 54321, dst, dst_port);

    // --- 3-way handshake (lazy path: two polls — drain + re-inject, then accept) ---
    inbound.send(client.syn()).await.unwrap();
    sleep(Duration::from_millis(150)).await;

    let synack = recv_outbound(&mut outbound).await;
    let synack_repr = parse(&synack);
    assert_eq!(synack_repr.control, TcpControl::Syn);
    // The decisive assertion: the actor answered on a port it was never told
    // about, proving a listener was created lazily from the observed SYN.
    assert_eq!(synack_repr.src_port, dst_port);
    assert_eq!(synack_repr.dst_port, 54321);
    if let Some(mss) = synack_repr.max_seg_size {
        client.mss = mss as usize;
    }
    client.recv_next = synack_repr.seq_number + 1;

    // ACK the SYN-ACK, completing the handshake.
    inbound.send(client.segment(&[])).await.unwrap();
    sleep(Duration::from_millis(150)).await;

    // --- Send application data through TUN → relay → proxy → echo ---
    let payload = b"lazy listener works!";
    inbound.send(client.segment(payload)).await.unwrap();

    let mut got = Vec::new();
    let result = timeout(Duration::from_millis(8000), async {
        loop {
            let pkt = recv_outbound(&mut outbound).await;
            let repr = parse(&pkt);
            if !repr.payload.is_empty() {
                client.recv_next += repr.payload.len();
                got.extend_from_slice(repr.payload);
                inbound.send(client.segment(&[])).await.unwrap();
                if got.len() >= payload.len() {
                    return;
                }
            } else if repr.control == TcpControl::Fin {
                client.recv_next += 1;
                inbound.send(client.segment(&[])).await.unwrap();
            }
        }
    })
    .await;
    assert!(result.is_ok(), "timed out waiting for echo; got {got:?}");

    assert_eq!(&got[..payload.len()], payload, "echo round-trip mismatch");
}
