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
//! The actor receives no destination-port configuration. Tests verify wildcard
//! handshakes and that SOCKS5 CONNECT preserves the original destination.
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

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{
    IpProtocol, IpRepr, IpVersion, Ipv4Packet, Ipv6Packet, TcpControl, TcpPacket, TcpRepr,
    TcpSeqNumber,
};
use smoltcp_socks::device::{DeviceHandles, Phy};
use smoltcp_socks::netstack::{NetstackActor, build_interface};
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

/// A toy TCP endpoint that talks raw IP/TCP to the smoltcp actor over the `Phy`
/// channels. It implements just enough of a TCP client to establish a
/// connection and exchange one round of application data.
struct TcpClient {
    src: IpAddr,
    src_port: u16,
    dst: IpAddr,
    dst_port: u16,
    send_next: TcpSeqNumber,
    recv_next: TcpSeqNumber,
    mss: usize,
}

impl TcpClient {
    fn new(src: IpAddr, src_port: u16, dst: IpAddr, dst_port: u16) -> Self {
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

    /// Build an IP/TCP packet with valid checksums.
    fn build(&self, repr: &TcpRepr<'_>) -> Vec<u8> {
        let ip_repr = IpRepr::new(
            self.src.into(),
            self.dst.into(),
            IpProtocol::Tcp,
            repr.buffer_len(),
            64,
        );
        let ip_len = ip_repr.header_len();
        let mut buf = vec![0u8; ip_len + repr.buffer_len()];
        let caps = ChecksumCapabilities::default();
        ip_repr.emit(&mut buf[..ip_len], &caps);
        repr.emit(
            &mut TcpPacket::new_unchecked(&mut buf[ip_len..]),
            &self.src.into(),
            &self.dst.into(),
            &caps,
        );
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

/// Parse and verify a TCP segment emitted by the actor.
fn parse(pkt: &[u8]) -> TcpRepr<'_> {
    let (src, dst, payload) = match IpVersion::of_packet(pkt).unwrap() {
        IpVersion::Ipv4 => {
            let ip = Ipv4Packet::new_checked(pkt).unwrap();
            assert!(ip.verify_checksum());
            assert_eq!(ip.next_header(), IpProtocol::Tcp);
            (
                ip.src_addr().into(),
                ip.dst_addr().into(),
                &pkt[ip.header_len() as usize..],
            )
        }
        IpVersion::Ipv6 => {
            let ip = Ipv6Packet::new_checked(pkt).unwrap();
            assert_eq!(ip.next_header(), IpProtocol::Tcp);
            (ip.src_addr().into(), ip.dst_addr().into(), &pkt[40..])
        }
    };
    TcpRepr::parse(
        &TcpPacket::new_checked(payload).unwrap(),
        &src,
        &dst,
        &ChecksumCapabilities::default(),
    )
    .expect("valid TCP checksum and header")
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
    assert_eq!(req_hdr, [0x05, 0x01, 0x00]);
    let requested_ip = match atyp[0] {
        0x01 => std::net::IpAddr::V4(Ipv4Addr::from(
            <[u8; 4]>::try_from(addr.as_slice()).unwrap(),
        )),
        0x04 => std::net::IpAddr::V6(std::net::Ipv6Addr::from(
            <[u8; 16]>::try_from(addr.as_slice()).unwrap(),
        )),
        _ => panic!("expected an IP destination"),
    };
    assert_eq!(
        std::net::SocketAddr::new(requested_ip, u16::from_be_bytes(port)),
        target
    );

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
    init_tracing();
    // The actor is not told the echo target's address or port.
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
    let handle = NetstackActor::spawn(iface, phy, proxy);

    let DeviceHandles { inbound, outbound } = device_handles;
    let mut outbound = outbound;

    // Our TUN client: src 10.0.0.2:54321, dst = the real echo address/port.
    let dst = match echo_addr.ip() {
        std::net::IpAddr::V4(v4) => v4,
        v6 => panic!("expected ipv4 echo target, got {v6}"),
    };
    let mut client = TcpClient::new(
        Ipv4Addr::new(10, 0, 0, 2).into(),
        54321,
        dst.into(),
        listen_port,
    );

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
    handle.stop().await;
}

/// Keep connections open while observing each original destination.
struct RecordingProxy(tokio::sync::mpsc::UnboundedSender<(SocketAddr, tokio::io::DuplexStream)>);

#[async_trait::async_trait]
impl smoltcp_socks::proxy::Proxy for RecordingProxy {
    async fn connect(&self, target: SocketAddr) -> std::io::Result<smoltcp_socks::proxy::Upstream> {
        let (stream, peer) = tokio::io::duplex(1024);
        self.0.send((target, peer)).unwrap();
        Ok(smoltcp_socks::proxy::Upstream {
            stream: Box::new(stream),
            local_addr: "127.0.0.1:1080".parse().unwrap(),
        })
    }
}

/// More connections than the initial pool, across IP versions and ports.
#[tokio::test]
async fn wildcard_listeners_preserve_destinations_and_replenish() {
    let (
        mut phy,
        DeviceHandles {
            inbound,
            mut outbound,
        },
    ) = Phy::new(1500);
    let iface = build_interface(&mut phy);
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let handle = NetstackActor::spawn(iface, phy, std::sync::Arc::new(RecordingProxy(tx)));
    let mut peers = Vec::new();

    for destination in [
        "203.0.113.1:80",
        "203.0.113.1:443",
        "203.0.113.2:443",
        "[2001:db8::1]:80",
        "[2001:db8::1]:443",
        "[2001:db8::2]:443",
    ] {
        let destination: SocketAddr = destination.parse().unwrap();
        let src: IpAddr = if destination.is_ipv4() {
            "10.0.0.2"
        } else {
            "fd00::2"
        }
        .parse()
        .unwrap();
        let mut client = TcpClient::new(src, 54321, destination.ip(), destination.port());
        inbound.send(client.syn()).await.unwrap();
        let packet = recv_outbound(&mut outbound).await;
        let synack = parse(&packet);
        assert_eq!(synack.control, TcpControl::Syn);
        assert_eq!(synack.src_port, destination.port());
        assert_eq!(synack.dst_port, client.src_port);
        match IpVersion::of_packet(&packet).unwrap() {
            IpVersion::Ipv4 => {
                let ip = Ipv4Packet::new_checked(&packet).unwrap();
                assert_eq!(IpAddr::V4(ip.src_addr()), destination.ip());
                assert_eq!(IpAddr::V4(ip.dst_addr()), src);
            }
            IpVersion::Ipv6 => {
                let ip = Ipv6Packet::new_checked(&packet).unwrap();
                assert_eq!(IpAddr::V6(ip.src_addr()), destination.ip());
                assert_eq!(IpAddr::V6(ip.dst_addr()), src);
            }
        }
        client.recv_next = synack.seq_number + 1;
        inbound.send(client.segment(&[])).await.unwrap();
        let (target, peer) = timeout(Duration::from_secs(3), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(target, destination);
        peers.push(peer);
    }

    handle.stop().await;
}
