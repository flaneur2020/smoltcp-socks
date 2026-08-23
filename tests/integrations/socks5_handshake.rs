//! Integration test: SOCKS5 client handshake against a mock server.
//!
//! GitHub-hosted Ubuntu runners do **not** grant the `CAP_NET_ADMIN` capability
//! or expose `/dev/net/tun`, so a real end-to-end TUN↔proxy test is impossible
//! there without fragile `--privileged` container workarounds (smoltcp's own CI
//! sidesteps this entirely by using its `Loopback` device in tests). We instead
//! drive the real `Socks5Proxy::connect` path against an in-process mock SOCKS5
//! server bound to loopback — no TUN, no privileges — which still exercises the
//! full client wire protocol: greeting, optional user/pass auth, CONNECT, and
//! bind-address parsing.

use std::net::SocketAddr;

use smoltcp_socks::proxy::{Proxy, ProxyUrl};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// A minimal SOCKS5 server that answers NO_AUTH CONNECTs for any target and,
/// once established, echoes back whatever it receives (so the client can verify
/// the stream is positioned past the handshake and live for relay).
async fn run_mock_socks5(listener: TcpListener) {
    let (mut sock, _) = listener.accept().await.unwrap();

    // 1. Greeting: VER, NMETHODS, METHODS...
    let mut hdr = [0u8; 2];
    sock.read_exact(&mut hdr).await.unwrap();
    assert_eq!(hdr[0], 0x05);
    let mut methods = vec![0u8; hdr[1] as usize];
    sock.read_exact(&mut methods).await.unwrap();
    // Reply: NO_AUTH.
    sock.write_all(&[0x05, 0x00]).await.unwrap();

    // 2. CONNECT request. Read VER, CMD, RSV.
    let mut req_hdr = [0u8; 3];
    sock.read_exact(&mut req_hdr).await.unwrap();
    assert_eq!(req_hdr[0], 0x05);
    assert_eq!(req_hdr[1], 0x01); // CONNECT

    // Read DST.ADDR depending on atyp.
    let mut atyp = [0u8; 1];
    sock.read_exact(&mut atyp).await.unwrap();
    let addr_len = match atyp[0] {
        0x01 => 4,  // IPv4
        0x04 => 16, // IPv6
        0x03 => {
            let mut len = [0u8; 1];
            sock.read_exact(&mut len).await.unwrap();
            len[0] as usize
        }
        other => panic!("unsupported atyp {other:#04x}"),
    };
    let mut addr = vec![0u8; addr_len];
    sock.read_exact(&mut addr).await.unwrap();
    let mut port = [0u8; 2];
    sock.read_exact(&mut port).await.unwrap();

    // 3. Success reply with an IPv4 0.0.0.0:0 bind address.
    let reply = [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    sock.write_all(&reply).await.unwrap();

    // From here the stream is live. Echo any received bytes back, to prove the
    // client's stream position is exactly at the start of proxied data.
    let mut buf = [0u8; 64];
    let n = sock.read(&mut buf).await.unwrap();
    sock.write_all(&buf[..n]).await.unwrap();
}

/// A mock server that demands username/password auth before CONNECT.
async fn run_mock_socks5_auth(listener: TcpListener, expect_user: &str, expect_pass: &str) {
    let (mut sock, _) = listener.accept().await.unwrap();

    // Greeting → require USER_PASS.
    let mut hdr = [0u8; 2];
    sock.read_exact(&mut hdr).await.unwrap();
    let mut methods = vec![0u8; hdr[1] as usize];
    sock.read_exact(&mut methods).await.unwrap();
    sock.write_all(&[0x05, 0x02]).await.unwrap();

    // RFC 1929 sub-negotiation: VER, ULEN, UNAME, PLEN, PASSWD.
    let mut v = [0u8; 1];
    sock.read_exact(&mut v).await.unwrap();
    assert_eq!(v[0], 0x01);
    let mut ulen = [0u8; 1];
    sock.read_exact(&mut ulen).await.unwrap();
    let mut uname = vec![0u8; ulen[0] as usize];
    sock.read_exact(&mut uname).await.unwrap();
    let mut plen = [0u8; 1];
    sock.read_exact(&mut plen).await.unwrap();
    let mut passwd = vec![0u8; plen[0] as usize];
    sock.read_exact(&mut passwd).await.unwrap();

    let ok = uname == expect_user.as_bytes() && passwd == expect_pass.as_bytes();
    // RFC 1929: status 0x00 = success, non-zero = failure.
    sock.write_all(&[0x01, u8::from(!ok)]).await.unwrap();
    if !ok {
        return;
    }

    // CONNECT request, same as the no-auth case.
    let mut req_hdr = [0u8; 3];
    sock.read_exact(&mut req_hdr).await.unwrap();
    let mut atyp = [0u8; 1];
    sock.read_exact(&mut atyp).await.unwrap();
    let addr_len = match atyp[0] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut len = [0u8; 1];
            sock.read_exact(&mut len).await.unwrap();
            len[0] as usize
        }
        _ => 0,
    };
    let mut addr = vec![0u8; addr_len];
    sock.read_exact(&mut addr).await.unwrap();
    let mut port = [0u8; 2];
    sock.read_exact(&mut port).await.unwrap();
    sock.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();

    let mut buf = [0u8; 64];
    let n = sock.read(&mut buf).await.unwrap();
    sock.write_all(&buf[..n]).await.unwrap();
}

fn proxy_url(listen: SocketAddr, creds: Option<&str>) -> String {
    let userpass = creds.unwrap_or("");
    format!("socks5://{userpass}@127.0.0.1:{}", listen.port())
}

#[tokio::test]
async fn no_auth_connect_round_trips() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(run_mock_socks5(listener));

    let target: SocketAddr = "203.0.113.7:443".parse().unwrap();
    let proxy = ProxyUrl::parse(&proxy_url(addr, None))
        .unwrap()
        .into_proxy();
    let mut up = proxy.connect(target).await.unwrap();

    // The stream must be live for bidirectional relay post-handshake.
    up.stream.write_all(b"hello").await.unwrap();
    let mut echo = [0u8; 5];
    up.stream.read_exact(&mut echo).await.unwrap();
    assert_eq!(&echo, b"hello");

    server.await.unwrap();
}

#[tokio::test]
async fn userpass_connect_round_trips() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(run_mock_socks5_auth(listener, "alice", "s3cret"));

    let target: SocketAddr = "198.51.100.42:8080".parse().unwrap();
    let url = proxy_url(addr, Some("alice:s3cret"));
    let proxy = ProxyUrl::parse(&url).unwrap().into_proxy();
    let mut up = proxy.connect(target).await.unwrap();

    up.stream.write_all(b"ping").await.unwrap();
    let mut echo = [0u8; 4];
    up.stream.read_exact(&mut echo).await.unwrap();
    assert_eq!(&echo, b"ping");

    server.await.unwrap();
}

#[tokio::test]
async fn wrong_password_is_rejected() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(run_mock_socks5_auth(listener, "alice", "s3cret"));

    let target: SocketAddr = "198.51.100.42:8080".parse().unwrap();
    let url = proxy_url(addr, Some("alice:wrong"));
    let proxy = ProxyUrl::parse(&url).unwrap().into_proxy();
    match proxy.connect(target).await {
        Ok(_) => panic!("connect should have failed with bad credentials"),
        Err(e) => assert!(e.to_string().contains("socks5"), "unexpected error: {e}"),
    }

    server.await.unwrap();
}

#[test]
fn proxy_url_parsing() {
    let p = ProxyUrl::parse("socks5://127.0.0.1:1080").unwrap();
    assert_eq!(p.host, "127.0.0.1");
    assert_eq!(p.port, 1080);
    assert!(p.username.is_none());

    let p = ProxyUrl::parse("socks5h://bob:hunter2@10.0.0.5:9050").unwrap();
    assert_eq!(p.host, "10.0.0.5");
    assert_eq!(p.port, 9050);
    assert_eq!(p.username.as_deref(), Some("bob"));
    assert_eq!(p.password.as_deref(), Some("hunter2"));

    let p = ProxyUrl::parse("socks5://[::1]:1080").unwrap();
    assert_eq!(p.host, "::1");
    assert_eq!(p.port, 1080);

    assert!(ProxyUrl::parse("http://x:1").is_err());
    assert!(ProxyUrl::parse("socks5://:1080").is_err()); // missing host
}
