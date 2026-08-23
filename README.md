# smoltcp-socks

Send traffic destined for a host (or hosts) through a SOCKS5 proxy, without
touching the app or the OS network stack.

It's a Rust port of [`tun2socks`](https://github.com/xjasonlyu/tun2socks)
(Go + gVisor), rebuilt on [`smoltcp`](https://github.com/smoltcp-rs/smoltcp)
for the userspace TCP/IP stack. You point it at a TUN device and a SOCKS5
server; it terminates the TCP connections that arrive on the TUN and tunnels
each one through the proxy.

## How it works

```
  app ──► TUN device ──► smoltcp (userspace TCP/IP stack)
                                  │ accepted TCP connection
                                  ▼
                              relay ──► SOCKS5 CONNECT ──► upstream proxy
```

1. The TUN device hands raw IP packets to a single task.
2. That task runs them through smoltcp — a TCP/IP stack living in userspace.
3. When a TCP handshake completes, the connection is handed to a relay task.
4. The relay opens a SOCKS5 tunnel to the upstream and copies bytes both ways.

The one wrinkle worth knowing: a real TUN carries connections to **any**
`(ip, port)` destination, but smoltcp only listens on ports you've named. So
the actor taps every inbound SYN through an all-protocol raw socket, lazily
creates a listener for whatever destination port shows up, and re-injects the
SYN so the handshake completes. No port has to be configured in advance.

## Status

The data path works end to end and is covered by integration tests (mocked
TUN → real netstack → real SOCKS5 → real echo, with bytes round-tripping).
CI runs `cargo fmt --check`, `cargo clippy -D warnings`, and `cargo test`.

Linux `tun` and macOS `utun` are supported. The Windows `wintun` backend is
the one missing piece.

## Build

```sh
cargo build
```

Running needs a TUN device (root):

```sh
# Linux (tun0) / macOS (kernel picks a free utun)
sudo target/debug/smoltcp-socks --device tun:// --proxy socks5://127.0.0.1:1080 --mtu 1500
# macOS, explicit utun unit
sudo target/debug/smoltcp-socks --device utun://utun9 --proxy socks5://127.0.0.1:1080
```

## Forwarding a destination on macOS

`scripts/up.sh` captures all TCP traffic for a single host and relays it
through the proxy — it builds the binary, creates the utun, and adds a `/32`
host route so traffic to that host flows into the TUN.

```sh
sudo scripts/up.sh          # defaults: 172.66.0.227 → socks5://127.0.0.1:7890
sudo scripts/down.sh        # stop, drop the route, tear down the utun
```

Override anything via the environment: `DST`, `PROXY`, `TUN_ADDR`,
`TUN_REMOTE`, `MTU`, `UTUN`, `LOG_LEVEL`.

The host route is more specific than your default route, so it wins for that
one host only — the rest of your traffic is untouched. There's no
proxy-egress exclusion, which assumes your SOCKS5 server forwards onward to a
*remote* upstream rather than dialing the destination itself. If it does dial
the destination directly, you'd loop back into the TUN and need to exempt the
proxy's own traffic yourself.
