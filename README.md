# smoltcp-socks

A userspace TCP/IP stack that forwards TUN device connections through a SOCKS5 proxy.

This is a Rust reimplementation, scaffolded from the architecture of
[`tun2socks`](https://github.com/xjasonlyu/tun2socks) (Go + gVisor), but built on
[`smoltcp`](https://github.com/smoltcp-rs/smoltcp) as the userspace TCP/IP stack.

## How it works

```
            kernel TUN fd              smoltcp userspace stack
  app ──►  ┌──────────────┐   packets   ┌───────────────────────┐
           │  tun device  │ ──────────► │ Interface::poll        │
           │              │ ◄────────── │  (single owner task)   │
           └──────────────┘   packets   └───────────┬───────────┘
                                                    │ accepted TCP conn
                                                    ▼
                                      ┌─────────────────────────────┐
                                      │ relay (bidirectional copy)  │
                                      └──────────────┬──────────────┘
                                                     │ SOCKS5 CONNECT
                                                     ▼
                                            upstream SOCKS5 server
```

1. TUN device (`tun` crate) delivers raw IP packets to a single owner task.
2. That task feeds packets into a `smoltcp::iface::Interface` and polls it —
   this is the userspace TCP/IP stack (equivalent to gVisor's `stack.Stack`).
3. When the stack completes a TCP handshake, the netstack actor hands the virtual
   connection off to a relay task, the same role tun2socks' `tunnel` package plays.
4. The relay dials the SOCKS5 upstream, performs the client handshake, and copies
   bytes both ways until either side closes.

## Status

The data path works end to end and is covered by integration tests: a mocked TUN
feeds the real netstack actor → relay → a real SOCKS5 server → a real echo target,
and bytes round-trip correctly. CI runs `cargo fmt --check`, `cargo clippy -D
warnings`, and `cargo test` on every PR.

One gap remains before this is production-ready (marked in the code with
`TODO`):

- **Windows `wintun` backend.** The TUN open path handles Linux `tun` and macOS
  `utun` (kernel-picked unit when no name is given, or an explicit `utunN`);
  the Windows backend is not yet wired.

Per-destination SYN interception — the gVisor `tcp.NewForwarder` equivalent,
where a TUN carrying TCP connections to arbitrary `(ip, port)` pairs is
matched without pre-listening on every port — *is* implemented: an
all-protocol smoltcp raw socket taps each inbound SYN, suppresses the RST
that would otherwise fire for an unmatched destination, lazily creates a
listener pool for the SYN's destination port, and re-injects the SYN so the
next poll completes the handshake. The lazy path is covered by
`integrations/tun_e2e.rs::lazy_syn_to_arbitrary_port_is_accepted`.

## Build

```sh
cargo build
```

Running requires creating a TUN device (root/cap), e.g.:

```sh
# Linux (named tun0) / macOS (kernel picks a free utun)
sudo target/debug/smoltcp-socks --device tun:// --proxy socks5://127.0.0.1:1080 --mtu 1500
# macOS with an explicit utun unit
sudo target/debug/smoltcp-socks --device utun://utun9 --proxy socks5://127.0.0.1:1080
```

## Forwarding a destination on macOS

`scripts/up.sh` captures all TCP traffic for a single destination and relays it
through a SOCKS5 proxy. It builds + launches the binary, configures the utun it
created, and installs a `/32` host route that pins the destination to the utun.

```sh
# Capture 172.66.0.227 → socks5://127.0.0.1:7890 (defaults; all overridable
# via environment: DST, PROXY, TUN_ADDR, TUN_REMOTE, MTU, UTUN, LOG_LEVEL).
sudo scripts/up.sh

# …use the machine; traffic to 172.66.0.227 is tunneled through the proxy…

# Stop, remove the route, and let the kernel tear down the utun.
sudo scripts/down.sh
```

The `/32` host route is more specific than the default route, so it captures app
traffic for `DST` regardless of the box's normal routing. No proxy-route
exclusion is added: this assumes the SOCKS5 server forwards to a *remote*
upstream (not to `DST` itself). If your proxy dials `DST` directly you'll loop
back into the utun and must exclude the proxy's egress (fwmark / a more-specific
route for the proxy host) yourself.
