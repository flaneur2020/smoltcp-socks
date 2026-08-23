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

Two gaps remain before this is production-ready (both are marked in the code with
`TODO`):

- **Per-destination SYN interception.** The actor currently listens on a single
  wildcard-address port. A real TUN carries TCP connections to arbitrary
  `(ip, port)` pairs; matching those requires intercepting SYNs at the IP layer
  and creating a listener per destination, the way gVisor's `tcp.NewForwarder`
  does. This is the hardest porting task.
- **Platform TUN setup.** The TUN open path is a thin placeholder; the per-OS
  specifics (Linux `tun` vs. macOS `utun` vs. Windows `wintun`) still need wiring.

## Build

```sh
cargo build
```

Running requires creating a TUN device (root/cap), e.g.:

```sh
sudo target/debug/smoltcp-socks --device tun://tun0 --proxy socks5://127.0.0.1:1080 --mtu 1500
```
