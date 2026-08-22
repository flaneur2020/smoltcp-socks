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

## Architecture / module map

| Rust module            | tun2socks (Go) counterpart          | Responsibility                                            |
|------------------------|-------------------------------------|-----------------------------------------------------------|
| `main.rs`              | `main.go`                           | CLI parsing, signal handling, start/stop.                |
| `config.rs`            | `engine/key.go`                     | Configuration struct.                                      |
| `runtime.rs`           | `engine/engine.go`                  | Wires device + netstack + proxy and drives the run loop.  |
| `netstack/mod.rs`      | `core/stack.go`                     | smoltcp `Interface` setup (NIC, routes, promiscuous).      |
| `netstack/actor.rs`    | `core/tcp.go` + `tunnel/tunnel.go`  | Single-owner poll loop; accepts virtual TCP connections.   |
| `netstack/vconn.rs`    | `core/adapter/adapter.go`           | The virtual TCP connection exposed as AsyncRead/Write.     |
| `device.rs`            | `core/device/*`                     | `smoltcp::phy::Device` impl over a `tun` fd.               |
| `socks5.rs`            | `transport/socks5/socks5.go`         | SOCKS5 client handshake (greeting / auth / CONNECT).       |
| `proxy.rs`             | `proxy/proxy.go` + `proxy/socks5/`  | `Proxy` trait + SOCKS5 dialer; target address parsing.     |
| `relay.rs`             | `tunnel/tcp.go`                     | Bidirectional copy between virtual conn and upstream.      |

## Status

This is a **scaffold**. The module boundaries, types, and data flow are laid out
to mirror tun2socks, and every place that needs version-specific smoltcp wiring
is marked with `// TODO(smoltcp)` / `todo!()` so it is easy to find and fill in.

## Build

```sh
cargo build
```

Running requires creating a TUN device (root/cap), e.g.:

```sh
sudo target/debug/smoltcp-socks --device tun://tun0 --proxy socks5://127.0.0.1:1080 --mtu 1500
```
