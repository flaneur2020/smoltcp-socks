//! smoltcp-socks — userspace TCP/IP stack forwarding TUN connections to SOCKS5.
//!
//! Library facade so the binary target ([`main.rs`]) and integration tests share
//! the same module surface. The crate-level docs in each module map the Rust
//! pieces back to their tun2socks (Go + gVisor) counterparts.

pub mod config;
pub mod device;
pub mod netstack;
pub mod proxy;
pub mod relay;
pub mod runtime;
pub mod socks5;
