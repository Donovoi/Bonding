//! Core library for the Bonding overlay network.
//!
//! This library implements a Windows-first bonding overlay that aggregates multiple
//! network interfaces (Wi-Fi + Ethernet) to provide increased bandwidth and redundancy.
//!
//! # Architecture
//!
//! The library is organized into several key modules:
//!
//! - `proto`: Wire protocol definitions, packet formats, and versioning
//! - `tun`: Virtual Layer-3 adapter (TUN/Wintun) for packet capture
//! - `transport`: Multi-interface UDP sockets with encryption
//! - `scheduler`: Path selection, redundancy, and pacing logic
//! - `reorder`: Sequence number tracking, jitter buffer, and replay protection
//! - `control`: Health metrics, interface discovery, and configuration
//!
//! # Example
//!
//! ```no_run
//! # async fn example() -> anyhow::Result<()> {
//! // Initialize the bonding client (example - actual usage may differ)
//! // let client = bonding_core::Client::new(config).await?;
//! // client.start().await?;
//! # Ok(())
//! # }
//! ```

pub mod control;
pub mod proto;
pub mod reorder;
pub mod scheduler;
pub mod transport;
pub mod tun;

pub use proto::{Packet, PacketHeader, ProtocolVersion};
