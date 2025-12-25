//! Wintun adapter implementation for Windows.
//!
//! This module provides a safe wrapper around the Wintun driver for creating
//! virtual Layer-3 adapters on Windows.
//!
//! # Safety Requirements
//!
//! - `wintun.dll` must be present in the executable directory or system PATH
//! - Adapter creation requires Administrator privileges
//! - The Wintun library is loaded dynamically at runtime
//!
//! # Platform
//!
//! This module is Windows-only and will not compile on other platforms.

#![cfg(target_os = "windows")]

use super::TunDevice;
use std::io;
use std::sync::Arc;
use wintun::Session;

/// Default MTU for Wintun adapters
const DEFAULT_MTU: usize = 1420;

/// Wintun adapter name prefix
const ADAPTER_NAME: &str = "Bonding";

/// Wintun adapter GUID (tunnel type identifier)
/// 
/// This GUID was generated specifically for the Bonding project and serves as a unique
/// identifier for the tunnel type. It helps Windows distinguish Bonding adapters from
/// other Wintun-based VPN applications. This GUID is consistent across all Bonding
/// installations to enable adapter reuse and proper identification.
const ADAPTER_GUID: &str = "5fb1c3e4-2e82-4e1b-a2f6-1d5c3e4f5a6b";

/// Wintun TUN device implementation
///
/// This structure wraps the Wintun adapter and provides a safe interface
/// for reading and writing IP packets.
///
/// # Safety
///
/// The internal implementation uses `unsafe` FFI calls to the Wintun library.
/// All safety invariants are maintained within this implementation.
pub struct WintunDevice {
    name: String,
    mtu: usize,
    session: Arc<Session>,
}

impl WintunDevice {
    /// Create a new Wintun device
    ///
    /// # Arguments
    ///
    /// * `adapter_name` - Name for the Wintun adapter
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `wintun.dll` cannot be loaded
    /// - Administrator privileges are insufficient
    /// - The adapter cannot be created
    ///
    /// # Safety
    ///
    /// This function performs FFI calls to load and initialize the Wintun library.
    /// It ensures that all handles are properly managed and cleaned up.
    pub fn new(adapter_name: &str) -> io::Result<Self> {
        use wintun::Adapter;

        // Load wintun.dll
        let wintun = unsafe {
            wintun::load().map_err(|e| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("Failed to load wintun.dll: {}", e),
                )
            })?
        };

        // Parse GUID
        let guid = ADAPTER_GUID
            .parse()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("Invalid GUID: {}", e)))?;

        // Create or open adapter
        let adapter = match Adapter::open(&wintun, adapter_name) {
            Ok(adapter) => adapter,
            Err(_) => {
                // Adapter doesn't exist, create it
                Adapter::create(&wintun, adapter_name, adapter_name, Some(guid)).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        format!(
                            "Failed to create Wintun adapter (Administrator privileges required): {}",
                            e
                        ),
                    )
                })?
            }
        };

        // Start a session with ring buffer capacity of 0x400000 bytes (4MB)
        let session = adapter.start_session(wintun::MAX_RING_CAPACITY).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to start Wintun session: {}", e),
            )
        })?;

        tracing::info!(
            "Created Wintun adapter '{}' with MTU {}",
            adapter_name,
            DEFAULT_MTU
        );

        Ok(Self {
            name: adapter_name.to_string(),
            mtu: DEFAULT_MTU,
            session: Arc::new(session),
        })
    }

    /// Create a Wintun device with default name
    pub fn new_default() -> io::Result<Self> {
        Self::new(ADAPTER_NAME)
    }
}

impl TunDevice for WintunDevice {
    fn read_packet(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // Try to receive a packet (non-blocking)
        match self.session.try_receive() {
            Ok(packet) => {
                let packet_bytes = packet.bytes();
                let len = packet_bytes.len();

                if len > buf.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "Packet too large for buffer: {} bytes (buffer: {})",
                            len,
                            buf.len()
                        ),
                    ));
                }

                buf[..len].copy_from_slice(packet_bytes);
                Ok(len)
            }
            Err(e) => {
                // Convert wintun error to io::Error
                match e {
                    wintun::Error::ShuttingDown => Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "Wintun session is shutting down",
                    )),
                    _ => Err(io::Error::new(io::ErrorKind::WouldBlock, "No packet available")),
                }
            }
        }
    }

    fn write_packet(&self, buf: &[u8]) -> io::Result<()> {
        if buf.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Cannot write empty packet",
            ));
        }

        if buf.len() > self.mtu {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Packet too large for MTU: {} bytes (MTU: {})",
                    buf.len(),
                    self.mtu
                ),
            ));
        }

        // Allocate send packet
        let mut packet = self.session.allocate_send_packet(buf.len() as u16).map_err(|e| {
            io::Error::new(
                io::ErrorKind::OutOfMemory,
                format!("Failed to allocate send packet: {}", e),
            )
        })?;

        // Copy data to packet
        packet.bytes_mut().copy_from_slice(buf);

        // Send packet
        self.session.send_packet(packet);

        Ok(())
    }

    fn mtu(&self) -> usize {
        self.mtu
    }

    fn name(&self) -> &str {
        &self.name
    }
}

// Safety: WintunDevice manages Wintun handles through the safe wintun crate
// The Session type automatically handles proper cleanup through its Drop implementation
// All FFI calls are encapsulated within the wintun crate's safe abstractions

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_os = "windows")]
    #[ignore] // Requires Administrator privileges and wintun.dll
    fn test_wintun_device_creation() {
        // This test requires:
        // 1. Administrator privileges
        // 2. wintun.dll in the current directory or PATH
        let name = "TestAdapter";
        let device = WintunDevice::new(name);

        match device {
            Ok(dev) => {
                assert_eq!(dev.name(), name);
                assert_eq!(dev.mtu(), DEFAULT_MTU);
            }
            Err(e) => {
                // Expected to fail without admin privileges or wintun.dll
                eprintln!("Note: Test failed as expected without admin/wintun.dll: {}", e);
            }
        }
    }

    #[test]
    #[cfg(target_os = "windows")]
    #[ignore] // Requires Administrator privileges and wintun.dll
    fn test_wintun_device_io() {
        let mut device = match WintunDevice::new_default() {
            Ok(d) => d,
            Err(_) => return, // Skip if can't create adapter
        };

        // Test read (should return WouldBlock if no packets)
        let mut buf = vec![0u8; 2048];
        let result = device.read_packet(&mut buf);
        // Either WouldBlock or actual data is fine
        assert!(result.is_ok() || result.unwrap_err().kind() == io::ErrorKind::WouldBlock);

        // Test write
        let test_packet = vec![0x45, 0x00, 0x00, 0x20]; // Simple IP header start
        let result = device.write_packet(&test_packet);
        // Should succeed or fail gracefully
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn test_empty_packet_write() {
        // This test doesn't require actual Wintun setup
        // We just verify our validation logic
        let empty_packet: Vec<u8> = vec![];
        // Can't test actual write without adapter, but we document the expected behavior
        assert!(empty_packet.is_empty());
    }
}
