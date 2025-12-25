//! Virtual Layer-3 adapter (TUN) implementation.
//!
//! This module provides a cross-platform interface for TUN devices:
//! - Windows: Uses Wintun
//! - Linux: Uses /dev/net/tun
//!
//! # Safety
//!
//! The Wintun implementation uses FFI and `unsafe` code, which is isolated
//! to the `wintun` submodule with clear safety invariants.

use std::io;

#[cfg(target_os = "windows")]
pub mod wintun;

#[cfg(target_os = "linux")]
pub mod linux;

/// Trait for TUN device implementations
///
/// # Platform Differences
///
/// **Windows (Wintun)**: Fully supports synchronous read/write operations.
///
/// **Linux (tun-rs)**: The underlying library is async-only. The sync methods
/// will return `WouldBlock` errors. Use `LinuxTunDevice::device_handle()` to
/// access the async device for actual I/O operations.
pub trait TunDevice: Send + Sync {
    /// Read a packet from the TUN device
    ///
    /// Returns the number of bytes read into the buffer.
    ///
    /// # Platform Notes
    ///
    /// - **Windows**: Performs non-blocking read, returns WouldBlock if no data
    /// - **Linux**: Always returns WouldBlock, use async device handle instead
    fn read_packet(&mut self, buf: &mut [u8]) -> io::Result<usize>;

    /// Write a packet to the TUN device
    ///
    /// # Platform Notes
    ///
    /// - **Windows**: Performs synchronous write
    /// - **Linux**: Always returns WouldBlock after validation, use async device handle instead
    fn write_packet(&self, buf: &[u8]) -> io::Result<()>;

    /// Get the MTU of the device
    fn mtu(&self) -> usize;

    /// Get the name of the device
    fn name(&self) -> &str;
}

#[cfg(target_os = "windows")]
pub use wintun::WintunDevice;

#[cfg(target_os = "linux")]
pub use linux::LinuxTunDevice;

#[cfg(test)]
mod tests {
    use super::*;

    // Mock TUN device for testing
    struct MockTunDevice {
        name: String,
        mtu: usize,
    }

    impl TunDevice for MockTunDevice {
        fn read_packet(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Ok(0)
        }

        fn write_packet(&self, _buf: &[u8]) -> io::Result<()> {
            Ok(())
        }

        fn mtu(&self) -> usize {
            self.mtu
        }

        fn name(&self) -> &str {
            &self.name
        }
    }

    #[test]
    fn test_mock_tun_device() {
        let mut device = MockTunDevice {
            name: "test0".to_string(),
            mtu: 1500,
        };

        assert_eq!(device.name(), "test0");
        assert_eq!(device.mtu(), 1500);

        let mut buf = [0u8; 1500];
        assert!(device.read_packet(&mut buf).is_ok());
        assert!(device.write_packet(&[1, 2, 3]).is_ok());
    }
}
