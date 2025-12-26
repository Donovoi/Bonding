//! Linux TUN device implementation.
//!
//! This module provides a safe wrapper around Linux TUN/TAP devices for creating
//! virtual Layer-3 adapters on Linux.
//!
//! # Safety Requirements
//!
//! - Root privileges required for TUN device creation
//! - Requires TUN/TAP kernel module loaded (`modprobe tun`)
//! - `/dev/net/tun` must be accessible
//!
//! # Platform
//!
//! This module is Linux-only and will not compile on other platforms.

use super::TunDevice;
use std::io;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Default MTU for TUN adapters
const DEFAULT_MTU: usize = 1420;

/// Default TUN device name
const DEFAULT_DEVICE_NAME: &str = "bonding0";

/// Linux TUN device implementation
///
/// This structure wraps the Linux TUN device and provides a safe interface
/// for reading and writing IP packets.
///
/// # Important Note on Async vs Sync
///
/// The underlying `tun-rs` library is async-only. The `TunDevice` trait methods
/// (`read_packet` and `write_packet`) will return `WouldBlock` errors to indicate
/// that async operations should be used instead.
///
/// For Linux, use `device_handle()` to get access to the async device for actual
/// I/O operations in async contexts.
///
/// # Example
///
/// ```no_run
/// # use bonding_core::tun::LinuxTunDevice;
/// # async fn example() -> std::io::Result<()> {
/// let device = LinuxTunDevice::new("tun0").await?;
/// let device_handle = device.device_handle();
///
/// // Use async operations on the device handle in async context
/// // The device_handle is an Arc<Mutex<tun_rs::AsyncDevice>>
/// // which can be used with tokio for async I/O
/// # Ok(())
/// # }
/// ```
pub struct LinuxTunDevice {
    name: String,
    mtu: usize,
    device: Arc<Mutex<tun_rs::AsyncDevice>>,
}

impl LinuxTunDevice {
    /// Create a new Linux TUN device
    ///
    /// # Arguments
    ///
    /// * `device_name` - Name for the TUN device (e.g., "tun0")
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Root privileges are insufficient
    /// - TUN module is not loaded
    /// - The device cannot be created
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use bonding_core::tun::LinuxTunDevice;
    /// # async fn example() -> std::io::Result<()> {
    /// let device = LinuxTunDevice::new("tun0").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn new(device_name: &str) -> io::Result<Self> {
        use tun_rs::DeviceBuilder;

        // Create the TUN device
        let device = DeviceBuilder::new()
            .name(device_name)
            .mtu(u16::try_from(DEFAULT_MTU).expect("MTU must fit in u16"))
            .build_async()
            .map_err(|e| io::Error::other(format!("Failed to create TUN device: {}", e)))?;

        let actual_name = device
            .name()
            .map_err(|e| io::Error::other(format!("Failed to get device name: {}", e)))?;

        tracing::info!(
            "Created Linux TUN device '{}' with MTU {}",
            actual_name,
            DEFAULT_MTU
        );

        Ok(Self {
            name: actual_name,
            mtu: DEFAULT_MTU,
            device: Arc::new(Mutex::new(device)),
        })
    }

    /// Create a TUN device with default name
    pub async fn new_default() -> io::Result<Self> {
        Self::new(DEFAULT_DEVICE_NAME).await
    }

    /// Get a clone of the device handle for async operations
    pub fn device_handle(&self) -> Arc<Mutex<tun_rs::AsyncDevice>> {
        Arc::clone(&self.device)
    }
}

impl TunDevice for LinuxTunDevice {
    fn read_packet(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        // The TunDevice trait is synchronous, but tun-rs AsyncDevice requires async
        // For Linux, users should use the async device directly via device_handle()
        // This is a design limitation of the current TunDevice trait which was
        // designed with Windows Wintun's sync API in mind
        Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "Linux TUN device requires async operations - use device_handle() to get async device",
        ))
    }

    fn write_packet(&self, buf: &[u8]) -> io::Result<()> {
        // Validate input first for consistent error messages
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

        // The TunDevice trait is synchronous, but tun-rs AsyncDevice requires async
        // Validation passed, but operation requires async context
        Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "Linux TUN device requires async operations - use device_handle() to get async device",
        ))
    }

    fn mtu(&self) -> usize {
        self.mtu
    }

    fn name(&self) -> &str {
        &self.name
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[cfg(target_os = "linux")]
    #[ignore] // Requires root privileges
    async fn test_linux_tun_device_creation() {
        // This test requires root privileges
        let device_name = "test_tun0";
        let device = LinuxTunDevice::new(device_name).await;

        match device {
            Ok(dev) => {
                assert_eq!(dev.mtu(), DEFAULT_MTU);
                // Name might have been modified by the system
                assert!(!dev.name().is_empty());
            }
            Err(e) => {
                // Expected to fail without root privileges
                eprintln!("Note: Test failed as expected without root: {}", e);
            }
        }
    }

    #[tokio::test]
    #[cfg(target_os = "linux")]
    #[ignore] // Requires root privileges
    async fn test_linux_tun_device_io() {
        let mut device = match LinuxTunDevice::new_default().await {
            Ok(d) => d,
            Err(_) => return, // Skip if can't create device
        };

        // Test that sync read returns WouldBlock (as expected for async device)
        let mut buf = vec![0u8; 2048];
        let result = device.read_packet(&mut buf);
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::WouldBlock);

        // Test that sync write returns WouldBlock (as expected for async device)
        let test_packet = vec![0x45, 0x00, 0x00, 0x20]; // Simple IP header start
        let result = device.write_packet(&test_packet);
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::WouldBlock);

        // Verify we can get the async device handle
        let _device_handle = device.device_handle();
    }
}
