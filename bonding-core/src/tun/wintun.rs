use std::io;
use std::sync::Arc;
use wintun;

use crate::tun::{TunDevice, TunConfig};

pub struct WintunDevice {
    session: Arc<wintun::Session>,
    adapter: Arc<wintun::Adapter>,
}

impl WintunDevice {
    pub fn new(config: TunConfig) -> io::Result<Self> {
        // Load the wintun.dll
        let wintun = unsafe { wintun::load() }.map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to load wintun.dll: {}", e),
            )
        })?;

        // Create or open the adapter
        let adapter = match wintun::Adapter::open(&wintun, &config.name) {
            Ok(adapter) => adapter,
            Err(_) => wintun::Adapter::create(&wintun, &config.name, &config.name, None)
                .map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::Other,
                        format!("Failed to create wintun adapter: {}", e),
                    )
                })?,
        };

        // Set the IP address and netmask
        // Note: This is typically done through the Windows API or netsh
        // For now, we'll assume it's configured externally

        // Start a session
        let session = adapter.start_session(wintun::MAX_RING_CAPACITY).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to start wintun session: {}", e),
            )
        })?;

        Ok(WintunDevice {
            session: Arc::new(session),
            adapter: Arc::new(adapter),
        })
    }

    fn read_packet(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // Try to receive a packet (non-blocking)
        match self.session.try_receive() {
            Ok(Some(packet)) => {
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
            Ok(None) => Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "No packet available",
            )),
            Err(e) => {
                // Convert wintun error to io::Error
                match e {
                    wintun::Error::ShuttingDown => Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "Wintun session is shutting down",
                    )),
                    _ => Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "No packet available",
                    )),
                }
            }
        }
    }

    fn write_packet(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Allocate a send packet
        let mut packet = self.session.allocate_send_packet(buf.len() as u16).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to allocate send packet: {}", e),
            )
        })?;

        // Copy data into the packet
        packet.bytes_mut().copy_from_slice(buf);

        // Send the packet
        self.session.send_packet(packet);

        Ok(buf.len())
    }
}

impl TunDevice for WintunDevice {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.read_packet(buf)
    }

    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_packet(buf)
    }

    fn name(&self) -> &str {
        // The wintun adapter doesn't expose the name directly
        // We'll return a placeholder for now
        "wintun"
    }

    fn mtu(&self) -> io::Result<usize> {
        // Wintun doesn't have a direct MTU query
        // Return the default MTU for now
        Ok(1500)
    }
}
