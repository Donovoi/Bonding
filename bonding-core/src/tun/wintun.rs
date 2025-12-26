use std::io;
use std::net::Ipv4Addr;
use std::sync::Arc;
use wintun;

use crate::tun::{TunDevice, TunInterface};

pub struct WintunDevice {
    adapter: Arc<wintun::Adapter>,
    session: Arc<wintun::Session>,
}

impl WintunDevice {
    pub fn new(name: &str, tunnel_type: &str) -> io::Result<Self> {
        // Load wintun.dll
        let wintun = unsafe {
            wintun::load().map_err(|e| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("Failed to load wintun.dll: {:?}", e),
                )
            })?
        };

        // Create adapter
        let adapter = match wintun::Adapter::open(&wintun, name) {
            Ok(adapter) => adapter,
            Err(_) => wintun::Adapter::create(&wintun, name, tunnel_type, None).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("Failed to create adapter: {:?}", e),
                )
            })?,
        };

        // Start session with 0x400000 ring capacity
        let session = adapter.start_session(wintun::MAX_RING_CAPACITY).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to start session: {:?}", e),
            )
        })?;

        Ok(WintunDevice {
            adapter: Arc::new(adapter),
            session: Arc::new(session),
        })
    }

    pub fn set_ip(&self, ip: Ipv4Addr, netmask: Ipv4Addr) -> io::Result<()> {
        // Use netsh to set IP address
        let output = std::process::Command::new("netsh")
            .args(&[
                "interface",
                "ip",
                "set",
                "address",
                &self.adapter.get_adapter_name().map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::Other,
                        format!("Failed to get adapter name: {:?}", e),
                    )
                })?,
                "static",
                &ip.to_string(),
                &netmask.to_string(),
            ])
            .output()?;

        if !output.status.success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "Failed to set IP address: {}",
                    String::from_utf8_lossy(&output.stderr)
                ),
            ));
        }

        Ok(())
    }

    pub fn set_mtu(&self, mtu: u32) -> io::Result<()> {
        // Use netsh to set MTU
        let output = std::process::Command::new("netsh")
            .args(&[
                "interface",
                "ipv4",
                "set",
                "subinterface",
                &self.adapter.get_adapter_name().map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::Other,
                        format!("Failed to get adapter name: {:?}", e),
                    )
                })?,
                &format!("mtu={}", mtu),
            ])
            .output()?;

        if !output.status.success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "Failed to set MTU: {}",
                    String::from_utf8_lossy(&output.stderr)
                ),
            ));
        }

        Ok(())
    }

    pub fn up(&self) -> io::Result<()> {
        // Use netsh to enable interface
        let output = std::process::Command::new("netsh")
            .args(&[
                "interface",
                "set",
                "interface",
                &self.adapter.get_adapter_name().map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::Other,
                        format!("Failed to get adapter name: {:?}", e),
                    )
                })?,
                "admin=enabled",
            ])
            .output()?;

        if !output.status.success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "Failed to enable interface: {}",
                    String::from_utf8_lossy(&output.stderr)
                ),
            ));
        }

        Ok(())
    }

    fn read_packet(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // Try to receive a packet (non-blocking)
        match self.session.try_receive() {
            Ok(packet) => {
                // Handle the Option type - packet might be None
                if let Some(pkt) = packet {
                    let packet_bytes = pkt.bytes();
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
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "No packet available",
                    ))
                }
            }
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
        let len = buf.len();

        // Allocate a send packet
        let mut packet = self
            .session
            .allocate_send_packet(len as u16)
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("Failed to allocate send packet: {:?}", e),
                )
            })?;

        // Copy data into packet
        packet.bytes_mut()[..len].copy_from_slice(buf);

        // Send the packet
        self.session.send_packet(packet);

        Ok(len)
    }
}

impl TunDevice for WintunDevice {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.read_packet(buf)
    }

    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_packet(buf)
    }

    fn name(&self) -> io::Result<String> {
        self.adapter.get_adapter_name().map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to get adapter name: {:?}", e),
            )
        })
    }
}

impl TunInterface for WintunDevice {
    fn set_ip(&mut self, ip: Ipv4Addr, netmask: Ipv4Addr) -> io::Result<()> {
        self.set_ip(ip, netmask)
    }

    fn set_mtu(&mut self, mtu: u32) -> io::Result<()> {
        self.set_mtu(mtu)
    }

    fn up(&mut self) -> io::Result<()> {
        self.up()
    }
}
