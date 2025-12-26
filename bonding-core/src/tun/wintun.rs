use std::sync::Arc;
use wintun::Session;
use crate::error::Result;

pub struct WintunTun {
    session: Arc<Session>,
}

impl WintunTun {
    pub fn new(session: Arc<Session>) -> Self {
        Self { session }
    }

    pub fn read_packet(&self) -> Result<Vec<u8>> {
        let packet = self.session.receive_blocking();
        let pkt = packet.expect("Failed to receive packet");
        let packet_bytes = pkt.bytes();
        Ok(packet_bytes.to_vec())
    }

    pub fn write_packet(&self, data: &[u8]) -> Result<()> {
        let mut packet = self.session.allocate_send_packet(data.len() as u16)?;
        packet.bytes_mut().copy_from_slice(data);
        self.session.send_packet(packet);
        Ok(())
    }
}
