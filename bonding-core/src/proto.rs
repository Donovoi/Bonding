//! Protocol definitions for the Bonding overlay network.
//!
//! This module defines the wire format for all packets exchanged between client and server.
//! The protocol is versioned from day one and uses network byte order (big-endian) for all
//! multi-byte fields.
//!
//! # Packet Format
//!
//! Every data-plane packet includes:
//! - Magic number (4 bytes): Protocol identifier
//! - Version (1 byte): Protocol version
//! - Session ID (8 bytes): Unique session identifier
//! - Sequence number (8 bytes): Monotonically increasing counter
//! - Flags (1 byte): Packet flags (retransmit, redundant, ack-only, etc.)
//! - Payload length (2 bytes): Length of encrypted payload
//! - Authenticated tag (16 bytes): AEAD authentication tag
//! - Payload (variable): Encrypted IP packet
//!
//! Total header size: 40 bytes + variable payload

use serde::{Deserialize, Serialize};
use std::fmt;

/// Magic number identifying Bonding protocol packets (ASCII: "BOND")
pub const PROTOCOL_MAGIC: u32 = 0x424F4E44;

/// Current protocol version
pub const CURRENT_VERSION: u8 = 1;

/// Size of the AEAD authentication tag (ChaCha20Poly1305)
pub const AUTH_TAG_SIZE: usize = 16;

/// Minimum packet size (header only, no payload)
pub const MIN_PACKET_SIZE: usize = 40;

/// Maximum packet size (limited by MTU considerations)
pub const MAX_PACKET_SIZE: usize = 1500;

/// Protocol version information
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolVersion(pub u8);

impl ProtocolVersion {
    /// Create a new protocol version
    pub fn new(version: u8) -> Self {
        Self(version)
    }

    /// Get the current protocol version
    pub fn current() -> Self {
        Self(CURRENT_VERSION)
    }

    /// Check if this version is supported
    pub fn is_supported(&self) -> bool {
        self.0 == CURRENT_VERSION
    }
}

impl fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "v{}", self.0)
    }
}

/// Packet flags
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketFlags(u8);

impl PacketFlags {
    /// Create empty flags
    pub fn empty() -> Self {
        Self(0)
    }

    /// Packet is a retransmission
    pub const RETRANSMIT: u8 = 0b0000_0001;

    /// Packet is a redundant copy
    pub const REDUNDANT: u8 = 0b0000_0010;

    /// Packet is ACK-only (no payload)
    pub const ACK_ONLY: u8 = 0b0000_0100;

    /// Set a flag
    pub fn set(&mut self, flag: u8) {
        self.0 |= flag;
    }

    /// Check if a flag is set
    pub fn is_set(&self, flag: u8) -> bool {
        self.0 & flag != 0
    }

    /// Get raw flags value
    pub fn raw(&self) -> u8 {
        self.0
    }

    /// Create from raw value
    pub fn from_raw(value: u8) -> Self {
        Self(value)
    }
}

/// Packet header structure
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketHeader {
    /// Magic number for protocol identification
    pub magic: u32,
    /// Protocol version
    pub version: ProtocolVersion,
    /// Session identifier
    pub session_id: u64,
    /// Sequence number
    pub sequence: u64,
    /// Packet flags
    pub flags: PacketFlags,
    /// Payload length
    pub payload_len: u16,
}

impl PacketHeader {
    /// Size of the header in bytes
    pub const SIZE: usize = 24;

    /// Create a new packet header
    pub fn new(session_id: u64, sequence: u64) -> Self {
        Self {
            magic: PROTOCOL_MAGIC,
            version: ProtocolVersion::current(),
            session_id,
            sequence,
            flags: PacketFlags::empty(),
            payload_len: 0,
        }
    }

    /// Encode header to bytes (network byte order)
    pub fn encode(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0..4].copy_from_slice(&self.magic.to_be_bytes());
        buf[4] = self.version.0;
        buf[5..13].copy_from_slice(&self.session_id.to_be_bytes());
        buf[13..21].copy_from_slice(&self.sequence.to_be_bytes());
        buf[21] = self.flags.raw();
        buf[22..24].copy_from_slice(&self.payload_len.to_be_bytes());
        buf
    }

    /// Decode header from bytes (network byte order)
    pub fn decode(buf: &[u8]) -> Result<Self, ProtocolError> {
        if buf.len() < Self::SIZE {
            return Err(ProtocolError::InvalidLength {
                expected: Self::SIZE,
                actual: buf.len(),
            });
        }

        let magic = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if magic != PROTOCOL_MAGIC {
            return Err(ProtocolError::InvalidMagic(magic));
        }

        let version = ProtocolVersion(buf[4]);
        if !version.is_supported() {
            return Err(ProtocolError::UnsupportedVersion(version));
        }

        let session_id = u64::from_be_bytes([
            buf[5], buf[6], buf[7], buf[8], buf[9], buf[10], buf[11], buf[12],
        ]);
        let sequence = u64::from_be_bytes([
            buf[13], buf[14], buf[15], buf[16], buf[17], buf[18], buf[19], buf[20],
        ]);
        let flags = PacketFlags::from_raw(buf[21]);
        let payload_len = u16::from_be_bytes([buf[22], buf[23]]);

        Ok(Self {
            magic,
            version,
            session_id,
            sequence,
            flags,
            payload_len,
        })
    }

    /// Validate header fields
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.magic != PROTOCOL_MAGIC {
            return Err(ProtocolError::InvalidMagic(self.magic));
        }
        if !self.version.is_supported() {
            return Err(ProtocolError::UnsupportedVersion(self.version));
        }
        if self.payload_len as usize > MAX_PACKET_SIZE - MIN_PACKET_SIZE {
            return Err(ProtocolError::PayloadTooLarge(self.payload_len as usize));
        }
        Ok(())
    }
}

/// Complete packet with header and payload
#[derive(Debug, Clone)]
pub struct Packet {
    /// Packet header
    pub header: PacketHeader,
    /// AEAD authentication tag
    pub auth_tag: [u8; AUTH_TAG_SIZE],
    /// Encrypted payload (IP packet)
    pub payload: Vec<u8>,
}

impl Packet {
    /// Create a new packet
    pub fn new(session_id: u64, sequence: u64, payload: Vec<u8>) -> Self {
        let mut header = PacketHeader::new(session_id, sequence);
        header.payload_len = payload.len() as u16;

        Self {
            header,
            auth_tag: [0u8; AUTH_TAG_SIZE],
            payload,
        }
    }

    /// Total size of the packet in bytes
    pub fn total_size(&self) -> usize {
        PacketHeader::SIZE + AUTH_TAG_SIZE + self.payload.len()
    }

    /// Encode packet to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.total_size());
        buf.extend_from_slice(&self.header.encode());
        buf.extend_from_slice(&self.auth_tag);
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// Decode packet from bytes
    pub fn decode(buf: &[u8]) -> Result<Self, ProtocolError> {
        if buf.len() < MIN_PACKET_SIZE {
            return Err(ProtocolError::InvalidLength {
                expected: MIN_PACKET_SIZE,
                actual: buf.len(),
            });
        }

        let header = PacketHeader::decode(&buf[..PacketHeader::SIZE])?;
        header.validate()?;

        let auth_tag_end = PacketHeader::SIZE + AUTH_TAG_SIZE;
        if buf.len() < auth_tag_end {
            return Err(ProtocolError::InvalidLength {
                expected: auth_tag_end,
                actual: buf.len(),
            });
        }

        let mut auth_tag = [0u8; AUTH_TAG_SIZE];
        auth_tag.copy_from_slice(&buf[PacketHeader::SIZE..auth_tag_end]);

        let payload_start = auth_tag_end;
        let expected_len = payload_start + header.payload_len as usize;
        if buf.len() < expected_len {
            return Err(ProtocolError::InvalidLength {
                expected: expected_len,
                actual: buf.len(),
            });
        }

        let payload = buf[payload_start..expected_len].to_vec();

        Ok(Self {
            header,
            auth_tag,
            payload,
        })
    }
}

/// Protocol-related errors
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("Invalid magic number: 0x{0:08X} (expected 0x{:08X})", PROTOCOL_MAGIC)]
    InvalidMagic(u32),

    #[error("Unsupported protocol version: {0}")]
    UnsupportedVersion(ProtocolVersion),

    #[error("Invalid packet length: expected at least {expected}, got {actual}")]
    InvalidLength { expected: usize, actual: usize },

    #[error("Payload too large: {0} bytes")]
    PayloadTooLarge(usize),

    #[error("Invalid flags: unknown flags set")]
    InvalidFlags,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_version() {
        let version = ProtocolVersion::current();
        assert!(version.is_supported());
        assert_eq!(version.0, CURRENT_VERSION);
    }

    #[test]
    fn test_packet_flags() {
        let mut flags = PacketFlags::empty();
        assert!(!flags.is_set(PacketFlags::RETRANSMIT));

        flags.set(PacketFlags::RETRANSMIT);
        assert!(flags.is_set(PacketFlags::RETRANSMIT));
        assert!(!flags.is_set(PacketFlags::REDUNDANT));

        flags.set(PacketFlags::REDUNDANT);
        assert!(flags.is_set(PacketFlags::RETRANSMIT));
        assert!(flags.is_set(PacketFlags::REDUNDANT));
    }

    #[test]
    fn test_header_encode_decode() {
        let header = PacketHeader {
            magic: PROTOCOL_MAGIC,
            version: ProtocolVersion::current(),
            session_id: 0x1234567890ABCDEF,
            sequence: 42,
            flags: PacketFlags::empty(),
            payload_len: 100,
        };

        let encoded = header.encode();
        let decoded = PacketHeader::decode(&encoded).expect("Failed to decode header");

        assert_eq!(header, decoded);
    }

    #[test]
    fn test_header_invalid_magic() {
        let mut buf = [0u8; PacketHeader::SIZE];
        buf[0..4].copy_from_slice(&0xDEADBEEFu32.to_be_bytes());
        buf[4] = CURRENT_VERSION;

        let result = PacketHeader::decode(&buf);
        assert!(matches!(result, Err(ProtocolError::InvalidMagic(_))));
    }

    #[test]
    fn test_header_unsupported_version() {
        let mut buf = [0u8; PacketHeader::SIZE];
        buf[0..4].copy_from_slice(&PROTOCOL_MAGIC.to_be_bytes());
        buf[4] = 99; // Unsupported version

        let result = PacketHeader::decode(&buf);
        assert!(matches!(result, Err(ProtocolError::UnsupportedVersion(_))));
    }

    #[test]
    fn test_packet_encode_decode() {
        let payload = vec![1, 2, 3, 4, 5];
        let packet = Packet::new(0x123456, 100, payload.clone());

        let encoded = packet.encode();
        let decoded = Packet::decode(&encoded).expect("Failed to decode packet");

        assert_eq!(packet.header.session_id, decoded.header.session_id);
        assert_eq!(packet.header.sequence, decoded.header.sequence);
        assert_eq!(packet.payload, decoded.payload);
    }

    #[test]
    fn test_packet_too_short() {
        let buf = vec![0u8; 10]; // Too short
        let result = Packet::decode(&buf);
        assert!(matches!(result, Err(ProtocolError::InvalidLength { .. })));
    }
}
