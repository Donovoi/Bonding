//! Transport layer for multi-interface UDP with encryption.
//!
//! This module handles:
//! - UDP socket management per interface
//! - Packet encryption/decryption using ChaCha20Poly1305
//! - Sending and receiving packets across multiple paths

use chacha20poly1305::{
    aead::{Aead, AeadInPlace, KeyInit, OsRng},
    ChaCha20Poly1305, Key, Nonce,
};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;

use crate::proto::{Packet, PacketFlags, AUTH_TAG_SIZE};

/// Size of ChaCha20Poly1305 key in bytes
const KEY_SIZE: usize = 32;

/// Size of nonce in bytes
const NONCE_SIZE: usize = 12;

/// Transport encryption key
pub type EncryptionKey = [u8; KEY_SIZE];

/// Transport errors
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("Encryption error")]
    Encryption,

    #[error("Decryption error")]
    Decryption,

    #[error("Invalid key length")]
    InvalidKeyLength,

    #[error("Path not found: {0}")]
    PathNotFound(usize),
}

/// Transport path (UDP socket bound to specific interface)
pub struct TransportPath {
    /// Path identifier
    pub id: usize,
    /// UDP socket
    socket: Arc<UdpSocket>,
    /// Remote peer address
    peer_addr: SocketAddr,
}

impl TransportPath {
    /// Create a new transport path
    pub async fn new(id: usize, local_addr: SocketAddr, peer_addr: SocketAddr) -> io::Result<Self> {
        let socket = UdpSocket::bind(local_addr).await?;
        Ok(Self {
            id,
            socket: Arc::new(socket),
            peer_addr,
        })
    }

    /// Send data on this path
    pub async fn send(&self, data: &[u8]) -> io::Result<usize> {
        self.socket.send_to(data, self.peer_addr).await
    }

    /// Receive data on this path
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.socket.recv_from(buf).await
    }

    /// Get local address
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }
}

/// Packet encryptor/decryptor
pub struct PacketCrypto {
    cipher: ChaCha20Poly1305,
}

impl PacketCrypto {
    /// Create a new packet crypto with the given key
    pub fn new(key: &EncryptionKey) -> Self {
        let key = Key::from_slice(key);
        let cipher = ChaCha20Poly1305::new(key);
        Self { cipher }
    }

    /// Generate a new random encryption key
    pub fn generate_key() -> EncryptionKey {
        ChaCha20Poly1305::generate_key(&mut OsRng).into()
    }

    /// Encrypt a packet
    ///
    /// The nonce should be derived from the packet sequence number.
    pub fn encrypt(
        &self,
        nonce: &[u8; NONCE_SIZE],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, TransportError> {
        let nonce = Nonce::from_slice(nonce);
        self.cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| TransportError::Encryption)
    }

    /// Decrypt a packet
    pub fn decrypt(
        &self,
        nonce: &[u8; NONCE_SIZE],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, TransportError> {
        let nonce = Nonce::from_slice(nonce);
        self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| TransportError::Decryption)
    }

    /// Encrypt a packet returning a detached authentication tag.
    ///
    /// This matches the `proto::Packet` wire format, where the authentication
    /// tag is transported separately from the encrypted payload.
    ///
    /// `aad` should usually be the encoded packet header (`PacketHeader::encode()`)
    /// so that header fields are authenticated.
    pub fn encrypt_detached(
        &self,
        nonce: &[u8; NONCE_SIZE],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, [u8; AUTH_TAG_SIZE]), TransportError> {
        let nonce = Nonce::from_slice(nonce);
        let mut buf = plaintext.to_vec();

        let tag = self
            .cipher
            .encrypt_in_place_detached(nonce, aad, &mut buf)
            .map_err(|_| TransportError::Encryption)?;

        let mut tag_bytes = [0u8; AUTH_TAG_SIZE];
        tag_bytes.copy_from_slice(tag.as_slice());
        Ok((buf, tag_bytes))
    }

    /// Decrypt a packet with a detached authentication tag.
    pub fn decrypt_detached(
        &self,
        nonce: &[u8; NONCE_SIZE],
        aad: &[u8],
        ciphertext: &[u8],
        auth_tag: &[u8; AUTH_TAG_SIZE],
    ) -> Result<Vec<u8>, TransportError> {
        let nonce = Nonce::from_slice(nonce);
        let mut buf = ciphertext.to_vec();

        let tag = chacha20poly1305::Tag::from_slice(auth_tag);

        self.cipher
            .decrypt_in_place_detached(nonce, aad, &mut buf, tag)
            .map_err(|_| TransportError::Decryption)?;

        Ok(buf)
    }

    /// Create a nonce from a sequence number
    pub fn nonce_from_sequence(sequence: u64) -> [u8; NONCE_SIZE] {
        let mut nonce = [0u8; NONCE_SIZE];
        nonce[4..12].copy_from_slice(&sequence.to_be_bytes());
        nonce
    }

    /// Create a nonce from a domain and sequence number.
    ///
    /// This is important when both directions share the same encryption key;
    /// it avoids nonce reuse by scoping each direction to a different domain.
    pub fn nonce_from_domain_and_sequence(domain: u32, sequence: u64) -> [u8; NONCE_SIZE] {
        let mut nonce = [0u8; NONCE_SIZE];
        nonce[0..4].copy_from_slice(&domain.to_be_bytes());
        nonce[4..12].copy_from_slice(&sequence.to_be_bytes());
        nonce
    }

    /// Seal a `proto::Packet` (encrypt payload + fill `auth_tag`).
    ///
    /// The header is authenticated as AEAD associated data.
    pub fn seal_packet(
        &self,
        domain: u32,
        session_id: u64,
        sequence: u64,
        plaintext_payload: &[u8],
    ) -> Result<Packet, TransportError> {
        let mut packet = Packet::new(session_id, sequence, plaintext_payload.to_vec());

        let aad = packet.header.encode();
        let nonce = Self::nonce_from_domain_and_sequence(domain, sequence);
        let (ciphertext, tag) = self.encrypt_detached(&nonce, &aad, plaintext_payload)?;

        packet.payload = ciphertext;
        packet.auth_tag = tag;
        Ok(packet)
    }

    /// Seal a `proto::Packet` while setting header flags.
    ///
    /// This is useful for control/keepalive packets (e.g. `ACK_ONLY`) while
    /// still authenticating the header fields as AEAD associated data.
    pub fn seal_packet_with_flags(
        &self,
        domain: u32,
        session_id: u64,
        sequence: u64,
        flags_raw: u8,
        plaintext_payload: &[u8],
    ) -> Result<Packet, TransportError> {
        let mut packet = Packet::new(session_id, sequence, plaintext_payload.to_vec());
        packet.header.flags = PacketFlags::from_raw(flags_raw);

        let aad = packet.header.encode();
        let nonce = Self::nonce_from_domain_and_sequence(domain, sequence);
        let (ciphertext, tag) = self.encrypt_detached(&nonce, &aad, plaintext_payload)?;

        packet.payload = ciphertext;
        packet.auth_tag = tag;
        Ok(packet)
    }

    /// Open a `proto::Packet` (verify/decrypt payload).
    pub fn open_packet(
        &self,
        domain: u32,
        packet: &Packet,
    ) -> Result<Vec<u8>, TransportError> {
        // Basic sanity check before decrypt.
        if packet.header.payload_len as usize != packet.payload.len() {
            return Err(TransportError::Decryption);
        }

        let aad = packet.header.encode();
        let nonce = Self::nonce_from_domain_and_sequence(domain, packet.header.sequence);
        self.decrypt_detached(&nonce, &aad, &packet.payload, &packet.auth_tag)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::proto::PacketFlags;

    const DOMAIN_A: u32 = 0xAABBCCDD;
    const DOMAIN_B: u32 = 0x11223344;

    #[test]
    fn test_packet_crypto() {
        let key = PacketCrypto::generate_key();
        let crypto = PacketCrypto::new(&key);

        let plaintext = b"Hello, World!";
        let nonce = PacketCrypto::nonce_from_sequence(1);

        // Encrypt
        let ciphertext = crypto
            .encrypt(&nonce, plaintext)
            .expect("Encryption failed");
        assert_ne!(ciphertext.as_slice(), plaintext);

        // Decrypt
        let decrypted = crypto
            .decrypt(&nonce, &ciphertext)
            .expect("Decryption failed");
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn test_nonce_from_sequence() {
        let nonce1 = PacketCrypto::nonce_from_sequence(1);
        let nonce2 = PacketCrypto::nonce_from_sequence(2);

        assert_ne!(nonce1, nonce2);
        assert_eq!(nonce1.len(), NONCE_SIZE);
    }

    #[test]
    fn test_nonce_from_domain_and_sequence() {
        let a1 = PacketCrypto::nonce_from_domain_and_sequence(DOMAIN_A, 1);
        let a2 = PacketCrypto::nonce_from_domain_and_sequence(DOMAIN_A, 2);
        let b1 = PacketCrypto::nonce_from_domain_and_sequence(DOMAIN_B, 1);

        assert_ne!(a1, a2);
        assert_ne!(a1, b1);
        assert_eq!(a1.len(), NONCE_SIZE);
    }

    #[test]
    fn test_seal_open_packet_roundtrip() {
        let key = PacketCrypto::generate_key();
        let crypto = PacketCrypto::new(&key);

        let session_id = 42;
        let seq = 7;
        let plaintext = b"test payload";

        let pkt = crypto
            .seal_packet(DOMAIN_A, session_id, seq, plaintext)
            .expect("seal failed");

        // Ensure we actually produced a tag.
        assert_ne!(pkt.auth_tag, [0u8; AUTH_TAG_SIZE]);

        let opened = crypto
            .open_packet(DOMAIN_A, &pkt)
            .expect("open failed");
        assert_eq!(opened.as_slice(), plaintext);
    }

    #[test]
    fn test_open_packet_wrong_domain_fails() {
        let key = PacketCrypto::generate_key();
        let crypto = PacketCrypto::new(&key);

        let pkt = crypto
            .seal_packet(DOMAIN_A, 1, 1, b"hi")
            .expect("seal failed");

        let res = crypto.open_packet(DOMAIN_B, &pkt);
        assert!(res.is_err());
    }

    #[test]
    fn test_open_packet_tampered_header_fails() {
        let key = PacketCrypto::generate_key();
        let crypto = PacketCrypto::new(&key);

        let mut pkt = crypto
            .seal_packet(DOMAIN_A, 123, 99, b"hello")
            .expect("seal failed");

        // Flip a bit in the authenticated header.
        pkt.header.session_id ^= 1;

        let res = crypto.open_packet(DOMAIN_A, &pkt);
        assert!(res.is_err());
    }

    #[test]
    fn test_seal_packet_with_flags_roundtrip() {
        let key = PacketCrypto::generate_key();
        let crypto = PacketCrypto::new(&key);

        let session_id = 123;
        let seq = 1;
        let flags = PacketFlags::ACK_ONLY;
        let plaintext = b"";

        let pkt = crypto
            .seal_packet_with_flags(DOMAIN_A, session_id, seq, flags, plaintext)
            .expect("seal failed");

        assert!(pkt.header.flags.is_set(PacketFlags::ACK_ONLY));
        assert_eq!(pkt.payload.len(), 0);

        let opened = crypto.open_packet(DOMAIN_A, &pkt).expect("open failed");
        assert_eq!(opened.as_slice(), plaintext);
    }

    #[test]
    fn test_decrypt_wrong_nonce() {
        let key = PacketCrypto::generate_key();
        let crypto = PacketCrypto::new(&key);

        let plaintext = b"Test data";
        let nonce1 = PacketCrypto::nonce_from_sequence(1);
        let nonce2 = PacketCrypto::nonce_from_sequence(2);

        let ciphertext = crypto
            .encrypt(&nonce1, plaintext)
            .expect("Encryption failed");

        // Decryption with wrong nonce should fail
        let result = crypto.decrypt(&nonce2, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_tampered_ciphertext() {
        let key = PacketCrypto::generate_key();
        let crypto = PacketCrypto::new(&key);

        let plaintext = b"Test data";
        let nonce = PacketCrypto::nonce_from_sequence(1);

        let mut ciphertext = crypto
            .encrypt(&nonce, plaintext)
            .expect("Encryption failed");

        // Tamper with ciphertext
        if let Some(byte) = ciphertext.first_mut() {
            *byte ^= 0xFF;
        }

        // Decryption should fail due to authentication
        let result = crypto.decrypt(&nonce, &ciphertext);
        assert!(result.is_err());
    }
}
