//! Transport layer for multi-interface UDP with encryption.
//!
//! This module handles:
//! - UDP socket management per interface
//! - Packet encryption/decryption using ChaCha20Poly1305
//! - Sending and receiving packets across multiple paths

use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Key, Nonce,
};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;

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

    /// Create a nonce from a sequence number
    pub fn nonce_from_sequence(sequence: u64) -> [u8; NONCE_SIZE] {
        let mut nonce = [0u8; NONCE_SIZE];
        nonce[4..12].copy_from_slice(&sequence.to_be_bytes());
        nonce
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
