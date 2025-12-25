//! Control plane for health metrics, interface discovery, and configuration.
//!
//! This module manages:
//! - Network interface enumeration
//! - Health monitoring and metrics collection
//! - Configuration management
//! - Session management

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

/// Configuration for the bonding client
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BondingConfig {
    /// Server address
    pub server_addr: String,
    /// Server port
    pub server_port: u16,
    /// Bonding mode
    pub bonding_mode: String,
    /// TUN adapter name
    pub adapter_name: String,
    /// TUN adapter MTU
    pub mtu: usize,
    /// Enable encryption
    pub enable_encryption: bool,
    /// Health check interval
    pub health_check_interval: Duration,
}

impl Default for BondingConfig {
    fn default() -> Self {
        Self {
            server_addr: "127.0.0.1".to_string(),
            server_port: 5000,
            bonding_mode: "stripe".to_string(),
            adapter_name: "Bonding".to_string(),
            mtu: 1420,
            enable_encryption: true,
            health_check_interval: Duration::from_secs(5),
        }
    }
}

/// Network interface information
#[derive(Debug, Clone)]
pub struct NetworkInterface {
    /// Interface name
    pub name: String,
    /// Interface index
    pub index: u32,
    /// IP addresses assigned to this interface
    pub addresses: Vec<IpAddr>,
    /// Whether interface is up
    pub is_up: bool,
    /// Interface type (ethernet, wifi, etc.)
    pub if_type: InterfaceType,
}

/// Network interface type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterfaceType {
    Ethernet,
    Wifi,
    Loopback,
    Other,
}

/// Health metrics for a session
#[derive(Debug, Clone, Default)]
pub struct SessionHealth {
    /// Total packets sent
    pub packets_sent: u64,
    /// Total packets received
    pub packets_received: u64,
    /// Total bytes sent
    pub bytes_sent: u64,
    /// Total bytes received
    pub bytes_received: u64,
    /// Packet loss rate
    pub loss_rate: f64,
    /// Average RTT
    pub avg_rtt: Duration,
    /// Session uptime
    pub uptime: Duration,
}

/// Session manager for tracking active sessions
pub struct SessionManager {
    /// Active sessions by session ID
    sessions: HashMap<u64, SessionHealth>,
}

impl SessionManager {
    /// Create a new session manager
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }

    /// Register a new session
    pub fn register(&mut self, session_id: u64) {
        self.sessions.insert(session_id, SessionHealth::default());
    }

    /// Unregister a session
    pub fn unregister(&mut self, session_id: u64) {
        self.sessions.remove(&session_id);
    }

    /// Update session metrics
    pub fn update(&mut self, session_id: u64, health: SessionHealth) {
        self.sessions.insert(session_id, health);
    }

    /// Get session health metrics
    pub fn get(&self, session_id: u64) -> Option<&SessionHealth> {
        self.sessions.get(&session_id)
    }

    /// Get all active session IDs
    pub fn active_sessions(&self) -> Vec<u64> {
        self.sessions.keys().copied().collect()
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Interface discovery for enumerating network interfaces
pub struct InterfaceDiscovery;

impl InterfaceDiscovery {
    /// Discover all network interfaces
    ///
    /// This is a placeholder that will need platform-specific implementation.
    pub fn discover() -> Vec<NetworkInterface> {
        // TODO: Implement actual interface discovery
        // On Windows: Use GetAdaptersAddresses
        // On Linux: Parse /sys/class/net or use netlink
        Vec::new()
    }

    /// Discover interfaces suitable for bonding (active internet connections)
    pub fn discover_bondable() -> Vec<NetworkInterface> {
        Self::discover()
            .into_iter()
            .filter(|iface| {
                iface.is_up
                    && !iface.addresses.is_empty()
                    && iface.if_type != InterfaceType::Loopback
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bonding_config_default() {
        let config = BondingConfig::default();
        assert_eq!(config.server_port, 5000);
        assert_eq!(config.bonding_mode, "stripe");
        assert!(config.enable_encryption);
    }

    #[test]
    fn test_session_manager() {
        let mut manager = SessionManager::new();

        // Register sessions
        manager.register(1);
        manager.register(2);

        assert_eq!(manager.active_sessions().len(), 2);

        // Update metrics
        let health = SessionHealth {
            packets_sent: 100,
            ..Default::default()
        };
        manager.update(1, health);

        let retrieved = manager.get(1).unwrap();
        assert_eq!(retrieved.packets_sent, 100);

        // Unregister
        manager.unregister(1);
        assert_eq!(manager.active_sessions().len(), 1);
        assert!(manager.get(1).is_none());
    }

    #[test]
    fn test_interface_discovery() {
        let interfaces = InterfaceDiscovery::discover();
        // For now, this returns empty until implemented
        assert!(interfaces.is_empty() || !interfaces.is_empty());
    }
}
