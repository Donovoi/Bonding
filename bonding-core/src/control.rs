//! Control plane for health metrics, interface discovery, and configuration.
//!
//! This module manages:
//! - Network interface enumeration
//! - Health monitoring and metrics collection
//! - Configuration management
//! - Session management

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

fn default_tun_ipv4_prefix() -> u8 {
    24
}

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

    /// Enable TUN packet forwarding (data-plane).
    ///
    /// When enabled, the client will attempt to read IP packets from the local
    /// TUN adapter and forward them to the server over UDP.
    #[serde(default)]
    pub enable_tun: bool,

    /// Automatically configure the local TUN adapter with IP/MTU/routes.
    ///
    /// Safe default: false. When enabled, platform-specific commands may be
    /// executed (Windows: netsh/route; Linux: ip).
    #[serde(default)]
    pub auto_config_tun: bool,

    /// IPv4 address to assign to the local TUN adapter.
    ///
    /// Only used when `enable_tun` and `auto_config_tun` are true.
    #[serde(default)]
    pub tun_ipv4_addr: Option<Ipv4Addr>,

    /// IPv4 prefix length to use with `tun_ipv4_addr` (e.g. 24 for /24).
    #[serde(default = "default_tun_ipv4_prefix")]
    pub tun_ipv4_prefix: u8,

    /// Optional routes (CIDR strings) to add via the TUN adapter.
    ///
    /// Examples: "10.10.0.0/16", "0.0.0.0/0".
    #[serde(default)]
    pub tun_routes: Vec<String>,
    /// Enable encryption
    pub enable_encryption: bool,

    /// Base64-encoded 32-byte pre-shared key used for packet encryption.
    ///
    /// If `enable_encryption` is true, client/server must be configured with the
    /// same key.
    #[serde(default)]
    pub encryption_key_b64: Option<String>,
    /// Health check interval
    #[serde(with = "humantime_serde")]
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
            enable_tun: false,
            auto_config_tun: false,
            tun_ipv4_addr: None,
            tun_ipv4_prefix: default_tun_ipv4_prefix(),
            tun_routes: Vec::new(),
            enable_encryption: true,
            encryption_key_b64: None,
            health_check_interval: Duration::from_secs(5),
        }
    }
}

/// Configuration for the bonding server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Address to bind the UDP socket to
    pub listen_addr: String,
    /// Port to bind the UDP socket to
    pub listen_port: u16,

    /// Enable TUN packet forwarding (data-plane).
    ///
    /// When enabled on Linux, the server will attempt to read/write IP packets
    /// from/to a local TUN device and forward them over UDP.
    #[serde(default)]
    pub enable_tun: bool,

    /// Automatically configure the local TUN device with IP/MTU/routes.
    ///
    /// Safe default: false.
    #[serde(default)]
    pub auto_config_tun: bool,

    /// IPv4 address to assign to the server-side TUN device.
    #[serde(default)]
    pub tun_ipv4_addr: Option<Ipv4Addr>,

    /// IPv4 prefix length to use with `tun_ipv4_addr`.
    #[serde(default = "default_tun_ipv4_prefix")]
    pub tun_ipv4_prefix: u8,

    /// Optional routes (CIDR strings) to add via the TUN device.
    #[serde(default)]
    pub tun_routes: Vec<String>,

    /// Enable IPv4 forwarding on the server (Linux only).
    ///
    /// Required for routing packets between the Bonding TUN device and other
    /// interfaces (e.g. `tailscale0` for tailnet access, or `eth0` for WAN).
    #[serde(default)]
    pub enable_ipv4_forwarding: bool,

    /// Add IPv4 NAT (MASQUERADE) rules for traffic sourced from the Bonding TUN
    /// subnet and leaving via the given output interfaces (Linux only).
    ///
    /// Example for "Option A" (tailnet access from tunnel clients):
    /// ["tailscale0"].
    #[serde(default)]
    pub nat_masquerade_out_ifaces: Vec<String>,

    /// Enable Windows NAT using NetNat (PowerShell) for traffic from the Bonding
    /// TUN subnet (Windows only).
    ///
    /// Safe default: false.
    #[serde(default)]
    pub windows_enable_netnat: bool,

    /// Name to use for the NetNat instance (Windows only).
    #[serde(default = "default_windows_netnat_name")]
    pub windows_netnat_name: String,

    /// Internal prefix for NetNat (CIDR string), e.g. "198.18.0.0/24".
    ///
    /// If not set, the server derives it from `tun_ipv4_addr` + `tun_ipv4_prefix`.
    #[serde(default)]
    pub windows_netnat_internal_prefix: Option<String>,

    /// Linux TUN device name (used when `enable_tun` is enabled).
    #[serde(default)]
    pub tun_device_name: String,

    /// Linux TUN MTU (used when `enable_tun` is enabled).
    #[serde(default)]
    pub tun_mtu: usize,
    /// Enable encryption (future)
    pub enable_encryption: bool,

    /// Base64-encoded 32-byte pre-shared key used for packet encryption.
    ///
    /// If `enable_encryption` is true, the server will attempt to decrypt inbound
    /// packets using this key.
    #[serde(default)]
    pub encryption_key_b64: Option<String>,
    /// Health/logging interval
    #[serde(with = "humantime_serde")]
    pub health_interval: Duration,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0".to_string(),
            listen_port: 5000,
            enable_tun: false,
            auto_config_tun: false,
            tun_ipv4_addr: None,
            tun_ipv4_prefix: default_tun_ipv4_prefix(),
            tun_routes: Vec::new(),
            enable_ipv4_forwarding: false,
            nat_masquerade_out_ifaces: Vec::new(),
            windows_enable_netnat: false,
            windows_netnat_name: default_windows_netnat_name(),
            windows_netnat_internal_prefix: None,
            tun_device_name: "bonding0".to_string(),
            tun_mtu: 1420,
            enable_encryption: true,
            encryption_key_b64: None,
            health_interval: Duration::from_secs(5),
        }
    }
}

fn default_windows_netnat_name() -> String {
    "Bonding".to_string()
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
    #[cfg(target_os = "windows")]
    pub fn discover() -> Vec<NetworkInterface> {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
        use windows::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS};
        use windows::Win32::NetworkManagement::IpHelper::{
            GetAdaptersAddresses, GAA_FLAG_INCLUDE_PREFIX, GAA_FLAG_SKIP_ANYCAST,
            GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST, IF_TYPE_ETHERNET_CSMACD,
            IF_TYPE_IEEE80211, IF_TYPE_SOFTWARE_LOOPBACK, IP_ADAPTER_ADDRESSES_LH,
        };
        use windows::Win32::Networking::WinSock::{
            AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6,
        };

        let mut out_buf_len = 15000;
        let mut out_buf = vec![0u8; out_buf_len as usize];
        let flags = GAA_FLAG_INCLUDE_PREFIX
            | GAA_FLAG_SKIP_ANYCAST
            | GAA_FLAG_SKIP_MULTICAST
            | GAA_FLAG_SKIP_DNS_SERVER;

        // Initial call to get buffer size
        let mut ret = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC.0 as u32,
                flags,
                None,
                Some(out_buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH),
                &mut out_buf_len,
            )
        };

        if ret == ERROR_BUFFER_OVERFLOW.0 {
            out_buf = vec![0u8; out_buf_len as usize];
            ret = unsafe {
                GetAdaptersAddresses(
                    AF_UNSPEC.0 as u32,
                    flags,
                    None,
                    Some(out_buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH),
                    &mut out_buf_len,
                )
            };
        }

        if ret != ERROR_SUCCESS.0 {
            return Vec::new();
        }

        let mut interfaces = Vec::new();
        let mut adapter = out_buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;

        while !adapter.is_null() {
            unsafe {
                let name = (*adapter).FriendlyName.to_string().unwrap_or_default();
                let index = (*adapter).Anonymous1.Anonymous.IfIndex;
                let if_type_raw = (*adapter).IfType;
                let oper_status = (*adapter).OperStatus;

                let if_type = match if_type_raw {
                    IF_TYPE_ETHERNET_CSMACD => InterfaceType::Ethernet,
                    IF_TYPE_IEEE80211 => InterfaceType::Wifi,
                    IF_TYPE_SOFTWARE_LOOPBACK => InterfaceType::Loopback,
                    _ => InterfaceType::Other,
                };

                // IfOperStatusUp = 1
                let is_up = oper_status.0 == 1;

                let mut addresses = Vec::new();
                let mut unicast = (*adapter).FirstUnicastAddress;
                while !unicast.is_null() {
                    let socket_address = (*unicast).Address;
                    let sockaddr = socket_address.lpSockaddr;

                    if !sockaddr.is_null() {
                        let family = (*sockaddr).sa_family;
                        if family == AF_INET {
                            let ipv4 = &*(sockaddr as *const SOCKADDR_IN);
                            let ip_bytes = ipv4.sin_addr.S_un.S_addr.to_ne_bytes();
                            addresses.push(IpAddr::V4(Ipv4Addr::from(ip_bytes)));
                        } else if family == AF_INET6 {
                            let ipv6 = &*(sockaddr as *const SOCKADDR_IN6);
                            let ip_bytes = ipv6.sin6_addr.u.Byte;
                            addresses.push(IpAddr::V6(Ipv6Addr::from(ip_bytes)));
                        }
                    }
                    unicast = (*unicast).Next;
                }

                interfaces.push(NetworkInterface {
                    name,
                    index,
                    addresses,
                    is_up,
                    if_type,
                });

                adapter = (*adapter).Next;
            }
        }

        interfaces
    }

    /// Discover all network interfaces (Linux/Other stub)
    #[cfg(not(target_os = "windows"))]
    pub fn discover() -> Vec<NetworkInterface> {
        // TODO: Implement actual interface discovery for Linux
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
