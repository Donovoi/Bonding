# Architecture

This document describes the detailed architecture of the Bonding overlay network.

## Component Overview

```
┌─────────────────────────────────────────────────────────────┐
│                      CLIENT (Windows)                        │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────┐         ┌──────────────┐                 │
│  │ Application  │◄────────┤  TUN Device  │                 │
│  │   Traffic    │         │   (Wintun)   │                 │
│  └──────────────┘         └──────┬───────┘                 │
│                                   │                          │
│                          ┌────────▼────────┐                │
│                          │   Proto Layer   │                │
│                          │  (Encapsulate)  │                │
│                          └────────┬────────┘                │
│                                   │                          │
│                          ┌────────▼────────┐                │
│                          │   Scheduler     │                │
│                          │  (Path Select)  │                │
│                          └────────┬────────┘                │
│                                   │                          │
│                     ┌─────────────┼─────────────┐          │
│                     │             │             │           │
│              ┌──────▼──────┐ ┌───▼──────┐ ┌────▼──────┐   │
│              │   WiFi UDP  │ │ Eth UDP  │ │ Other...  │   │
│              │  Transport  │ │Transport │ │           │   │
│              └──────┬──────┘ └───┬──────┘ └────┬──────┘   │
└─────────────────────┼────────────┼─────────────┼───────────┘
                      │            │             │
                      │            │             │
                  Internet     Internet      Internet
                      │            │             │
┌─────────────────────┼────────────┼─────────────┼───────────┐
│                     │            │             │            │
│              ┌──────▼──────┐ ┌───▼──────┐ ┌────▼──────┐   │
│              │   UDP Recv  │ │ UDP Recv │ │ UDP Recv  │   │
│              └──────┬──────┘ └───┬──────┘ └────┬──────┘   │
│                     │             │             │           │
│                     └─────────────┼─────────────┘           │
│                                   │                          │
│                          ┌────────▼────────┐                │
│                          │  Reorder Buffer │                │
│                          │  (Dedup/Seq)    │                │
│                          └────────┬────────┘                │
│                                   │                          │
│                          ┌────────▼────────┐                │
│                          │   Proto Layer   │                │
│                          │ (Decapsulate)   │                │
│                          └────────┬────────┘                │
│                                   │                          │
│                          ┌────────▼────────┐                │
│                          │   TUN Device    │                │
│                          │   (Linux)       │                │
│                          └────────┬────────┘                │
│                                   │                          │
│                          ┌────────▼────────┐                │
│                          │   NAT/Forward   │                │
│                          │ (iptables/nft)  │                │
│                          └────────┬────────┘                │
│                                   │                          │
│                      SERVER (Linux)                          │
└─────────────────────────┼────────────────────────────────────┘
                          │
                     Public Internet
```

## Data Flow

### Client → Server (Outbound)

1. Application sends packet to TUN device
2. TUN device captures IP packet
3. Protocol layer:
   - Assigns sequence number
   - Encrypts payload with ChaCha20Poly1305
   - Adds authenticated header
4. Scheduler selects path(s) based on mode:
   - STRIPE: Round-robin across paths
   - PREFERRED: Best path by metrics
   - REDUNDANT: All paths simultaneously
5. Transport encrypts and sends UDP packets per interface
6. Server receives packets on multiple UDP ports
7. Reorder buffer:
   - Validates sequence numbers
   - Detects and drops replays/duplicates
   - Reorders out-of-order packets
8. Protocol layer decrypts and validates
9. TUN device injects packet into kernel
10. Optional forwarding/NAT routes packet to:
  - the public internet (e.g. via `eth0`)
  - the server's tailnet (e.g. via `tailscale0`)

### Server → Client (Inbound)

1. Public internet packet arrives at server
2. Kernel routes to TUN device via NAT
3. TUN device captures packet
4. Protocol layer encapsulates and encrypts
5. Server sends to client (round-robin or per-flow affinity)
6. Client receives on any interface
7. Reorder buffer processes packet
8. Protocol layer decrypts
9. TUN device injects into Windows network stack
10. Application receives packet

## Module Details

### proto (Protocol)

**Responsibility**: Wire format, versioning, encode/decode

**Key Components**:
- `PacketHeader`: Fixed 24-byte header with magic, version, session ID, sequence, flags
- `Packet`: Complete packet with header + auth tag + payload
- `ProtocolVersion`: Version negotiation and compatibility

**Invariants**:
- All multi-byte fields are big-endian (network byte order)
- Sequence numbers are monotonically increasing per session
- Authentication tag covers both header and payload

### tun (Virtual Adapter)

**Responsibility**: OS-specific TUN device interface

**Platform Support**:
- Windows: Wintun driver via FFI
- Linux: TUN device (server uses `tun-rs` today)

**Key Operations**:
- `read_packet()`: Non-blocking read from virtual adapter
- `write_packet()`: Inject packet into network stack
- `mtu()`: Get/set adapter MTU

**Safety**: All FFI calls isolated with documented invariants

**Windows Client Integration**:
- `wintun_loader`: Handles DLL discovery and extraction
- `build.rs`: Embeds architecture-specific Wintun DLL at compile time
- DLL automatically extracted to executable directory on first run
- Supports x86_64, x86, ARM64, and ARM architectures

### transport (Multi-path UDP)

**Responsibility**: UDP sockets per interface + encryption

**Key Components**:
- `TransportPath`: One UDP socket bound to specific interface
- `PacketCrypto`: ChaCha20Poly1305 encryption/decryption

**Features**:
- Per-path send/receive queues
- Nonce derived from sequence number
- Authenticated encryption (AEAD)

### scheduler (Path Selection)

**Responsibility**: Decide which path(s) to use for each packet

**Modes**:
- **STRIPE**: Distribute packets round-robin across all paths
  - Maximum throughput when paths have similar characteristics
  - Simple and predictable
- **PREFERRED**: Use best path based on real-time metrics
  - Optimizes for latency or throughput
  - Falls back to alternate paths on failure
- **REDUNDANT**: Send duplicate packets on multiple paths
  - Maximum reliability
  - Higher overhead

**Metrics**:
- RTT: Exponentially weighted moving average
- Loss rate: Packet loss percentage
- Queue depth: Buffered packets waiting to send
- Goodput: Actual throughput (excluding retransmits)

**Scoring**: Weighted combination of metrics determines "best" path

### reorder (Packet Reordering)

**Responsibility**: Handle out-of-order delivery, replay protection

**Key Features**:
- **Jitter buffer**: Holds packets until in-order
- **Replay window**: Sliding window of seen sequence numbers
- **Duplicate detection**: Drops duplicate packets
- **Stale packet cleanup**: Removes old packets from buffer

**Invariants**:
- Sequence numbers are strictly increasing (with wraparound)
- Packets older than replay window are rejected
- Buffer has maximum size to prevent memory exhaustion

### control (Management)

**Responsibility**: Configuration, metrics, interface discovery

**Key Components**:
- `BondingConfig`: Client/server configuration
- `SessionHealth`: Per-session statistics
- `InterfaceDiscovery`: Enumerate network interfaces
- `SessionManager`: Track active sessions

## Security Design

### Threat Model

**Protected Against**:
- Eavesdropping: All payload encrypted with AEAD
- Tampering: Authentication tag prevents modification
- Replay: Sequence number + sliding window
- Spoofing: Session ID + authentication

**NOT Protected Against**:
- Traffic analysis: Packet sizes and timing visible
- DDoS: No rate limiting (yet)
- Compromised server: Server can read all traffic

### Encryption

- **Cipher**: ChaCha20Poly1305 (AEAD)
- **Key size**: 256 bits
- **Nonce**: 96 bits (derived from sequence number)
- **Tag size**: 128 bits

### Future Enhancements

- Key rotation per time/data threshold
- Forward secrecy with ephemeral keys
- Certificate-based authentication
- Rate limiting and DDoS protection

## Performance Considerations

### Data Path Optimization

- Minimize allocations: Reuse buffers where possible
- Batching: Process multiple packets per syscall
- Lock-free where feasible: Use message passing
- Avoid copying: Zero-copy I/O when supported

### Measured Overhead

(To be added after profiling)

### Bottlenecks

- Encryption: ChaCha20 is fast but CPU-bound
- System calls: Each packet involves multiple syscalls
- Context switching: Async runtime overhead

## Deployment

### Client Configuration

Typically deployed as Windows Service:
- Starts automatically at boot
- Runs with SYSTEM privileges
- Configured via registry or config file
- Wintun.dll embedded in release builds (no manual DLL management required)
- Extracted automatically to executable directory on first run

### Server Configuration

Deployed as systemd service on Linux:
- Bound to specific network interfaces
- NAT rules configured via iptables/nftables (optionally configured automatically by the server)
- Monitoring via health check endpoint

#### Tailscale coexistence (Linux)

If the server runs Tailscale and you want tunnel clients to access the tailnet, a practical approach is to NAT/MASQUERADE the tunnel subnet out via `tailscale0`.

This is implemented as an optional server-side startup configuration (Linux only), using `iptables` rules for:
- `POSTROUTING -j MASQUERADE` from the tunnel subnet to `tailscale0`
- `FORWARD` allow rules (including `RELATED,ESTABLISHED` return traffic)

#### Windows server mode (experimental)

The server can also run on Windows using Wintun for the TUN device. For full-tunnel NAT/forwarding, Windows uses NetNat (PowerShell cmdlets like `New-NetNat`) rather than iptables/nft.

Linux remains the recommended server platform for predictable NAT/forwarding behavior.

#### Multi-client routing (experimental)

The TUN-mode server can track multiple clients, but routing is still intentionally simple:

- The server learns a client "virtual IP" (inner IPv4 source address) by observing client→server packets.
- When sending kernel→client traffic (TUN→UDP), it routes packets by the inner IPv4 destination address.
- Once at least one client IP has been learned, the server will **not guess** a destination for unknown packets (to avoid sending one client's traffic to another).

This requires that each client uses a unique tunnel IPv4 address within the tunnel subnet and that the server OS routes that subnet via the TUN interface.

#### Backpressure / queueing

Windows TUN-mode pumps use a bounded UDP→TUN queue and may drop packets if the queue is full. This prevents unbounded memory growth under load.

#### Routing / DNS UX

Full-tunnel routing interacts with existing host routes (including Tailscale). DNS configuration is not currently managed automatically; plan explicitly how clients should resolve DNS when the default route is redirected.

### Scaling

Scaling is not yet benchmarked. Practical capacity will be limited by UDP packet processing, encryption cost, and OS forwarding/NAT behavior.

## Testing Strategy

### Unit Tests

- Protocol encode/decode
- Scheduler decision logic
- Reorder buffer correctness
- Encryption/decryption

### Integration Tests

- Loopback client-server tunnel
- Out-of-order packet handling
- Path failover scenarios
- Packet loss recovery

### Manual Testing

- Real-world networks (Wi-Fi + Ethernet)
- Various MTU sizes
- Network congestion scenarios
- Long-running stability tests

## Future Directions

1. **Mobile support**: Android/iOS clients
2. **Multiple servers**: Failover and load balancing
3. **QoS**: Traffic prioritization
4. **Web UI**: Real-time monitoring dashboard
5. **Advanced bonding**: Per-flow path selection
6. **Congestion control**: TCP-friendly rate limiting
