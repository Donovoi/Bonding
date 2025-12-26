# Bonding

A Windows-first, open-source bonding overlay that aggregates multiple network connections (Wi-Fi + Ethernet) for increased bandwidth and reliability.

## Overview

Bonding creates a virtual Layer-3 adapter (TUN) on Windows using Wintun, captures outbound IP packets, encrypts and encapsulates them into a custom tunnel protocol, and sends them across multiple physical interfaces. A server component reorders, validates, and decapsulates packets before NAT'ing them to the public internet.

## Features

- **Multi-path transport**: Simultaneously use Wi-Fi and Ethernet connections
- **Multiple bonding modes**:
  - STRIPE: Round-robin distribution for maximum throughput
  - PREFERRED: Smart path selection based on metrics
  - REDUNDANT: Send duplicate packets for reliability
- **Encryption**: ChaCha20Poly1305 AEAD for packet security
- **Reordering**: Handles out-of-order packet delivery with jitter buffer
- **Replay protection**: Sequence number tracking prevents replay attacks
- **Health metrics**: RTT, loss rate, and throughput monitoring per path

## Architecture

The project is organized into three crates:

- **bonding-core**: Core library with all bonding logic
  - `proto`: Wire protocol definitions and versioning
  - `tun`: Virtual adapter interface (Wintun on Windows)
  - `transport`: UDP sockets with encryption per interface
  - `scheduler`: Path selection and bonding logic
  - `reorder`: Sequence number tracking and replay protection
  - `control`: Health metrics and configuration
- **bonding-client**: Windows client application
  - `wintun_loader`: DLL loading with embedded support
  - `build.rs`: Build script for embedding Wintun DLL
- **bonding-server**: Linux server application

## Requirements

### Client (Windows)

- Windows 11 (primary target)
- Administrator privileges (for Wintun adapter creation)
- Active network interfaces (Wi-Fi and/or Ethernet)

**Note**: Release builds have `wintun.dll` embedded, so no additional DLL installation is required.

### Server (Linux)

- Linux with TUN/TAP support
- iptables or nftables for NAT
- UDP port accessible from clients

## Building

```bash
# Build all crates
cargo build --release

# Run tests
cargo test

# Run clippy
cargo clippy --all-targets -- -D warnings

# Build documentation
cargo doc --no-deps --open
```

### Building with Embedded Wintun (Windows)

To build Windows binaries with embedded wintun.dll:

1. Download Wintun from [Wintun website](https://www.wintun.net/)
2. Extract and place the DLL files in the `resources/` directory:
   - `resources/wintun_amd64.dll` (from wintun/bin/amd64/wintun.dll)
   - `resources/wintun_x86.dll` (from wintun/bin/x86/wintun.dll)
   - `resources/wintun_arm64.dll` (from wintun/bin/arm64/wintun.dll)
   - `resources/wintun_arm.dll` (from wintun/bin/arm/wintun.dll)
3. Build normally: `cargo build --release`

The build script will automatically embed the appropriate DLL for your architecture.

## Installation

### Client Setup (Windows)

**Using Release Builds (Recommended)**:

1. Download the latest release from the [Releases page](https://github.com/Donovoi/Bonding/releases)
2. Extract the archive
3. Run as Administrator:

```powershell
.\bonding-client.exe
```

Release binaries have `wintun.dll` embedded, so no additional setup is required.

**For Development Builds**:

If you built the client yourself without embedding wintun.dll, you'll need to:

1. Download `wintun.dll` from [Wintun website](https://www.wintun.net/)
2. Place `wintun.dll` next to `bonding-client.exe`
3. Run as Administrator:

```powershell
.\bonding-client.exe
```

### Server Setup (Linux)

1. Configure iptables/nftables for NAT:

```bash
# Enable IP forwarding
sudo sysctl -w net.ipv4.ip_forward=1

# Configure NAT (example with iptables)
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
sudo iptables -A FORWARD -i tun0 -j ACCEPT
```

2. Run the server:

```bash
sudo ./bonding-server
```

## Configuration

Configuration is managed through environment variables or a config file (to be implemented):

- `BONDING_SERVER_ADDR`: Server IP address
- `BONDING_SERVER_PORT`: Server UDP port (default: 5000)
- `BONDING_MODE`: Bonding mode (stripe/preferred/redundant)
- `BONDING_MTU`: TUN adapter MTU (default: 1420)

## Usage

The client and server are currently in development. Full usage instructions will be added as features are completed.

## Troubleshooting

### Windows Client

**Issue**: "Failed to create Wintun adapter"
- Solution: Ensure you're running as Administrator. If using a development build, verify `wintun.dll` is present in the executable directory.

**Issue**: "No network interfaces found"
- Solution: Check that at least one active network connection exists

**Issue**: "wintun.dll not found"
- Solution: Use a release build which has the DLL embedded, or place `wintun.dll` next to the executable for development builds.

### Linux Server

**Issue**: "Cannot create TUN device"
- Solution: Ensure TUN/TAP kernel module is loaded: `sudo modprobe tun`

**Issue**: "Packets not being forwarded"
- Solution: Verify IP forwarding is enabled and NAT rules are configured

## Development

### Code Style

- Uses `rustfmt` with default settings
- Enforces `clippy` warnings in CI
- Follows Rust API guidelines

### Testing

```bash
# Run all tests
cargo test

# Run tests for a specific crate
cargo test -p bonding-core

# Run with output
cargo test -- --nocapture
```

### Contributing

Contributions are welcome! Please ensure:

- All tests pass
- Code is formatted with `rustfmt`
- No clippy warnings
- Documentation is updated

**Release Process:**
- When you merge a PR with a version bump in `Cargo.toml`, an automated release pipeline will:
  - Run all tests and quality checks
  - Build binaries for Windows and Linux
  - Create a GitHub Release with artifacts
  - Generate release notes automatically

See [DEVELOPMENT.md](docs/DEVELOPMENT.md) for detailed contribution guidelines and release workflow.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

## Non-Goals

- Censorship evasion or stealth features
- "True bonding" without a server
- Mobile broadband support (v0)

## Roadmap

- [x] Core protocol implementation
- [x] Scheduler and reorder buffer
- [x] Basic encryption support
- [x] Embedded Wintun DLL support for Windows client
- [ ] Full Wintun FFI implementation
- [ ] Linux TUN support
- [ ] Complete client/server applications
- [ ] Configuration file support
- [ ] Web UI for monitoring
- [ ] Performance optimization
- [ ] Production hardening

## Security

Never use this for sensitive traffic without reviewing the code. The project is in early development and has not undergone security auditing.

Report security issues privately to the maintainers.

