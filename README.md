# Bonding

A Windows-first, open-source bonding overlay that aggregates multiple network connections (Wi-Fi + Ethernet) for increased bandwidth and reliability.

## Overview

Bonding creates a virtual Layer-3 adapter (TUN) on Windows using Wintun, captures outbound IP packets, encrypts and encapsulates them into a custom tunnel protocol, and sends them across multiple physical interfaces.

On the server side (Linux-first), packets are authenticated/decrypted and written to a Linux TUN device. The server can optionally enable IPv4 forwarding and set up NAT (MASQUERADE) to forward tunnel client traffic to the public internet and/or to a Tailscale interface (`tailscale0`).

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
- **Embedded Wintun DLL**: Windows release builds include Wintun DLL bundled directly in the executable - no separate installation required

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

**Important**: All official release binaries from the [Releases page](https://github.com/Donovoi/Bonding/releases) have the Wintun DLL embedded directly in the executable. You do **not** need to download or install `wintun.dll` separately when using release builds.

### Server (Linux)

- Linux with TUN/TAP support
- iptables or nftables for NAT
- UDP port accessible from clients

**Note**: Server TUN mode is currently supported on **Linux**. Running the server on Windows is possible in principle (Wintun exists), but NAT/forwarding is more complex; see the Tailscale section below.

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

**Important**: The Wintun DLL is **automatically bundled** in official releases from GitHub Actions. The instructions below are only needed if you're building locally and want to embed the DLL yourself.

To build Windows binaries with embedded wintun.dll:

1. Download Wintun from [Wintun website](https://www.wintun.net/)
2. Extract and place the DLL files in the `resources/` directory:
   - `resources/wintun_amd64.dll` (from wintun/bin/amd64/wintun.dll)
   - `resources/wintun_x86.dll` (from wintun/bin/x86/wintun.dll)
   - `resources/wintun_arm64.dll` (from wintun/bin/arm64/wintun.dll)
   - `resources/wintun_arm.dll` (from wintun/bin/arm/wintun.dll)
3. Build normally: `cargo build --release`

The build script (`bonding-client/build.rs`) will automatically detect and embed the appropriate DLL for your target architecture. If the DLL files are not present in `resources/`, the build will still succeed, but the resulting executable will require `wintun.dll` to be placed next to it at runtime.

## Installation

### Client Setup (Windows)

**Using Release Builds (Recommended)**:

Release builds from GitHub have the Wintun DLL **bundled directly into the executable**, making installation simple and straightforward.

1. Download the latest release from the [Releases page](https://github.com/Donovoi/Bonding/releases)
2. Extract the archive to your preferred location
3. Run `bonding-client.exe` as Administrator:

```powershell
.\bonding-client.exe
```

This launches the terminal UI. Use:

- `s` to start/stop
- `r` to reload config
- `q` to quit

✅ **No additional files needed** - The Wintun DLL is embedded in the executable, so there's nothing else to download or configure.

**For Development Builds**:

If you built the client yourself without embedding wintun.dll (see Building section), you'll need to:

1. Download `wintun.dll` from [Wintun website](https://www.wintun.net/)
2. Place `wintun.dll` next to `bonding-client.exe` in the same directory
3. Run as Administrator:

```powershell
.\bonding-client.exe
```

If you prefer a non-interactive foreground run, use:

```powershell
.\bonding-client.exe run
```

### Server Setup (Linux)

The server can either be run in a basic UDP mode, or in **TUN mode** (Linux) to forward IP packets.

1. Run the server:

```bash
sudo ./bonding-server
```

This launches the terminal UI by default. For a headless foreground run:

```bash
sudo ./bonding-server run
```

2. (Optional) Enable TUN + auto configuration + NAT in the server config.

Example (Linux server):

```toml
enable_tun = true
auto_config_tun = true
tun_device_name = "bonding0"
tun_mtu = 1420
tun_ipv4_addr = "198.18.0.1"
tun_ipv4_prefix = 24

# Full tunnel for clients typically includes a default route:
tun_routes = ["0.0.0.0/0"]

# Option A: allow tunnel clients to access the server's tailnet
enable_ipv4_forwarding = true
nat_masquerade_out_ifaces = ["tailscale0"]
```

This setup requires root (or equivalent capabilities) because it configures `net.ipv4.ip_forward` and `iptables`.

## Configuration

Both `bonding-client` and `bonding-server` support a TOML config file.

- To see where the config lives on your system:
  - `bonding-client print-config-path`
  - `bonding-server print-config-path`
- To create a default config file:
  - `bonding-client init-config`
  - `bonding-server init-config`

If the config file does not exist, defaults are used.

## Usage

Both binaries provide a small terminal UI (TUI) as a usability layer.

- `bonding-client`:
  - `bonding-client ui` (default if no subcommand)
  - `bonding-client run` (headless foreground run)
  - `bonding-client init-config [--force]`

- `bonding-server`:
  - `bonding-server ui` (default if no subcommand)
  - `bonding-server run` (headless foreground run)
  - `bonding-server init-config [--force]`

When `enable_tun=true`, the client and server forward real IP packets between the local TUN device and UDP.

By default, configurations ship with `enable_tun=false` as a safe default.

## Tailscale coexistence

Bonding can coexist with Tailscale. The main rule is to avoid overlapping routes/subnets and to avoid accidental “default route fights”.

### Full tunnel + Tailscale on the server (recommended: Linux “Option A”)

If the server is on Tailscale and you want **Bonding clients** to have access to the tailnet while still doing **full tunnel**:

1. On the **client**, route `0.0.0.0/0` via the Bonding TUN (full tunnel).
2. On the **server**, enable forwarding and NAT (MASQUERADE) out via `tailscale0` using:

```toml
enable_ipv4_forwarding = true
nat_masquerade_out_ifaces = ["tailscale0"]
```

This provides outbound access to tailnet resources from tunnel clients. If you need tailnet devices to initiate connections back to tunnel clients, you likely want subnet-route advertisement instead (not implemented here).

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

See [DEVELOPMENT.md](docs/DEVELOPMENT.md) for detailed contribution guidelines and [RELEASE.md](docs/RELEASE.md) for the complete release process.

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
- [x] Basic configuration file support (TOML)
- [x] Terminal UI (TUI) to start/stop and view logs
- [ ] Web UI for monitoring
- [ ] Performance optimization
- [ ] Production hardening

## Security

Never use this for sensitive traffic without reviewing the code. The project is in early development and has not undergone security auditing.

Report security issues privately to the maintainers.

