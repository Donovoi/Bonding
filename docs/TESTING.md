# Testing Guide

This document describes the testing strategy and how to run tests for the Bonding project.

## Test Organization

Tests are organized into three categories:

1. **Unit Tests**: Located in each module's source file
2. **Integration Tests**: Located in `bonding-client/tests/` (verifies client-server interaction)
3. **Documentation Tests**: Examples in rustdoc comments

## Running Tests

### All Tests

```bash
cargo test --all
```

### Specific Crate

```bash
cargo test -p bonding-core
cargo test -p bonding-client
cargo test -p bonding-server
```

### Integration Tests

The integration tests verify the handshake and packet exchange between the client and server without requiring a TUN interface (using loopback UDP).

```bash
cargo test -p bonding-client --test integration_test
```

### Specific Module

```bash
cargo test -p bonding-core proto::tests
cargo test -p bonding-core scheduler::tests
cargo test -p bonding-core reorder::tests
```

### With Output

```bash
cargo test -- --nocapture
```

### Release Mode

```bash
cargo test --release
```

## Current Test Coverage

### Protocol Module (`proto.rs`)

- ✅ Protocol version validation
- ✅ Packet flag operations
- ✅ Header encoding/decoding (network byte order)
- ✅ Invalid magic number detection
- ✅ Unsupported version handling
- ✅ Complete packet encoding/decoding
- ✅ Packet length validation

### TUN Module (`tun.rs`, `tun/wintun.rs`)

- ✅ Mock TUN device operations
- ✅ Wintun device creation (placeholder)
- ⏳ Actual Wintun FFI (pending implementation)

### Wintun Loader Module (`bonding-client/src/wintun_loader.rs`)

- ✅ DLL discovery in executable directory
- ✅ Embedded DLL extraction
- ✅ Graceful handling of missing DLL
- ✅ Works with and without embedded resources

### Build Script (`bonding-client/build.rs`)

- ✅ Architecture detection
- ✅ DLL embedding code generation
- ✅ Builds succeed without DLLs present (with warnings)
- ✅ Correct path handling for Windows

### Scheduler Module (`scheduler.rs`)

- ✅ STRIPE mode: Round-robin distribution
- ✅ PREFERRED mode: Best path selection
- ✅ REDUNDANT mode: All paths used
- ✅ Path metrics scoring
- ✅ RTT update with EWMA
- ✅ Loss rate update with EWMA
- ✅ Path addition/removal

### Reorder Module (`reorder.rs`)

- ✅ In-order packet processing
- ✅ Out-of-order packet reordering
- ✅ Duplicate detection
- ✅ Old packet rejection
- ✅ Replay attack detection
- ✅ Buffer wraparound handling (near u64::MAX)
- ✅ Buffer size limits
- ✅ Buffer reset

### Transport Module (`transport.rs`)

- ✅ Packet encryption with ChaCha20Poly1305
- ✅ Packet decryption
- ✅ Nonce generation from sequence
- ✅ Wrong nonce detection
- ✅ Tampered ciphertext detection

### Control Module (`control.rs`)

- ✅ Configuration defaults
- ✅ Session manager operations
- ✅ Interface discovery (placeholder)

### Integration Tests (`bonding-client/tests/integration_test.rs`)

- ✅ Client-Server Handshake (No TUN): Verifies UDP connectivity, encryption handshake, and keepalive exchange over loopback.

## Test Statistics

```
Total Tests: ~40 passing
Coverage: Core logic modules + client infrastructure + integration
Lines of Test Code: ~600
```

## Benchmarks (To Be Added)

```bash
cargo bench
```

Planned benchmarks:
- Protocol encoding/decoding throughput
- Encryption/decryption performance
- Scheduler decision latency
- Reorder buffer insertion/retrieval

## Continuous Integration

CI runs on every push and pull request:

1. **Format Check**: `cargo fmt --check`
2. **Lint Check**: `cargo clippy -- -D warnings`
3. **Build**: `cargo build --release`
4. **Test**: `cargo test --all`

Platforms tested:
- Linux (Ubuntu latest)
- Windows (latest)

**Release Workflow**: Automatically downloads and embeds Wintun DLLs for Windows builds.

## Manual Testing

### Prerequisites

**Windows Client:**
- Windows 11
- Administrator privileges
- For release builds: No additional requirements (DLL embedded)
- For dev builds: Either place Wintun DLLs in `resources/` directory before building, or manually place `wintun.dll` next to executable

**Linux Server:**
- Linux with TUN/TAP support
- Root privileges

### Setup

1. Build the project:
```bash
# For development build without embedded DLL
cargo build --release

# For release build with embedded DLL (after setting up resources/)
# See DEVELOPMENT.md for Wintun DLL setup instructions
cargo build --release
```

2. Copy binaries:
```bash
# Windows (development build without embedded DLL)
copy target\release\bonding-client.exe C:\bonding\
copy wintun.dll C:\bonding\

# Windows (release build with embedded DLL)
copy target\release\bonding-client.exe C:\bonding\
# No wintun.dll needed - it's embedded!

# Linux
sudo cp target/release/bonding-server /usr/local/bin/
```

### Running

**Server (Linux):**
```bash
sudo bonding-server
```

**Client (Windows):**
```powershell
# Run as Administrator
.\bonding-client.exe
```

### Verification

Check that:
1. TUN adapter is created
2. UDP sockets are bound
3. Packets flow through tunnel
4. No crashes or errors in logs
5. For embedded builds: wintun.dll extracted to executable directory on first run

## Troubleshooting Tests

### Test Failures

If tests fail:

1. Check Rust version: `rustc --version` (should be 1.70+)
2. Update dependencies: `cargo update`
3. Clean build: `cargo clean && cargo test`
4. Check for platform-specific issues

### Platform-Specific Tests

Some tests are platform-specific:

```rust
#[test]
#[cfg(target_os = "windows")]
fn windows_only_test() {
    // Windows-specific test
}

#[test]
#[cfg(target_os = "linux")]
fn linux_only_test() {
    // Linux-specific test
}
```

## Future Testing Improvements

1. **Fuzzing**: Add fuzzing targets for protocol parsing
2. **Property Testing**: Use proptest for scheduler logic
3. **Performance Testing**: Add benchmarks for data path
4. **Stress Testing**: Long-running stability tests
5. **Network Simulation**: Test with simulated packet loss/latency

## Contributing Tests

When adding new features:

1. Write unit tests for pure logic
2. Add integration tests for end-to-end scenarios
3. Update documentation tests if API changes
4. Ensure all tests pass before submitting PR

Test naming conventions:
- `test_<feature>_<scenario>`: Unit tests
- `test_<feature>_end_to_end`: Integration tests
- Use descriptive names that explain what is being tested
