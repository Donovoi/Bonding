# Development Guide

This guide helps you get started with Bonding development.

## Prerequisites

### Required

- Rust 1.70 or later
- Git
- A code editor (VS Code, RustRover, vim, etc.)

### Platform-Specific

**Windows Development:**
- Windows 11
- Visual Studio Build Tools (for some dependencies)
- Administrator privileges (for testing TUN adapter)

**Linux Development:**
- GCC or Clang
- TUN/TAP kernel module (`modprobe tun`)
- Root privileges (for testing)

If you are testing full-tunnel or Tailscale coexistence (server-side NAT/forwarding), you'll also need `iptables` available (or a compatible wrapper).

## Getting Started

1. Clone the repository:
```bash
git clone https://github.com/Donovoi/Bonding.git
cd Bonding
```

2. Build the project:
```bash
cargo build
```

3. Run tests:
```bash
cargo test
```

4. Check code quality:
```bash
cargo clippy
cargo fmt --check
```

## Project Structure

```
Bonding/
├── bonding-core/          # Core library
│   ├── src/
│   │   ├── lib.rs         # Library entry point
│   │   ├── proto.rs       # Wire protocol
│   │   ├── tun/           # TUN device
│   │   │   ├── wintun.rs  # Windows Wintun
│   │   │   └── linux.rs   # Linux TUN (future)
│   │   ├── transport.rs   # UDP + encryption
│   │   ├── scheduler.rs   # Path selection
│   │   ├── reorder.rs     # Packet reordering
│   │   └── control.rs     # Configuration
│   └── Cargo.toml
├── bonding-client/        # Windows client
│   ├── src/
│   │   ├── main.rs        # Client entry point
│   │   └── wintun_loader.rs # DLL loading/extraction
│   ├── build.rs           # Build script (embeds Wintun)
│   └── Cargo.toml
├── bonding-server/        # Linux server
│   ├── src/main.rs
│   ├── src/linux_tun_config.rs  # Linux: IP/route setup for TUN
│   ├── src/linux_nat_config.rs  # Linux: forwarding/NAT (MASQUERADE) helpers
│   └── Cargo.toml
├── resources/             # Embedded binary resources
│   ├── README.md          # Resource documentation
│   └── wintun_*.dll       # Wintun DLLs (placed here for embedding)
├── docs/                  # Documentation
│   ├── ARCHITECTURE.md
│   ├── TESTING.md
│   ├── DEVELOPMENT.md
│   └── CICD.md            # CI/CD pipeline documentation
├── .github/
│   └── workflows/
│       ├── ci.yml         # CI checks on every PR
│       ├── auto-release.yml # Auto-release on PR merge
│       └── release.yml    # Manual release workflow
├── Cargo.toml             # Workspace config
└── README.md
```

## Development Workflow

### 1. Create a Feature Branch

```bash
git checkout -b feature/my-feature
```

### 2. Make Changes

Edit files, add features, fix bugs.

### 3. Run Tests

```bash
cargo test
```

### 4. Check Code Quality

```bash
cargo clippy --all-targets -- -D warnings
cargo fmt
```

### 5. Commit Changes

```bash
git add .
git commit -m "Add feature X"
```

### 6. Push and Create PR

```bash
git push origin feature/my-feature
```

Then create a pull request on GitHub.

## Coding Standards

### Rust Style

- Use `rustfmt` with default settings
- Follow Rust API Guidelines
- No `clippy` warnings allowed
- Prefer explicit types at module boundaries

### Error Handling

- Use `Result<T, E>` for recoverable errors
- Use `thiserror` for error types
- Never panic in data plane code
- Log errors with `tracing`

### Documentation

- Document all public APIs with rustdoc
- Include examples in documentation
- Keep comments up to date with code
- Explain "why" not "what" in comments

### Testing

- Write unit tests for pure logic
- Add integration tests for features
- Aim for high test coverage
- Test edge cases and error conditions

## Module Guidelines

### proto (Protocol)

- All fields must be explicit endian
- Validate all inputs strictly
- Add tests for encode/decode
- Never break wire format compatibility

### tun (Virtual Adapter)

- Isolate all `unsafe` code
- Document safety invariants
- Platform-specific code behind `cfg`
- Test on actual hardware when possible

### wintun_loader (Windows Client)

- Handles DLL discovery and extraction
- Checks for existing DLL before extraction
- Gracefully handles missing embedded DLL
- Provides clear error messages for users

### build.rs (Build Scripts)

- Embeds architecture-specific Wintun DLL at compile time
- Generates code for embedded resources
- Warns if resources are missing (non-fatal)
- Supports cross-compilation for all Windows architectures

### scheduler (Bonding Logic)

- Keep pure and deterministic
- No I/O in scheduler logic
- Easy to unit test
- Document scoring algorithms

### reorder (Packet Reordering)

- Handle wraparound correctly
- Test with realistic scenarios
- Tune buffer sizes carefully
- Document memory usage

### transport (Network)

- Use AEAD for all encryption
- Never reuse nonces
- Validate authentication tags
- Handle network errors gracefully

## Debugging

### Enable Logging

```bash
RUST_LOG=debug cargo run
```

Log levels:
- `error`: Serious problems
- `warn`: Potential issues
- `info`: General information
- `debug`: Detailed debugging
- `trace`: Very verbose

### Use Debugger

**VS Code:**
Install "CodeLLDB" extension and use launch.json.

**Command Line:**
```bash
rust-gdb target/debug/bonding-client
rust-lldb target/debug/bonding-client
```

### Profiling

**CPU Profiling:**
```bash
cargo install flamegraph
sudo cargo flamegraph
```

**Memory Profiling:**
```bash
cargo build --release
valgrind --tool=massif target/release/bonding-client
```

## Common Tasks

### Building with Embedded Wintun (Windows)

For development builds with embedded Wintun DLL:

1. Download Wintun from [wintun.net](https://www.wintun.net/):
```bash
# PowerShell
Invoke-WebRequest -Uri https://www.wintun.net/builds/wintun-0.14.1.zip -OutFile wintun.zip
Expand-Archive -Path wintun.zip -DestinationPath wintun
```

2. Copy DLLs to resources directory:
```bash
# PowerShell
Copy-Item "wintun/wintun/bin/amd64/wintun.dll" "resources/wintun_amd64.dll"
Copy-Item "wintun/wintun/bin/x86/wintun.dll" "resources/wintun_x86.dll"
Copy-Item "wintun/wintun/bin/arm64/wintun.dll" "resources/wintun_arm64.dll"
Copy-Item "wintun/wintun/bin/arm/wintun.dll" "resources/wintun_arm.dll"
```

3. Build normally:
```bash
cargo build --release
```

The build script will automatically detect and embed the appropriate DLL for your target architecture.

**Note**: Release builds from GitHub Actions automatically include embedded DLLs. Manual DLL placement is only needed for local development builds.

### Add a New Dependency

1. Add to workspace dependencies in root `Cargo.toml`:
```toml
[workspace.dependencies]
my-crate = "1.0"
```

2. Use in crate:
```toml
[dependencies]
my-crate = { workspace = true }
```

### Add a New Module

1. Create file: `bonding-core/src/mymodule.rs`
2. Add to `lib.rs`:
```rust
pub mod mymodule;
```
3. Write tests in same file
4. Document public APIs

### Add a New Test

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_my_feature() {
        // Test code here
        assert!(true);
    }
}
```

### Update Documentation

```bash
cargo doc --no-deps --open
```

This builds and opens the documentation in your browser.

## Full-tunnel + Tailscale (Linux server)

If the server runs Tailscale and you want tunnel clients to access the tailnet while doing full tunnel, configure the server to NAT/MASQUERADE the tunnel subnet out via `tailscale0`.

Relevant server config keys (see `bonding-core/src/control.rs`):
- `enable_tun`, `auto_config_tun`, `tun_ipv4_addr`, `tun_ipv4_prefix`, `tun_routes`
- `enable_ipv4_forwarding`
- `nat_masquerade_out_ifaces = ["tailscale0"]`

## Performance Tips

### Data Path

- Minimize allocations (reuse buffers)
- Avoid unnecessary copies
- Use batching when possible
- Profile before optimizing

### Async Code

- Don't block async tasks
- Use `tokio::spawn` for CPU work
- Prefer message passing over locks
- Test with realistic workloads

## Security Considerations

### Cryptography

- Never implement your own crypto
- Use reviewed libraries (ChaCha20Poly1305)
- Handle keys securely
- Clear sensitive data when done

### Input Validation

- Validate all external inputs
- Check bounds and lengths
- Reject malformed packets early
- Prevent resource exhaustion

### Dependencies

- Review new dependencies
- Keep dependencies updated
- Check for known vulnerabilities
- Minimize dependency count

## Getting Help

- **Documentation**: Check `docs/` directory
  - `ARCHITECTURE.md` - System design and architecture
  - `TESTING.md` - Testing guidelines
  - `CICD.md` - CI/CD pipeline and release process
  - `DEVELOPMENT.md` - This guide
- **Issues**: Open a GitHub issue
- **Discussions**: Use GitHub discussions
- **Code Review**: Ask for reviews on PRs

## Release Process

The project uses an automated release pipeline that triggers when pull requests are merged to the main branch.

For complete details on creating and managing releases, see [RELEASE.md](RELEASE.md).

### Automated Release (Recommended)

When you merge a PR that includes a version bump, the release pipeline automatically creates a release:

1. **Make your changes** in a feature branch
2. **Update version** in the `[workspace.package]` section of `Cargo.toml`
3. **Create a PR** with your changes (code changes + version bump together)
4. **Merge the PR** - This triggers the automated release pipeline:
   - Detects version change in `Cargo.toml`
   - Runs full test suite (tests, clippy, formatting)
   - Builds release binaries for Windows and Linux
   - Creates a git tag (e.g., `v0.1.0`)
   - Publishes a GitHub Release with binaries and release notes
   - Sends status notifications

The pipeline will only trigger if the version in `Cargo.toml` changed in the merged commit.

### Creating the First Release

To create the first release (v0.1.0), use the provided script:

**Linux/macOS:**
```bash
./scripts/create-first-release.sh
```

**Windows:**
```powershell
.\scripts\create-first-release.ps1
```

Or manually:
```bash
git tag -a v0.1.0 -m "Release v0.1.0"
git push origin v0.1.0
```

### Manual Release (Alternative)

If you need to create a release manually:

1. Update version in workspace `Cargo.toml`
2. Create git tag: `git tag v0.1.0`
3. Push tag: `git push origin v0.1.0`
4. GitHub Actions builds and publishes the release

### Release Pipeline Workflow

The automated release pipeline (`.github/workflows/auto-release.yml`) includes:

- **Version Detection**: Checks if version changed in the last commit
- **Testing**: Runs tests, clippy, and formatting checks on both platforms
- **Building**: Compiles release binaries with embedded Wintun DLL (Windows)
- **Packaging**: Creates distribution archives
- **Release Creation**: Tags the commit and creates a GitHub Release
- **Notifications**: Provides success/failure status

### Monitoring Pipeline Status

- View workflow runs at: `https://github.com/Donovoi/Bonding/actions`
- Pipeline status appears in PR checks before merge
- GitHub notifications alert on build failures
- Release notes are auto-generated from PR descriptions

## Useful Commands

```bash
# Build all crates
cargo build --all

# Run specific test
cargo test test_name

# Check without building
cargo check

# View docs
cargo doc --open

# Clean build artifacts
cargo clean

# Update dependencies
cargo update

# Show dependency tree
cargo tree

# Audit dependencies
cargo audit
```

## Editor Setup

### VS Code

Install extensions:
- rust-analyzer
- CodeLLDB
- Better TOML
- crates

### Vim/Neovim

Install:
- rust.vim
- rust-analyzer (via LSP)
- vim-cargo

### RustRover

JetBrains IDE with built-in Rust support.

## Contributing Checklist

Before submitting a PR:

- [ ] Tests pass: `cargo test --all`
- [ ] No clippy warnings: `cargo clippy -- -D warnings`
- [ ] Code formatted: `cargo fmt`
- [ ] Documentation updated
- [ ] Commit messages are clear
- [ ] PR description explains changes

## Resources

- [Rust Book](https://doc.rust-lang.org/book/)
- [Rust by Example](https://doc.rust-lang.org/rust-by-example/)
- [Tokio Tutorial](https://tokio.rs/tokio/tutorial)
- [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
