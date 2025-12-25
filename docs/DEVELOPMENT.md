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
│   │   │   └── wintun.rs  # Windows Wintun
│   │   ├── transport.rs   # UDP + encryption
│   │   ├── scheduler.rs   # Path selection
│   │   ├── reorder.rs     # Packet reordering
│   │   └── control.rs     # Configuration
│   └── Cargo.toml
├── bonding-client/        # Windows client
│   ├── src/main.rs
│   └── Cargo.toml
├── bonding-server/        # Linux server
│   ├── src/main.rs
│   └── Cargo.toml
├── docs/                  # Documentation
│   ├── ARCHITECTURE.md
│   ├── TESTING.md
│   └── DEVELOPMENT.md
├── .github/
│   └── workflows/
│       └── ci.yml         # CI/CD pipeline
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
- **Issues**: Open a GitHub issue
- **Discussions**: Use GitHub discussions
- **Code Review**: Ask for reviews on PRs

## Release Process

1. Update version in `Cargo.toml`
2. Update `CHANGELOG.md`
3. Run full test suite
4. Create git tag: `git tag v0.1.0`
5. Push tag: `git push --tags`
6. GitHub Actions builds release artifacts

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
