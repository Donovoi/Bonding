# CI/CD Pipeline Documentation

This document describes the Continuous Integration and Continuous Deployment (CI/CD) pipelines used in the Bonding project.

## Overview

The project uses GitHub Actions for CI/CD with three main workflows:

1. **CI Workflow** (`ci.yml`) - Runs on every push and pull request
2. **Auto Release Workflow** (`auto-release.yml`) - Runs when PRs are merged to main
3. **Manual Release Workflow** (`release.yml`) - Triggered manually or by tags

## CI Workflow

**File:** `.github/workflows/ci.yml`

**Triggers:**
- Push to `main` branch
- Pull requests to `main` branch

**Jobs:**

### 1. Test Suite
- **Platforms:** Ubuntu (Linux) and Windows
- **Rust Version:** Stable
- **Steps:**
  - Checkout code
  - Install Rust toolchain
  - Cache cargo dependencies
  - Run tests: `cargo test --all --verbose`

### 2. Code Formatting (Rustfmt)
- **Platform:** Ubuntu
- **Steps:**
  - Check code formatting: `cargo fmt --all -- --check`
  - Ensures consistent code style

### 3. Linting (Clippy)
- **Platform:** Ubuntu
- **Steps:**
  - Run clippy: `cargo clippy --all-targets -- -D warnings`
  - Treats warnings as errors

### 4. Build
- **Platforms:** Ubuntu and Windows
- **Steps:**
  - Download Wintun DLL (Windows only)
  - Build release binaries: `cargo build --release --verbose`
  - Upload artifacts

## Auto Release Workflow

**File:** `.github/workflows/auto-release.yml`

**Triggers:**
- Push to `main` branch (typically from merged PRs)
- Excludes documentation-only changes

**Overview:**
This workflow automates the release process when a PR with a version bump is merged.

**Jobs:**

### 1. Check Version
- **Purpose:** Detect if version changed in `Cargo.toml`
- **Output:** 
  - `version_changed` - true/false
  - `new_version` - the version number
- **Logic:**
  - Compares current version with previous commit
  - Subsequent jobs only run if version changed

### 2. Test
- **Depends on:** Version check (runs only if version changed)
- **Platforms:** Ubuntu and Windows
- **Steps:**
  - Run full test suite
  - Run clippy checks
  - Check code formatting
- **Purpose:** Final validation before release

### 3. Build and Release
- **Depends on:** Successful tests
- **Platforms:**
  - Windows: `x86_64-pc-windows-msvc`
  - Linux: `x86_64-unknown-linux-gnu`
- **Steps:**
  - Download and embed Wintun DLL (Windows)
  - Build release binaries with optimizations
  - Package binaries with documentation
  - Upload as artifacts

### 4. Create Release
- **Depends on:** Successful builds
- **Steps:**
  - Download all build artifacts
  - Create git tag (e.g., `v0.1.0`)
  - Create GitHub Release
  - Attach build artifacts
  - Generate release notes from merged PRs
  - Send status notifications

**Artifacts:**
- `bonding-windows-x86_64-pc-windows-msvc.zip` - Windows client with embedded Wintun
- `bonding-linux-x86_64-unknown-linux-gnu.tar.gz` - Linux server binary

## Manual Release Workflow

**File:** `.github/workflows/release.yml`

**Triggers:**
- Git tags matching `v*` pattern (e.g., `v0.1.0`)
- Manual workflow dispatch

**Purpose:** Allows manual control over releases when needed.

**Jobs:** Similar to auto-release but always runs (no version check)

## How to Use

### For Contributors

1. **Regular Development:**
   - Create a feature branch
   - Make your changes
   - Submit a PR
   - CI workflow runs automatically

2. **Releasing a New Version:**
   - Update version in workspace `Cargo.toml`:
     ```toml
     [workspace.package]
     version = "0.2.0"  # Increment appropriately
     ```
   - Commit the version change
   - Create and merge PR
   - Auto-release workflow triggers automatically

### For Maintainers

**Automated Release (Recommended):**
- Merge PRs with version bumps
- Pipeline handles everything automatically
- Monitor at: `https://github.com/Donovoi/Bonding/actions`

**Manual Release:**
```bash
# Create and push a tag
git tag v0.2.0
git push origin v0.2.0

# Or use GitHub's workflow dispatch
# Go to Actions → Release → Run workflow
```

## Pipeline Status and Notifications

### Monitoring

- **GitHub Actions UI:** View all workflow runs
- **PR Checks:** Status appears on pull requests
- **Email Notifications:** GitHub sends emails on failures
- **Release Page:** Successful releases appear at `/releases`

### Status Badges

You can add status badges to README.md:

```markdown
![CI](https://github.com/Donovoi/Bonding/workflows/CI/badge.svg)
```

### Notifications

The workflow provides several notification methods:

1. **GitHub Checks:** Status in PR interface
2. **Notice Annotations:** Success messages in workflow logs
3. **Error Annotations:** Failure messages in workflow logs
4. **Email:** GitHub's built-in email notifications

## Best Practices

### Version Numbering

Follow [Semantic Versioning](https://semver.org/):
- **MAJOR** (1.x.x): Breaking changes
- **MINOR** (x.1.x): New features, backwards compatible
- **PATCH** (x.x.1): Bug fixes

### Commit Messages

- Clear, descriptive commit messages
- Reference issue numbers when applicable
- Example: `feat: add redundant bonding mode (#42)`

### Pull Requests

- Keep PRs focused and small
- Include version bump if releasing
- Update documentation
- Ensure all checks pass

### Testing

- Add tests for new features
- Run locally before pushing: `cargo test --all`
- Check formatting: `cargo fmt`
- Run clippy: `cargo clippy --all-targets`

## Troubleshooting

### Pipeline Failures

**Test Failures:**
- Check the "Test Suite" job logs
- Run tests locally: `cargo test --all --verbose`
- Fix issues and push again

**Build Failures:**
- Check the "Build" job logs
- Verify dependencies in `Cargo.toml`
- Test build locally: `cargo build --release`

**Release Failures:**
- Verify version was actually changed
- Check if tag already exists
- Ensure GITHUB_TOKEN has write permissions

### Common Issues

**"Version did not change"**
- Solution: Ensure version in `Cargo.toml` was modified in the latest commit

**"Tag already exists"**
- Solution: Increment to a new version number or delete the existing tag

**"Permission denied"**
- Solution: Check repository settings → Actions → Workflow permissions
- Ensure "Read and write permissions" is enabled

**Wintun Download Fails (Windows)**
- Solution: Check if wintun.net is accessible
- Verify URL is correct in workflow file
- The workflow includes SHA256 checksum verification for security

**"Checksum verification failed"**
- Solution: The downloaded Wintun archive doesn't match the expected checksum
- Update the `expectedHash` in the workflow if Wintun version was updated
- This is a security feature to prevent tampered downloads

## Security Considerations

### Secrets

- `GITHUB_TOKEN` is automatically provided by GitHub Actions
- Never commit secrets to the repository
- Use GitHub Secrets for sensitive data

### Permissions

The workflows use minimal required permissions:
- `contents: write` - For creating releases and tags
- `pull-requests: read` - For reading PR information
- `contents: read` - For checking out code

### Artifact Security

- Build artifacts are publicly accessible
- Don't include sensitive data in binaries
- Review dependencies for vulnerabilities
- **Wintun DLL Security:**
  - Downloaded from official source (wintun.net)
  - SHA256 checksum verified before use
  - Prevents tampering during download
  - Checksum must be updated when Wintun version changes

## Future Improvements

Potential enhancements to consider:

- [ ] Add changelog generation
- [ ] Include checksum files for downloads
- [ ] Sign binaries with code signing certificate
- [ ] Add more target platforms (ARM, macOS)
- [ ] Implement staging/preview releases
- [ ] Add performance benchmarks
- [ ] Integration tests in CI
- [ ] Automated dependency updates (Dependabot)
- [ ] Security scanning (CodeQL)

## Resources

- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [Semantic Versioning](https://semver.org/)
- [Conventional Commits](https://www.conventionalcommits.org/)
- [Cargo Book - Publishing](https://doc.rust-lang.org/cargo/reference/publishing.html)

## Support

For issues with CI/CD:
- Check workflow logs in GitHub Actions
- Review this documentation
- Open an issue on GitHub
- Contact maintainers
