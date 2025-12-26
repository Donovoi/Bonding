# Release Guide

This document describes how to create releases for the Bonding project.

## Overview

The Bonding project uses two release mechanisms:

1. **Automated releases**: Triggered automatically when a PR with a version bump is merged to `main`
2. **Manual releases**: Created by pushing a git tag or using GitHub Actions UI

## Creating the First Release

Since no releases exist yet, you can create the first release (v0.1.0) using one of these methods:

### Method 1: Manual Tag Push (Recommended)

```bash
# Create an annotated tag
git tag -a v0.1.0 -m "Release v0.1.0 - First release"

# Push the tag to GitHub
git push origin v0.1.0
```

This will trigger the Release workflow (`.github/workflows/release.yml`) which will:
- Build binaries for Windows and Linux
- Create a GitHub Release with the tag
- Upload the built artifacts
- Generate release notes

### Method 2: GitHub Actions UI

1. Go to: https://github.com/Donovoi/Bonding/actions/workflows/release.yml
2. Click "Run workflow" button
3. Select the `main` branch
4. Click "Run workflow"

This manually triggers the Release workflow without needing to create a tag first.

## Automated Releases (Future Releases)

After the first release, all subsequent releases should be created automatically when code changes are merged to `main` with a version bump.

### How It Works

The auto-release workflow (`.github/workflows/auto-release.yml`) monitors pushes to the `main` branch:

1. **Version Detection**: When a PR is merged to `main`, it checks if the version in `Cargo.toml` changed
2. **Testing**: If version changed, it runs the full test suite (tests, clippy, formatting)
3. **Building**: Builds release binaries for Windows (x86_64) and Linux (x86_64)
4. **Release Creation**: 
   - Creates a git tag (e.g., `v0.2.0`)
   - Creates a GitHub Release
   - Uploads built binaries
   - Generates release notes automatically

### Creating a New Release (After First Release)

1. **Create a feature branch**:
   ```bash
   git checkout -b feature/my-feature
   ```

2. **Make your changes** (code, tests, documentation)

3. **Update the version** in `Cargo.toml`:
   ```toml
   [workspace.package]
   version = "0.2.0"  # Bump from 0.1.0 to 0.2.0
   ```

4. **Commit and push**:
   ```bash
   git add .
   git commit -m "Add feature X and bump version to 0.2.0"
   git push origin feature/my-feature
   ```

5. **Create and merge PR**: The CI checks will run on the PR

6. **Merge to main**: Once the PR is approved and merged, the auto-release workflow will:
   - Detect the version change
   - Run tests
   - Build binaries
   - Create release v0.2.0 automatically

### Version Bump Guidelines

Follow [Semantic Versioning](https://semver.org/):

- **MAJOR** version (1.0.0 → 2.0.0): Breaking changes
- **MINOR** version (0.1.0 → 0.2.0): New features, backwards compatible
- **PATCH** version (0.1.0 → 0.1.1): Bug fixes, backwards compatible

Examples:
- New feature added: 0.1.0 → 0.2.0
- Bug fix: 0.1.0 → 0.1.1
- Breaking change: 0.1.0 → 1.0.0

## Release Artifacts

Each release includes:

### Windows Build
- `bonding-windows-x86_64-pc-windows-msvc.zip`
  - Contains: `bonding-client.exe` with embedded Wintun DLL
  - Platform: Windows 11 (x86_64)
  - No additional DLL installation required

### Linux Build
- `bonding-linux-x86_64-unknown-linux-gnu.tar.gz`
  - Contains: `bonding-server`
  - Platform: Linux (x86_64)
  - Requires: TUN/TAP support

### Additional Files
- `README.md`: Project documentation
- `LICENSE-MIT`: MIT License
- `LICENSE-APACHE`: Apache 2.0 License

## Release Workflow Details

### Workflow Triggers

**Auto-release workflow** (`.github/workflows/auto-release.yml`):
- Trigger: Push to `main` branch
- Condition: Version in `Cargo.toml` changed
- Ignores: Documentation-only changes (`.md`, `docs/`, etc.)

**Manual release workflow** (`.github/workflows/release.yml`):
- Trigger 1: Git tag matching `v*` pattern
- Trigger 2: Manual dispatch via GitHub Actions UI

### Build Process

1. **Checkout code**
2. **Setup Rust toolchain** (stable)
3. **Download Wintun DLL** (Windows only):
   - Version: 0.14.1
   - SHA256 verified for security
   - DLLs embedded for all architectures (amd64, x86, arm64, arm)
4. **Build binaries** with `cargo build --release`
5. **Package artifacts**:
   - Windows: ZIP archive
   - Linux: TAR.GZ archive
6. **Create GitHub Release** with auto-generated notes

### Monitoring Releases

- View all releases: https://github.com/Donovoi/Bonding/releases
- View workflow runs: https://github.com/Donovoi/Bonding/actions
- GitHub notifications alert on build failures

## Troubleshooting

### Release Workflow Failed

1. Check the workflow logs at: https://github.com/Donovoi/Bonding/actions
2. Common issues:
   - **Tests failed**: Fix failing tests before merging
   - **Clippy warnings**: Address all clippy warnings
   - **Formatting issues**: Run `cargo fmt`
   - **Duplicate tag**: Tag already exists, increment version

### No Release Created After PR Merge

Check if:
1. Version in `Cargo.toml` actually changed in the merged commit
2. The commit wasn't documentation-only (paths-ignore)
3. Workflow logs for any errors

### Manual Release Needed

If automated release fails, you can create a manual release:

1. Fix any issues
2. Push a git tag: `git tag v0.2.0 && git push origin v0.2.0`
3. Or use GitHub Actions UI to trigger the release workflow

## Security Considerations

- **Wintun DLL**: SHA256 checksum verified during build
- **Artifacts**: Built in GitHub Actions, not locally
- **Secrets**: Only `GITHUB_TOKEN` (automatic) is used
- **Permissions**: Workflows have minimal required permissions

## Release Checklist

Before creating a release:

- [ ] All tests pass (`cargo test`)
- [ ] No clippy warnings (`cargo clippy -- -D warnings`)
- [ ] Code formatted (`cargo fmt`)
- [ ] Documentation updated
- [ ] Version bumped in `Cargo.toml`
- [ ] CHANGELOG updated (if exists)
- [ ] Breaking changes documented (if any)

## Future Enhancements

Planned improvements to the release process:

- [ ] Add ARM64 Windows builds
- [ ] Add additional Linux architectures
- [ ] Automated changelog generation
- [ ] Release candidate (RC) builds
- [ ] Pre-release testing workflow
- [ ] Artifact signing
- [ ] Checksums file generation

## References

- [Semantic Versioning](https://semver.org/)
- [GitHub Actions Workflows](https://docs.github.com/en/actions/using-workflows)
- [GitHub Releases](https://docs.github.com/en/repositories/releasing-projects-on-github)
- [Wintun Documentation](https://www.wintun.net/)
