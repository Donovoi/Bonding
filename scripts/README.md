# Scripts

This directory contains utility scripts for the Bonding project.

## Release Scripts

### `create-first-release.sh` / `create-first-release.ps1`

Creates the first release (v0.1.0) for the Bonding project by creating and pushing a git tag.

**Usage (Linux/macOS):**
```bash
./scripts/create-first-release.sh
```

**Usage (Windows PowerShell):**
```powershell
.\scripts\create-first-release.ps1
```

This will:
1. Check that you're in the repository root
2. Verify the tag doesn't already exist
3. Show current version and confirm
4. Create an annotated git tag `v0.1.0`
5. Push the tag to GitHub
6. Trigger the Release workflow to build and publish

**Note:** You only need to run this script once to create the first release. Future releases will be created automatically when PRs with version bumps are merged to main.

For more information on the release process, see [docs/RELEASE.md](../docs/RELEASE.md).
