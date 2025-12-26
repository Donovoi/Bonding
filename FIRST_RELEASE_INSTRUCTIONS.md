# First Release - Action Required

## Summary

The release automation is now fully documented and ready. To create the first release (v0.1.0), you need to trigger the release workflow.

## What Was Done

1. ✅ **Created comprehensive release documentation** (`docs/RELEASE.md`)
   - Detailed instructions for creating releases
   - Version bump guidelines (semantic versioning)
   - Troubleshooting section
   - Release workflow details

2. ✅ **Created release scripts** for easy first release:
   - `scripts/create-first-release.sh` (Linux/macOS)
   - `scripts/create-first-release.ps1` (Windows)
   - `scripts/README.md` (documentation)

3. ✅ **Updated existing documentation**:
   - `README.md` - Added reference to RELEASE.md
   - `docs/DEVELOPMENT.md` - Added first release instructions
   - `docs/CICD.md` - Added first release section

4. ✅ **Verified release automation is configured**:
   - `auto-release.yml` - Triggers on version changes in merged PRs
   - `release.yml` - Triggers on git tags or manual dispatch

## How to Create the First Release

You have **two options** to create the first release:

### Option 1: Using the Script (Recommended)

After this PR is merged, run the provided script:

**Linux/macOS:**
```bash
./scripts/create-first-release.sh
```

**Windows:**
```powershell
.\scripts\create-first-release.ps1
```

This will:
1. Create an annotated git tag `v0.1.0`
2. Push it to GitHub
3. Trigger the Release workflow automatically
4. Build binaries for Windows and Linux
5. Create a GitHub Release with artifacts

### Option 2: Manual Tag (Alternative)

After this PR is merged, create and push a tag:

```bash
git tag -a v0.1.0 -m "Release v0.1.0 - First release"
git push origin v0.1.0
```

### Option 3: GitHub UI (Alternative)

1. Go to: https://github.com/Donovoi/Bonding/actions/workflows/release.yml
2. Click "Run workflow"
3. Select the `main` branch
4. Click "Run workflow"

## What Happens Next

Once you trigger the release (via any method above):

1. **Build Workflow Runs** (~5-10 minutes):
   - Downloads Wintun DLL (Windows)
   - Builds `bonding-client.exe` for Windows with embedded Wintun
   - Builds `bonding-server` for Linux
   - Packages both as archives

2. **Release Created**:
   - Git tag `v0.1.0` is created
   - GitHub Release is published
   - Build artifacts are attached
   - Release notes are auto-generated

3. **Release Available**:
   - Users can download from: https://github.com/Donovoi/Bonding/releases

## Future Releases (Automated)

After the first release, all subsequent releases will be automated:

1. Make changes in a feature branch
2. Update version in `Cargo.toml`:
   ```toml
   [workspace.package]
   version = "0.2.0"  # Bump version
   ```
3. Create and merge PR
4. Release is automatically created!

No manual intervention needed - the `auto-release.yml` workflow handles everything.

## Monitoring

Track the release workflow at:
- Workflow runs: https://github.com/Donovoi/Bonding/actions
- Releases page: https://github.com/Donovoi/Bonding/releases

## Documentation

- **Complete Release Guide**: `docs/RELEASE.md`
- **Development Guide**: `docs/DEVELOPMENT.md`
- **CI/CD Guide**: `docs/CICD.md`
- **Scripts Documentation**: `scripts/README.md`

## Next Steps

1. ✅ Merge this PR
2. ⏳ Run the first release script OR create tag manually
3. ⏳ Verify the release was created successfully
4. ✅ Automated releases will work from now on!

---

**Note:** You only need to create the first release once. After that, the automation takes over for all future releases when version numbers are bumped in PRs.
