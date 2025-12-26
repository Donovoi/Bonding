# Script to create the first release (v0.1.0) for the Bonding project
#
# This script creates and pushes a git tag which triggers the Release workflow
# in GitHub Actions to build binaries and create the GitHub Release.
#
# Usage: .\scripts\create-first-release.ps1

param(
    [string]$Version = 'v0.1.0',
    [switch]$Yes
)

$ErrorActionPreference = 'Stop'

$VERSION = $Version
$TAG_MESSAGE = @"
Release $VERSION - First release

This is the first release of Bonding, a Windows-first bonding overlay that aggregates multiple network connections.

Features:
- Multi-path transport (Wi-Fi + Ethernet)
- Multiple bonding modes (STRIPE, PREFERRED, REDUNDANT)
- ChaCha20Poly1305 encryption
- Packet reordering with jitter buffer
- Embedded Wintun DLL support for Windows
- Automated release pipeline

See README.md for installation and usage instructions.
"@

Write-Host '=========================================' -ForegroundColor Cyan
Write-Host 'Creating First Release for Bonding' -ForegroundColor Cyan
Write-Host '=========================================' -ForegroundColor Cyan
Write-Host ''

# Check if we're in the right directory
if (-not (Test-Path 'Cargo.toml')) {
    Write-Host 'Error: Cargo.toml not found. Please run this script from the repository root.' -ForegroundColor Red
    exit 1
}

# Check if tag already exists (PowerShell try/catch won't catch external command failures)
& git show-ref --verify --quiet "refs/tags/$VERSION" 2>$null
$localTagExists = ($LASTEXITCODE -eq 0)

$remoteTagInfo = & git ls-remote --tags origin "refs/tags/$VERSION" 2>$null
$remoteTagExists = (($LASTEXITCODE -eq 0) -and ($null -ne $remoteTagInfo) -and $remoteTagInfo)

if ($localTagExists -or $remoteTagExists) {
    if ($localTagExists) {
        Write-Host "Error: Tag $VERSION already exists locally!" -ForegroundColor Red
        Write-Host "To view the tag: git show $VERSION"
        Write-Host "To delete and recreate locally: git tag -d $VERSION"
        Write-Host "To push the existing local tag: git push origin $VERSION"
        Write-Host ''
    }
    if ($remoteTagExists) {
        Write-Host "Error: Tag $VERSION already exists on origin!" -ForegroundColor Red
        Write-Host "To view remote tag refs: git ls-remote --tags origin $VERSION"
        Write-Host "To fetch the tag locally: git fetch origin tag $VERSION"
        Write-Host "To delete the remote tag (destructive): git push --delete origin $VERSION"
        Write-Host ''
    }
    exit 1
}

# Check if there are uncommitted changes
$gitStatus = git status --porcelain
if ($gitStatus) {
    Write-Host 'Warning: You have uncommitted changes:' -ForegroundColor Yellow
    git status --short
    Write-Host ''
    if (-not $Yes) {
        $continue = Read-Host 'Continue anyway? (y/N)'
        if ($continue -ne 'y' -and $continue -ne 'Y') {
            Write-Host 'Aborted.'
            exit 1
        }
    }
}

# Show current version in Cargo.toml
# Parse the workspace.package section specifically
$cargoContent = Get-Content 'Cargo.toml' -Raw
$workspacePackageMatch = [regex]::Match($cargoContent, '\[workspace\.package\](.*?)(?=\[|\z)', [System.Text.RegularExpressions.RegexOptions]::Singleline)
if ($workspacePackageMatch.Success) {
    $versionMatch = [regex]::Match($workspacePackageMatch.Groups[1].Value, 'version\s*=\s*"([^"]+)"')
    if ($versionMatch.Success) {
        $CURRENT_VERSION = $versionMatch.Groups[1].Value
    }
}

Write-Host "Current version in Cargo.toml: $CURRENT_VERSION"
Write-Host "Creating release tag: $VERSION"
Write-Host ''

# Confirm with user
if (-not $Yes) {
    $confirm = Read-Host "Create and push tag $VERSION? (y/N)"
    if ($confirm -ne 'y' -and $confirm -ne 'Y') {
        Write-Host 'Aborted.'
        exit 1
    }
}

Write-Host ''
Write-Host 'Creating annotated tag...'

# Create the annotated tag
git tag -a $VERSION -m $TAG_MESSAGE

Write-Host "✓ Tag $VERSION created locally" -ForegroundColor Green
Write-Host ''

# Push the tag
Write-Host 'Pushing tag to GitHub...'
try {
    git push origin $VERSION
    Write-Host '✓ Tag pushed successfully' -ForegroundColor Green
    Write-Host ''
    Write-Host '=========================================' -ForegroundColor Cyan
    Write-Host 'Success!' -ForegroundColor Green
    Write-Host '=========================================' -ForegroundColor Cyan
    Write-Host ''
    Write-Host 'The Release workflow has been triggered.'
    Write-Host ''
    Write-Host 'You can monitor the progress at:'
    Write-Host '  https://github.com/Donovoi/Bonding/actions/workflows/release.yml'
    Write-Host ''
    Write-Host 'Once complete, the release will be available at:'
    Write-Host "  https://github.com/Donovoi/Bonding/releases/tag/$VERSION"
    Write-Host ''
}
catch {
    Write-Host '✗ Failed to push tag' -ForegroundColor Red
    Write-Host ''
    Write-Host 'The tag was created locally but could not be pushed.'
    Write-Host "To retry: git push origin $VERSION"
    Write-Host "To delete local tag: git tag -d $VERSION"
    exit 1
}
