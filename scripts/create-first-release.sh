#!/bin/bash
#
# Script to create the first release (v0.1.0) for the Bonding project
#
# This script creates and pushes a git tag which triggers the Release workflow
# in GitHub Actions to build binaries and create the GitHub Release.
#
# Usage: ./scripts/create-first-release.sh

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

VERSION="v0.1.0"
TAG_MESSAGE="Release v0.1.0 - First release

This is the first release of Bonding, a Windows-first bonding overlay that aggregates multiple network connections.

Features:
- Multi-path transport (Wi-Fi + Ethernet)
- Multiple bonding modes (STRIPE, PREFERRED, REDUNDANT)
- ChaCha20Poly1305 encryption
- Packet reordering with jitter buffer
- Embedded Wintun DLL support for Windows
- Automated release pipeline

See README.md for installation and usage instructions."

echo "========================================="
echo "Creating First Release for Bonding"
echo "========================================="
echo ""

# Check if we're in the right directory
if [ ! -f "Cargo.toml" ]; then
    echo -e "${RED}Error: Cargo.toml not found. Please run this script from the repository root.${NC}"
    exit 1
fi

# Check if tag already exists
if git rev-parse "$VERSION" >/dev/null 2>&1; then
    echo -e "${RED}Error: Tag $VERSION already exists!${NC}"
    echo "To view the tag: git show $VERSION"
    echo "To delete and recreate: git tag -d $VERSION"
    exit 1
fi

# Check if there are uncommitted changes
if [ -n "$(git status --porcelain)" ]; then
    echo -e "${YELLOW}Warning: You have uncommitted changes:${NC}"
    git status --short
    echo ""
    read -p "Continue anyway? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Aborted."
        exit 1
    fi
fi

# Show current version in Cargo.toml
CURRENT_VERSION=$(awk '
  /^\[workspace\.package\]/ { in_section=1; next }
  /^\[/ { in_section=0 }
  in_section && /^version/ { gsub(/"/, "", $3); print $3; exit }
' Cargo.toml)

echo "Current version in Cargo.toml: $CURRENT_VERSION"
echo "Creating release tag: $VERSION"
echo ""

# Confirm with user
read -p "Create and push tag $VERSION? (y/N) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 1
fi

echo ""
echo "Creating annotated tag..."

# Create the annotated tag
git tag -a "$VERSION" -m "$TAG_MESSAGE"

echo -e "${GREEN}✓ Tag $VERSION created locally${NC}"
echo ""

# Push the tag
echo "Pushing tag to GitHub..."
if git push origin "$VERSION"; then
    echo -e "${GREEN}✓ Tag pushed successfully${NC}"
    echo ""
    echo "========================================="
    echo -e "${GREEN}Success!${NC}"
    echo "========================================="
    echo ""
    echo "The Release workflow has been triggered."
    echo ""
    echo "You can monitor the progress at:"
    echo "  https://github.com/Donovoi/Bonding/actions/workflows/release.yml"
    echo ""
    echo "Once complete, the release will be available at:"
    echo "  https://github.com/Donovoi/Bonding/releases/tag/$VERSION"
    echo ""
else
    echo -e "${RED}✗ Failed to push tag${NC}"
    echo ""
    echo "The tag was created locally but could not be pushed."
    echo "To retry: git push origin $VERSION"
    echo "To delete local tag: git tag -d $VERSION"
    exit 1
fi
