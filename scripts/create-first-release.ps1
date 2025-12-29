$ErrorActionPreference = "Stop"

# 1. Check that we're in the repository root
if (-not (Test-Path "Cargo.toml")) {
    Write-Error "Cargo.toml not found. Please run this script from the repository root."
    exit 1
}

# 2. Get current version from Cargo.toml
$versionLine = Get-Content Cargo.toml | Select-String 'version = "(.*)"' | Select-Object -First 1
if (-not $versionLine) {
    Write-Error "Could not find version in Cargo.toml"
    exit 1
}
$version = $versionLine.Matches.Groups[1].Value
$tagName = "v$version"

Write-Host "Current version detected: $version"
Write-Host "Target tag: $tagName"

# 3. Verify the tag doesn't already exist
$existingTag = git tag -l $tagName
if ($existingTag) {
    Write-Warning "Tag $tagName already exists."
    $response = Read-Host "Do you want to delete the local tag and recreate it? (y/n)"
    if ($response -eq 'y') {
        git tag -d $tagName
    } else {
        Write-Host "Aborting."
        exit 0
    }
}

# 4. Confirm with user
$response = Read-Host "Ready to create and push tag $tagName. Continue? (y/n)"
if ($response -ne 'y') {
    Write-Host "Aborted."
    exit 0
}

# 5. Create annotated git tag
Write-Host "Creating tag $tagName..."
git tag -a $tagName -m "Release $tagName"

# 6. Push the tag to GitHub
Write-Host "Pushing tag to origin..."
git push origin $tagName

Write-Host "Done! GitHub Actions should now trigger the release workflow."
