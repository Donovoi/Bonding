# Resources Directory

This directory contains binary resources that are embedded into the Bonding executables during the build process.

## Wintun DLL

For Windows builds, place the appropriate Wintun DLL files here to embed them in the client executable:

- `wintun_amd64.dll` - For 64-bit Windows (x86_64)
- `wintun_x86.dll` - For 32-bit Windows (x86)
- `wintun_arm64.dll` - For ARM64 Windows
- `wintun_arm.dll` - For ARM Windows

### Obtaining Wintun

Download the latest Wintun release from: https://www.wintun.net/

The Wintun release zip contains the DLL files for each architecture in the following structure:
```
wintun/
├── amd64/
│   └── wintun.dll  (rename to wintun_amd64.dll)
├── x86/
│   └── wintun.dll  (rename to wintun_x86.dll)
├── arm64/
│   └── wintun.dll  (rename to wintun_arm64.dll)
└── arm/
    └── wintun.dll  (rename to wintun_arm.dll)
```

### Build Behavior

- **With DLLs present**: The build script will embed the appropriate DLL for the target architecture into the executable. Users won't need to install or provide wintun.dll separately.
- **Without DLLs**: The build will succeed but the executable will require wintun.dll to be present in the same directory at runtime.

### CI/CD Integration

The GitHub Actions workflow automatically downloads and places the Wintun DLLs in this directory during release builds, ensuring that all published binaries have the DLL embedded.

## License Note

Wintun is licensed under the GPLv2 license. When distributing binaries with embedded Wintun, ensure compliance with the license terms. See: https://git.zx2c4.com/wintun/tree/COPYING
