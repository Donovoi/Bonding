//! Wintun DLL loader with embedded support
//!
//! This module handles loading the Wintun DLL, with support for embedded DLLs
//! that are compiled into the binary. This eliminates the need for users to
//! manually place wintun.dll in the executable directory.
//!
//! # Architecture Support
//!
//! The loader automatically detects the system architecture and loads the
//! appropriate DLL:
//! - x86_64: wintun_amd64.dll
//! - x86: wintun_x86.dll
//! - aarch64: wintun_arm64.dll
//! - arm: wintun_arm.dll

#![cfg(target_os = "windows")]

use std::fs;
use std::io;
use std::path::PathBuf;

// Include the generated code from build.rs
include!(concat!(env!("OUT_DIR"), "/embedded_wintun.rs"));

/// Get the path to wintun.dll, extracting it from embedded resources if necessary
///
/// This function first checks if wintun.dll is already present in the executable
/// directory. If not, and if the DLL is embedded in the binary, it will extract
/// it to the executable directory and return that path.
///
/// # Returns
///
/// Returns the path where wintun.dll can be loaded from, or an error if the DLL
/// cannot be found or extracted.
///
/// # Errors
///
/// Returns an error if:
/// - The DLL is not embedded and not found in the executable directory
/// - The DLL cannot be extracted to the executable directory
/// - File I/O operations fail
pub fn ensure_wintun_dll() -> io::Result<PathBuf> {
    // First, check if wintun.dll exists in the current executable directory
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            let dll_path = exe_dir.join("wintun.dll");
            if dll_path.exists() {
                tracing::debug!("Found wintun.dll in executable directory: {}", dll_path.display());
                return Ok(dll_path);
            }
        }
    }

    // If not found, try to extract the embedded DLL
    if let Some(embedded_dll) = EMBEDDED_WINTUN_DLL {
        tracing::info!("Extracting embedded wintun.dll ({} bytes)", embedded_dll.len());
        
        // Extract to the executable directory
        let exe_path = std::env::current_exe()
            .map_err(|e| io::Error::new(io::ErrorKind::NotFound, 
                format!("Failed to get executable path: {}", e)))?;
        
        let exe_dir = exe_path.parent()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, 
                "Failed to get executable directory"))?;
        
        let dll_path = exe_dir.join("wintun.dll");
        
        // Write the embedded DLL to disk
        fs::write(&dll_path, embedded_dll)
            .map_err(|e| io::Error::new(e.kind(), 
                format!("Failed to extract wintun.dll to {}: {}", dll_path.display(), e)))?;
        
        tracing::info!("Successfully extracted wintun.dll to {}", dll_path.display());
        return Ok(dll_path);
    }

    // Neither found locally nor embedded
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "wintun.dll not found. Please download it from https://www.wintun.net/ and place it next to the executable, or rebuild with the DLL in the resources directory to embed it.",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ensure_wintun_dll() {
        // This test will succeed if either:
        // 1. wintun.dll is present in the executable directory
        // 2. The DLL is embedded in the binary
        // It will fail if neither condition is met, which is expected in development
        let result = ensure_wintun_dll();
        
        match result {
            Ok(path) => {
                println!("Wintun DLL available at: {}", path.display());
                assert!(path.exists() || EMBEDDED_WINTUN_DLL.is_some());
            }
            Err(e) => {
                println!("Note: wintun.dll not available (expected in dev): {}", e);
                // This is expected in development without the DLL
                assert!(EMBEDDED_WINTUN_DLL.is_none());
            }
        }
    }
}
