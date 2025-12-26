//! Wintun DLL loader with embedded support (server)
//!
//! This module is identical in spirit to the client loader: it ensures that
//! `wintun.dll` is available next to the executable, extracting it from embedded
//! bytes if present.

use std::fs;
use std::io;
use std::path::PathBuf;

// Include the generated code from build.rs
include!(concat!(env!("OUT_DIR"), "/embedded_wintun.rs"));

/// Get the path to wintun.dll, extracting it from embedded resources if necessary.
pub fn ensure_wintun_dll() -> io::Result<PathBuf> {
    // First, check if wintun.dll exists in the current executable directory
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            let dll_path = exe_dir.join("wintun.dll");
            if dll_path.exists() {
                tracing::debug!(
                    "Found wintun.dll in executable directory: {}",
                    dll_path.display()
                );
                return Ok(dll_path);
            }
        }
    }

    // If not found, try to extract the embedded DLL
    if let Some(embedded_dll) = EMBEDDED_WINTUN_DLL {
        tracing::info!(
            "Extracting embedded wintun.dll ({} bytes)",
            embedded_dll.len()
        );

        let exe_path = std::env::current_exe().map_err(|e| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("Failed to get executable path: {}", e),
            )
        })?;

        let exe_dir = exe_path.parent().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "Failed to get executable directory",
            )
        })?;

        let dll_path = exe_dir.join("wintun.dll");

        fs::write(&dll_path, embedded_dll).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!(
                    "Failed to extract wintun.dll to {}: {}",
                    dll_path.display(),
                    e
                ),
            )
        })?;

        tracing::info!(
            "Successfully extracted wintun.dll to {}",
            dll_path.display()
        );

        return Ok(dll_path);
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "wintun.dll not found. Place it next to the executable, or rebuild with wintun_*.dll in the resources directory to embed it.",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ensure_wintun_dll() {
        let result = ensure_wintun_dll();

        match result {
            Ok(path) => {
                println!("Wintun DLL available at: {}", path.display());
                assert!(path.exists() || EMBEDDED_WINTUN_DLL.is_some());
            }
            Err(e) => {
                println!("Note: wintun.dll not available (expected in dev): {}", e);
                assert!(EMBEDDED_WINTUN_DLL.is_none());
            }
        }
    }
}
