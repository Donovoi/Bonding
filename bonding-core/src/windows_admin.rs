//! Windows elevation / UAC helpers.
//!
//! Bonding needs Administrator privileges on Windows to create/open Wintun adapters.
//! Rather than failing later, we can proactively relaunch the current executable
//! with the `runas` verb (UAC prompt) when not already elevated.

#![cfg(target_os = "windows")]

use anyhow::{Context, Result};
use std::env;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE, HWND};
use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::Win32::UI::Shell::ShellExecuteW;
use windows::Win32::UI::WindowsAndMessaging::SHOW_WINDOW_CMD;

fn wide_null(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0)).collect()
}

// Quote an argument using Windows CreateProcess-style quoting rules.
// This produces a command line string that will round-trip through CommandLineToArgvW.
fn quote_windows_arg(arg: &OsStr) -> String {
    let s = arg.to_string_lossy();

    // Fast path: no quoting needed.
    if !s.is_empty() && !s.chars().any(|c| c == ' ' || c == '\t' || c == '"') {
        return s.into_owned();
    }

    let mut out = String::new();
    out.push('"');

    let mut backslashes = 0usize;
    for ch in s.chars() {
        match ch {
            '\\' => {
                backslashes += 1;
            }
            '"' => {
                // Escape all accumulated backslashes, then escape the quote.
                out.push_str(&"\\".repeat(backslashes * 2 + 1));
                out.push('"');
                backslashes = 0;
            }
            _ => {
                if backslashes > 0 {
                    out.push_str(&"\\".repeat(backslashes));
                    backslashes = 0;
                }
                out.push(ch);
            }
        }
    }

    // Escape trailing backslashes before closing quote.
    if backslashes > 0 {
        out.push_str(&"\\".repeat(backslashes * 2));
    }

    out.push('"');
    out
}

fn build_windows_param_string() -> String {
    let args: Vec<_> = env::args_os().skip(1).collect();
    args.into_iter()
        .map(|a| quote_windows_arg(&a))
        .collect::<Vec<_>>()
        .join(" ")
}

fn is_elevated() -> Result<bool> {
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)
            .context("OpenProcessToken failed")?;

        let mut elevation = TOKEN_ELEVATION::default();
        let mut out_len: u32 = 0;
        GetTokenInformation(
            token,
            TokenElevation,
            Some((&mut elevation as *mut TOKEN_ELEVATION).cast()),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut out_len,
        )
        .context("GetTokenInformation(TokenElevation) failed")?;

        // Best-effort close.
        let _ = CloseHandle(token);

        Ok(elevation.TokenIsElevated != 0)
    }
}

/// If the current process is not elevated, relaunches itself with UAC (`runas`).
///
/// Returns:
/// - `Ok(true)` if a relaunch was initiated (caller should exit).
/// - `Ok(false)` if already elevated (caller should continue).
pub fn relaunch_as_admin_if_needed() -> Result<bool> {
    if is_elevated().context("failed to determine elevation status")? {
        return Ok(false);
    }

    let exe = env::current_exe().context("failed to get current exe path")?;
    let params = build_windows_param_string();
    let cwd = env::current_dir().ok();

    let verb_w = wide_null(OsStr::new("runas"));
    let exe_w = wide_null(exe.as_os_str());
    let params_w = wide_null(OsStr::new(&params));
    let cwd_w = cwd.as_ref().map(|p| wide_null(p.as_os_str()));

    unsafe {
        // ShellExecuteW returns a value > 32 on success, or an error code (<= 32).
        let hinst = ShellExecuteW(
            HWND(std::ptr::null_mut()),
            PCWSTR::from_raw(verb_w.as_ptr()),
            PCWSTR::from_raw(exe_w.as_ptr()),
            if params.is_empty() {
                PCWSTR::null()
            } else {
                PCWSTR::from_raw(params_w.as_ptr())
            },
            match &cwd_w {
                Some(w) => PCWSTR::from_raw(w.as_ptr()),
                None => PCWSTR::null(),
            },
            SHOW_WINDOW_CMD(1), // SW_SHOWNORMAL
        );

        // ShellExecuteW returns a "HINSTANCE" which is pointer-typed. On failure it is
        // a small integer value (<= 32) cast to a pointer.
        let code = hinst.0 as isize;
        if code <= 32 {
            anyhow::bail!(
                "failed to relaunch with UAC (ShellExecuteW returned {})",
                code
            );
        }
    }

    Ok(true)
}
