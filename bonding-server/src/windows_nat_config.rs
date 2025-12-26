#![cfg(target_os = "windows")]

use anyhow::{bail, Context, Result};
use std::net::Ipv4Addr;
use std::process::Command;

fn ipv4_network_cidr(ip: Ipv4Addr, prefix: u8) -> Result<String> {
    if prefix > 32 {
        bail!("invalid IPv4 prefix length: {prefix}");
    }

    let ip_u32 = u32::from_be_bytes(ip.octets());
    let mask: u32 = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
    let net_u32 = ip_u32 & mask;
    let net_ip = Ipv4Addr::from(net_u32.to_be_bytes());
    Ok(format!("{net_ip}/{prefix}"))
}

fn run_ps(script: &str) -> Result<String> {
    // Prefer Windows PowerShell for widest compatibility.
    // Fall back to pwsh if powershell.exe isn't available.
    let try_cmds = ["powershell", "pwsh"];

    for cmd in try_cmds {
        let out = Command::new(cmd)
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                script,
            ])
            .output();

        let out = match out {
            Ok(o) => o,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e).with_context(|| format!("failed to spawn {cmd}")),
        };

        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();

        if out.status.success() {
            return Ok(format!("{}{}", stdout, stderr));
        }

        bail!("{cmd} failed ({}): {}{}", out.status, stdout, stderr);
    }

    bail!("neither powershell nor pwsh was found on PATH")
}

/// Configure Windows forwarding + NAT using NetNat (best-effort).
///
/// This is intended to support the "Option A" experience on Windows:
/// full-tunnel clients can reach tailnet resources via the Windows server.
///
/// Notes:
/// - Requires elevation (Administrator).
/// - Requires NetNat cmdlets (New-NetNat/Get-NetNat), typically available on
///   Windows 10/11.
pub fn configure_windows_forwarding_and_netnat(
    tun_interface_alias: &str,
    tun_ipv4: Ipv4Addr,
    tun_prefix: u8,
    enable_forwarding: bool,
    enable_netnat: bool,
    netnat_name: &str,
    internal_prefix_override: Option<&str>,
    log: &dyn Fn(String),
) -> Result<()> {
    if !enable_forwarding && !enable_netnat {
        return Ok(());
    }

    let internal_prefix = match internal_prefix_override {
        Some(p) if !p.trim().is_empty() => p.trim().to_string(),
        _ => ipv4_network_cidr(tun_ipv4, tun_prefix)?,
    };

    // Escape single quotes for PowerShell single-quoted strings.
    let alias = tun_interface_alias.replace('"', "");
    let name = netnat_name.replace('"', "");

    // Build a single script with explicit output to help troubleshooting.
    let script = format!(
        r#"$ErrorActionPreference = 'Stop'

function Have-Cmd([string]$n) {{
  return [bool](Get-Command $n -ErrorAction SilentlyContinue)
}}

if (-not (Have-Cmd 'Get-NetNat')) {{
  throw 'NetNat cmdlets not available (Get-NetNat not found).'
}}

$alias = '{alias}'
$name = '{name}'
$prefix = '{internal_prefix}'

Write-Output ("Bonding: NetNat requested name='{name}' prefix='{internal_prefix}'")

if ({enable_forwarding}) {{
  try {{
    if (Have-Cmd 'Set-NetIPInterface') {{
      Set-NetIPInterface -InterfaceAlias $alias -Forwarding Enabled -ErrorAction Stop | Out-Null
      Write-Output ("Bonding: Enabled IP forwarding on interface '{alias}'")
    }} else {{
      Write-Output 'Bonding: Set-NetIPInterface not available; skipping forwarding enable.'
    }}
  }} catch {{
    Write-Output ("Bonding: Warning: failed to enable forwarding on '{alias}': $($_.Exception.Message)")
  }}
}}

if ({enable_netnat}) {{
  if (-not (Have-Cmd 'New-NetNat')) {{
    throw 'New-NetNat not available.'
  }}

  $existing = Get-NetNat -Name $name -ErrorAction SilentlyContinue
  if ($null -ne $existing) {{
    $prefixes = @($existing.InternalIPInterfaceAddressPrefix)
    if ($prefixes -contains $prefix) {{
      Write-Output ("Bonding: NetNat '{name}' already exists with prefix '{internal_prefix}'")
      exit 0
    }}

    Write-Output ("Bonding: NetNat '{name}' exists but prefixes do not match; recreating")
    Remove-NetNat -Name $name -Confirm:$false | Out-Null
  }}

  New-NetNat -Name $name -InternalIPInterfaceAddressPrefix $prefix | Out-Null
  Write-Output ("Bonding: Created NetNat '{name}' prefix '{internal_prefix}'")
}}
"#
    );

    let out = run_ps(&script).context("failed to configure Windows forwarding/NetNat")?;
    for line in out.lines().filter(|l| !l.trim().is_empty()) {
        log(line.to_string());
    }

    Ok(())
}
