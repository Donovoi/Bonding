use anyhow::{bail, Context, Result};
use std::net::Ipv4Addr;
use std::process::Command;

fn prefix_to_mask(prefix: u8) -> Result<Ipv4Addr> {
    if prefix > 32 {
        bail!("invalid IPv4 prefix length: {prefix}");
    }

    let mask: u32 = if prefix == 0 {
        0
    } else {
        (!0u32) << (32 - prefix)
    };
    Ok(Ipv4Addr::from(mask.to_be()))
}

fn parse_cidr_v4(s: &str) -> Result<(Ipv4Addr, u8)> {
    let (ip_s, prefix_s) = s
        .split_once('/')
        .with_context(|| format!("route must be CIDR like 10.0.0.0/24, got '{s}'"))?;

    let ip: Ipv4Addr = ip_s
        .parse()
        .with_context(|| format!("invalid IPv4 address in route '{s}'"))?;

    let prefix: u8 = prefix_s
        .parse()
        .with_context(|| format!("invalid prefix length in route '{s}'"))?;

    if prefix > 32 {
        bail!("invalid IPv4 prefix length in route '{s}'");
    }

    Ok((ip, prefix))
}

fn run(cmd: &str, args: &[String]) -> Result<String> {
    let out = Command::new(cmd)
        .args(args)
        .output()
        .with_context(|| format!("failed to spawn {cmd}"))?;

    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();

    if !out.status.success() {
        bail!("{cmd} failed ({}): {}{}", out.status, stdout, stderr);
    }

    Ok(format!("{}{}", stdout, stderr))
}

fn netsh(args: &[&str]) -> Result<String> {
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    run("netsh", &args)
}

fn route(args: &[&str]) -> Result<String> {
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    run("route", &args)
}

fn find_interface_index(interface_name: &str) -> Result<u32> {
    let out = netsh(&["interface", "ipv4", "show", "interfaces"])?;

    let target = interface_name.to_ascii_lowercase();

    // Typical format:
    // Idx     Met         MTU          State                Name
    // ---  ----------  ----------  ------------  ---------------------------
    //  17          15        1420  connected     Bonding
    for line in out.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Skip header lines.
        if trimmed.starts_with("Idx") || trimmed.starts_with("---") {
            continue;
        }

        // Match by line ending with interface name.
        if !trimmed.to_ascii_lowercase().ends_with(&target) {
            continue;
        }

        let first = trimmed
            .split_whitespace()
            .next()
            .context("unexpected netsh output format")?;
        let idx: u32 = first
            .parse()
            .with_context(|| format!("failed to parse interface index from '{trimmed}'"))?;
        return Ok(idx);
    }

    bail!("could not find interface index for '{interface_name}' in netsh output")
}

pub fn configure_windows_tun(
    interface_name: &str,
    mtu: usize,
    ipv4: Ipv4Addr,
    prefix: u8,
    routes: &[String],
    log: &dyn Fn(String),
) -> Result<()> {
    let mask = prefix_to_mask(prefix)?;

    // MTU (best-effort). netsh expects u32.
    if let Ok(mtu_u32) = u32::try_from(mtu) {
        let _ = netsh(&[
            "interface",
            "ipv4",
            "set",
            "subinterface",
            &format!("name={interface_name}"),
            &format!("mtu={mtu_u32}"),
            "store=persistent",
        ])
        .map(|_| ())
        .map_err(|e| {
            log(format!("Warning: failed to set MTU via netsh: {e}"));
            e
        });
    }

    // IPv4 address.
    netsh(&[
        "interface",
        "ipv4",
        "set",
        "address",
        &format!("name={interface_name}"),
        "static",
        &ipv4.to_string(),
        &mask.to_string(),
    ])
    .with_context(|| format!("failed to set IPv4 address on '{interface_name}'"))?;

    log(format!(
        "Configured '{interface_name}' IPv4={} /{}",
        ipv4, prefix
    ));

    if routes.is_empty() {
        return Ok(());
    }

    let if_index = find_interface_index(interface_name)?;

    for r in routes {
        let (dest, pfx) = parse_cidr_v4(r)?;
        let r_mask = prefix_to_mask(pfx)?;

        // On-link route via interface index.
        // NOTE: This requires elevation; failures are returned.
        route(&[
            "ADD",
            &dest.to_string(),
            "MASK",
            &r_mask.to_string(),
            "0.0.0.0",
            "IF",
            &if_index.to_string(),
        ])
        .with_context(|| format!("failed to add route '{r}' via interface '{interface_name}'"))?;

        log(format!("Added route {dest}/{pfx} via '{interface_name}'"));
    }

    Ok(())
}
