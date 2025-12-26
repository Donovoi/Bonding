use anyhow::{bail, Context, Result};
use std::net::Ipv4Addr;
use std::process::Command;

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

fn ip(args: &[&str]) -> Result<String> {
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    run("ip", &args)
}

pub fn configure_linux_tun(
    ifname: &str,
    mtu: usize,
    ipv4: Ipv4Addr,
    prefix: u8,
    routes: &[String],
    log: &dyn Fn(String),
) -> Result<()> {
    if prefix > 32 {
        bail!("invalid IPv4 prefix length: {prefix}");
    }

    ip(&["link", "set", "dev", ifname, "up"]).with_context(|| {
        format!("failed to bring interface '{ifname}' up (ip link set dev ... up)")
    })?;

    // Best-effort set MTU (tun-rs builder already sets MTU, but keep in sync).
    let _ = ip(&["link", "set", "dev", ifname, "mtu", &mtu.to_string()])
        .map(|_| ())
        .map_err(|e| {
            log(format!("Warning: failed to set MTU via ip: {e}"));
            e
        });

    ip(&[
        "addr",
        "replace",
        &format!("{ipv4}/{prefix}"),
        "dev",
        ifname,
    ])
    .with_context(|| format!("failed to set IPv4 address on '{ifname}'"))?;

    log(format!("Configured '{ifname}' IPv4={ipv4}/{prefix}"));

    for r in routes {
        let (dest, pfx) = parse_cidr_v4(r)?;
        ip(&["route", "replace", &format!("{dest}/{pfx}"), "dev", ifname])
            .with_context(|| format!("failed to add route '{r}' via '{ifname}'"))?;
        log(format!("Added route {dest}/{pfx} via '{ifname}'"));
    }

    Ok(())
}
