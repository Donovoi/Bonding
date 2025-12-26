#![cfg(target_os = "linux")]

use anyhow::{bail, Context, Result};
use std::net::Ipv4Addr;
use std::process::Command;

fn run_capture(cmd: &str, args: &[String]) -> Result<(bool, String)> {
    let out = Command::new(cmd)
        .args(args)
        .output()
        .with_context(|| format!("failed to spawn {cmd}"))?;

    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    let ok = out.status.success();

    Ok((ok, format!("{}{}", stdout, stderr)))
}

fn run(cmd: &str, args: &[String]) -> Result<String> {
    let (ok, out) = run_capture(cmd, args)?;
    if !ok {
        bail!("{cmd} failed: {out}");
    }
    Ok(out)
}

fn write_proc(path: &str, value: &str) -> Result<()> {
    std::fs::write(path, value).with_context(|| format!("failed to write '{value}' to {path}"))?;
    Ok(())
}

fn enable_ipv4_forwarding() -> Result<()> {
    // Fast path: write /proc directly.
    // Requires CAP_SYS_ADMIN (typically root).
    if write_proc("/proc/sys/net/ipv4/ip_forward", "1\n").is_ok() {
        return Ok(());
    }

    // Fallback: sysctl
    let args: Vec<String> = ["-w", "net.ipv4.ip_forward=1"]
        .into_iter()
        .map(|s| s.to_string())
        .collect();
    let _ = run("sysctl", &args).context("failed to enable net.ipv4.ip_forward")?;
    Ok(())
}

fn ipv4_network_cidr(ip: Ipv4Addr, prefix: u8) -> Result<String> {
    if prefix > 32 {
        bail!("invalid IPv4 prefix length: {prefix}");
    }

    let ip_u32 = u32::from_be_bytes(ip.octets());
    let mask: u32 = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };

    let net_u32 = ip_u32 & mask;
    let net_ip = Ipv4Addr::from(net_u32.to_be_bytes());
    Ok(format!("{net_ip}/{prefix}"))
}

fn iptables_check(args: &[&str]) -> Result<bool> {
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();

    // iptables -C returns:
    //  - exit 0: rule exists
    //  - exit 1: rule does not exist
    //  - exit >1: error
    let (ok, out) = run_capture("iptables", &args)?;
    if ok {
        return Ok(true);
    }

    // Try to distinguish "not found" from hard errors.
    // iptables uses exit code 1 for "bad rule" / "no rule" checks.
    // We conservatively treat any non-success as "missing" unless output hints
    // at a real failure.
    let lower = out.to_ascii_lowercase();
    if lower.contains("not found")
        || lower.contains("no chain")
        || lower.contains("unknown option")
        || lower.contains("permission denied")
        || lower.contains("can't initialize")
    {
        // These should be surfaced because they require operator action.
        bail!("iptables check failed: {out}");
    }

    Ok(false)
}

fn iptables_ensure(args_check: &[&str], args_add: &[&str]) -> Result<bool> {
    if iptables_check(args_check)? {
        return Ok(false);
    }

    let args_add: Vec<String> = args_add.iter().map(|s| s.to_string()).collect();
    let _ = run("iptables", &args_add)?;
    Ok(true)
}

/// Configure IPv4 forwarding + NAT for the Bonding server (Linux only).
///
/// This implements "Option A": tunnel clients can reach the server's tailnet
/// by NAT'ing tunnel traffic out via `tailscale0`.
pub fn configure_linux_forwarding_and_nat(
    tun_ifname: &str,
    tun_ipv4: Ipv4Addr,
    tun_prefix: u8,
    out_ifaces: &[String],
    enable_forwarding: bool,
    log: &dyn Fn(String),
) -> Result<()> {
    if out_ifaces.is_empty() && !enable_forwarding {
        return Ok(());
    }

    if enable_forwarding || !out_ifaces.is_empty() {
        enable_ipv4_forwarding().context("failed to enable IPv4 forwarding")?;
        log("Enabled IPv4 forwarding (net.ipv4.ip_forward=1)".to_string());
    }

    if out_ifaces.is_empty() {
        return Ok(());
    }

    let tun_cidr = ipv4_network_cidr(tun_ipv4, tun_prefix)?;

    for out in out_ifaces {
        if out.trim().is_empty() {
            continue;
        }

        // NAT: tunnel subnet -> out iface
        // iptables -t nat -A POSTROUTING -s <tun_cidr> -o <out> -j MASQUERADE
        let added_nat = iptables_ensure(
            &[
                "-t",
                "nat",
                "-C",
                "POSTROUTING",
                "-s",
                &tun_cidr,
                "-o",
                out,
                "-j",
                "MASQUERADE",
            ],
            &[
                "-t",
                "nat",
                "-A",
                "POSTROUTING",
                "-s",
                &tun_cidr,
                "-o",
                out,
                "-j",
                "MASQUERADE",
            ],
        )?;

        // Forward: allow outbound from tun to out
        let added_fwd_out = iptables_ensure(
            &["-C", "FORWARD", "-i", tun_ifname, "-o", out, "-j", "ACCEPT"],
            &["-A", "FORWARD", "-i", tun_ifname, "-o", out, "-j", "ACCEPT"],
        )?;

        // Forward: allow return traffic (established) from out to tun
        let added_fwd_in = iptables_ensure(
            &[
                "-C",
                "FORWARD",
                "-i",
                out,
                "-o",
                tun_ifname,
                "-m",
                "conntrack",
                "--ctstate",
                "RELATED,ESTABLISHED",
                "-j",
                "ACCEPT",
            ],
            &[
                "-A",
                "FORWARD",
                "-i",
                out,
                "-o",
                tun_ifname,
                "-m",
                "conntrack",
                "--ctstate",
                "RELATED,ESTABLISHED",
                "-j",
                "ACCEPT",
            ],
        )?;

        log(format!(
            "Linux NAT/forwarding configured for tun='{tun_ifname}' subnet={tun_cidr} out='{out}' (added: nat={added_nat} fwd_out={added_fwd_out} fwd_in={added_fwd_in})"
        ));
    }

    Ok(())
}
