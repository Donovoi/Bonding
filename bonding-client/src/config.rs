use anyhow::{Context, Result};
use base64::Engine;
use bonding_core::control::BondingConfig;
use bonding_core::transport::PacketCrypto;
use std::fs;
use std::path::{Path, PathBuf};

const CONFIG_FILE_NAME: &str = "bonding-client.toml";

pub fn default_config_path() -> Result<PathBuf> {
    // Keep config next to the executable for portable, self-contained deployments.
    let exe = std::env::current_exe().context("could not determine current executable path")?;
    let dir = exe
        .parent()
        .context("could not determine executable directory")?;
    Ok(dir.join(CONFIG_FILE_NAME))
}

pub fn ensure_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create config directory: {}", parent.display()))?;
    }
    Ok(())
}

pub fn load(path: &Path) -> Result<BondingConfig> {
    if !path.exists() {
        return Ok(BondingConfig::default());
    }
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read config: {}", path.display()))?;
    let cfg: BondingConfig = toml::from_str(&raw)
        .with_context(|| format!("failed to parse TOML: {}", path.display()))?;
    Ok(cfg)
}

pub fn save(path: &Path, cfg: &BondingConfig, overwrite: bool) -> Result<()> {
    if path.exists() && !overwrite {
        anyhow::bail!(
            "config already exists at {} (use --force to overwrite)",
            path.display()
        );
    }
    ensure_parent_dir(path)?;
    let raw = toml::to_string_pretty(cfg).context("failed to serialize config to TOML")?;
    fs::write(path, raw).with_context(|| format!("failed to write config: {}", path.display()))?;
    Ok(())
}

/// Write a default config to `path` (generating an encryption key when encryption is enabled).
/// This is a no-op if the file already exists; returns `true` when the file was created.
pub fn create_default(path: &Path) -> Result<bool> {
    if path.exists() {
        return Ok(false);
    }
    let mut cfg = BondingConfig::default();
    if cfg.enable_encryption {
        let key = PacketCrypto::generate_key();
        cfg.encryption_key_b64 =
            Some(base64::engine::general_purpose::STANDARD.encode(key));
    }
    save(path, &cfg, false)?;
    Ok(true)
}
