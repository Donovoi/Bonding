use anyhow::{Context, Result};
use bonding_core::control::ServerConfig;
use directories::ProjectDirs;
use std::fs;
use std::path::{Path, PathBuf};

const CONFIG_FILE_NAME: &str = "bonding-server.toml";

pub fn default_config_path() -> Result<PathBuf> {
    let proj = ProjectDirs::from("io", "Donovoi", "Bonding")
        .context("could not determine platform config directory")?;
    let dir = proj.config_dir();
    Ok(dir.join(CONFIG_FILE_NAME))
}

pub fn ensure_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create config directory: {}", parent.display()))?;
    }
    Ok(())
}

pub fn load(path: &Path) -> Result<ServerConfig> {
    if !path.exists() {
        return Ok(ServerConfig::default());
    }
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read config: {}", path.display()))?;
    let cfg: ServerConfig = toml::from_str(&raw)
        .with_context(|| format!("failed to parse TOML: {}", path.display()))?;
    Ok(cfg)
}

pub fn save(path: &Path, cfg: &ServerConfig, overwrite: bool) -> Result<()> {
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
