use anyhow::{Context, Result};
use base64::Engine;
use bonding_core::control::ServerConfig;
use bonding_core::transport::PacketCrypto;
use std::fs;
use std::path::{Path, PathBuf};

const CONFIG_FILE_NAME: &str = "bonding-server.toml";

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

/// Write a default config to `path` (generating an encryption key when encryption is enabled).
/// This is a no-op if the file already exists; returns `true` when the file was created.
pub fn create_default(path: &Path) -> Result<bool> {
    if path.exists() {
        return Ok(false);
    }
    let mut cfg = ServerConfig::default();
    if cfg.enable_encryption {
        let key = PacketCrypto::generate_key();
        cfg.encryption_key_b64 = Some(base64::engine::general_purpose::STANDARD.encode(key));
    }
    save(path, &cfg, false)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_config_path() -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir()
            .join("bonding-tests")
            .join(format!("server-config-{unique}.toml"))
    }

    #[test]
    fn load_missing_config_returns_defaults_without_writing() {
        let path = temp_config_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        if path.exists() {
            fs::remove_file(&path).unwrap();
        }
        assert!(!path.exists());

        let cfg = load(&path).unwrap();

        assert!(!path.exists());
        assert!(!cfg.enable_encryption);
        assert!(cfg.encryption_key_b64.is_none());
    }

    #[test]
    fn create_default_creates_missing_config_with_defaults() {
        let path = temp_config_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        if path.exists() {
            fs::remove_file(&path).unwrap();
        }
        assert!(!path.exists());

        assert!(create_default(&path).unwrap());
        assert!(path.exists());

        let written = fs::read_to_string(&path).unwrap();
        let parsed: ServerConfig = toml::from_str(&written).unwrap();
        assert_eq!(parsed.listen_addr, ServerConfig::default().listen_addr);
        assert!(!parsed.enable_encryption);
        assert!(parsed.encryption_key_b64.is_none());

        fs::remove_file(&path).unwrap();
    }
}
