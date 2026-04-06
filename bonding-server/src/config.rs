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

    fn temp_path(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after unix epoch")
            .as_nanos();
        std::env::temp_dir()
            .join(format!("bonding-server-config-{label}-{nanos}"))
            .join(CONFIG_FILE_NAME)
    }

    fn cleanup(path: &Path) {
        if let Some(parent) = path.parent() {
            let _ = fs::remove_dir_all(parent);
        }
    }

    #[test]
    fn default_config_path_uses_binary_directory() {
        let path = default_config_path().expect("default config path should resolve");
        assert_eq!(
            path.file_name().and_then(|name| name.to_str()),
            Some(CONFIG_FILE_NAME)
        );
    }

    #[test]
    fn load_returns_defaults_when_file_is_missing() {
        let path = temp_path("missing");
        cleanup(&path);

        let cfg = load(&path).expect("missing config should fall back to defaults");

        assert_eq!(cfg.listen_addr, ServerConfig::default().listen_addr);
        cleanup(&path);
    }

    #[test]
    fn load_rejects_invalid_toml() {
        let path = temp_path("invalid");
        cleanup(&path);
        ensure_parent_dir(&path).expect("parent directory should be created");
        fs::write(&path, "not = [valid").expect("invalid config should be written");

        let err = load(&path).expect_err("invalid TOML should fail to parse");

        assert!(err.to_string().contains("failed to parse TOML"));
        cleanup(&path);
    }

    #[test]
    fn save_round_trips_config() {
        let path = temp_path("roundtrip");
        cleanup(&path);

        let cfg = ServerConfig {
            listen_addr: "127.0.0.2".into(),
            listen_port: 7001,
            ..ServerConfig::default()
        };

        save(&path, &cfg, false).expect("config should save");
        let loaded = load(&path).expect("config should load");

        assert_eq!(loaded.listen_addr, "127.0.0.2");
        assert_eq!(loaded.listen_port, 7001);
        cleanup(&path);
    }

    #[test]
    fn save_requires_force_to_overwrite() {
        let path = temp_path("overwrite");
        cleanup(&path);

        save(&path, &ServerConfig::default(), false).expect("initial save should succeed");
        let err = save(&path, &ServerConfig::default(), false)
            .expect_err("second save without force should fail");
        assert!(err.to_string().contains("use --force to overwrite"));

        save(&path, &ServerConfig::default(), true).expect("forced overwrite should succeed");
        cleanup(&path);
    }

    #[test]
    fn ensure_parent_dir_allows_relative_leaf_paths() {
        ensure_parent_dir(Path::new(CONFIG_FILE_NAME))
            .expect("leaf paths without a parent should be accepted");
    }

    #[test]
    fn create_default_creates_config_once_and_generates_key() {
        let path = temp_path("create-default");
        cleanup(&path);

        assert!(create_default(&path).expect("default config should be created"));
        assert!(!create_default(&path).expect("existing config should be preserved"));

        let cfg = load(&path).expect("created config should load");
        let key = cfg
            .encryption_key_b64
            .expect("default config should generate an encryption key");
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(key)
            .expect("generated key should be valid base64");

        assert_eq!(decoded.len(), 32);
        cleanup(&path);
    }
}
