pub mod types;

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use types::{GlobalConfig, WorkspaceConfig};

const WORKSPACE_CONFIG_FILE: &str = ".ctf.toml";

pub fn find_workspace_root(from: &Path) -> Option<PathBuf> {
  let mut current = from.to_path_buf();
  loop {
    if current.join(WORKSPACE_CONFIG_FILE).exists() {
      return Some(current);
    }
    if !current.pop() {
      return None;
    }
  }
}

pub fn load_workspace_config(workspace_root: &Path) -> Result<WorkspaceConfig> {
  let config_path = workspace_root.join(WORKSPACE_CONFIG_FILE);
  let content = std::fs::read_to_string(&config_path).map_err(|e| {
    Error::Config(format!(
      "Failed to read {}: {e}",
      config_path.display()
    ))
  })?;
  let config: WorkspaceConfig = toml::from_str(&content)?;
  Ok(config)
}

pub fn load_global_config() -> Result<GlobalConfig> {
  let config_dir = dirs::config_dir()
    .ok_or_else(|| Error::Config("Could not determine config directory".into()))?;
  let config_path = config_dir.join("ctf").join("config.toml");

  if !config_path.exists() {
    return Ok(GlobalConfig::default());
  }

  let content = std::fs::read_to_string(&config_path).map_err(|e| {
    Error::Config(format!(
      "Failed to read {}: {e}",
      config_path.display()
    ))
  })?;
  let config: GlobalConfig = toml::from_str(&content)?;
  Ok(config)
}

#[cfg(test)]
mod tests {
  use super::*;
  use tempfile::TempDir;

  #[test]
  fn find_workspace_root_from_subdirectory() {
    let dir = TempDir::new().unwrap();
    let ws = dir.path().join("my-ctf");
    std::fs::create_dir_all(&ws).unwrap();
    std::fs::write(ws.join(".ctf.toml"), "[platform]\nurl = \"x\"\n[workspace]\nname = \"t\"").unwrap();

    let sub = ws.join("crypto/challenge1");
    std::fs::create_dir_all(&sub).unwrap();

    let found = find_workspace_root(&sub);
    assert_eq!(found, Some(ws));
  }

  #[test]
  fn find_workspace_root_not_found() {
    let dir = TempDir::new().unwrap();
    let found = find_workspace_root(dir.path());
    assert!(found.is_none());
  }

  #[test]
  fn load_workspace_config_valid() {
    let dir = TempDir::new().unwrap();
    let toml_content = r#"
      [platform]
      type = "ctfd"
      url = "https://ctf.example.com"
      [workspace]
      name = "test"
    "#;
    std::fs::write(dir.path().join(".ctf.toml"), toml_content).unwrap();

    let config = load_workspace_config(dir.path()).unwrap();
    assert_eq!(config.platform.platform_type.as_deref(), Some("ctfd"));
    assert_eq!(config.workspace.name, "test");
  }
}
