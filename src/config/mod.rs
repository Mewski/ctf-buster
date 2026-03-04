pub mod types;

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use types::WorkspaceConfig;

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
  let content = std::fs::read_to_string(&config_path)
    .map_err(|e| Error::Config(format!("Failed to read {}: {e}", config_path.display())))?;
  let config: WorkspaceConfig = toml::from_str(&content)?;

  // Validate platform URL
  if config.platform.url.is_empty() {
    return Err(Error::Config("Platform URL cannot be empty".into()));
  }
  if !config.platform.url.starts_with("http://") && !config.platform.url.starts_with("https://") {
    return Err(Error::Config(format!(
      "Platform URL must start with http:// or https://, got: {}",
      config.platform.url
    )));
  }

  // Validate platform type if specified
  if let Some(ref pt) = config.platform.platform_type {
    if !["ctfd", "rctf"].contains(&pt.as_str()) {
      return Err(Error::Config(format!("Unknown platform type: '{}'. Supported: ctfd, rctf", pt)));
    }
  }

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

  #[test]
  fn load_workspace_config_rejects_empty_url() {
    let dir = TempDir::new().unwrap();
    let toml_content = r#"
      [platform]
      url = ""
      [workspace]
      name = "test"
    "#;
    std::fs::write(dir.path().join(".ctf.toml"), toml_content).unwrap();
    let err = load_workspace_config(dir.path()).unwrap_err();
    assert!(err.to_string().contains("cannot be empty"));
  }

  #[test]
  fn load_workspace_config_rejects_bad_url() {
    let dir = TempDir::new().unwrap();
    let toml_content = r#"
      [platform]
      url = "ftp://ctf.example.com"
      [workspace]
      name = "test"
    "#;
    std::fs::write(dir.path().join(".ctf.toml"), toml_content).unwrap();
    let err = load_workspace_config(dir.path()).unwrap_err();
    assert!(err.to_string().contains("http://"));
  }

  #[test]
  fn load_workspace_config_rejects_bad_platform_type() {
    let dir = TempDir::new().unwrap();
    let toml_content = r#"
      [platform]
      type = "htbctf"
      url = "https://ctf.example.com"
      [workspace]
      name = "test"
    "#;
    std::fs::write(dir.path().join(".ctf.toml"), toml_content).unwrap();
    let err = load_workspace_config(dir.path()).unwrap_err();
    assert!(err.to_string().contains("Unknown platform type"));
  }

  #[test]
  fn load_workspace_config_accepts_http_url() {
    let dir = TempDir::new().unwrap();
    let toml_content = r#"
      [platform]
      url = "http://localhost:8000"
      [workspace]
      name = "local-ctf"
    "#;
    std::fs::write(dir.path().join(".ctf.toml"), toml_content).unwrap();
    let config = load_workspace_config(dir.path()).unwrap();
    assert_eq!(config.platform.url, "http://localhost:8000");
  }

  #[test]
  fn load_workspace_config_with_token() {
    let dir = TempDir::new().unwrap();
    let toml_content = r#"
      [platform]
      url = "https://ctf.example.com"
      token = "my_secret_token"
      [workspace]
      name = "test"
    "#;
    std::fs::write(dir.path().join(".ctf.toml"), toml_content).unwrap();
    let config = load_workspace_config(dir.path()).unwrap();
    assert_eq!(config.platform.token.as_deref(), Some("my_secret_token"));
  }
}
