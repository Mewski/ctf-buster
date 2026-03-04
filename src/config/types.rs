use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceConfig {
  pub platform: PlatformConfig,
  pub workspace: WorkspaceSection,
  #[serde(default)]
  pub scaffold: ScaffoldConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformConfig {
  #[serde(rename = "type")]
  pub platform_type: Option<String>,
  pub url: String,
  /// API token — if set here, used directly (no keyring/env needed).
  /// Supports env var expansion: "${CTF_TOKEN}" resolves at runtime.
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceSection {
  pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScaffoldConfig {
  #[serde(default = "default_template")]
  pub template: String,
  #[serde(default = "default_true")]
  pub create_solve_file: bool,
  #[serde(default = "default_true")]
  pub create_notes_file: bool,
}

impl Default for ScaffoldConfig {
  fn default() -> Self {
    Self { template: default_template(), create_solve_file: true, create_notes_file: true }
  }
}

fn default_template() -> String {
  "{category}/{name}".to_string()
}

fn default_true() -> bool {
  true
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn parse_minimal_workspace_config() {
    let toml = r#"
      [platform]
      url = "https://ctf.example.com"

      [workspace]
      name = "test-ctf"
    "#;
    let config: WorkspaceConfig = toml::from_str(toml).unwrap();
    assert_eq!(config.platform.url, "https://ctf.example.com");
    assert!(config.platform.platform_type.is_none());
    assert_eq!(config.workspace.name, "test-ctf");
    // scaffold should use defaults
    assert_eq!(config.scaffold.template, "{category}/{name}");
    assert!(config.scaffold.create_solve_file);
    assert!(config.scaffold.create_notes_file);
  }

  #[test]
  fn parse_full_workspace_config() {
    let toml = r#"
      [platform]
      type = "ctfd"
      url = "https://ctf.example.com"

      [workspace]
      name = "heroctf"

      [scaffold]
      template = "{name}"
      create_solve_file = false
      create_notes_file = true
    "#;
    let config: WorkspaceConfig = toml::from_str(toml).unwrap();
    assert_eq!(config.platform.platform_type.as_deref(), Some("ctfd"));
    assert_eq!(config.scaffold.template, "{name}");
    assert!(!config.scaffold.create_solve_file);
  }

  #[test]
  fn scaffold_config_defaults() {
    let config = ScaffoldConfig::default();
    assert_eq!(config.template, "{category}/{name}");
    assert!(config.create_solve_file);
    assert!(config.create_notes_file);
  }

  #[test]
  fn platform_config_without_type() {
    let toml = r#"url = "https://ctf.example.com""#;
    let config: PlatformConfig = toml::from_str(toml).unwrap();
    assert!(config.platform_type.is_none());
    assert_eq!(config.url, "https://ctf.example.com");
    assert!(config.token.is_none());
  }

  #[test]
  fn platform_config_with_token() {
    let toml = r#"
      url = "https://ctf.example.com"
      token = "ctfd_abc123"
    "#;
    let config: PlatformConfig = toml::from_str(toml).unwrap();
    assert_eq!(config.token.as_deref(), Some("ctfd_abc123"));
  }

  #[test]
  fn platform_config_with_env_var_token() {
    let toml = r#"
      url = "https://ctf.example.com"
      token = "${CTF_TOKEN}"
    "#;
    let config: PlatformConfig = toml::from_str(toml).unwrap();
    assert_eq!(config.token.as_deref(), Some("${CTF_TOKEN}"));
  }

  #[test]
  fn platform_config_token_not_serialized_when_none() {
    let config = WorkspaceConfig {
      platform: PlatformConfig {
        platform_type: Some("ctfd".into()),
        url: "https://ctf.example.com".into(),
        token: None,
      },
      workspace: WorkspaceSection { name: "test".into() },
      scaffold: ScaffoldConfig::default(),
    };
    let serialized = toml::to_string_pretty(&config).unwrap();
    assert!(!serialized.contains("token"));
  }
}
