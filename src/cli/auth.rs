use clap::Subcommand;
use colored::Colorize;
use dialoguer::{Input, Password};

use crate::config::types::PlatformConfig;
use crate::error::{Error, Result};
use crate::platform;

#[derive(Subcommand)]
pub enum AuthCommand {
  /// Log in to a CTF platform
  Login,
  /// Log out (clear stored credentials)
  Logout,
  /// Show current auth status
  Status,
}

fn keyring_key(workspace_name: &str) -> String {
  format!("ctf:{workspace_name}")
}

pub fn store_token(workspace_name: &str, token: &str) -> Result<()> {
  let entry = keyring::Entry::new("ctf-buster", &keyring_key(workspace_name))
    .map_err(|e| Error::Keyring(e.to_string()))?;
  entry
    .set_password(token)
    .map_err(|e| Error::Keyring(e.to_string()))?;
  Ok(())
}

/// Expand environment variable references in a string.
/// Supports `${VAR}` and `${VAR:-default}` syntax.
pub fn expand_env_vars(s: &str) -> String {
  let re = regex_lite::Regex::new(r"\$\{([^}:]+)(?::-([^}]*))?\}").unwrap();
  re.replace_all(s, |caps: &regex_lite::Captures| {
    let var_name = caps.get(1).unwrap().as_str();
    let default_val = caps.get(2).map(|m| m.as_str()).unwrap_or("");
    std::env::var(var_name).unwrap_or_else(|_| default_val.to_string())
  })
  .into_owned()
}

/// Resolve the API token from multiple sources (in priority order):
/// 1. Explicit token passed via CLI arg or caller
/// 2. `CTF_TOKEN` environment variable
/// 3. `token` field in `.ctf.toml` (with env var expansion)
/// 4. System keyring
pub fn get_token_with_config(
  workspace_name: &str,
  config_token: Option<&str>,
  cli_token: Option<&str>,
) -> Result<String> {
  // 1. CLI arg (highest priority)
  if let Some(token) = cli_token {
    return Ok(token.to_string());
  }

  // 2. CTF_TOKEN env var
  if let Ok(token) = std::env::var("CTF_TOKEN") {
    return Ok(token);
  }

  // 3. Config file token (with env var expansion)
  if let Some(token) = config_token {
    let expanded = expand_env_vars(token);
    if !expanded.is_empty() {
      return Ok(expanded);
    }
  }

  // 4. Keyring
  let entry = keyring::Entry::new("ctf-buster", &keyring_key(workspace_name))
    .map_err(|e| Error::Keyring(e.to_string()))?;
  entry
    .get_password()
    .map_err(|e| Error::Auth(format!("No token found. Set CTF_TOKEN env var, add `token` to .ctf.toml, or run `ctf auth login`. ({e})")))
}

pub fn get_token(workspace_name: &str) -> Result<String> {
  get_token_with_config(workspace_name, None, None)
}

pub fn delete_token(workspace_name: &str) -> Result<()> {
  let entry = keyring::Entry::new("ctf-buster", &keyring_key(workspace_name))
    .map_err(|e| Error::Keyring(e.to_string()))?;
  entry
    .delete_credential()
    .map_err(|e| Error::Keyring(e.to_string()))?;
  Ok(())
}

pub async fn handle_login(workspace_name: &str, platform_url: &str) -> Result<()> {
  let token: String = Password::new()
    .with_prompt("API token")
    .interact()
    .map_err(|e| Error::Auth(e.to_string()))?;

  // Verify the token works
  let config = PlatformConfig {
    platform_type: None,
    url: platform_url.to_string(),
    token: None,
  };

  let plat = platform::create_platform(&config, &token).await?;
  let info = plat.whoami().await?;

  store_token(workspace_name, &token)?;

  println!(
    "{} Logged in as {} (score: {})",
    "✓".green().bold(),
    info.name.bold(),
    info.score,
  );
  if let Some(rank) = info.rank {
    println!("  Rank: #{rank}");
  }

  Ok(())
}

pub async fn handle_login_interactive() -> Result<()> {
  let url: String = Input::new()
    .with_prompt("Platform URL")
    .interact_text()
    .map_err(|e| Error::Auth(e.to_string()))?;

  let workspace_name: String = Input::new()
    .with_prompt("Workspace name")
    .interact_text()
    .map_err(|e| Error::Auth(e.to_string()))?;

  let token: String = Password::new()
    .with_prompt("API token")
    .interact()
    .map_err(|e| Error::Auth(e.to_string()))?;

  let config = PlatformConfig {
    platform_type: None,
    url: url.clone(),
    token: None,
  };

  let plat = platform::create_platform(&config, &token).await?;
  let info = plat.whoami().await?;

  store_token(&workspace_name, &token)?;

  println!(
    "{} Logged in as {} (score: {})",
    "✓".green().bold(),
    info.name.bold(),
    info.score,
  );
  if let Some(rank) = info.rank {
    println!("  Rank: #{rank}");
  }

  Ok(())
}

pub async fn handle_logout(workspace_name: &str) -> Result<()> {
  delete_token(workspace_name)?;
  println!("{} Logged out", "✓".green().bold());
  Ok(())
}

pub async fn handle_status(workspace_name: &str, platform_url: &str) -> Result<()> {
  let token = get_token(workspace_name)?;
  let config = PlatformConfig {
    platform_type: None,
    url: platform_url.to_string(),
    token: None,
  };

  let plat = platform::create_platform(&config, &token).await?;
  let info = plat.whoami().await?;

  println!("Workspace: {}", workspace_name.bold());
  println!("Platform:  {platform_url}");
  println!("Team:      {}", info.name.bold());
  println!("Score:     {}", info.score);
  if let Some(rank) = info.rank {
    println!("Rank:      #{rank}");
  }

  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::sync::Mutex;

  /// Tests that modify CTF_TOKEN must hold this lock to avoid racing each other.
  static ENV_LOCK: Mutex<()> = Mutex::new(());

  #[test]
  fn expand_env_vars_no_vars() {
    assert_eq!(expand_env_vars("plain text"), "plain text");
  }

  #[test]
  fn expand_env_vars_simple_var() {
    std::env::set_var("CTF_TEST_TOKEN_XYZ", "secret123");
    assert_eq!(expand_env_vars("${CTF_TEST_TOKEN_XYZ}"), "secret123");
    std::env::remove_var("CTF_TEST_TOKEN_XYZ");
  }

  #[test]
  fn expand_env_vars_with_default() {
    std::env::remove_var("CTF_NONEXISTENT_VAR_XYZ");
    assert_eq!(
      expand_env_vars("${CTF_NONEXISTENT_VAR_XYZ:-fallback}"),
      "fallback"
    );
  }

  #[test]
  fn expand_env_vars_set_var_ignores_default() {
    std::env::set_var("CTF_TEST_VAR_ABC", "actual");
    assert_eq!(
      expand_env_vars("${CTF_TEST_VAR_ABC:-fallback}"),
      "actual"
    );
    std::env::remove_var("CTF_TEST_VAR_ABC");
  }

  #[test]
  fn expand_env_vars_multiple_vars() {
    std::env::set_var("CTF_A_XYZ", "hello");
    std::env::set_var("CTF_B_XYZ", "world");
    assert_eq!(
      expand_env_vars("${CTF_A_XYZ} ${CTF_B_XYZ}"),
      "hello world"
    );
    std::env::remove_var("CTF_A_XYZ");
    std::env::remove_var("CTF_B_XYZ");
  }

  #[test]
  fn expand_env_vars_unset_no_default() {
    std::env::remove_var("CTF_UNSET_VAR_XYZ");
    assert_eq!(expand_env_vars("${CTF_UNSET_VAR_XYZ}"), "");
  }

  #[test]
  fn expand_env_vars_embedded_in_string() {
    std::env::set_var("CTF_HOST_XYZ", "ctf.example.com");
    assert_eq!(
      expand_env_vars("https://${CTF_HOST_XYZ}/api"),
      "https://ctf.example.com/api"
    );
    std::env::remove_var("CTF_HOST_XYZ");
  }

  #[test]
  fn get_token_with_config_cli_takes_priority() {
    let _lock = ENV_LOCK.lock().unwrap();
    std::env::set_var("CTF_TOKEN", "env_token");
    let result = get_token_with_config("test", Some("config_token"), Some("cli_token"));
    std::env::remove_var("CTF_TOKEN");
    assert_eq!(result.unwrap(), "cli_token");
  }

  #[test]
  fn get_token_with_config_env_over_config() {
    let _lock = ENV_LOCK.lock().unwrap();
    std::env::set_var("CTF_TOKEN", "env_token");
    let result = get_token_with_config("test", Some("config_token"), None);
    std::env::remove_var("CTF_TOKEN");
    assert_eq!(result.unwrap(), "env_token");
  }

  #[test]
  fn get_token_with_config_config_token_expanded() {
    let _lock = ENV_LOCK.lock().unwrap();
    std::env::remove_var("CTF_TOKEN");
    std::env::set_var("CTF_MY_SECRET_XYZ", "expanded_secret");
    let result = get_token_with_config("test", Some("${CTF_MY_SECRET_XYZ}"), None);
    std::env::remove_var("CTF_MY_SECRET_XYZ");
    assert_eq!(result.unwrap(), "expanded_secret");
  }

  #[test]
  fn get_token_with_config_literal_config_token() {
    let _lock = ENV_LOCK.lock().unwrap();
    std::env::remove_var("CTF_TOKEN");
    let result = get_token_with_config("test", Some("literal_token_value"), None);
    assert_eq!(result.unwrap(), "literal_token_value");
  }
}
