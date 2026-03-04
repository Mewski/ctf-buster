use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
  #[error("HTTP error: {0}")]
  Http(#[from] reqwest::Error),

  #[error("JSON error: {0}")]
  Json(#[from] serde_json::Error),

  #[error("IO error: {0}")]
  Io(#[from] std::io::Error),

  #[error("Config error: {0}")]
  Config(String),

  #[error("Platform error: {0}")]
  Platform(String),

  #[error("Workspace error: {0}")]
  Workspace(String),

  #[error("Auth error: {0}")]
  Auth(String),

  #[error("Not in a CTF workspace. Run `ctf init` first.")]
  NotInWorkspace,

  #[error("Challenge not found: {0}")]
  ChallengeNotFound(String),

  #[error("TOML parse error: {0}")]
  Toml(#[from] toml::de::Error),

  #[error("TOML serialize error: {0}")]
  TomlSerialize(#[from] toml::ser::Error),

  #[error("Keyring error: {0}")]
  Keyring(String),

  #[error("MCP error: {0}")]
  Mcp(String),
}
