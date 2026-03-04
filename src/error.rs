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

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn error_display_messages() {
    assert_eq!(Error::Platform("connection refused".into()).to_string(), "Platform error: connection refused");
    assert_eq!(Error::Auth("invalid token".into()).to_string(), "Auth error: invalid token");
    assert_eq!(Error::NotInWorkspace.to_string(), "Not in a CTF workspace. Run `ctf init` first.");
    assert_eq!(Error::ChallengeNotFound("crypto101".into()).to_string(), "Challenge not found: crypto101");
    assert_eq!(Error::Config("bad url".into()).to_string(), "Config error: bad url");
    assert_eq!(Error::Workspace("missing dir".into()).to_string(), "Workspace error: missing dir");
    assert_eq!(Error::Keyring("access denied".into()).to_string(), "Keyring error: access denied");
    assert_eq!(Error::Mcp("transport failed".into()).to_string(), "MCP error: transport failed");
  }

  #[test]
  fn error_from_io() {
    let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file gone");
    let err: Error = io_err.into();
    assert!(err.to_string().contains("file gone"));
  }

  #[test]
  fn error_from_json() {
    let json_err = serde_json::from_str::<String>("invalid").unwrap_err();
    let err: Error = json_err.into();
    assert!(err.to_string().contains("JSON error"));
  }

  #[test]
  fn error_from_toml() {
    let toml_err = toml::from_str::<String>("[[invalid").unwrap_err();
    let err: Error = toml_err.into();
    assert!(err.to_string().contains("TOML"));
  }
}
