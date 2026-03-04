pub mod ctfd;
#[cfg(test)]
pub mod mock;
pub mod rctf;
pub mod types;

use std::path::Path;

use async_trait::async_trait;

use crate::config::types::PlatformConfig;
use crate::error::Result;
use types::*;

#[async_trait]
pub trait Platform: Send + Sync {
  async fn whoami(&self) -> Result<TeamInfo>;
  async fn challenges(&self) -> Result<Vec<Challenge>>;
  async fn challenge(&self, id: &str) -> Result<Challenge>;
  async fn submit(&self, challenge_id: &str, flag: &str) -> Result<SubmitResult>;
  async fn scoreboard(&self, limit: Option<u32>) -> Result<Vec<ScoreboardEntry>>;
  async fn download_file(&self, file: &ChallengeFile, dest: &Path) -> Result<()>;
  async fn solves(&self, challenge_id: &str) -> Result<Vec<SolveInfo>>;
  async fn unlock_hint(&self, hint_id: &str) -> Result<Hint>;
}

pub async fn create_platform(
  config: &PlatformConfig,
  token: &str,
) -> Result<Box<dyn Platform>> {
  match &config.platform_type {
    Some(t) => match t.as_str() {
      "ctfd" => Ok(Box::new(ctfd::CtfdPlatform::new(
        config.url.clone(),
        token.to_string(),
      ))),
      "rctf" => Ok(Box::new(rctf::RctfPlatform::new(
        config.url.clone(),
        token.to_string(),
      ))),
      other => Err(crate::error::Error::Config(format!(
        "Unknown platform type: {other}"
      ))),
    },
    None => detect_platform(config, token).await,
  }
}

async fn detect_platform(
  config: &PlatformConfig,
  token: &str,
) -> Result<Box<dyn Platform>> {
  // Try CTFd first — construct platform and probe whoami
  let ctfd = ctfd::CtfdPlatform::new(config.url.clone(), token.to_string());
  if ctfd.whoami().await.is_ok() {
    tracing::info!("Auto-detected CTFd platform");
    return Ok(Box::new(ctfd));
  }

  // Try rCTF
  let rctf = rctf::RctfPlatform::new(config.url.clone(), token.to_string());
  if rctf.whoami().await.is_ok() {
    tracing::info!("Auto-detected rCTF platform");
    return Ok(Box::new(rctf));
  }

  Err(crate::error::Error::Config(
    "Could not auto-detect platform type. Set `type` in .ctf.toml [platform] section.".into(),
  ))
}
