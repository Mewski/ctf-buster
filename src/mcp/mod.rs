pub mod types;

use std::path::PathBuf;
use std::sync::Arc;

use rmcp::{
  ErrorData as McpError, ServerHandler,
  handler::server::{router::tool::ToolRouter, wrapper::Parameters},
  model::{CallToolResult, Content, ServerCapabilities, ServerInfo},
  tool, tool_handler, tool_router,
};

use crate::config::types::WorkspaceConfig;
use crate::platform::Platform;
use crate::workspace::{scaffold, state};
use types::*;

fn to_mcp_error(e: impl std::fmt::Display) -> McpError {
  McpError::internal_error(e.to_string(), None)
}

#[derive(Clone)]
pub struct McpServer {
  platform: Arc<dyn Platform>,
  workspace_root: PathBuf,
  workspace_config: WorkspaceConfig,
  tool_router: ToolRouter<Self>,
}

#[tool_router]
impl McpServer {
  pub fn new(
    platform: Arc<dyn Platform>,
    workspace_root: PathBuf,
    workspace_config: WorkspaceConfig,
  ) -> Self {
    Self {
      platform,
      workspace_root,
      workspace_config,
      tool_router: Self::tool_router(),
    }
  }

  #[tool(description = "Get info about the authenticated team/user — name, score, rank")]
  async fn ctf_whoami(&self) -> Result<CallToolResult, McpError> {
    let info = self.platform.whoami().await.map_err(to_mcp_error)?;
    let json = serde_json::to_string_pretty(&info).map_err(to_mcp_error)?;
    Ok(CallToolResult::success(vec![Content::text(json)]))
  }

  #[tool(
    description = "List CTF challenges with optional filters. Returns challenges with cached descriptions/hints when available."
  )]
  async fn ctf_challenges(
    &self,
    Parameters(params): Parameters<ChallengesParams>,
  ) -> Result<CallToolResult, McpError> {
    let mut challenges = self.platform.challenges().await.map_err(to_mcp_error)?;

    // Merge cached details from state
    if let Ok(ws_state) = state::load_state(&self.workspace_root) {
      state::merge_cached_details(&mut challenges, &ws_state);
    }

    if let Some(cat) = &params.category {
      let cat_lower = cat.to_lowercase();
      challenges.retain(|c| c.category.to_lowercase() == cat_lower);
    }
    if params.unsolved.unwrap_or(false) {
      challenges.retain(|c| !c.solved_by_me);
    }
    if params.solved.unwrap_or(false) {
      challenges.retain(|c| c.solved_by_me);
    }

    challenges.sort_by(|a, b| a.category.cmp(&b.category).then(a.name.cmp(&b.name)));

    let json = serde_json::to_string_pretty(&challenges).map_err(to_mcp_error)?;
    Ok(CallToolResult::success(vec![Content::text(json)]))
  }

  #[tool(
    description = "Get full details of a specific challenge by ID or name — includes description, hints, files, and solve count"
  )]
  async fn ctf_challenge_detail(
    &self,
    Parameters(params): Parameters<ChallengeDetailParams>,
  ) -> Result<CallToolResult, McpError> {
    let challenges = self.platform.challenges().await.map_err(to_mcp_error)?;
    let challenge = resolve_challenge(&*self.platform, &params.id_or_name, &challenges)
      .await
      .map_err(to_mcp_error)?;
    let json = serde_json::to_string_pretty(&challenge).map_err(to_mcp_error)?;
    Ok(CallToolResult::success(vec![Content::text(json)]))
  }

  #[tool(
    description = "Submit a flag for a challenge. Returns whether it was correct, incorrect, already solved, or rate-limited."
  )]
  async fn ctf_submit_flag(
    &self,
    Parameters(params): Parameters<SubmitFlagParams>,
  ) -> Result<CallToolResult, McpError> {
    let challenges = self.platform.challenges().await.map_err(to_mcp_error)?;
    let challenge = resolve_challenge(&*self.platform, &params.challenge, &challenges)
      .await
      .map_err(to_mcp_error)?;

    let result = self
      .platform
      .submit(&challenge.id, &params.flag)
      .await
      .map_err(to_mcp_error)?;

    // Update local state on success
    if let crate::platform::types::SubmitResult::Correct {
      challenge: ref name,
      points,
    } = result
    {
      let _ = state::mark_solved(
        &self.workspace_root,
        &challenge.id,
        name,
        points,
        &params.flag,
      );
    }

    let json = serde_json::to_string_pretty(&result).map_err(to_mcp_error)?;
    Ok(CallToolResult::success(vec![Content::text(json)]))
  }

  #[tool(description = "Show the competition scoreboard with team rankings")]
  async fn ctf_scoreboard(
    &self,
    Parameters(params): Parameters<ScoreboardParams>,
  ) -> Result<CallToolResult, McpError> {
    let entries = self
      .platform
      .scoreboard(params.limit)
      .await
      .map_err(to_mcp_error)?;
    let json = serde_json::to_string_pretty(&entries).map_err(to_mcp_error)?;
    Ok(CallToolResult::success(vec![Content::text(json)]))
  }

  #[tool(
    description = "Sync challenges from the CTF platform — creates workspace directories, downloads files, and updates local state. Use full=true to also fetch descriptions/hints for all challenges."
  )]
  async fn ctf_sync(
    &self,
    Parameters(params): Parameters<SyncParams>,
  ) -> Result<CallToolResult, McpError> {
    let challenges = self.platform.challenges().await.map_err(to_mcp_error)?;

    let mut new_count = 0u32;
    let mut file_count = 0u32;

    for challenge in &challenges {
      let created =
        scaffold::scaffold_challenge(&self.workspace_root, challenge, &self.workspace_config.scaffold)
          .map_err(to_mcp_error)?;
      if created {
        new_count += 1;
      }

      let challenge_dir =
        scaffold::challenge_dir(&self.workspace_root, challenge, &self.workspace_config.scaffold);
      let dist_dir = challenge_dir.join("dist");

      for file in &challenge.files {
        let dest = dist_dir.join(&file.name);
        if !dest.exists() {
          std::fs::create_dir_all(&dist_dir).map_err(to_mcp_error)?;
          if let Err(e) = self.platform.download_file(file, &dest).await {
            tracing::warn!("Failed to download {}: {e}", file.name);
          } else {
            file_count += 1;
          }
        }
      }
    }

    // Update state
    if params.full.unwrap_or(false) {
      // Fetch full details for each challenge concurrently
      use futures::stream::{self, StreamExt};

      let ids: Vec<String> = challenges.iter().map(|c| c.id.clone()).collect();
      let platform = self.platform.clone();

      let detailed: Vec<_> = stream::iter(ids.into_iter().map(move |id| {
        let platform = platform.clone();
        async move { platform.challenge(&id).await }
      }))
      .buffer_unordered(5)
      .filter_map(|r| async { r.ok() })
      .collect()
      .await;

      state::update_sync_full(&self.workspace_root, &detailed).map_err(to_mcp_error)?;
    } else {
      state::update_sync(&self.workspace_root, &challenges).map_err(to_mcp_error)?;
    }

    let summary = format!(
      "Synced {} challenges ({} new, {} files downloaded){}",
      challenges.len(),
      new_count,
      file_count,
      if params.full.unwrap_or(false) {
        " with full details cached"
      } else {
        ""
      }
    );
    Ok(CallToolResult::success(vec![Content::text(summary)]))
  }

  #[tool(description = "Download files attached to a challenge into the workspace")]
  async fn ctf_download_files(
    &self,
    Parameters(params): Parameters<DownloadFilesParams>,
  ) -> Result<CallToolResult, McpError> {
    let challenges = self.platform.challenges().await.map_err(to_mcp_error)?;
    let challenge = resolve_challenge(&*self.platform, &params.challenge, &challenges)
      .await
      .map_err(to_mcp_error)?;

    if challenge.files.is_empty() {
      return Ok(CallToolResult::success(vec![Content::text(
        "No files attached to this challenge.",
      )]));
    }

    let challenge_dir =
      scaffold::challenge_dir(&self.workspace_root, &challenge, &self.workspace_config.scaffold);
    let dist_dir = challenge_dir.join("dist");
    std::fs::create_dir_all(&dist_dir).map_err(to_mcp_error)?;

    let mut downloaded = Vec::new();
    for file in &challenge.files {
      let dest = dist_dir.join(&file.name);
      self
        .platform
        .download_file(file, &dest)
        .await
        .map_err(to_mcp_error)?;
      downloaded.push(dest.display().to_string());
    }

    let json = serde_json::to_string_pretty(&downloaded).map_err(to_mcp_error)?;
    Ok(CallToolResult::success(vec![Content::text(json)]))
  }

  #[tool(
    description = "Get workspace status — team info, score, challenge counts per category, solve progress"
  )]
  async fn ctf_workspace_status(&self) -> Result<CallToolResult, McpError> {
    let info = self.platform.whoami().await.map_err(to_mcp_error)?;
    let challenges = self.platform.challenges().await.map_err(to_mcp_error)?;

    let total = challenges.len();
    let solved: usize = challenges.iter().filter(|c| c.solved_by_me).count();
    let total_points: u32 = challenges.iter().map(|c| c.value).sum();
    let solved_points: u32 = challenges
      .iter()
      .filter(|c| c.solved_by_me)
      .map(|c| c.value)
      .sum();

    let mut categories: std::collections::BTreeMap<&str, (u32, u32, u32)> =
      std::collections::BTreeMap::new();
    for c in &challenges {
      let entry = categories.entry(&c.category).or_default();
      entry.1 += 1;
      entry.2 += c.value;
      if c.solved_by_me {
        entry.0 += 1;
      }
    }

    let status = serde_json::json!({
      "team": info.name,
      "score": info.score,
      "rank": info.rank,
      "challenges": {
        "total": total,
        "solved": solved,
        "total_points": total_points,
        "solved_points": solved_points,
      },
      "categories": categories.iter().map(|(cat, (s, t, pts))| {
        serde_json::json!({
          "name": cat,
          "solved": s,
          "total": t,
          "points": pts,
        })
      }).collect::<Vec<_>>(),
    });

    let json = serde_json::to_string_pretty(&status).map_err(to_mcp_error)?;
    Ok(CallToolResult::success(vec![Content::text(json)]))
  }

  #[tool(description = "Unlock a hint for a challenge (may cost points)")]
  async fn ctf_unlock_hint(
    &self,
    Parameters(params): Parameters<UnlockHintParams>,
  ) -> Result<CallToolResult, McpError> {
    let hint = self
      .platform
      .unlock_hint(&params.hint_id)
      .await
      .map_err(to_mcp_error)?;
    let json = serde_json::to_string_pretty(&hint).map_err(to_mcp_error)?;
    Ok(CallToolResult::success(vec![Content::text(json)]))
  }
}

#[tool_handler]
impl ServerHandler for McpServer {
  fn get_info(&self) -> ServerInfo {
    ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
      .with_instructions(
        "CTF competition assistant. Use these tools to interact with a CTF platform: \
         list challenges, read descriptions and hints for context, submit flags, \
         track progress, and download challenge files. Start with ctf_workspace_status \
         to understand the current state, then use ctf_challenges to browse. \
         Use ctf_sync with full=true to cache all challenge descriptions for context."
          .to_string(),
      )
  }
}

async fn resolve_challenge(
  platform: &dyn Platform,
  id_or_name: &str,
  cached_challenges: &[crate::platform::types::Challenge],
) -> crate::error::Result<crate::platform::types::Challenge> {
  crate::cli::challenge::resolve_challenge(platform, id_or_name, cached_challenges).await
}
