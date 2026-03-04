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
    // Input validation
    let flag = params.flag.trim();
    if flag.is_empty() {
      return Err(McpError::invalid_params("Flag cannot be empty", None));
    }
    let challenge_name = params.challenge.trim();
    if challenge_name.is_empty() {
      return Err(McpError::invalid_params("Challenge name cannot be empty", None));
    }

    let challenges = self.platform.challenges().await.map_err(to_mcp_error)?;
    let challenge = resolve_challenge(&*self.platform, challenge_name, &challenges)
      .await
      .map_err(to_mcp_error)?;

    let result = self
      .platform
      .submit(&challenge.id, flag)
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
        flag,
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
        let safe_name = scaffold::sanitize_filename(&file.name);
        let dest = dist_dir.join(&safe_name);
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
    let (is_full, hints_unlocked) = if params.full.unwrap_or(false) {
      // Fetch full details for each challenge concurrently
      use futures::stream::{self, StreamExt};

      let ids: Vec<String> = challenges.iter().map(|c| c.id.clone()).collect();
      let platform = self.platform.clone();

      let detailed: Vec<_> = stream::iter(ids.into_iter().map(move |id| {
        let platform = platform.clone();
        async move { (id.clone(), platform.challenge(&id).await) }
      }))
      .buffer_unordered(5) // Limit concurrent API requests
      .filter_map(|(id, r)| async move {
        match r {
          Ok(c) => Some(c),
          Err(e) => {
            tracing::warn!("Failed to fetch details for challenge {id}: {e}");
            None
          }
        }
      })
      .collect()
      .await;

      // Auto-unlock free hints (cost == 0) during full sync
      let mut hints_unlocked = 0u32;
      let platform_for_hints = self.platform.clone();
      for challenge in &detailed {
        for hint in &challenge.hints {
          if hint.cost == 0 && hint.content.is_none() {
            if let Ok(_unlocked) = platform_for_hints.unlock_hint(&hint.id).await {
              hints_unlocked += 1;
            }
          }
        }
      }

      // Re-fetch details for challenges that had hints unlocked to get the content
      if hints_unlocked > 0 {
        let platform_refetch = self.platform.clone();
        let ids_with_hints: Vec<String> = detailed
          .iter()
          .filter(|c| c.hints.iter().any(|h| h.cost == 0 && h.content.is_none()))
          .map(|c| c.id.clone())
          .collect();

        let mut updated_detailed = detailed;
        for id in ids_with_hints {
          if let Ok(refreshed) = platform_refetch.challenge(&id).await {
            if let Some(entry) = updated_detailed.iter_mut().find(|c| c.id == id) {
              *entry = refreshed;
            }
          }
        }
        state::update_sync_full(&self.workspace_root, &updated_detailed).map_err(to_mcp_error)?;
      } else {
        state::update_sync_full(&self.workspace_root, &detailed).map_err(to_mcp_error)?;
      }

      (true, hints_unlocked)
    } else {
      state::update_sync(&self.workspace_root, &challenges).map_err(to_mcp_error)?;
      (false, 0)
    };

    // Fetch notifications (always, regardless of full flag)
    let notifications = self.platform.notifications().await.unwrap_or_default();
    let notif_count = notifications.len();
    let _ = state::update_notifications(&self.workspace_root, &notifications);

    let mut summary = format!(
      "Synced {} challenges ({} new, {} files downloaded)",
      challenges.len(),
      new_count,
      file_count,
    );
    if is_full {
      summary.push_str(" with full details cached");
    }
    if hints_unlocked > 0 {
      summary.push_str(&format!(", {} free hints unlocked", hints_unlocked));
    }
    if notif_count > 0 {
      summary.push_str(&format!(", {} notifications fetched", notif_count));
    }
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
      let safe_name = scaffold::sanitize_filename(&file.name);
      let dest = dist_dir.join(&safe_name);
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

  #[tool(
    description = "Unlock a hint for a challenge. WARNING: hints with cost > 0 will deduct points from your team score."
  )]
  async fn ctf_unlock_hint(
    &self,
    Parameters(params): Parameters<UnlockHintParams>,
  ) -> Result<CallToolResult, McpError> {
    let hint_id = params.hint_id.trim();
    if hint_id.is_empty() {
      return Err(McpError::invalid_params("Hint ID cannot be empty", None));
    }

    // Check if we have cached info about this hint's cost
    if let Ok(ws_state) = state::load_state(&self.workspace_root) {
      for cs in ws_state.challenges.values() {
        if let Some(hints) = &cs.hints {
          for h in hints {
            if h.id == hint_id && h.cost > 0 {
              let hint = self
                .platform
                .unlock_hint(hint_id)
                .await
                .map_err(to_mcp_error)?;
              let mut result = serde_json::to_value(&hint).map_err(to_mcp_error)?;
              result["warning"] = serde_json::json!(
                format!("This hint cost {} points — your team score has been reduced", h.cost)
              );
              let json = serde_json::to_string_pretty(&result).map_err(to_mcp_error)?;
              return Ok(CallToolResult::success(vec![Content::text(json)]));
            }
          }
        }
      }
    }

    let hint = self
      .platform
      .unlock_hint(hint_id)
      .await
      .map_err(to_mcp_error)?;
    let json = serde_json::to_string_pretty(&hint).map_err(to_mcp_error)?;
    Ok(CallToolResult::success(vec![Content::text(json)]))
  }

  #[tool(
    description = "Get the challenge priority queue — shows what to solve next, what's in progress, and what failed. Persists across agent restarts."
  )]
  async fn ctf_queue_status(&self) -> Result<CallToolResult, McpError> {
    let orch = state::load_orchestration(&self.workspace_root).map_err(to_mcp_error)?;
    let json = serde_json::to_string_pretty(&orch).map_err(to_mcp_error)?;
    Ok(CallToolResult::success(vec![Content::text(json)]))
  }

  #[tool(
    description = "Update the challenge queue — set priorities, mark challenges as in-progress or failed, prioritize specific challenges, or retry failed ones. Persists across agent restarts."
  )]
  async fn ctf_queue_update(
    &self,
    Parameters(params): Parameters<QueueUpdateParams>,
  ) -> Result<CallToolResult, McpError> {
    let mut orch = state::load_orchestration(&self.workspace_root).map_err(to_mcp_error)?;

    match params.action.as_str() {
      "set_queue" => {
        let json_str = params
          .queue_json
          .ok_or_else(|| McpError::invalid_params("queue_json required for set_queue", None))?;
        let queue: Vec<state::QueuedChallenge> =
          serde_json::from_str(&json_str).map_err(to_mcp_error)?;
        orch.queue = queue;
      }
      "start" => {
        let name = params
          .challenge
          .ok_or_else(|| McpError::invalid_params("challenge required for start", None))?;
        orch.queue.retain(|q| q.name != name);
        if !orch.in_progress.contains(&name) {
          orch.in_progress.push(name);
        }
      }
      "complete" => {
        let name = params
          .challenge
          .ok_or_else(|| McpError::invalid_params("challenge required for complete", None))?;
        orch.in_progress.retain(|n| n != &name);
      }
      "fail" => {
        let name = params
          .challenge
          .ok_or_else(|| McpError::invalid_params("challenge required for fail", None))?;
        orch.in_progress.retain(|n| n != &name);
        orch.failed.push(state::FailedAttempt {
          name,
          category: params.category.unwrap_or_default(),
          attempted_at: chrono::Utc::now(),
          notes: params.notes.unwrap_or_else(|| "failed".to_string()),
        });
      }
      "prioritize" => {
        let name = params
          .challenge
          .ok_or_else(|| McpError::invalid_params("challenge required for prioritize", None))?;
        // Find the challenge in queue, remove it, give it max priority, insert at front
        let name_lower = name.to_lowercase();
        if let Some(pos) = orch.queue.iter().position(|q| q.name.to_lowercase() == name_lower) {
          let mut entry = orch.queue.remove(pos);
          // Set priority higher than everything else
          let max_priority = orch.queue.iter().map(|q| q.priority).max().unwrap_or(0);
          entry.priority = max_priority + 100;
          orch.queue.insert(0, entry);
        } else {
          // Check if it's in failed list — pull it back into queue at front
          if let Some(failed_pos) = orch.failed.iter().position(|f| f.name.to_lowercase() == name_lower) {
            let failed = orch.failed.remove(failed_pos);
            let max_priority = orch.queue.iter().map(|q| q.priority).max().unwrap_or(0);
            orch.queue.insert(0, state::QueuedChallenge {
              name: failed.name,
              category: failed.category,
              priority: max_priority + 100,
              points: 0, // Unknown from failed state; auto_queue will fix on next run
            });
          } else if orch.in_progress.iter().any(|n| n.to_lowercase() == name_lower) {
            return Ok(CallToolResult::success(vec![Content::text(format!(
              "'{}' is already in progress.", name
            ))]));
          } else {
            return Err(McpError::invalid_params(
              format!("Challenge '{}' not found in queue or failed list.", name),
              None,
            ));
          }
        }
      }
      "retry" => {
        let name = params
          .challenge
          .ok_or_else(|| McpError::invalid_params("challenge required for retry", None))?;
        // Move from failed back to queue with reduced priority
        let name_lower = name.to_lowercase();
        if let Some(pos) = orch.failed.iter().position(|f| f.name.to_lowercase() == name_lower) {
          let failed = orch.failed.remove(pos);
          orch.queue.push(state::QueuedChallenge {
            name: failed.name,
            category: failed.category,
            priority: -5, // Low priority retry; auto_queue will rescore
            points: 0,
          });
        } else {
          return Err(McpError::invalid_params(
            format!("Challenge '{}' not in the failed list.", name),
            None,
          ));
        }
      }
      "clear" => {
        orch = state::OrchestrationState::default();
      }
      other => {
        return Err(McpError::invalid_params(
          format!("Unknown action: {other}. Use set_queue, start, complete, fail, prioritize, retry, or clear."),
          None,
        ));
      }
    }

    orch.updated_at = Some(chrono::Utc::now());
    state::update_orchestration(&self.workspace_root, orch).map_err(to_mcp_error)?;

    let updated = state::load_orchestration(&self.workspace_root).map_err(to_mcp_error)?;
    let json = serde_json::to_string_pretty(&updated).map_err(to_mcp_error)?;
    Ok(CallToolResult::success(vec![Content::text(json)]))
  }

  #[tool(description = "Get competition notifications/announcements from the CTF platform")]
  async fn ctf_notifications(&self) -> Result<CallToolResult, McpError> {
    let notifications = self
      .platform
      .notifications()
      .await
      .map_err(to_mcp_error)?;

    // Update cached state
    let _ = state::update_notifications(&self.workspace_root, &notifications);

    let json = serde_json::to_string_pretty(&notifications).map_err(to_mcp_error)?;
    Ok(CallToolResult::success(vec![Content::text(json)]))
  }

  #[tool(
    description = "Auto-score and queue all unsolved challenges by priority. Implements the scoring algorithm: category_score (crypto/forensics +10, web +8, rev +6, misc +4, pwn +2) + difficulty_bonus (>50 solves: +20, 20-50: +10, <20: +0) + solve_bonus (points/solves < 10: +5). Replaces the current queue. Call this after ctf_sync to automatically prioritize what to solve next."
  )]
  async fn ctf_auto_queue(
    &self,
    Parameters(params): Parameters<AutoQueueParams>,
  ) -> Result<CallToolResult, McpError> {
    // Get current challenges from platform
    let challenges = self.platform.challenges().await.map_err(to_mcp_error)?;

    // Merge cached details for solve count info
    let mut challenges = challenges;
    if let Ok(ws_state) = state::load_state(&self.workspace_root) {
      state::merge_cached_details(&mut challenges, &ws_state);
    }

    // Load orchestration state for in_progress and failed lists
    let orch = state::load_orchestration(&self.workspace_root).map_err(to_mcp_error)?;

    // Skip solved and already in-progress challenges
    let in_progress_names: std::collections::HashSet<String> = orch
      .in_progress
      .iter()
      .map(|n| n.to_lowercase())
      .collect();
    let unsolved: Vec<_> = challenges
      .iter()
      .filter(|c| !c.solved_by_me && !in_progress_names.contains(&c.name.to_lowercase()))
      .collect();

    let failed_names: std::collections::HashSet<String> = orch
      .failed
      .iter()
      .map(|f| f.name.to_lowercase())
      .collect();

    // Score each challenge
    let mut scored: Vec<state::QueuedChallenge> = unsolved
      .iter()
      .map(|c| {
        let cat = c.category.to_lowercase();
        let category_score: i32 = match cat.as_str() {
          "crypto" | "cryptography" => 10,
          "forensics" | "forensic" => 10,
          "web" | "web exploitation" => 8,
          "rev" | "reverse" | "reverse engineering" | "reversing" => 6,
          "misc" | "miscellaneous" | "trivia" => 4,
          "pwn" | "binary exploitation" | "exploitation" | "pwnable" => 2,
          _ => 4, // default to misc-level
        };

        let difficulty_bonus: i32 = if c.solves > 50 {
          20
        } else if c.solves >= 20 {
          10
        } else {
          0
        };

        let solve_bonus: i32 = if c.solves > 0 && (c.value as f64 / c.solves as f64) < 10.0 {
          5
        } else {
          0
        };

        let mut priority = category_score + difficulty_bonus + solve_bonus;

        // Deprioritize previously failed challenges
        if failed_names.contains(&c.name.to_lowercase()) {
          priority -= 10;
        }

        state::QueuedChallenge {
          name: c.name.clone(),
          category: c.category.clone(),
          priority,
          points: c.value,
        }
      })
      .collect();

    // Sort by priority descending, then by points descending as tiebreaker
    scored.sort_by(|a, b| b.priority.cmp(&a.priority).then(b.points.cmp(&a.points)));

    // Apply limit if specified
    if let Some(limit) = params.limit {
      scored.truncate(limit);
    }

    let queue_len = scored.len();

    // Save to orchestration state
    let mut orch = state::load_orchestration(&self.workspace_root).map_err(to_mcp_error)?;
    orch.queue = scored;
    orch.updated_at = Some(chrono::Utc::now());
    state::update_orchestration(&self.workspace_root, orch).map_err(to_mcp_error)?;

    // Return the queue as JSON
    let updated = state::load_orchestration(&self.workspace_root).map_err(to_mcp_error)?;
    let json = serde_json::to_string_pretty(&updated).map_err(to_mcp_error)?;

    Ok(CallToolResult::success(vec![Content::text(format!(
      "Auto-queued {queue_len} unsolved challenges by priority.\n\n{json}"
    ))]))
  }

  #[tool(
    description = "Generate ready-to-use subagent prompts for solving challenges. Takes from the top of the queue (or a specific challenge). Returns structured JSON with: challenge info, recommended model, full prompt text, and tool suggestions. Use this to launch subagents via the Task tool."
  )]
  async fn ctf_generate_solve_prompt(
    &self,
    Parameters(params): Parameters<SolvePromptParams>,
  ) -> Result<CallToolResult, McpError> {
    let ws_state = state::load_state(&self.workspace_root).map_err(to_mcp_error)?;
    let mut orch = state::load_orchestration(&self.workspace_root).map_err(to_mcp_error)?;

    // Determine which challenges to generate prompts for
    let targets: Vec<state::QueuedChallenge> = if let Some(ref name) = params.challenge {
      // Specific challenge requested
      let name_lower = name.to_lowercase();
      let found = orch.queue.iter().find(|q| q.name.to_lowercase() == name_lower);
      if let Some(q) = found {
        vec![q.clone()]
      } else {
        // Not in queue — check if it exists in state at all
        if ws_state.challenges.contains_key(&name_lower) {
          return Err(McpError::invalid_params(
            format!("Challenge '{}' exists but is not in the queue. Run ctf_auto_queue first, or it may already be solved.", name),
            None,
          ));
        }
        return Err(McpError::invalid_params(
          format!("Challenge '{}' not found. Run ctf_sync and ctf_auto_queue first.", name),
          None,
        ));
      }
    } else {
      let count = params.count.unwrap_or(1);
      orch.queue.iter().take(count).cloned().collect()
    };

    if targets.is_empty() {
      return Ok(CallToolResult::success(vec![Content::text(
        "Queue is empty. Run ctf_auto_queue to populate it.",
      )]));
    }

    // Auto-mark selected challenges as in_progress
    let target_names: Vec<String> = targets.iter().map(|t| t.name.clone()).collect();
    for name in &target_names {
      orch.queue.retain(|q| q.name != *name);
      if !orch.in_progress.contains(name) {
        orch.in_progress.push(name.clone());
      }
    }
    orch.updated_at = Some(chrono::Utc::now());
    state::update_orchestration(&self.workspace_root, orch.clone()).map_err(to_mcp_error)?;

    // Generate prompts
    let mut prompts = Vec::new();
    for target in &targets {
      let cached = ws_state.challenges.get(&target.name.to_lowercase());
      let description = cached
        .and_then(|c| c.description.as_deref())
        .unwrap_or("(no description cached — run ctf_sync with full=true)");
      let files: Vec<String> = cached
        .and_then(|c| c.files.as_ref())
        .map(|f| f.iter().map(|ff| ff.name.clone()).collect())
        .unwrap_or_default();
      let hints: Vec<String> = cached
        .and_then(|c| c.hints.as_ref())
        .map(|h| {
          h.iter()
            .filter_map(|hh| hh.content.clone())
            .collect()
        })
        .unwrap_or_default();

      // Determine recommended model based on category, difficulty, and retry status
      let cat_lower = target.category.to_lowercase();
      let is_retry = orch.failed.iter().any(|f| f.name.to_lowercase() == target.name.to_lowercase());

      let recommended_model = if is_retry || target.points > 300 {
        // Retries and hard challenges need deep reasoning
        "opus"
      } else if matches!(cat_lower.as_str(),
        "crypto" | "cryptography" | "pwn" | "binary exploitation" | "exploitation" | "pwnable"
      ) {
        // Crypto (math reasoning) and pwn (exploit chains) benefit from opus
        if target.priority >= 25 {
          // Easy crypto/pwn (high priority = high solves) can use sonnet
          "sonnet"
        } else {
          "opus"
        }
      } else if target.priority >= 30 {
        // Very easy challenges (high solves + good category) — haiku is sufficient
        "haiku"
      } else {
        // Default: sonnet for web, forensics, rev, misc first attempts
        "sonnet"
      };

      // Category-specific tool suggestions
      let tool_hints = match cat_lower.as_str() {
        "crypto" | "cryptography" => "\
Use crypto_identify to detect encoding/cipher type, then:\n\
- Encoding/XOR: crypto_transform_chain for decode pipelines, crypto_xor_analyze for key recovery from ciphertext\n\
- RSA: crypto_rsa_toolkit (auto-tries factordb, fermat, wiener, small-e)\n\
- Constraints/math: crypto_math_solve (z3 for integer constraints, eval for sympy)\n\
- Advanced (finite fields, lattice, DLP): crypto_sage_solve with a SageMath script\n\
- Classical ciphers: crypto_frequency_analysis + crypto_transform_chain with rot/vigenere/atbash\n\
Start with crypto_identify. If data looks like hex/base64, try crypto_transform_chain. If XOR, use crypto_xor_analyze.",
        "forensics" | "forensic" => "\
Use forensics_file_triage first (file type, metadata, embedded data, entropy), then:\n\
- Steganography: forensics_stego_analyze (tries all tools per file type)\n\
- Embedded files: forensics_extract_embedded (binwalk + foremost)\n\
- Images: forensics_image_analysis (channels, LSB, histogram anomalies)\n\
- Encrypted/compressed regions: forensics_entropy_analysis\n\
- Memory dumps (.raw, .vmem, .dmp): forensics_volatility with plugins (windows.pslist, windows.filescan, windows.hashdump, windows.cmdline)",
        "web" | "web exploitation" => "Use curl, sqlmap, ffuf from bash. Check source code, headers, cookies, robots.txt. Common patterns: SQL injection, XSS, SSRF, path traversal, deserialization.",
        "rev" | "reverse" | "reverse engineering" | "reversing" => "\
Start with rev_functions for an overview, then rev_decompile for pseudocode of key functions.\n\
- Call graph: rev_xrefs to trace who calls what\n\
- Interesting strings: rev_strings_xrefs to find functions referencing flag/password/key\n\
- Control flow: rev_cfg for branch conditions and basic blocks\n\
- Binary diff: rev_diff for patched vs original\n\
- Runtime validation: gdb_break_inspect to confirm static analysis\n\
- Automated solving: pwn_angr_analyze in auto/find_string mode for simple checks",
        "pwn" | "binary exploitation" | "exploitation" | "pwnable" => "\
Use pwn_triage first (checksec, imports, dangerous functions, architecture), then:\n\
- Buffer overflow: gdb_trace_input (cyclic pattern + crash), pwn_pattern_offset\n\
- Format string: pwn_format_string to find offset and generate write payloads\n\
- ROP: pwn_rop_gadgets for gadgets, pwn_pwntools_template for exploit skeleton\n\
- Libc attacks: pwn_one_gadget on libc for single-gadget RCE, pwn_libc_lookup to identify libc from leaks\n\
- Shellcode: pwn_shellcode_generate for payload generation\n\
- Dynamic analysis: gdb_break_inspect, gdb_memory_dump, gdb_checksec_runtime\n\
- Auto-solve: pwn_angr_analyze for simple challenges",
        _ => "\
Use forensics_file_triage on any downloaded files to determine content type, then:\n\
- Binary files: pwn_triage or rev_functions\n\
- Images/media: forensics_stego_analyze\n\
- Encoded text: crypto_identify + crypto_transform_chain\n\
- Memory dumps: forensics_volatility",
      };

      let files_str = if files.is_empty() {
        "None attached".to_string()
      } else {
        files.join(", ")
      };

      let hints_str = if hints.is_empty() {
        String::new()
      } else {
        format!("\n   Hints: {}", hints.join("; "))
      };

      // Compute the challenge directory path
      let cat_dir = scaffold::sanitize_filename(&target.category.to_lowercase());
      let name_dir = scaffold::sanitize_filename(&target.name.to_lowercase()
        .chars()
        .map(|c| if c == ' ' { '-' } else { c })
        .collect::<String>());
      let challenge_dir = format!("{}/{}/{}", self.workspace_root.display(), cat_dir, name_dir);

      let retry_section = if is_retry {
        format!(
          "\nRETRY: This challenge was attempted before and failed. Check:\n\
           - {challenge_dir}/solve.py — may contain partial work from previous attempt\n\
           - {challenge_dir}/notes.md — may have observations\n\
           Build on existing work rather than starting over.\n"
        )
      } else {
        String::new()
      };

      let prompt = format!(
        "Solve CTF challenge '{name}' (category: {cat}, {pts} pts).\n\
         Description: {desc}\n\
         Files: {files}{hints}\n\
         Workspace: {workspace_root}\n\
         Challenge directory: {challenge_dir}\n\
         Downloaded files will be in: {challenge_dir}/dist/\n\
         {retry}\
         \n\
         Tool suggestions: {tool_hints}\n\
         \n\
         Steps:\n\
         1. Download files with ctf_download_files('{name}')\n\
         2. Check {challenge_dir}/dist/ for downloaded files\n\
         3. Read {challenge_dir}/solve.py — it has a category-appropriate template \
            (or prior work from a failed attempt). Build on what's there.\n\
         4. Triage with the appropriate tool for {cat} challenges\n\
         5. As you work, EDIT solve.py incrementally:\n\
            - Add imports you need\n\
            - Add working code as you discover the solution\n\
            - Keep the script runnable — it should reproduce the solve\n\
            - Don't rewrite from scratch; append/edit sections\n\
         6. For quick analysis, MCP tools are fine (crypto_identify, forensics_file_triage, etc.)\n\
            But any multi-step decode pipeline, exploit, or solution logic should go into solve.py.\n\
         7. AUTO-SUBMIT: As soon as you find ANYTHING matching a flag format \
            (e.g. flag{{...}}, CTF{{...}}), immediately call \
            ctf_submit_flag('{name}', '<the_flag>') — do NOT wait or ask.\n\
         8. If correct, continue to step 9. If incorrect, continue analysis.\n\
         9. After a correct flag, call ctf_save_writeup('{name}', \
            methodology='<how you solved it>', tools_used=['<tools>'])\n\
         10. Mark complete: ctf_queue_update(action='complete', challenge='{name}')\n\
         11. Report back: solved/unsolved/needs-help\n\
         \n\
         If you cannot solve it after thorough analysis, call \
         ctf_queue_update(action='fail', challenge='{name}', notes='<what you tried>') \
         and report needs-help.",
        name = target.name,
        cat = target.category,
        pts = target.points,
        desc = description,
        files = files_str,
        hints = hints_str,
        retry = retry_section,
        workspace_root = self.workspace_root.display(),
        challenge_dir = challenge_dir,
        tool_hints = tool_hints,
      );

      prompts.push(serde_json::json!({
        "challenge": target.name,
        "category": target.category,
        "points": target.points,
        "priority": target.priority,
        "recommended_model": recommended_model,
        "subagent_type": "general-purpose",
        "is_retry": is_retry,
        "prompt": prompt,
      }));
    }

    let result = serde_json::json!({
      "count": prompts.len(),
      "prompts": prompts,
      "usage": "For each prompt, launch a subagent: Task(description='Solve <name>', prompt=prompt, model=recommended_model, subagent_type='general-purpose'). Launch multiple in parallel for maximum throughput.",
    });

    let json = serde_json::to_string_pretty(&result).map_err(to_mcp_error)?;
    Ok(CallToolResult::success(vec![Content::text(json)]))
  }

  #[tool(
    description = "Save a writeup for a solved challenge — records methodology and tools used, generates writeup.md in the challenge directory. Call this AFTER successfully submitting a flag."
  )]
  async fn ctf_save_writeup(
    &self,
    Parameters(params): Parameters<WriteupParams>,
  ) -> Result<CallToolResult, McpError> {
    let challenge_name = params.challenge.trim();
    if challenge_name.is_empty() {
      return Err(McpError::invalid_params(
        "Challenge name cannot be empty",
        None,
      ));
    }

    state::save_writeup(
      &self.workspace_root,
      challenge_name,
      &params.methodology,
      &params.tools_used,
    )
    .map_err(to_mcp_error)?;

    let ws_state = state::load_state(&self.workspace_root).map_err(to_mcp_error)?;
    let key = challenge_name.to_lowercase();
    let challenge_state = ws_state.challenges.get(&key).ok_or_else(|| {
      McpError::invalid_params(
        format!(
          "Challenge '{}' not found in state. Submit the flag first.",
          challenge_name
        ),
        None,
      )
    })?;

    let writeup_content = scaffold::generate_writeup(challenge_state);

    let pseudo_challenge = crate::platform::types::Challenge {
      id: challenge_state.id.clone(),
      name: challenge_state.name.clone(),
      category: challenge_state.category.clone(),
      description: String::new(),
      value: challenge_state.points.unwrap_or(0),
      solves: 0,
      solved_by_me: true,
      files: vec![],
      tags: vec![],
      hints: vec![],
    };
    let challenge_dir = scaffold::challenge_dir(
      &self.workspace_root,
      &pseudo_challenge,
      &self.workspace_config.scaffold,
    );

    if challenge_dir.exists() {
      scaffold::save_writeup_file(&challenge_dir, &writeup_content).map_err(to_mcp_error)?;
    }

    Ok(CallToolResult::success(vec![Content::text(format!(
      "Writeup saved for '{}' at {}/writeup.md",
      challenge_name,
      challenge_dir.display(),
    ))]))
  }
}

#[tool_handler]
impl ServerHandler for McpServer {
  fn get_info(&self) -> ServerInfo {
    ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
      .with_instructions(
        "CTF competition assistant with two modes of operation:\n\n\
         \
         ORCHESTRATOR MODE (main agent coordinating a CTF):\n\
         1. ctf_sync(full=true) — fetch all challenges, descriptions, files, unlock free hints\n\
         2. ctf_auto_queue() — auto-score and prioritize all unsolved challenges\n\
         3. ctf_generate_solve_prompt(count=N) — get ready-to-use subagent prompts (auto-marks as in_progress)\n\
         4. Launch subagents via Task tool using the returned prompts and recommended models\n\
         5. After subagents complete: check ctf_challenges(unsolved=true) for remaining work\n\
         6. For failures: ctf_queue_update(action='fail', challenge='...', notes='...')\n\
         7. To prioritize a specific challenge: ctf_queue_update(action='prioritize', challenge='...')\n\
         8. Loop back to step 1\n\n\
         \
         SOLVER MODE (subagent solving a specific challenge):\n\
         - Download files with ctf_download_files, triage with category tools, analyze and solve\n\
         - AUTO-SUBMIT flags immediately: call ctf_submit_flag as soon as you find any flag-like \
         string (flag{...}, CTF{...}). Do not wait or ask. The tool returns correct/incorrect.\n\
         - After correct submission: call ctf_save_writeup to document methodology\n\
         - After solving or giving up: call ctf_queue_update(action='complete'|'fail', challenge='...')\n\n\
         \
         Key tools: ctf_workspace_status (overview), ctf_challenges (browse), \
         ctf_sync (fetch from platform), ctf_auto_queue (score/prioritize), \
         ctf_generate_solve_prompt (create subagent prompts), ctf_queue_update (manage queue state)"
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

#[cfg(test)]
mod tests {
  use super::*;
  use crate::config::types::{PlatformConfig, ScaffoldConfig, WorkspaceConfig, WorkspaceSection};
  use crate::platform::mock::MockPlatform;
  use tempfile::TempDir;

  fn make_server() -> (McpServer, TempDir) {
    let dir = TempDir::new().unwrap();
    let platform = Arc::new(MockPlatform::new());
    let config = WorkspaceConfig {
      platform: PlatformConfig {
        platform_type: Some("ctfd".into()),
        url: "https://ctf.example.com".into(),
        token: None,
      },
      workspace: WorkspaceSection {
        name: "test-ctf".into(),
      },
      scaffold: ScaffoldConfig::default(),
    };
    let server = McpServer::new(platform, dir.path().to_path_buf(), config);
    (server, dir)
  }

  // ── ctf_submit_flag validation tests ─────────────────────────────────────

  #[tokio::test]
  async fn submit_flag_empty_flag_returns_error() {
    let (server, _dir) = make_server();
    let params = Parameters(SubmitFlagParams {
      flag: "   ".into(),
      challenge: "Easy RSA".into(),
    });
    let result = server.ctf_submit_flag(params).await;
    assert!(result.is_err());
  }

  #[tokio::test]
  async fn submit_flag_empty_challenge_returns_error() {
    let (server, _dir) = make_server();
    let params = Parameters(SubmitFlagParams {
      flag: "flag{test}".into(),
      challenge: "   ".into(),
    });
    let result = server.ctf_submit_flag(params).await;
    assert!(result.is_err());
  }

  // ── ctf_queue_update validation tests ────────────────────────────────────

  #[tokio::test]
  async fn queue_update_start_without_challenge_returns_error() {
    let (server, _dir) = make_server();
    let params = Parameters(QueueUpdateParams {
      action: "start".into(),
      challenge: None,
      category: None,
      notes: None,
      queue_json: None,
    });
    let result = server.ctf_queue_update(params).await;
    assert!(result.is_err());
  }

  #[tokio::test]
  async fn queue_update_complete_without_challenge_returns_error() {
    let (server, _dir) = make_server();
    let params = Parameters(QueueUpdateParams {
      action: "complete".into(),
      challenge: None,
      category: None,
      notes: None,
      queue_json: None,
    });
    let result = server.ctf_queue_update(params).await;
    assert!(result.is_err());
  }

  #[tokio::test]
  async fn queue_update_unknown_action_returns_error() {
    let (server, _dir) = make_server();
    let params = Parameters(QueueUpdateParams {
      action: "invalid_action".into(),
      challenge: None,
      category: None,
      notes: None,
      queue_json: None,
    });
    let result = server.ctf_queue_update(params).await;
    assert!(result.is_err());
  }

  // ── ctf_save_writeup validation tests ────────────────────────────────────

  #[tokio::test]
  async fn save_writeup_empty_name_returns_error() {
    let (server, _dir) = make_server();
    let params = Parameters(WriteupParams {
      challenge: "   ".into(),
      methodology: "some method".into(),
      tools_used: vec!["tool1".into()],
    });
    let result = server.ctf_save_writeup(params).await;
    assert!(result.is_err());
  }

  // ── ctf_unlock_hint validation tests ─────────────────────────────────────

  #[tokio::test]
  async fn unlock_hint_empty_id_returns_error() {
    let (server, _dir) = make_server();
    let params = Parameters(UnlockHintParams {
      hint_id: "   ".into(),
    });
    let result = server.ctf_unlock_hint(params).await;
    assert!(result.is_err());
  }
}
