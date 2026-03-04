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
        async move { platform.challenge(&id).await }
      }))
      .buffer_unordered(5) // Limit concurrent API requests
      .filter_map(|r| async { r.ok() })
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
    description = "Update the challenge queue — set priorities, mark challenges as in-progress or failed. Persists across agent restarts."
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
      "clear" => {
        orch = state::OrchestrationState::default();
      }
      other => {
        return Err(McpError::invalid_params(
          format!("Unknown action: {other}. Use set_queue, start, complete, fail, or clear."),
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

    // Filter to unsolved only
    let unsolved: Vec<_> = challenges.iter().filter(|c| !c.solved_by_me).collect();

    // Also check what's already failed to deprioritize
    let orch = state::load_orchestration(&self.workspace_root).map_err(to_mcp_error)?;
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
    let orch = state::load_orchestration(&self.workspace_root).map_err(to_mcp_error)?;

    // Determine which challenges to generate prompts for
    let targets: Vec<&state::QueuedChallenge> = if let Some(ref name) = params.challenge {
      // Specific challenge requested
      let name_lower = name.to_lowercase();
      let found = orch.queue.iter().find(|q| q.name.to_lowercase() == name_lower);
      if let Some(q) = found {
        vec![q]
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
      orch.queue.iter().take(count).collect()
    };

    if targets.is_empty() {
      return Ok(CallToolResult::success(vec![Content::text(
        "Queue is empty. Run ctf_auto_queue to populate it.",
      )]));
    }

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

      // Determine recommended model
      let cat_lower = target.category.to_lowercase();
      let is_retry = orch.failed.iter().any(|f| f.name.to_lowercase() == target.name.to_lowercase());
      let recommended_model = if is_retry || target.points > 300 {
        "opus"
      } else {
        "sonnet"
      };

      // Category-specific tool suggestions
      let tool_hints = match cat_lower.as_str() {
        "crypto" | "cryptography" => "Use crypto_identify, transform_chain, rsa_toolkit, math_solve. Start with crypto_identify to detect encoding/cipher type.",
        "forensics" | "forensic" => "Use file_triage, stego_analyze, extract_embedded, entropy_analysis. Start with file_triage.",
        "web" | "web exploitation" => "Use curl, sqlmap, ffuf from bash. Check source code, headers, cookies, robots.txt.",
        "rev" | "reverse" | "reverse engineering" | "reversing" => "Use r2_functions, r2_decompile, r2_xrefs, r2_strings_xrefs. Start with r2_functions for an overview, then decompile key functions.",
        "pwn" | "binary exploitation" | "exploitation" | "pwnable" => "Use binary_triage first, then gdb_break_inspect, gdb_trace_input, angr_analyze. Check for buffer overflows, format strings, use-after-free.",
        _ => "Use file_triage on any downloaded files, then choose tools based on content type.",
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

      let prompt = format!(
        "Solve CTF challenge '{name}' (category: {cat}, {pts} pts).\n\
         Description: {desc}\n\
         Files: {files}{hints}\n\
         Workspace: {workspace_root}\n\
         \n\
         Tool suggestions: {tool_hints}\n\
         \n\
         Steps:\n\
         1. Download files with ctf_download_files('{name}')\n\
         2. Triage with the appropriate tool for {cat} challenges\n\
         3. Analyze and solve using the MCP tools available\n\
         4. AUTO-SUBMIT: As soon as you find ANYTHING matching a flag format \
            (e.g. flag{{...}}, CTF{{...}}), immediately call \
            ctf_submit_flag('{name}', '<the_flag>') — do NOT wait or ask.\n\
         5. If correct, report solved. If incorrect, continue analysis.\n\
         6. After a correct flag, call ctf_save_writeup('{name}', \
            methodology='<how you solved it>', tools_used=['<tools>'])\n\
         7. Report back: solved/unsolved/needs-help",
        name = target.name,
        cat = target.category,
        pts = target.points,
        desc = description,
        files = files_str,
        hints = hints_str,
        workspace_root = self.workspace_root.display(),
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
        "CTF competition assistant. Use these tools to interact with a CTF platform: \
         list challenges, read descriptions and hints for context, submit flags, \
         track progress, and download challenge files. Start with ctf_workspace_status \
         to understand the current state, then use ctf_challenges to browse. \
         Use ctf_sync with full=true to cache all challenge descriptions for context. \
         IMPORTANT: Always auto-submit flags immediately when found — call \
         ctf_submit_flag as soon as you find any flag-like string (e.g. flag{...}, \
         CTF{...}). Do not wait or ask for confirmation. The tool returns whether \
         the flag was correct, so there is no risk in submitting. \
         After a correct submission, call ctf_save_writeup to document how \
         you solved the challenge."
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
