use rmcp::schemars;
use serde::Deserialize;

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ChallengesParams {
  #[schemars(description = "Filter by category name (case-insensitive)")]
  pub category: Option<String>,
  #[schemars(description = "Only show unsolved challenges")]
  pub unsolved: Option<bool>,
  #[schemars(description = "Only show solved challenges")]
  pub solved: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ChallengeDetailParams {
  #[schemars(description = "Challenge ID (numeric) or name (substring match supported)")]
  pub id_or_name: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SubmitFlagParams {
  #[schemars(description = "Challenge ID or name")]
  pub challenge: String,
  #[schemars(description = "The flag string to submit")]
  pub flag: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ScoreboardParams {
  #[schemars(description = "Number of entries to return (default: 10)")]
  pub limit: Option<u32>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DownloadFilesParams {
  #[schemars(description = "Challenge ID or name")]
  pub challenge: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct UnlockHintParams {
  #[schemars(description = "The hint ID to unlock")]
  pub hint_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SyncParams {
  #[schemars(
    description = "If true, fetch full details (descriptions, hints, files) for every challenge. Slower but provides complete context."
  )]
  pub full: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct QueueUpdateParams {
  #[schemars(
    description = "Action: 'set_queue' (replace queue), 'start' (mark in-progress), 'complete' (remove from in-progress), 'fail' (record failure), 'prioritize' (move to front of queue / rescue from failed), 'retry' (move failed challenge back to queue), 'clear' (reset all)"
  )]
  pub action: String,
  #[schemars(description = "Challenge name (for start/complete/fail actions)")]
  pub challenge: Option<String>,
  #[schemars(description = "Challenge category (for fail action)")]
  pub category: Option<String>,
  #[schemars(description = "Failure notes (for fail action)")]
  pub notes: Option<String>,
  #[schemars(
    description = "Full queue replacement as JSON array of {name, category, priority, points} objects (for set_queue action)"
  )]
  pub queue_json: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct AutoQueueParams {
  #[schemars(
    description = "Override the default parallel capacity (how many challenges to include). Defaults to all unsolved challenges, sorted by priority."
  )]
  pub limit: Option<usize>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SolvePromptParams {
  #[schemars(
    description = "Number of challenges to generate prompts for (takes from top of queue). Defaults to 1."
  )]
  pub count: Option<usize>,
  #[schemars(
    description = "Specific challenge name to generate a prompt for (ignores queue order)"
  )]
  pub challenge: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct WriteupParams {
  #[schemars(description = "Challenge name (must already exist in state — submit the flag first)")]
  pub challenge: String,
  #[schemars(
    description = "How the challenge was solved — approach, key insights, steps taken"
  )]
  pub methodology: String,
  #[schemars(
    description = "List of tools/techniques used (e.g., [\"rsa_toolkit\", \"transform_chain\", \"python\"])"
  )]
  pub tools_used: Vec<String>,
}
