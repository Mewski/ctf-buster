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
    description = "Action: 'set_queue' (replace queue), 'start' (mark challenge in-progress), 'complete' (remove from in-progress), 'fail' (record failure), 'clear' (reset all)"
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
