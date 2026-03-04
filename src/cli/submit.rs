use std::path::Path;

use colored::Colorize;

use crate::cli::OutputFormat;
use crate::config;
use crate::error::{Error, Result};
use crate::platform::types::{Challenge, SubmitResult};
use crate::platform::Platform;
use crate::workspace::state;

pub async fn handle_submit(
  platform: &dyn Platform,
  first: &str,
  second: Option<&str>,
  challenges: &[Challenge],
  workspace_root: &Path,
  format: &OutputFormat,
) -> Result<()> {
  let (challenge_id, flag) = if let Some(flag) = second {
    // Two args: first is challenge id/name, second is flag
    let challenge = crate::cli::challenge::resolve_challenge(platform, first, challenges).await?;
    (challenge.id, flag.to_string())
  } else {
    // One arg: flag only, infer challenge from cwd
    let challenge = infer_challenge_from_cwd(challenges, workspace_root)?;
    (challenge.id.clone(), first.to_string())
  };

  let result = platform.submit(&challenge_id, &flag).await?;

  match format {
    OutputFormat::Json => {
      println!("{}", serde_json::to_string_pretty(&result)?);
    }
    _ => {
      print_submit_result(&result);
    }
  }

  // Update local state on success
  if let SubmitResult::Correct { challenge, points } = &result {
    if config::load_workspace_config(workspace_root).is_ok() {
      if let Err(e) = state::mark_solved(workspace_root, &challenge_id, challenge, *points, &flag) {
        eprintln!("Warning: failed to update local state: {e}");
      }
    }
  }

  Ok(())
}

fn infer_challenge_from_cwd<'a>(challenges: &'a [Challenge], workspace_root: &Path) -> Result<&'a Challenge> {
  let cwd = std::env::current_dir()?;
  let relative = cwd
    .strip_prefix(workspace_root)
    .map_err(|_| Error::Workspace("Current directory is not inside workspace".into()))?;

  // The last component of the relative path is the challenge name
  // e.g., crypto/andor -> "andor"
  let challenge_name = relative
    .file_name()
    .and_then(|n| n.to_str())
    .ok_or_else(|| Error::Workspace("Could not determine challenge from current directory".into()))?;

  let lower = challenge_name.to_lowercase();
  challenges
    .iter()
    .find(|c| c.name.to_lowercase() == lower)
    .or_else(|| {
      // Try matching by directory name containing the challenge name
      challenges.iter().find(|c| c.name.to_lowercase().contains(&lower) || lower.contains(&c.name.to_lowercase()))
    })
    .ok_or_else(|| {
      Error::ChallengeNotFound(format!(
        "Could not infer challenge from directory '{challenge_name}'. Specify explicitly: ctf submit <challenge> <flag>"
      ))
    })
}

fn print_submit_result(result: &SubmitResult) {
  match result {
    SubmitResult::Correct { challenge, points } => {
      println!("{} {} ({} pts)", "✓ Correct!".green().bold(), challenge.bold(), points);
    }
    SubmitResult::Incorrect => {
      println!("{}", "✗ Incorrect flag.".red().bold());
    }
    SubmitResult::AlreadySolved => {
      println!("{}", "Already solved.".yellow().bold());
    }
    SubmitResult::RateLimited { retry_after } => {
      let msg = match retry_after {
        Some(secs) => format!("Rate limited. Try again in {secs}s."),
        None => "Rate limited. Try again later.".to_string(),
      };
      println!("{}", msg.yellow().bold());
    }
  }
}
