use colored::Colorize;

use crate::cli::OutputFormat;
use crate::error::Result;
use crate::output;
use crate::platform::types::Challenge;
use crate::platform::Platform;

pub async fn handle_list(
  platform: &dyn Platform,
  category: Option<&str>,
  unsolved: bool,
  solved: bool,
  format: &OutputFormat,
) -> Result<()> {
  let mut challenges = platform.challenges().await?;

  if let Some(cat) = category {
    let cat_lower = cat.to_lowercase();
    challenges.retain(|c| c.category.to_lowercase() == cat_lower);
  }

  if unsolved {
    challenges.retain(|c| !c.solved_by_me);
  }

  if solved {
    challenges.retain(|c| c.solved_by_me);
  }

  // Sort by category, then name
  challenges.sort_by(|a, b| a.category.cmp(&b.category).then(a.name.cmp(&b.name)));

  match format {
    OutputFormat::Json => {
      println!("{}", serde_json::to_string_pretty(&challenges)?);
    }
    _ => {
      output::table::print_challenges(&challenges);
    }
  }

  Ok(())
}

pub async fn handle_show(platform: &dyn Platform, id_or_name: &str, challenges: &[Challenge]) -> Result<()> {
  let challenge = resolve_challenge(platform, id_or_name, challenges).await?;

  println!("{} {}", "Challenge:".bold(), challenge.name.bold().cyan());
  println!("{} {}", "Category: ".bold(), challenge.category);
  println!("{} {}", "Points:   ".bold(), challenge.value);
  println!("{} {}", "Solves:   ".bold(), challenge.solves);

  let status = if challenge.solved_by_me { "Solved".green().to_string() } else { "Unsolved".red().to_string() };
  println!("{} {status}", "Status:   ".bold());

  if !challenge.tags.is_empty() {
    println!("{} {}", "Tags:     ".bold(), challenge.tags.join(", "));
  }

  if !challenge.description.is_empty() {
    println!();
    println!("{}", "Description:".bold());
    println!("{}", challenge.description);
  }

  if !challenge.files.is_empty() {
    println!();
    println!("{}", "Files:".bold());
    for file in &challenge.files {
      println!("  - {}", file.name);
    }
  }

  if !challenge.hints.is_empty() {
    println!();
    println!("{}", "Hints:".bold());
    for hint in &challenge.hints {
      match &hint.content {
        Some(content) => println!("  - {content}"),
        None => println!("  - [Locked, cost: {}]", hint.cost),
      }
    }
  }

  Ok(())
}

pub async fn resolve_challenge(
  platform: &dyn Platform,
  id_or_name: &str,
  cached_challenges: &[Challenge],
) -> Result<Challenge> {
  // Try numeric ID first
  if id_or_name.parse::<u64>().is_ok() {
    return platform.challenge(id_or_name).await;
  }

  // Try exact name match
  let lower = id_or_name.to_lowercase();
  if let Some(c) = cached_challenges.iter().find(|c| c.name.to_lowercase() == lower) {
    return platform.challenge(&c.id).await;
  }

  // Try fuzzy match (substring)
  let matches: Vec<_> = cached_challenges.iter().filter(|c| c.name.to_lowercase().contains(&lower)).collect();

  match matches.len() {
    0 => Err(crate::error::Error::ChallengeNotFound(id_or_name.to_string())),
    1 => platform.challenge(&matches[0].id).await,
    _ => {
      let names: Vec<_> = matches.iter().map(|c| c.name.as_str()).collect();
      Err(crate::error::Error::ChallengeNotFound(format!(
        "Ambiguous name '{}'. Matches: {}",
        id_or_name,
        names.join(", ")
      )))
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::platform::mock::MockPlatform;

  #[tokio::test]
  async fn resolve_by_numeric_id() {
    let mock = MockPlatform::new();
    let challenges = mock.challenges.clone();
    let result = resolve_challenge(&mock, "1", &challenges).await.unwrap();
    assert_eq!(result.name, "Easy RSA");
  }

  #[tokio::test]
  async fn resolve_by_exact_name() {
    let mock = MockPlatform::new();
    let challenges = mock.challenges.clone();
    let result = resolve_challenge(&mock, "SQL Injection", &challenges).await.unwrap();
    assert_eq!(result.id, "2");
  }

  #[tokio::test]
  async fn resolve_by_exact_name_case_insensitive() {
    let mock = MockPlatform::new();
    let challenges = mock.challenges.clone();
    let result = resolve_challenge(&mock, "easy rsa", &challenges).await.unwrap();
    assert_eq!(result.id, "1");
  }

  #[tokio::test]
  async fn resolve_by_substring() {
    let mock = MockPlatform::new();
    let challenges = mock.challenges.clone();
    let result = resolve_challenge(&mock, "Buffer", &challenges).await.unwrap();
    assert_eq!(result.id, "3");
  }

  #[tokio::test]
  async fn resolve_not_found() {
    let mock = MockPlatform::new();
    let challenges = mock.challenges.clone();
    let result = resolve_challenge(&mock, "nonexistent", &challenges).await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("not found") || err.contains("Challenge"));
  }

  #[tokio::test]
  async fn resolve_ambiguous_returns_error() {
    let mock = MockPlatform::new();
    // Both "Easy RSA" and "SQL Injection" contain lowercase 'a'
    // Use a term that matches multiple challenges
    let mut challenges = mock.challenges.clone();
    challenges.push(Challenge {
      id: "4".into(),
      name: "Easy AES".into(),
      category: "crypto".into(),
      description: "".into(),
      value: 100,
      solves: 5,
      solved_by_me: false,
      files: vec![],
      tags: vec![],
      hints: vec![],
    });
    let result = resolve_challenge(&mock, "Easy", &challenges).await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("Ambiguous"));
  }
}
