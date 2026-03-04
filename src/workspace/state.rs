use std::collections::HashMap;
use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::platform::types::Challenge;

const STATE_FILE: &str = ".ctf-state.json";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WorkspaceState {
  #[serde(default)]
  pub last_sync: Option<DateTime<Utc>>,
  #[serde(default)]
  pub challenges: HashMap<String, ChallengeState>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeState {
  pub id: String,
  pub name: String,
  pub category: String,
  pub status: ChallengeStatus,
  pub solved_at: Option<DateTime<Utc>>,
  pub points: Option<u32>,
  pub flag: Option<String>,
  // Cached detail fields (populated by sync --full)
  #[serde(default)]
  pub description: Option<String>,
  #[serde(default)]
  pub hints: Option<Vec<CachedHint>>,
  #[serde(default)]
  pub files: Option<Vec<CachedFile>>,
  #[serde(default)]
  pub tags: Option<Vec<String>>,
  #[serde(default)]
  pub details_fetched_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CachedHint {
  pub id: String,
  pub content: Option<String>,
  pub cost: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CachedFile {
  pub name: String,
  pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
  Unsolved,
  InProgress,
  Solved,
}

pub fn init_state(workspace_root: &Path) -> Result<()> {
  let state = WorkspaceState::default();
  write_state(workspace_root, &state)
}

pub fn load_state(workspace_root: &Path) -> Result<WorkspaceState> {
  let path = workspace_root.join(STATE_FILE);
  if !path.exists() {
    return Ok(WorkspaceState::default());
  }
  let content = std::fs::read_to_string(&path)?;
  let state: WorkspaceState = serde_json::from_str(&content)?;
  Ok(state)
}

fn write_state(workspace_root: &Path, state: &WorkspaceState) -> Result<()> {
  let path = workspace_root.join(STATE_FILE);
  let content = serde_json::to_string_pretty(state)?;
  std::fs::write(path, content)?;
  Ok(())
}

pub fn update_sync(workspace_root: &Path, challenges: &[Challenge]) -> Result<()> {
  let mut state = load_state(workspace_root)?;
  state.last_sync = Some(Utc::now());

  for c in challenges {
    let entry = state
      .challenges
      .entry(c.name.to_lowercase())
      .or_insert_with(|| ChallengeState {
        id: c.id.clone(),
        name: c.name.clone(),
        category: c.category.clone(),
        status: ChallengeStatus::Unsolved,
        solved_at: None,
        points: None,
        flag: None,
        description: None,
        hints: None,
        files: None,
        tags: None,
        details_fetched_at: None,
      });

    entry.id = c.id.clone();
    entry.name = c.name.clone();
    entry.category = c.category.clone();

    if c.solved_by_me && entry.status != ChallengeStatus::Solved {
      entry.status = ChallengeStatus::Solved;
      entry.points = Some(c.value);
    }
  }

  write_state(workspace_root, &state)
}

/// Update state with full challenge details (descriptions, hints, files).
pub fn update_sync_full(workspace_root: &Path, challenges: &[Challenge]) -> Result<()> {
  let mut state = load_state(workspace_root)?;
  state.last_sync = Some(Utc::now());
  let now = Utc::now();

  for c in challenges {
    let entry = state
      .challenges
      .entry(c.name.to_lowercase())
      .or_insert_with(|| ChallengeState {
        id: c.id.clone(),
        name: c.name.clone(),
        category: c.category.clone(),
        status: ChallengeStatus::Unsolved,
        solved_at: None,
        points: None,
        flag: None,
        description: None,
        hints: None,
        files: None,
        tags: None,
        details_fetched_at: None,
      });

    entry.id = c.id.clone();
    entry.name = c.name.clone();
    entry.category = c.category.clone();

    if c.solved_by_me && entry.status != ChallengeStatus::Solved {
      entry.status = ChallengeStatus::Solved;
      entry.points = Some(c.value);
    }

    // Cache full details
    if !c.description.is_empty() {
      entry.description = Some(c.description.clone());
    }
    if !c.hints.is_empty() {
      entry.hints = Some(
        c.hints
          .iter()
          .map(|h| CachedHint {
            id: h.id.clone(),
            content: h.content.clone(),
            cost: h.cost,
          })
          .collect(),
      );
    }
    if !c.files.is_empty() {
      entry.files = Some(
        c.files
          .iter()
          .map(|f| CachedFile {
            name: f.name.clone(),
            url: f.url.clone(),
          })
          .collect(),
      );
    }
    if !c.tags.is_empty() {
      entry.tags = Some(c.tags.clone());
    }
    entry.details_fetched_at = Some(now);
  }

  write_state(workspace_root, &state)
}

/// Merge cached descriptions/hints into a challenge list from the platform.
pub fn merge_cached_details(challenges: &mut [Challenge], state: &WorkspaceState) {
  for c in challenges.iter_mut() {
    if let Some(cached) = state.challenges.get(&c.name.to_lowercase()) {
      if c.description.is_empty() {
        if let Some(desc) = &cached.description {
          c.description = desc.clone();
        }
      }
      if c.hints.is_empty() {
        if let Some(hints) = &cached.hints {
          c.hints = hints
            .iter()
            .map(|h| crate::platform::types::Hint {
              id: h.id.clone(),
              content: h.content.clone(),
              cost: h.cost,
            })
            .collect();
        }
      }
      if c.files.is_empty() {
        if let Some(files) = &cached.files {
          c.files = files
            .iter()
            .map(|f| crate::platform::types::ChallengeFile {
              name: f.name.clone(),
              url: f.url.clone(),
            })
            .collect();
        }
      }
      if c.tags.is_empty() {
        if let Some(tags) = &cached.tags {
          c.tags = tags.clone();
        }
      }
    }
  }
}

pub fn mark_solved(
  workspace_root: &Path,
  challenge_id: &str,
  challenge_name: &str,
  points: u32,
  flag: &str,
) -> Result<()> {
  let mut state = load_state(workspace_root)?;

  let key = challenge_name.to_lowercase();
  let entry = state.challenges.entry(key).or_insert_with(|| ChallengeState {
    id: challenge_id.to_string(),
    name: challenge_name.to_string(),
    category: String::new(),
    status: ChallengeStatus::Unsolved,
    solved_at: None,
    points: None,
    flag: None,
    description: None,
    hints: None,
    files: None,
    tags: None,
    details_fetched_at: None,
  });

  entry.status = ChallengeStatus::Solved;
  entry.solved_at = Some(Utc::now());
  entry.points = Some(points);
  entry.flag = Some(flag.to_string());

  write_state(workspace_root, &state)
}

#[cfg(test)]
mod tests {
  use super::*;
  use tempfile::TempDir;

  fn make_challenge(id: &str, name: &str, category: &str) -> Challenge {
    Challenge {
      id: id.into(),
      name: name.into(),
      category: category.into(),
      description: String::new(),
      value: 100,
      solves: 5,
      solved_by_me: false,
      files: vec![],
      tags: vec![],
      hints: vec![],
    }
  }

  #[test]
  fn init_creates_default_state() {
    let dir = TempDir::new().unwrap();
    init_state(dir.path()).unwrap();
    let state = load_state(dir.path()).unwrap();
    assert!(state.last_sync.is_none());
    assert!(state.challenges.is_empty());
  }

  #[test]
  fn load_nonexistent_returns_default() {
    let dir = TempDir::new().unwrap();
    let state = load_state(dir.path()).unwrap();
    assert!(state.challenges.is_empty());
  }

  #[test]
  fn update_sync_adds_new_challenges() {
    let dir = TempDir::new().unwrap();
    init_state(dir.path()).unwrap();

    let challenges = vec![
      make_challenge("1", "Test A", "crypto"),
      make_challenge("2", "Test B", "web"),
    ];
    update_sync(dir.path(), &challenges).unwrap();

    let state = load_state(dir.path()).unwrap();
    assert_eq!(state.challenges.len(), 2);
    assert!(state.last_sync.is_some());
    assert_eq!(state.challenges["test a"].name, "Test A");
    assert_eq!(state.challenges["test b"].category, "web");
  }

  #[test]
  fn update_sync_preserves_solved_status() {
    let dir = TempDir::new().unwrap();
    init_state(dir.path()).unwrap();

    mark_solved(dir.path(), "1", "Test A", 100, "flag{test}").unwrap();

    let challenges = vec![make_challenge("1", "Test A", "crypto")];
    update_sync(dir.path(), &challenges).unwrap();

    let state = load_state(dir.path()).unwrap();
    assert_eq!(state.challenges["test a"].status, ChallengeStatus::Solved);
    assert_eq!(state.challenges["test a"].flag.as_deref(), Some("flag{test}"));
  }

  #[test]
  fn mark_solved_updates_state() {
    let dir = TempDir::new().unwrap();
    init_state(dir.path()).unwrap();

    mark_solved(dir.path(), "42", "My Challenge", 500, "flag{win}").unwrap();

    let state = load_state(dir.path()).unwrap();
    let entry = &state.challenges["my challenge"];
    assert_eq!(entry.status, ChallengeStatus::Solved);
    assert_eq!(entry.points, Some(500));
    assert_eq!(entry.flag.as_deref(), Some("flag{win}"));
    assert!(entry.solved_at.is_some());
  }

  #[test]
  fn backward_compatible_state_loading() {
    let dir = TempDir::new().unwrap();
    // Write old-format state without new cached fields
    let old_json = r#"{
      "last_sync": "2026-01-01T00:00:00Z",
      "challenges": {
        "test": {
          "id": "1",
          "name": "test",
          "category": "crypto",
          "status": "unsolved",
          "solved_at": null,
          "points": null,
          "flag": null
        }
      }
    }"#;
    std::fs::write(dir.path().join(".ctf-state.json"), old_json).unwrap();

    let state = load_state(dir.path()).unwrap();
    assert_eq!(state.challenges["test"].description, None);
    assert_eq!(state.challenges["test"].hints, None);
    assert_eq!(state.challenges["test"].files, None);
  }

  #[test]
  fn update_sync_full_caches_details() {
    let dir = TempDir::new().unwrap();
    init_state(dir.path()).unwrap();

    let mut c = make_challenge("1", "Crypto 101", "crypto");
    c.description = "Solve this RSA problem".into();
    c.tags = vec!["easy".into()];
    c.hints = vec![crate::platform::types::Hint {
      id: "10".into(),
      content: Some("Think about factoring".into()),
      cost: 50,
    }];
    c.files = vec![crate::platform::types::ChallengeFile {
      name: "challenge.py".into(),
      url: "/files/challenge.py".into(),
    }];

    update_sync_full(dir.path(), &[c]).unwrap();

    let state = load_state(dir.path()).unwrap();
    let entry = &state.challenges["crypto 101"];
    assert_eq!(entry.description.as_deref(), Some("Solve this RSA problem"));
    assert_eq!(entry.hints.as_ref().unwrap().len(), 1);
    assert_eq!(entry.files.as_ref().unwrap().len(), 1);
    assert_eq!(entry.tags.as_ref().unwrap(), &["easy"]);
    assert!(entry.details_fetched_at.is_some());
  }

  #[test]
  fn merge_cached_details_fills_empty_fields() {
    let mut state = WorkspaceState::default();
    state.challenges.insert(
      "test".into(),
      ChallengeState {
        id: "1".into(),
        name: "test".into(),
        category: "web".into(),
        status: ChallengeStatus::Unsolved,
        solved_at: None,
        points: None,
        flag: None,
        description: Some("A web challenge".into()),
        hints: Some(vec![CachedHint {
          id: "5".into(),
          content: Some("Check headers".into()),
          cost: 0,
        }]),
        files: None,
        tags: Some(vec!["easy".into()]),
        details_fetched_at: None,
      },
    );

    let mut challenges = vec![make_challenge("1", "test", "web")];
    merge_cached_details(&mut challenges, &state);

    assert_eq!(challenges[0].description, "A web challenge");
    assert_eq!(challenges[0].hints.len(), 1);
    assert_eq!(challenges[0].tags, vec!["easy"]);
  }
}
