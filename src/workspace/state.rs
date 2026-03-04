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
  #[serde(default)]
  pub notifications: Vec<CachedNotification>,
  #[serde(default)]
  pub orchestration: OrchestrationState,
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
  #[serde(default)]
  pub methodology: Option<String>,
  #[serde(default)]
  pub tools_used: Option<Vec<String>>,
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
pub struct CachedNotification {
  pub id: String,
  pub title: String,
  pub content: String,
  pub date: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OrchestrationState {
  #[serde(default)]
  pub queue: Vec<QueuedChallenge>,
  #[serde(default)]
  pub in_progress: Vec<String>,
  #[serde(default)]
  pub failed: Vec<FailedAttempt>,
  #[serde(default)]
  pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct QueuedChallenge {
  pub name: String,
  pub category: String,
  pub priority: i32,
  pub points: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FailedAttempt {
  pub name: String,
  pub category: String,
  pub attempted_at: DateTime<Utc>,
  pub notes: String,
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
  // Atomic write: write to temp file then rename to prevent corruption
  let tmp_path = path.with_extension("json.tmp");
  std::fs::write(&tmp_path, &content)?;
  std::fs::rename(&tmp_path, &path)?;
  Ok(())
}

pub fn update_sync(workspace_root: &Path, challenges: &[Challenge]) -> Result<()> {
  let mut state = load_state(workspace_root)?;
  state.last_sync = Some(Utc::now());

  for c in challenges {
    let entry = state.challenges.entry(c.name.to_lowercase()).or_insert_with(|| ChallengeState {
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
      methodology: None,
      tools_used: None,
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
    let entry = state.challenges.entry(c.name.to_lowercase()).or_insert_with(|| ChallengeState {
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
      methodology: None,
      tools_used: None,
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
        c.hints.iter().map(|h| CachedHint { id: h.id.clone(), content: h.content.clone(), cost: h.cost }).collect(),
      );
    }
    if !c.files.is_empty() {
      entry.files = Some(c.files.iter().map(|f| CachedFile { name: f.name.clone(), url: f.url.clone() }).collect());
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
            .map(|h| crate::platform::types::Hint { id: h.id.clone(), content: h.content.clone(), cost: h.cost })
            .collect();
        }
      }
      if c.files.is_empty() {
        if let Some(files) = &cached.files {
          c.files = files
            .iter()
            .map(|f| crate::platform::types::ChallengeFile { name: f.name.clone(), url: f.url.clone() })
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
    methodology: None,
    tools_used: None,
  });

  entry.status = ChallengeStatus::Solved;
  entry.solved_at = Some(Utc::now());
  entry.points = Some(points);
  entry.flag = Some(flag.to_string());

  write_state(workspace_root, &state)
}

pub fn update_notifications(
  workspace_root: &Path,
  notifications: &[crate::platform::types::Notification],
) -> Result<()> {
  let mut state = load_state(workspace_root)?;
  state.notifications = notifications
    .iter()
    .map(|n| CachedNotification {
      id: n.id.clone(),
      title: n.title.clone(),
      content: n.content.clone(),
      date: n.date.clone(),
    })
    .collect();
  write_state(workspace_root, &state)
}

pub fn load_orchestration(workspace_root: &Path) -> Result<OrchestrationState> {
  let state = load_state(workspace_root)?;
  Ok(state.orchestration)
}

pub fn update_orchestration(workspace_root: &Path, orchestration: OrchestrationState) -> Result<()> {
  let mut state = load_state(workspace_root)?;
  state.orchestration = orchestration;
  write_state(workspace_root, &state)
}

pub fn save_writeup(
  workspace_root: &Path,
  challenge_name: &str,
  methodology: &str,
  tools_used: &[String],
) -> Result<()> {
  let mut state = load_state(workspace_root)?;
  let key = challenge_name.to_lowercase();

  if let Some(entry) = state.challenges.get_mut(&key) {
    entry.methodology = Some(methodology.to_string());
    entry.tools_used = Some(tools_used.to_vec());
    write_state(workspace_root, &state)?;
  }

  Ok(())
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

    let challenges = vec![make_challenge("1", "Test A", "crypto"), make_challenge("2", "Test B", "web")];
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
    c.hints =
      vec![crate::platform::types::Hint { id: "10".into(), content: Some("Think about factoring".into()), cost: 50 }];
    c.files =
      vec![crate::platform::types::ChallengeFile { name: "challenge.py".into(), url: "/files/challenge.py".into() }];

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
  fn update_notifications_stores_and_replaces() {
    let dir = TempDir::new().unwrap();
    init_state(dir.path()).unwrap();

    let notifs = vec![
      crate::platform::types::Notification {
        id: "1".into(),
        title: "Welcome".into(),
        content: "Hello everyone!".into(),
        date: "2026-01-01".into(),
      },
      crate::platform::types::Notification {
        id: "2".into(),
        title: "Hint Released".into(),
        content: "Check the headers".into(),
        date: "2026-01-02".into(),
      },
    ];
    update_notifications(dir.path(), &notifs).unwrap();

    let state = load_state(dir.path()).unwrap();
    assert_eq!(state.notifications.len(), 2);
    assert_eq!(state.notifications[0].title, "Welcome");
    assert_eq!(state.notifications[1].content, "Check the headers");

    // Replace with new notifications
    let new_notifs = vec![crate::platform::types::Notification {
      id: "3".into(),
      title: "Flag Format".into(),
      content: "flag{...}".into(),
      date: "2026-01-03".into(),
    }];
    update_notifications(dir.path(), &new_notifs).unwrap();

    let state = load_state(dir.path()).unwrap();
    assert_eq!(state.notifications.len(), 1);
    assert_eq!(state.notifications[0].id, "3");
  }

  #[test]
  fn update_notifications_empty_list() {
    let dir = TempDir::new().unwrap();
    init_state(dir.path()).unwrap();

    let notifs = vec![crate::platform::types::Notification {
      id: "1".into(),
      title: "Test".into(),
      content: "Content".into(),
      date: "2026-01-01".into(),
    }];
    update_notifications(dir.path(), &notifs).unwrap();

    // Clear with empty list
    update_notifications(dir.path(), &[]).unwrap();
    let state = load_state(dir.path()).unwrap();
    assert!(state.notifications.is_empty());
  }

  #[test]
  fn cached_notification_roundtrip() {
    let notif = CachedNotification {
      id: "42".into(),
      title: "Important".into(),
      content: "Flag format changed".into(),
      date: "2026-03-04T12:00:00Z".into(),
    };
    let json = serde_json::to_string(&notif).unwrap();
    let deserialized: CachedNotification = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized, notif);
  }

  #[test]
  fn challenge_status_serialization() {
    assert_eq!(serde_json::to_string(&ChallengeStatus::Unsolved).unwrap(), "\"unsolved\"");
    assert_eq!(serde_json::to_string(&ChallengeStatus::InProgress).unwrap(), "\"in_progress\"");
    assert_eq!(serde_json::to_string(&ChallengeStatus::Solved).unwrap(), "\"solved\"");
  }

  #[test]
  fn cached_hint_equality() {
    let h1 = CachedHint { id: "1".into(), content: Some("hint text".into()), cost: 50 };
    let h2 = CachedHint { id: "1".into(), content: Some("hint text".into()), cost: 50 };
    let h3 = CachedHint { id: "1".into(), content: None, cost: 0 };
    assert_eq!(h1, h2);
    assert_ne!(h1, h3);
  }

  #[test]
  fn cached_file_equality() {
    let f1 = CachedFile { name: "data.bin".into(), url: "/files/data.bin".into() };
    let f2 = CachedFile { name: "data.bin".into(), url: "/files/data.bin".into() };
    assert_eq!(f1, f2);
  }

  #[test]
  fn mark_solved_creates_entry_if_missing() {
    let dir = TempDir::new().unwrap();
    init_state(dir.path()).unwrap();

    // Mark solved without any prior sync
    mark_solved(dir.path(), "99", "New Challenge", 250, "flag{new}").unwrap();

    let state = load_state(dir.path()).unwrap();
    let entry = &state.challenges["new challenge"];
    assert_eq!(entry.id, "99");
    assert_eq!(entry.status, ChallengeStatus::Solved);
    assert_eq!(entry.points, Some(250));
    assert_eq!(entry.flag.as_deref(), Some("flag{new}"));
  }

  #[test]
  fn update_sync_detects_platform_solves() {
    let dir = TempDir::new().unwrap();
    init_state(dir.path()).unwrap();

    // First sync: unsolved
    let challenges = vec![make_challenge("1", "Test", "web")];
    update_sync(dir.path(), &challenges).unwrap();
    let state = load_state(dir.path()).unwrap();
    assert_eq!(state.challenges["test"].status, ChallengeStatus::Unsolved);

    // Second sync: now solved_by_me is true
    let mut solved = make_challenge("1", "Test", "web");
    solved.solved_by_me = true;
    update_sync(dir.path(), &[solved]).unwrap();
    let state = load_state(dir.path()).unwrap();
    assert_eq!(state.challenges["test"].status, ChallengeStatus::Solved);
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
        hints: Some(vec![CachedHint { id: "5".into(), content: Some("Check headers".into()), cost: 0 }]),
        files: None,
        tags: Some(vec!["easy".into()]),
        details_fetched_at: None,
        methodology: None,
        tools_used: None,
      },
    );

    let mut challenges = vec![make_challenge("1", "test", "web")];
    merge_cached_details(&mut challenges, &state);

    assert_eq!(challenges[0].description, "A web challenge");
    assert_eq!(challenges[0].hints.len(), 1);
    assert_eq!(challenges[0].tags, vec!["easy"]);
  }

  // ── Orchestration state tests ──────────────────────────────────────────────

  #[test]
  fn load_orchestration_empty_by_default() {
    let dir = TempDir::new().unwrap();
    init_state(dir.path()).unwrap();
    let orch = load_orchestration(dir.path()).unwrap();
    assert!(orch.queue.is_empty());
    assert!(orch.in_progress.is_empty());
    assert!(orch.failed.is_empty());
    assert!(orch.updated_at.is_none());
  }

  #[test]
  fn update_orchestration_persists_queue() {
    let dir = TempDir::new().unwrap();
    init_state(dir.path()).unwrap();

    let orch = OrchestrationState {
      queue: vec![
        QueuedChallenge { name: "Easy RSA".into(), category: "crypto".into(), priority: 30, points: 100 },
        QueuedChallenge { name: "SQLi".into(), category: "web".into(), priority: 28, points: 200 },
      ],
      in_progress: vec![],
      failed: vec![],
      updated_at: Some(Utc::now()),
    };
    update_orchestration(dir.path(), orch).unwrap();

    let loaded = load_orchestration(dir.path()).unwrap();
    assert_eq!(loaded.queue.len(), 2);
    assert_eq!(loaded.queue[0].name, "Easy RSA");
    assert_eq!(loaded.queue[0].priority, 30);
    assert_eq!(loaded.queue[1].name, "SQLi");
    assert!(loaded.updated_at.is_some());
  }

  #[test]
  fn update_orchestration_persists_in_progress() {
    let dir = TempDir::new().unwrap();
    init_state(dir.path()).unwrap();

    let orch = OrchestrationState {
      queue: vec![],
      in_progress: vec!["Challenge A".into(), "Challenge B".into()],
      failed: vec![],
      updated_at: Some(Utc::now()),
    };
    update_orchestration(dir.path(), orch).unwrap();

    let loaded = load_orchestration(dir.path()).unwrap();
    assert_eq!(loaded.in_progress, vec!["Challenge A", "Challenge B"]);
  }

  #[test]
  fn update_orchestration_persists_failed() {
    let dir = TempDir::new().unwrap();
    init_state(dir.path()).unwrap();

    let now = Utc::now();
    let orch = OrchestrationState {
      queue: vec![],
      in_progress: vec![],
      failed: vec![FailedAttempt {
        name: "Hard Pwn".into(),
        category: "pwn".into(),
        attempted_at: now,
        notes: "Could not find overflow offset".into(),
      }],
      updated_at: Some(now),
    };
    update_orchestration(dir.path(), orch).unwrap();

    let loaded = load_orchestration(dir.path()).unwrap();
    assert_eq!(loaded.failed.len(), 1);
    assert_eq!(loaded.failed[0].name, "Hard Pwn");
    assert_eq!(loaded.failed[0].notes, "Could not find overflow offset");
  }

  #[test]
  fn update_orchestration_replaces_previous() {
    let dir = TempDir::new().unwrap();
    init_state(dir.path()).unwrap();

    // Set initial queue
    let orch1 = OrchestrationState {
      queue: vec![QueuedChallenge { name: "A".into(), category: "web".into(), priority: 10, points: 100 }],
      in_progress: vec![],
      failed: vec![],
      updated_at: Some(Utc::now()),
    };
    update_orchestration(dir.path(), orch1).unwrap();

    // Replace with different queue
    let orch2 = OrchestrationState {
      queue: vec![
        QueuedChallenge { name: "B".into(), category: "crypto".into(), priority: 20, points: 200 },
        QueuedChallenge { name: "C".into(), category: "rev".into(), priority: 15, points: 150 },
      ],
      in_progress: vec!["A".into()],
      failed: vec![],
      updated_at: Some(Utc::now()),
    };
    update_orchestration(dir.path(), orch2).unwrap();

    let loaded = load_orchestration(dir.path()).unwrap();
    assert_eq!(loaded.queue.len(), 2);
    assert_eq!(loaded.queue[0].name, "B");
    assert_eq!(loaded.queue[1].name, "C");
    assert_eq!(loaded.in_progress, vec!["A"]);
  }

  #[test]
  fn orchestration_does_not_clobber_challenges() {
    let dir = TempDir::new().unwrap();
    init_state(dir.path()).unwrap();

    // Sync some challenges first
    let challenges = vec![make_challenge("1", "Test", "web")];
    update_sync(dir.path(), &challenges).unwrap();

    // Update orchestration
    let orch = OrchestrationState {
      queue: vec![QueuedChallenge { name: "Test".into(), category: "web".into(), priority: 10, points: 100 }],
      in_progress: vec![],
      failed: vec![],
      updated_at: Some(Utc::now()),
    };
    update_orchestration(dir.path(), orch).unwrap();

    // Verify challenges are still there
    let state = load_state(dir.path()).unwrap();
    assert_eq!(state.challenges.len(), 1);
    assert_eq!(state.challenges["test"].name, "Test");
    assert_eq!(state.orchestration.queue.len(), 1);
  }

  #[test]
  fn save_writeup_stores_methodology_and_tools() {
    let dir = TempDir::new().unwrap();
    init_state(dir.path()).unwrap();

    // First create a challenge entry
    mark_solved(dir.path(), "1", "Easy RSA", 100, "flag{rsa}").unwrap();

    // Save writeup
    save_writeup(
      dir.path(),
      "Easy RSA",
      "Factored n using factordb, computed d, decrypted",
      &["crypto_rsa_toolkit".into(), "python".into()],
    )
    .unwrap();

    let state = load_state(dir.path()).unwrap();
    let entry = &state.challenges["easy rsa"];
    assert_eq!(entry.methodology.as_deref(), Some("Factored n using factordb, computed d, decrypted"));
    assert_eq!(entry.tools_used.as_ref().unwrap(), &["crypto_rsa_toolkit", "python"]);
  }

  #[test]
  fn save_writeup_noop_for_missing_challenge() {
    let dir = TempDir::new().unwrap();
    init_state(dir.path()).unwrap();

    // Saving writeup for nonexistent challenge should not error
    let result = save_writeup(dir.path(), "nonexistent", "method", &["tool".into()]);
    assert!(result.is_ok());

    // But nothing should be stored
    let state = load_state(dir.path()).unwrap();
    assert!(state.challenges.is_empty());
  }

  #[test]
  fn save_writeup_overwrites_previous() {
    let dir = TempDir::new().unwrap();
    init_state(dir.path()).unwrap();
    mark_solved(dir.path(), "1", "Test", 100, "flag{x}").unwrap();

    save_writeup(dir.path(), "Test", "first attempt", &["tool1".into()]).unwrap();
    save_writeup(dir.path(), "Test", "better method", &["tool1".into(), "tool2".into()]).unwrap();

    let state = load_state(dir.path()).unwrap();
    let entry = &state.challenges["test"];
    assert_eq!(entry.methodology.as_deref(), Some("better method"));
    assert_eq!(entry.tools_used.as_ref().unwrap().len(), 2);
  }

  // ── Queue operation simulation tests ───────────────────────────────────────
  // These test the queue state machine operations that ctf_queue_update performs

  #[test]
  fn queue_start_action_moves_to_in_progress() {
    let dir = TempDir::new().unwrap();
    init_state(dir.path()).unwrap();

    let mut orch = OrchestrationState {
      queue: vec![
        QueuedChallenge { name: "A".into(), category: "crypto".into(), priority: 30, points: 100 },
        QueuedChallenge { name: "B".into(), category: "web".into(), priority: 20, points: 200 },
      ],
      in_progress: vec![],
      failed: vec![],
      updated_at: None,
    };

    // Simulate "start" action for challenge A
    let name = "A".to_string();
    orch.queue.retain(|q| q.name != name);
    if !orch.in_progress.contains(&name) {
      orch.in_progress.push(name);
    }
    orch.updated_at = Some(Utc::now());
    update_orchestration(dir.path(), orch).unwrap();

    let loaded = load_orchestration(dir.path()).unwrap();
    assert_eq!(loaded.queue.len(), 1);
    assert_eq!(loaded.queue[0].name, "B");
    assert_eq!(loaded.in_progress, vec!["A"]);
  }

  #[test]
  fn queue_complete_action_removes_from_in_progress() {
    let dir = TempDir::new().unwrap();
    init_state(dir.path()).unwrap();

    let mut orch =
      OrchestrationState { queue: vec![], in_progress: vec!["A".into(), "B".into()], failed: vec![], updated_at: None };

    // Simulate "complete" action for A
    let name = "A";
    orch.in_progress.retain(|n| n != name);
    orch.updated_at = Some(Utc::now());
    update_orchestration(dir.path(), orch).unwrap();

    let loaded = load_orchestration(dir.path()).unwrap();
    assert!(loaded.in_progress == vec!["B"]);
  }

  #[test]
  fn queue_fail_action_moves_to_failed() {
    let dir = TempDir::new().unwrap();
    init_state(dir.path()).unwrap();

    let mut orch = OrchestrationState {
      queue: vec![],
      in_progress: vec!["Hard Challenge".into()],
      failed: vec![],
      updated_at: None,
    };

    // Simulate "fail" action
    let name = "Hard Challenge".to_string();
    orch.in_progress.retain(|n| n != &name);
    orch.failed.push(FailedAttempt {
      name,
      category: "pwn".into(),
      attempted_at: Utc::now(),
      notes: "buffer overflow offset unknown".into(),
    });
    orch.updated_at = Some(Utc::now());
    update_orchestration(dir.path(), orch).unwrap();

    let loaded = load_orchestration(dir.path()).unwrap();
    assert!(loaded.in_progress.is_empty());
    assert_eq!(loaded.failed.len(), 1);
    assert_eq!(loaded.failed[0].name, "Hard Challenge");
  }

  #[test]
  fn queue_retry_action_moves_failed_to_queue() {
    let dir = TempDir::new().unwrap();
    init_state(dir.path()).unwrap();

    let mut orch = OrchestrationState {
      queue: vec![QueuedChallenge { name: "Other".into(), category: "web".into(), priority: 10, points: 100 }],
      in_progress: vec![],
      failed: vec![FailedAttempt {
        name: "Hard Pwn".into(),
        category: "pwn".into(),
        attempted_at: Utc::now(),
        notes: "failed first attempt".into(),
      }],
      updated_at: None,
    };

    // Simulate "retry" action
    let name_lower = "hard pwn".to_lowercase();
    if let Some(pos) = orch.failed.iter().position(|f| f.name.to_lowercase() == name_lower) {
      let failed = orch.failed.remove(pos);
      orch.queue.push(QueuedChallenge { name: failed.name, category: failed.category, priority: -5, points: 0 });
    }
    orch.updated_at = Some(Utc::now());
    update_orchestration(dir.path(), orch).unwrap();

    let loaded = load_orchestration(dir.path()).unwrap();
    assert!(loaded.failed.is_empty());
    assert_eq!(loaded.queue.len(), 2);
    assert_eq!(loaded.queue[1].name, "Hard Pwn");
    assert_eq!(loaded.queue[1].priority, -5);
  }

  #[test]
  fn queue_prioritize_action_moves_to_front() {
    let dir = TempDir::new().unwrap();
    init_state(dir.path()).unwrap();

    let mut orch = OrchestrationState {
      queue: vec![
        QueuedChallenge { name: "A".into(), category: "crypto".into(), priority: 30, points: 100 },
        QueuedChallenge { name: "B".into(), category: "web".into(), priority: 20, points: 200 },
        QueuedChallenge { name: "C".into(), category: "rev".into(), priority: 10, points: 150 },
      ],
      in_progress: vec![],
      failed: vec![],
      updated_at: None,
    };

    // Simulate "prioritize" action for C
    let name_lower = "c".to_lowercase();
    if let Some(pos) = orch.queue.iter().position(|q| q.name.to_lowercase() == name_lower) {
      let mut entry = orch.queue.remove(pos);
      let max_priority = orch.queue.iter().map(|q| q.priority).max().unwrap_or(0);
      entry.priority = max_priority + 100;
      orch.queue.insert(0, entry);
    }
    orch.updated_at = Some(Utc::now());
    update_orchestration(dir.path(), orch).unwrap();

    let loaded = load_orchestration(dir.path()).unwrap();
    assert_eq!(loaded.queue.len(), 3);
    assert_eq!(loaded.queue[0].name, "C");
    assert_eq!(loaded.queue[0].priority, 130); // 30 + 100
  }

  #[test]
  fn queue_prioritize_rescues_from_failed() {
    let dir = TempDir::new().unwrap();
    init_state(dir.path()).unwrap();

    let mut orch = OrchestrationState {
      queue: vec![QueuedChallenge { name: "A".into(), category: "crypto".into(), priority: 20, points: 100 }],
      in_progress: vec![],
      failed: vec![FailedAttempt {
        name: "Failed One".into(),
        category: "web".into(),
        attempted_at: Utc::now(),
        notes: "timeout".into(),
      }],
      updated_at: None,
    };

    // Simulate "prioritize" for a failed challenge
    let name_lower = "failed one".to_lowercase();
    let found_in_queue = orch.queue.iter().position(|q| q.name.to_lowercase() == name_lower);
    assert!(found_in_queue.is_none());

    if let Some(failed_pos) = orch.failed.iter().position(|f| f.name.to_lowercase() == name_lower) {
      let failed = orch.failed.remove(failed_pos);
      let max_priority = orch.queue.iter().map(|q| q.priority).max().unwrap_or(0);
      orch.queue.insert(
        0,
        QueuedChallenge { name: failed.name, category: failed.category, priority: max_priority + 100, points: 0 },
      );
    }
    orch.updated_at = Some(Utc::now());
    update_orchestration(dir.path(), orch).unwrap();

    let loaded = load_orchestration(dir.path()).unwrap();
    assert!(loaded.failed.is_empty());
    assert_eq!(loaded.queue.len(), 2);
    assert_eq!(loaded.queue[0].name, "Failed One");
    assert_eq!(loaded.queue[0].priority, 120); // 20 + 100
  }

  #[test]
  fn queue_clear_resets_everything() {
    let dir = TempDir::new().unwrap();
    init_state(dir.path()).unwrap();

    let orch = OrchestrationState {
      queue: vec![QueuedChallenge { name: "A".into(), category: "crypto".into(), priority: 30, points: 100 }],
      in_progress: vec!["B".into()],
      failed: vec![FailedAttempt {
        name: "C".into(),
        category: "pwn".into(),
        attempted_at: Utc::now(),
        notes: "failed".into(),
      }],
      updated_at: Some(Utc::now()),
    };
    update_orchestration(dir.path(), orch).unwrap();

    // Simulate "clear" action
    update_orchestration(dir.path(), OrchestrationState::default()).unwrap();

    let loaded = load_orchestration(dir.path()).unwrap();
    assert!(loaded.queue.is_empty());
    assert!(loaded.in_progress.is_empty());
    assert!(loaded.failed.is_empty());
  }

  // ── Auto-queue scoring algorithm tests ─────────────────────────────────────
  // These test the scoring logic from ctf_auto_queue by reproducing it directly

  fn score_challenge(challenge: &Challenge, failed_names: &std::collections::HashSet<String>) -> i32 {
    let cat = challenge.category.to_lowercase();
    let category_score: i32 = match cat.as_str() {
      "crypto" | "cryptography" => 10,
      "forensics" | "forensic" => 10,
      "web" | "web exploitation" => 8,
      "rev" | "reverse" | "reverse engineering" | "reversing" => 6,
      "misc" | "miscellaneous" | "trivia" => 4,
      "pwn" | "binary exploitation" | "exploitation" | "pwnable" => 2,
      _ => 4,
    };

    let difficulty_bonus: i32 = if challenge.solves > 50 {
      20
    } else if challenge.solves >= 20 {
      10
    } else {
      0
    };

    let solve_bonus: i32 =
      if challenge.solves > 0 && (challenge.value as f64 / challenge.solves as f64) < 10.0 { 5 } else { 0 };

    let mut priority = category_score + difficulty_bonus + solve_bonus;

    if failed_names.contains(&challenge.name.to_lowercase()) {
      priority -= 10;
    }

    priority
  }

  #[test]
  fn scoring_crypto_high_solves() {
    let empty = std::collections::HashSet::new();
    let c = Challenge {
      id: "1".into(),
      name: "Easy RSA".into(),
      category: "crypto".into(),
      description: String::new(),
      value: 100,
      solves: 60,
      solved_by_me: false,
      files: vec![],
      tags: vec![],
      hints: vec![],
    };
    // crypto=10 + difficulty(>50)=20 + solve_bonus(100/60<10)=5 = 35
    assert_eq!(score_challenge(&c, &empty), 35);
  }

  #[test]
  fn scoring_pwn_low_solves() {
    let empty = std::collections::HashSet::new();
    let c = Challenge {
      id: "2".into(),
      name: "Hard Exploit".into(),
      category: "pwn".into(),
      description: String::new(),
      value: 500,
      solves: 5,
      solved_by_me: false,
      files: vec![],
      tags: vec![],
      hints: vec![],
    };
    // pwn=2 + difficulty(<20)=0 + solve_bonus(500/5=100, not<10)=0 = 2
    assert_eq!(score_challenge(&c, &empty), 2);
  }

  #[test]
  fn scoring_web_medium_solves() {
    let empty = std::collections::HashSet::new();
    let c = Challenge {
      id: "3".into(),
      name: "SQLi Basic".into(),
      category: "web".into(),
      description: String::new(),
      value: 100,
      solves: 35,
      solved_by_me: false,
      files: vec![],
      tags: vec![],
      hints: vec![],
    };
    // web=8 + difficulty(20-50)=10 + solve_bonus(100/35≈2.8<10)=5 = 23
    assert_eq!(score_challenge(&c, &empty), 23);
  }

  #[test]
  fn scoring_failed_challenge_penalized() {
    let mut failed = std::collections::HashSet::new();
    failed.insert("hard rev".to_string());

    let c = Challenge {
      id: "4".into(),
      name: "Hard Rev".into(),
      category: "rev".into(),
      description: String::new(),
      value: 400,
      solves: 25,
      solved_by_me: false,
      files: vec![],
      tags: vec![],
      hints: vec![],
    };
    // rev=6 + difficulty(20-50)=10 + solve_bonus(400/25=16, not<10)=0 - failed=10 = 6
    assert_eq!(score_challenge(&c, &failed), 6);
  }

  #[test]
  fn scoring_unknown_category_defaults_to_misc() {
    let empty = std::collections::HashSet::new();
    let c = Challenge {
      id: "5".into(),
      name: "Random".into(),
      category: "osint".into(),
      description: String::new(),
      value: 50,
      solves: 100,
      solved_by_me: false,
      files: vec![],
      tags: vec![],
      hints: vec![],
    };
    // unknown(osint)=4 + difficulty(>50)=20 + solve_bonus(50/100=0.5<10)=5 = 29
    assert_eq!(score_challenge(&c, &empty), 29);
  }

  #[test]
  fn scoring_forensics_matches_crypto_priority() {
    let empty = std::collections::HashSet::new();
    let crypto = Challenge {
      id: "1".into(),
      name: "A".into(),
      category: "crypto".into(),
      description: String::new(),
      value: 100,
      solves: 10,
      solved_by_me: false,
      files: vec![],
      tags: vec![],
      hints: vec![],
    };
    let forensics = Challenge {
      id: "2".into(),
      name: "B".into(),
      category: "forensics".into(),
      description: String::new(),
      value: 100,
      solves: 10,
      solved_by_me: false,
      files: vec![],
      tags: vec![],
      hints: vec![],
    };
    assert_eq!(score_challenge(&crypto, &empty), score_challenge(&forensics, &empty));
  }

  #[test]
  fn scoring_category_aliases() {
    let empty = std::collections::HashSet::new();
    let make = |cat: &str| Challenge {
      id: "1".into(),
      name: "T".into(),
      category: cat.into(),
      description: String::new(),
      value: 100,
      solves: 10,
      solved_by_me: false,
      files: vec![],
      tags: vec![],
      hints: vec![],
    };
    // All pwn aliases should score the same
    assert_eq!(score_challenge(&make("pwn"), &empty), score_challenge(&make("binary exploitation"), &empty));
    assert_eq!(score_challenge(&make("pwn"), &empty), score_challenge(&make("exploitation"), &empty));
    assert_eq!(score_challenge(&make("pwn"), &empty), score_challenge(&make("pwnable"), &empty));

    // All rev aliases
    assert_eq!(score_challenge(&make("rev"), &empty), score_challenge(&make("reverse engineering"), &empty));
    assert_eq!(score_challenge(&make("rev"), &empty), score_challenge(&make("reversing"), &empty));

    // All misc aliases
    assert_eq!(score_challenge(&make("misc"), &empty), score_challenge(&make("miscellaneous"), &empty));
    assert_eq!(score_challenge(&make("misc"), &empty), score_challenge(&make("trivia"), &empty));
  }

  #[test]
  fn scoring_difficulty_bonus_boundary_at_20() {
    let empty = std::collections::HashSet::new();
    let make = |solves: u32| Challenge {
      id: "1".into(),
      name: "T".into(),
      category: "misc".into(),
      description: String::new(),
      value: 200,
      solves,
      solved_by_me: false,
      files: vec![],
      tags: vec![],
      hints: vec![],
    };
    // 19 solves → 0 bonus, 20 solves → 10 bonus
    let score_19 = score_challenge(&make(19), &empty);
    let score_20 = score_challenge(&make(20), &empty);
    assert_eq!(score_20 - score_19, 10);
  }

  #[test]
  fn scoring_difficulty_bonus_boundary_at_51() {
    let empty = std::collections::HashSet::new();
    let make = |solves: u32| Challenge {
      id: "1".into(),
      name: "T".into(),
      category: "misc".into(),
      description: String::new(),
      value: 1000,
      solves,
      solved_by_me: false,
      files: vec![],
      tags: vec![],
      hints: vec![],
    };
    // 50 solves → 10 bonus, 51 solves → 20 bonus
    let score_50 = score_challenge(&make(50), &empty);
    let score_51 = score_challenge(&make(51), &empty);
    assert_eq!(score_51 - score_50, 10);
  }

  #[test]
  fn scoring_solve_bonus_boundary() {
    let empty = std::collections::HashSet::new();
    // value/solves < 10 → bonus 5
    let with_bonus = Challenge {
      id: "1".into(),
      name: "T".into(),
      category: "misc".into(),
      description: String::new(),
      value: 90,
      solves: 10,
      solved_by_me: false,
      files: vec![],
      tags: vec![],
      hints: vec![],
    };
    // value/solves = 10 → no bonus
    let without_bonus = Challenge {
      id: "1".into(),
      name: "T".into(),
      category: "misc".into(),
      description: String::new(),
      value: 100,
      solves: 10,
      solved_by_me: false,
      files: vec![],
      tags: vec![],
      hints: vec![],
    };
    assert_eq!(score_challenge(&with_bonus, &empty) - score_challenge(&without_bonus, &empty), 5);
  }

  #[test]
  fn scoring_zero_solves_no_bonus() {
    let empty = std::collections::HashSet::new();
    let c = Challenge {
      id: "1".into(),
      name: "T".into(),
      category: "misc".into(),
      description: String::new(),
      value: 0,
      solves: 0,
      solved_by_me: false,
      files: vec![],
      tags: vec![],
      hints: vec![],
    };
    // misc=4 + difficulty(0<20)=0 + solve_bonus(0 solves → no bonus)=0 = 4
    assert_eq!(score_challenge(&c, &empty), 4);
  }

  // ── Queued challenge / failed attempt serialization tests ──────────────────

  #[test]
  fn queued_challenge_roundtrip() {
    let qc = QueuedChallenge { name: "Easy RSA".into(), category: "crypto".into(), priority: 35, points: 100 };
    let json = serde_json::to_string(&qc).unwrap();
    let deserialized: QueuedChallenge = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized, qc);
  }

  #[test]
  fn failed_attempt_roundtrip() {
    let fa = FailedAttempt {
      name: "Hard Pwn".into(),
      category: "pwn".into(),
      attempted_at: Utc::now(),
      notes: "Could not find offset".into(),
    };
    let json = serde_json::to_string(&fa).unwrap();
    let deserialized: FailedAttempt = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized, fa);
  }

  #[test]
  fn orchestration_state_roundtrip() {
    let orch = OrchestrationState {
      queue: vec![QueuedChallenge { name: "A".into(), category: "crypto".into(), priority: 30, points: 100 }],
      in_progress: vec!["B".into()],
      failed: vec![FailedAttempt {
        name: "C".into(),
        category: "pwn".into(),
        attempted_at: Utc::now(),
        notes: "failed".into(),
      }],
      updated_at: Some(Utc::now()),
    };
    let json = serde_json::to_string(&orch).unwrap();
    let deserialized: OrchestrationState = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.queue, orch.queue);
    assert_eq!(deserialized.in_progress, orch.in_progress);
    assert_eq!(deserialized.failed, orch.failed);
  }

  // ── Writeup generation tests ──────────────────────────────────────────────

  #[test]
  fn save_writeup_preserves_existing_solved_fields() {
    let dir = TempDir::new().unwrap();
    init_state(dir.path()).unwrap();
    mark_solved(dir.path(), "1", "Test", 200, "flag{test}").unwrap();

    save_writeup(dir.path(), "Test", "used crypto tools", &["crypto_identify".into()]).unwrap();

    let state = load_state(dir.path()).unwrap();
    let entry = &state.challenges["test"];
    // Solved fields should still be there
    assert_eq!(entry.status, ChallengeStatus::Solved);
    assert_eq!(entry.flag.as_deref(), Some("flag{test}"));
    assert_eq!(entry.points, Some(200));
    // And writeup fields too
    assert_eq!(entry.methodology.as_deref(), Some("used crypto tools"));
  }

  #[test]
  fn merge_does_not_overwrite_existing_description() {
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
        description: Some("Old description".into()),
        hints: None,
        files: None,
        tags: None,
        details_fetched_at: None,
        methodology: None,
        tools_used: None,
      },
    );

    let mut challenges = vec![Challenge {
      id: "1".into(),
      name: "test".into(),
      category: "web".into(),
      description: "Platform description".into(),
      value: 100,
      solves: 5,
      solved_by_me: false,
      files: vec![],
      tags: vec![],
      hints: vec![],
    }];

    merge_cached_details(&mut challenges, &state);
    // Platform already has a description, so cached one should NOT override
    assert_eq!(challenges[0].description, "Platform description");
  }

  #[test]
  fn merge_fills_empty_description_from_cache() {
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
        description: Some("Cached description".into()),
        hints: None,
        files: None,
        tags: None,
        details_fetched_at: None,
        methodology: None,
        tools_used: None,
      },
    );

    let mut challenges = vec![Challenge {
      id: "1".into(),
      name: "test".into(),
      category: "web".into(),
      description: String::new(), // empty
      value: 100,
      solves: 5,
      solved_by_me: false,
      files: vec![],
      tags: vec![],
      hints: vec![],
    }];

    merge_cached_details(&mut challenges, &state);
    assert_eq!(challenges[0].description, "Cached description");
  }
}
