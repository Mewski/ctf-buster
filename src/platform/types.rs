use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
  pub id: String,
  pub name: String,
  pub category: String,
  pub description: String,
  pub value: u32,
  pub solves: u32,
  pub solved_by_me: bool,
  pub files: Vec<ChallengeFile>,
  pub tags: Vec<String>,
  pub hints: Vec<Hint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeFile {
  pub name: String,
  pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hint {
  pub id: String,
  pub content: Option<String>,
  pub cost: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SubmitResult {
  Correct { challenge: String, points: u32 },
  Incorrect,
  AlreadySolved,
  RateLimited { retry_after: Option<u64> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreboardEntry {
  pub rank: u32,
  pub name: String,
  pub score: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeamInfo {
  pub name: String,
  pub score: u32,
  pub rank: Option<u32>,
  pub solves: Vec<SolveInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SolveInfo {
  pub challenge_id: String,
  pub challenge_name: String,
  pub solved_at: DateTime<Utc>,
  pub points: u32,
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn challenge_roundtrip() {
    let challenge = Challenge {
      id: "42".into(),
      name: "Test Challenge".into(),
      category: "crypto".into(),
      description: "Solve this".into(),
      value: 500,
      solves: 10,
      solved_by_me: false,
      files: vec![ChallengeFile {
        name: "data.bin".into(),
        url: "/files/data.bin".into(),
      }],
      tags: vec!["aes".into()],
      hints: vec![Hint {
        id: "1".into(),
        content: Some("Try XOR".into()),
        cost: 50,
      }],
    };
    let json = serde_json::to_string(&challenge).unwrap();
    let deserialized: Challenge = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.name, "Test Challenge");
    assert_eq!(deserialized.value, 500);
    assert_eq!(deserialized.files.len(), 1);
    assert_eq!(deserialized.hints[0].content.as_deref(), Some("Try XOR"));
  }

  #[test]
  fn submit_result_correct_roundtrip() {
    let result = SubmitResult::Correct {
      challenge: "test".into(),
      points: 100,
    };
    let json = serde_json::to_string(&result).unwrap();
    let deserialized: SubmitResult = serde_json::from_str(&json).unwrap();
    match deserialized {
      SubmitResult::Correct { challenge, points } => {
        assert_eq!(challenge, "test");
        assert_eq!(points, 100);
      }
      _ => panic!("wrong variant"),
    }
  }

  #[test]
  fn submit_result_all_variants() {
    let variants: Vec<SubmitResult> = vec![
      SubmitResult::Correct { challenge: "a".into(), points: 50 },
      SubmitResult::Incorrect,
      SubmitResult::AlreadySolved,
      SubmitResult::RateLimited { retry_after: Some(10) },
      SubmitResult::RateLimited { retry_after: None },
    ];
    for v in &variants {
      let json = serde_json::to_string(v).unwrap();
      let _: SubmitResult = serde_json::from_str(&json).unwrap();
    }
  }

  #[test]
  fn team_info_with_and_without_rank() {
    let with_rank = TeamInfo {
      name: "team".into(),
      score: 100,
      rank: Some(3),
      solves: vec![],
    };
    let json = serde_json::to_string(&with_rank).unwrap();
    assert!(json.contains("\"rank\":3"));

    let without_rank = TeamInfo {
      name: "team".into(),
      score: 0,
      rank: None,
      solves: vec![],
    };
    let json = serde_json::to_string(&without_rank).unwrap();
    assert!(json.contains("\"rank\":null"));
  }

  #[test]
  fn scoreboard_entry_roundtrip() {
    let entry = ScoreboardEntry { rank: 1, name: "winners".into(), score: 9999 };
    let json = serde_json::to_string(&entry).unwrap();
    let deserialized: ScoreboardEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.rank, 1);
    assert_eq!(deserialized.name, "winners");
  }
}
