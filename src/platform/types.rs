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
pub struct Notification {
  pub id: String,
  pub title: String,
  pub content: String,
  pub date: String,
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
      files: vec![ChallengeFile { name: "data.bin".into(), url: "/files/data.bin".into() }],
      tags: vec!["aes".into()],
      hints: vec![Hint { id: "1".into(), content: Some("Try XOR".into()), cost: 50 }],
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
    let result = SubmitResult::Correct { challenge: "test".into(), points: 100 };
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
    let with_rank = TeamInfo { name: "team".into(), score: 100, rank: Some(3), solves: vec![] };
    let json = serde_json::to_string(&with_rank).unwrap();
    assert!(json.contains("\"rank\":3"));

    let without_rank = TeamInfo { name: "team".into(), score: 0, rank: None, solves: vec![] };
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

  #[test]
  fn notification_roundtrip() {
    let notif = Notification {
      id: "10".into(),
      title: "Flag Format Change".into(),
      content: "Use flag{...} format".into(),
      date: "2026-03-04T00:00:00Z".into(),
    };
    let json = serde_json::to_string(&notif).unwrap();
    let deserialized: Notification = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.id, "10");
    assert_eq!(deserialized.title, "Flag Format Change");
    assert_eq!(deserialized.content, "Use flag{...} format");
    assert_eq!(deserialized.date, "2026-03-04T00:00:00Z");
  }

  #[test]
  fn hint_with_content() {
    let hint = Hint { id: "5".into(), content: Some("Check the RSA exponent".into()), cost: 50 };
    let json = serde_json::to_string(&hint).unwrap();
    let deserialized: Hint = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.content.as_deref(), Some("Check the RSA exponent"));
    assert_eq!(deserialized.cost, 50);
  }

  #[test]
  fn hint_without_content() {
    let hint = Hint { id: "6".into(), content: None, cost: 100 };
    let json = serde_json::to_string(&hint).unwrap();
    assert!(json.contains("null"));
    let deserialized: Hint = serde_json::from_str(&json).unwrap();
    assert!(deserialized.content.is_none());
  }

  #[test]
  fn challenge_file_roundtrip() {
    let file = ChallengeFile { name: "data.enc".into(), url: "/files/1234/data.enc".into() };
    let json = serde_json::to_string(&file).unwrap();
    let deserialized: ChallengeFile = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.name, "data.enc");
    assert_eq!(deserialized.url, "/files/1234/data.enc");
  }

  #[test]
  fn solve_info_roundtrip() {
    let solve = SolveInfo {
      challenge_id: "42".into(),
      challenge_name: "Easy RSA".into(),
      solved_at: chrono::Utc::now(),
      points: 100,
    };
    let json = serde_json::to_string(&solve).unwrap();
    let deserialized: SolveInfo = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.challenge_id, "42");
    assert_eq!(deserialized.points, 100);
  }

  #[test]
  fn submit_result_rate_limited_with_retry() {
    let result = SubmitResult::RateLimited { retry_after: Some(30) };
    let json = serde_json::to_string(&result).unwrap();
    assert!(json.contains("30"));
    let deserialized: SubmitResult = serde_json::from_str(&json).unwrap();
    match deserialized {
      SubmitResult::RateLimited { retry_after } => assert_eq!(retry_after, Some(30)),
      _ => panic!("wrong variant"),
    }
  }

  #[test]
  fn challenge_empty_fields() {
    let challenge = Challenge {
      id: "1".into(),
      name: "Minimal".into(),
      category: "misc".into(),
      description: String::new(),
      value: 0,
      solves: 0,
      solved_by_me: false,
      files: vec![],
      tags: vec![],
      hints: vec![],
    };
    let json = serde_json::to_string(&challenge).unwrap();
    let deserialized: Challenge = serde_json::from_str(&json).unwrap();
    assert!(deserialized.description.is_empty());
    assert!(deserialized.files.is_empty());
    assert!(deserialized.hints.is_empty());
  }
}
