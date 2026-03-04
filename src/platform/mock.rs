use std::path::Path;
use std::sync::Mutex;

use async_trait::async_trait;

use super::types::*;
use super::Platform;
use crate::error::{Error, Result};

pub struct MockPlatform {
  pub challenges: Vec<Challenge>,
  pub team_info: TeamInfo,
  pub scoreboard: Vec<ScoreboardEntry>,
  pub submit_results: Mutex<Vec<SubmitResult>>,
}

impl MockPlatform {
  pub fn new() -> Self {
    Self {
      challenges: vec![
        Challenge {
          id: "1".into(),
          name: "Easy RSA".into(),
          category: "crypto".into(),
          description: "Factor n to find the flag".into(),
          value: 100,
          solves: 50,
          solved_by_me: false,
          files: vec![ChallengeFile {
            name: "output.txt".into(),
            url: "/files/output.txt".into(),
          }],
          tags: vec!["easy".into(), "rsa".into()],
          hints: vec![Hint {
            id: "1".into(),
            content: Some("Use factordb".into()),
            cost: 0,
          }],
        },
        Challenge {
          id: "2".into(),
          name: "SQL Injection".into(),
          category: "web".into(),
          description: "Find the admin password".into(),
          value: 200,
          solves: 30,
          solved_by_me: true,
          files: vec![],
          tags: vec!["medium".into()],
          hints: vec![],
        },
        Challenge {
          id: "3".into(),
          name: "Buffer Overflow".into(),
          category: "pwn".into(),
          description: "Exploit the binary".into(),
          value: 300,
          solves: 10,
          solved_by_me: false,
          files: vec![
            ChallengeFile {
              name: "vuln".into(),
              url: "/files/vuln".into(),
            },
            ChallengeFile {
              name: "vuln.c".into(),
              url: "/files/vuln.c".into(),
            },
          ],
          tags: vec!["hard".into()],
          hints: vec![
            Hint {
              id: "2".into(),
              content: None,
              cost: 50,
            },
          ],
        },
      ],
      team_info: TeamInfo {
        name: "TestTeam".into(),
        score: 200,
        rank: Some(5),
        solves: vec![],
      },
      scoreboard: vec![
        ScoreboardEntry { rank: 1, name: "Alpha".into(), score: 1000 },
        ScoreboardEntry { rank: 2, name: "Beta".into(), score: 800 },
        ScoreboardEntry { rank: 3, name: "Gamma".into(), score: 600 },
      ],
      submit_results: Mutex::new(vec![SubmitResult::Correct {
        challenge: "test".into(),
        points: 100,
      }]),
    }
  }
}

#[async_trait]
impl Platform for MockPlatform {
  async fn whoami(&self) -> Result<TeamInfo> {
    Ok(self.team_info.clone())
  }

  async fn challenges(&self) -> Result<Vec<Challenge>> {
    Ok(self.challenges.clone())
  }

  async fn challenge(&self, id: &str) -> Result<Challenge> {
    self
      .challenges
      .iter()
      .find(|c| c.id == id)
      .cloned()
      .ok_or(Error::ChallengeNotFound(id.into()))
  }

  async fn submit(&self, _challenge_id: &str, _flag: &str) -> Result<SubmitResult> {
    let mut results = self.submit_results.lock().unwrap();
    if results.is_empty() {
      Ok(SubmitResult::Incorrect)
    } else {
      Ok(results.remove(0))
    }
  }

  async fn scoreboard(&self, limit: Option<u32>) -> Result<Vec<ScoreboardEntry>> {
    let limit = limit.unwrap_or(10) as usize;
    Ok(self.scoreboard.iter().take(limit).cloned().collect())
  }

  async fn download_file(&self, _file: &ChallengeFile, dest: &Path) -> Result<()> {
    tokio::fs::write(dest, b"mock file content").await?;
    Ok(())
  }

  async fn unlock_hint(&self, hint_id: &str) -> Result<Hint> {
    Ok(Hint {
      id: hint_id.into(),
      content: Some("Unlocked hint content".into()),
      cost: 50,
    })
  }

  async fn notifications(&self) -> Result<Vec<Notification>> {
    Ok(vec![Notification {
      id: "1".into(),
      title: "Welcome".into(),
      content: "Welcome to the CTF!".into(),
      date: "2026-01-01T00:00:00Z".into(),
    }])
  }
}
