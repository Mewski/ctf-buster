use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;

use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;

use super::types::*;
use super::Platform;
use crate::error::{Error, Result};

enum AuthMethod {
  Token(String),
  Session,
}

pub struct CtfdPlatform {
  base_url: String,
  auth: AuthMethod,
  client: Client,
  csrf_nonce: Mutex<Option<String>>,
}

impl CtfdPlatform {
  pub fn new(url: String, token: String) -> Self {
    let base_url = url.trim_end_matches('/').to_string();

    // Detect if this is a session cookie vs an API token.
    // Flask session cookies: base64.base64.base64 (3 dot-separated parts, with base64 chars)
    // API tokens: hex strings, or prefixed with "ctfd_"
    // JWT tokens (rCTF style): also 3 dot-separated base64 parts but handled by rctf platform
    let is_session_cookie = {
      let parts: Vec<&str> = token.split('.').collect();
      // Flask sessions have exactly 3 dot-separated parts and don't start with "ctfd_"
      // Also exclude pure hex strings that happen to contain dots
      !token.starts_with("ctfd_")
        && parts.len() >= 2
        && parts.iter().all(|p| !p.is_empty())
        && !token.chars().all(|c| c.is_ascii_hexdigit())
    };
    let (auth, client) = if is_session_cookie {
      // Session cookie — build client with cookie jar
      let jar = Arc::new(reqwest::cookie::Jar::default());
      let url_parsed: url::Url = base_url.parse().unwrap_or_else(|_| "http://localhost".parse().unwrap());
      jar.add_cookie_str(&format!("session={token}"), &url_parsed);
      let client = Client::builder().cookie_provider(jar).build().unwrap_or_default();
      (AuthMethod::Session, client)
    } else {
      (AuthMethod::Token(token), Client::new())
    };

    Self { base_url, auth, client, csrf_nonce: Mutex::new(None) }
  }

  /// Fetch CSRF nonce from CTFd (needed for session-based POST requests).
  /// Caches the nonce; call `refresh_csrf_nonce` to force a re-fetch.
  async fn get_csrf_nonce(&self) -> Result<String> {
    let mut guard = self.csrf_nonce.lock().await;
    if let Some(ref nonce) = *guard {
      return Ok(nonce.clone());
    }
    let nonce = self.fetch_csrf_nonce().await?;
    *guard = Some(nonce.clone());
    Ok(nonce)
  }

  /// Force re-fetch the CSRF nonce (called on 403 errors).
  async fn refresh_csrf_nonce(&self) -> Result<String> {
    let mut guard = self.csrf_nonce.lock().await;
    let nonce = self.fetch_csrf_nonce().await?;
    *guard = Some(nonce.clone());
    Ok(nonce)
  }

  async fn fetch_csrf_nonce(&self) -> Result<String> {
    let resp = self.client.get(format!("{}/challenges", self.base_url)).send().await?;
    let status = resp.status();
    let html = resp.text().await?;
    if !status.is_success() {
      return Err(Error::Platform(format!("Failed to fetch CSRF nonce (HTTP {status})")));
    }
    html
      .find("csrfNonce")
      .and_then(|pos| {
        let after = &html[pos..];
        let quote_start = after.find('"')? + 1;
        let quote_end = quote_start + after[quote_start..].find('"')?;
        Some(after[quote_start..quote_end].to_string())
      })
      .ok_or_else(|| Error::Platform("Could not find csrfNonce in CTFd page".into()))
  }

  /// Fetch the set of challenge IDs that the current user/team has solved.
  /// Works with both token and session auth by checking solves endpoints.
  async fn fetch_my_solve_ids(&self) -> Result<std::collections::HashSet<String>> {
    // Try /teams/me/solves first (team mode), fall back to /users/me/solves
    let body = match self.get("/teams/me/solves").await {
      Ok(b) => b,
      Err(_) => match self.get("/users/me/solves").await {
        Ok(b) => b,
        Err(_) => return Ok(std::collections::HashSet::new()),
      },
    };

    let data = body.get("data").and_then(|d| d.as_array()).cloned().unwrap_or_default();

    let ids: std::collections::HashSet<String> = data
      .iter()
      .filter_map(|solve| solve.get("challenge_id").and_then(|id| id.as_u64()).map(|id| id.to_string()))
      .collect();

    Ok(ids)
  }

  fn api_url(&self, path: &str) -> String {
    format!("{}/api/v1{path}", self.base_url)
  }

  fn apply_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
    match &self.auth {
      AuthMethod::Token(token) => req.header("Authorization", format!("Token {token}")),
      AuthMethod::Session => req, // cookie jar handles it
    }
  }

  async fn get(&self, path: &str) -> Result<serde_json::Value> {
    let req = self.client.get(self.api_url(path)).header("Content-Type", "application/json");
    let resp = self.apply_auth(req).send().await?;

    let status = resp.status();
    let body: serde_json::Value = resp.json().await?;

    if !status.is_success() {
      return Err(Error::Platform(format!(
        "CTFd API error ({}): {}",
        status,
        body.get("message").and_then(|m| m.as_str()).unwrap_or("unknown error")
      )));
    }

    if body.get("success").and_then(|s| s.as_bool()) != Some(true) {
      return Err(Error::Platform(format!(
        "CTFd API returned failure: {}",
        serde_json::to_string_pretty(&body).unwrap_or_default()
      )));
    }

    Ok(body)
  }

  async fn post(&self, path: &str, payload: &serde_json::Value) -> Result<serde_json::Value> {
    let result = self.post_inner(path, payload).await;

    // On 403 with session auth, the CSRF nonce may have expired — refresh and retry once
    if matches!(self.auth, AuthMethod::Session) {
      if let Err(Error::Platform(ref msg)) = result {
        if msg.contains("403") {
          self.refresh_csrf_nonce().await?;
          return self.post_inner(path, payload).await;
        }
      }
    }

    result
  }

  async fn post_inner(&self, path: &str, payload: &serde_json::Value) -> Result<serde_json::Value> {
    let mut req = self.client.post(self.api_url(path)).header("Content-Type", "application/json").json(payload);
    req = self.apply_auth(req);
    // Session auth requires CSRF nonce on POST requests
    if matches!(self.auth, AuthMethod::Session) {
      let nonce = self.get_csrf_nonce().await?;
      req = req.header("CSRF-Token", &nonce);
    }
    let resp = req.send().await?;

    let status = resp.status();
    let body: serde_json::Value = resp.json().await?;

    if !status.is_success() {
      return Err(Error::Platform(format!(
        "CTFd API error ({}): {}",
        status,
        body.get("message").and_then(|m| m.as_str()).unwrap_or("unknown error")
      )));
    }

    Ok(body)
  }
}

#[derive(Debug, Deserialize)]
struct CtfdChallenge {
  id: u64,
  name: String,
  category: String,
  #[serde(default)]
  description: String,
  value: u32,
  solves: u32,
  solved_by_me: Option<bool>,
  #[serde(default)]
  files: Vec<String>,
  #[serde(default)]
  tags: Vec<serde_json::Value>,
  #[serde(default)]
  hints: Vec<CtfdHint>,
}

#[derive(Debug, Deserialize)]
struct CtfdHint {
  id: u64,
  content: Option<String>,
  cost: u32,
}

impl From<CtfdChallenge> for Challenge {
  fn from(c: CtfdChallenge) -> Self {
    Challenge {
      id: c.id.to_string(),
      name: c.name,
      category: c.category,
      description: c.description,
      value: c.value,
      solves: c.solves,
      solved_by_me: c.solved_by_me.unwrap_or(false),
      files: c
        .files
        .into_iter()
        .map(|url| {
          let name = url.split('/').next_back().and_then(|s| s.split('?').next()).unwrap_or("unknown").to_string();
          ChallengeFile { name, url }
        })
        .collect(),
      tags: c
        .tags
        .into_iter()
        .filter_map(|t| {
          t.as_str().map(|s| s.to_string()).or_else(|| t.get("value").and_then(|v| v.as_str()).map(|s| s.to_string()))
        })
        .collect(),
      hints: c.hints.into_iter().map(|h| h.into()).collect(),
    }
  }
}

impl From<CtfdHint> for Hint {
  fn from(h: CtfdHint) -> Self {
    Hint { id: h.id.to_string(), content: h.content, cost: h.cost }
  }
}

#[async_trait]
impl Platform for CtfdPlatform {
  async fn whoami(&self) -> Result<TeamInfo> {
    // Try /teams/me first (team mode), fall back to /users/me
    let body = match self.get("/teams/me").await {
      Ok(b) => b,
      Err(_) => self.get("/users/me").await?,
    };

    let data = body.get("data").ok_or_else(|| Error::Platform("Missing data field".into()))?;

    let name = data.get("name").and_then(|n| n.as_str()).unwrap_or("unknown").to_string();
    let score = data.get("score").and_then(|s| s.as_u64()).unwrap_or(0) as u32;
    let rank =
      data.get("place").and_then(|p| p.as_u64().map(|v| v as u32).or_else(|| p.as_str().and_then(|s| s.parse().ok())));

    Ok(TeamInfo { name, score, rank, solves: Vec::new() })
  }

  async fn challenges(&self) -> Result<Vec<Challenge>> {
    let body = self.get("/challenges").await?;
    let data = body.get("data").ok_or_else(|| Error::Platform("Missing data field".into()))?;

    let ctfd_challenges: Vec<CtfdChallenge> = serde_json::from_value(data.clone())?;
    let mut challenges: Vec<Challenge> = ctfd_challenges.into_iter().map(|c| c.into()).collect();

    // Some CTFd versions don't return solved_by_me in the list endpoint,
    // or return null for session/cookie auth. Cross-reference with the
    // user/team solves endpoint to ensure accurate solve status.
    let solved_ids = self.fetch_my_solve_ids().await.unwrap_or_default();
    if !solved_ids.is_empty() {
      for c in &mut challenges {
        if solved_ids.contains(&c.id) {
          c.solved_by_me = true;
        }
      }
    }

    Ok(challenges)
  }

  async fn challenge(&self, id: &str) -> Result<Challenge> {
    let body = self.get(&format!("/challenges/{id}")).await?;
    let data = body.get("data").ok_or_else(|| Error::Platform("Missing data field".into()))?;

    let ctfd_challenge: CtfdChallenge = serde_json::from_value(data.clone())?;
    Ok(ctfd_challenge.into())
  }

  async fn submit(&self, challenge_id: &str, flag: &str) -> Result<SubmitResult> {
    let challenge_id_num: u64 =
      challenge_id.parse().map_err(|_| Error::Platform(format!("Invalid challenge ID: {challenge_id}")))?;

    let payload = serde_json::json!({
      "challenge_id": challenge_id_num,
      "submission": flag,
    });

    let body = self.post("/challenges/attempt", &payload).await?;

    let data = body.get("data").ok_or_else(|| Error::Platform("Missing data field".into()))?;

    let status = data.get("status").and_then(|s| s.as_str()).unwrap_or("");

    match status {
      "correct" => {
        let challenge = self.challenge(challenge_id).await.ok();
        let name = challenge.as_ref().map(|c| c.name.clone()).unwrap_or_else(|| challenge_id.to_string());
        let points = challenge.as_ref().map(|c| c.value).unwrap_or(0);
        Ok(SubmitResult::Correct { challenge: name, points })
      }
      "incorrect" => Ok(SubmitResult::Incorrect),
      "already_solved" => Ok(SubmitResult::AlreadySolved),
      "ratelimited" => {
        // Try to parse retry_after from the response message
        let message = data.get("message").and_then(|m| m.as_str()).unwrap_or("");
        let retry_after = message
          .split_whitespace()
          .find_map(|word| word.trim_end_matches(|c: char| !c.is_ascii_digit()).parse::<u64>().ok());
        Ok(SubmitResult::RateLimited { retry_after })
      }
      _ => Err(Error::Platform(format!("Unknown submit status: {status}"))),
    }
  }

  async fn scoreboard(&self, limit: Option<u32>) -> Result<Vec<ScoreboardEntry>> {
    let limit = limit.unwrap_or(10);
    let body = self.get(&format!("/scoreboard/top/{limit}")).await?;
    let data = body.get("data").ok_or_else(|| Error::Platform("Missing data field".into()))?;

    let mut entries = Vec::new();

    // CTFd top endpoint returns { "1": { "name": ..., "solves": [...] }, "2": ... }
    if let Some(obj) = data.as_object() {
      for (rank_str, team_data) in obj {
        let rank: u32 = rank_str.parse().unwrap_or(0);
        let name = team_data.get("name").and_then(|n| n.as_str()).unwrap_or("unknown").to_string();

        let score = team_data
          .get("solves")
          .and_then(|s| s.as_array())
          .map(|solves| solves.iter().filter_map(|s| s.get("value").and_then(|v| v.as_u64())).sum::<u64>() as u32)
          .unwrap_or(0);

        entries.push(ScoreboardEntry { rank, name, score });
      }
    }

    entries.sort_by_key(|e| e.rank);
    Ok(entries)
  }

  async fn download_file(&self, file: &ChallengeFile, dest: &Path) -> Result<()> {
    let url = if file.url.starts_with("http") { file.url.clone() } else { format!("{}{}", self.base_url, file.url) };

    let req = self.client.get(&url);
    let resp = self.apply_auth(req).send().await?;
    if !resp.status().is_success() {
      return Err(Error::Platform(format!("Failed to download file '{}' (HTTP {})", file.name, resp.status())));
    }

    let bytes = resp.bytes().await?;
    tokio::fs::write(dest, &bytes).await?;
    Ok(())
  }

  async fn notifications(&self) -> Result<Vec<Notification>> {
    let body = self.get("/notifications").await?;
    let data = body.get("data").ok_or_else(|| Error::Platform("Missing data field".into()))?;

    let raw: Vec<serde_json::Value> = serde_json::from_value(data.clone())?;
    let notifications = raw
      .into_iter()
      .map(|n| Notification {
        id: n.get("id").and_then(|v| v.as_u64()).unwrap_or(0).to_string(),
        title: n.get("title").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        content: n.get("content").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        date: n.get("date").and_then(|v| v.as_str()).unwrap_or("").to_string(),
      })
      .collect();
    Ok(notifications)
  }

  async fn unlock_hint(&self, hint_id: &str) -> Result<Hint> {
    let payload = serde_json::json!({
      "target": hint_id.parse::<u64>().map_err(|_| Error::Platform("Invalid hint ID".into()))?,
      "type": "hints",
    });
    self.post("/unlocks", &payload).await?;

    let body = self.get(&format!("/hints/{hint_id}")).await?;
    let data = body.get("data").ok_or_else(|| Error::Platform("Missing data field".into()))?;

    Ok(Hint {
      id: hint_id.to_string(),
      content: data.get("content").and_then(|c| c.as_str()).map(|s| s.to_string()),
      cost: data.get("cost").and_then(|c| c.as_u64()).unwrap_or(0) as u32,
    })
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn parse_ctfd_challenge_list_item() {
    let json = r#"{"id":1,"name":"Test","category":"web","value":100,"solves":5,"solved_by_me":false,"tags":[]}"#;
    let c: CtfdChallenge = serde_json::from_str(json).unwrap();
    assert_eq!(c.id, 1);
    assert_eq!(c.name, "Test");
    assert!(c.description.is_empty());
    assert!(c.files.is_empty());
    assert!(c.hints.is_empty());
  }

  #[test]
  fn parse_ctfd_challenge_with_details() {
    let json = r#"{
      "id": 42,
      "name": "Crypto 101",
      "category": "crypto",
      "description": "<p>Solve this RSA problem</p>",
      "value": 500,
      "solves": 10,
      "solved_by_me": true,
      "files": ["/files/abc123/output.txt?token=xyz"],
      "tags": [{"value": "easy"}],
      "hints": [{"id": 5, "content": "Think about factoring", "cost": 50}]
    }"#;
    let c: CtfdChallenge = serde_json::from_str(json).unwrap();
    assert_eq!(c.description, "<p>Solve this RSA problem</p>");
    assert_eq!(c.files.len(), 1);
    assert_eq!(c.hints.len(), 1);
    assert_eq!(c.hints[0].cost, 50);
    assert_eq!(c.solved_by_me, Some(true));
  }

  #[test]
  fn ctfd_challenge_to_domain_conversion() {
    let ctfd = CtfdChallenge {
      id: 1,
      name: "Test".into(),
      category: "web".into(),
      description: "desc".into(),
      value: 100,
      solves: 5,
      solved_by_me: Some(true),
      files: vec!["/files/abc/data.bin?token=x".into()],
      tags: vec![serde_json::json!({"value": "easy"})],
      hints: vec![CtfdHint { id: 10, content: Some("hint".into()), cost: 0 }],
    };
    let challenge: Challenge = ctfd.into();
    assert_eq!(challenge.id, "1");
    assert!(challenge.solved_by_me);
    assert_eq!(challenge.files[0].name, "data.bin");
    assert_eq!(challenge.tags, vec!["easy"]);
    assert_eq!(challenge.hints[0].content.as_deref(), Some("hint"));
  }

  #[test]
  fn ctfd_file_name_extraction() {
    let ctfd = CtfdChallenge {
      id: 1,
      name: "t".into(),
      category: "c".into(),
      description: String::new(),
      value: 0,
      solves: 0,
      solved_by_me: None,
      files: vec!["/files/abc123/challenge.py?token=xyz".into(), "/files/def456/flag.enc".into()],
      tags: vec![],
      hints: vec![],
    };
    let challenge: Challenge = ctfd.into();
    assert_eq!(challenge.files[0].name, "challenge.py");
    assert_eq!(challenge.files[1].name, "flag.enc");
  }

  #[test]
  fn auth_method_session_cookie() {
    let plat = CtfdPlatform::new("https://ctf.example.com".into(), "abc123.XYZdef456".into());
    assert!(matches!(plat.auth, AuthMethod::Session));
  }

  #[test]
  fn auth_method_api_token() {
    let plat = CtfdPlatform::new("https://ctf.example.com".into(), "abcdef1234567890".into());
    assert!(matches!(plat.auth, AuthMethod::Token(_)));
  }

  #[test]
  fn auth_method_ctfd_prefix_token() {
    let plat = CtfdPlatform::new("https://ctf.example.com".into(), "ctfd_abcdef.1234567890".into());
    assert!(matches!(plat.auth, AuthMethod::Token(_)));
  }

  #[test]
  fn auth_method_pure_hex_is_token() {
    // Pure hex string without dots — definitely an API token
    let plat = CtfdPlatform::new("https://ctf.example.com".into(), "a1b2c3d4e5f6".into());
    assert!(matches!(plat.auth, AuthMethod::Token(_)));
  }

  #[test]
  fn auth_method_flask_session_with_three_parts() {
    // Typical Flask session: base64.timestamp.signature
    let plat =
      CtfdPlatform::new("https://ctf.example.com".into(), "eyJpZCI6MX0.ZxYzAw.aBcDeFgHiJkLmNoPqRsTuVwXyZ".into());
    assert!(matches!(plat.auth, AuthMethod::Session));
  }
}
