use std::path::{Path, PathBuf};

use crate::config::types::ScaffoldConfig;
use crate::error::Result;
use crate::platform::types::Challenge;

/// Returns the directory path for a challenge based on the scaffold template.
pub fn challenge_dir(
  workspace_root: &Path,
  challenge: &Challenge,
  config: &ScaffoldConfig,
) -> PathBuf {
  let path = config
    .template
    .replace("{category}", &sanitize_name(&challenge.category))
    .replace("{name}", &sanitize_name(&challenge.name));
  workspace_root.join(path)
}

/// Scaffold a challenge directory. Returns true if the directory was newly created.
pub fn scaffold_challenge(
  workspace_root: &Path,
  challenge: &Challenge,
  config: &ScaffoldConfig,
) -> Result<bool> {
  let dir = challenge_dir(workspace_root, challenge, config);

  if dir.exists() {
    return Ok(false);
  }

  std::fs::create_dir_all(&dir)?;

  if config.create_solve_file {
    let solve_path = dir.join("solve.py");
    if !solve_path.exists() {
      std::fs::write(&solve_path, generate_solve_template(challenge))?;
    }
  }

  if config.create_notes_file {
    let notes_path = dir.join("notes.md");
    if !notes_path.exists() {
      std::fs::write(&notes_path, generate_notes_template(challenge))?;
    }
  }

  Ok(true)
}

fn sanitize_name(name: &str) -> String {
  name
    .to_lowercase()
    .chars()
    .map(|c| {
      if c.is_alphanumeric() || c == '-' || c == '_' {
        c
      } else if c == ' ' {
        '-'
      } else {
        '_'
      }
    })
    .collect()
}

fn generate_solve_template(challenge: &Challenge) -> String {
  format!(
    r#"#!/usr/bin/env python3
"""
{name} ({category}, {value} pts)
"""

from pwn import *

# challenge files in ./dist/
"#,
    name = challenge.name,
    category = challenge.category,
    value = challenge.value,
  )
}

fn generate_notes_template(challenge: &Challenge) -> String {
  format!(
    r#"# {name}

**Category:** {category}
**Points:** {value}
**Solves:** {solves}

## Description

{description}

## Notes

"#,
    name = challenge.name,
    category = challenge.category,
    value = challenge.value,
    solves = challenge.solves,
    description = challenge.description,
  )
}

#[cfg(test)]
mod tests {
  use super::*;
  use tempfile::TempDir;

  fn make_challenge(name: &str, category: &str) -> Challenge {
    Challenge {
      id: "1".into(),
      name: name.into(),
      category: category.into(),
      description: "A test challenge".into(),
      value: 100,
      solves: 5,
      solved_by_me: false,
      files: vec![],
      tags: vec![],
      hints: vec![],
    }
  }

  #[test]
  fn sanitize_spaces_to_hyphens() {
    assert_eq!(sanitize_name("my challenge"), "my-challenge");
  }

  #[test]
  fn sanitize_special_chars() {
    assert_eq!(sanitize_name("RSA!@#"), "rsa___");
  }

  #[test]
  fn sanitize_preserves_hyphens_and_underscores() {
    assert_eq!(sanitize_name("my-test_challenge"), "my-test_challenge");
  }

  #[test]
  fn sanitize_uppercase_to_lowercase() {
    assert_eq!(sanitize_name("CryptoHack"), "cryptohack");
  }

  #[test]
  fn challenge_dir_default_template() {
    let c = make_challenge("Easy RSA", "Crypto");
    let config = ScaffoldConfig::default();
    let dir = challenge_dir(Path::new("/ws"), &c, &config);
    assert_eq!(dir, Path::new("/ws/crypto/easy-rsa"));
  }

  #[test]
  fn challenge_dir_custom_template() {
    let c = make_challenge("Easy RSA", "Crypto");
    let config = ScaffoldConfig {
      template: "{name}".into(),
      create_solve_file: false,
      create_notes_file: false,
    };
    let dir = challenge_dir(Path::new("/ws"), &c, &config);
    assert_eq!(dir, Path::new("/ws/easy-rsa"));
  }

  #[test]
  fn scaffold_creates_directory_and_files() {
    let dir = TempDir::new().unwrap();
    let c = make_challenge("Test", "Web");
    let config = ScaffoldConfig::default();

    let created = scaffold_challenge(dir.path(), &c, &config).unwrap();
    assert!(created);

    let challenge_path = dir.path().join("web/test");
    assert!(challenge_path.exists());
    assert!(challenge_path.join("solve.py").exists());
    assert!(challenge_path.join("notes.md").exists());
  }

  #[test]
  fn scaffold_idempotent() {
    let dir = TempDir::new().unwrap();
    let c = make_challenge("Test", "Web");
    let config = ScaffoldConfig::default();

    assert!(scaffold_challenge(dir.path(), &c, &config).unwrap());
    assert!(!scaffold_challenge(dir.path(), &c, &config).unwrap());
  }

  #[test]
  fn solve_template_contains_name() {
    let c = make_challenge("My Challenge", "Crypto");
    let content = generate_solve_template(&c);
    assert!(content.contains("My Challenge"));
    assert!(content.contains("Crypto"));
    assert!(content.contains("100 pts"));
  }

  #[test]
  fn notes_template_contains_description() {
    let c = make_challenge("My Challenge", "Crypto");
    let content = generate_notes_template(&c);
    assert!(content.contains("# My Challenge"));
    assert!(content.contains("A test challenge"));
    assert!(content.contains("**Points:** 100"));
  }
}
