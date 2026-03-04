use colored::Colorize;
use tabled::{Table, Tabled};

use crate::platform::types::{Challenge, ScoreboardEntry};

#[derive(Tabled)]
struct ChallengeRow {
  #[tabled(rename = "ID")]
  id: String,
  #[tabled(rename = "Name")]
  name: String,
  #[tabled(rename = "Category")]
  category: String,
  #[tabled(rename = "Points")]
  value: u32,
  #[tabled(rename = "Solves")]
  solves: u32,
  #[tabled(rename = "Status")]
  status: String,
}

#[derive(Tabled)]
struct ScoreboardRow {
  #[tabled(rename = "#")]
  rank: u32,
  #[tabled(rename = "Team")]
  name: String,
  #[tabled(rename = "Score")]
  score: u32,
}

pub fn print_challenges(challenges: &[Challenge]) {
  if challenges.is_empty() {
    println!("No challenges found.");
    return;
  }

  let rows: Vec<ChallengeRow> = challenges
    .iter()
    .map(|c| ChallengeRow {
      id: c.id.clone(),
      name: c.name.clone(),
      category: c.category.clone(),
      value: c.value,
      solves: c.solves,
      status: if c.solved_by_me { "✓".green().to_string() } else { " ".to_string() },
    })
    .collect();

  let table = Table::new(rows).with(tabled::settings::Style::rounded()).to_string();
  println!("{table}");
  println!("  {} challenges ({} solved)", challenges.len(), challenges.iter().filter(|c| c.solved_by_me).count());
}

pub fn print_scoreboard(entries: &[ScoreboardEntry]) {
  if entries.is_empty() {
    println!("No scoreboard entries found.");
    return;
  }

  let rows: Vec<ScoreboardRow> =
    entries.iter().map(|e| ScoreboardRow { rank: e.rank, name: e.name.clone(), score: e.score }).collect();

  let table = Table::new(rows).with(tabled::settings::Style::rounded()).to_string();
  println!("{table}");
}
