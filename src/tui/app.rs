use std::path::PathBuf;
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyEvent};

use crate::error::Result;
use crate::workspace::state::{self, ChallengeState, ChallengeStatus, WorkspaceState};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ActivePanel {
  Challenges,
  Queue,
  Notifications,
}

impl ActivePanel {
  pub fn next(self) -> Self {
    match self {
      Self::Challenges => Self::Queue,
      Self::Queue => Self::Notifications,
      Self::Notifications => Self::Challenges,
    }
  }
}

pub struct App {
  pub workspace_root: PathBuf,
  pub workspace_name: String,
  pub state: WorkspaceState,
  pub active_panel: ActivePanel,
  pub should_quit: bool,
  pub challenge_scroll: usize,
  pub notif_scroll: usize,
}

impl App {
  pub fn new(workspace_root: PathBuf, workspace_name: String) -> Result<Self> {
    let state = state::load_state(&workspace_root)?;
    Ok(Self {
      workspace_root,
      workspace_name,
      state,
      active_panel: ActivePanel::Challenges,
      should_quit: false,
      challenge_scroll: 0,
      notif_scroll: 0,
    })
  }

  pub fn reload_state(&mut self) {
    if let Ok(new_state) = state::load_state(&self.workspace_root) {
      self.state = new_state;
    }
  }

  pub fn handle_key(&mut self, key: KeyEvent) {
    match key.code {
      KeyCode::Char('q') | KeyCode::Esc => self.should_quit = true,
      KeyCode::Tab => self.active_panel = self.active_panel.next(),
      KeyCode::Char('r') => self.reload_state(),
      KeyCode::Down | KeyCode::Char('j') => self.scroll_down(),
      KeyCode::Up | KeyCode::Char('k') => self.scroll_up(),
      _ => {}
    }
  }

  fn scroll_down(&mut self) {
    match self.active_panel {
      ActivePanel::Challenges => {
        if self.challenge_scroll < self.state.challenges.len().saturating_sub(1) {
          self.challenge_scroll += 1;
        }
      }
      ActivePanel::Notifications => {
        if self.notif_scroll < self.state.notifications.len().saturating_sub(1) {
          self.notif_scroll += 1;
        }
      }
      ActivePanel::Queue => {}
    }
  }

  fn scroll_up(&mut self) {
    match self.active_panel {
      ActivePanel::Challenges => {
        self.challenge_scroll = self.challenge_scroll.saturating_sub(1);
      }
      ActivePanel::Notifications => {
        self.notif_scroll = self.notif_scroll.saturating_sub(1);
      }
      ActivePanel::Queue => {}
    }
  }

  pub fn solved_count(&self) -> usize {
    self.state.challenges.values().filter(|c| c.status == ChallengeStatus::Solved).count()
  }

  pub fn total_points(&self) -> u32 {
    self.state.challenges.values().filter(|c| c.status == ChallengeStatus::Solved).filter_map(|c| c.points).sum()
  }

  pub fn sorted_challenges(&self) -> Vec<&ChallengeState> {
    let mut challenges: Vec<&ChallengeState> = self.state.challenges.values().collect();
    challenges.sort_by(|a, b| {
      let status_ord = |s: &ChallengeStatus| match s {
        ChallengeStatus::InProgress => 0,
        ChallengeStatus::Unsolved => 1,
        ChallengeStatus::Solved => 2,
      };
      status_ord(&a.status)
        .cmp(&status_ord(&b.status))
        .then_with(|| a.category.cmp(&b.category))
        .then_with(|| a.name.cmp(&b.name))
    });
    challenges
  }

  pub fn categories(&self) -> Vec<(String, usize, usize)> {
    let mut cats: std::collections::BTreeMap<String, (usize, usize)> = std::collections::BTreeMap::new();
    for c in self.state.challenges.values() {
      let entry = cats.entry(c.category.clone()).or_insert((0, 0));
      entry.1 += 1;
      if c.status == ChallengeStatus::Solved {
        entry.0 += 1;
      }
    }
    cats.into_iter().map(|(cat, (solved, total))| (cat, solved, total)).collect()
  }
}

pub async fn run_dashboard(workspace_root: PathBuf, workspace_name: String) -> Result<()> {
  let mut terminal = ratatui::init();
  let mut app = App::new(workspace_root, workspace_name)?;
  let poll_interval = Duration::from_secs(2);
  let mut last_poll = Instant::now();

  loop {
    terminal.draw(|frame| super::ui::draw(frame, &app)).map_err(crate::error::Error::Io)?;

    if event::poll(Duration::from_millis(250)).unwrap_or(false) {
      if let Ok(Event::Key(key)) = event::read() {
        app.handle_key(key);
      }
    }

    if app.should_quit {
      break;
    }

    if last_poll.elapsed() >= poll_interval {
      app.reload_state();
      last_poll = Instant::now();
    }
  }

  ratatui::restore();
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::collections::HashMap;

  use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

  fn make_challenge(name: &str, category: &str, status: ChallengeStatus, points: Option<u32>) -> ChallengeState {
    ChallengeState {
      id: name.to_lowercase().replace(' ', "-"),
      name: name.into(),
      category: category.into(),
      status,
      solved_at: None,
      points,
      flag: None,
      description: None,
      hints: None,
      files: None,
      tags: None,
      details_fetched_at: None,
      methodology: None,
      tools_used: None,
    }
  }

  fn make_app(challenges: Vec<ChallengeState>) -> App {
    let mut map = HashMap::new();
    for c in challenges {
      map.insert(c.name.to_lowercase(), c);
    }
    App {
      workspace_root: PathBuf::from("/tmp"),
      workspace_name: "test".into(),
      state: WorkspaceState {
        last_sync: None,
        challenges: map,
        notifications: vec![],
        orchestration: Default::default(),
      },
      active_panel: ActivePanel::Challenges,
      should_quit: false,
      challenge_scroll: 0,
      notif_scroll: 0,
    }
  }

  // ── ActivePanel::next cycle tests ────────────────────────────────────────

  #[test]
  fn active_panel_cycles_challenges_to_queue() {
    assert_eq!(ActivePanel::Challenges.next(), ActivePanel::Queue);
  }

  #[test]
  fn active_panel_cycles_queue_to_notifications() {
    assert_eq!(ActivePanel::Queue.next(), ActivePanel::Notifications);
  }

  #[test]
  fn active_panel_cycles_notifications_to_challenges() {
    assert_eq!(ActivePanel::Notifications.next(), ActivePanel::Challenges);
  }

  // ── solved_count tests ───────────────────────────────────────────────────

  #[test]
  fn solved_count_with_mixed_statuses() {
    let app = make_app(vec![
      make_challenge("A", "crypto", ChallengeStatus::Solved, Some(100)),
      make_challenge("B", "web", ChallengeStatus::Unsolved, Some(200)),
      make_challenge("C", "pwn", ChallengeStatus::Solved, Some(300)),
      make_challenge("D", "rev", ChallengeStatus::InProgress, Some(150)),
    ]);
    assert_eq!(app.solved_count(), 2);
  }

  #[test]
  fn solved_count_with_none_solved() {
    let app = make_app(vec![
      make_challenge("A", "crypto", ChallengeStatus::Unsolved, Some(100)),
      make_challenge("B", "web", ChallengeStatus::InProgress, Some(200)),
    ]);
    assert_eq!(app.solved_count(), 0);
  }

  #[test]
  fn solved_count_empty_state() {
    let app = make_app(vec![]);
    assert_eq!(app.solved_count(), 0);
  }

  // ── total_points tests ───────────────────────────────────────────────────

  #[test]
  fn total_points_sums_only_solved() {
    let app = make_app(vec![
      make_challenge("A", "crypto", ChallengeStatus::Solved, Some(100)),
      make_challenge("B", "web", ChallengeStatus::Unsolved, Some(200)),
      make_challenge("C", "pwn", ChallengeStatus::Solved, Some(300)),
    ]);
    assert_eq!(app.total_points(), 400);
  }

  #[test]
  fn total_points_zero_when_none_solved() {
    let app = make_app(vec![make_challenge("A", "crypto", ChallengeStatus::Unsolved, Some(100))]);
    assert_eq!(app.total_points(), 0);
  }

  #[test]
  fn total_points_skips_none_points() {
    let app = make_app(vec![
      make_challenge("A", "crypto", ChallengeStatus::Solved, None),
      make_challenge("B", "web", ChallengeStatus::Solved, Some(200)),
    ]);
    assert_eq!(app.total_points(), 200);
  }

  // ── sorted_challenges tests ──────────────────────────────────────────────

  #[test]
  fn sorted_challenges_by_status_then_category_then_name() {
    let app = make_app(vec![
      make_challenge("Zebra", "crypto", ChallengeStatus::Solved, Some(100)),
      make_challenge("Alpha", "web", ChallengeStatus::Unsolved, Some(200)),
      make_challenge("Beta", "crypto", ChallengeStatus::Unsolved, Some(150)),
      make_challenge("Gamma", "crypto", ChallengeStatus::InProgress, Some(300)),
    ]);
    let sorted = app.sorted_challenges();
    // InProgress first, then Unsolved, then Solved
    assert_eq!(sorted[0].name, "Gamma"); // InProgress
                                         // Unsolved: crypto before web
    assert_eq!(sorted[1].name, "Beta"); // Unsolved, crypto
    assert_eq!(sorted[2].name, "Alpha"); // Unsolved, web
    assert_eq!(sorted[3].name, "Zebra"); // Solved
  }

  // ── categories tests ─────────────────────────────────────────────────────

  #[test]
  fn categories_groups_correctly() {
    let app = make_app(vec![
      make_challenge("A", "crypto", ChallengeStatus::Solved, Some(100)),
      make_challenge("B", "crypto", ChallengeStatus::Unsolved, Some(200)),
      make_challenge("C", "web", ChallengeStatus::Solved, Some(150)),
    ]);
    let cats = app.categories();
    // BTreeMap so categories are sorted alphabetically
    assert_eq!(cats.len(), 2);
    assert_eq!(cats[0], ("crypto".into(), 1, 2)); // 1 solved, 2 total
    assert_eq!(cats[1], ("web".into(), 1, 1)); // 1 solved, 1 total
  }

  // ── handle_key tests ─────────────────────────────────────────────────────

  #[test]
  fn handle_key_q_quits() {
    let mut app = make_app(vec![]);
    let key = KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE);
    app.handle_key(key);
    assert!(app.should_quit);
  }

  #[test]
  fn handle_key_esc_quits() {
    let mut app = make_app(vec![]);
    let key = KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE);
    app.handle_key(key);
    assert!(app.should_quit);
  }

  #[test]
  fn handle_key_tab_cycles_panel() {
    let mut app = make_app(vec![]);
    assert_eq!(app.active_panel, ActivePanel::Challenges);

    let tab = KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE);
    app.handle_key(tab);
    assert_eq!(app.active_panel, ActivePanel::Queue);

    app.handle_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
    assert_eq!(app.active_panel, ActivePanel::Notifications);

    app.handle_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
    assert_eq!(app.active_panel, ActivePanel::Challenges);
  }

  #[test]
  fn handle_key_scroll_down_increments() {
    let mut app = make_app(vec![
      make_challenge("A", "crypto", ChallengeStatus::Unsolved, Some(100)),
      make_challenge("B", "web", ChallengeStatus::Unsolved, Some(200)),
      make_challenge("C", "pwn", ChallengeStatus::Unsolved, Some(300)),
    ]);
    assert_eq!(app.challenge_scroll, 0);

    let down = KeyEvent::new(KeyCode::Down, KeyModifiers::NONE);
    app.handle_key(down);
    assert_eq!(app.challenge_scroll, 1);

    app.handle_key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE));
    assert_eq!(app.challenge_scroll, 2);

    // Should not go beyond len-1
    app.handle_key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
    assert_eq!(app.challenge_scroll, 2);
  }

  #[test]
  fn handle_key_scroll_up_decrements() {
    let mut app = make_app(vec![
      make_challenge("A", "crypto", ChallengeStatus::Unsolved, Some(100)),
      make_challenge("B", "web", ChallengeStatus::Unsolved, Some(200)),
    ]);
    app.challenge_scroll = 1;

    let up = KeyEvent::new(KeyCode::Up, KeyModifiers::NONE);
    app.handle_key(up);
    assert_eq!(app.challenge_scroll, 0);

    // Should not go below 0
    app.handle_key(KeyEvent::new(KeyCode::Char('k'), KeyModifiers::NONE));
    assert_eq!(app.challenge_scroll, 0);
  }
}
