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
    self.state
      .challenges
      .values()
      .filter(|c| c.status == ChallengeStatus::Solved)
      .count()
  }

  pub fn total_points(&self) -> u32 {
    self.state
      .challenges
      .values()
      .filter(|c| c.status == ChallengeStatus::Solved)
      .filter_map(|c| c.points)
      .sum()
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
    let mut cats: std::collections::BTreeMap<String, (usize, usize)> =
      std::collections::BTreeMap::new();
    for c in self.state.challenges.values() {
      let entry = cats.entry(c.category.clone()).or_insert((0, 0));
      entry.1 += 1;
      if c.status == ChallengeStatus::Solved {
        entry.0 += 1;
      }
    }
    cats
      .into_iter()
      .map(|(cat, (solved, total))| (cat, solved, total))
      .collect()
  }
}

pub async fn run_dashboard(workspace_root: PathBuf, workspace_name: String) -> Result<()> {
  let mut terminal = ratatui::init();
  let mut app = App::new(workspace_root, workspace_name)?;
  let poll_interval = Duration::from_secs(2);
  let mut last_poll = Instant::now();

  loop {
    terminal
      .draw(|frame| super::ui::draw(frame, &app))
      .map_err(crate::error::Error::Io)?;

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
