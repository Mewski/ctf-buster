use ratatui::prelude::*;
use ratatui::widgets::*;

use crate::workspace::state::ChallengeStatus;

use super::app::{ActivePanel, App};

pub fn draw(frame: &mut Frame, app: &App) {
  let root = Layout::vertical([
    Constraint::Length(3),
    Constraint::Min(0),
    Constraint::Length(1),
  ])
  .split(frame.area());

  draw_header(frame, root[0], app);
  draw_body(frame, root[1], app);
  draw_footer(frame, root[2]);
}

fn draw_header(frame: &mut Frame, area: Rect, app: &App) {
  let sync_ago = app
    .state
    .last_sync
    .map(|t| {
      let secs = (chrono::Utc::now() - t).num_seconds();
      if secs < 60 {
        format!("{secs}s ago")
      } else if secs < 3600 {
        format!("{}m ago", secs / 60)
      } else {
        format!("{}h ago", secs / 3600)
      }
    })
    .unwrap_or_else(|| "never".into());

  let line = Line::from(vec![
    Span::styled(
      format!(" CTF: {} ", app.workspace_name),
      Style::default().fg(Color::Cyan).bold(),
    ),
    Span::raw(" | "),
    Span::styled(
      format!(
        "Solved: {}/{} ",
        app.solved_count(),
        app.state.challenges.len()
      ),
      Style::default().fg(Color::Green).bold(),
    ),
    Span::styled(
      format!("({} pts) ", app.total_points()),
      Style::default().fg(Color::Yellow),
    ),
    Span::raw(" | "),
    Span::raw(format!("Synced: {sync_ago} ")),
  ]);

  let block = Block::bordered()
    .title(" ctf-buster ")
    .border_style(Style::default().fg(Color::DarkGray));
  let para = Paragraph::new(line).block(block);
  frame.render_widget(para, area);
}

fn draw_body(frame: &mut Frame, area: Rect, app: &App) {
  let cols = Layout::horizontal([Constraint::Percentage(60), Constraint::Percentage(40)])
    .split(area);

  let left =
    Layout::vertical([Constraint::Percentage(70), Constraint::Percentage(30)]).split(cols[0]);

  let right =
    Layout::vertical([Constraint::Percentage(60), Constraint::Percentage(40)]).split(cols[1]);

  draw_challenges_table(frame, left[0], app);
  draw_categories(frame, left[1], app);
  draw_queue(frame, right[0], app);
  draw_notifications(frame, right[1], app);
}

fn panel_border(title: &str, active: bool) -> Block<'_> {
  Block::bordered()
    .title(format!(" {title} "))
    .border_style(if active {
      Style::default().fg(Color::Cyan)
    } else {
      Style::default().fg(Color::DarkGray)
    })
}

fn draw_challenges_table(frame: &mut Frame, area: Rect, app: &App) {
  let challenges = app.sorted_challenges();

  let header = Row::new(["Name", "Category", "Pts", "Status"])
    .style(Style::default().bold().fg(Color::White))
    .bottom_margin(1);

  let rows = challenges.iter().map(|c| {
    let (status_str, style) = match c.status {
      ChallengeStatus::Solved => ("[OK]", Style::default().fg(Color::Green)),
      ChallengeStatus::InProgress => ("[..]", Style::default().fg(Color::Yellow)),
      ChallengeStatus::Unsolved => ("[  ]", Style::default().fg(Color::DarkGray)),
    };
    Row::new([
      c.name.clone(),
      c.category.clone(),
      c.points.map(|p| p.to_string()).unwrap_or_default(),
      status_str.to_string(),
    ])
    .style(style)
  });

  let table = Table::new(
    rows,
    [
      Constraint::Percentage(40),
      Constraint::Percentage(25),
      Constraint::Percentage(15),
      Constraint::Percentage(20),
    ],
  )
  .header(header)
  .block(panel_border("Challenges", app.active_panel == ActivePanel::Challenges));

  let mut table_state = TableState::default().with_offset(app.challenge_scroll);
  frame.render_stateful_widget(table, area, &mut table_state);
}

fn draw_queue(frame: &mut Frame, area: Rect, app: &App) {
  let orch = &app.state.orchestration;
  let mut lines = Vec::new();

  lines.push(Line::from(Span::styled(
    format!("Queued: {}", orch.queue.len()),
    Style::default().fg(Color::White).bold(),
  )));
  for q in orch.queue.iter().take(10) {
    lines.push(Line::from(
      format!("  {} ({}, p{})", q.name, q.category, q.priority)
    ));
  }
  if orch.queue.len() > 10 {
    lines.push(Line::from(
      format!("  ... and {} more", orch.queue.len() - 10)
    ).style(Style::default().fg(Color::DarkGray)));
  }

  lines.push(Line::from(""));
  lines.push(Line::from(Span::styled(
    format!("In Progress: {}", orch.in_progress.len()),
    Style::default().fg(Color::Yellow).bold(),
  )));
  for name in &orch.in_progress {
    lines.push(
      Line::from(format!("  {name}")).style(Style::default().fg(Color::Yellow)),
    );
  }

  lines.push(Line::from(""));
  lines.push(Line::from(Span::styled(
    format!("Failed: {}", orch.failed.len()),
    Style::default().fg(Color::Red).bold(),
  )));
  for f in orch.failed.iter().take(5) {
    lines.push(
      Line::from(format!("  {} ({})", f.name, f.notes))
        .style(Style::default().fg(Color::Red)),
    );
  }

  let block = panel_border("Queue", app.active_panel == ActivePanel::Queue);
  let para = Paragraph::new(lines).block(block).wrap(Wrap { trim: true });
  frame.render_widget(para, area);
}

fn draw_categories(frame: &mut Frame, area: Rect, app: &App) {
  let cats = app.categories();
  let mut lines = Vec::new();

  for (cat, solved, total) in &cats {
    let style = if *solved == *total && *total > 0 {
      Style::default().fg(Color::Green)
    } else if *solved > 0 {
      Style::default().fg(Color::Yellow)
    } else {
      Style::default().fg(Color::DarkGray)
    };
    lines.push(Line::from(format!("  {cat:<16} {solved}/{total}")).style(style));
  }

  if cats.is_empty() {
    lines.push(Line::from("  No challenges synced").style(Style::default().fg(Color::DarkGray)));
  }

  let block = Block::bordered()
    .title(" Categories ")
    .border_style(Style::default().fg(Color::DarkGray));
  let para = Paragraph::new(lines).block(block);
  frame.render_widget(para, area);
}

fn draw_notifications(frame: &mut Frame, area: Rect, app: &App) {
  let mut lines = Vec::new();

  if app.state.notifications.is_empty() {
    lines.push(
      Line::from("  No notifications").style(Style::default().fg(Color::DarkGray)),
    );
  } else {
    for (i, n) in app.state.notifications.iter().enumerate() {
      lines.push(Line::from(vec![
        Span::styled(format!("[{}] ", i + 1), Style::default().fg(Color::Cyan)),
        Span::styled(&n.title, Style::default().bold()),
      ]));
      if !n.content.is_empty() {
        let preview: String = n.content.chars().take(60).collect();
        lines.push(
          Line::from(format!("    {preview}")).style(Style::default().fg(Color::DarkGray)),
        );
      }
    }
  }

  let block = panel_border(
    "Notifications",
    app.active_panel == ActivePanel::Notifications,
  );
  let para = Paragraph::new(lines)
    .block(block)
    .wrap(Wrap { trim: true });
  frame.render_widget(para, area);
}

fn draw_footer(frame: &mut Frame, area: Rect) {
  let spans = vec![
    Span::styled(" Tab", Style::default().fg(Color::Cyan).bold()),
    Span::raw(": panel  "),
    Span::styled("q", Style::default().fg(Color::Cyan).bold()),
    Span::raw(": quit  "),
    Span::styled("r", Style::default().fg(Color::Cyan).bold()),
    Span::raw(": refresh  "),
    Span::styled("j/k", Style::default().fg(Color::Cyan).bold()),
    Span::raw(": scroll"),
  ];
  frame.render_widget(Paragraph::new(Line::from(spans)), area);
}
