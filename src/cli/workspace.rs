use std::path::Path;

use colored::Colorize;

use crate::cli::auth;
use crate::config;
use crate::config::types::{PlatformConfig, ScaffoldConfig, WorkspaceConfig, WorkspaceSection};
use crate::error::Result;
use crate::platform;
use crate::workspace::{scaffold, state};

pub async fn handle_init(
  name: &str,
  url: Option<&str>,
  platform_type: Option<&str>,
) -> Result<()> {
  let dir = Path::new(name);

  if dir.join(".ctf.toml").exists() {
    println!("{} Workspace already initialized at {name}/", "!".yellow().bold());
    return Ok(());
  }

  std::fs::create_dir_all(dir)?;

  let url = match url {
    Some(u) => u.to_string(),
    None => {
      dialoguer::Input::new()
        .with_prompt("Platform URL")
        .interact_text()
        .map_err(|e| crate::error::Error::Config(e.to_string()))?
    }
  };

  let config = WorkspaceConfig {
    platform: PlatformConfig {
      platform_type: platform_type.map(|s| s.to_string()),
      url,
    },
    workspace: WorkspaceSection {
      name: name.to_string(),
    },
    scaffold: ScaffoldConfig::default(),
  };

  let config_str = toml::to_string_pretty(&config)?;
  std::fs::write(dir.join(".ctf.toml"), config_str)?;

  // Initialize empty state
  state::init_state(dir)?;

  println!(
    "{} Initialized workspace at {}/",
    "✓".green().bold(),
    name.bold()
  );
  println!("  Run `cd {name} && ctf auth login` to authenticate.");

  Ok(())
}

pub async fn handle_sync(workspace_root: &Path, full: bool) -> Result<()> {
  let ws_config = config::load_workspace_config(workspace_root)?;
  let token = auth::get_token(&ws_config.workspace.name)?;
  let plat = platform::create_platform(&ws_config.platform, &token).await?;

  println!("Syncing challenges...");
  let challenges = plat.challenges().await?;

  let mut new_count = 0;
  let mut file_count = 0;

  for challenge in &challenges {
    let created = scaffold::scaffold_challenge(workspace_root, challenge, &ws_config.scaffold)?;
    if created {
      new_count += 1;
    }

    // Download files
    let challenge_dir = scaffold::challenge_dir(workspace_root, challenge, &ws_config.scaffold);
    let dist_dir = challenge_dir.join("dist");

    for file in &challenge.files {
      let dest = dist_dir.join(&file.name);
      if !dest.exists() {
        std::fs::create_dir_all(&dist_dir)?;
        if let Err(e) = plat.download_file(file, &dest).await {
          eprintln!("  Warning: failed to download {}: {e}", file.name);
        } else {
          file_count += 1;
        }
      }
    }
  }

  // Update state
  if full {
    use futures::stream::{self, StreamExt};

    println!("Fetching full challenge details...");
    let pb = indicatif::ProgressBar::new(challenges.len() as u64);
    pb.set_style(
      indicatif::ProgressStyle::default_bar()
        .template("{bar:40.cyan/blue} {pos}/{len} {msg}")
        .unwrap(),
    );

    let detailed: Vec<_> = stream::iter(challenges.iter().map(|c| {
      let platform = plat.as_ref();
      let id = c.id.clone();
      let pb = pb.clone();
      async move {
        let result = platform.challenge(&id).await;
        pb.inc(1);
        result
      }
    }))
    .buffer_unordered(5)
    .filter_map(|r| async { r.ok() })
    .collect()
    .await;

    pb.finish_with_message("done");
    state::update_sync_full(workspace_root, &detailed)?;
  } else {
    state::update_sync(workspace_root, &challenges)?;
  }

  println!(
    "{} Synced {} challenges ({} new, {} files downloaded){}",
    "✓".green().bold(),
    challenges.len(),
    new_count,
    file_count,
    if full { " with full details cached" } else { "" }
  );

  Ok(())
}

pub async fn handle_status(workspace_root: &Path) -> Result<()> {
  let ws_config = config::load_workspace_config(workspace_root)?;
  let token = auth::get_token(&ws_config.workspace.name)?;
  let plat = platform::create_platform(&ws_config.platform, &token).await?;

  let info = plat.whoami().await?;
  let challenges = plat.challenges().await?;

  let total = challenges.len();
  let solved = challenges.iter().filter(|c| c.solved_by_me).count();
  let total_points: u32 = challenges.iter().map(|c| c.value).sum();
  let solved_points: u32 = challenges
    .iter()
    .filter(|c| c.solved_by_me)
    .map(|c| c.value)
    .sum();

  println!(
    "  {} | Team: {} | Score: {}/{}",
    ws_config.workspace.name.bold().cyan(),
    info.name.bold(),
    solved_points,
    total_points,
  );
  if let Some(rank) = info.rank {
    println!("  Rank: #{rank}");
  }
  println!();

  // Group by category
  let mut categories: std::collections::BTreeMap<String, (u32, u32, u32)> =
    std::collections::BTreeMap::new();
  for c in &challenges {
    let entry = categories.entry(c.category.clone()).or_default();
    entry.1 += 1; // total
    entry.2 += c.value; // total points
    if c.solved_by_me {
      entry.0 += 1; // solved
    }
  }

  println!(
    "  {:<15} {:<10} {:<10}",
    "Category".bold(),
    "Solved".bold(),
    "Points".bold()
  );
  println!("  {}", "-".repeat(35));
  for (cat, (solved_c, total_c, _points)) in &categories {
    let pct = if *total_c > 0 {
      (*solved_c as f32 / *total_c as f32 * 100.0) as u32
    } else {
      0
    };
    println!("  {cat:<15} {solved_c}/{total_c:<7} {pct}%");
  }
  println!();
  println!(
    "  Total: {solved}/{total} challenges solved ({solved_points}/{total_points} pts)"
  );

  Ok(())
}

pub async fn handle_files(
  workspace_root: &Path,
  id_or_name: &str,
) -> Result<()> {
  let ws_config = config::load_workspace_config(workspace_root)?;
  let token = auth::get_token(&ws_config.workspace.name)?;
  let plat = platform::create_platform(&ws_config.platform, &token).await?;

  let challenges = plat.challenges().await?;
  let challenge =
    crate::cli::challenge::resolve_challenge(plat.as_ref(), id_or_name, &challenges).await?;

  if challenge.files.is_empty() {
    println!("No files attached to this challenge.");
    return Ok(());
  }

  let challenge_dir =
    scaffold::challenge_dir(workspace_root, &challenge, &ws_config.scaffold);
  let dist_dir = challenge_dir.join("dist");
  std::fs::create_dir_all(&dist_dir)?;

  for file in &challenge.files {
    let dest = dist_dir.join(&file.name);
    print!("  Downloading {}...", file.name);
    plat.download_file(file, &dest).await?;
    println!(" {}", "✓".green());
  }

  println!(
    "{} Downloaded {} files to {}",
    "✓".green().bold(),
    challenge.files.len(),
    dist_dir.display()
  );

  Ok(())
}
