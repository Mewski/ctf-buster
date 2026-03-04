mod cli;
mod config;
mod error;
mod mcp;
mod output;
mod platform;
mod tui;
mod workspace;

use clap::Parser;

use cli::{Cli, Command};

#[tokio::main]
async fn main() {
  tracing_subscriber::fmt()
    .with_env_filter(
      tracing_subscriber::EnvFilter::from_default_env()
        .add_directive("ctf_buster=info".parse().expect("valid directive")),
    )
    .without_time()
    .init();

  let cli = Cli::parse();

  if let Err(e) = run(cli).await {
    eprintln!("Error: {e}");
    std::process::exit(1);
  }
}

async fn run(cli: Cli) -> error::Result<()> {
  match cli.command {
    Command::Auth { command } => {
      use cli::auth::AuthCommand;
      // Try to find workspace context for auth commands
      let cwd = std::env::current_dir()?;
      let ws_root = config::find_workspace_root(&cwd);

      match command {
        AuthCommand::Login => {
          if let Some(root) = &ws_root {
            let ws_config = config::load_workspace_config(root)?;
            cli::auth::handle_login(&ws_config.workspace.name, &ws_config.platform.url).await?;
          } else {
            cli::auth::handle_login_interactive().await?;
          }
        }
        AuthCommand::Logout => {
          let root = ws_root.ok_or(error::Error::NotInWorkspace)?;
          let ws_config = config::load_workspace_config(&root)?;
          cli::auth::handle_logout(&ws_config.workspace.name).await?;
        }
        AuthCommand::Status => {
          let root = ws_root.ok_or(error::Error::NotInWorkspace)?;
          let ws_config = config::load_workspace_config(&root)?;
          cli::auth::handle_status(&ws_config.workspace.name, &ws_config.platform.url).await?;
        }
      }
    }

    Command::Init {
      name,
      url,
      platform_type,
    } => {
      cli::workspace::handle_init(&name, url.as_deref(), platform_type.as_deref()).await?;
    }

    Command::Sync { full } => {
      let cwd = std::env::current_dir()?;
      let root = config::find_workspace_root(&cwd).ok_or(error::Error::NotInWorkspace)?;
      cli::workspace::handle_sync(&root, full).await?;
    }

    Command::Challenges {
      category,
      unsolved,
      solved,
    } => {
      let (plat, _root) = load_platform().await?;
      cli::challenge::handle_list(
        plat.as_ref(),
        category.as_deref(),
        unsolved,
        solved,
        &cli.output,
      )
      .await?;
    }

    Command::Challenge {
      id_or_name,
      download,
    } => {
      let (plat, root) = load_platform().await?;
      let challenges = plat.challenges().await?;
      cli::challenge::handle_show(plat.as_ref(), &id_or_name, &challenges).await?;

      if download {
        cli::workspace::handle_files(&root, &id_or_name).await?;
      }
    }

    Command::Submit { first, second } => {
      let (plat, root) = load_platform().await?;
      let challenges = plat.challenges().await?;
      cli::submit::handle_submit(
        plat.as_ref(),
        &first,
        second.as_deref(),
        &challenges,
        &root,
        &cli.output,
      )
      .await?;
    }

    Command::Scoreboard { limit } => {
      let (plat, _root) = load_platform().await?;
      cli::scoreboard::handle_scoreboard(plat.as_ref(), limit, &cli.output).await?;
    }

    Command::Status => {
      let cwd = std::env::current_dir()?;
      let root = config::find_workspace_root(&cwd).ok_or(error::Error::NotInWorkspace)?;
      cli::workspace::handle_status(&root).await?;
    }

    Command::Files { id_or_name } => {
      let cwd = std::env::current_dir()?;
      let root = config::find_workspace_root(&cwd).ok_or(error::Error::NotInWorkspace)?;
      cli::workspace::handle_files(&root, &id_or_name).await?;
    }

    Command::Dashboard => {
      let cwd = std::env::current_dir()?;
      let root = config::find_workspace_root(&cwd).ok_or(error::Error::NotInWorkspace)?;
      let ws_config = config::load_workspace_config(&root)?;
      tui::run_dashboard(root, ws_config.workspace.name).await?;
    }

    Command::Mcp { workspace, token } => {
      use rmcp::ServiceExt;
      use std::sync::Arc;

      // Resolve workspace: --workspace arg > CTF_WORKSPACE env > cwd auto-detect
      let root = if let Some(ws) = workspace {
        ws
      } else {
        let cwd = std::env::current_dir()?;
        config::find_workspace_root(&cwd).ok_or(error::Error::NotInWorkspace)?
      };

      let ws_config = config::load_workspace_config(&root)?;
      let resolved_token = cli::auth::get_token_with_config(
        &ws_config.workspace.name,
        ws_config.platform.token.as_deref(),
        token.as_deref(),
      )?;
      let plat = platform::create_platform(&ws_config.platform, &resolved_token).await?;
      let plat: Arc<dyn platform::Platform> = Arc::from(plat);

      let server = mcp::McpServer::new(plat, root, ws_config);
      let service = server
        .serve(rmcp::transport::stdio())
        .await
        .map_err(|e| error::Error::Mcp(e.to_string()))?;

      service
        .waiting()
        .await
        .map_err(|e| error::Error::Mcp(e.to_string()))?;
    }
  }

  Ok(())
}

async fn load_platform() -> error::Result<(Box<dyn platform::Platform>, std::path::PathBuf)> {
  let cwd = std::env::current_dir()?;
  let root = config::find_workspace_root(&cwd).ok_or(error::Error::NotInWorkspace)?;
  let ws_config = config::load_workspace_config(&root)?;
  let token = cli::auth::get_token_with_config(
    &ws_config.workspace.name,
    ws_config.platform.token.as_deref(),
    None,
  )?;
  let plat = platform::create_platform(&ws_config.platform, &token).await?;
  Ok((plat, root))
}
