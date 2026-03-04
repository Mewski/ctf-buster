pub mod auth;
pub mod challenge;
pub mod scoreboard;
pub mod submit;
pub mod workspace;

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "ctf", about = "CTF competition workflow tool")]
pub struct Cli {
  #[command(subcommand)]
  pub command: Command,

  /// Output format
  #[arg(long, global = true, default_value = "table")]
  pub output: OutputFormat,
}

#[derive(Debug, Clone, clap::ValueEnum)]
pub enum OutputFormat {
  Table,
  Json,
  Plain,
}

#[derive(Subcommand)]
pub enum Command {
  /// Authentication management
  Auth {
    #[command(subcommand)]
    command: auth::AuthCommand,
  },

  /// Initialize a CTF workspace
  Init {
    /// Workspace name
    name: String,
    /// Platform URL
    #[arg(long)]
    url: Option<String>,
    /// Platform type (ctfd or rctf, auto-detected if omitted)
    #[arg(long, name = "type")]
    platform_type: Option<String>,
  },

  /// Sync challenges from the platform
  Sync {
    /// Fetch full details (descriptions, hints, files) for all challenges
    #[arg(long)]
    full: bool,
  },

  /// List all challenges
  #[command(alias = "ls", alias = "chals")]
  Challenges {
    /// Filter by category
    #[arg(long)]
    category: Option<String>,
    /// Show only unsolved challenges
    #[arg(long)]
    unsolved: bool,
    /// Show only solved challenges
    #[arg(long)]
    solved: bool,
  },

  /// Show details of a specific challenge
  Challenge {
    /// Challenge ID or name
    id_or_name: String,
    /// Download attached files
    #[arg(long)]
    download: bool,
  },

  /// Submit a flag
  #[command(alias = "sub")]
  Submit {
    /// Flag string, or challenge ID/name if two args given
    first: String,
    /// Flag string (if first arg is challenge ID/name)
    second: Option<String>,
  },

  /// Show scoreboard
  #[command(alias = "sb")]
  Scoreboard {
    /// Number of entries to show
    #[arg(long, default_value = "10")]
    limit: u32,
  },

  /// Show workspace status dashboard
  Status,

  /// Download challenge files
  #[command(alias = "dl")]
  Files {
    /// Challenge ID or name
    id_or_name: String,
  },

  /// Launch the TUI monitoring dashboard
  Dashboard,

  /// Run as an MCP server (stdio transport)
  Mcp {
    /// Workspace directory (defaults to CTF_WORKSPACE env or auto-detected)
    #[arg(long, env = "CTF_WORKSPACE")]
    workspace: Option<PathBuf>,
    /// API token (overrides CTF_TOKEN env var and config file)
    #[arg(long, env = "CTF_TOKEN")]
    token: Option<String>,
  },
}
