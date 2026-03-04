# Architecture

## Overview

CTF-Buster is a Rust CLI + MCP server backed by three Python MCP servers for
domain-specific analysis. All four servers communicate over stdio using the
Model Context Protocol, allowing AI agents to orchestrate CTF challenge solving.

```
                        Claude Code / AI Agent
                                |
          +-----------+---------+---------+-----------+
          |           |                   |           |
   ctf-buster     ctf-crypto      ctf-binary    ctf-forensics
    (Rust)        (Python)         (Python)       (Python)
    9 tools       6 tools          8 tools        5 tools
      |               |               |               |
   CTFd/rCTF     sympy, z3       radare2, pwn    binwalk, zsteg
   platforms     cryptography    ROPgadget        steghide, PIL
```

## Module Structure

### Rust (`src/`)

```
src/
  main.rs              Entry point, CLI dispatch, MCP server startup
  error.rs             Centralized error types (thiserror)
  cli/
    mod.rs             Clap CLI argument structs and subcommands
    auth.rs            Token management (keyring, env var, config file)
    challenge.rs       Challenge resolution and display
    submit.rs          Flag submission with result handling
    workspace.rs       init, sync, status, files command handlers
    scoreboard.rs      Scoreboard display
  config/
    mod.rs             Workspace config loading and discovery
    types.rs           Config data structures (.ctf.toml schema)
  platform/
    mod.rs             Platform trait + factory + auto-detection
    types.rs           Domain types: Challenge, Hint, Notification, SubmitResult, etc.
    ctfd.rs            CTFd API implementation (with CSRF nonce support)
    rctf.rs            rCTF API implementation
    mock.rs            Mock platform for testing (#[cfg(test)])
  workspace/
    mod.rs             Module exports
    state.rs           .ctf-state.json persistence and caching
    scaffold.rs        Challenge directory creation and file downloads
  output/
    mod.rs             Module exports
    table.rs           Table formatting for CLI display
  mcp/
    mod.rs             MCP server with 9 tools (rmcp framework)
    types.rs           MCP parameter types (schemars for JSON schema)
```

### Python (`tools/`)

```
tools/
  ctf_crypto.py        Crypto & encoding MCP server (6 tools, FastMCP)
  ctf_binary.py        Binary analysis MCP server (8 tools, FastMCP)
  ctf_forensics.py     Forensics & stego MCP server (5 tools, FastMCP)
  lib/
    subprocess_utils.py  Shared utilities: safe subprocess execution, checksec parsing
  tests/
    test_crypto.py     Crypto tool tests
    test_binary.py     Binary tool tests
    test_forensics.py  Forensics tool tests
    test_subprocess_utils.py  Utility tests
```

## Key Abstractions

### Platform Trait

The core abstraction that enables CTFd and rCTF support through a single interface:

```rust
#[async_trait]
pub trait Platform: Send + Sync {
  async fn whoami(&self) -> Result<TeamInfo>;
  async fn challenges(&self) -> Result<Vec<Challenge>>;
  async fn challenge(&self, id: &str) -> Result<Challenge>;
  async fn submit(&self, challenge_id: &str, flag: &str) -> Result<SubmitResult>;
  async fn scoreboard(&self, limit: Option<u32>) -> Result<Vec<ScoreboardEntry>>;
  async fn download_file(&self, file: &ChallengeFile, dest: &Path) -> Result<()>;
  async fn unlock_hint(&self, hint_id: &str) -> Result<Hint>;
  async fn notifications(&self) -> Result<Vec<Notification>>;
}
```

Platform auto-detection probes the URL to determine whether it's CTFd or rCTF.

### Authentication

Token resolution order (highest priority first):
1. `--token` CLI argument
2. `CTF_TOKEN` environment variable
3. `token` field in `.ctf.toml` (supports `${VAR}` and `${VAR:-default}` expansion)
4. System keyring (set via `ctf auth login`)

CTFd supports both API tokens and session cookies. Session cookies (Flask
format containing `.`) are auto-detected and use a cookie jar + CSRF nonce
for POST requests.

### Workspace State

`.ctf-state.json` tracks:
- Last sync timestamp
- Per-challenge state: solved status, flag, points, timestamp
- Cached details: descriptions, hints, files, tags (from `--full` sync)
- Platform notifications

State is shared between the CLI and MCP server — `ctf_submit_flag` writes
solve results that `ctf_workspace_status` reads.

## Platform Differences

| | CTFd | rCTF |
|---|---|---|
| Auth header | `Token <token>` | `Bearer <jwt>` |
| Challenges | `GET /api/v1/challenges` | `GET /api/v1/challs` |
| Submit | `POST /api/v1/challenges/attempt` | `POST /api/v1/challs/:id/submit` |
| Scoreboard | `GET /api/v1/scoreboard/top/N` | `GET /api/v1/leaderboard/now` |
| Response envelope | `{ "success": bool, "data": ... }` | `{ "kind": "good*"\|"bad*", "data": ... }` |
| Notifications | `GET /api/v1/notifications` | Not supported |
| Hint unlocking | `POST /api/v1/unlocks` | Not supported |
