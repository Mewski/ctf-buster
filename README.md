# CTF-Buster

An AI-powered CTF (Capture The Flag) toolkit combining a Rust CLI with four MCP
(Model Context Protocol) servers. Designed to let AI agents -- particularly
Claude Code -- interact with CTFd and rCTF platforms, perform cryptographic
attacks, analyze binaries, and run forensic investigations, all from a unified
workspace.

## Features

- **Platform integration** -- authenticate, sync challenges, submit flags, and
  track scores on CTFd and rCTF with automatic platform detection.
- **Workspace management** -- initialize per-competition workspaces with
  scaffolded directories, solve templates, and notes files.
- **6 MCP servers / 42 tools** -- expose every capability over MCP so AI agents
  can call them directly.
- **TUI dashboard** -- run `ctf dashboard` in a separate terminal to monitor
  progress in real-time while the AI orchestrator works.
- **160+ security tools** -- the Nix dev shell bundles a curated set of
  security CLI tools (radare2, Ghidra, binwalk, hashcat, pwntools, angr, z3,
  and many more).
- **Multi-agent orchestration** -- priority queue, model selection, and
  parallel subagent coordination for solving challenges at scale.

## Architecture

```
                        Claude Code / AI Agent
                                |
    +--------+--------+---------+---------+---------+--------+
    |        |        |                   |         |        |
ctf-buster ctf-crypto ctf-binary  ctf-forensics  ctf-gdb  ctf-re
  (Rust)   (Python)   (Python)     (Python)     (Python) (Python)
 11 tools  6 tools    8 tools      5 tools      5 tools  6 tools
    |          |          |            |            |        |
 CTFd/rCTF  sympy,z3  radare2,pwn  binwalk,    GDB      radare2
 platforms  crypto    ROPgadget    zsteg,PIL   batch     r2ghidra
```

All six servers communicate over **stdio** using the Model Context Protocol.
The Rust server (`ctf-buster`) handles platform interaction, workspace
management, and orchestration queuing. The five Python servers handle
domain-specific analysis, built on the
[FastMCP](https://github.com/jlowin/fastmcp) framework.

## Quick Start

```bash
# Enter the dev shell (includes Rust toolchain, Python env, 160+ security tools)
nix develop

# Build the CLI
cargo build --release

# Initialize a workspace for a competition
ctf init my-ctf --url https://ctf.example.com

# Authenticate (token stored in system keyring)
ctf auth login

# Sync challenges, scaffold directories, download files
ctf sync --full

# List unsolved challenges
ctf challenges --unsolved

# Submit a flag
ctf submit "challenge-name" "flag{...}"
```

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture](docs/architecture.md) | System design, module structure, platform abstraction |
| [CLI Reference](docs/cli-reference.md) | All CLI commands with examples |
| [MCP Tools](docs/mcp-tools.md) | All 42 tools across 6 MCP servers |
| [Configuration](docs/configuration.md) | `.ctf.toml`, authentication, scaffold templates |
| [Integration](docs/integration.md) | Claude Code setup and `.mcp.json` |
| [Security Tools](docs/security-tools.md) | 160+ tools available in the Nix dev shell |

## Development

```bash
nix develop                        # Enter dev shell
cargo build --release              # Build Rust CLI
cargo test                         # Run Rust tests (94 tests)
cargo clippy -- -W clippy::all     # Lint Rust
pytest tools/tests/                # Run Python tests (309 tests)
```

## Platform Support

| Platform | Status | Auth method |
|----------|--------|-------------|
| [CTFd](https://ctfd.io/) | Supported | API token or session cookie |
| [rCTF](https://rctf.redpwn.net/) | Supported | API token (JWT) |

## License

See [LICENSE](LICENSE) for details.
