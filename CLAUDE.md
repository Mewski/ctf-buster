# CTF-Buster

AI-powered CTF competition toolkit. Rust CLI + 4 MCP servers (28 tools total).

## Architecture

```
ctf-buster (Rust)     — 9 tools: platform interaction (CTFd/rCTF)
ctf-crypto (Python)   — 6 tools: encoding chains, RSA attacks, constraint solving
ctf-binary (Python)   — 8 tools: triage, disassembly, ROP, pwntools, angr
ctf-forensics (Python) — 5 tools: file analysis, stego, extraction, entropy
```

All servers communicate over MCP stdio transport.

## CTF Competition Workflow

When working on a CTF competition, use this multi-agent orchestration strategy.

### 1. Initial Recon

```
ctf_sync(full=true)          # Fetch all challenges + descriptions + files + unlock free hints
ctf_workspace_status()       # See score, progress, categories
ctf_challenges(unsolved=true) # List what's left to solve
ctf_notifications()          # Check for announcements, errata, format changes
```

### 2. Challenge Priority Queue

Score and sort unsolved challenges before launching subagents:

```
priority = category_score + difficulty_bonus + solve_bonus

category_score (tool coverage strength):
  crypto:     +10  (best tool coverage: rsa_toolkit, math_solve, transform_chain)
  forensics:  +10  (best tool coverage: file_triage, stego_analyze, extract_embedded)
  web:        +8   (good with curl/sqlmap/ffuf from bash)
  rev:        +6   (disassemble + angr_analyze cover common patterns)
  misc:       +4   (varies widely)
  pwn:        +2   (often needs interactive exploitation beyond tool scope)

difficulty_bonus:
  "easy" tag or > 50 solves:  +20
  "medium" tag or 20-50 solves: +10
  "hard" tag or < 20 solves:  +0

solve_bonus:
  points / solves < 10:  +5  (likely easy, high value)
```

Queue rules:
- Process in descending priority order
- Batch by category when launching parallel subagents (shared context)
- Skip challenges already being attempted by another subagent
- Re-queue failed challenges with lower priority (-10) after one attempt
- Time-box: if no progress after agent's full turn, mark as "needs-help" and move on

### 3. Orchestration Loop

The main agent acts as an **orchestrator** — it does NOT solve challenges directly.
Instead it launches subagents and monitors progress:

```
while unsolved challenges remain:
  1. ctf_challenges(unsolved=true)         # Get current unsolved list
  2. Score and sort by priority queue above
  3. Take top N (N = parallel capacity, typically 3-5)
  4. Group by category for context sharing
  5. Select model per challenge (see Model Selection below)
  6. Launch subagents (Task tool) for the batch
  7. Collect results, submit any found flags
  8. Re-queue failures with reduced priority
  9. ctf_sync()                            # Catch team solves, new challenges
  10. ctf_workspace_status()               # Check updated score/progress
```

Key orchestration rules:
- **Always check `ctf_challenges(unsolved=true)` before launching new agents** — avoids
  re-attempting challenges already solved by another subagent
- **State is shared** — `ctf_submit_flag` writes to `.ctf-state.json` which tracks every
  solve with timestamp, flag, and points. `ctf_workspace_status` reads this.
- **Re-sync periodically** — `ctf_sync()` updates local state from the platform, catching
  solves from other team members too

### 4. Model Selection for Subagents

Select the model based on challenge characteristics:

**opus** (deep reasoning, complex multi-step):
- Crypto requiring mathematical reasoning (RSA, discrete log, custom ciphers)
- Binary exploitation (pwn) requiring exploit chain development
- Challenges where the first attempt failed and need deeper analysis
- Any challenge worth > 300 points

**sonnet** (fast, capable, good default):
- Most challenges on first attempt
- Web challenges (pattern matching + known techniques)
- Forensics/stego (tool-driven, follow the output)
- Easy/medium crypto (simple encoding chains, known ciphers)
- Rev challenges with clear structure

**haiku** (fast, lightweight):
- Challenges with known solution patterns (just need tool execution)
- Re-attempting with a clear approach that failed on execution
- Simple encoding/decoding tasks
- File extraction and triage-only tasks

**Default: sonnet for first attempt, opus for retry on failure, haiku for pure tool execution.**

### 5. Subagent Structure

Each subagent receives a specific challenge (or small batch) to solve:

```
Subagent prompt pattern:
  "Solve CTF challenge '{name}' (category: {category}, {points} pts).
   Description: {description}
   Files: {file_list}
   Workspace: {workspace_path}
   Flag format: {flag_format}

   Steps:
   1. Download files with ctf_download_files('{name}')
   2. Triage with {appropriate_triage_tool}
   3. Analyze and solve
   4. AUTO-SUBMIT: As soon as you find ANYTHING matching the flag format
      (e.g. flag{...}, CTF{...}, or the competition's format), immediately
      call ctf_submit_flag('{name}', '<the_flag>') — do NOT wait, do NOT
      ask for confirmation, do NOT continue analysis before submitting.
   5. If the flag is correct, report back as solved.
      If incorrect, continue analysis and try other candidates.
   6. Report back: solved/unsolved/needs-help"

Launch subagent with:
  model: select based on category + difficulty (see Model Selection)
  subagent_type: "general-purpose"
```

**Flag detection rules for subagents:**
- Scan ALL tool output (stdout, extracted data, decoded text, solver results) for flag patterns
- Common patterns: `flag{...}`, `CTF{...}`, `FLAG{...}`, `ctf{...}`, or the competition-specific format from `ctf_workspace_status`
- If a tool like `angr_analyze`, `transform_chain`, `rsa_toolkit`, or `stego_analyze` returns output containing a flag, **submit it immediately**
- When multiple flag candidates exist, submit each one — `ctf_submit_flag` reports correct/incorrect so you'll know which worked
- Never hold a flag without submitting. The moment you see it, submit it.

For parallel execution, launch multiple subagents in a single message using the Task tool.

### 6. Category-Specific Approaches

**Crypto challenges:**
- `crypto_identify` to detect encoding/cipher type
- `transform_chain` for multi-step decode pipelines
- `rsa_toolkit` for RSA challenges (auto-tries factordb, fermat, wiener, small-e)
- `math_solve` with z3 mode for constraint problems
- `frequency_analysis` for classical ciphers

**Binary/Pwn challenges:**
- `binary_triage` first — get checksec, imports, dangerous functions, architecture
- `disassemble` to read key functions
- `angr_analyze` for automatic solving of simple stack-based challenges:
  - `auto` mode: finds inputs producing flag-like output
  - `find_addr` mode: finds inputs reaching a specific address
  - `find_string` mode: finds inputs causing specific output
- `find_rop_gadgets` for ROP chains
- `pattern_offset` to find buffer overflow offsets
- `pwntools_template` to generate exploit scripts
- `shellcode_generate` for shellcode payloads
- Use bash + pwntools/gdb for interactive exploitation

**Forensics/Stego challenges:**
- `file_triage` first — get file type, metadata, embedded data, entropy
- `stego_analyze` systematically tries all stego tools for the file type
- `extract_embedded` for binwalk/foremost extraction
- `entropy_analysis` to find encrypted/compressed regions
- `image_analysis` for deep image inspection (LSB, channels, histograms)

**Web challenges:**
- Use bash directly: curl, sqlmap, ffuf, nuclei, nikto, etc.
- These tools work well from bash and don't need MCP wrapping

### 7. Progress Tracking & Flag Submission

- **Auto-submit immediately** — the moment any tool output, decoded string, solver result,
  or extracted data contains a flag-like pattern, call `ctf_submit_flag` right away. Do NOT
  wait until the end of analysis. Do NOT ask the user for confirmation before submitting.
- **Always submit via `ctf_submit_flag`** — this writes to `.ctf-state.json` with the flag,
  points, and timestamp. Never submit flags manually via curl/bash.
- **Submit, then verify** — `ctf_submit_flag` returns correct/incorrect/already-solved, so
  there's no risk in submitting. If wrong, keep trying other candidates.
- **Check progress often** — `ctf_workspace_status()` gives a live scoreboard-style view
  of solved/unsolved per category
- **`ctf_challenges(solved=true)`** — review what's been solved to avoid duplicating work
- **Flags are stored** — `.ctf-state.json` keeps every flag for later reference. The
  `mark_solved` function records challenge ID, name, points, flag, and solve timestamp.
- **Platform sync** — `ctf_sync()` also detects solves made outside ctf-buster (e.g. by
  teammates) via the `solved_by_me` field from the API
- **Notifications** — `ctf_notifications()` fetches platform announcements which may
  contain hints, errata, or flag format changes

## Development

### Build & Test

```bash
nix develop                                    # Enter devShell
cargo build --release                          # Build Rust CLI
cargo test                                     # Run Rust tests (94 tests)
cargo clippy -- -W clippy::all                 # Lint Rust
python3 -m pytest tools/tests/                 # Run Python tests (222 tests)
python3 -m pytest tools/tests/ --cov=tools     # Python coverage
cargo tarpaulin                                # Rust coverage
```

### Project Structure

```
src/                    Rust CLI + MCP server
  cli/                  CLI command handlers
  config/               Workspace config (.ctf.toml)
  mcp/                  MCP server (rmcp)
  platform/             CTFd + rCTF API clients
  workspace/            Scaffolding + state management
tools/                  Python MCP servers
  ctf_crypto.py         Crypto & encoding server
  ctf_binary.py         Binary analysis server
  ctf_forensics.py      Forensics & stego server
  lib/                  Shared subprocess utilities
  tests/                Python test suite
docs/                   Extended documentation
```

### Authentication

Token resolution order (highest priority first):
1. `--token` CLI arg: `ctf mcp --token <token>`
2. `CTF_TOKEN` environment variable
3. `token` field in `.ctf.toml` (supports `${VAR}` and `${VAR:-default}` expansion)
4. System keyring (set via `ctf auth login`)

Example `.ctf.toml` with env var token:
```toml
[platform]
url = "https://ctf.example.com"
token = "${CTF_TOKEN}"

[workspace]
name = "my-ctf"
```

### MCP Server Registration

**Via CLI:**
```bash
claude mcp add -s user ctf-buster -- /path/to/target/release/ctf mcp --workspace /path/to/workspace
claude mcp add -s user ctf-crypto -- python3 /path/to/tools/ctf_crypto.py
claude mcp add -s user ctf-binary -- python3 /path/to/tools/ctf_binary.py
claude mcp add -s user ctf-forensics -- python3 /path/to/tools/ctf_forensics.py
```

**Via `.mcp.json` (recommended):**
```json
{
  "mcpServers": {
    "ctf-buster": {
      "command": "./target/release/ctf",
      "args": ["mcp", "--workspace", "."],
      "env": { "CTF_TOKEN": "${CTF_TOKEN}" }
    },
    "ctf-crypto": {
      "command": "python3",
      "args": ["./tools/ctf_crypto.py"]
    },
    "ctf-binary": {
      "command": "python3",
      "args": ["./tools/ctf_binary.py"]
    },
    "ctf-forensics": {
      "command": "python3",
      "args": ["./tools/ctf_forensics.py"]
    }
  }
}
```

## Conventions

- Rust: stable toolchain, `cargo clippy -- -W clippy::all` clean
- Python: no external deps beyond what's in flake.nix pythonEnv
- All Python MCP servers use fastmcp with stdio transport
- Tools return JSON strings for structured data
- Security tools are for authorized CTF competitions only
