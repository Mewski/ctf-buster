# CTF-Buster

AI-powered CTF competition toolkit. Rust CLI + 6 MCP servers (44 tools total).

## Architecture

```
ctf-buster (Rust)      — 14 tools: platform interaction (CTFd/rCTF), queue management, auto-orchestration, writeups
ctf-crypto (Python)    — 6 tools: encoding chains, RSA attacks, constraint solving
ctf-binary (Python)    — 8 tools: triage, disassembly, ROP, pwntools, angr
ctf-forensics (Python) — 5 tools: file analysis, stego, extraction, entropy
ctf-gdb (Python)       — 5 tools: GDB dynamic analysis, breakpoints, input tracing
ctf-re (Python)        — 6 tools: decompilation, xrefs, CFG, function analysis
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

**Automated:** Call `ctf_auto_queue()` to automatically score and queue all unsolved challenges.
It implements this scoring algorithm:

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
  > 50 solves:  +20
  20-50 solves: +10
  < 20 solves:  +0

solve_bonus:
  points / solves < 10:  +5  (likely easy, high value)

failure_penalty:
  previously failed: -10
```

Queue rules:
- Process in descending priority order
- Batch by category when launching parallel subagents (shared context)
- Skip challenges already being attempted by another subagent
- Re-queue failed challenges with lower priority (-10) after one attempt
- Time-box: if no progress after agent's full turn, mark as "needs-help" and move on

### 3. Orchestration Loop

The main agent acts as an **orchestrator** — it does NOT solve challenges directly.
Instead it uses two automation tools and launches subagents:

```
while unsolved challenges remain:
  1. ctf_sync(full=true)                   # Fetch challenges + descriptions + files
  2. ctf_auto_queue()                      # Auto-score and queue all unsolved
  3. ctf_generate_solve_prompt(count=N)    # Get prompts for top N (typically 3-5)
  4. Launch subagents (Task tool) in parallel using the generated prompts
     — each prompt includes: challenge info, model recommendation, tool hints, steps
  5. Collect results from subagents
  6. For any failures: ctf_queue_update(action='fail', challenge='...', notes='...')
  7. Loop back to step 1 (re-sync catches team solves, new challenges)
```

**One-command start:** When asked to "solve this CTF" or "start solving", execute steps
1-4 immediately without asking for confirmation. The tools handle all scoring, prompt
generation, and model selection automatically.

Key orchestration rules:
- **Always re-sync before each batch** — `ctf_sync()` catches solves from other subagents
  and teammates, preventing duplicate work
- **Use `ctf_generate_solve_prompt`** — it generates complete, self-contained prompts with
  descriptions, file lists, hints, tool suggestions, model recommendations, and step-by-step
  instructions. No need to manually construct prompts.
- **State is shared** — `ctf_submit_flag` writes to `.ctf-state.json` which tracks every
  solve with timestamp, flag, and points. `ctf_auto_queue` reads this to skip solved ones.
- **Parallel launches** — call multiple Task tools in a single message to launch subagents
  concurrently. Use `recommended_model` from the prompt generator for each.

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

**Automated:** Call `ctf_generate_solve_prompt(count=N)` to get ready-to-use prompts.
Each prompt includes challenge info, tool suggestions, model recommendation, and the
full step sequence. Just pass them directly to the Task tool.

```
# Generate prompts for top 3 challenges
result = ctf_generate_solve_prompt(count=3)

# Launch each as a subagent
for prompt_data in result.prompts:
  Task(
    description="Solve " + prompt_data.challenge,
    prompt=prompt_data.prompt,
    model=prompt_data.recommended_model,
    subagent_type="general-purpose"
  )
```

The generated prompts follow this structure:
1. Download files with ctf_download_files
2. Triage with category-appropriate tools
3. Analyze and solve
4. AUTO-SUBMIT any flag-like strings immediately
5. On correct flag, call ctf_save_writeup to document methodology
6. Report back: solved/unsolved/needs-help

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
- `r2_decompile` for pseudocode (r2ghidra/r2dec fallback chain)
- `r2_functions` to list all functions with sizes and call targets
- `r2_xrefs` to trace call graphs and cross-references
- `r2_cfg` for control flow graph analysis
- `r2_strings_xrefs` to find which functions reference interesting strings
- `gdb_break_inspect` to examine registers/stack/memory at breakpoints
- `gdb_trace_input` to find buffer overflow offsets (cyclic pattern + crash analysis)
- `gdb_memory_dump` to read memory at specific addresses during execution
- `gdb_checksec_runtime` for runtime security info (ASLR, libc base, GOT, symbols)
- `gdb_run` for general GDB command execution
- `angr_analyze` for automatic solving of simple stack-based challenges:
  - `auto` mode: finds inputs producing flag-like output
  - `find_addr` mode: finds inputs reaching a specific address
  - `find_string` mode: finds inputs causing specific output
- `find_rop_gadgets` for ROP chains
- `pattern_offset` to find buffer overflow offsets
- `pwntools_template` to generate exploit scripts
- `shellcode_generate` for shellcode payloads

**Reverse engineering challenges:**
- `r2_functions` to get an overview of all functions
- `r2_decompile` for pseudocode of key functions
- `r2_xrefs` to trace call graphs (who calls what)
- `r2_strings_xrefs` to find functions referencing flag/password/key strings
- `r2_cfg` to analyze control flow and branch conditions
- `r2_diff` to compare patched vs original binaries
- `gdb_break_inspect` to validate static analysis with runtime state

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

### 8. Post-Solve Documentation

After every successful flag submission, subagents MUST call `ctf_save_writeup` to document the solution:

```
ctf_save_writeup(
  challenge: "challenge-name",
  methodology: "Detailed description of approach...",
  tools_used: ["tool1", "tool2", "python", ...]
)
```

Methodology should include:
- What vulnerability or technique was exploited
- Key observations that led to the solution
- Any dead ends encountered and why they didn't work
- The step-by-step process from triage to flag

This generates a `writeup.md` in the challenge directory alongside `solve.py` and `notes.md`.

### 9. TUI Dashboard

Run `ctf dashboard` in a separate terminal to monitor progress in real-time while the
orchestrator works. The dashboard polls `.ctf-state.json` every 2 seconds and shows:
- Challenge table with solve status
- Orchestration queue (queued/in-progress/failed)
- Category breakdown
- Platform notifications

## Development

### Build & Test

```bash
nix develop                                    # Enter devShell
cargo build --release                          # Build Rust CLI
cargo test                                     # Run Rust tests (94 tests)
cargo clippy -- -W clippy::all                 # Lint Rust
python3 -m pytest tools/tests/                 # Run Python tests (309 tests)
python3 -m pytest tools/tests/ --cov=tools     # Python coverage
cargo tarpaulin                                # Rust coverage
```

### Project Structure

```
src/                    Rust CLI + MCP server
  cli/                  CLI command handlers
  config/               Workspace config (.ctf.toml)
  mcp/                  MCP server (rmcp)
  tui/                  TUI dashboard (ratatui)
  platform/             CTFd + rCTF API clients
  workspace/            Scaffolding + state management
tools/                  Python MCP servers
  ctf_crypto.py         Crypto & encoding server
  ctf_binary.py         Binary analysis server
  ctf_forensics.py      Forensics & stego server
  ctf_gdb.py            GDB dynamic analysis server
  ctf_re.py             Reverse engineering server
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
claude mcp add -s user ctf-gdb -- python3 /path/to/tools/ctf_gdb.py
claude mcp add -s user ctf-re -- python3 /path/to/tools/ctf_re.py
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
    },
    "ctf-gdb": {
      "command": "python3",
      "args": ["./tools/ctf_gdb.py"]
    },
    "ctf-re": {
      "command": "python3",
      "args": ["./tools/ctf_re.py"]
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
