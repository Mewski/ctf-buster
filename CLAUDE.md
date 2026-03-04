# CTF-Buster

AI-powered CTF competition toolkit. Rust CLI + 7 MCP servers (44 tools total).

## Architecture

```
ctf-buster (Rust)      — 15 tools: platform interaction (CTFd/rCTF), queue management, auto-orchestration, writeups
ctf-crypto (Python)    — 8 tools: encoding chains, RSA attacks, constraint solving, XOR analysis, SageMath
ctf-pwn (Python)       — 10 tools: triage, disassembly, ROP, pwntools, angr, format strings, libc lookup
ctf-forensics (Python) — 6 tools: file analysis, stego, extraction, entropy, volatility
ctf-gdb (Python)       — 5 tools: GDB dynamic analysis, breakpoints, input tracing
ctf-rev (Python)       — 6 tools: decompilation, xrefs, CFG, function analysis
ctf-jail (Python)      — 4 tools: pyjail/bashjail analysis, bypass payloads, subclass chains
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
  jail:       +8   (dedicated pyjail/bashjail analysis and payload generation)
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
  3. ctf_generate_solve_prompt(count=10)   # Get prompts for top 10
     — returns JSON with: prompt, recommended_model, subagent_type per challenge
     — auto-marks selected challenges as in_progress
  4. Launch subagents via Task tool — one per challenge, ALL in parallel:
     Task(
       description="Solve <challenge_name>",
       prompt=<prompt from step 3>,
       model=<recommended_model from step 3>,  // "opus", "sonnet", or "haiku"
       subagent_type="general-purpose",
       run_in_background=true                   // Non-blocking!
     )
     Launch ALL in a single message for parallel execution using run_in_background=true.
  5. Do NOT wait for all subagents. Instead, immediately loop back to step 1.
     — ctf_sync + ctf_auto_queue will skip in_progress challenges automatically
     — Generate prompts for the NEXT batch while previous agents are still running
     — Periodically check on background agents via their output_file (Read tool)
  6. When a batch of agents completes, review results and continue launching
```

**One-command start:** When asked to "solve this CTF" or "start solving", execute steps
1-4 immediately without asking for confirmation. The tools handle all scoring, prompt
generation, and model selection automatically.

**Continuous throughput:** Launch 10 subagents per batch using `run_in_background=true`.
Do NOT wait for all to finish before launching more. The queue system handles deduplication:
- `ctf_generate_solve_prompt` auto-marks challenges as in_progress
- `ctf_auto_queue` skips in_progress and solved challenges
- Subagents auto-submit flags and auto-mark queue state (complete/fail)
This means you can safely launch the next batch immediately — no risk of duplicate work.

**Result handling:** Subagents call `ctf_queue_update(action='complete')` on success and
`ctf_queue_update(action='fail')` on failure. Periodically check `ctf_queue_status()` and
`ctf_challenges(unsolved=true)` to monitor progress. Keep launching until queue is empty.

Key orchestration rules:
- **Always re-sync before each batch** — `ctf_sync()` catches solves from other subagents
  and teammates, preventing duplicate work
- **`ctf_generate_solve_prompt` auto-marks in_progress** — challenges are automatically
  moved from queue to in_progress when prompts are generated, preventing duplicate work.
  No need to manually call `ctf_queue_update(action='start')`.
- **`ctf_auto_queue` skips in_progress** — won't re-queue challenges being actively worked on.
- **State is shared** — `ctf_submit_flag` writes to `.ctf-state.json` which tracks every
  solve with timestamp, flag, and points. `ctf_auto_queue` reads this to skip solved ones.
- **Parallel launches** — call multiple Task tools in a single message to launch subagents
  concurrently. Use `recommended_model` from the prompt generator for each.
- **Prioritize specific challenges** — use `ctf_queue_update(action='prioritize', challenge='X')`
  to move a challenge to the front of the queue (also rescues from the failed list).
- **Retry failures** — use `ctf_queue_update(action='retry', challenge='X')` to move a
  failed challenge back to the queue for another attempt.

### 4. Model Selection for Subagents

`ctf_generate_solve_prompt` automatically selects the best model per challenge.
The selection logic (you don't need to do this manually):

**opus** (deep reasoning, complex multi-step):
- Retries (any challenge that previously failed)
- Any challenge worth > 300 points
- Crypto and pwn challenges with low solve counts (hard)

**sonnet** (fast, capable, good default):
- Most challenges on first attempt
- Easy crypto/pwn (high solve counts, priority >= 25)
- Web challenges (pattern matching + known techniques)
- Forensics/stego (tool-driven, follow the output)
- Easy/medium crypto (simple encoding chains, known ciphers)
- Rev challenges with clear structure

**haiku** (fast, lightweight):
- Very easy challenges (priority >= 30, meaning high solve count + good category)
- Simple encoding/decoding tasks
- File extraction and triage-only tasks

**All automatic:** `ctf_generate_solve_prompt` returns the `recommended_model` field
for each challenge. Just pass it to the Task tool's `model` parameter.

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
2. Read solve.py — it has a category-appropriate template or prior work from a failed attempt
3. Triage with category-appropriate tools
4. Build solution in solve.py incrementally as you work
5. AUTO-SUBMIT any flag-like strings immediately
6. On correct flag, call ctf_save_writeup to document methodology
7. Report back: solved/unsolved/needs-help

**Flag detection rules for subagents:**
- Scan ALL tool output (stdout, extracted data, decoded text, solver results) for flag patterns
- Common patterns: `flag{...}`, `CTF{...}`, `FLAG{...}`, `ctf{...}`, or the competition-specific format from `ctf_workspace_status`
- If a tool like `pwn_angr_analyze`, `crypto_transform_chain`, `crypto_rsa_toolkit`, or `forensics_stego_analyze` returns output containing a flag, **submit it immediately**
- When multiple flag candidates exist, submit each one — `ctf_submit_flag` reports correct/incorrect so you'll know which worked
- Never hold a flag without submitting. The moment you see it, submit it.

For parallel execution, launch multiple subagents in a single message using the Task tool.

### 6. Category-Specific Approaches

**Crypto challenges:** (solve.py has a minimal Python template — add your decode logic there)
- `crypto_identify` to detect encoding/cipher type
- `crypto_transform_chain` for multi-step decode pipelines
- `crypto_rsa_toolkit` for RSA challenges (auto-tries factordb, fermat, wiener, small-e)
- `crypto_math_solve` with z3 mode for constraint problems
- `crypto_frequency_analysis` for classical ciphers
- `crypto_xor_analyze` for XOR/stream cipher challenges (known-plaintext, Kasiski, IC, brute force)
- For SageMath and hash cracking: use `sage` and `hashcat`/`john` directly from bash

**Binary/Pwn challenges:** (solve.py has a pwntools skeleton with ELF/remote setup — fill in the exploit)
- `pwn_triage` first — get checksec, imports, dangerous functions, architecture
- `rev_decompile` for pseudocode (r2ghidra/r2dec fallback chain)
- `rev_functions` to list all functions with sizes and call targets
- `rev_strings_xrefs` to find which functions reference interesting strings
- `gdb_break_inspect` to examine registers/stack/memory at breakpoints
- `gdb_trace_input` to find buffer overflow offsets (cyclic pattern + crash analysis)
- `gdb_checksec_runtime` for runtime security info (ASLR, libc base, GOT, symbols)
- `gdb_run` for general GDB command execution
- `pwn_angr_analyze` for automatic solving of simple stack-based challenges:
  - `auto` mode: finds inputs producing flag-like output
  - `find_addr` mode: finds inputs reaching a specific address
  - `find_string` mode: finds inputs causing specific output
- `pwn_pattern_offset` to find buffer overflow offsets
- `pwn_pwntools_template` to generate exploit scripts
- `pwn_shellcode_generate` for shellcode payloads
- `pwn_format_string` for format string exploit automation (probe for offset, generate write payloads)
- `pwn_libc_lookup` to identify libc version from leaked symbol addresses (libc.rip API)
- For ROP gadgets, one_gadget, disassembly: use `ROPgadget`, `one_gadget`, `r2` directly from bash

**Reverse engineering challenges:** (solve.py has subprocess/struct imports — add decoder/keygen logic)
- `rev_functions` to get an overview of all functions
- `rev_decompile` for pseudocode of key functions
- `rev_strings_xrefs` to find functions referencing flag/password/key strings
- `gdb_run` for arbitrary GDB commands, `gdb_break_inspect` to validate static analysis with runtime state
- For xrefs, CFG, binary diff: use `r2` and `radiff2` directly from bash

**Forensics/Stego challenges:** (solve.py is minimal — most work uses MCP tools, add extraction logic if needed)
- `forensics_file_triage` first — get file type, metadata, embedded data, entropy
- `forensics_stego_analyze` systematically tries all stego tools for the file type
- `forensics_extract_embedded` for binwalk/foremost extraction
- `forensics_entropy_analysis` to find encrypted/compressed regions
- `forensics_image_analysis` for deep image inspection (LSB, channels, histograms)
- For memory dumps: use `vol` (volatility3) directly from bash

**Web challenges:** (solve.py has a requests session template — build your exploit there)
- Use bash directly: curl, sqlmap, ffuf, nuclei, nikto, etc.
- These tools work well from bash and don't need MCP wrapping

**Jail challenges (pyjail/bashjail):** (solve.py has a pwntools template — test payloads interactively)
- Read the jail source code first — understand what's filtered
- `jail_analyze_source` to automatically identify blocked strings, chars, and restriction mechanism
- `jail_find_subclass_chain` to find Python MRO paths to os/builtins/import
- `jail_construct_string` to build blocked strings using only allowed characters
- `jail_build_payload` to generate complete bypass payloads matching restrictions
- For bash jails: use `jail_build_payload` with `jail_type="bash"` for glob/hex/variable tricks
- Common Python techniques: subclass chains, chr() string building, getattr(), Unicode NFKC
- Common bash techniques: $'\xNN' hex, ${PATH:0:1} for /, glob patterns /???/??t

### 7. Incremental Work & Retries

Subagents should treat `solve.py` as a living document:
- **Read it first** — it may contain prior work from failed attempts
- **Edit incrementally** — don't rewrite from scratch
- **Keep it runnable** — the script should reproduce the solve end-to-end
- **Even failed attempts** should leave useful code in solve.py for the next try
- **MCP tools are for analysis**; solve.py is for the actual solution logic
- **Submit first, polish after** — don't hold a flag waiting for clean code

### 8. Progress Tracking & Flag Submission

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

### 9. Post-Solve Documentation

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

### 10. TUI Dashboard

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
cargo test                                     # Run Rust tests (163 tests)
cargo clippy -- -W clippy::all                 # Lint Rust
python3 -m pytest tools/tests/                 # Run Python tests (405 tests)
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
  ctf_pwn.py            Binary analysis server
  ctf_forensics.py      Forensics & stego server
  ctf_gdb.py            GDB dynamic analysis server
  ctf_rev.py            Reverse engineering server
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
claude mcp add -s user ctf-pwn -- python3 /path/to/tools/ctf_pwn.py
claude mcp add -s user ctf-forensics -- python3 /path/to/tools/ctf_forensics.py
claude mcp add -s user ctf-gdb -- python3 /path/to/tools/ctf_gdb.py
claude mcp add -s user ctf-rev -- python3 /path/to/tools/ctf_rev.py
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
    "ctf-pwn": {
      "command": "python3",
      "args": ["./tools/ctf_pwn.py"]
    },
    "ctf-forensics": {
      "command": "python3",
      "args": ["./tools/ctf_forensics.py"]
    },
    "ctf-gdb": {
      "command": "python3",
      "args": ["./tools/ctf_gdb.py"]
    },
    "ctf-rev": {
      "command": "python3",
      "args": ["./tools/ctf_rev.py"]
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
