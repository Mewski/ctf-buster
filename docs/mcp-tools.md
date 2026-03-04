# MCP Tools Reference

CTF-Buster provides 54 tools across 7 MCP servers.

## ctf-buster (Rust) -- 15 tools

Platform interaction, workspace management, auto-orchestration, and documentation.

| Tool | Description |
|------|-------------|
| `ctf_whoami` | Get info about the authenticated team/user -- name, score, rank. |
| `ctf_challenges` | List challenges with optional filters (category, solved/unsolved). Returns cached descriptions when available. |
| `ctf_challenge_detail` | Get full details of a challenge by ID or name -- description, hints, files, solve count. |
| `ctf_submit_flag` | Submit a flag for a challenge. Returns correct, incorrect, already solved, or rate-limited. |
| `ctf_scoreboard` | Show competition scoreboard with team rankings. |
| `ctf_sync` | Sync challenges from the platform -- creates workspace directories, downloads files, updates local state. Use `full=true` to cache descriptions/hints and auto-unlock free hints. |
| `ctf_download_files` | Download files attached to a challenge into the workspace. |
| `ctf_workspace_status` | Get workspace status -- team info, score, challenge counts per category, solve progress. |
| `ctf_unlock_hint` | Unlock a hint for a challenge. Warns when hints cost points. |
| `ctf_notifications` | Get competition notifications/announcements from the platform. |
| `ctf_queue_status` | Get the challenge priority queue -- shows what to solve next, what's in progress, and what failed. Persists across agent restarts. |
| `ctf_queue_update` | Update the challenge queue -- set priorities, mark challenges as in-progress, completed, or failed. Actions: `set_queue`, `start`, `complete`, `fail`, `prioritize` (move to front), `retry` (rescue from failed), `clear`. |
| `ctf_auto_queue` | Auto-score and queue all unsolved challenges by priority. Implements scoring: category_score + difficulty_bonus + solve_bonus - failure_penalty. Call after `ctf_sync`. |
| `ctf_generate_solve_prompt` | Generate ready-to-use subagent prompts for solving challenges. Returns JSON with challenge info, recommended model, tool suggestions, and full prompt text for the Task tool. |
| `ctf_save_writeup` | Save a writeup for a solved challenge -- records methodology and tools used, generates `writeup.md` in the challenge directory. Call after submitting a flag. |

## ctf-crypto (Python) -- 8 tools

Encoding pipelines, cryptographic attacks, and mathematical solving.

| Tool | Description |
|------|-------------|
| `crypto_transform_chain` | Apply a chain of encoding/decoding operations (base64, hex, rot(N), xor, vigenere, URL, binary, atbash, etc.) with intermediate results. |
| `crypto_identify` | Identify encoding or cipher type -- detects Base64, hex, hashes (MD5/SHA), JWT, binary, Caesar shifts, URL encoding. |
| `crypto_rsa_toolkit` | RSA attacks: auto, small_e, fermat, wiener, factordb, or given_pq. Accepts n, e, c, and optional p/q/dp/dq. |
| `crypto_math_solve` | Evaluate sympy expressions (`mode="eval"`) or solve Z3 constraints (`mode="z3"` with semicolon-separated constraints). |
| `crypto_hash_crack` | Identify hash type and attempt lightweight dictionary cracking. Supports MD5, SHA-1, SHA-256, SHA-512, bcrypt, crypt variants. |
| `crypto_frequency_analysis` | Character and bigram frequency analysis, chi-squared English scoring, and index of coincidence for classical cipher analysis. |
| `crypto_xor_analyze` | XOR key recovery and analysis -- known-plaintext attack, Kasiski examination, Index of Coincidence key length estimation, single-byte brute force, multi-byte key recovery. |
| `crypto_sage_solve` | Execute SageMath scripts for finite field math, lattice reduction, discrete log, and polynomial solving. Returns stdout/stderr with optional JSON parsing. |

## ctf-pwn (Python) -- 10 tools

Binary analysis and exploit development.

| Tool | Description |
|------|-------------|
| `pwn_triage` | Comprehensive one-shot analysis -- file type, checksec mitigations, architecture, imports/exports, sections, dangerous functions, interesting strings. |
| `pwn_disassemble` | Disassemble a function or address range using radare2. |
| `pwn_rop_gadgets` | Search for ROP gadgets using ROPgadget with optional filters. |
| `pwn_pattern_offset` | Generate cyclic patterns or find crash offsets using pwntools. |
| `pwn_shellcode_generate` | Generate shellcode via pwntools shellcraft (sh, cat_flag, connect_back, execve) for amd64/i386/arm/aarch64/mips. |
| `pwn_pwntools_template` | Generate a complete pwntools exploit script skeleton (ret2win, ret2libc, format_string, shellcode) from binary analysis. |
| `pwn_angr_analyze` | Symbolic execution via angr -- auto mode finds flag-like output, find_addr reaches specific addresses, find_string matches output. |
| `pwn_one_gadget` | Find single-instruction RCE gadgets in libc using one_gadget. Returns gadget addresses and their constraints. |
| `pwn_libc_lookup` | Identify libc version from leaked symbol addresses via libc.rip API. Computes base address and key offsets (system, /bin/sh, hooks). |
| `pwn_format_string` | Format string exploit automation -- probe for stack offset (`find_offset`), generate arbitrary write payloads (`write`), or get a reference guide (`info`). |

## ctf-forensics (Python) -- 6 tools

File forensics and steganography.

| Tool | Description |
|------|-------------|
| `forensics_file_triage` | Comprehensive file analysis -- file type, EXIF metadata, binwalk signatures, interesting strings, entropy, trailing data detection. |
| `forensics_stego_analyze` | Systematic steganography analysis. Runs all applicable tools per file type: zsteg (PNG), steghide (JPEG/BMP/WAV), EXIF comments, trailing data, LSB. |
| `forensics_extract_embedded` | Extract embedded files using binwalk and foremost. Returns extracted file types, sizes, and content previews. |
| `forensics_entropy_analysis` | Block-level Shannon entropy calculation to detect encrypted/compressed regions and anomalous boundaries. |
| `forensics_image_analysis` | Deep image inspection -- channel statistics, LSB ratio analysis, palette examination, histogram anomaly detection. Optional LSB data extraction. |
| `forensics_volatility` | Memory dump analysis using volatility3. Runs plugins (pslist, filescan, hashdump, netscan, etc.) on .raw/.vmem/.dmp files. Tries JSON renderer with text fallback. |

## ctf-gdb (Python) -- 5 tools

Dynamic binary analysis using GDB batch mode.

| Tool | Description |
|------|-------------|
| `gdb_run` | Run a binary under GDB with a sequence of commands. General-purpose GDB execution with structured output parsing. |
| `gdb_break_inspect` | Set breakpoints, run to them, dump registers, stack, memory, and backtrace at each breakpoint. |
| `gdb_trace_input` | Trace where user input lands in memory. Generates cyclic patterns, catches SIGSEGV, and reports pattern offsets for buffer overflow development. |
| `gdb_memory_dump` | Read memory at specific addresses at a given execution point. Returns hex dump and ASCII interpretation. |
| `gdb_checksec_runtime` | Get runtime security info -- actual ASLR state, libc base address, process mappings, GOT entries, and resolved symbol addresses. |

## ctf-rev (Python) -- 6 tools

Deep static analysis using radare2.

| Tool | Description |
|------|-------------|
| `rev_functions` | List all functions with addresses, sizes, basic block counts, and call targets after full analysis. |
| `rev_xrefs` | Find cross-references to/from a function or address. Shows call graph relationships (who calls what). |
| `rev_decompile` | Decompile a function to pseudocode. Tries r2ghidra (pdg), r2dec (pdd), then falls back to annotated disassembly. |
| `rev_strings_xrefs` | List strings with which functions reference them. Optional regex filter (e.g., "flag\|password\|key"). |
| `rev_cfg` | Extract control flow graph for a function -- basic blocks, instructions, branch targets, and conditions. |
| `rev_diff` | Compare two binaries to find byte-level differences. Useful for patch analysis challenges. |

## ctf-jail (Python) -- 4 tools

Pyjail and bash jail analysis, bypass payload generation, and subclass chain discovery.

| Tool | Description |
|------|-------------|
| `jail_analyze_source` | Parse jail source code to identify blocked strings, chars, restriction mechanisms (blacklist, AST filtering, audit hooks, builtins wiped), and suggest bypasses. |
| `jail_find_subclass_chain` | Walk Python MRO/subclass tree to find chains reaching a target module (os, builtins, etc.) via `__init__.__globals__`. |
| `jail_construct_string` | Construct a target string using only allowed characters -- chr(), hex escapes, bytes().decode(), Unicode NFKC, f-strings. |
| `jail_build_payload` | Generate complete jail bypass payloads (Python or bash) that avoid blocked strings and characters. Supports read_flag, exec_command, get_shell goals. |
