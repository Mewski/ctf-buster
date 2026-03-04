# MCP Tools Reference

CTF-Buster provides 28 tools across 4 MCP servers.

## ctf-buster (Rust) -- 9 tools

Platform interaction and workspace management.

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

## ctf-crypto (Python) -- 6 tools

Encoding pipelines, cryptographic attacks, and mathematical solving.

| Tool | Description |
|------|-------------|
| `transform_chain` | Apply a chain of encoding/decoding operations (base64, hex, rot(N), xor, vigenere, URL, binary, atbash, etc.) with intermediate results. |
| `crypto_identify` | Identify encoding or cipher type -- detects Base64, hex, hashes (MD5/SHA), JWT, binary, Caesar shifts, URL encoding. |
| `rsa_toolkit` | RSA attacks: auto, small_e, fermat, wiener, factordb, or given_pq. Accepts n, e, c, and optional p/q/dp/dq. |
| `math_solve` | Evaluate sympy expressions (`mode="eval"`) or solve Z3 constraints (`mode="z3"` with semicolon-separated constraints). |
| `hash_crack` | Identify hash type and attempt lightweight dictionary cracking. Supports MD5, SHA-1, SHA-256, SHA-512, bcrypt, crypt variants. |
| `frequency_analysis` | Character and bigram frequency analysis, chi-squared English scoring, and index of coincidence for classical cipher analysis. |

## ctf-binary (Python) -- 8 tools

Binary analysis and exploit development.

| Tool | Description |
|------|-------------|
| `binary_triage` | Comprehensive one-shot analysis -- file type, checksec mitigations, architecture, imports/exports, sections, dangerous functions, interesting strings. |
| `disassemble` | Disassemble a function or address range using radare2. |
| `find_rop_gadgets` | Search for ROP gadgets using ROPgadget with optional filters. |
| `pattern_offset` | Generate cyclic patterns or find crash offsets using pwntools. |
| `shellcode_generate` | Generate shellcode via pwntools shellcraft (sh, cat_flag, connect_back, execve) for amd64/i386/arm/aarch64/mips. |
| `pwntools_template` | Generate a complete pwntools exploit script skeleton (ret2win, ret2libc, format_string, shellcode) from binary analysis. |
| `angr_analyze` | Symbolic execution via angr -- auto mode finds flag-like output, find_addr reaches specific addresses, find_string matches output. |

## ctf-forensics (Python) -- 5 tools

File forensics and steganography.

| Tool | Description |
|------|-------------|
| `file_triage` | Comprehensive file analysis -- file type, EXIF metadata, binwalk signatures, interesting strings, entropy, trailing data detection. |
| `stego_analyze` | Systematic steganography analysis. Runs all applicable tools per file type: zsteg (PNG), steghide (JPEG/BMP/WAV), EXIF comments, trailing data, LSB. |
| `extract_embedded` | Extract embedded files using binwalk and foremost. Returns extracted file types, sizes, and content previews. |
| `entropy_analysis` | Block-level Shannon entropy calculation to detect encrypted/compressed regions and anomalous boundaries. |
| `image_analysis` | Deep image inspection -- channel statistics, LSB ratio analysis, palette examination, histogram anomaly detection. Optional LSB data extraction. |
