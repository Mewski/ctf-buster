# Claude Code Integration

## MCP Server Registration

### Via `.mcp.json` (recommended)

Place in your workspace root:

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

### Via CLI

```bash
claude mcp add -s user ctf-buster -- /path/to/target/release/ctf mcp --workspace /path/to/workspace
claude mcp add -s user ctf-crypto -- python3 /path/to/tools/ctf_crypto.py
claude mcp add -s user ctf-pwn -- python3 /path/to/tools/ctf_pwn.py
claude mcp add -s user ctf-forensics -- python3 /path/to/tools/ctf_forensics.py
claude mcp add -s user ctf-gdb -- python3 /path/to/tools/ctf_gdb.py
claude mcp add -s user ctf-rev -- python3 /path/to/tools/ctf_rev.py
```

## Typical Workflow

1. `ctf_workspace_status` -- understand the current competition state
2. `ctf_challenges` -- browse available challenges
3. `ctf_challenge_detail` -- read a specific challenge description
4. `ctf_download_files` -- pull challenge attachments into the workspace
5. Use domain tools (`pwn_triage`, `forensics_file_triage`, `crypto_rsa_toolkit`, etc.)
6. `ctf_submit_flag` -- submit the flag

## Multi-Agent Orchestration

See the orchestration strategy documented in [CLAUDE.md](../CLAUDE.md), which
covers:
- Priority-based challenge queue
- Model selection per challenge type
- Subagent prompt patterns
- Flag detection and auto-submission rules
