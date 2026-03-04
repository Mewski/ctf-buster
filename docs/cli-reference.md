# CLI Reference

The binary is named `ctf`. All commands support `--output table|json|plain`.

## Commands

| Command | Aliases | Description |
|---------|---------|-------------|
| `ctf init <name> --url <url>` | | Initialize a CTF workspace. Creates `.ctf.toml` and directory structure. Optionally pass `--type ctfd\|rctf` to skip auto-detection. |
| `ctf auth login` | | Authenticate with the platform. Stores the API token in the system keyring. |
| `ctf auth logout` | | Remove stored credentials. |
| `ctf auth status` | | Show current authentication state. |
| `ctf sync` | | Sync challenges from the platform, scaffold directories, download attached files. Pass `--full` to also cache descriptions, hints, and auto-unlock free hints. |
| `ctf challenges` | `ls`, `chals` | List all challenges. Filter with `--category <cat>`, `--unsolved`, or `--solved`. |
| `ctf challenge <id_or_name>` | | Show full details of a challenge (description, hints, files, solve count). Pass `--download` to fetch attached files. |
| `ctf submit <flag>` | `sub` | Submit a flag. Accepts either `ctf submit <flag>` or `ctf submit <challenge> <flag>`. |
| `ctf files <id_or_name>` | `dl` | Download challenge files into the workspace `dist/` directory. |
| `ctf scoreboard` | `sb` | Show competition scoreboard. Use `--limit <n>` to control how many entries (default 10). |
| `ctf status` | | Dashboard showing team info, score, rank, and per-category solve progress. |
| `ctf mcp` | | Run as an MCP server over stdio. Optionally pass `--workspace <path>` or set `CTF_WORKSPACE`. |

## Examples

```bash
# Initialize and sync a workspace
ctf init my-ctf --url https://ctf.example.com
ctf auth login
ctf sync --full

# Browse and solve
ctf challenges --unsolved
ctf challenge "Easy RSA" --download
ctf submit "Easy RSA" "flag{found_it}"

# Check progress
ctf status
ctf scoreboard --limit 20
```
