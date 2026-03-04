# Configuration

## Workspace Config (`.ctf.toml`)

Each workspace is defined by a `.ctf.toml` file at the workspace root.

### Minimal

```toml
[platform]
url = "https://ctf.example.com"

[workspace]
name = "my-ctf"
```

### Full

```toml
[platform]
type = "ctfd"                    # "ctfd" or "rctf" (auto-detected if omitted)
url = "https://ctf.example.com"
token = "${CTF_TOKEN}"           # Supports ${VAR} and ${VAR:-default} expansion

[workspace]
name = "heroctf"

[scaffold]
template = "{category}/{name}"   # Directory layout template (default)
create_solve_file = true         # Generate solve.py per challenge (default: true)
create_notes_file = true         # Generate notes.md per challenge (default: true)
```

## Authentication

Token resolution order (highest priority first):

1. `--token` CLI arg: `ctf mcp --token <token>`
2. `CTF_TOKEN` environment variable
3. `token` field in `.ctf.toml` (supports env var expansion)
4. System keyring (set via `ctf auth login`)

### Session cookie support

CTFd session cookies (Flask format containing `.`) are auto-detected. When
using a session cookie instead of an API token, the client automatically:
- Sets the cookie via a cookie jar
- Fetches a CSRF nonce for POST requests

### Environment variable expansion

The `token` field in `.ctf.toml` supports:
- `${VAR}` -- expand to the value of environment variable `VAR`
- `${VAR:-default}` -- expand to `VAR` or `default` if unset

## Scaffold Template Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `{category}` | Challenge category, lowercased and sanitized | `crypto` |
| `{name}` | Challenge name, lowercased and sanitized | `easy-rsa` |

## Workspace Structure

After syncing, a workspace looks like this:

```
my-ctf/
  .ctf.toml
  .ctf-state.json       # Local state (auto-managed)
  crypto/
    easy-rsa/
      solve.py           # Auto-generated solve template
      notes.md           # Auto-generated notes with description
      dist/              # Downloaded challenge files
        output.txt
        rsa.pub
  web/
    login-bypass/
      solve.py
      notes.md
      dist/
        app.py
```

## Platform Support

| Platform | Status | Auth method |
|----------|--------|-------------|
| [CTFd](https://ctfd.io/) | Supported | API token or session cookie |
| [rCTF](https://rctf.redpwn.net/) | Supported | API token (JWT) |

Platform type is auto-detected by probing the API endpoints. Override with
`type` in the `[platform]` section of `.ctf.toml`.
