import os
import subprocess


def run_tool(cmd, timeout=30, input_data=None, cwd=None):
    """Run a subprocess safely and return structured output."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout,
            input=input_data,
            cwd=cwd,
        )
        return {
            "stdout": result.stdout.decode("utf-8", errors="replace"),
            "stderr": result.stderr.decode("utf-8", errors="replace"),
            "returncode": result.returncode,
        }
    except subprocess.TimeoutExpired:
        return {
            "stdout": "",
            "stderr": "",
            "returncode": -1,
            "error": f"Timed out after {timeout}s",
        }
    except FileNotFoundError:
        return {
            "stdout": "",
            "stderr": "",
            "returncode": -1,
            "error": f"Tool not found: {cmd[0]}",
        }
    except Exception as e:
        return {"stdout": "", "stderr": "", "returncode": -1, "error": str(e)}


def parse_checksec(output):
    """Parse checksec output into a structured dict."""
    result = {}
    for line in output.strip().splitlines():
        line = line.strip()
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower().replace(" ", "_")
        value = value.strip()
        if key == "nx":
            result["nx"] = "enabled" in value.lower()
        elif key == "canary":
            result["canary"] = "found" in value.lower() or "enabled" in value.lower()
        elif key == "pie":
            result["pie"] = "enabled" in value.lower() or value.lower() not in (
                "no pie",
                "disabled",
            )
        elif key == "relro":
            result["relro"] = value.lower()
        elif key == "stack":
            result["canary"] = "found" in value.lower() or "enabled" in value.lower()
        elif key in ("arch", "stack_canary", "fortify", "rpath", "runpath"):
            result[key] = value
    return result


def safe_read_file(path, max_size=10_000_000):
    """Read a file with size limit. Returns bytes."""
    path = os.path.realpath(path)
    size = os.path.getsize(path)
    if size > max_size:
        raise ValueError(f"File too large: {size} bytes (max {max_size})")
    with open(path, "rb") as f:
        return f.read()


def which(tool):
    """Check if a tool is available on PATH."""
    import shutil

    return shutil.which(tool)
