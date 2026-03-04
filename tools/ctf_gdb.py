#!/usr/bin/env python3
"""CTF GDB MCP Server — dynamic analysis, breakpoint inspection, input tracing."""

import json
import os
import re
import shlex
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "lib"))
from fastmcp import FastMCP
from subprocess_utils import run_tool

mcp = FastMCP(
    "ctf-gdb",
    instructions=(
        "Dynamic binary analysis tools using GDB. Use gdb_break_inspect to examine "
        "registers and memory at breakpoints. Use gdb_trace_input to find buffer "
        "overflow offsets. Use gdb_run for general GDB command execution. "
        "Use gdb_checksec_runtime for runtime security info and symbol resolution."
    ),
)


def _build_gdb_script(preamble_commands, main_commands):
    """Build a GDB batch script with standard preamble."""
    lines = [
        "set pagination off",
        "set disable-randomization on",
        "set confirm off",
        "set print elements 0",
    ]
    lines.extend(preamble_commands)
    lines.extend(main_commands)
    lines.append("quit")
    return "\n".join(lines)


def _write_temp(content, suffix="", mode="w"):
    """Write content to a temp file, return path."""
    f = tempfile.NamedTemporaryFile(mode=mode, suffix=suffix, delete=False)
    f.write(content)
    f.close()
    return f.name


def _run_gdb(path, script_content, args="", stdin_data=None, timeout=30):
    """Execute GDB in batch mode with a script."""
    script_path = _write_temp(script_content, suffix=".gdb")
    temps = [script_path]

    try:
        cmd = ["gdb", "--batch", "--quiet", "-x", script_path, "--args", path]
        if args:
            cmd.extend(shlex.split(args))

        input_bytes = None
        if stdin_data is not None:
            input_bytes = (
                stdin_data if isinstance(stdin_data, bytes) else stdin_data.encode()
            )

        return run_tool(cmd, timeout=timeout, input_data=input_bytes)
    finally:
        for t in temps:
            try:
                os.unlink(t)
            except OSError:
                pass


def _parse_registers(output):
    """Extract register values from 'info registers' output."""
    regs = {}
    for line in output.splitlines():
        m = re.match(r"^(\w+)\s+(0x[0-9a-fA-F]+)\s+(.*)$", line.strip())
        if m:
            regs[m.group(1)] = {"hex": m.group(2), "decimal": m.group(3).strip()}
    return regs


def _parse_backtrace(output):
    """Extract backtrace frames from 'bt' output."""
    frames = []
    for line in output.splitlines():
        m = re.match(r"^#(\d+)\s+(0x[0-9a-fA-F]+)?\s*(?:in\s+)?(\S+)", line.strip())
        if m:
            frames.append(
                {
                    "frame": int(m.group(1)),
                    "address": m.group(2) or "",
                    "function": m.group(3),
                }
            )
    return frames


def _parse_memory(output):
    """Parse GDB x/ memory dump output."""
    lines = []
    for line in output.splitlines():
        line = line.strip()
        if line and (line.startswith("0x") or ":" in line):
            lines.append(line)
    return lines


@mcp.tool()
def gdb_run(
    path: str,
    commands: list[str],
    args: str = "",
    stdin_data: str = "",
    stdin_hex: str = "",
    timeout: int = 30,
) -> str:
    """Run a binary under GDB with a sequence of GDB commands.

    Args:
        path: Path to the binary
        commands: List of GDB commands (e.g., ["break main", "run", "info registers"])
        args: Command-line arguments for the binary
        stdin_data: String data to feed as stdin
        stdin_hex: Hex-encoded bytes to feed as stdin (alternative to stdin_data)
        timeout: Execution timeout in seconds

    Returns:
        JSON with GDB output, parsed registers, and backtrace.
    """
    path = os.path.realpath(path)
    if not os.path.isfile(path):
        return json.dumps({"error": f"File not found: {path}"})

    stdin = None
    if stdin_hex:
        try:
            stdin = bytes.fromhex(stdin_hex.replace(" ", ""))
        except ValueError:
            return json.dumps({"error": "Invalid hex in stdin_hex"})
    elif stdin_data:
        stdin = stdin_data.encode()

    preamble = []
    main_cmds = list(commands)

    has_run = any(
        c.strip().startswith(("run", "r ", "start", "starti")) for c in commands
    )
    if not has_run and stdin is not None:
        stdin_path = _write_temp(stdin, suffix=".stdin", mode="wb")
        preamble.append(f"run < {stdin_path}")

    script = _build_gdb_script(preamble, main_cmds)
    result = _run_gdb(
        path,
        script,
        args=args,
        stdin_data=stdin if has_run else None,
        timeout=timeout,
    )

    output = result["stdout"] + result.get("stderr", "")

    parsed = {
        "path": path,
        "commands": commands,
        "output": output[:10000],
        "returncode": result["returncode"],
    }

    if "error" in result:
        parsed["error"] = result["error"]

    registers = _parse_registers(output)
    if registers:
        parsed["registers"] = registers

    backtrace = _parse_backtrace(output)
    if backtrace:
        parsed["backtrace"] = backtrace

    return json.dumps(parsed, indent=2)


@mcp.tool()
def gdb_break_inspect(
    path: str,
    breakpoints: list[str],
    args: str = "",
    stdin_data: str = "",
    stdin_hex: str = "",
    memory_reads: list[str] | None = None,
) -> str:
    """Set breakpoints, run to them, and dump registers, stack, and memory.

    Args:
        path: Path to the binary
        breakpoints: Breakpoint locations — function names or hex addresses ("0x401234")
        args: Command-line arguments for the binary
        stdin_data: String data to feed as stdin
        stdin_hex: Hex-encoded bytes for stdin
        memory_reads: Optional GDB x/ specs (e.g., ["x/32xb $rsp", "x/s 0x404000"])

    Returns:
        JSON with per-breakpoint snapshots: registers, stack, memory, backtrace.
    """
    path = os.path.realpath(path)
    if not os.path.isfile(path):
        return json.dumps({"error": f"File not found: {path}"})

    stdin = None
    if stdin_hex:
        try:
            stdin = bytes.fromhex(stdin_hex.replace(" ", ""))
        except ValueError:
            return json.dumps({"error": "Invalid hex in stdin_hex"})
    elif stdin_data:
        stdin = stdin_data.encode()

    main_cmds = []
    for bp in breakpoints:
        main_cmds.append(f"break {bp}")

    if stdin is not None:
        stdin_path = _write_temp(stdin, suffix=".stdin", mode="wb")
        main_cmds.append(f"run < {stdin_path}")
    else:
        main_cmds.append("run")

    for i, bp in enumerate(breakpoints):
        main_cmds.append(f"echo ===BREAKPOINT_{i}_{bp}===\\n")
        main_cmds.append("info registers")
        main_cmds.append("echo ===STACK===\\n")
        main_cmds.append("x/32xg $rsp")
        main_cmds.append("echo ===BACKTRACE===\\n")
        main_cmds.append("bt")
        if memory_reads:
            main_cmds.append("echo ===MEMORY===\\n")
            for mem_cmd in memory_reads:
                main_cmds.append(
                    mem_cmd if mem_cmd.startswith("x/") else f"x/ {mem_cmd}"
                )
        if i < len(breakpoints) - 1:
            main_cmds.append("continue")

    script = _build_gdb_script([], main_cmds)
    result = _run_gdb(path, script, args=args, timeout=30)
    output = result["stdout"] + result.get("stderr", "")

    snapshots = []
    sections = re.split(r"===BREAKPOINT_(\d+)_(.+?)===", output)

    i = 1
    while i + 2 < len(sections):
        bp_name = sections[i + 1]
        bp_output = sections[i + 2]

        snapshot = {
            "breakpoint": bp_name,
            "registers": _parse_registers(bp_output),
            "backtrace": _parse_backtrace(bp_output),
        }

        stack_match = re.search(r"===STACK===(.*?)(?:===|$)", bp_output, re.DOTALL)
        if stack_match:
            snapshot["stack"] = _parse_memory(stack_match.group(1))

        mem_match = re.search(r"===MEMORY===(.*?)(?:===|$)", bp_output, re.DOTALL)
        if mem_match:
            snapshot["memory"] = _parse_memory(mem_match.group(1))

        snapshots.append(snapshot)
        i += 3

    parsed = {
        "path": path,
        "breakpoints": breakpoints,
        "snapshots": snapshots,
        "raw_output": output[:5000],
    }
    if "error" in result:
        parsed["error"] = result["error"]

    return json.dumps(parsed, indent=2)


@mcp.tool()
def gdb_trace_input(
    path: str,
    input_data: str = "",
    input_hex: str = "",
    breakpoint: str = "",
    pattern_length: int = 200,
) -> str:
    """Trace where user input lands in memory — finds buffer overflow offsets.

    If no input is provided, generates a cyclic pattern. Catches SIGSEGV and
    shows where pattern bytes appear in registers and on the stack.

    Args:
        path: Path to the binary
        input_data: String input to send
        input_hex: Hex-encoded input bytes
        breakpoint: Optional breakpoint instead of waiting for crash
        pattern_length: Length of cyclic pattern to generate (default 200)

    Returns:
        JSON with crash info, register values, pattern offsets, and stack layout.
    """
    path = os.path.realpath(path)
    if not os.path.isfile(path):
        return json.dumps({"error": f"File not found: {path}"})

    use_pattern = False
    if input_hex:
        try:
            stdin = bytes.fromhex(input_hex.replace(" ", ""))
        except ValueError:
            return json.dumps({"error": "Invalid hex in input_hex"})
    elif input_data:
        stdin = input_data.encode()
    else:
        try:
            from pwn import cyclic

            stdin = cyclic(pattern_length)
            use_pattern = True
        except ImportError:
            # Fallback: simple sequential pattern
            stdin = b""
            for i in range(pattern_length // 4):
                stdin += bytes(
                    [
                        0x41 + (i % 26),
                        0x61 + (i % 26),
                        (i >> 8) & 0xFF,
                        i & 0xFF,
                    ]
                )
            stdin = stdin[:pattern_length]
            use_pattern = True

    stdin_path = _write_temp(stdin, suffix=".stdin", mode="wb")

    main_cmds = []
    if breakpoint:
        main_cmds.append(f"break {breakpoint}")
    main_cmds.extend(
        [
            f"run < {stdin_path}",
            "echo ===CRASH_INFO===\\n",
            "info registers",
            "echo ===STACK===\\n",
            "x/64xg $rsp",
            "echo ===BACKTRACE===\\n",
            "bt",
        ]
    )

    script = _build_gdb_script([], main_cmds)
    result = _run_gdb(path, script, timeout=30)
    output = result["stdout"] + result.get("stderr", "")

    parsed = {
        "path": path,
        "input_length": len(stdin),
        "used_cyclic_pattern": use_pattern,
        "registers": _parse_registers(output),
        "backtrace": _parse_backtrace(output),
    }

    if "SIGSEGV" in output:
        parsed["signal"] = "SIGSEGV"
        sig_match = re.search(r"(0x[0-9a-fA-F]+) in", output)
        if sig_match:
            parsed["crash_address"] = sig_match.group(1)
    elif "SIGABRT" in output:
        parsed["signal"] = "SIGABRT"
    elif breakpoint:
        parsed["signal"] = None
        parsed["stopped_at"] = breakpoint

    if use_pattern and "crash_address" in parsed:
        try:
            from pwn import cyclic_find

            crash_val = int(parsed["crash_address"], 16) & 0xFFFFFFFF
            offset = cyclic_find(crash_val)
            if offset >= 0:
                parsed["pattern_offset"] = offset
                parsed["overflow_size"] = offset
        except (ImportError, ValueError):
            pass

    if use_pattern and parsed.get("registers"):
        offsets_found = {}
        try:
            from pwn import cyclic_find

            for reg, val in parsed["registers"].items():
                try:
                    reg_val = int(val["hex"], 16) & 0xFFFFFFFF
                    off = cyclic_find(reg_val)
                    if 0 <= off < pattern_length:
                        offsets_found[reg] = off
                except (ValueError, TypeError):
                    pass
        except ImportError:
            pass
        if offsets_found:
            parsed["pattern_offsets_in_registers"] = offsets_found

    stack_match = re.search(r"===STACK===(.*?)(?:===|$)", output, re.DOTALL)
    if stack_match:
        parsed["stack"] = _parse_memory(stack_match.group(1))

    parsed["raw_output"] = output[:5000]

    try:
        os.unlink(stdin_path)
    except OSError:
        pass

    return json.dumps(parsed, indent=2)


@mcp.tool()
def gdb_memory_dump(
    path: str,
    breakpoint: str,
    addresses: list[str],
    args: str = "",
    stdin_data: str = "",
    stdin_hex: str = "",
) -> str:
    """Read memory at specific addresses at a given execution point.

    Args:
        path: Path to the binary
        breakpoint: Where to stop execution (function name or hex address)
        addresses: List of "address:byte_count" specs (e.g., ["0x404000:64", "$rsp:128"])
        args: Command-line arguments for the binary
        stdin_data: String data for stdin
        stdin_hex: Hex-encoded bytes for stdin

    Returns:
        JSON with hex dump and ASCII interpretation for each address.
    """
    path = os.path.realpath(path)
    if not os.path.isfile(path):
        return json.dumps({"error": f"File not found: {path}"})

    stdin = None
    if stdin_hex:
        try:
            stdin = bytes.fromhex(stdin_hex.replace(" ", ""))
        except ValueError:
            return json.dumps({"error": "Invalid hex in stdin_hex"})
    elif stdin_data:
        stdin = stdin_data.encode()

    main_cmds = [f"break {breakpoint}"]
    if stdin is not None:
        stdin_path = _write_temp(stdin, suffix=".stdin", mode="wb")
        main_cmds.append(f"run < {stdin_path}")
    else:
        main_cmds.append("run")

    for addr_spec in addresses:
        parts = addr_spec.rsplit(":", 1)
        addr = parts[0]
        count = int(parts[1]) if len(parts) > 1 else 64
        label = addr_spec.replace("$", "REG_")
        main_cmds.append(f"echo ===DUMP_{label}===\\n")
        main_cmds.append(f"x/{count}xb {addr}")
        main_cmds.append(f"echo ===ASCII_{label}===\\n")
        main_cmds.append(f"x/{count}cb {addr}")

    script = _build_gdb_script([], main_cmds)
    result = _run_gdb(path, script, args=args, stdin_data=stdin, timeout=30)
    output = result["stdout"] + result.get("stderr", "")

    memory_regions = []
    for addr_spec in addresses:
        label = addr_spec.replace("$", "REG_")
        region = {"address": addr_spec}

        dump_match = re.search(
            rf"===DUMP_{re.escape(label)}===(.*?)===ASCII_{re.escape(label)}===",
            output,
            re.DOTALL,
        )
        if dump_match:
            region["hex_dump"] = _parse_memory(dump_match.group(1))

        ascii_match = re.search(
            rf"===ASCII_{re.escape(label)}===(.*?)(?:===|$)", output, re.DOTALL
        )
        if ascii_match:
            region["ascii"] = _parse_memory(ascii_match.group(1))

        memory_regions.append(region)

    parsed = {
        "path": path,
        "breakpoint": breakpoint,
        "memory": memory_regions,
    }
    if "error" in result:
        parsed["error"] = result["error"]

    return json.dumps(parsed, indent=2)


@mcp.tool()
def gdb_checksec_runtime(path: str, symbols: list[str] | None = None) -> str:
    """Get runtime security info — ASLR state, libc base, GOT entries, symbol addresses.

    Args:
        path: Path to the binary
        symbols: Optional symbol names to resolve (e.g., ["system", "execve"])

    Returns:
        JSON with base addresses, process mappings, and resolved symbols.
    """
    path = os.path.realpath(path)
    if not os.path.isfile(path):
        return json.dumps({"error": f"File not found: {path}"})

    main_cmds = [
        "break main",
        "run",
        "echo ===MAPPINGS===\\n",
        "info proc mappings",
        "echo ===PLT===\\n",
        "info functions @plt",
        "echo ===REGISTERS===\\n",
        "info registers",
    ]

    if symbols:
        main_cmds.append("echo ===SYMBOLS===\\n")
        for sym in symbols:
            main_cmds.append(f"info address {sym}")

    script = _build_gdb_script([], main_cmds)
    result = _run_gdb(path, script, timeout=30)
    output = result["stdout"] + result.get("stderr", "")

    parsed = {"path": path}

    mappings = []
    in_mappings = False
    for line in output.splitlines():
        if "===MAPPINGS===" in line:
            in_mappings = True
            continue
        if "===" in line and in_mappings:
            break
        if in_mappings and line.strip():
            parts = line.split()
            if len(parts) >= 4 and parts[0].startswith("0x"):
                entry = {
                    "start": parts[0],
                    "end": parts[1],
                }
                if len(parts) >= 5:
                    entry["perms"] = parts[3]
                    entry["file"] = parts[-1]
                mappings.append(entry)

    parsed["mappings"] = mappings[:50]

    for m in mappings:
        if "libc" in m.get("file", "") and "r-x" in m.get("perms", ""):
            parsed["libc_base"] = m["start"]
            parsed["libc_path"] = m["file"]
            break

    for m in mappings:
        fname = m.get("file", "")
        if fname and os.path.basename(fname) == os.path.basename(path):
            if "r-x" in m.get("perms", ""):
                parsed["binary_base"] = m["start"]
                break

    if symbols:
        resolved = {}
        for line in output.splitlines():
            addr_match = re.search(r'Symbol "(\w+)" is at (0x[0-9a-fA-F]+)', line)
            if addr_match:
                resolved[addr_match.group(1)] = addr_match.group(2)
        parsed["resolved_symbols"] = resolved

    if "error" in result:
        parsed["error"] = result["error"]

    return json.dumps(parsed, indent=2)


if __name__ == "__main__":
    mcp.run(transport="stdio")
