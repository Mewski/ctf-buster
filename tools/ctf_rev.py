#!/usr/bin/env python3
"""CTF Reverse Engineering MCP Server — decompilation, xrefs, CFG, function analysis."""

import json
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "lib"))
from fastmcp import FastMCP
from subprocess_utils import run_tool

mcp = FastMCP(
    "ctf-rev",
    instructions=(
        "Reverse engineering tools for deep binary analysis. Use rev_functions for "
        "function discovery, rev_decompile for pseudocode, and rev_strings_xrefs to "
        "find string references in context. Start with rev_functions to get an overview."
    ),
)


def _r2_cmd(path, commands, timeout=60):
    """Run radare2 in quiet batch mode with semicolon-separated commands."""
    cmd_str = "; ".join(commands)
    return run_tool(["r2", "-q", "-c", cmd_str, path], timeout=timeout)


def _parse_r2_json(stdout):
    """Parse JSON from r2 output, handling potential warnings before the JSON."""
    stdout = stdout.strip()
    if not stdout:
        return None
    start = stdout.find("[")
    obj_start = stdout.find("{")
    if start < 0 and obj_start < 0:
        return None
    if start < 0:
        start = obj_start
    elif obj_start >= 0:
        start = min(start, obj_start)
    try:
        return json.loads(stdout[start:])
    except json.JSONDecodeError:
        return None


@mcp.tool()
def rev_functions(path: str) -> str:
    """List all functions with addresses, sizes, and call targets after full analysis.

    Args:
        path: Path to the binary

    Returns:
        JSON list of functions with name, address, size, and basic block count.
    """
    path = os.path.realpath(path)
    if not os.path.isfile(path):
        return json.dumps({"error": f"File not found: {path}"})

    result = _r2_cmd(path, ["aaa", "aflj"])
    if result["returncode"] != 0:
        return json.dumps(
            {"error": "radare2 analysis failed", "stderr": result["stderr"][:2000]}
        )

    functions_raw = _parse_r2_json(result["stdout"])
    if functions_raw is None:
        return json.dumps(
            {"error": "No function data from r2", "raw": result["stdout"][:2000]}
        )

    functions = []
    for f in functions_raw:
        func = {
            "name": f.get("name", ""),
            "address": hex(f.get("offset", 0)),
            "size": f.get("size", 0),
            "basic_blocks": f.get("nbbs", 0),
        }
        if f.get("callrefs"):
            func["calls"] = [
                {"address": hex(ref.get("addr", 0)), "type": ref.get("type", "")}
                for ref in f["callrefs"]
            ]
        functions.append(func)

    return json.dumps(
        {
            "path": path,
            "function_count": len(functions),
            "functions": functions,
        },
        indent=2,
    )


@mcp.tool()
def rev_decompile(path: str, function: str = "main", decompiler: str = "auto") -> str:
    """Decompile a function to pseudocode.

    Tries r2ghidra (pdg), r2dec (pdd), or falls back to annotated disassembly.

    Args:
        path: Path to the binary
        function: Function name or hex address to decompile (default: "main")
        decompiler: "r2ghidra", "r2dec", or "auto" (tries both, then falls back to disasm)

    Returns:
        JSON with decompiled pseudocode or annotated assembly.
    """
    path = os.path.realpath(path)
    if not os.path.isfile(path):
        return json.dumps({"error": f"File not found: {path}"})

    seek = function if function.startswith("0x") else f"sym.{function}"
    if function == "main":
        seek = "main"

    decompilers = []
    if decompiler == "auto":
        decompilers = [("r2ghidra", "pdg"), ("r2dec", "pdd"), ("disasm", "pdf")]
    elif decompiler == "r2ghidra":
        decompilers = [("r2ghidra", "pdg"), ("disasm", "pdf")]
    elif decompiler == "r2dec":
        decompilers = [("r2dec", "pdd"), ("disasm", "pdf")]
    else:
        decompilers = [("disasm", "pdf")]

    for name, cmd in decompilers:
        # Combine address lookup and decompile in a single r2 invocation
        result = _r2_cmd(
            path,
            ["aaa", f"s {seek}", "echo ===ADDR===", "?v $$", f"echo ===CODE===", cmd],
            timeout=120,
        )

        output = result["stdout"].strip()
        if result["returncode"] == 0 and output and "Cannot" not in output:
            # Parse address and code from combined output
            address = "unknown"
            code = output
            if "===ADDR===" in output and "===CODE===" in output:
                parts = output.split("===CODE===", 1)
                addr_section = parts[0].split("===ADDR===", 1)
                if len(addr_section) > 1:
                    address = addr_section[1].strip()
                code = parts[1].strip() if len(parts) > 1 else ""

            if code and len(code) > 20:
                return json.dumps(
                    {
                        "path": path,
                        "function": function,
                        "address": address,
                        "decompiler": name,
                        "code": code[:5000],
                    },
                    indent=2,
                )

    return json.dumps(
        {
            "error": f"Failed to decompile {function} — no decompiler produced output",
            "path": path,
        }
    )


@mcp.tool()
def rev_strings_xrefs(path: str, filter: str = "") -> str:
    """List strings with the functions that reference them.

    Args:
        path: Path to the binary
        filter: Optional regex to filter strings (e.g., "flag|password|key")

    Returns:
        JSON list of strings with addresses, sections, and referencing functions.
    """
    path = os.path.realpath(path)
    if not os.path.isfile(path):
        return json.dumps({"error": f"File not found: {path}"})

    result = _r2_cmd(path, ["aaa", "izj"])
    if result["returncode"] != 0:
        return json.dumps(
            {"error": "radare2 analysis failed", "stderr": result["stderr"][:2000]}
        )

    strings_raw = _parse_r2_json(result["stdout"])
    if strings_raw is None:
        return json.dumps({"error": "Failed to parse string data"})

    filter_re = re.compile(filter, re.IGNORECASE) if filter else None

    # Filter strings first, then batch xref lookups in a single r2 invocation
    filtered = []
    for s in strings_raw:
        string_val = s.get("string", "")
        if filter_re and not filter_re.search(string_val):
            continue
        if not filter_re and len(string_val) < 4:
            continue
        filtered.append(s)
        if len(filtered) >= 100:
            break

    # Build a single r2 command that seeks to each string and gets xrefs
    xref_cmds = ["aaa"]
    for s in filtered:
        addr = s.get("vaddr", s.get("paddr", 0))
        xref_cmds.append(f"echo ===XREF_{addr}===")
        xref_cmds.append(f"s {addr}")
        xref_cmds.append("axtj")

    xref_result = _r2_cmd(path, xref_cmds, timeout=120) if filtered else None
    xref_output = xref_result["stdout"] if xref_result else ""

    # Parse batched xref results
    xref_map = {}
    for s in filtered:
        addr = s.get("vaddr", s.get("paddr", 0))
        marker = f"===XREF_{addr}==="
        if marker in xref_output:
            section = xref_output.split(marker, 1)[1]
            # Take content until next marker or end
            next_marker = section.find("===XREF_")
            if next_marker >= 0:
                section = section[:next_marker]
            parsed = _parse_r2_json(section.strip())
            if parsed:
                xref_map[addr] = parsed

    strings = []
    for s in filtered:
        string_val = s.get("string", "")
        addr = s.get("vaddr", s.get("paddr", 0))
        entry = {
            "string": string_val,
            "address": hex(addr),
            "section": s.get("section", ""),
            "type": s.get("type", ""),
            "size": s.get("size", 0),
        }

        xrefs = xref_map.get(addr)
        if xrefs:
            entry["referenced_by"] = [
                {
                    "function": x.get("fcn_name", ""),
                    "address": hex(x.get("from", 0)),
                    "opcode": x.get("opcode", ""),
                }
                for x in xrefs
            ]

        strings.append(entry)

    return json.dumps(
        {
            "path": path,
            "filter": filter,
            "count": len(strings),
            "strings": strings,
        },
        indent=2,
    )


if __name__ == "__main__":
    mcp.run(transport="stdio")
