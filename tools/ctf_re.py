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
    "ctf-re",
    instructions=(
        "Reverse engineering tools for deep binary analysis. Use r2_functions for "
        "function discovery, r2_decompile for pseudocode, r2_xrefs to trace call "
        "graphs, r2_strings_xrefs to find string references in context, and r2_cfg "
        "for control flow analysis. Start with r2_functions to get an overview."
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
def r2_functions(path: str) -> str:
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
def r2_xrefs(path: str, target: str, direction: str = "both") -> str:
    """Find cross-references to/from a function or address.

    Args:
        path: Path to the binary
        target: Function name (e.g., "main") or hex address (e.g., "0x401234")
        direction: "to" (who calls this), "from" (what this calls), or "both"

    Returns:
        JSON list of cross-references with source/destination addresses.
    """
    path = os.path.realpath(path)
    if not os.path.isfile(path):
        return json.dumps({"error": f"File not found: {path}"})

    seek = target if target.startswith("0x") else f"sym.{target}"

    xrefs_to = []
    xrefs_from = []

    if direction in ("to", "both"):
        result = _r2_cmd(path, ["aaa", f"s {seek}", "axtj"])
        if result["returncode"] == 0:
            parsed = _parse_r2_json(result["stdout"])
            if parsed:
                xrefs_to = parsed

    if direction in ("from", "both"):
        result = _r2_cmd(path, ["aaa", f"s {seek}", "axfj"])
        if result["returncode"] == 0:
            parsed = _parse_r2_json(result["stdout"])
            if parsed:
                xrefs_from = parsed

    parsed_to = [
        {
            "from_address": hex(x.get("from", 0)),
            "to_address": hex(x.get("addr", 0)),
            "type": x.get("type", ""),
            "opcode": x.get("opcode", ""),
        }
        for x in xrefs_to
    ]

    parsed_from = [
        {
            "from_address": hex(x.get("from", 0)),
            "to_address": hex(x.get("addr", 0)),
            "type": x.get("type", ""),
            "opcode": x.get("opcode", ""),
        }
        for x in xrefs_from
    ]

    return json.dumps(
        {
            "path": path,
            "target": target,
            "xrefs_to": parsed_to,
            "xrefs_from": parsed_from,
        },
        indent=2,
    )


@mcp.tool()
def r2_decompile(path: str, function: str = "main", decompiler: str = "auto") -> str:
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
        result = _r2_cmd(path, ["aaa", f"s {seek}", cmd], timeout=120)

        output = result["stdout"].strip()
        if (
            result["returncode"] == 0
            and output
            and "Cannot" not in output
            and len(output) > 20
        ):
            addr_result = _r2_cmd(path, ["aaa", f"s {seek}", "?v $$"])
            address = (
                addr_result["stdout"].strip()
                if addr_result["returncode"] == 0
                else "unknown"
            )

            return json.dumps(
                {
                    "path": path,
                    "function": function,
                    "address": address,
                    "decompiler": name,
                    "code": output[:5000],
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
def r2_strings_xrefs(path: str, filter: str = "") -> str:
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

    strings = []
    for s in strings_raw:
        string_val = s.get("string", "")
        if filter_re and not filter_re.search(string_val):
            continue
        if not filter_re and len(string_val) < 4:
            continue

        addr = s.get("vaddr", s.get("paddr", 0))
        entry = {
            "string": string_val,
            "address": hex(addr),
            "section": s.get("section", ""),
            "type": s.get("type", ""),
            "size": s.get("size", 0),
        }

        xref_result = _r2_cmd(path, ["aaa", f"s {addr}", "axtj"])
        if xref_result["returncode"] == 0:
            xrefs = _parse_r2_json(xref_result["stdout"])
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
        if len(strings) >= 100:
            break

    return json.dumps(
        {
            "path": path,
            "filter": filter,
            "count": len(strings),
            "strings": strings,
        },
        indent=2,
    )


@mcp.tool()
def r2_cfg(path: str, function: str = "main") -> str:
    """Extract control flow graph for a function.

    Args:
        path: Path to the binary
        function: Function name or hex address (default: "main")

    Returns:
        JSON with basic blocks, instructions, and branch targets.
    """
    path = os.path.realpath(path)
    if not os.path.isfile(path):
        return json.dumps({"error": f"File not found: {path}"})

    seek = function if function.startswith("0x") else f"sym.{function}"
    if function == "main":
        seek = "main"

    result = _r2_cmd(path, ["aaa", f"s {seek}", "agfj"])
    if result["returncode"] != 0 or not result["stdout"].strip():
        return json.dumps(
            {"error": "Failed to get CFG", "stderr": result["stderr"][:2000]}
        )

    cfg_raw = _parse_r2_json(result["stdout"])
    if cfg_raw is None:
        return json.dumps({"error": "Failed to parse CFG data"})

    blocks = []
    for block in cfg_raw:
        parsed_block = {
            "offset": hex(block.get("offset", 0)),
            "size": block.get("size", 0),
        }

        if "ops" in block:
            parsed_block["instructions"] = [
                {
                    "address": hex(op.get("offset", 0)),
                    "opcode": op.get("disasm", op.get("opcode", "")),
                    "type": op.get("type", ""),
                }
                for op in block["ops"]
            ]
            parsed_block["instruction_count"] = len(block["ops"])

        if "jump" in block:
            parsed_block["jump"] = hex(block["jump"])
        if "fail" in block:
            parsed_block["fail"] = hex(block["fail"])

        blocks.append(parsed_block)

    return json.dumps(
        {
            "path": path,
            "function": function,
            "block_count": len(blocks),
            "blocks": blocks,
        },
        indent=2,
    )


@mcp.tool()
def r2_diff(path1: str, path2: str) -> str:
    """Compare two binaries to find differences (patched vs original).

    Args:
        path1: Path to the first (original) binary
        path2: Path to the second (patched) binary

    Returns:
        JSON with list of byte-level differences.
    """
    path1 = os.path.realpath(path1)
    path2 = os.path.realpath(path2)
    if not os.path.isfile(path1):
        return json.dumps({"error": f"File not found: {path1}"})
    if not os.path.isfile(path2):
        return json.dumps({"error": f"File not found: {path2}"})

    summary_result = run_tool(["radiff2", "-c", path1, path2], timeout=60)
    summary = summary_result["stdout"].strip()

    detail_result = run_tool(["radiff2", path1, path2], timeout=60)
    detail = detail_result["stdout"].strip()

    diffs = []
    for line in detail.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0].startswith("0x"):
            diffs.append(
                {
                    "offset": parts[0],
                    "original": parts[1] if len(parts) > 1 else "",
                    "patched": parts[2] if len(parts) > 2 else "",
                }
            )

    return json.dumps(
        {
            "file1": path1,
            "file2": path2,
            "summary": summary,
            "differences": diffs[:500],
            "diff_count": len(diffs),
        },
        indent=2,
    )


if __name__ == "__main__":
    mcp.run(transport="stdio")
