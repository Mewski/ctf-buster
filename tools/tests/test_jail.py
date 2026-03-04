"""Tests for ctf_jail.py — jail escape MCP tools."""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import ctf_jail


def _unwrap(tool):
    """Get underlying function from FastMCP tool wrapper (2.x .fn vs 3.x plain)."""
    return getattr(tool, "fn", tool)


analyze = _unwrap(ctf_jail.jail_analyze_source)
find_chain = _unwrap(ctf_jail.jail_find_subclass_chain)
construct = _unwrap(ctf_jail.jail_construct_string)
build_payload = _unwrap(ctf_jail.jail_build_payload)


# ---------------------------------------------------------------------------
# jail_analyze_source tests
# ---------------------------------------------------------------------------


class TestAnalyzeSource:
    def test_empty_source(self):
        result = json.loads(analyze(""))
        assert "error" in result

    def test_detects_python_blacklist(self):
        source = """
inp = input("> ")
if "import" in inp or "os" in inp or "system" in inp:
    print("blocked!")
    exit()
exec(inp)
"""
        result = json.loads(analyze(source))
        assert result["jail_type"] == "python"
        assert "import" in result["blocked_strings"]
        assert "os" in result["blocked_strings"]
        assert "system" in result["blocked_strings"]

    def test_detects_blocked_chars(self):
        source = """
inp = input()
for c in inp:
    if c in "_.":
        print("nope")
        exit()
eval(inp)
"""
        result = json.loads(analyze(source))
        assert "_" in result["blocked_chars"]
        assert "." in result["blocked_chars"]

    def test_detects_builtins_wiped(self):
        source = """
inp = input()
exec(inp, {"__builtins__": {}})
"""
        result = json.loads(analyze(source))
        assert result["builtins_wiped"] is True
        assert "builtins_wiped" in result["restriction_mechanism"]

    def test_detects_builtins_none(self):
        source = """
exec(inp, {"__builtins__": None})
"""
        result = json.loads(analyze(source))
        assert result["builtins_wiped"] is True

    def test_detects_ast_filtering(self):
        source = """
import ast
tree = ast.parse(inp)
for node in ast.walk(tree):
    if isinstance(node, ast.Import):
        raise Exception("no imports")
exec(compile(tree, "<jail>", "exec"))
"""
        result = json.loads(analyze(source))
        assert result["ast_filtered"] is True
        assert "ast_filtering" in result["restriction_mechanism"]

    def test_detects_audit_hooks(self):
        source = """
import sys
def hook(event, args):
    if event in ("import", "exec", "compile"):
        raise RuntimeError("nope")
sys.addaudithook(hook)
exec(input())
"""
        result = json.loads(analyze(source))
        assert result["audit_hooks"] is True

    def test_detects_length_limit(self):
        source = """
inp = input()
if len(inp) > 50:
    print("too long")
    exit()
eval(inp)
"""
        result = json.loads(analyze(source))
        assert result["input_length_limit"] == 50

    def test_detects_blacklist_array(self):
        source = """
blacklist = ["eval", "exec", "import", "os"]
inp = input()
for word in blacklist:
    if word in inp:
        exit()
exec(inp)
"""
        result = json.loads(analyze(source))
        assert "eval" in result["blocked_strings"]
        assert "exec" in result["blocked_strings"]
        assert "import" in result["blocked_strings"]

    def test_auto_detects_python(self):
        source = """
inp = input(">>> ")
exec(inp, {"__builtins__": {}})
"""
        result = json.loads(analyze(source, jail_type="auto"))
        assert result["jail_type"] == "python"

    def test_auto_detects_bash(self):
        source = """#!/bin/bash
set -r
read -p "> " cmd
if [[ $cmd == *"cat"* ]]; then
    echo "blocked"
    exit 1
fi
eval "$cmd"
"""
        result = json.loads(analyze(source, jail_type="auto"))
        assert result["jail_type"] == "bash"

    def test_detects_bash_rbash(self):
        source = """#!/bin/bash
set -r
read -p "$ " input
eval "$input"
"""
        result = json.loads(analyze(source, jail_type="bash"))
        assert result["restricted_shell"] is True
        assert "restricted_shell" in result["restriction_mechanism"]

    def test_detects_bash_path_cleared(self):
        source = """
PATH=""
read cmd
eval "$cmd"
"""
        result = json.loads(analyze(source, jail_type="bash"))
        assert result["path_cleared"] is True

    def test_bypass_suggestions_generated(self):
        source = """
inp = input()
if "_" in inp or "." in inp or "import" in inp:
    exit()
exec(inp, {"__builtins__": {}})
"""
        result = json.loads(analyze(source))
        assert len(result["bypass_suggestions"]) > 0
        # Should have suggestions for underscores, dots, builtins, import
        suggestions_text = " ".join(result["bypass_suggestions"])
        assert "underscore" in suggestions_text.lower() or "chr(95)" in suggestions_text

    def test_returns_valid_json(self):
        source = "exec(input())"
        raw = analyze(source)
        parsed = json.loads(raw)
        assert "jail_type" in parsed

    def test_unknown_jail_type(self):
        result = json.loads(analyze("code", jail_type="ruby"))
        assert "error" in result


# ---------------------------------------------------------------------------
# jail_find_subclass_chain tests
# ---------------------------------------------------------------------------


class TestFindSubclassChain:
    def test_finds_os_chain(self):
        result = json.loads(find_chain(target="os"))
        assert result["chains_found"] > 0
        assert any("os" in c["path"] for c in result["chains"])

    def test_finds_builtins_chain(self):
        result = json.loads(find_chain(target="__builtins__"))
        assert result["chains_found"] > 0

    def test_blocked_string_filtering(self):
        result = json.loads(find_chain(target="os", blocked_strings="os"))
        # All chains should have been filtered out since they contain "os"
        for chain in result["chains"]:
            assert "os" not in chain["path"]

    def test_generates_valid_python_expression(self):
        result = json.loads(find_chain(target="os"))
        if result["chains_found"] > 0:
            path = result["chains"][0]["path"]
            # Should be a syntactically valid Python expression
            assert "().__class__.__base__.__subclasses__()" in path

    def test_reports_python_version(self):
        result = json.loads(find_chain())
        assert "python_version" in result
        assert result["python_version"].startswith("3.")

    def test_reports_useful_subclasses(self):
        result = json.loads(find_chain(target="os"))
        assert len(result["all_useful_subclasses"]) > 0

    def test_returns_valid_json(self):
        raw = find_chain(target="os")
        parsed = json.loads(raw)
        assert "target" in parsed
        assert "chains_found" in parsed


# ---------------------------------------------------------------------------
# jail_construct_string tests
# ---------------------------------------------------------------------------


class TestConstructString:
    def test_empty_target(self):
        result = json.loads(construct(""))
        assert "error" in result

    def test_chr_construction(self):
        result = json.loads(construct("__", blocked_chars="_"))
        assert result["construction_count"] > 0
        for c in result["constructions"]:
            assert "_" not in c["expression"]
        # At least one should use chr
        techniques = [c["technique"] for c in result["constructions"]]
        assert any(
            "chr" in t or "hex" in t or "bytes" in t or "nfkc" in t.lower()
            for t in techniques
        )

    def test_hex_escape_when_parens_blocked(self):
        result = json.loads(construct("os", blocked_chars="()"))
        # chr() can't be used since parens blocked, should fall back to hex or other
        for c in result["constructions"]:
            assert "(" not in c["expression"]
            assert ")" not in c["expression"]

    def test_bytes_decode(self):
        result = json.loads(construct("flag"))
        techniques = [c["technique"] for c in result["constructions"]]
        assert "bytes_decode" in techniques

    def test_blocked_char_validation(self):
        result = json.loads(construct("test", blocked_chars="te"))
        # All constructions should avoid blocked chars
        for c in result["constructions"]:
            assert "t" not in c["expression"] or c["uses_blocked"]
            assert "e" not in c["expression"] or c["uses_blocked"]

    def test_bash_hex_escape(self):
        result = json.loads(construct("/flag", jail_type="bash"))
        assert result["construction_count"] > 0
        techniques = [c["technique"] for c in result["constructions"]]
        assert any("hex" in t or "printf" in t or "variable" in t for t in techniques)

    def test_bash_slash_construction(self):
        result = json.loads(construct("/", blocked_chars="/", jail_type="bash"))
        # Should offer variable slicing like ${PATH:0:1}
        for c in result["constructions"]:
            assert "/" not in c["expression"]

    def test_unicode_nfkc(self):
        result = json.loads(construct("_"))
        # Should include NFKC option
        techniques = [c["technique"] for c in result["constructions"]]
        assert "unicode_nfkc" in techniques

    def test_unknown_jail_type(self):
        result = json.loads(construct("test", jail_type="ruby"))
        assert "error" in result

    def test_returns_valid_json(self):
        raw = construct("test")
        parsed = json.loads(raw)
        assert "target" in parsed
        assert "constructions" in parsed

    def test_sorted_by_length(self):
        result = json.loads(construct("__import__"))
        lengths = [c["length"] for c in result["constructions"]]
        assert lengths == sorted(lengths)


# ---------------------------------------------------------------------------
# jail_build_payload tests
# ---------------------------------------------------------------------------


class TestBuildPayload:
    def test_avoids_blocked_strings(self):
        result = json.loads(
            build_payload(
                blocked_strings="import,os,system",
                goal="read_flag",
            )
        )
        for p in result["payloads"]:
            assert "import" not in p["payload"]
            assert "system" not in p["payload"]

    def test_avoids_blocked_chars(self):
        result = json.loads(
            build_payload(
                blocked_chars="_.",
                goal="read_flag",
            )
        )
        for p in result["payloads"]:
            assert "_" not in p["payload"]
            assert "." not in p["payload"]

    def test_builtin_recovery_payload(self):
        result = json.loads(
            build_payload(
                builtins_wiped=True,
                goal="read_flag",
            )
        )
        # Should only have subclass-based payloads
        for p in result["payloads"]:
            assert "subclass" in p["technique"] or "getattr" in p["technique"]

    def test_bash_glob_payload(self):
        result = json.loads(
            build_payload(
                jail_type="bash",
                goal="read_flag",
            )
        )
        assert result["payload_count"] > 0
        techniques = [p["technique"] for p in result["payloads"]]
        assert any(
            "glob" in t or "cat" in t or "read" in t or "redirect" in t
            for t in techniques
        )

    def test_length_limit_filters(self):
        result = json.loads(
            build_payload(
                goal="read_flag",
                max_length=30,
            )
        )
        for p in result["payloads"]:
            assert p["length"] <= 30

    def test_exec_command_goal(self):
        result = json.loads(build_payload(goal="exec_command"))
        assert result["goal"] == "exec_command"
        assert result["payload_count"] > 0

    def test_get_shell_goal(self):
        result = json.loads(build_payload(goal="get_shell"))
        assert result["goal"] == "get_shell"
        assert result["payload_count"] > 0

    def test_recover_builtins_goal(self):
        result = json.loads(build_payload(goal="recover_builtins"))
        assert result["goal"] == "recover_builtins"

    def test_unknown_goal(self):
        result = json.loads(build_payload(goal="unknown_thing"))
        assert "error" in result

    def test_unknown_jail_type(self):
        result = json.loads(build_payload(jail_type="ruby"))
        assert "error" in result

    def test_sorted_by_length(self):
        result = json.loads(build_payload(goal="read_flag"))
        lengths = [p["length"] for p in result["payloads"]]
        assert lengths == sorted(lengths)

    def test_returns_valid_json(self):
        raw = build_payload()
        parsed = json.loads(raw)
        assert "goal" in parsed
        assert "payload_count" in parsed
        assert "payloads" in parsed

    def test_custom_flag_path(self):
        result = json.loads(
            build_payload(
                goal="read_flag",
                flag_path="/home/ctf/flag.txt",
            )
        )
        if result["payload_count"] > 0:
            assert any("/home/ctf/flag.txt" in p["payload"] for p in result["payloads"])

    def test_bash_get_shell(self):
        result = json.loads(
            build_payload(
                jail_type="bash",
                goal="get_shell",
            )
        )
        assert result["payload_count"] > 0
        # Should include $0 trick
        payloads = [p["payload"] for p in result["payloads"]]
        assert any("$0" in p or "/bin/sh" in p or "???" in p for p in payloads)


# ---------------------------------------------------------------------------
# Constants / module-level tests
# ---------------------------------------------------------------------------


class TestConstants:
    def test_fullwidth_map_has_underscore(self):
        assert "_" in ctf_jail._FULLWIDTH_MAP

    def test_fullwidth_map_normalizes(self):
        for ascii_char, fw_char in ctf_jail._FULLWIDTH_MAP.items():
            assert unicodedata.normalize("NFKC", fw_char) == ascii_char

    def test_python_common_blocks_nonempty(self):
        assert len(ctf_jail.PYTHON_COMMON_BLOCKS) > 0

    def test_bash_builtins_nonempty(self):
        assert len(ctf_jail.BASH_BUILTINS) > 0


import unicodedata
