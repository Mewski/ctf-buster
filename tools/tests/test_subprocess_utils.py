"""Tests for lib/subprocess_utils.py — run_tool, parse_checksec, safe_read_file."""

import os
import sys
import tempfile

import pytest

# Allow imports from the tools directory
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from lib.subprocess_utils import parse_checksec, run_tool, safe_read_file

# ── run_tool tests ───────────────────────────────────────────────────────────


class TestRunTool:
    def test_echo_hello(self):
        result = run_tool(["echo", "hello"])
        assert result["returncode"] == 0
        assert result["stdout"].strip() == "hello"
        assert result["stderr"] == ""

    def test_returns_stdout(self):
        result = run_tool(["printf", "abc"])
        assert result["stdout"] == "abc"

    def test_returns_stderr(self):
        result = run_tool(["sh", "-c", "echo err >&2"])
        assert "err" in result["stderr"]

    def test_returns_nonzero_returncode(self):
        result = run_tool(["false"])
        assert result["returncode"] != 0

    def test_timeout_returns_error(self):
        result = run_tool(["sleep", "10"], timeout=1)
        assert result["returncode"] == -1
        assert "error" in result or "Timed out" in result.get("error", "")

    def test_tool_not_found(self):
        result = run_tool(["nonexistent_tool_xyz_123"])
        assert result["returncode"] == -1
        assert "error" in result
        assert (
            "not found" in result["error"].lower()
            or "Tool not found" in result["error"]
        )

    def test_input_data(self):
        result = run_tool(["cat"], input_data=b"hello from stdin")
        assert result["stdout"] == "hello from stdin"

    def test_cwd_parameter(self):
        result = run_tool(["pwd"], cwd="/tmp")
        # On NixOS /tmp may resolve differently, just check it works
        assert result["returncode"] == 0
        assert len(result["stdout"].strip()) > 0

    def test_multiline_output(self):
        result = run_tool(["sh", "-c", "echo line1; echo line2; echo line3"])
        lines = result["stdout"].strip().splitlines()
        assert len(lines) == 3
        assert lines[0] == "line1"
        assert lines[2] == "line3"


# ── parse_checksec tests ─────────────────────────────────────────────────────


class TestParseChecksec:
    def test_nx_enabled(self):
        output = "NX: NX enabled"
        result = parse_checksec(output)
        assert result["nx"] is True

    def test_nx_disabled(self):
        output = "NX: NX disabled"
        result = parse_checksec(output)
        assert result["nx"] is False

    def test_canary_found(self):
        output = "Canary: Canary found"
        result = parse_checksec(output)
        assert result["canary"] is True

    def test_canary_not_found(self):
        output = "Canary: No canary"
        result = parse_checksec(output)
        assert result["canary"] is False

    def test_pie_enabled(self):
        output = "PIE: PIE enabled"
        result = parse_checksec(output)
        assert result["pie"] is True

    def test_pie_disabled(self):
        output = "PIE: No PIE"
        result = parse_checksec(output)
        assert result["pie"] is False

    def test_relro_full(self):
        output = "RELRO: Full RELRO"
        result = parse_checksec(output)
        assert result["relro"] == "full relro"

    def test_relro_partial(self):
        output = "RELRO: Partial RELRO"
        result = parse_checksec(output)
        assert result["relro"] == "partial relro"

    def test_full_checksec_output(self):
        output = """RELRO: Full RELRO
Stack: Canary found
NX: NX enabled
PIE: PIE enabled"""
        result = parse_checksec(output)
        assert result["relro"] == "full relro"
        assert result["canary"] is True
        assert result["nx"] is True
        assert result["pie"] is True

    def test_empty_output(self):
        result = parse_checksec("")
        assert result == {}

    def test_no_colon_lines_ignored(self):
        output = "Some header line\n---\nNX: NX enabled"
        result = parse_checksec(output)
        assert result.get("nx") is True

    def test_stack_key_sets_canary(self):
        output = "Stack: Canary found"
        result = parse_checksec(output)
        assert result["canary"] is True


# ── safe_read_file tests ─────────────────────────────────────────────────────


class TestSafeReadFile:
    def test_read_small_file(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
            f.write(b"hello world")
            path = f.name
        try:
            data = safe_read_file(path)
            assert data == b"hello world"
        finally:
            os.unlink(path)

    def test_read_binary_file(self):
        content = bytes(range(256))
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(content)
            path = f.name
        try:
            data = safe_read_file(path)
            assert data == content
        finally:
            os.unlink(path)

    def test_read_empty_file(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
            path = f.name
        try:
            data = safe_read_file(path)
            assert data == b""
        finally:
            os.unlink(path)

    def test_oversized_file_raises(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"x" * 1000)
            path = f.name
        try:
            with pytest.raises(ValueError, match="File too large"):
                safe_read_file(path, max_size=500)
        finally:
            os.unlink(path)

    def test_custom_max_size(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
            f.write(b"A" * 100)
            path = f.name
        try:
            # Should succeed with sufficient max_size
            data = safe_read_file(path, max_size=200)
            assert len(data) == 100
            # Should fail with too-small max_size
            with pytest.raises(ValueError):
                safe_read_file(path, max_size=50)
        finally:
            os.unlink(path)

    def test_nonexistent_file_raises(self):
        with pytest.raises((FileNotFoundError, OSError)):
            safe_read_file("/tmp/nonexistent_file_xyz_456.bin")

    def test_returns_bytes(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
            f.write(b"test")
            path = f.name
        try:
            data = safe_read_file(path)
            assert isinstance(data, bytes)
        finally:
            os.unlink(path)
