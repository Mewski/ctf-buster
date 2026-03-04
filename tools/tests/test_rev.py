"""Tests for ctf_rev.py — radare2 output parsing, JSON handling, and tool output."""

import json
import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import ctf_rev

# Access underlying functions from FastMCP tool wrappers
rev_functions = ctf_rev.rev_functions.fn
rev_xrefs = ctf_rev.rev_xrefs.fn
rev_decompile = ctf_rev.rev_decompile.fn
rev_strings_xrefs = ctf_rev.rev_strings_xrefs.fn
rev_cfg = ctf_rev.rev_cfg.fn
rev_diff = ctf_rev.rev_diff.fn


# ── _parse_r2_json tests ────────────────────────────────────────────────────


class TestParseR2Json:
    def test_valid_array(self):
        result = ctf_rev._parse_r2_json('[{"name": "main", "offset": 4096}]')
        assert result == [{"name": "main", "offset": 4096}]

    def test_valid_object(self):
        result = ctf_rev._parse_r2_json('{"key": "value"}')
        assert result == {"key": "value"}

    def test_with_warning_prefix(self):
        raw = 'WARNING: some r2 warning\n[{"name": "main"}]'
        result = ctf_rev._parse_r2_json(raw)
        assert result == [{"name": "main"}]

    def test_with_multiple_warning_lines(self):
        raw = "WARN: blah\nSome info\n\n[1, 2, 3]"
        result = ctf_rev._parse_r2_json(raw)
        assert result == [1, 2, 3]

    def test_empty_string(self):
        assert ctf_rev._parse_r2_json("") is None

    def test_whitespace_only(self):
        assert ctf_rev._parse_r2_json("   \n  ") is None

    def test_no_json(self):
        assert ctf_rev._parse_r2_json("just some text output") is None

    def test_invalid_json(self):
        assert ctf_rev._parse_r2_json("[{broken json") is None

    def test_object_before_array(self):
        result = ctf_rev._parse_r2_json('warn\n{"a": 1}')
        assert result == {"a": 1}

    def test_nested_json(self):
        raw = '[{"funcs": [{"name": "a"}, {"name": "b"}]}]'
        result = ctf_rev._parse_r2_json(raw)
        assert len(result) == 1
        assert len(result[0]["funcs"]) == 2


# ── _r2_cmd tests ───────────────────────────────────────────────────────────


class TestR2Cmd:
    def test_returns_dict_with_stdout_stderr_returncode(self):
        # Even if r2 is not installed, run_tool returns a structured dict
        result = ctf_rev._r2_cmd("/dev/null", ["?V"])
        assert "stdout" in result
        assert "stderr" in result
        assert "returncode" in result


# ── rev_functions tool tests ─────────────────────────────────────────────────


class TestR2Functions:
    def test_nonexistent_file(self):
        result = json.loads(rev_functions("/nonexistent/binary/xyz"))
        assert "error" in result
        assert "not found" in result["error"].lower()

    def test_returns_valid_json(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"\x7fELF" + b"\x00" * 100)
            path = f.name
        try:
            raw = rev_functions(path)
            parsed = json.loads(raw)
            assert "path" in parsed or "error" in parsed
        finally:
            os.unlink(path)

    def test_symlink_resolves(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"data")
            real_path = f.name
        link_path = real_path + ".link"
        try:
            os.symlink(real_path, link_path)
            result = json.loads(rev_functions(link_path))
            if "path" in result:
                assert result["path"] == os.path.realpath(link_path)
        finally:
            os.unlink(real_path)
            if os.path.exists(link_path):
                os.unlink(link_path)


# ── rev_xrefs tool tests ────────────────────────────────────────────────────


class TestR2Xrefs:
    def test_nonexistent_file(self):
        result = json.loads(rev_xrefs("/nonexistent/binary/xyz", target="main"))
        assert "error" in result

    def test_returns_valid_json(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"\x7fELF" + b"\x00" * 100)
            path = f.name
        try:
            raw = rev_xrefs(path, target="main")
            parsed = json.loads(raw)
            assert "path" in parsed
            assert "target" in parsed
        finally:
            os.unlink(path)

    def test_direction_both(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"\x7fELF" + b"\x00" * 100)
            path = f.name
        try:
            result = json.loads(rev_xrefs(path, target="main", direction="both"))
            assert "xrefs_to" in result
            assert "xrefs_from" in result
        finally:
            os.unlink(path)

    def test_direction_to(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"\x7fELF" + b"\x00" * 100)
            path = f.name
        try:
            result = json.loads(rev_xrefs(path, target="main", direction="to"))
            assert "xrefs_to" in result
        finally:
            os.unlink(path)

    def test_hex_address_target(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"\x7fELF" + b"\x00" * 100)
            path = f.name
        try:
            result = json.loads(rev_xrefs(path, target="0x401000"))
            assert result["target"] == "0x401000"
        finally:
            os.unlink(path)


# ── rev_decompile tool tests ────────────────────────────────────────────────


class TestR2Decompile:
    def test_nonexistent_file(self):
        result = json.loads(rev_decompile("/nonexistent/binary/xyz"))
        assert "error" in result

    def test_returns_valid_json(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"\x7fELF" + b"\x00" * 100)
            path = f.name
        try:
            raw = rev_decompile(path)
            parsed = json.loads(raw)
            assert isinstance(parsed, dict)
        finally:
            os.unlink(path)

    def test_custom_function(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"\x7fELF" + b"\x00" * 100)
            path = f.name
        try:
            result = json.loads(rev_decompile(path, function="vuln"))
            # Will likely fail to decompile a fake ELF, but should have proper structure
            assert "function" in result or "error" in result
        finally:
            os.unlink(path)

    def test_hex_address_function(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"\x7fELF" + b"\x00" * 100)
            path = f.name
        try:
            result = json.loads(rev_decompile(path, function="0x401000"))
            assert isinstance(result, dict)
        finally:
            os.unlink(path)

    def test_decompiler_param(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"\x7fELF" + b"\x00" * 100)
            path = f.name
        try:
            for dec in ["auto", "r2ghidra", "r2dec"]:
                raw = rev_decompile(path, decompiler=dec)
                parsed = json.loads(raw)
                assert isinstance(parsed, dict)
        finally:
            os.unlink(path)


# ── rev_strings_xrefs tool tests ────────────────────────────────────────────


class TestR2StringsXrefs:
    def test_nonexistent_file(self):
        result = json.loads(rev_strings_xrefs("/nonexistent/binary/xyz"))
        assert "error" in result

    def test_returns_valid_json(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"\x7fELF" + b"\x00" * 100)
            path = f.name
        try:
            raw = rev_strings_xrefs(path)
            parsed = json.loads(raw)
            assert isinstance(parsed, dict)
        finally:
            os.unlink(path)

    def test_filter_param(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"\x7fELF" + b"\x00" * 100)
            path = f.name
        try:
            result = json.loads(rev_strings_xrefs(path, filter="flag|password"))
            assert "filter" in result
            assert result["filter"] == "flag|password"
        finally:
            os.unlink(path)


# ── rev_cfg tool tests ──────────────────────────────────────────────────────


class TestR2Cfg:
    def test_nonexistent_file(self):
        result = json.loads(rev_cfg("/nonexistent/binary/xyz"))
        assert "error" in result

    def test_returns_valid_json(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"\x7fELF" + b"\x00" * 100)
            path = f.name
        try:
            raw = rev_cfg(path)
            parsed = json.loads(raw)
            assert isinstance(parsed, dict)
        finally:
            os.unlink(path)

    def test_custom_function(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"\x7fELF" + b"\x00" * 100)
            path = f.name
        try:
            result = json.loads(rev_cfg(path, function="vuln"))
            assert isinstance(result, dict)
        finally:
            os.unlink(path)


# ── rev_diff tool tests ─────────────────────────────────────────────────────


class TestR2Diff:
    def test_nonexistent_file1(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"data")
            path2 = f.name
        try:
            result = json.loads(rev_diff("/nonexistent/xyz", path2))
            assert "error" in result
        finally:
            os.unlink(path2)

    def test_nonexistent_file2(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"data")
            path1 = f.name
        try:
            result = json.loads(rev_diff(path1, "/nonexistent/xyz"))
            assert "error" in result
        finally:
            os.unlink(path1)

    def test_identical_files(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"\x7fELF" + b"\x00" * 100)
            path = f.name
        try:
            result = json.loads(rev_diff(path, path))
            assert "file1" in result
            assert "file2" in result
            assert "differences" in result
        finally:
            os.unlink(path)

    def test_different_files(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f1:
            f1.write(b"\x7fELF" + b"\x00" * 100)
            path1 = f1.name
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f2:
            f2.write(b"\x7fELF" + b"\x01" * 100)
            path2 = f2.name
        try:
            result = json.loads(rev_diff(path1, path2))
            assert "file1" in result
            assert "file2" in result
            assert "diff_count" in result
        finally:
            os.unlink(path1)
            os.unlink(path2)

    def test_returns_valid_json(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"data1")
            path1 = f.name
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"data2")
            path2 = f.name
        try:
            raw = rev_diff(path1, path2)
            parsed = json.loads(raw)
            assert isinstance(parsed, dict)
        finally:
            os.unlink(path1)
            os.unlink(path2)


# ── Integration: all tools return valid JSON ────────────────────────────────


class TestJsonOutput:
    """Every tool must return valid JSON regardless of input."""

    def test_r2_functions_always_json(self):
        raw = rev_functions("/dev/null")
        json.loads(raw)

    def test_r2_xrefs_always_json(self):
        raw = rev_xrefs("/dev/null", target="main")
        json.loads(raw)

    def test_r2_decompile_always_json(self):
        raw = rev_decompile("/dev/null")
        json.loads(raw)

    def test_r2_strings_xrefs_always_json(self):
        raw = rev_strings_xrefs("/dev/null")
        json.loads(raw)

    def test_r2_cfg_always_json(self):
        raw = rev_cfg("/dev/null")
        json.loads(raw)

    def test_r2_diff_always_json(self):
        raw = rev_diff("/dev/null", "/dev/null")
        json.loads(raw)
