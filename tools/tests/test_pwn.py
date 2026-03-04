"""Tests for ctf_pwn.py — pure-Python logic and mocked tool calls."""

import json
import os
import struct
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import ctf_pwn

# Access the underlying functions from FastMCP tool wrappers
pwn_triage = ctf_pwn.pwn_triage.fn
_pwn_triage_impl = ctf_pwn._pwn_triage_impl
disassemble = ctf_pwn.pwn_disassemble.fn
find_rop_gadgets = ctf_pwn.pwn_rop_gadgets.fn
pattern_offset = ctf_pwn.pwn_pattern_offset.fn
shellcode_generate = ctf_pwn.pwn_shellcode_generate.fn
pwntools_template = ctf_pwn.pwn_pwntools_template.fn
angr_analyze = ctf_pwn.pwn_angr_analyze.fn


# ── DANGEROUS_FUNCS constant ─────────────────────────────────────────────────


class TestDangerousFuncs:
    def test_contains_gets(self):
        assert "gets" in ctf_pwn.DANGEROUS_FUNCS

    def test_contains_scanf(self):
        assert "scanf" in ctf_pwn.DANGEROUS_FUNCS

    def test_contains_strcpy(self):
        assert "strcpy" in ctf_pwn.DANGEROUS_FUNCS

    def test_contains_sprintf(self):
        assert "sprintf" in ctf_pwn.DANGEROUS_FUNCS

    def test_is_a_set(self):
        assert isinstance(ctf_pwn.DANGEROUS_FUNCS, set)


# ── pwn_triage tests ──────────────────────────────────────────────────────


class TestBinaryTriage:
    def test_nonexistent_file(self):
        result = json.loads(pwn_triage("/nonexistent/binary/xyz"))
        assert "error" in result
        assert "not found" in result["error"].lower()

    def test_empty_file(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"")
            path = f.name
        try:
            result = json.loads(pwn_triage(path))
            assert "file_type" in result
            assert result["path"] == os.path.realpath(path)
        finally:
            os.unlink(path)

    def test_text_file(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt", mode="w") as f:
            f.write("Hello world, this is a text file\n")
            path = f.name
        try:
            result = json.loads(pwn_triage(path))
            assert "file_type" in result
            assert (
                "text" in result["file_type"].lower() or "ASCII" in result["file_type"]
            )
        finally:
            os.unlink(path)

    def test_returns_valid_json(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"\x7fELF" + b"\x00" * 100)
            path = f.name
        try:
            raw = pwn_triage(path)
            parsed = json.loads(raw)
            assert "path" in parsed
            assert "file_type" in parsed
        finally:
            os.unlink(path)

    def test_symlink_resolves(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"data")
            real_path = f.name
        link_path = real_path + ".link"
        try:
            os.symlink(real_path, link_path)
            result = json.loads(pwn_triage(link_path))
            assert result["path"] == os.path.realpath(link_path)
        finally:
            os.unlink(real_path)
            if os.path.exists(link_path):
                os.unlink(link_path)


# ── disassemble tests ────────────────────────────────────────────────────────


class TestDisassemble:
    def test_nonexistent_file(self):
        result = json.loads(disassemble("/nonexistent/binary/xyz"))
        assert "error" in result
        assert "not found" in result["error"].lower()

    def test_returns_function_field(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"\x7fELF" + b"\x00" * 100)
            path = f.name
        try:
            result = json.loads(disassemble(path, function="main"))
            assert result["function"] == "main"
        finally:
            os.unlink(path)

    def test_custom_function_name(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"\x7fELF" + b"\x00" * 100)
            path = f.name
        try:
            result = json.loads(disassemble(path, function="vuln"))
            assert result["function"] == "vuln"
        finally:
            os.unlink(path)

    def test_hex_address(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"\x7fELF" + b"\x00" * 100)
            path = f.name
        try:
            result = json.loads(disassemble(path, function="0x401000"))
            assert result["function"] == "0x401000"
        finally:
            os.unlink(path)

    def test_returns_valid_json(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"not a real binary")
            path = f.name
        try:
            raw = disassemble(path)
            parsed = json.loads(raw)
            assert "function" in parsed
            assert "disassembly" in parsed
        finally:
            os.unlink(path)


# ── find_rop_gadgets tests ───────────────────────────────────────────────────


class TestFindRopGadgets:
    def test_nonexistent_file(self):
        result = json.loads(find_rop_gadgets("/nonexistent/binary/xyz"))
        assert "error" in result

    def test_returns_valid_json(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"\x7fELF" + b"\x00" * 100)
            path = f.name
        try:
            raw = find_rop_gadgets(path)
            parsed = json.loads(raw)
            # Either has gadgets or an error (ROPgadget might not parse the minimal ELF)
            assert "gadgets" in parsed or "error" in parsed
        finally:
            os.unlink(path)


# ── pattern_offset tests ─────────────────────────────────────────────────────


class TestPatternOffset:
    def test_create_default_length(self):
        result = json.loads(pattern_offset(action="create"))
        assert result["length"] == 200
        assert len(result["pattern"]) == 200
        assert "pattern_hex" in result

    def test_create_custom_length(self):
        result = json.loads(pattern_offset(action="create", length=64))
        assert result["length"] == 64
        assert len(result["pattern"]) == 64

    def test_create_minimal_length(self):
        result = json.loads(pattern_offset(action="create", length=4))
        assert result["length"] == 4

    def test_find_offset_ascii(self):
        result = json.loads(pattern_offset(action="find", value="aaab"))
        assert "offset" in result
        assert isinstance(result["offset"], int)

    def test_find_offset_hex(self):
        result = json.loads(pattern_offset(action="find", value="0x61616162"))
        assert "offset" in result

    def test_unknown_action(self):
        result = json.loads(pattern_offset(action="invalid"))
        assert "error" in result

    def test_pattern_is_cyclic(self):
        result = json.loads(pattern_offset(action="create", length=100))
        pattern = result["pattern"]
        # No 4-byte substring should repeat in a cyclic pattern
        substrings = set()
        for i in range(len(pattern) - 3):
            sub = pattern[i : i + 4]
            assert sub not in substrings, f"Repeated substring: {sub}"
            substrings.add(sub)

    def test_create_and_find_roundtrip(self):
        # Create a pattern, pick a 4-byte chunk, find its offset
        create_result = json.loads(pattern_offset(action="create", length=200))
        pattern = create_result["pattern"]
        # Pick bytes at offset 40
        chunk = pattern[40:44]
        find_result = json.loads(pattern_offset(action="find", value=chunk))
        assert find_result["offset"] == 40


# ── shellcode_generate tests ─────────────────────────────────────────────────


class TestShellcodeGenerate:
    def test_sh_payload_amd64(self):
        result = json.loads(shellcode_generate(arch="amd64", payload="sh"))
        assert result["arch"] == "amd64"
        assert result["payload"] == "sh"
        assert len(result["shellcode_hex"]) > 0
        assert result["length"] > 0
        assert "assembly" in result

    def test_sh_payload_i386(self):
        result = json.loads(shellcode_generate(arch="i386", payload="sh"))
        if "error" not in result:
            assert result["arch"] == "i386"
            assert result["length"] > 0
        else:
            # i386 assembly may not be available on all platforms
            pytest.skip(f"i386 shellcode not available: {result['error']}")

    def test_cat_flag_payload(self):
        result = json.loads(shellcode_generate(payload="cat_flag"))
        assert result["payload"] == "cat_flag"
        assert result["length"] > 0

    def test_shellcode_hex_is_valid(self):
        result = json.loads(shellcode_generate(arch="amd64", payload="sh"))
        hex_str = result["shellcode_hex"]
        # Should be valid hex
        bytes.fromhex(hex_str)
        assert len(hex_str) == result["length"] * 2

    def test_shellcode_escaped_format(self):
        result = json.loads(shellcode_generate(arch="amd64", payload="sh"))
        escaped = result["shellcode_escaped"]
        assert escaped.startswith("\\x")
        # Each byte is 4 chars: \xHH
        assert len(escaped) == result["length"] * 4

    def test_invalid_payload(self):
        result = json.loads(
            shellcode_generate(arch="amd64", payload="nonexistent_payload_xyz")
        )
        assert "error" in result


# ── pwntools_template tests ──────────────────────────────────────────────────


class TestPwntoolsTemplate:
    def _make_binary(self):
        """Create a minimal file for testing (doesn't need to be a real ELF)."""
        f = tempfile.NamedTemporaryFile(delete=False, suffix=".bin")
        f.write(b"\x7fELF" + b"\x00" * 100)
        f.close()
        return f.name

    def test_ret2win_template(self):
        path = self._make_binary()
        try:
            result = json.loads(pwntools_template(path, technique="ret2win"))
            assert result["technique"] == "ret2win"
            assert "script" in result
            assert "from pwn import" in result["script"]
            assert "binary_info" in result
        finally:
            os.unlink(path)

    def test_ret2libc_template(self):
        path = self._make_binary()
        try:
            result = json.loads(pwntools_template(path, technique="ret2libc"))
            assert result["technique"] == "ret2libc"
            assert "libc" in result["script"].lower()
        finally:
            os.unlink(path)

    def test_format_string_template(self):
        path = self._make_binary()
        try:
            result = json.loads(pwntools_template(path, technique="format_string"))
            assert result["technique"] == "format_string"
            assert "fmtstr_payload" in result["script"]
        finally:
            os.unlink(path)

    def test_shellcode_template(self):
        path = self._make_binary()
        try:
            result = json.loads(pwntools_template(path, technique="shellcode"))
            assert result["technique"] == "shellcode"
            assert "shellcraft" in result["script"]
        finally:
            os.unlink(path)

    def test_with_remote(self):
        path = self._make_binary()
        try:
            result = json.loads(pwntools_template(path, remote="ctf.example.com:1337"))
            assert "ctf.example.com" in result["script"]
            assert "1337" in result["script"]
            assert result["remote"] == "ctf.example.com:1337"
        finally:
            os.unlink(path)

    def test_local_default(self):
        path = self._make_binary()
        try:
            result = json.loads(pwntools_template(path))
            assert result["remote"] == "local"
            assert "process(" in result["script"]
        finally:
            os.unlink(path)

    def test_nonexistent_file(self):
        # pwntools_template calls pwn_triage internally, which handles missing files
        result = json.loads(pwntools_template("/nonexistent/xyz"))
        # Should still produce a template with whatever info it has
        assert "script" in result or "technique" in result

    def test_returns_valid_json(self):
        path = self._make_binary()
        try:
            raw = pwntools_template(path)
            parsed = json.loads(raw)
            assert isinstance(parsed, dict)
        finally:
            os.unlink(path)


# ── angr_analyze tests ───────────────────────────────────────────────────────


class TestAngrAnalyze:
    def test_nonexistent_file(self):
        result = json.loads(angr_analyze("/nonexistent/binary/xyz"))
        assert "error" in result
        assert "not found" in result["error"].lower()

    def test_unknown_mode(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"\x7fELF" + b"\x00" * 100)
            path = f.name
        try:
            result = json.loads(angr_analyze(path, mode="bad_mode"))
            # Should either error on bad mode or fail to load the binary
            assert "error" in result or result.get("mode") == "bad_mode"
        finally:
            os.unlink(path)

    def test_returns_binary_and_mode(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"\x7fELF" + b"\x00" * 100)
            path = f.name
        try:
            result = json.loads(angr_analyze(path, mode="auto"))
            # Will likely error since this isn't a real ELF, but should have structure
            assert "binary" in result or "error" in result
        finally:
            os.unlink(path)

    def test_angr_import_available(self):
        """Verify angr is importable in this environment."""
        try:
            import angr

            assert hasattr(angr, "Project")
        except ImportError:
            pytest.skip("angr not available")


# ── Integration: tool output is always valid JSON ────────────────────────────


class TestJsonOutput:
    """Every tool must return valid JSON regardless of input."""

    def test_pwn_triage_json(self):
        raw = pwn_triage("/dev/null")
        json.loads(raw)

    def test_disassemble_json(self):
        raw = disassemble("/dev/null")
        json.loads(raw)

    def test_pattern_offset_create_json(self):
        raw = pattern_offset(action="create", length=10)
        json.loads(raw)

    def test_pattern_offset_find_json(self):
        raw = pattern_offset(action="find", value="AAAA")
        json.loads(raw)

    def test_shellcode_generate_json(self):
        raw = shellcode_generate()
        json.loads(raw)
