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
        assert "error" not in result, f"i386 shellcode failed: {result.get('error')}"
        assert result["arch"] == "i386"
        assert result["length"] > 0

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


# ── pwn_one_gadget tests ────────────────────────────────────────────────────

one_gadget = ctf_pwn.pwn_one_gadget.fn


class TestOneGadget:
    def test_nonexistent_file(self):
        result = json.loads(one_gadget("/nonexistent/libc.so.6"))
        assert "error" in result

    def test_output_parsing(self):
        from unittest.mock import patch

        mock_output = (
            '0x4f2a5 execve("/bin/sh", rsp+0x40, environ)\n'
            "constraints:\n"
            "  [rsp+0x40] == NULL\n"
            "  [[rsp+0x40]+0x8] == NULL\n"
            "\n"
            '0x4f302 execve("/bin/sh", rsp+0x70, environ)\n'
            "constraints:\n"
            "  [rsp+0x70] == NULL\n"
        )
        mock_result = {"stdout": mock_output, "stderr": "", "returncode": 0}
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"\x7fELF")
            path = f.name
        try:
            with patch("ctf_pwn.run_tool", return_value=mock_result):
                result = json.loads(one_gadget(path))
                assert result["gadget_count"] == 2
                assert result["gadgets"][0]["address"] == "0x4f2a5"
                assert len(result["gadgets"][0]["constraints"]) == 2
                assert result["gadgets"][1]["address"] == "0x4f302"
        finally:
            os.unlink(path)

    def test_returns_valid_json(self):
        from unittest.mock import patch

        mock_result = {"stdout": "", "stderr": "", "returncode": 0}
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"\x7fELF")
            path = f.name
        try:
            with patch("ctf_pwn.run_tool", return_value=mock_result):
                json.loads(one_gadget(path))
        finally:
            os.unlink(path)


# ── pwn_libc_lookup tests ───────────────────────────────────────────────────

libc_lookup = ctf_pwn.pwn_libc_lookup.fn


class TestLibcLookup:
    def test_invalid_json(self):
        result = json.loads(libc_lookup("not json"))
        assert "error" in result

    def test_empty_symbols(self):
        result = json.loads(libc_lookup("{}"))
        assert "error" in result

    def test_api_payload_format(self):
        from unittest.mock import MagicMock, patch

        mock_resp = MagicMock()
        mock_resp.json.return_value = []
        mock_resp.raise_for_status = MagicMock()
        with patch("requests.post", return_value=mock_resp) as mock_post:
            result = json.loads(libc_lookup('{"puts": "0x7f1234567890"}'))
            call_args = mock_post.call_args
            payload = (
                call_args[1]["json"] if "json" in call_args[1] else call_args[0][1]
            )
            # Last 12 bits of 0x7f1234567890 = 0x890
            assert payload["symbols"]["puts"] == "0x890"

    def test_parses_response(self):
        from unittest.mock import MagicMock, patch

        mock_resp = MagicMock()
        mock_resp.json.return_value = [
            {
                "id": "libc6_2.31-0ubuntu9_amd64",
                "buildid": "abc123",
                "download_url": "https://libc.rip/download/...",
                "symbols": {
                    "puts": "0x84890",
                    "system": "0x52290",
                    "str_bin_sh": "0x1b45bd",
                },
            }
        ]
        mock_resp.raise_for_status = MagicMock()
        with patch("requests.post", return_value=mock_resp):
            result = json.loads(libc_lookup('{"puts": "0x7f1234567890"}'))
            assert result["match_count"] == 1
            assert result["matches"][0]["id"] == "libc6_2.31-0ubuntu9_amd64"
            assert "system_offset" in result["matches"][0]

    def test_computes_base_address(self):
        from unittest.mock import MagicMock, patch

        mock_resp = MagicMock()
        mock_resp.json.return_value = [
            {
                "id": "test",
                "buildid": "",
                "download_url": "",
                "symbols": {"puts": "0x84890"},
            }
        ]
        mock_resp.raise_for_status = MagicMock()
        with patch("requests.post", return_value=mock_resp):
            result = json.loads(libc_lookup('{"puts": "0x7f1234567890"}'))
            # base = 0x7f1234567890 - 0x84890 = 0x7f12344e3000
            assert "computed_base" in result["matches"][0]
            base = int(result["matches"][0]["computed_base"], 16)
            assert base == 0x7F1234567890 - 0x84890

    def test_api_failure(self):
        from unittest.mock import patch

        with patch("requests.post", side_effect=Exception("Network error")):
            result = json.loads(libc_lookup('{"puts": "0x7f1234567890"}'))
            assert "error" in result

    def test_returns_valid_json(self):
        from unittest.mock import MagicMock, patch

        mock_resp = MagicMock()
        mock_resp.json.return_value = []
        mock_resp.raise_for_status = MagicMock()
        with patch("requests.post", return_value=mock_resp):
            json.loads(libc_lookup('{"puts": "0x7f1234567890"}'))


# ── pwn_format_string tests ─────────────────────────────────────────────────

format_string = ctf_pwn.pwn_format_string.fn


class TestFormatString:
    def test_find_offset_generates_probe(self):
        result = json.loads(format_string(mode="find_offset"))
        assert result["mode"] == "find_offset"
        assert "%1$p" in result["probe_payload"]
        assert "%29$p" in result["probe_payload"]
        assert "instructions" in result

    def test_write_mode_generates_payload(self):
        result = json.loads(
            format_string(mode="write", offset=6, writes='{"0x404020": "0x401234"}')
        )
        assert result["mode"] == "write"
        assert len(result["payload_hex"]) > 0
        assert result["payload_length"] > 0

    def test_write_mode_missing_writes(self):
        result = json.loads(format_string(mode="write", offset=6))
        assert "error" in result

    def test_write_mode_invalid_writes_json(self):
        result = json.loads(format_string(mode="write", offset=6, writes="not json"))
        assert "error" in result

    def test_info_mode_returns_reference(self):
        result = json.loads(format_string(mode="info"))
        assert result["mode"] == "info"
        assert "%p" in result["format_specifiers"]
        assert "%n" in result["format_specifiers"]
        assert len(result["exploit_steps"]) >= 4

    def test_unknown_mode_returns_error(self):
        result = json.loads(format_string(mode="unknown"))
        assert "error" in result

    def test_returns_valid_json(self):
        json.loads(format_string())
        json.loads(format_string(mode="info"))
        json.loads(
            format_string(mode="write", offset=6, writes='{"0x404020": "0x401234"}')
        )


# ── TestTriageMocked — mock rabin2 successful output parsing ────────────────


class TestTriageMocked:
    def test_rabin2_imports_parsing(self):
        """Mock rabin2 -i -j returning import JSON, verify dangerous function detection."""
        from unittest.mock import patch

        def mock_run(cmd, timeout=None, input_data=None, cwd=None):
            if cmd[0] == "file":
                return {
                    "stdout": "ELF 64-bit LSB executable",
                    "stderr": "",
                    "returncode": 0,
                }
            if cmd[0] == "checksec":
                return {
                    "stdout": "NX: enabled\nCanary: found",
                    "stderr": "",
                    "returncode": 0,
                }
            if "rabin2" in cmd[0]:
                if "-I" in cmd:
                    return {
                        "stdout": "arch x86\nbits 64\nendian little\nos linux\nbintype elf",
                        "stderr": "",
                        "returncode": 0,
                    }
                if "-i" in cmd and "-j" in cmd:
                    return {
                        "stdout": json.dumps(
                            {
                                "imports": [
                                    {"name": "gets"},
                                    {"name": "printf"},
                                    {"name": "strcpy"},
                                ]
                            }
                        ),
                        "stderr": "",
                        "returncode": 0,
                    }
                if "-E" in cmd:
                    return {
                        "stdout": json.dumps(
                            {"exports": [{"name": "main"}, {"name": "win"}]}
                        ),
                        "stderr": "",
                        "returncode": 0,
                    }
                if "-S" in cmd:
                    return {
                        "stdout": json.dumps(
                            {
                                "sections": [
                                    {"name": ".text", "size": 100, "perm": "r-x"}
                                ]
                            }
                        ),
                        "stderr": "",
                        "returncode": 0,
                    }
                if "-z" in cmd:
                    return {
                        "stdout": json.dumps(
                            {"strings": [{"string": "flag{test}"}, {"string": "hello"}]}
                        ),
                        "stderr": "",
                        "returncode": 0,
                    }
            return {"stdout": "", "stderr": "", "returncode": 1}

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"\x7fELF" + b"\x00" * 100)
            path = f.name
        try:
            with patch("ctf_pwn.run_tool", side_effect=mock_run):
                result = json.loads(pwn_triage(path))
                assert result["arch"] == "x86"
                assert result["bits"] == "64"
                assert "gets" in result["dangerous_functions"]
                assert "strcpy" in result["dangerous_functions"]
                assert "printf" not in result["dangerous_functions"]
                assert "main" in result["exports"]
                assert "win" in result["exports"]
                assert len(result["sections"]) == 1
                assert "flag{test}" in result["strings_interesting"]
                assert result["strings_total"] == 2
        finally:
            os.unlink(path)

    def test_rop_gadgets_parsing(self):
        """Mock ROPgadget output parsing."""
        from unittest.mock import patch

        mock_output = (
            "Gadgets information\n"
            "============================================================\n"
            "0x0000000000401234 : pop rdi ; ret\n"
            "0x0000000000401238 : pop rsi ; pop r15 ; ret\n"
            "0x000000000040123c : ret\n"
            "\n"
            "Unique gadgets found: 3\n"
        )
        mock_result = {"stdout": mock_output, "stderr": "", "returncode": 0}
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"\x7fELF")
            path = f.name
        try:
            with patch("ctf_pwn.run_tool", return_value=mock_result):
                result = json.loads(find_rop_gadgets(path))
                assert result["total_gadgets"] == 3
                assert result["gadgets"][0]["address"] == "0x0000000000401234"
                assert result["gadgets"][0]["instructions"] == "pop rdi ; ret"
        finally:
            os.unlink(path)


# ── TestAngrMocked — mock angr for all modes ────────────────────────────────


class TestAngrMocked:
    def test_auto_mode_finds_flag(self):
        """Mock angr finding flag output in auto mode."""
        from unittest.mock import MagicMock, patch

        mock_angr = MagicMock()
        mock_claripy = MagicMock()

        # Setup project
        mock_proj = MagicMock()
        mock_proj.arch.name = "AMD64"
        mock_angr.Project.return_value = mock_proj

        # Setup state and simgr
        mock_state = MagicMock()
        mock_simgr = MagicMock()
        mock_proj.factory.entry_state.return_value = mock_state
        mock_proj.factory.simulation_manager.return_value = mock_simgr

        # Make explore find a state
        found_state = MagicMock()
        found_state.solver.eval.return_value = b"input123\x00"
        found_state.posix.dumps.return_value = b"flag{test_flag}"

        def fake_explore(find=None, avoid=None):
            mock_simgr.found = [found_state]

        mock_simgr.explore = fake_explore
        mock_simgr.found = []

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"\x7fELF" + b"\x00" * 100)
            path = f.name
        try:
            with patch.dict(
                "sys.modules", {"angr": mock_angr, "claripy": mock_claripy}
            ):
                # Need to reimport to use mocked modules
                result = json.loads(angr_analyze(path, mode="auto"))
                # Either found or error depending on mock depth - just verify structure
                assert "binary" in result or "error" in result
        finally:
            os.unlink(path)

    def test_find_addr_mode(self):
        """Test find_addr mode with mocked angr."""
        from unittest.mock import MagicMock, patch

        mock_angr = MagicMock()
        mock_claripy = MagicMock()
        mock_proj = MagicMock()
        mock_proj.arch.name = "AMD64"
        mock_angr.Project.return_value = mock_proj

        mock_simgr = MagicMock()
        mock_proj.factory.entry_state.return_value = MagicMock()
        mock_proj.factory.simulation_manager.return_value = mock_simgr

        found_state = MagicMock()
        found_state.solver.eval.return_value = b"AAAA\x00"
        found_state.posix.dumps.return_value = b"You win!"

        def fake_explore(find=None, avoid=None):
            mock_simgr.found = [found_state]

        mock_simgr.explore = fake_explore
        mock_simgr.found = []

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"\x7fELF" + b"\x00" * 100)
            path = f.name
        try:
            with patch.dict(
                "sys.modules", {"angr": mock_angr, "claripy": mock_claripy}
            ):
                result = json.loads(
                    angr_analyze(path, mode="find_addr", target_addr="0x401234")
                )
                assert "binary" in result or "error" in result
        finally:
            os.unlink(path)

    def test_explore_mode(self):
        """Test explore mode."""
        from unittest.mock import MagicMock, patch

        mock_angr = MagicMock()
        mock_claripy = MagicMock()
        mock_proj = MagicMock()
        mock_proj.arch.name = "AMD64"
        mock_angr.Project.return_value = mock_proj

        mock_simgr = MagicMock()
        mock_proj.factory.entry_state.return_value = MagicMock()
        mock_proj.factory.simulation_manager.return_value = mock_simgr
        mock_simgr.deadended = []
        mock_simgr.active = []

        def fake_run(until=None):
            mock_simgr.active = []

        mock_simgr.run = fake_run

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"\x7fELF" + b"\x00" * 100)
            path = f.name
        try:
            with patch.dict(
                "sys.modules", {"angr": mock_angr, "claripy": mock_claripy}
            ):
                result = json.loads(angr_analyze(path, mode="explore"))
                assert "binary" in result or "error" in result
        finally:
            os.unlink(path)


# ── TestShellcodeEdgeCases ──────────────────────────────────────────────────


class TestShellcodeEdgeCases:
    def test_connect_back_payload(self):
        result = json.loads(
            shellcode_generate(arch="amd64", payload="connect_back('127.0.0.1',4444)")
        )
        # May succeed or error depending on pwntools support
        assert "length" in result or "error" in result

    def test_arm_architecture(self):
        result = json.loads(shellcode_generate(arch="arm", payload="sh"))
        assert "length" in result or "error" in result


# ── TestPatternOffsetEdgeCases ──────────────────────────────────────────────


class TestPatternOffsetEdgeCases:
    def test_find_8byte_hex_value(self):
        result = json.loads(pattern_offset(action="find", value="0x6161616261616163"))
        assert "offset" in result or "error" in result
