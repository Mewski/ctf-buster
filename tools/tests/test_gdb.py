"""Tests for ctf_gdb.py — GDB script building, output parsing, and tool JSON output."""

import json
import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import ctf_gdb

# Access underlying functions from FastMCP tool wrappers
gdb_run = ctf_gdb.gdb_run.fn
gdb_break_inspect = ctf_gdb.gdb_break_inspect.fn
gdb_trace_input = ctf_gdb.gdb_trace_input.fn
gdb_memory_dump = ctf_gdb.gdb_memory_dump.fn
gdb_checksec_runtime = ctf_gdb.gdb_checksec_runtime.fn


# ── _build_gdb_script tests ──────────────────────────────────────────────────


class TestBuildGdbScript:
    def test_includes_standard_preamble(self):
        script = ctf_gdb._build_gdb_script([], [])
        assert "set pagination off" in script
        assert "set disable-randomization on" in script
        assert "set confirm off" in script

    def test_includes_quit(self):
        script = ctf_gdb._build_gdb_script([], [])
        lines = script.strip().splitlines()
        assert lines[-1] == "quit"

    def test_preamble_commands_before_main(self):
        script = ctf_gdb._build_gdb_script(["break main"], ["run", "info registers"])
        lines = script.splitlines()
        break_idx = next(i for i, l in enumerate(lines) if l == "break main")
        run_idx = next(i for i, l in enumerate(lines) if l == "run")
        assert break_idx < run_idx

    def test_main_commands_included(self):
        script = ctf_gdb._build_gdb_script([], ["break main", "run", "bt"])
        assert "break main" in script
        assert "run" in script
        assert "bt" in script

    def test_empty_commands(self):
        script = ctf_gdb._build_gdb_script([], [])
        assert "set pagination off" in script
        assert "quit" in script


# ── _parse_registers tests ───────────────────────────────────────────────────


class TestParseRegisters:
    def test_parses_standard_output(self):
        output = (
            "rax            0x401000           4198400\n"
            "rbx            0x0                0\n"
            "rcx            0x7fff5fbff8c0     140734799804608\n"
        )
        regs = ctf_gdb._parse_registers(output)
        assert "rax" in regs
        assert regs["rax"]["hex"] == "0x401000"
        assert "rbx" in regs
        assert regs["rbx"]["hex"] == "0x0"
        assert "rcx" in regs

    def test_empty_output(self):
        assert ctf_gdb._parse_registers("") == {}

    def test_ignores_non_register_lines(self):
        output = (
            "Breakpoint 1 at 0x401000\n"
            "rax            0x401000           4198400\n"
            "Some random line\n"
        )
        regs = ctf_gdb._parse_registers(output)
        assert "rax" in regs
        assert len(regs) == 1

    def test_multiple_registers(self):
        output = "\n".join(
            [
                "rax            0x0                0",
                "rbx            0x1                1",
                "rcx            0x2                2",
                "rdx            0x3                3",
                "rsp            0x7fffffffe000     140737488347136",
                "rbp            0x7fffffffe010     140737488347152",
                "rip            0x401000           4198400",
            ]
        )
        regs = ctf_gdb._parse_registers(output)
        assert len(regs) == 7
        assert regs["rip"]["hex"] == "0x401000"


# ── _parse_backtrace tests ───────────────────────────────────────────────────


class TestParseBacktrace:
    def test_parses_backtrace(self):
        output = (
            "#0  0x0000000000401000 in main ()\n"
            "#1  0x00007ffff7a2d840 in __libc_start_main ()\n"
        )
        frames = ctf_gdb._parse_backtrace(output)
        assert len(frames) == 2
        assert frames[0]["frame"] == 0
        assert frames[0]["function"] == "main"
        assert frames[1]["frame"] == 1

    def test_empty_output(self):
        assert ctf_gdb._parse_backtrace("") == []

    def test_ignores_non_bt_lines(self):
        output = "Breakpoint 1\n#0  0x0000000000401000 in main ()\nrax: 0x0\n"
        frames = ctf_gdb._parse_backtrace(output)
        assert len(frames) == 1


# ── _parse_memory tests ─────────────────────────────────────────────────────


class TestParseMemory:
    def test_parses_hex_dump(self):
        output = (
            "0x7fffffffe000:\t0x41\t0x42\t0x43\n0x7fffffffe003:\t0x44\t0x45\t0x46\n"
        )
        lines = ctf_gdb._parse_memory(output)
        assert len(lines) == 2
        assert lines[0].startswith("0x7fffffffe000")

    def test_empty_output(self):
        assert ctf_gdb._parse_memory("") == []

    def test_ignores_blank_lines(self):
        output = "\n\n0x401000: data\n\n"
        lines = ctf_gdb._parse_memory(output)
        assert len(lines) == 1


# ── _write_temp tests ───────────────────────────────────────────────────────


class TestWriteTemp:
    def test_creates_file(self):
        path = ctf_gdb._write_temp("hello", suffix=".txt")
        try:
            assert os.path.isfile(path)
            with open(path) as f:
                assert f.read() == "hello"
        finally:
            os.unlink(path)

    def test_custom_suffix(self):
        path = ctf_gdb._write_temp("data", suffix=".gdb")
        try:
            assert path.endswith(".gdb")
        finally:
            os.unlink(path)

    def test_binary_mode(self):
        path = ctf_gdb._write_temp(b"\x00\x01\x02", suffix=".bin", mode="wb")
        try:
            with open(path, "rb") as f:
                assert f.read() == b"\x00\x01\x02"
        finally:
            os.unlink(path)


# ── gdb_run tool tests ──────────────────────────────────────────────────────


class TestGdbRun:
    def test_nonexistent_file(self):
        result = json.loads(gdb_run("/nonexistent/binary/xyz", commands=["run"]))
        assert "error" in result
        assert "not found" in result["error"].lower()

    def test_returns_valid_json(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"\x7fELF" + b"\x00" * 100)
            path = f.name
        try:
            raw = gdb_run(path, commands=["info target"])
            parsed = json.loads(raw)
            assert "path" in parsed
            assert "commands" in parsed
            assert "output" in parsed
        finally:
            os.unlink(path)

    def test_commands_in_output(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"\x7fELF" + b"\x00" * 100)
            path = f.name
        try:
            result = json.loads(gdb_run(path, commands=["info target", "quit"]))
            assert result["commands"] == ["info target", "quit"]
        finally:
            os.unlink(path)

    def test_invalid_hex_stdin(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"\x7fELF" + b"\x00" * 100)
            path = f.name
        try:
            result = json.loads(
                gdb_run(path, commands=["run"], stdin_hex="not-valid-hex")
            )
            assert "error" in result
        finally:
            os.unlink(path)

    def test_valid_hex_stdin(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"\x7fELF" + b"\x00" * 100)
            path = f.name
        try:
            raw = gdb_run(path, commands=["run"], stdin_hex="41 42 43 44")
            parsed = json.loads(raw)
            assert "path" in parsed
        finally:
            os.unlink(path)


# ── gdb_break_inspect tool tests ────────────────────────────────────────────


class TestGdbBreakInspect:
    def test_nonexistent_file(self):
        result = json.loads(
            gdb_break_inspect("/nonexistent/binary/xyz", breakpoints=["main"])
        )
        assert "error" in result

    def test_returns_valid_json(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"\x7fELF" + b"\x00" * 100)
            path = f.name
        try:
            raw = gdb_break_inspect(path, breakpoints=["main"])
            parsed = json.loads(raw)
            assert "path" in parsed
            assert "breakpoints" in parsed
            assert "snapshots" in parsed
        finally:
            os.unlink(path)

    def test_invalid_hex_stdin(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"\x7fELF" + b"\x00" * 100)
            path = f.name
        try:
            result = json.loads(
                gdb_break_inspect(path, breakpoints=["main"], stdin_hex="ZZZZ")
            )
            assert "error" in result
        finally:
            os.unlink(path)

    def test_breakpoints_preserved(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"\x7fELF" + b"\x00" * 100)
            path = f.name
        try:
            result = json.loads(
                gdb_break_inspect(path, breakpoints=["main", "0x401234"])
            )
            assert result["breakpoints"] == ["main", "0x401234"]
        finally:
            os.unlink(path)


# ── gdb_trace_input tool tests ──────────────────────────────────────────────


class TestGdbTraceInput:
    def test_nonexistent_file(self):
        result = json.loads(gdb_trace_input("/nonexistent/binary/xyz"))
        assert "error" in result

    def test_returns_valid_json(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"\x7fELF" + b"\x00" * 100)
            path = f.name
        try:
            raw = gdb_trace_input(path)
            parsed = json.loads(raw)
            assert "path" in parsed
            assert "input_length" in parsed
        finally:
            os.unlink(path)

    def test_generates_pattern_when_no_input(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"\x7fELF" + b"\x00" * 100)
            path = f.name
        try:
            result = json.loads(gdb_trace_input(path))
            assert result["used_cyclic_pattern"] is True
            assert result["input_length"] == 200
        finally:
            os.unlink(path)

    def test_custom_pattern_length(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"\x7fELF" + b"\x00" * 100)
            path = f.name
        try:
            result = json.loads(gdb_trace_input(path, pattern_length=64))
            assert result["input_length"] == 64
        finally:
            os.unlink(path)

    def test_with_custom_input(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"\x7fELF" + b"\x00" * 100)
            path = f.name
        try:
            result = json.loads(gdb_trace_input(path, input_data="AAAA"))
            assert result["used_cyclic_pattern"] is False
            assert result["input_length"] == 4
        finally:
            os.unlink(path)

    def test_with_hex_input(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"\x7fELF" + b"\x00" * 100)
            path = f.name
        try:
            result = json.loads(gdb_trace_input(path, input_hex="41424344"))
            assert result["used_cyclic_pattern"] is False
            assert result["input_length"] == 4
        finally:
            os.unlink(path)

    def test_invalid_hex_input(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"\x7fELF" + b"\x00" * 100)
            path = f.name
        try:
            result = json.loads(gdb_trace_input(path, input_hex="ZZZZ"))
            assert "error" in result
        finally:
            os.unlink(path)


# ── gdb_memory_dump tool tests ──────────────────────────────────────────────


class TestGdbMemoryDump:
    def test_nonexistent_file(self):
        result = json.loads(
            gdb_memory_dump(
                "/nonexistent/binary/xyz",
                breakpoint="main",
                addresses=["0x400000:16"],
            )
        )
        assert "error" in result

    def test_returns_valid_json(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"\x7fELF" + b"\x00" * 100)
            path = f.name
        try:
            raw = gdb_memory_dump(path, breakpoint="main", addresses=["0x400000:16"])
            parsed = json.loads(raw)
            assert "path" in parsed
            assert "breakpoint" in parsed
            assert "memory" in parsed
        finally:
            os.unlink(path)

    def test_address_specs_preserved(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"\x7fELF" + b"\x00" * 100)
            path = f.name
        try:
            result = json.loads(
                gdb_memory_dump(
                    path,
                    breakpoint="main",
                    addresses=["0x400000:16", "$rsp:32"],
                )
            )
            assert len(result["memory"]) == 2
            assert result["memory"][0]["address"] == "0x400000:16"
            assert result["memory"][1]["address"] == "$rsp:32"
        finally:
            os.unlink(path)

    def test_invalid_hex_stdin(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"\x7fELF" + b"\x00" * 100)
            path = f.name
        try:
            result = json.loads(
                gdb_memory_dump(
                    path,
                    breakpoint="main",
                    addresses=["0x400000:16"],
                    stdin_hex="ZZZZ",
                )
            )
            assert "error" in result
        finally:
            os.unlink(path)


# ── gdb_checksec_runtime tool tests ─────────────────────────────────────────


class TestGdbChecksecRuntime:
    def test_nonexistent_file(self):
        result = json.loads(gdb_checksec_runtime("/nonexistent/binary/xyz"))
        assert "error" in result

    def test_returns_valid_json(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"\x7fELF" + b"\x00" * 100)
            path = f.name
        try:
            raw = gdb_checksec_runtime(path)
            parsed = json.loads(raw)
            assert "path" in parsed
        finally:
            os.unlink(path)

    def test_symbols_param(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"\x7fELF" + b"\x00" * 100)
            path = f.name
        try:
            raw = gdb_checksec_runtime(path, symbols=["system", "puts"])
            parsed = json.loads(raw)
            assert "path" in parsed
        finally:
            os.unlink(path)


# ── Integration: all tools return valid JSON ────────────────────────────────


class TestJsonOutput:
    """Every tool must return valid JSON regardless of input."""

    def test_gdb_run_always_json(self):
        raw = gdb_run("/dev/null", commands=["quit"])
        json.loads(raw)

    def test_gdb_break_inspect_always_json(self):
        raw = gdb_break_inspect("/dev/null", breakpoints=["main"])
        json.loads(raw)

    def test_gdb_trace_input_always_json(self):
        raw = gdb_trace_input("/dev/null")
        json.loads(raw)

    def test_gdb_memory_dump_always_json(self):
        raw = gdb_memory_dump("/dev/null", breakpoint="main", addresses=["0x0:1"])
        json.loads(raw)

    def test_gdb_checksec_runtime_always_json(self):
        raw = gdb_checksec_runtime("/dev/null")
        json.loads(raw)


# ── TestGdbOutputParsing — mock-based GDB output parsing tests ──────────────


class TestGdbOutputParsing:
    """Test GDB output parsing with mocked GDB output."""

    def test_break_inspect_snapshot_parsing(self):
        """Mock GDB output with breakpoint markers and verify snapshot parsing."""
        from unittest.mock import patch

        gdb_output = (
            "Breakpoint 1, main () at test.c:5\n"
            "===BREAKPOINT_0_main===\n"
            "rax            0x401234            4198964\n"
            "rbp            0x7fffffffde90      0x7fffffffde90\n"
            "rsp            0x7fffffffde80      0x7fffffffde80\n"
            "===STACK===\n"
            "0x7fffffffde80: 0x00000001\n"
            "===BACKTRACE===\n"
            "#0  0x0000000000401234 in main ()\n"
        )
        mock_result = {"stdout": gdb_output, "stderr": "", "returncode": 0}

        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"\x7fELF" + b"\x00" * 100)
            path = f.name
        try:
            # We need to mock _run_gdb rather than run_tool since it handles temp files
            with patch("ctf_gdb._run_gdb", return_value=mock_result):
                result = json.loads(gdb_break_inspect(path, breakpoints=["main"]))
                assert len(result["snapshots"]) == 1
                assert "rax" in result["snapshots"][0]["registers"]
                assert result["snapshots"][0]["registers"]["rax"]["hex"] == "0x401234"
        finally:
            os.unlink(path)

    def test_trace_input_sigsegv_detection(self):
        """Mock GDB SIGSEGV output and verify crash detection."""
        from unittest.mock import patch

        gdb_output = (
            "Program received signal SIGSEGV, Segmentation fault.\n"
            "0x0000000041414141 in ?? ()\n"
            "===CRASH_INFO===\n"
            "rax            0x0                 0\n"
            "rip            0x41414141          0x41414141\n"
            "===STACK===\n"
            "0x7fffffffde80: 0x41414141\n"
            "===BACKTRACE===\n"
            "#0  0x0000000041414141 in ?? ()\n"
        )
        mock_result = {"stdout": gdb_output, "stderr": "", "returncode": 0}

        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"\x7fELF" + b"\x00" * 100)
            path = f.name
        try:
            with patch("ctf_gdb._run_gdb", return_value=mock_result):
                with patch("ctf_gdb._write_temp", return_value="/tmp/fake_stdin"):
                    with patch("os.unlink"):
                        result = json.loads(gdb_trace_input(path))
                        assert result["signal"] == "SIGSEGV"
                        assert result["crash_address"] == "0x0000000041414141"
        finally:
            os.unlink(path)

    def test_checksec_runtime_mappings_parsing(self):
        """Mock GDB process mappings output."""
        from unittest.mock import patch

        gdb_output = (
            "Breakpoint 1, main () at test.c:5\n"
            "===MAPPINGS===\n"
            "0x400000 0x401000 0x1000 r-xp /usr/bin/test\n"
            "0x7f1234000000 0x7f1234200000 0x200000 r-xp /lib/x86_64-linux-gnu/libc.so.6\n"
            "===PLT===\n"
            "0x401030  puts@plt\n"
            "===REGISTERS===\n"
            "rax            0x401234            4198964\n"
            "===SYMBOLS===\n"
            'Symbol "system" is at 0x7f1234050d60\n'
        )
        mock_result = {"stdout": gdb_output, "stderr": "", "returncode": 0}

        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"\x7fELF" + b"\x00" * 100)
            path = f.name
        try:
            with patch("ctf_gdb._run_gdb", return_value=mock_result):
                result = json.loads(gdb_checksec_runtime(path, symbols=["system"]))
                assert "libc_base" in result
                assert result["libc_base"] == "0x7f1234000000"
                assert result["resolved_symbols"]["system"] == "0x7f1234050d60"
        finally:
            os.unlink(path)

    def test_memory_dump_parsing(self):
        """Mock GDB memory dump output."""
        from unittest.mock import patch

        gdb_output = (
            "Breakpoint 1, main () at test.c:5\n"
            "===DUMP_0x404000:64===\n"
            "0x404000:\t0x48\t0x65\t0x6c\t0x6c\n"
            "===ASCII_0x404000:64===\n"
            "0x404000:\t72 'H'\t101 'e'\t108 'l'\t108 'l'\n"
        )
        mock_result = {"stdout": gdb_output, "stderr": "", "returncode": 0}

        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"\x7fELF" + b"\x00" * 100)
            path = f.name
        try:
            with patch("ctf_gdb._run_gdb", return_value=mock_result):
                result = json.loads(
                    gdb_memory_dump(path, breakpoint="main", addresses=["0x404000:64"])
                )
                assert len(result["memory"]) == 1
                assert "hex_dump" in result["memory"][0]
        finally:
            os.unlink(path)
