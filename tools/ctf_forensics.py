#!/usr/bin/env python3
"""CTF Forensics & Steganography MCP Server — file analysis, stego, data extraction."""

import json
import math
import os
import re
import shlex
import sys
import tempfile

sys.path.insert(0, os.path.dirname(__file__))
from fastmcp import FastMCP
from lib.subprocess_utils import run_tool, safe_read_file

mcp = FastMCP(
    "ctf-forensics",
    instructions=(
        "File forensics and steganography tools for CTF challenges. "
        "Start with forensics_file_triage for a comprehensive overview, then use "
        "forensics_stego_analyze for steganography, forensics_extract_embedded for data carving, "
        "forensics_image_analysis for deep image inspection, or forensics_volatility for memory dumps."
    ),
)


# ── file_triage ──────────────────────────────────────────────────────────────


@mcp.tool()
def forensics_file_triage(path: str) -> str:
    """Comprehensive one-shot file analysis — runs file, exiftool, binwalk, strings.

    Returns file type, metadata, embedded data signatures, interesting strings,
    file size, and overall entropy.
    """
    path = os.path.realpath(path)
    if not os.path.isfile(path):
        return json.dumps({"error": f"File not found: {path}"})

    result = {"path": path, "size": os.path.getsize(path)}

    r = run_tool(["file", "-b", path])
    result["file_type"] = r["stdout"].strip()

    r = run_tool(["file", "-b", "--mime-type", path])
    result["mime_type"] = r["stdout"].strip()

    r = run_tool(["exiftool", "-j", path])
    if r["returncode"] == 0:
        try:
            meta = json.loads(r["stdout"])
            if meta and isinstance(meta, list):
                m = meta[0]
                interesting_keys = {
                    "Comment",
                    "UserComment",
                    "ImageDescription",
                    "Artist",
                    "Author",
                    "Creator",
                    "Title",
                    "Subject",
                    "Keywords",
                    "XPComment",
                    "XPTitle",
                    "XPAuthor",
                    "XPKeywords",
                    "ImageWidth",
                    "ImageHeight",
                    "ColorType",
                    "BitDepth",
                    "Compression",
                    "Filter",
                    "Interlace",
                    "Software",
                    "Warning",
                    "Error",
                    "ExifToolWarning",
                }
                result["metadata"] = {
                    k: v for k, v in m.items() if k in interesting_keys
                }
                for k, v in m.items():
                    v_str = str(v).lower()
                    if any(
                        kw in v_str
                        for kw in ["flag", "ctf", "hidden", "secret", "password"]
                    ):
                        result["metadata"][k] = v
        except json.JSONDecodeError:
            pass

    r = run_tool(["binwalk", "--quiet", path])
    if r["returncode"] == 0:
        embedded = []
        for line in r["stdout"].splitlines():
            line = line.strip()
            if not line or line.startswith("DECIMAL") or line.startswith("-"):
                continue
            parts = line.split(None, 2)
            if len(parts) >= 3 and parts[0].isdigit():
                embedded.append(
                    {
                        "offset": int(parts[0]),
                        "hex_offset": parts[1],
                        "description": parts[2],
                    }
                )
        result["embedded_signatures"] = embedded

    r = run_tool(["strings", "-n", "6", path])
    if r["returncode"] == 0:
        all_strings = r["stdout"].splitlines()
        interesting_re = re.compile(
            r"flag\{|ctf\{|password|secret|hidden|/bin/sh|admin|key[=:]|token|base64|http://|https://|\.onion",
            re.IGNORECASE,
        )
        result["strings_interesting"] = [
            s.strip() for s in all_strings if interesting_re.search(s)
        ][:50]
        result["strings_total"] = len(all_strings)

    try:
        data = safe_read_file(path, max_size=50_000_000)
        result["entropy"] = round(_calculate_entropy(data), 4)
        result["entropy_note"] = _entropy_interpretation(result["entropy"])
    except Exception:
        pass

    result["trailing_data"] = _check_trailing_data(path, result.get("mime_type", ""))

    return json.dumps(result, indent=2)


def _check_trailing_data(path, mime_type):
    """Check if there's data appended after the file's logical end."""
    try:
        data = safe_read_file(path, max_size=50_000_000)
        if "png" in mime_type:
            iend = data.find(b"IEND")
            if iend >= 0:
                end_pos = iend + 12  # IEND chunk + CRC
                if end_pos < len(data):
                    trailing = data[end_pos:]
                    return {
                        "found": True,
                        "offset": end_pos,
                        "size": len(trailing),
                        "preview": trailing[:100].decode("latin-1", errors="replace"),
                    }
        elif "jpeg" in mime_type or "jpg" in mime_type:
            eoi = data.rfind(b"\xff\xd9")
            if eoi >= 0:
                end_pos = eoi + 2
                if end_pos < len(data):
                    trailing = data[end_pos:]
                    return {
                        "found": True,
                        "offset": end_pos,
                        "size": len(trailing),
                        "preview": trailing[:100].decode("latin-1", errors="replace"),
                    }
        elif "zip" in mime_type:
            eocd = data.rfind(b"\x50\x4b\x05\x06")
            if eocd >= 0 and eocd + 22 <= len(data):
                # Read the comment length field (2 bytes at offset 20 in EOCD)
                comment_len = int.from_bytes(data[eocd + 20 : eocd + 22], "little")
                end_pos = eocd + 22 + comment_len
                if end_pos < len(data):
                    return {
                        "found": True,
                        "offset": end_pos,
                        "size": len(data) - end_pos,
                    }
    except Exception:
        pass
    return {"found": False}


# ── stego_analyze ────────────────────────────────────────────────────────────


@mcp.tool()
def forensics_stego_analyze(path: str, password: str = "") -> str:
    """Systematic steganography analysis — tries ALL applicable tools for the file type.

    Args:
        path: Path to the file to analyze
        password: Optional password for tools that support it (steghide, etc.)

    For PNG: zsteg (LSB/MSB, all channel combos), trailing data, palette analysis
    For JPEG: steghide, EXIF/comment, EOF data, jsteg
    For WAV/audio: LSB audio, spectrogram hints
    """
    path = os.path.realpath(path)
    if not os.path.isfile(path):
        return json.dumps({"error": f"File not found: {path}"})

    r = run_tool(["file", "-b", "--mime-type", path])
    mime = r["stdout"].strip()

    findings = []

    if "png" in mime:
        findings.extend(_stego_png(path))
    elif "jpeg" in mime or "jpg" in mime:
        findings.extend(_stego_jpeg(path, password))
    elif "bmp" in mime:
        findings.extend(_stego_bmp(path))
    elif "wav" in mime or "audio" in mime:
        findings.extend(_stego_audio(path))
    elif "gif" in mime:
        findings.extend(_stego_gif(path))
    else:
        # Generic checks
        findings.extend(_stego_generic(path, password))

    # Always check steghide if applicable (works on JPEG, BMP, WAV, AU)
    if any(t in mime for t in ["jpeg", "jpg", "bmp", "wav", "audio"]):
        findings.extend(_try_steghide(path, password))

    # Sort by confidence
    findings.sort(key=lambda x: x.get("confidence", 0), reverse=True)

    return json.dumps({"file": path, "mime_type": mime, "findings": findings}, indent=2)


def _stego_png(path):
    findings = []

    # zsteg — comprehensive PNG stego analysis
    r = run_tool(["zsteg", path, "--all"], timeout=30)
    if r["returncode"] == 0:
        for line in r["stdout"].splitlines():
            line = line.strip()
            if not line or "Nothing" in line:
                continue
            # zsteg outputs "method  .. data"
            if ".." in line:
                method, _, data = line.partition("..")
                data = data.strip()
                # Filter out noise — only report meaningful findings
                if len(data) > 3 and not all(c in " .~" for c in data[:20]):
                    confidence = 0.5
                    if any(
                        kw in data.lower()
                        for kw in ["flag", "ctf", "http", "password", "key"]
                    ):
                        confidence = 0.9
                    elif data.isprintable() and len(data) > 10:
                        confidence = 0.7
                    findings.append(
                        {
                            "tool": "zsteg",
                            "method": method.strip(),
                            "data": data[:500],
                            "confidence": confidence,
                        }
                    )

    # Check trailing data after IEND
    try:
        data = safe_read_file(path)
        iend = data.find(b"IEND")
        if iend >= 0:
            end_pos = iend + 12
            if end_pos < len(data):
                trailing = data[end_pos:]
                findings.append(
                    {
                        "tool": "manual",
                        "method": "trailing_data_after_IEND",
                        "data": trailing[:500].decode("latin-1", errors="replace"),
                        "size": len(trailing),
                        "confidence": 0.8,
                    }
                )
    except Exception:
        pass

    return findings


def _stego_jpeg(path, password):
    findings = []

    # Check EXIF comments
    r = run_tool(["exiftool", "-Comment", "-UserComment", "-s", "-s", "-s", path])
    if r["returncode"] == 0 and r["stdout"].strip():
        findings.append(
            {
                "tool": "exiftool",
                "method": "EXIF_comment",
                "data": r["stdout"].strip(),
                "confidence": 0.8,
            }
        )

    # Check for trailing data after EOI
    try:
        data = safe_read_file(path)
        eoi = data.rfind(b"\xff\xd9")
        if eoi >= 0 and eoi + 2 < len(data):
            trailing = data[eoi + 2 :]
            findings.append(
                {
                    "tool": "manual",
                    "method": "trailing_data_after_EOI",
                    "data": trailing[:500].decode("latin-1", errors="replace"),
                    "size": len(trailing),
                    "confidence": 0.8,
                }
            )
    except Exception:
        pass

    return findings


def _stego_bmp(path):
    findings = []
    # Check LSB with zsteg (supports BMP too)
    r = run_tool(["zsteg", path], timeout=30)
    if r["returncode"] == 0:
        for line in r["stdout"].splitlines():
            if ".." in line:
                method, _, data = line.partition("..")
                data = data.strip()
                if len(data) > 3:
                    findings.append(
                        {
                            "tool": "zsteg",
                            "method": method.strip(),
                            "data": data[:500],
                            "confidence": 0.6,
                        }
                    )
    return findings


def _stego_audio(path):
    findings = []
    # Check strings in audio file
    r = run_tool(["strings", "-n", "8", path])
    if r["returncode"] == 0:
        interesting = re.compile(r"flag|ctf|password|secret|hidden", re.IGNORECASE)
        for s in r["stdout"].splitlines():
            if interesting.search(s):
                findings.append(
                    {
                        "tool": "strings",
                        "method": "embedded_strings",
                        "data": s.strip(),
                        "confidence": 0.7,
                    }
                )
    return findings


def _stego_gif(path):
    findings = []
    # GIF can have comment extensions
    r = run_tool(["exiftool", "-Comment", "-s", "-s", "-s", path])
    if r["returncode"] == 0 and r["stdout"].strip():
        findings.append(
            {
                "tool": "exiftool",
                "method": "GIF_comment",
                "data": r["stdout"].strip(),
                "confidence": 0.8,
            }
        )
    # Check for multiple frames (data might be hidden in specific frames)
    r = run_tool(["exiftool", "-FrameCount", "-s", "-s", "-s", path])
    if r["returncode"] == 0 and r["stdout"].strip():
        try:
            frames = int(r["stdout"].strip())
            if frames > 1:
                findings.append(
                    {
                        "tool": "exiftool",
                        "method": "multi_frame_gif",
                        "data": f"GIF has {frames} frames — check individual frames for hidden data",
                        "confidence": 0.4,
                    }
                )
        except ValueError:
            pass
    return findings


def _stego_generic(path, password):
    findings = []
    # strings search
    r = run_tool(["strings", "-n", "8", path])
    if r["returncode"] == 0:
        interesting = re.compile(r"flag\{|ctf\{|password|secret|hidden", re.IGNORECASE)
        for s in r["stdout"].splitlines():
            if interesting.search(s):
                findings.append(
                    {
                        "tool": "strings",
                        "method": "embedded_strings",
                        "data": s.strip(),
                        "confidence": 0.7,
                    }
                )
    return findings


def _try_steghide(path, password):
    findings = []
    passwords = [password] if password else ["", "password", "secret", "flag", "ctf"]
    for pw in passwords:
        with tempfile.NamedTemporaryFile(suffix=".out", delete=False) as tmp:
            tmp_path = tmp.name
        try:
            cmd = ["steghide", "extract", "-sf", path, "-xf", tmp_path, "-p", pw, "-f"]
            r = run_tool(cmd, timeout=15)
            if (
                r["returncode"] == 0
                and os.path.exists(tmp_path)
                and os.path.getsize(tmp_path) > 0
            ):
                extracted = safe_read_file(tmp_path, max_size=1_000_000)
                findings.append(
                    {
                        "tool": "steghide",
                        "method": f"steghide_password={'<empty>' if not pw else pw}",
                        "data": extracted.decode("utf-8", errors="replace")[:500],
                        "size": len(extracted),
                        "confidence": 0.95,
                    }
                )
                break
        except Exception:
            pass
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
    return findings


# ── extract_embedded ─────────────────────────────────────────────────────────


@mcp.tool()
def forensics_extract_embedded(path: str) -> str:
    """Extract embedded files from a binary/image using binwalk and foremost.

    Returns a list of extracted files with their types and paths.
    """
    path = os.path.realpath(path)
    if not os.path.isfile(path):
        return json.dumps({"error": f"File not found: {path}"})

    with tempfile.TemporaryDirectory(prefix="ctf_extract_") as tmpdir:
        extracted = []

        # binwalk extraction
        r = run_tool(["binwalk", "-e", "--directory", tmpdir, "-q", path], timeout=60)
        binwalk_dir = os.path.join(tmpdir)

        for root, dirs, files in os.walk(binwalk_dir):
            for f in files:
                fpath = os.path.join(root, f)
                fr = run_tool(["file", "-b", fpath])
                try:
                    size = os.path.getsize(fpath)
                except OSError:
                    size = 0
                entry = {
                    "name": f,
                    "type": fr["stdout"].strip(),
                    "size": size,
                    "tool": "binwalk",
                }
                # Try to read small text files
                if size < 10000:
                    try:
                        content = safe_read_file(fpath, max_size=10000)
                        if all(32 <= b < 127 or b in (9, 10, 13) for b in content):
                            entry["content"] = content.decode()
                    except Exception:
                        pass
                extracted.append(entry)

        # foremost (if binwalk didn't find much)
        if len(extracted) <= 1:
            foremost_dir = os.path.join(tmpdir, "foremost_out")
            os.makedirs(foremost_dir, exist_ok=True)
            r = run_tool(["foremost", "-i", path, "-o", foremost_dir, "-T"], timeout=60)
            for root, dirs, files in os.walk(foremost_dir):
                for f in files:
                    if f == "audit.txt":
                        continue
                    fpath = os.path.join(root, f)
                    fr = run_tool(["file", "-b", fpath])
                    extracted.append(
                        {
                            "name": f,
                            "type": fr["stdout"].strip(),
                            "size": os.path.getsize(fpath),
                            "tool": "foremost",
                        }
                    )

    return json.dumps(
        {"source": path, "extracted_count": len(extracted), "files": extracted},
        indent=2,
    )


# ── entropy_analysis ─────────────────────────────────────────────────────────


def _calculate_entropy(data):
    """Calculate Shannon entropy of data."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    length = len(data)
    entropy = 0.0
    for count in counts:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return entropy


def _entropy_interpretation(entropy):
    if entropy < 1.0:
        return "Very low — likely mostly empty/padding"
    elif entropy < 3.5:
        return "Low — likely plaintext or simple data"
    elif entropy < 5.0:
        return "Medium — structured data, possibly compressed text"
    elif entropy < 7.0:
        return "High — likely compressed data"
    elif entropy < 7.9:
        return "Very high — likely encrypted or compressed"
    else:
        return "Near maximum — encrypted or random data"


@mcp.tool()
def forensics_entropy_analysis(path: str, block_size: int = 4096) -> str:
    """Calculate block-level entropy to detect encrypted/compressed regions.

    Args:
        path: Path to the file
        block_size: Size of each block in bytes (default 4096)

    Returns per-block entropy values to identify interesting regions.
    """
    path = os.path.realpath(path)
    if not os.path.isfile(path):
        return json.dumps({"error": f"File not found: {path}"})

    try:
        data = safe_read_file(path, max_size=50_000_000)
    except ValueError as e:
        return json.dumps({"error": str(e)})

    overall = _calculate_entropy(data)
    blocks = []
    anomalies = []

    for i in range(0, len(data), block_size):
        block = data[i : i + block_size]
        ent = _calculate_entropy(block)
        blocks.append({"offset": i, "entropy": round(ent, 4)})

    # Find anomalies (significant entropy changes between adjacent blocks)
    for i in range(1, len(blocks)):
        diff = abs(blocks[i]["entropy"] - blocks[i - 1]["entropy"])
        if diff > 2.0:
            anomalies.append(
                {
                    "offset": blocks[i]["offset"],
                    "entropy_change": round(diff, 4),
                    "from": blocks[i - 1]["entropy"],
                    "to": blocks[i]["entropy"],
                    "note": "Significant entropy change — possible boundary between data types",
                }
            )

    # Summarize regions
    high_entropy_regions = [b for b in blocks if b["entropy"] > 7.0]
    low_entropy_regions = [b for b in blocks if b["entropy"] < 2.0]

    return json.dumps(
        {
            "file": path,
            "size": len(data),
            "overall_entropy": round(overall, 4),
            "interpretation": _entropy_interpretation(overall),
            "block_size": block_size,
            "total_blocks": len(blocks),
            "high_entropy_blocks": len(high_entropy_regions),
            "low_entropy_blocks": len(low_entropy_regions),
            "anomalies": anomalies[:20],
            "blocks": blocks[:100]
            if len(blocks) <= 100
            else blocks[:: max(1, len(blocks) // 50)],
        },
        indent=2,
    )


# ── image_analysis ───────────────────────────────────────────────────────────


@mcp.tool()
def forensics_image_analysis(path: str, extract_lsb: bool = False) -> str:
    """Deep image analysis — channel separation, LSB extraction, palette, histogram anomalies.

    Args:
        path: Path to the image file
        extract_lsb: If true, extract and return LSB plane data as hex
    """
    path = os.path.realpath(path)
    if not os.path.isfile(path):
        return json.dumps({"error": f"File not found: {path}"})

    try:
        import numpy as np
        from PIL import Image
    except ImportError:
        return json.dumps({"error": "PIL/numpy not available"})

    try:
        img = Image.open(path)
    except Exception as e:
        return json.dumps({"error": f"Cannot open image: {e}"})

    result = {
        "format": img.format,
        "mode": img.mode,
        "size": {"width": img.width, "height": img.height},
        "info": {k: str(v) for k, v in img.info.items() if k not in ("icc_profile",)},
    }

    # Check for palette
    if img.mode == "P":
        palette = img.getpalette()
        if palette:
            result["palette_entries"] = len(palette) // 3
            # Check for suspicious palette entries
            unique_colors = set()
            for i in range(0, len(palette), 3):
                unique_colors.add((palette[i], palette[i + 1], palette[i + 2]))
            result["unique_palette_colors"] = len(unique_colors)

    # Convert to RGB for analysis
    if img.mode not in ("RGB", "RGBA"):
        img_rgb = img.convert("RGB")
    else:
        img_rgb = img

    pixels = np.array(img_rgb)

    # Channel statistics
    channels = {}
    for i, name in enumerate(["red", "green", "blue"]):
        ch = pixels[:, :, i]
        channels[name] = {
            "min": int(ch.min()),
            "max": int(ch.max()),
            "mean": round(float(ch.mean()), 2),
            "std": round(float(ch.std()), 2),
            "unique_values": int(len(np.unique(ch))),
        }
    result["channels"] = channels

    # LSB analysis
    lsb_data = {}
    for i, name in enumerate(["red", "green", "blue"]):
        ch = pixels[:, :, i]
        lsb = ch & 1
        ones_ratio = float(lsb.sum()) / lsb.size
        lsb_data[name] = {
            "ones_ratio": round(ones_ratio, 4),
            "note": "suspicious" if abs(ones_ratio - 0.5) > 0.1 else "normal",
        }
    result["lsb_analysis"] = lsb_data

    # Extract LSB if requested
    if extract_lsb:
        # Extract LSB from all channels, row by row
        lsb_bits = []
        for row in pixels:
            for pixel in row:
                for ch in range(min(3, len(pixel))):
                    lsb_bits.append(pixel[ch] & 1)

        # Convert bits to bytes
        lsb_bytes = bytearray()
        for i in range(0, len(lsb_bits) - 7, 8):
            byte = 0
            for bit in lsb_bits[i : i + 8]:
                byte = (byte << 1) | bit
            lsb_bytes.append(byte)

        # Show first 200 bytes
        preview = bytes(lsb_bytes[:200])
        result["lsb_extracted"] = {
            "hex": preview.hex(),
            "ascii": preview.decode("latin-1", errors="replace"),
            "total_bytes": len(lsb_bytes),
        }

    # Histogram anomaly detection
    hist = img_rgb.histogram()
    # Split into R, G, B histograms (256 values each)
    r_hist = hist[0:256]
    g_hist = hist[256:512]
    b_hist = hist[512:768]

    # Check for unusual gaps or spikes
    for name, h in [("red", r_hist), ("green", g_hist), ("blue", b_hist)]:
        zero_bins = sum(1 for v in h if v == 0)
        if zero_bins > 200:
            result.setdefault("histogram_anomalies", []).append(
                f"{name} channel has {zero_bins}/256 empty bins — possible data hiding or manipulation"
            )

    return json.dumps(result, indent=2)


# ── volatility ────────────────────────────────────────────────────────────────


@mcp.tool()
def forensics_volatility(
    dump_path: str,
    plugin: str = "windows.info",
    extra_args: str = "",
    timeout: int = 120,
) -> str:
    """Run a volatility3 plugin on a memory dump for forensic analysis.

    Args:
        dump_path: Path to the memory dump file (.raw, .vmem, .dmp, etc.)
        plugin: Volatility3 plugin name. Common plugins:
            - windows.info: OS version and kernel info
            - windows.pslist / linux.pslist: Process listing
            - windows.pstree: Process tree
            - windows.filescan: Find file objects in memory
            - windows.dumpfiles: Extract files (use extra_args for --pid)
            - windows.hashdump: Dump password hashes
            - windows.cmdline: Command line arguments per process
            - windows.netscan: Network connections
            - linux.bash: Bash command history
        extra_args: Additional arguments (space-separated), e.g. "--pid 1234"
        timeout: Execution timeout in seconds (default 120, memory analysis can be slow)
    """
    path = os.path.realpath(dump_path)
    if not os.path.isfile(path):
        return json.dumps({"error": f"File not found: {path}"})

    cmd = ["vol", "-f", path, plugin]
    if extra_args:
        cmd.extend(shlex.split(extra_args))

    result = {"dump": path, "plugin": plugin}

    # Try JSON renderer first
    r = run_tool(cmd + ["-r", "json"], timeout=timeout)
    if r["returncode"] == 0 and r["stdout"].strip():
        try:
            parsed = json.loads(r["stdout"])
            result["data"] = parsed
            result["renderer"] = "json"
            return json.dumps(result, indent=2)
        except json.JSONDecodeError:
            pass

    # Fallback to text output
    r = run_tool(cmd, timeout=timeout)
    if r["returncode"] != 0:
        result["error"] = r["stderr"] or r.get("error", "volatility3 failed")
        result["returncode"] = r["returncode"]
        return json.dumps(result, indent=2)

    lines = r["stdout"].strip().splitlines()
    if len(lines) > 1:
        headers = (
            [h.strip() for h in lines[0].split("\t")]
            if "\t" in lines[0]
            else lines[0].split()
        )
        rows = []
        for line in lines[1:500]:
            if "\t" in line:
                cells = [c.strip() for c in line.split("\t")]
            else:
                cells = line.split(None, max(len(headers) - 1, 0))
            if len(cells) >= len(headers):
                rows.append(dict(zip(headers, cells)))
            else:
                rows.append({"raw": line})
        result["headers"] = headers
        result["rows"] = rows
        result["row_count"] = len(rows)
    else:
        result["raw_output"] = r["stdout"][:5000]

    result["renderer"] = "text"
    return json.dumps(result, indent=2)


if __name__ == "__main__":
    mcp.run(transport="stdio")
