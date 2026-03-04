"""Tests for ctf_forensics.py — pure-Python helper functions and tool JSON output."""

import json
import math
import os
import sys
import tempfile

import pytest

# Allow imports from the tools directory
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# Access tool functions through FastMCP wrappers
import ctf_forensics
from ctf_forensics import (
    _calculate_entropy,
    _check_trailing_data,
    _entropy_interpretation,
)

file_triage = ctf_forensics.forensics_file_triage.fn
stego_analyze = ctf_forensics.forensics_stego_analyze.fn
extract_embedded = ctf_forensics.forensics_extract_embedded.fn
entropy_analysis = ctf_forensics.forensics_entropy_analysis.fn
image_analysis = ctf_forensics.forensics_image_analysis.fn

# ── _calculate_entropy tests ─────────────────────────────────────────────────


class TestCalculateEntropy:
    def test_empty_data(self):
        assert _calculate_entropy(b"") == 0.0

    def test_single_byte_repeated(self):
        # All zeros — only one symbol, entropy = 0
        data = b"\x00" * 1000
        assert _calculate_entropy(data) == 0.0

    def test_two_equal_symbols(self):
        # Half 0x00, half 0x01 — entropy should be 1.0 bit
        data = b"\x00" * 500 + b"\x01" * 500
        entropy = _calculate_entropy(data)
        assert abs(entropy - 1.0) < 0.01

    def test_four_equal_symbols(self):
        # Four equally distributed symbols — entropy should be 2.0 bits
        data = b"\x00" * 250 + b"\x01" * 250 + b"\x02" * 250 + b"\x03" * 250
        entropy = _calculate_entropy(data)
        assert abs(entropy - 2.0) < 0.01

    def test_all_256_bytes_uniform(self):
        # All 256 byte values equally distributed — max entropy = 8.0
        data = bytes(range(256)) * 100
        entropy = _calculate_entropy(data)
        assert abs(entropy - 8.0) < 0.01

    def test_highly_random_data(self):
        # os.urandom should produce high entropy (close to 8)
        data = os.urandom(10000)
        entropy = _calculate_entropy(data)
        assert entropy > 7.5

    def test_english_text_moderate_entropy(self):
        # ASCII English text typically has entropy around 3.5-5.0
        text = (
            b"The quick brown fox jumps over the lazy dog. "
            b"This sentence contains a reasonable distribution "
            b"of English letters and should have moderate entropy."
        )
        entropy = _calculate_entropy(text)
        assert 3.0 < entropy < 5.5

    def test_single_byte_data(self):
        data = b"\x42"
        assert _calculate_entropy(data) == 0.0

    def test_entropy_is_non_negative(self):
        for data in [b"", b"\x00", b"abc", os.urandom(100)]:
            assert _calculate_entropy(data) >= 0.0

    def test_entropy_at_most_eight(self):
        # Shannon entropy of byte data is at most 8 bits
        data = os.urandom(10000)
        assert _calculate_entropy(data) <= 8.0


# ── _entropy_interpretation tests ────────────────────────────────────────────


class TestEntropyInterpretation:
    def test_very_low(self):
        result = _entropy_interpretation(0.5)
        assert "low" in result.lower() or "empty" in result.lower()

    def test_low(self):
        result = _entropy_interpretation(2.0)
        assert "low" in result.lower() or "plaintext" in result.lower()

    def test_medium(self):
        result = _entropy_interpretation(4.0)
        assert "medium" in result.lower() or "structured" in result.lower()

    def test_high(self):
        result = _entropy_interpretation(6.0)
        assert "high" in result.lower() or "compressed" in result.lower()

    def test_very_high(self):
        result = _entropy_interpretation(7.5)
        assert "high" in result.lower() or "encrypted" in result.lower()

    def test_near_maximum(self):
        result = _entropy_interpretation(7.95)
        assert (
            "maximum" in result.lower()
            or "encrypted" in result.lower()
            or "random" in result.lower()
        )

    def test_boundary_values(self):
        # Each threshold boundary should return a valid string
        for val in [0.0, 0.99, 1.0, 3.49, 3.5, 4.99, 5.0, 6.99, 7.0, 7.89, 7.9, 8.0]:
            result = _entropy_interpretation(val)
            assert isinstance(result, str)
            assert len(result) > 0


# ── _check_trailing_data tests ───────────────────────────────────────────────


class TestCheckTrailingData:
    def test_non_matching_mime_returns_not_found(self):
        # Create a simple temp file and check with a non-image mime type
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"just some data")
            path = f.name
        try:
            result = _check_trailing_data(path, "application/octet-stream")
            assert result["found"] is False
        finally:
            os.unlink(path)

    def test_png_without_iend_returns_not_found(self):
        # A file that claims to be PNG but has no IEND marker
        with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as f:
            f.write(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)
            path = f.name
        try:
            result = _check_trailing_data(path, "image/png")
            assert result["found"] is False
        finally:
            os.unlink(path)

    def test_png_with_trailing_data(self):
        # Simulate a PNG with IEND chunk followed by trailing data.
        # The function searches for b"IEND" and skips 12 bytes from that position
        # (covering IEND tag + CRC + padding). We place the trailing data so it
        # starts well past that 12-byte window.
        #
        # Build file: [PNG header][padding][IEND text][8 bytes post-IEND][trailing]
        # The function finds "IEND" at some offset, then end_pos = offset + 12.
        png_header = b"\x89PNG\r\n\x1a\n"
        body_padding = b"\x00" * 50
        # Just the IEND marker followed by 8 bytes of "CRC + extra"
        iend_and_crc = b"IEND" + b"\xae\x42\x60\x82" + b"\x00\x00\x00\x00"
        trailing = b"SECRET_FLAG_HERE"
        with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as f:
            f.write(png_header + body_padding + iend_and_crc + trailing)
            path = f.name
        try:
            result = _check_trailing_data(path, "image/png")
            assert result["found"] is True
            assert result["size"] == len(trailing)
            assert "SECRET_FLAG_HERE" in result["preview"]
        finally:
            os.unlink(path)

    def test_png_without_trailing_data(self):
        # PNG ending exactly at the point the function considers "end of IEND".
        # The function does end_pos = iend_pos + 12, so we need exactly 12 bytes
        # from the "IEND" string to EOF (IEND(4) + CRC(4) + 4 extra bytes).
        png_header = b"\x89PNG\r\n\x1a\n"
        body_padding = b"\x00" * 50
        iend_and_crc = b"IEND" + b"\xae\x42\x60\x82" + b"\x00\x00\x00\x00"
        with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as f:
            f.write(png_header + body_padding + iend_and_crc)
            path = f.name
        try:
            result = _check_trailing_data(path, "image/png")
            assert result["found"] is False
        finally:
            os.unlink(path)

    def test_jpeg_with_trailing_data(self):
        # Simulate JPEG ending with EOI marker (FF D9) + trailing data
        trailing = b"HIDDEN_DATA"
        with tempfile.NamedTemporaryFile(delete=False, suffix=".jpg") as f:
            f.write(b"\xff\xd8\xff\xe0" + b"\x00" * 50 + b"\xff\xd9" + trailing)
            path = f.name
        try:
            result = _check_trailing_data(path, "image/jpeg")
            assert result["found"] is True
            assert result["size"] == len(trailing)
            assert "HIDDEN_DATA" in result["preview"]
        finally:
            os.unlink(path)

    def test_jpeg_without_trailing_data(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".jpg") as f:
            f.write(b"\xff\xd8\xff\xe0" + b"\x00" * 50 + b"\xff\xd9")
            path = f.name
        try:
            result = _check_trailing_data(path, "image/jpeg")
            assert result["found"] is False
        finally:
            os.unlink(path)

    def test_zip_with_trailing_data(self):
        # Simulate ZIP EOCD record followed by trailing data
        eocd = b"\x50\x4b\x05\x06" + b"\x00" * 18  # minimum EOCD = 22 bytes total
        trailing = b"EXTRA"
        with tempfile.NamedTemporaryFile(delete=False, suffix=".zip") as f:
            f.write(b"\x50\x4b\x03\x04" + b"\x00" * 50 + eocd + trailing)
            path = f.name
        try:
            result = _check_trailing_data(path, "application/zip")
            assert result["found"] is True
            assert result["size"] == len(trailing)
        finally:
            os.unlink(path)

    def test_nonexistent_file_returns_not_found(self):
        # Should handle gracefully (exception caught internally)
        result = _check_trailing_data("/tmp/nonexistent_file_xyz.bin", "image/png")
        assert result["found"] is False


# ── file_triage tool tests ───────────────────────────────────────────────────


class TestFileTriage:
    def test_nonexistent_file(self):
        result = json.loads(file_triage("/nonexistent/file/xyz"))
        assert "error" in result

    def test_text_file(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt", mode="w") as f:
            f.write("Hello world, testing file triage\n")
            path = f.name
        try:
            result = json.loads(file_triage(path))
            assert result["path"] == os.path.realpath(path)
            assert "file_type" in result
            assert "size" in result
            assert result["size"] > 0
        finally:
            os.unlink(path)

    def test_binary_file_with_strings(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"\x00" * 50 + b"flag{hidden_data}" + b"\x00" * 50)
            path = f.name
        try:
            result = json.loads(file_triage(path))
            assert "file_type" in result
            assert "entropy" in result
            assert result["entropy"] >= 0
        finally:
            os.unlink(path)

    def test_returns_valid_json(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".dat") as f:
            f.write(os.urandom(100))
            path = f.name
        try:
            raw = file_triage(path)
            parsed = json.loads(raw)
            assert isinstance(parsed, dict)
        finally:
            os.unlink(path)

    def test_entropy_present(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(os.urandom(1000))
            path = f.name
        try:
            result = json.loads(file_triage(path))
            assert "entropy" in result
            assert result["entropy"] > 7.0  # random data should be high entropy
        finally:
            os.unlink(path)

    def test_trailing_data_field(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"plain data")
            path = f.name
        try:
            result = json.loads(file_triage(path))
            assert "trailing_data" in result
        finally:
            os.unlink(path)


# ── stego_analyze tool tests ─────────────────────────────────────────────────


class TestStegoAnalyze:
    def test_nonexistent_file(self):
        result = json.loads(stego_analyze("/nonexistent/file/xyz"))
        assert "error" in result

    def test_returns_findings_list(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"not a real image")
            path = f.name
        try:
            result = json.loads(stego_analyze(path))
            assert "findings" in result
            assert isinstance(result["findings"], list)
        finally:
            os.unlink(path)

    def test_returns_mime_type(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"test data")
            path = f.name
        try:
            result = json.loads(stego_analyze(path))
            assert "mime_type" in result
        finally:
            os.unlink(path)


# ── extract_embedded tool tests ──────────────────────────────────────────────


class TestExtractEmbedded:
    def test_nonexistent_file(self):
        result = json.loads(extract_embedded("/nonexistent/file/xyz"))
        assert "error" in result

    def test_plain_file_no_extraction(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
            f.write(b"just plain text, nothing embedded")
            path = f.name
        try:
            result = json.loads(extract_embedded(path))
            assert "source" in result
            assert "extracted_count" in result
        finally:
            os.unlink(path)

    def test_returns_valid_json(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"\x00" * 100)
            path = f.name
        try:
            raw = extract_embedded(path)
            parsed = json.loads(raw)
            assert isinstance(parsed, dict)
        finally:
            os.unlink(path)


# ── entropy_analysis tool tests ──────────────────────────────────────────────


class TestEntropyAnalysis:
    def test_nonexistent_file(self):
        result = json.loads(entropy_analysis("/nonexistent/file/xyz"))
        assert "error" in result

    def test_uniform_random_data(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(os.urandom(10000))
            path = f.name
        try:
            result = json.loads(entropy_analysis(path))
            assert result["overall_entropy"] > 7.0
            assert result["size"] == 10000
            assert result["total_blocks"] > 0
        finally:
            os.unlink(path)

    def test_low_entropy_data(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"\x00" * 10000)
            path = f.name
        try:
            result = json.loads(entropy_analysis(path))
            assert result["overall_entropy"] == 0.0
            assert result["low_entropy_blocks"] > 0
        finally:
            os.unlink(path)

    def test_custom_block_size(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(os.urandom(1000))
            path = f.name
        try:
            result = json.loads(entropy_analysis(path, block_size=100))
            assert result["block_size"] == 100
            assert result["total_blocks"] == 10
        finally:
            os.unlink(path)

    def test_anomaly_detection(self):
        # Create file with sudden entropy change
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"\x00" * 4096)  # low entropy block
            f.write(os.urandom(4096))  # high entropy block
            path = f.name
        try:
            result = json.loads(entropy_analysis(path, block_size=4096))
            assert len(result["anomalies"]) > 0
            assert result["anomalies"][0]["entropy_change"] > 2.0
        finally:
            os.unlink(path)

    def test_returns_valid_json(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"abc" * 100)
            path = f.name
        try:
            raw = entropy_analysis(path)
            parsed = json.loads(raw)
            assert "overall_entropy" in parsed
            assert "blocks" in parsed
            assert "interpretation" in parsed
        finally:
            os.unlink(path)

    def test_interpretation_field(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(os.urandom(5000))
            path = f.name
        try:
            result = json.loads(entropy_analysis(path))
            assert isinstance(result["interpretation"], str)
            assert len(result["interpretation"]) > 0
        finally:
            os.unlink(path)


# ── image_analysis tool tests ────────────────────────────────────────────────


class TestImageAnalysis:
    def test_nonexistent_file(self):
        result = json.loads(image_analysis("/nonexistent/file/xyz"))
        assert "error" in result

    def test_non_image_file(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
            f.write(b"not an image")
            path = f.name
        try:
            result = json.loads(image_analysis(path))
            assert "error" in result
        finally:
            os.unlink(path)

    def test_valid_png(self):
        """Create a minimal valid PNG and analyze it."""
        try:
            from PIL import Image
        except ImportError:
            pytest.skip("PIL not available")

        with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as f:
            path = f.name

        img = Image.new("RGB", (10, 10), color=(255, 0, 0))
        img.save(path)
        try:
            result = json.loads(image_analysis(path))
            assert result["format"] == "PNG"
            assert result["mode"] == "RGB"
            assert result["size"]["width"] == 10
            assert result["size"]["height"] == 10
            assert "channels" in result
            assert "red" in result["channels"]
            assert "lsb_analysis" in result
        finally:
            os.unlink(path)

    def test_lsb_extraction(self):
        """Test LSB extraction on a simple image."""
        try:
            from PIL import Image
        except ImportError:
            pytest.skip("PIL not available")

        with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as f:
            path = f.name

        img = Image.new("RGB", (10, 10), color=(128, 64, 32))
        img.save(path)
        try:
            result = json.loads(image_analysis(path, extract_lsb=True))
            assert "lsb_extracted" in result
            assert "hex" in result["lsb_extracted"]
            assert "ascii" in result["lsb_extracted"]
            assert result["lsb_extracted"]["total_bytes"] > 0
        finally:
            os.unlink(path)

    def test_channel_statistics(self):
        """Verify channel stats are computed correctly for a solid color."""
        try:
            from PIL import Image
        except ImportError:
            pytest.skip("PIL not available")

        with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as f:
            path = f.name

        # Solid green image
        img = Image.new("RGB", (5, 5), color=(0, 200, 0))
        img.save(path)
        try:
            result = json.loads(image_analysis(path))
            channels = result["channels"]
            assert channels["red"]["min"] == 0
            assert channels["red"]["max"] == 0
            assert channels["green"]["min"] == 200
            assert channels["green"]["max"] == 200
            assert channels["blue"]["min"] == 0
            assert channels["blue"]["max"] == 0
        finally:
            os.unlink(path)

    def test_rgba_image(self):
        """Test RGBA image handling."""
        try:
            from PIL import Image
        except ImportError:
            pytest.skip("PIL not available")

        with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as f:
            path = f.name

        img = Image.new("RGBA", (5, 5), color=(255, 128, 64, 200))
        img.save(path)
        try:
            result = json.loads(image_analysis(path))
            assert result["mode"] == "RGBA"
            assert "channels" in result
        finally:
            os.unlink(path)

    def test_palette_image(self):
        """Test palette (P mode) image."""
        try:
            from PIL import Image
        except ImportError:
            pytest.skip("PIL not available")

        with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as f:
            path = f.name

        img = Image.new("P", (5, 5))
        img.save(path)
        try:
            result = json.loads(image_analysis(path))
            assert "palette_entries" in result or result["mode"] == "P"
        finally:
            os.unlink(path)


# ── JSON output validation ───────────────────────────────────────────────────


class TestJsonOutput:
    """Every tool must return valid JSON."""

    def test_file_triage_json(self):
        raw = file_triage("/dev/null")
        json.loads(raw)

    def test_stego_analyze_json(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"data")
            path = f.name
        try:
            raw = stego_analyze(path)
            json.loads(raw)
        finally:
            os.unlink(path)

    def test_entropy_analysis_json(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"data" * 100)
            path = f.name
        try:
            raw = entropy_analysis(path)
            json.loads(raw)
        finally:
            os.unlink(path)


# ── forensics_volatility tests ──────────────────────────────────────────────

volatility = ctf_forensics.forensics_volatility.fn


class TestVolatility:
    def test_nonexistent_file(self):
        result = json.loads(volatility("/nonexistent/memdump.raw"))
        assert "error" in result

    def test_json_renderer_parsing(self):
        from unittest.mock import patch

        vol_json = json.dumps(
            [
                {"PID": 4, "ImageFileName": "System", "Offset": "0x12345"},
                {"PID": 100, "ImageFileName": "svchost.exe", "Offset": "0x67890"},
            ]
        )
        # First call (JSON renderer) succeeds
        mock_result = {"stdout": vol_json, "stderr": "", "returncode": 0}
        with tempfile.NamedTemporaryFile(delete=False, suffix=".raw") as f:
            f.write(b"\x00" * 100)
            path = f.name
        try:
            with patch("ctf_forensics.run_tool", return_value=mock_result):
                result = json.loads(volatility(path, plugin="windows.pslist"))
                assert result["renderer"] == "json"
                assert len(result["data"]) == 2
                assert result["data"][0]["PID"] == 4
        finally:
            os.unlink(path)

    def test_text_renderer_fallback(self):
        from unittest.mock import patch

        # First call (JSON) fails, second (text) succeeds
        json_fail = {"stdout": "not json", "stderr": "", "returncode": 0}
        text_output = (
            "PID\tName\tOffset\n4\tSystem\t0x12345\n100\tsvchost.exe\t0x67890\n"
        )
        text_result = {"stdout": text_output, "stderr": "", "returncode": 0}
        call_count = [0]

        def mock_run_tool(cmd, timeout=None):
            call_count[0] += 1
            if "-r" in cmd and "json" in cmd:
                return json_fail
            return text_result

        with tempfile.NamedTemporaryFile(delete=False, suffix=".raw") as f:
            f.write(b"\x00" * 100)
            path = f.name
        try:
            with patch("ctf_forensics.run_tool", side_effect=mock_run_tool):
                result = json.loads(volatility(path, plugin="windows.pslist"))
                assert result["renderer"] == "text"
                assert result["row_count"] == 2
                assert "PID" in result["headers"]
        finally:
            os.unlink(path)

    def test_plugin_and_args_in_command(self):
        from unittest.mock import patch

        mock_result = {"stdout": "{}", "stderr": "", "returncode": 0}
        with tempfile.NamedTemporaryFile(delete=False, suffix=".raw") as f:
            f.write(b"\x00" * 100)
            path = f.name
        try:
            with patch("ctf_forensics.run_tool", return_value=mock_result) as mock_run:
                volatility(path, plugin="windows.filescan", extra_args="--pid 1234")
                # Check that at least one call included the plugin name
                found = False
                for call_args in mock_run.call_args_list:
                    cmd = call_args[0][0]
                    if "windows.filescan" in cmd:
                        found = True
                        assert "--pid" in cmd
                        assert "1234" in cmd
                assert found
        finally:
            os.unlink(path)

    def test_vol_failure(self):
        from unittest.mock import patch

        fail_result = {
            "stdout": "",
            "stderr": "Error: not a valid memory image",
            "returncode": 1,
        }
        with tempfile.NamedTemporaryFile(delete=False, suffix=".raw") as f:
            f.write(b"\x00" * 100)
            path = f.name
        try:
            with patch("ctf_forensics.run_tool", return_value=fail_result):
                result = json.loads(volatility(path))
                assert "error" in result
        finally:
            os.unlink(path)

    def test_returns_valid_json(self):
        from unittest.mock import patch

        mock_result = {"stdout": "[]", "stderr": "", "returncode": 0}
        with tempfile.NamedTemporaryFile(delete=False, suffix=".raw") as f:
            f.write(b"\x00" * 100)
            path = f.name
        try:
            with patch("ctf_forensics.run_tool", return_value=mock_result):
                json.loads(volatility(path))
        finally:
            os.unlink(path)


# ── TestStegoMocked — mock stego helper functions ───────────────────────────


class TestStegoMocked:
    def test_stego_png_zsteg_findings(self):
        """Mock zsteg finding data in a PNG."""
        from unittest.mock import patch

        def mock_run(cmd, timeout=None, input_data=None, cwd=None):
            if cmd[0] == "file":
                return {"stdout": "image/png", "stderr": "", "returncode": 0}
            if cmd[0] == "zsteg":
                return {
                    "stdout": "b1,rgb,lsb,xy .. flag{hidden_in_lsb}\nb2,rgb,msb,xy .. ~.~.~noise~.~",
                    "stderr": "",
                    "returncode": 0,
                }
            return {"stdout": "", "stderr": "", "returncode": 1}

        with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as f:
            f.write(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)
            path = f.name
        try:
            with patch("ctf_forensics.run_tool", side_effect=mock_run):
                # Need to also mock safe_read_file for trailing data check
                with patch(
                    "ctf_forensics.safe_read_file",
                    return_value=b"\x89PNG" + b"\x00" * 100,
                ):
                    result = json.loads(stego_analyze(path))
                    assert len(result["findings"]) >= 1
                    # The flag finding should have high confidence
                    flag_finding = [
                        f
                        for f in result["findings"]
                        if "flag" in f.get("data", "").lower()
                    ]
                    assert len(flag_finding) > 0
                    assert flag_finding[0]["confidence"] == 0.9
        finally:
            os.unlink(path)

    def test_stego_jpeg_exif_comment(self):
        """Mock JPEG EXIF comment extraction."""
        from unittest.mock import patch

        def mock_run(cmd, timeout=None, input_data=None, cwd=None):
            if cmd[0] == "file":
                return {"stdout": "image/jpeg", "stderr": "", "returncode": 0}
            if cmd[0] == "exiftool":
                return {"stdout": "Secret message here", "stderr": "", "returncode": 0}
            if cmd[0] == "steghide":
                return {"stdout": "", "stderr": "could not extract", "returncode": 1}
            return {"stdout": "", "stderr": "", "returncode": 1}

        with tempfile.NamedTemporaryFile(delete=False, suffix=".jpg") as f:
            f.write(b"\xff\xd8\xff\xe0" + b"\x00" * 50 + b"\xff\xd9")
            path = f.name
        try:
            with patch("ctf_forensics.run_tool", side_effect=mock_run):
                with patch(
                    "ctf_forensics.safe_read_file",
                    return_value=b"\xff\xd8\xff\xe0" + b"\x00" * 50 + b"\xff\xd9",
                ):
                    result = json.loads(stego_analyze(path))
                    exif_findings = [
                        f
                        for f in result["findings"]
                        if f.get("method") == "EXIF_comment"
                    ]
                    assert len(exif_findings) > 0
                    assert "Secret message" in exif_findings[0]["data"]
        finally:
            os.unlink(path)

    def test_stego_audio_strings(self):
        """Mock audio stego analysis."""
        from unittest.mock import patch

        def mock_run(cmd, timeout=None, input_data=None, cwd=None):
            if cmd[0] == "file":
                return {"stdout": "audio/wav", "stderr": "", "returncode": 0}
            if cmd[0] == "strings":
                return {
                    "stdout": "flag{audio_hidden}\nsome other text\n",
                    "stderr": "",
                    "returncode": 0,
                }
            if cmd[0] == "steghide":
                return {"stdout": "", "stderr": "not supported", "returncode": 1}
            return {"stdout": "", "stderr": "", "returncode": 1}

        with tempfile.NamedTemporaryFile(delete=False, suffix=".wav") as f:
            f.write(b"RIFF" + b"\x00" * 100)
            path = f.name
        try:
            with patch("ctf_forensics.run_tool", side_effect=mock_run):
                result = json.loads(stego_analyze(path))
                string_findings = [
                    f for f in result["findings"] if "flag" in f.get("data", "").lower()
                ]
                assert len(string_findings) > 0
        finally:
            os.unlink(path)

    def test_stego_gif_comment(self):
        """Mock GIF comment extraction."""
        from unittest.mock import patch

        def mock_run(cmd, timeout=None, input_data=None, cwd=None):
            if cmd[0] == "file":
                return {"stdout": "image/gif", "stderr": "", "returncode": 0}
            if cmd[0] == "exiftool":
                if "-FrameCount" in cmd:
                    return {"stdout": "3", "stderr": "", "returncode": 0}
                if "-Comment" in cmd:
                    return {
                        "stdout": "Hidden comment data",
                        "stderr": "",
                        "returncode": 0,
                    }
            return {"stdout": "", "stderr": "", "returncode": 1}

        with tempfile.NamedTemporaryFile(delete=False, suffix=".gif") as f:
            f.write(b"GIF89a" + b"\x00" * 100)
            path = f.name
        try:
            with patch("ctf_forensics.run_tool", side_effect=mock_run):
                result = json.loads(stego_analyze(path))
                comment_findings = [
                    f for f in result["findings"] if f.get("method") == "GIF_comment"
                ]
                assert len(comment_findings) > 0
                frame_findings = [
                    f
                    for f in result["findings"]
                    if "multi_frame" in f.get("method", "")
                ]
                assert len(frame_findings) > 0
        finally:
            os.unlink(path)

    def test_triage_exiftool_metadata(self):
        """Mock exiftool returning interesting metadata."""
        from unittest.mock import patch

        def mock_run(cmd, timeout=None, input_data=None, cwd=None):
            if cmd[0] == "file":
                if "--mime-type" in cmd:
                    return {"stdout": "image/png", "stderr": "", "returncode": 0}
                return {"stdout": "PNG image data", "stderr": "", "returncode": 0}
            if cmd[0] == "exiftool":
                return {
                    "stdout": json.dumps(
                        [
                            {
                                "Comment": "flag{metadata}",
                                "ImageWidth": 100,
                                "SomeField": "normal",
                            }
                        ]
                    ),
                    "stderr": "",
                    "returncode": 0,
                }
            if cmd[0] == "binwalk":
                return {"stdout": "", "stderr": "", "returncode": 0}
            if cmd[0] == "strings":
                return {"stdout": "", "stderr": "", "returncode": 0}
            return {"stdout": "", "stderr": "", "returncode": 0}

        with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as f:
            f.write(b"\x89PNG" + b"\x00" * 100)
            path = f.name
        try:
            with patch("ctf_forensics.run_tool", side_effect=mock_run):
                with patch(
                    "ctf_forensics.safe_read_file",
                    return_value=b"\x89PNG" + b"\x00" * 100,
                ):
                    result = json.loads(file_triage(path))
                    assert "Comment" in result.get("metadata", {})
                    assert result["metadata"]["Comment"] == "flag{metadata}"
        finally:
            os.unlink(path)

    def test_volatility_space_separated_text(self):
        """Test volatility text parsing with space-separated output."""
        from unittest.mock import patch

        json_fail = {"stdout": "", "stderr": "", "returncode": 1}
        text_output = "PID Name Offset\n4 System 0x12345\n100 svchost 0x67890\n"
        text_result = {"stdout": text_output, "stderr": "", "returncode": 0}

        def mock_run(cmd, timeout=None, input_data=None, cwd=None):
            if "-r" in cmd:
                return json_fail
            return text_result

        with tempfile.NamedTemporaryFile(delete=False, suffix=".raw") as f:
            f.write(b"\x00" * 100)
            path = f.name
        try:
            with patch("ctf_forensics.run_tool", side_effect=mock_run):
                result = json.loads(volatility(path))
                assert result["renderer"] == "text"
                assert result["row_count"] == 2
        finally:
            os.unlink(path)
