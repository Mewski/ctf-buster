"""Tests for ctf_crypto.py — pure-Python functions only (no external CLI tools)."""

import hashlib
import json
import os
import sys

import pytest

# Allow imports from the tools directory
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import ctf_crypto

# _apply_op is a plain function (not decorated with @mcp.tool)
_apply_op = ctf_crypto._apply_op

# Decorated @mcp.tool functions become FunctionTool objects;
# access the underlying function via .fn
transform_chain = ctf_crypto.crypto_transform_chain.fn
crypto_identify = ctf_crypto.crypto_identify.fn
frequency_analysis = ctf_crypto.crypto_frequency_analysis.fn
hash_crack = ctf_crypto.crypto_hash_crack.fn

# ── _apply_op tests ──────────────────────────────────────────────────────────


class TestApplyOpBase64:
    def test_base64_encode(self):
        assert _apply_op("Hello", "base64_encode") == "SGVsbG8="

    def test_base64_decode(self):
        assert _apply_op("SGVsbG8=", "base64_decode") == "Hello"

    def test_base64_roundtrip(self):
        original = "CTF{flag_value_123}"
        encoded = _apply_op(original, "base64_encode")
        decoded = _apply_op(encoded, "base64_decode")
        assert decoded == original

    def test_base64_decode_no_padding(self):
        # "Hello" base64 is "SGVsbG8=" — test without the padding
        assert _apply_op("SGVsbG8", "base64_decode") == "Hello"

    def test_base64_encode_empty(self):
        assert _apply_op("", "base64_encode") == ""

    def test_base64_decode_empty(self):
        assert _apply_op("", "base64_decode") == ""


class TestApplyOpHex:
    def test_hex_encode(self):
        assert _apply_op("Hi", "hex_encode") == "4869"

    def test_hex_decode(self):
        assert _apply_op("4869", "hex_decode") == "Hi"

    def test_hex_roundtrip(self):
        original = "flag{hex_test}"
        encoded = _apply_op(original, "hex_encode")
        decoded = _apply_op(encoded, "hex_decode")
        assert decoded == original

    def test_hex_decode_with_spaces(self):
        assert _apply_op("48 69", "hex_decode") == "Hi"

    def test_hex_decode_with_0x_prefix(self):
        assert _apply_op("0x48 0x69", "hex_decode") == "Hi"

    def test_hex_decode_with_backslash_x(self):
        assert _apply_op("\\x48\\x69", "hex_decode") == "Hi"


class TestApplyOpUrl:
    def test_url_encode(self):
        result = _apply_op("hello world", "url_encode")
        assert result == "hello%20world"

    def test_url_decode(self):
        assert _apply_op("hello%20world", "url_decode") == "hello world"

    def test_url_encode_special_chars(self):
        result = _apply_op("a=1&b=2", "url_encode")
        assert "%26" in result or "&" not in result.replace("%26", "")

    def test_url_roundtrip(self):
        original = "key=value&foo=bar baz"
        encoded = _apply_op(original, "url_encode")
        decoded = _apply_op(encoded, "url_decode")
        assert decoded == original


class TestApplyOpRot13:
    def test_rot13_basic(self):
        assert _apply_op("Hello", "rot13") == "Uryyb"

    def test_rot13_double_is_identity(self):
        original = "The quick brown fox"
        double_rot = _apply_op(_apply_op(original, "rot13"), "rot13")
        assert double_rot == original

    def test_rot13_non_alpha_unchanged(self):
        assert _apply_op("123!@#", "rot13") == "123!@#"


class TestApplyOpRotN:
    def test_rot1(self):
        assert _apply_op("abc", "rot(1)") == "bcd"

    def test_rot25(self):
        # rot(25) on 'b' -> 'a'
        assert _apply_op("b", "rot(25)") == "a"

    def test_rot0_identity(self):
        assert _apply_op("Hello", "rot(0)") == "Hello"

    def test_rot13_via_param(self):
        assert _apply_op("Hello", "rot(13)") == "Uryyb"

    def test_rot_preserves_case(self):
        result = _apply_op("AbCd", "rot(1)")
        assert result == "BcDe"

    def test_rot_non_alpha_unchanged(self):
        assert _apply_op("a1b2", "rot(5)") == "f1g2"


class TestApplyOpXor:
    def test_xor_single_key(self):
        # XOR with single byte key is invertible
        encrypted = _apply_op("A", "xor(A)")
        # ord('A') ^ ord('A') == 0
        assert encrypted == "\x00"

    def test_xor_roundtrip(self):
        original = "secret"
        key = "K"
        encrypted = _apply_op(original, f"xor({key})")
        decrypted = _apply_op(encrypted, f"xor({key})")
        assert decrypted == original

    def test_xor_multi_byte_key(self):
        original = "ABCD"
        key = "xy"
        encrypted = _apply_op(original, f"xor({key})")
        decrypted = _apply_op(encrypted, f"xor({key})")
        assert decrypted == original


class TestApplyOpVigenere:
    def test_vigenere_encode(self):
        # "HELLO" with key "KEY":
        # H+K=R, E+E=I, L+Y=J, L+K=V, O+E=S
        result = _apply_op("HELLO", "vigenere_encode(KEY)")
        assert result == "RIJVS"

    def test_vigenere_decode(self):
        result = _apply_op("RIJVS", "vigenere_decode(KEY)")
        assert result == "HELLO"

    def test_vigenere_roundtrip(self):
        original = "AttackAtDawn"
        key = "LEMON"
        encoded = _apply_op(original, f"vigenere_encode({key})")
        decoded = _apply_op(encoded, f"vigenere_decode({key})")
        assert decoded == original

    def test_vigenere_preserves_non_alpha(self):
        result = _apply_op("HI 123", "vigenere_encode(KEY)")
        # Non-alpha characters should be preserved
        assert result[2] == " "
        assert "123" in result

    def test_vigenere_preserves_case(self):
        result = _apply_op("Hello", "vigenere_encode(KEY)")
        assert result[0].isupper()
        assert result[1].islower()


class TestApplyOpReverse:
    def test_reverse(self):
        assert _apply_op("abcdef", "reverse") == "fedcba"

    def test_reverse_empty(self):
        assert _apply_op("", "reverse") == ""

    def test_reverse_palindrome(self):
        assert _apply_op("racecar", "reverse") == "racecar"


class TestApplyOpCase:
    def test_upper(self):
        assert _apply_op("hello", "upper") == "HELLO"

    def test_lower(self):
        assert _apply_op("HELLO", "lower") == "hello"

    def test_strip(self):
        assert _apply_op("  hello  ", "strip") == "hello"


class TestApplyOpBinary:
    def test_binary_encode(self):
        result = _apply_op("A", "binary_encode")
        assert result == "01000001"

    def test_binary_decode(self):
        assert _apply_op("01000001", "binary_decode") == "A"

    def test_binary_encode_multi_char(self):
        result = _apply_op("Hi", "binary_encode")
        assert result == "01001000 01101001"

    def test_binary_roundtrip(self):
        original = "flag"
        encoded = _apply_op(original, "binary_encode")
        decoded = _apply_op(encoded, "binary_decode")
        assert decoded == original


class TestApplyOpAsciiDecimal:
    def test_ascii_to_decimal(self):
        result = _apply_op("Hi", "ascii_to_decimal")
        assert result == "72 105"

    def test_decimal_to_ascii(self):
        assert _apply_op("72 105", "decimal_to_ascii") == "Hi"

    def test_ascii_decimal_roundtrip(self):
        original = "CTF"
        decimal_form = _apply_op(original, "ascii_to_decimal")
        back = _apply_op(decimal_form, "decimal_to_ascii")
        assert back == original


class TestApplyOpAtbash:
    def test_atbash_basic(self):
        # a->z, b->y, c->x, ...
        assert _apply_op("abc", "atbash") == "zyx"

    def test_atbash_uppercase(self):
        assert _apply_op("ABC", "atbash") == "ZYX"

    def test_atbash_double_is_identity(self):
        original = "Hello World"
        double = _apply_op(_apply_op(original, "atbash"), "atbash")
        assert double == original

    def test_atbash_non_alpha_unchanged(self):
        assert _apply_op("a1b2", "atbash") == "z1y2"


class TestApplyOpUnknown:
    def test_unknown_op_raises(self):
        with pytest.raises(ValueError, match="Unknown operation"):
            _apply_op("data", "nonexistent_op")


# ── transform_chain tests ────────────────────────────────────────────────────


class TestTransformChain:
    def test_single_operation(self):
        result = json.loads(transform_chain("Hello", ["base64_encode"]))
        assert result["final"] == "SGVsbG8="
        assert len(result["steps"]) == 1
        assert result["steps"][0]["op"] == "base64_encode"

    def test_multi_step_pipeline(self):
        result = json.loads(transform_chain("Hello", ["base64_encode", "hex_encode"]))
        assert len(result["steps"]) == 2
        # First step: base64 encode "Hello" -> "SGVsbG8="
        assert result["steps"][0]["result"] == "SGVsbG8="
        # Second step: hex encode that result
        assert result["steps"][1]["result"] == _apply_op("SGVsbG8=", "hex_encode")
        assert result["final"] == result["steps"][-1]["result"]

    def test_empty_operations_list(self):
        result = json.loads(transform_chain("Hello", []))
        assert result["final"] == "Hello"
        assert result["steps"] == []

    def test_error_in_chain_stops_execution(self):
        result = json.loads(
            transform_chain("Hello", ["base64_encode", "bad_op", "reverse"])
        )
        # Should stop at the bad op
        assert len(result["steps"]) == 2
        assert "error" in result["steps"][1]
        # Only 2 steps (successful base64_encode + failed bad_op), not 3

    def test_decode_encode_roundtrip(self):
        original = "SGVsbG8="
        result = json.loads(
            transform_chain(original, ["base64_decode", "base64_encode"])
        )
        assert result["final"] == original

    def test_complex_chain(self):
        result = json.loads(
            transform_chain("hello", ["upper", "reverse", "base64_encode"])
        )
        assert result["steps"][0]["result"] == "HELLO"
        assert result["steps"][1]["result"] == "OLLEH"
        # Final is base64 of "OLLEH"
        import base64

        assert result["final"] == base64.b64encode(b"OLLEH").decode()

    def test_returns_valid_json(self):
        raw = transform_chain("test", ["rot13"])
        parsed = json.loads(raw)
        assert "steps" in parsed
        assert "final" in parsed


# ── crypto_identify tests ────────────────────────────────────────────────────


class TestCryptoIdentify:
    def test_identify_base64(self):
        # "Hello World" base64 encoded
        import base64

        b64 = base64.b64encode(b"Hello World").decode()
        result = json.loads(crypto_identify(b64))
        types = [r["type"] for r in result]
        assert any("Base64" in t for t in types)

    def test_identify_hex_string(self):
        result = json.loads(crypto_identify("48656c6c6f"))
        types = [r["type"] for r in result]
        assert any("Hex" in t for t in types)

    def test_identify_md5_hash(self):
        md5 = hashlib.md5(b"password").hexdigest()
        result = json.loads(crypto_identify(md5))
        types = [r["type"] for r in result]
        assert any("MD5" in t for t in types)

    def test_identify_sha1_hash(self):
        sha1 = hashlib.sha1(b"test").hexdigest()
        result = json.loads(crypto_identify(sha1))
        types = [r["type"] for r in result]
        assert any("SHA-1" in t for t in types)

    def test_identify_sha256_hash(self):
        sha256 = hashlib.sha256(b"test").hexdigest()
        result = json.loads(crypto_identify(sha256))
        types = [r["type"] for r in result]
        assert any("SHA-256" in t for t in types)

    def test_identify_jwt(self):
        # Minimal JWT structure: header.payload.signature
        import base64

        header = (
            base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}')
            .decode()
            .rstrip("=")
        )
        payload = (
            base64.urlsafe_b64encode(b'{"sub":"1234567890","name":"John"}')
            .decode()
            .rstrip("=")
        )
        sig = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        jwt_token = f"{header}.{payload}.{sig}"
        result = json.loads(crypto_identify(jwt_token))
        types = [r["type"] for r in result]
        assert any("JWT" in t for t in types)

    def test_identify_url_encoded(self):
        result = json.loads(crypto_identify("hello%20world%21"))
        types = [r["type"] for r in result]
        assert any("URL" in t for t in types)

    def test_identify_binary(self):
        # Binary string (space-separated 8-bit groups)
        binary_str = "01001000 01101001"
        result = json.loads(crypto_identify(binary_str))
        types = [r["type"] for r in result]
        assert any("Binary" in t for t in types)

    def test_identify_decimal_ascii(self):
        result = json.loads(crypto_identify("72 101 108 108 111"))
        types = [r["type"] for r in result]
        assert any("Decimal ASCII" in t for t in types)

    def test_identify_unknown(self):
        result = json.loads(crypto_identify("!!!???"))
        types = [r["type"] for r in result]
        assert any("Unknown" in t for t in types)

    def test_results_sorted_by_confidence(self):
        # An MD5 hash is also valid hex, so multiple results expected
        md5 = hashlib.md5(b"x").hexdigest()
        result = json.loads(crypto_identify(md5))
        confidences = [r["confidence"] for r in result]
        assert confidences == sorted(confidences, reverse=True)

    def test_returns_valid_json(self):
        raw = crypto_identify("test data")
        parsed = json.loads(raw)
        assert isinstance(parsed, list)
        assert all("type" in r and "confidence" in r for r in parsed)


# ── frequency_analysis tests ─────────────────────────────────────────────────


class TestFrequencyAnalysis:
    def test_single_char_repeated(self):
        result = json.loads(frequency_analysis("aaaa"))
        freqs = result["character_frequencies"]
        assert freqs["a"] == 100.0
        assert result["total_letters"] == 4

    def test_known_distribution(self):
        # "ab" repeated: 50% a, 50% b
        result = json.loads(frequency_analysis("ababab"))
        freqs = result["character_frequencies"]
        assert freqs["a"] == 50.0
        assert freqs["b"] == 50.0

    def test_english_text_likely_english(self):
        text = (
            "The quick brown fox jumps over the lazy dog. "
            "This is a fairly long sentence that should have "
            "a reasonable distribution of English letters for analysis."
        )
        result = json.loads(frequency_analysis(text))
        assert result["likely_english"] is True

    def test_non_alpha_ignored(self):
        result = json.loads(frequency_analysis("a1b2c3"))
        assert result["total_letters"] == 3
        freqs = result["character_frequencies"]
        assert len(freqs) == 3

    def test_empty_text_error(self):
        result = json.loads(frequency_analysis("12345"))
        assert "error" in result

    def test_bigrams_present(self):
        result = json.loads(frequency_analysis("aabbcc"))
        assert "top_bigrams" in result
        assert "aa" in result["top_bigrams"]

    def test_index_of_coincidence(self):
        # For a single repeated letter, IoC should be 1.0
        result = json.loads(frequency_analysis("aaaa"))
        assert result["index_of_coincidence"] == 1.0

    def test_chi_squared_present(self):
        result = json.loads(frequency_analysis("hello world"))
        assert "chi_squared_english" in result
        assert isinstance(result["chi_squared_english"], (int, float))

    def test_case_insensitive(self):
        result = json.loads(frequency_analysis("AaAa"))
        freqs = result["character_frequencies"]
        assert "a" in freqs
        assert freqs["a"] == 100.0

    def test_returns_valid_json(self):
        raw = frequency_analysis("some text here")
        parsed = json.loads(raw)
        assert "total_letters" in parsed
        assert "character_frequencies" in parsed


# ── hash_crack tests ─────────────────────────────────────────────────────────


class TestHashCrack:
    def test_identify_md5_length(self):
        md5 = hashlib.md5(b"anything").hexdigest()
        result = json.loads(hash_crack(md5))
        assert "MD5" in result["possible_types"]
        assert result["length"] == 32

    def test_identify_sha1_length(self):
        sha1 = hashlib.sha1(b"anything").hexdigest()
        result = json.loads(hash_crack(sha1))
        assert "SHA-1" in result["possible_types"]
        assert result["length"] == 40

    def test_identify_sha256_length(self):
        sha256 = hashlib.sha256(b"anything").hexdigest()
        result = json.loads(hash_crack(sha256))
        assert "SHA-256" in result["possible_types"]
        assert result["length"] == 64

    def test_identify_bcrypt(self):
        bcrypt_hash = "$2b$12$LJ3m4ys3Lg2VYmOgPlLQaO1cFwZmPJQE8c5pM3fM.DLMV4tykqFi"
        result = json.loads(hash_crack(bcrypt_hash))
        assert "bcrypt" in result["possible_types"]

    def test_identify_md5_crypt(self):
        result = json.loads(hash_crack("$1$salt$hash"))
        assert "MD5 crypt" in result["possible_types"]

    def test_identify_sha256_crypt(self):
        result = json.loads(hash_crack("$5$salt$hash"))
        assert "SHA-256 crypt" in result["possible_types"]

    def test_identify_sha512_crypt(self):
        result = json.loads(hash_crack("$6$salt$hash"))
        assert "SHA-512 crypt" in result["possible_types"]

    def test_crack_md5_from_default_wordlist(self):
        # "password" is in the default wordlist
        md5 = hashlib.md5(b"password").hexdigest()
        result = json.loads(hash_crack(md5))
        assert result["cracked"] is True
        assert result["plaintext"] == "password"
        assert result["hash_type"] == "md5"

    def test_crack_sha1_from_default_wordlist(self):
        sha1 = hashlib.sha1(b"admin").hexdigest()
        result = json.loads(hash_crack(sha1))
        assert result["cracked"] is True
        assert result["plaintext"] == "admin"

    def test_crack_sha256_from_default_wordlist(self):
        sha256 = hashlib.sha256(b"hello").hexdigest()
        result = json.loads(hash_crack(sha256))
        assert result["cracked"] is True
        assert result["plaintext"] == "hello"

    def test_crack_with_custom_wordlist(self):
        md5 = hashlib.md5(b"myspecialword").hexdigest()
        result = json.loads(hash_crack(md5, wordlist="myspecialword\nother"))
        assert result["cracked"] is True
        assert result["plaintext"] == "myspecialword"

    def test_crack_fails_unknown_hash(self):
        # A hash of something NOT in the default wordlist
        md5 = hashlib.md5(b"verylongandunusualpassword42").hexdigest()
        result = json.loads(hash_crack(md5))
        assert result["cracked"] is False

    def test_returns_valid_json(self):
        raw = hash_crack("d41d8cd98f00b204e9800998ecf8427e")
        parsed = json.loads(raw)
        assert "hash" in parsed
        assert "length" in parsed
        assert "possible_types" in parsed
