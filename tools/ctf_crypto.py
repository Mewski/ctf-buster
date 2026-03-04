#!/usr/bin/env python3
"""CTF Crypto & Encoding MCP Server — transform chains, RSA attacks, constraint solving."""

import base64
import codecs
import hashlib
import json
import os
import re
import string
import sys
import urllib.parse
from collections import Counter

sys.path.insert(0, os.path.dirname(__file__))
from fastmcp import FastMCP
from lib.subprocess_utils import run_tool

mcp = FastMCP(
    "ctf-crypto",
    instructions=(
        "Cryptographic analysis and encoding tools for CTF challenges. "
        "Use crypto_transform_chain for encoding/decoding pipelines, crypto_identify to detect "
        "encoding types, crypto_xor_analyze for XOR key recovery, crypto_rsa_toolkit for RSA attacks, "
        "crypto_math_solve for constraint solving, crypto_sage_solve for SageMath scripts "
        "(finite fields, lattice reduction, discrete log)."
    ),
)


# ── transform_chain ──────────────────────────────────────────────────────────


def _apply_op(data: str, op: str) -> str:
    """Apply a single transformation operation."""
    rot_match = re.match(r"rot\((\d+)\)", op)
    if rot_match:
        n = int(rot_match.group(1))
        table = str.maketrans(
            string.ascii_lowercase + string.ascii_uppercase,
            string.ascii_lowercase[n:]
            + string.ascii_lowercase[:n]
            + string.ascii_uppercase[n:]
            + string.ascii_uppercase[:n],
        )
        return data.translate(table)

    xor_match = re.match(r"xor\((.+)\)", op)
    if xor_match:
        key = xor_match.group(1).encode()
        data_bytes = data.encode("latin-1")
        result = bytes(b ^ key[i % len(key)] for i, b in enumerate(data_bytes))
        return result.decode("latin-1", errors="replace")

    vig_enc_match = re.match(r"vigenere_encode\((.+)\)", op)
    if vig_enc_match:
        key = vig_enc_match.group(1).upper()
        result = []
        ki = 0
        for ch in data:
            if ch.isalpha():
                base = ord("A") if ch.isupper() else ord("a")
                shift = ord(key[ki % len(key)]) - ord("A")
                result.append(chr((ord(ch) - base + shift) % 26 + base))
                ki += 1
            else:
                result.append(ch)
        return "".join(result)

    vig_dec_match = re.match(r"vigenere_decode\((.+)\)", op)
    if vig_dec_match:
        key = vig_dec_match.group(1).upper()
        result = []
        ki = 0
        for ch in data:
            if ch.isalpha():
                base = ord("A") if ch.isupper() else ord("a")
                shift = ord(key[ki % len(key)]) - ord("A")
                result.append(chr((ord(ch) - base - shift) % 26 + base))
                ki += 1
            else:
                result.append(ch)
        return "".join(result)

    if op == "base64_encode":
        return base64.b64encode(data.encode()).decode()
    elif op == "base64_decode":
        # Handle padding issues
        padded = data + "=" * (-len(data) % 4)
        return base64.b64decode(padded).decode("utf-8", errors="replace")
    elif op == "hex_encode":
        return data.encode().hex()
    elif op == "hex_decode":
        clean = data.replace(" ", "").replace("0x", "").replace("\\x", "")
        if len(clean) % 2 != 0:
            clean = "0" + clean
        return bytes.fromhex(clean).decode("utf-8", errors="replace")
    elif op == "url_encode":
        return urllib.parse.quote(data)
    elif op == "url_decode":
        return urllib.parse.unquote(data)
    elif op == "rot13":
        return codecs.decode(data, "rot_13")
    elif op == "reverse":
        return data[::-1]
    elif op == "upper":
        return data.upper()
    elif op == "lower":
        return data.lower()
    elif op == "binary_encode":
        return " ".join(format(b, "08b") for b in data.encode())
    elif op == "binary_decode":
        bits = data.replace(" ", "")
        return bytes(int(bits[i : i + 8], 2) for i in range(0, len(bits), 8)).decode(
            "utf-8", errors="replace"
        )
    elif op == "ascii_to_decimal":
        return " ".join(str(ord(c)) for c in data)
    elif op == "decimal_to_ascii":
        nums = re.findall(r"\d+", data)
        return "".join(chr(int(n)) for n in nums if int(n) <= 0x10FFFF)
    elif op == "atbash":
        table = str.maketrans(
            string.ascii_lowercase + string.ascii_uppercase,
            string.ascii_lowercase[::-1] + string.ascii_uppercase[::-1],
        )
        return data.translate(table)
    elif op == "strip":
        return data.strip()
    else:
        raise ValueError(f"Unknown operation: {op}")


@mcp.tool()
def crypto_transform_chain(data: str, operations: list[str]) -> str:
    """Apply a chain of encoding/decoding operations to data, returning intermediate results.

    Supported operations:
    - base64_encode, base64_decode, hex_encode, hex_decode
    - url_encode, url_decode, rot13, rot(N) where N is shift amount
    - xor(key), vigenere_encode(key), vigenere_decode(key)
    - reverse, upper, lower, strip, atbash
    - binary_encode, binary_decode, ascii_to_decimal, decimal_to_ascii

    Example: transform_chain("SGVsbG8=", ["base64_decode", "hex_encode"])
    """
    steps = []
    current = data
    for op in operations:
        try:
            current = _apply_op(current, op)
            steps.append({"op": op, "result": current})
        except Exception as e:
            steps.append({"op": op, "error": str(e)})
            break
    return json.dumps({"steps": steps, "final": current}, indent=2)


# ── crypto_identify ──────────────────────────────────────────────────────────

HASH_PATTERNS = {
    32: ["MD5", "NTLM"],
    40: ["SHA-1"],
    56: ["SHA-224"],
    64: ["SHA-256", "SHA3-256"],
    96: ["SHA-384", "SHA3-384"],
    128: ["SHA-512", "SHA3-512"],
}


@mcp.tool()
def crypto_identify(data: str) -> str:
    """Identify the encoding or cipher type of the given data.

    Analyzes the input and returns possible encodings/hash types with confidence scores.
    """
    results = []
    clean = data.strip()

    # Check Base64
    if (
        re.match(r"^[A-Za-z0-9+/]+=*$", clean)
        and len(clean) % 4 == 0
        and len(clean) > 4
    ):
        try:
            decoded = base64.b64decode(clean)
            if all(32 <= b < 127 or b in (9, 10, 13) for b in decoded):
                results.append(
                    {
                        "type": "Base64",
                        "confidence": 0.9,
                        "decoded_preview": decoded.decode()[:200],
                    }
                )
            else:
                results.append({"type": "Base64 (binary data)", "confidence": 0.7})
        except Exception:
            pass

    # Check hex
    if re.match(r"^[0-9a-fA-F]+$", clean) and len(clean) % 2 == 0:
        # Could be a hash
        if len(clean) in HASH_PATTERNS:
            for h in HASH_PATTERNS[len(clean)]:
                results.append({"type": f"Hash ({h})", "confidence": 0.8})
        if len(clean) >= 4:
            results.append({"type": "Hex-encoded data", "confidence": 0.6})

    # Check URL encoding
    if "%" in clean and re.search(r"%[0-9a-fA-F]{2}", clean):
        results.append(
            {
                "type": "URL-encoded",
                "confidence": 0.85,
                "decoded_preview": urllib.parse.unquote(clean)[:200],
            }
        )

    # Check JWT
    if re.match(r"^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$", clean):
        results.append({"type": "JWT token", "confidence": 0.95})
        try:
            header = json.loads(base64.b64decode(clean.split(".")[0] + "=="))
            results[-1]["header"] = header
        except Exception:
            pass

    # Check binary
    if re.match(r"^[01\s]+$", clean) and len(clean.replace(" ", "")) % 8 == 0:
        results.append({"type": "Binary-encoded", "confidence": 0.7})

    # Check decimal ASCII
    if re.match(r"^(\d{1,3}\s+)+\d{1,3}$", clean):
        nums = [int(n) for n in clean.split()]
        if all(32 <= n < 127 for n in nums):
            decoded = "".join(chr(n) for n in nums)
            results.append(
                {
                    "type": "Decimal ASCII",
                    "confidence": 0.8,
                    "decoded_preview": decoded[:200],
                }
            )

    # Check ROT13 / Caesar (if it looks like it could be English with shift)
    if clean.isascii() and any(c.isalpha() for c in clean):
        for shift in range(1, 26):
            shifted = _apply_op(clean, f"rot({shift})")
            # Simple English detection
            common_words = {
                "the",
                "and",
                "for",
                "are",
                "but",
                "not",
                "you",
                "all",
                "can",
                "had",
                "her",
                "was",
                "one",
                "our",
                "out",
                "flag",
            }
            words = set(shifted.lower().split())
            matches = words & common_words
            if len(matches) >= 2:
                results.append(
                    {
                        "type": f"Caesar/ROT-{shift}",
                        "confidence": 0.7,
                        "decoded_preview": shifted[:200],
                    }
                )
                break

    if not results:
        results.append(
            {
                "type": "Unknown",
                "confidence": 0.0,
                "note": "Could not identify encoding",
            }
        )

    results.sort(key=lambda x: x["confidence"], reverse=True)
    return json.dumps(results, indent=2)


# ── rsa_toolkit ──────────────────────────────────────────────────────────────


@mcp.tool()
def crypto_rsa_toolkit(
    n: str,
    e: int = 65537,
    c: str = "",
    attack: str = "auto",
    p: str = "",
    q: str = "",
    dp: str = "",
    dq: str = "",
) -> str:
    """Perform common RSA CTF attacks.

    Args:
        n: The modulus (decimal string)
        e: Public exponent (default 65537)
        c: Ciphertext to decrypt (decimal string, optional)
        attack: Attack to try — "auto", "factordb", "small_e", "wiener", "fermat", "given_pq"
        p: Known factor p (if available)
        q: Known factor q (if available)
        dp: CRT exponent dp (if available)
        dq: CRT exponent dq (if available)
    """
    import sympy

    n_int = int(n)
    c_int = int(c) if c else None
    results = {"n_bits": n_int.bit_length(), "e": e, "attacks_tried": []}

    # If p, q given directly
    if p and q:
        p_int, q_int = int(p), int(q)
        phi = (p_int - 1) * (q_int - 1)
        d = pow(e, -1, phi)
        results["p"] = str(p_int)
        results["q"] = str(q_int)
        results["d"] = str(d)
        if c_int:
            m = pow(c_int, d, n_int)
            try:
                plaintext = m.to_bytes((m.bit_length() + 7) // 8, "big").decode(
                    "utf-8", errors="replace"
                )
            except (ValueError, OverflowError):
                plaintext = str(m)
            results["plaintext"] = plaintext
            results["m"] = str(m)
        return json.dumps(results, indent=2)

    attacks = (
        [attack] if attack != "auto" else ["small_e", "fermat", "wiener", "factordb"]
    )

    for atk in attacks:
        results["attacks_tried"].append(atk)

        if atk == "small_e" and c_int:
            # If e is small, try taking eth root of c
            if e <= 17:
                m = sympy.integer_nthroot(c_int, e)
                if m[1]:  # exact root
                    results["attack_used"] = "small_e"
                    results["m"] = str(m[0])
                    try:
                        results["plaintext"] = (
                            m[0]
                            .to_bytes((m[0].bit_length() + 7) // 8, "big")
                            .decode("utf-8", errors="replace")
                        )
                    except (ValueError, OverflowError):
                        results["plaintext"] = str(m[0])
                    return json.dumps(results, indent=2)

        elif atk == "fermat":
            # Fermat factorization — works when p and q are close
            a = sympy.integer_nthroot(n_int, 2)[0] + 1
            for _ in range(10000):
                b2 = a * a - n_int
                b = sympy.integer_nthroot(b2, 2)
                if b[1]:
                    p_int = a + b[0]
                    q_int = a - b[0]
                    if p_int * q_int == n_int and p_int > 1 and q_int > 1:
                        results["attack_used"] = "fermat"
                        results["p"] = str(p_int)
                        results["q"] = str(q_int)
                        phi = (p_int - 1) * (q_int - 1)
                        d = pow(e, -1, phi)
                        results["d"] = str(d)
                        if c_int:
                            m = pow(c_int, d, n_int)
                            try:
                                results["plaintext"] = m.to_bytes(
                                    (m.bit_length() + 7) // 8, "big"
                                ).decode("utf-8", errors="replace")
                            except (ValueError, OverflowError):
                                results["plaintext"] = str(m)
                            results["m"] = str(m)
                        return json.dumps(results, indent=2)
                a += 1

        elif atk == "wiener":
            # Wiener's attack — works when d is small
            cf = []
            num, den = e, n_int
            while den:
                q_cf = num // den
                cf.append(q_cf)
                num, den = den, num - q_cf * den
            # Build convergents
            h_prev, k_prev = 0, 1
            h_curr, k_curr = 1, 0
            for q_cf in cf:
                h_prev, h_curr = h_curr, q_cf * h_curr + h_prev
                k_prev, k_curr = k_curr, q_cf * k_curr + k_prev
                if k_curr == 0:
                    continue
                d_candidate = k_curr
                if d_candidate <= 0:
                    continue
                phi_candidate = e * d_candidate - 1
                if phi_candidate <= 0:
                    continue
                # phi = n - p - q + 1, so p + q = n - phi + 1
                s = n_int - phi_candidate + 1
                # p and q are roots of x^2 - s*x + n = 0
                discriminant = s * s - 4 * n_int
                if discriminant < 0:
                    continue
                sqrt_d = sympy.integer_nthroot(discriminant, 2)
                if sqrt_d[1]:
                    p_int = (s + sqrt_d[0]) // 2
                    q_int = (s - sqrt_d[0]) // 2
                    if p_int * q_int == n_int:
                        results["attack_used"] = "wiener"
                        results["p"] = str(p_int)
                        results["q"] = str(q_int)
                        results["d"] = str(d_candidate)
                        if c_int:
                            m = pow(c_int, d_candidate, n_int)
                            try:
                                results["plaintext"] = m.to_bytes(
                                    (m.bit_length() + 7) // 8, "big"
                                ).decode("utf-8", errors="replace")
                            except (ValueError, OverflowError):
                                results["plaintext"] = str(m)
                            results["m"] = str(m)
                        return json.dumps(results, indent=2)

        elif atk == "factordb":
            try:
                import requests

                resp = requests.get(
                    f"http://factordb.com/api?query={n_int}", timeout=10
                )
                data = resp.json()
                if data.get("status") == "FF" and len(data.get("factors", [])) >= 2:
                    factors = [int(f[0]) for f in data["factors"]]
                    if len(factors) == 2:
                        p_int, q_int = factors
                        results["attack_used"] = "factordb"
                        results["p"] = str(p_int)
                        results["q"] = str(q_int)
                        phi = (p_int - 1) * (q_int - 1)
                        d = pow(e, -1, phi)
                        results["d"] = str(d)
                        if c_int:
                            m = pow(c_int, d, n_int)
                            try:
                                results["plaintext"] = m.to_bytes(
                                    (m.bit_length() + 7) // 8, "big"
                                ).decode("utf-8", errors="replace")
                            except (ValueError, OverflowError):
                                results["plaintext"] = str(m)
                            results["m"] = str(m)
                        return json.dumps(results, indent=2)
            except Exception as ex:
                results["factordb_error"] = str(ex)

    results["status"] = "No attack succeeded"
    return json.dumps(results, indent=2)


# ── math_solve ───────────────────────────────────────────────────────────────


@mcp.tool()
def crypto_math_solve(mode: str, expression: str, variables: str = "") -> str:
    """Evaluate math expressions or solve constraints.

    Args:
        mode: "eval" to evaluate a sympy expression, "z3" to solve constraints
        expression: The expression to evaluate or constraints (semicolon-separated for z3)
        variables: Comma-separated variable names for z3 mode (e.g. "x,y,z")

    Examples:
        math_solve("eval", "factorint(1234567890)")
        math_solve("eval", "pow(7, -1, 13)")
        math_solve("z3", "x + y == 10; x - y == 4", "x,y")
    """
    if mode == "eval":
        import sympy

        # Create a safe namespace with sympy functions
        ns = {
            name: getattr(sympy, name)
            for name in dir(sympy)
            if not name.startswith("_")
        }
        ns["pow"] = pow
        ns["int"] = int
        ns["hex"] = hex
        ns["bin"] = bin
        ns["bytes"] = bytes
        if "__" in expression:
            return json.dumps(
                {"error": "Expression contains forbidden dunder access"}, indent=2
            )
        try:
            result = eval(expression, {"__builtins__": {}}, ns)
            return json.dumps({"result": str(result)}, indent=2)
        except Exception as e:
            return json.dumps({"error": str(e)}, indent=2)

    elif mode == "z3":
        import z3

        var_names = [v.strip() for v in variables.split(",") if v.strip()]
        z3_vars = {}
        for name in var_names:
            z3_vars[name] = z3.Int(name)

        solver = z3.Solver()
        constraints = [c.strip() for c in expression.split(";") if c.strip()]

        for constraint in constraints:
            if "__" in constraint:
                return json.dumps(
                    {
                        "error": f"Constraint contains forbidden dunder access: '{constraint}'"
                    },
                    indent=2,
                )
            try:
                parsed = eval(constraint, {"__builtins__": {}}, z3_vars)
                solver.add(parsed)
            except Exception as e:
                return json.dumps(
                    {"error": f"Failed to parse constraint '{constraint}': {e}"},
                    indent=2,
                )

        if solver.check() == z3.sat:
            model = solver.model()
            solution = {
                str(v): str(model[z3_vars[v]])
                for v in var_names
                if model[z3_vars[v]] is not None
            }
            return json.dumps({"status": "sat", "solution": solution}, indent=2)
        else:
            return json.dumps(
                {"status": "unsat", "note": "No solution exists"}, indent=2
            )

    return json.dumps({"error": f"Unknown mode: {mode}"}, indent=2)


# ── hash_crack ───────────────────────────────────────────────────────────────


@mcp.tool()
def crypto_hash_crack(hash_value: str, wordlist: str = "") -> str:
    """Identify a hash type and attempt lightweight dictionary cracking.

    Args:
        hash_value: The hash string to identify/crack
        wordlist: Optional newline-separated wordlist for cracking attempt. If empty, tries common passwords.
    """
    clean = hash_value.strip()
    results = {"hash": clean, "length": len(clean), "possible_types": []}

    # Identify
    if len(clean) in HASH_PATTERNS:
        results["possible_types"] = HASH_PATTERNS[len(clean)]

    # Detect bcrypt
    if clean.startswith("$2"):
        results["possible_types"] = ["bcrypt"]
    elif clean.startswith("$6$"):
        results["possible_types"] = ["SHA-512 crypt"]
    elif clean.startswith("$5$"):
        results["possible_types"] = ["SHA-256 crypt"]
    elif clean.startswith("$1$"):
        results["possible_types"] = ["MD5 crypt"]

    # Quick crack attempt
    if wordlist:
        words = wordlist.strip().splitlines()
    else:
        words = [
            "password",
            "123456",
            "admin",
            "flag",
            "test",
            "root",
            "letmein",
            "qwerty",
            "abc123",
            "monkey",
            "master",
            "dragon",
            "login",
            "princess",
            "football",
            "shadow",
            "sunshine",
            "trustno1",
            "iloveyou",
            "batman",
            "access",
            "hello",
            "charlie",
            "password1",
        ]

    hash_funcs = {
        32: [("md5", hashlib.md5)],
        40: [("sha1", hashlib.sha1)],
        64: [("sha256", hashlib.sha256)],
        128: [("sha512", hashlib.sha512)],
    }

    if len(clean) in hash_funcs and not clean.startswith("$"):
        for word in words:
            for name, func in hash_funcs[len(clean)]:
                if func(word.encode()).hexdigest() == clean.lower():
                    results["cracked"] = True
                    results["plaintext"] = word
                    results["hash_type"] = name
                    return json.dumps(results, indent=2)

    results["cracked"] = False
    results["note"] = (
        f"Tried {len(words)} words, no match. Use hashcat/john for full wordlists."
    )
    return json.dumps(results, indent=2)


# ── frequency_analysis ───────────────────────────────────────────────────────


@mcp.tool()
def crypto_frequency_analysis(text: str) -> str:
    """Perform frequency analysis on text for classical cipher analysis.

    Returns character frequencies, bigram frequencies, and chi-squared English score.
    """
    # English letter frequencies
    english_freq = {
        "a": 8.167,
        "b": 1.492,
        "c": 2.782,
        "d": 4.253,
        "e": 12.702,
        "f": 2.228,
        "g": 2.015,
        "h": 6.094,
        "i": 6.966,
        "j": 0.153,
        "k": 0.772,
        "l": 4.025,
        "m": 2.406,
        "n": 6.749,
        "o": 7.507,
        "p": 1.929,
        "q": 0.095,
        "r": 5.987,
        "s": 6.327,
        "t": 9.056,
        "u": 2.758,
        "v": 0.978,
        "w": 2.360,
        "x": 0.150,
        "y": 1.974,
        "z": 0.074,
    }

    letters_only = [c.lower() for c in text if c.isalpha()]
    total = len(letters_only)

    if total == 0:
        return json.dumps({"error": "No alphabetic characters found"}, indent=2)

    # Character frequency
    char_counts = Counter(letters_only)
    char_freq = {
        ch: round(count / total * 100, 3) for ch, count in char_counts.most_common()
    }

    # Bigram frequency
    bigrams = [
        letters_only[i] + letters_only[i + 1] for i in range(len(letters_only) - 1)
    ]
    bigram_counts = Counter(bigrams)
    top_bigrams = dict(bigram_counts.most_common(15))

    # Chi-squared against English
    chi_sq = 0
    for letter in string.ascii_lowercase:
        observed = char_counts.get(letter, 0) / total * 100
        expected = english_freq.get(letter, 0)
        if expected > 0:
            chi_sq += (observed - expected) ** 2 / expected

    # Index of coincidence
    ioc = (
        sum(c * (c - 1) for c in char_counts.values()) / (total * (total - 1))
        if total > 1
        else 0
    )

    return json.dumps(
        {
            "total_letters": total,
            "character_frequencies": char_freq,
            "top_bigrams": top_bigrams,
            "chi_squared_english": round(chi_sq, 2),
            "index_of_coincidence": round(ioc, 5),
            "likely_english": chi_sq < 50,
            "ioc_note": "English ~0.0667, random ~0.0385",
        },
        indent=2,
    )


# ── xor_analyze ───────────────────────────────────────────────────────────────

# English letter frequencies (shared with frequency_analysis)
_ENGLISH_FREQ = {
    "a": 8.167,
    "b": 1.492,
    "c": 2.782,
    "d": 4.253,
    "e": 12.702,
    "f": 2.228,
    "g": 2.015,
    "h": 6.094,
    "i": 6.966,
    "j": 0.153,
    "k": 0.772,
    "l": 4.025,
    "m": 2.406,
    "n": 6.749,
    "o": 7.507,
    "p": 1.929,
    "q": 0.095,
    "r": 5.987,
    "s": 6.327,
    "t": 9.056,
    "u": 2.758,
    "v": 0.978,
    "w": 2.360,
    "x": 0.150,
    "y": 1.974,
    "z": 0.074,
}


def _chi_squared_score(data: bytes) -> float:
    """Score how close byte frequencies are to English letter frequencies."""
    total = len(data)
    if total == 0:
        return float("inf")
    counts = Counter(data)
    chi_sq = 0.0
    for letter, expected_pct in _ENGLISH_FREQ.items():
        observed = counts.get(ord(letter), 0) + counts.get(ord(letter.upper()), 0)
        observed_pct = observed / total * 100
        if expected_pct > 0:
            chi_sq += (observed_pct - expected_pct) ** 2 / expected_pct
    return chi_sq


def _find_repeating_key_length(key_bytes: bytes) -> int:
    """Find the shortest repeating period in recovered key bytes."""
    for period in range(1, len(key_bytes) + 1):
        if all(key_bytes[i] == key_bytes[i % period] for i in range(len(key_bytes))):
            return period
    return len(key_bytes)


def _kasiski_examination(data: bytes) -> dict[int, int]:
    """Find repeated trigrams and compute GCD of distances between them."""
    from math import gcd

    trigram_positions: dict[bytes, list[int]] = {}
    for i in range(len(data) - 2):
        tri = data[i : i + 3]
        trigram_positions.setdefault(tri, []).append(i)

    distances: list[int] = []
    for positions in trigram_positions.values():
        if len(positions) >= 2:
            for i in range(len(positions) - 1):
                distances.append(positions[i + 1] - positions[i])

    if not distances:
        return {}

    # Count how often each small factor divides the distances
    factor_scores: dict[int, int] = {}
    for d in distances:
        for k in range(2, min(d + 1, 33)):
            if d % k == 0:
                factor_scores[k] = factor_scores.get(k, 0) + 1
    return factor_scores


def _index_of_coincidence(data: bytes) -> float:
    """Compute index of coincidence for a byte sequence."""
    n = len(data)
    if n <= 1:
        return 0.0
    counts = Counter(data)
    return sum(c * (c - 1) for c in counts.values()) / (n * (n - 1))


@mcp.tool()
def crypto_xor_analyze(
    data_hex: str,
    known_plaintext: str = "",
    known_plaintext_hex: str = "",
    max_key_length: int = 32,
) -> str:
    """Analyze XOR-encrypted data: recover keys from known plaintext, estimate key length, brute-force single-byte keys.

    Args:
        data_hex: Hex-encoded ciphertext
        known_plaintext: Known plaintext (ASCII) for key recovery
        known_plaintext_hex: Known plaintext (hex) for key recovery (binary data)
        max_key_length: Maximum key length to test for IC/Kasiski analysis (default 32)
    """
    try:
        data = bytes.fromhex(
            data_hex.replace(" ", "").replace("0x", "").replace("\\x", "")
        )
    except ValueError as e:
        return json.dumps({"error": f"Invalid hex data: {e}"}, indent=2)

    if len(data) == 0:
        return json.dumps({"error": "Empty data"}, indent=2)

    result: dict = {"data_length": len(data)}

    # Known-plaintext key recovery
    if known_plaintext or known_plaintext_hex:
        if known_plaintext_hex:
            pt = bytes.fromhex(known_plaintext_hex.replace(" ", ""))
        else:
            pt = known_plaintext.encode()

        key_bytes = bytes(data[i] ^ pt[i] for i in range(min(len(data), len(pt))))
        repeating_len = _find_repeating_key_length(key_bytes)
        key_short = key_bytes[:repeating_len]
        result["known_plaintext_key"] = {
            "key_hex": key_short.hex(),
            "key_ascii": key_short.decode("ascii", errors="replace"),
            "repeating_length": repeating_len,
            "raw_key_hex": key_bytes.hex(),
        }
        # Decrypt with recovered key
        full_key = (key_short * ((len(data) // repeating_len) + 1))[: len(data)]
        decrypted = bytes(d ^ k for d, k in zip(data, full_key))
        result["decrypted_preview"] = decrypted[:200].decode("ascii", errors="replace")

    # Key length estimation via IC
    ic_scores = []
    for kl in range(1, min(max_key_length + 1, len(data) // 2 + 1)):
        streams = [data[i::kl] for i in range(kl)]
        avg_ic = sum(_index_of_coincidence(s) for s in streams) / kl
        ic_scores.append({"length": kl, "ic_score": round(avg_ic, 5)})
    ic_scores.sort(key=lambda x: abs(x["ic_score"] - 0.0667))
    result["key_length_candidates"] = ic_scores[:5]

    # Kasiski examination
    kasiski = _kasiski_examination(data)
    if kasiski:
        kasiski_ranked = sorted(kasiski.items(), key=lambda x: x[1], reverse=True)[:5]
        result["kasiski_candidates"] = [
            {"length": k, "score": v} for k, v in kasiski_ranked
        ]

    # Single-byte XOR brute force
    single_byte_results = []
    for key_byte in range(256):
        decrypted = bytes(b ^ key_byte for b in data)
        score = _chi_squared_score(decrypted)
        if score < 100:
            preview = decrypted[:80].decode("ascii", errors="replace")
            single_byte_results.append(
                {
                    "key_byte": f"0x{key_byte:02x}",
                    "chi_squared": round(score, 2),
                    "preview": preview,
                }
            )
    single_byte_results.sort(key=lambda x: x["chi_squared"])
    result["single_byte_results"] = single_byte_results[:5]

    # Multi-byte recovery for best IC candidate
    if ic_scores and not (known_plaintext or known_plaintext_hex):
        best_kl = ic_scores[0]["length"]
        if best_kl <= max_key_length:
            key_bytes_recovered = []
            for i in range(best_kl):
                stream = data[i::best_kl]
                best_byte = min(
                    range(256),
                    key=lambda b: _chi_squared_score(bytes(x ^ b for x in stream)),
                )
                key_bytes_recovered.append(best_byte)
            key = bytes(key_bytes_recovered)
            full_key = (key * ((len(data) // best_kl) + 1))[: len(data)]
            decrypted = bytes(d ^ k for d, k in zip(data, full_key))
            score = _chi_squared_score(decrypted)
            result["best_decryption"] = {
                "key_length": best_kl,
                "key_hex": key.hex(),
                "key_ascii": key.decode("ascii", errors="replace"),
                "chi_squared": round(score, 2),
                "plaintext_preview": decrypted[:200].decode("ascii", errors="replace"),
            }

    return json.dumps(result, indent=2)


# ── sage_solve ────────────────────────────────────────────────────────────────


@mcp.tool()
def crypto_sage_solve(
    script: str,
    timeout: int = 60,
) -> str:
    """Execute a SageMath script for advanced cryptographic computations.

    Runs the given Sage code and captures output. Use for finite field arithmetic,
    lattice reduction (LLL), discrete logarithm, polynomial solving over GF(p), etc.

    Args:
        script: SageMath code to execute. The script should print() its results.
        timeout: Execution timeout in seconds (default 60)

    Example:
        crypto_sage_solve("p = 2^127 - 1; print(is_prime(p))")
        crypto_sage_solve("R.<x> = GF(7)[]; print(factor(x^3 + 2*x + 1))")
    """
    import shutil
    import tempfile

    sage_path = shutil.which("sage")
    if not sage_path:
        return json.dumps({"error": "sage not found in PATH"}, indent=2)

    with tempfile.NamedTemporaryFile(mode="w", suffix=".sage", delete=False) as f:
        f.write(script)
        tmp = f.name

    try:
        r = run_tool(["sage", tmp], timeout=timeout)
        result: dict = {
            "stdout": r["stdout"],
            "stderr": r["stderr"],
            "returncode": r["returncode"],
        }
        if r.get("error"):
            result["error"] = r["error"]
        try:
            result["parsed"] = json.loads(r["stdout"])
        except (json.JSONDecodeError, ValueError):
            pass
        return json.dumps(result, indent=2)
    finally:
        os.unlink(tmp)


if __name__ == "__main__":
    mcp.run(transport="stdio")
