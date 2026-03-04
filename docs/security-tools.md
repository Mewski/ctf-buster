# Security Toolkit

The `nix develop` shell provides **80+ pre-configured security tools**
across all major CTF categories. All tools are declared in `flake.nix`
and available after running `nix develop`.

## CLI Tools

| Category | Tools |
|----------|-------|
| Reverse engineering | radare2, Ghidra, cutter, iaito, rizin, cfr, jadx, dex2jar, apktool |
| Binary exploitation | gdb, lldb, pwntools, ROPgadget, ropper, one_gadget, patchelf, checksec, nasm, binutils, elfutils |
| Forensics | binwalk, foremost, sleuthkit, volatility3, bulk_extractor, exiftool, testdisk, fcrackzip, pdfcrack, yara |
| Steganography | steghide, stegsolve, zsteg |
| Web | burpsuite, sqlmap, ffuf, feroxbuster, gobuster, nikto, whatweb, dalfox, commix, httpx |
| Crypto | hashcat, john, haiti, hash-identifier, SageMath |
| Networking | nmap, wireshark-cli, tcpdump, masscan, rustscan, mitmproxy, netcat, socat |
| OSINT | amass, subfinder, theharvester, sherlock, recon-ng, gitleaks, trufflehog |
| Password attacks | hydra, medusa, crowbar, kerbrute, hashcat, john |
| Utilities | curl, jq, rlwrap, strace, ltrace, docker, xxd, seclists |

## Python Packages

The Python 3.13 environment includes:

| Category | Packages |
|----------|----------|
| Binary analysis | angr, pwntools, capstone, keystone-engine, unicorn, ROPgadget, ropper |
| Crypto | z3-solver, pycryptodome, cryptography, sympy, gmpy2 |
| Forensics / imaging | pillow, opencv, numpy, scapy |
| Web / scripting | beautifulsoup4, requests, lxml, pefile |
| MCP framework | fastmcp |

All tools are declared in `flake.nix` and available after running `nix develop`.
