# Security Toolkit

The `nix develop` shell provides over **160 pre-configured security tools**,
including but not limited to:

| Category | Tools |
|----------|-------|
| Reverse engineering | radare2, Ghidra, cutter, iaito, rizin, dex2jar, jadx, apktool |
| Binary exploitation | gdb, lldb, pwntools, ROPgadget, ropper, one_gadget, patchelf, checksec |
| Forensics | binwalk, foremost, sleuthkit, autopsy, volatility3, bulk_extractor, exiftool, testdisk |
| Steganography | steghide, stegsolve, zsteg |
| Web | burpsuite, sqlmap, ffuf, feroxbuster, gobuster, nikto, whatweb, dalfox, commix |
| Crypto | hashcat, john, fcrackzip, SageMath |
| Networking | nmap, wireshark-cli, tcpdump, masscan, rustscan, scapy, mitmproxy |
| OSINT | amass, subfinder, theharvester, sherlock, recon-ng, gitleaks, trufflehog |
| Password attacks | hydra, medusa, hashcat, john, crowbar, kerbrute |

The Python environment includes angr, z3-solver, pwntools, pycryptodome,
cryptography, sympy, capstone, keystone-engine, unicorn, scapy, pillow, and
opencv.

All tools are declared in `flake.nix` and available after running `nix develop`.
