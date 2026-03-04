{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    flake-parts.url = "github:hercules-ci/flake-parts";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    crane.url = "github:ipetkov/crane";
  };

  outputs =
    inputs@{
      flake-parts,
      rust-overlay,
      crane,
      ...
    }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];

      perSystem =
        { system, ... }:
        let
          overlays = [ rust-overlay.overlays.default ];
          pkgs = import inputs.nixpkgs {
            inherit system overlays;
            config.allowUnfree = true;
          };
          rustToolchain = pkgs.rust-bin.stable.latest.default.override {
            extensions = [ "rust-src" ];
          };
          craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;
          ctf-cli = craneLib.buildPackage {
            src = craneLib.cleanCargoSource ./.;
            nativeBuildInputs = with pkgs; [ pkg-config ];
            buildInputs = with pkgs; [
              openssl
              dbus
            ];
          };

          # Python 3.13 — packages needed by MCP servers + CTF workflows
          pythonEnv = pkgs.python313.withPackages (
            ps: with ps; [
              # MCP server framework
              fastmcp

              # Used by ctf_crypto MCP server
              sympy
              z3-solver
              gmpy2
              pycryptodome

              # Used by ctf_pwn MCP server
              angr
              pwntools
              capstone
              keystone-engine
              unicorn
              ropgadget
              ropper

              # Used by ctf_forensics MCP server
              numpy
              pillow
              opencv4
              scapy

              # General CTF / scripting
              beautifulsoup4
              cryptography
              requests
              lxml
              pefile

              # Testing
              pytest
              pytest-cov
            ]
          );

          # CLI tools used by MCP servers via subprocess + essential CTF tools
          ctfTools = with pkgs; [
            # Used by ctf_pwn MCP server
            checksec
            radare2

            # Reverse engineering
            cfr
            jadx
            dex2jar
            apktool
            cutter
            iaito
            rizin

            # Used by ctf_forensics MCP server
            binwalk
            exiftool
            file
            foremost
            steghide
            stegsolve
            zsteg

            # Binary analysis
            binutils
            elfutils
            gdb
            lldb
            ghidra
            nasm
            one_gadget
            patchelf

            # Web CTF
            burpsuite
            ffuf
            gobuster
            feroxbuster
            sqlmap
            httpx
            nikto
            whatweb
            dalfox
            commix

            # Crypto / hashing
            haiti
            hash-identifier
            hashcat
            john
            sage

            # Networking
            netcat-gnu
            nmap
            socat
            tcpdump
            wireshark-cli
            masscan
            rustscan
            mitmproxy

            # Forensics
            # autopsy  # broken in nixpkgs (sleuthkit jar version mismatch)
            bulk_extractor
            fcrackzip
            pdfcrack
            sleuthkit
            testdisk
            volatility3
            xxd
            yara

            # OSINT
            amass
            subfinder
            theharvester
            sherlock
            recon-ng
            gitleaks
            trufflehog

            # Password attacks
            hydra
            medusa
            crowbar
            kerbrute

            # General utilities
            curl
            jq
            rlwrap
            strace
            ltrace
            docker-client

            # Wordlists
            seclists
          ];
        in
        {
          packages.default = ctf-cli;

          devShells.default = pkgs.mkShell {
            nativeBuildInputs = [
              # Rust toolchain
              rustToolchain
              pkgs.rust-analyzer
              pkgs.pkg-config
              pkgs.openssl
              pkgs.dbus
              pkgs.cargo-tarpaulin

              # Python with CTF packages + fastmcp
              pythonEnv
            ]
            ++ ctfTools;

            RUST_SRC_PATH = "${rustToolchain}/lib/rustlib/src/rust/library";

            shellHook = ''
              echo "ctf-buster dev shell — Rust + Python MCP servers + CTF toolkit"
            '';
          };
        };
    };
}
