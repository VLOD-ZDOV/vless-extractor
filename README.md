# VLESS & Hysteria 2 Link Extractor

A cross-platform utility (Windows & Linux) to extract raw `vless://` and `hysteria2://` links from subscription endpoints, Base64 data, local files, and Sing-Box / Xray JSON configurations.

## Quick Install (One-Liner)

### Linux & macOS (Bash)
```bash
curl -fsSL https://raw.githubusercontent.com/VLOD-ZDOV/vless-extractor/master/install.sh | bash
```

### Windows (PowerShell)
```powershell
irm https://raw.githubusercontent.com/VLOD-ZDOV/vless-extractor/master/install.ps1 | iex
```

---

## Features

- **Multi-Protocol Support**:
  - `vless://` (VLESS with TCP, Reality, TLS, WebSocket, gRPC, xHTTP)
  - `hysteria2://` (Hysteria 2 / Hy2 with QUIC, TLS, obfuscation)
- **Multi-Format Parsing**:
  - Base64-encoded subscription strings
  - Plain text proxy lists
  - Sing-Box JSON outbounds
  - Xray / V2Ray JSON configurations
- **Device Attestation (HWID)**: Automatically sends deterministic device headers for panels requiring hardware IDs (e.g. Remnawave), with optional custom HWID support.
- **Client Emulation**: Emulates standard client user-agents to prevent HTTP 502/403 blocks from panels that reject generic browsers.
- **Zero External Dependencies**: Single static binary for Linux and Windows using Go standard library. Python script also included.

---

## Usage

### Command Line

```bash
# Basic extraction (extracts VLESS, auto-falls back to Hysteria 2 if no VLESS present)
vless-extract "https://example.com/sub/token123"

# Include both VLESS and Hysteria 2 links
vless-extract -all "https://example.com/sub/token123"

# Extract only Hysteria 2 links
vless-extract -hy2-only "https://example.com/sub/token123"

# Save directly to a file
vless-extract -o links.txt "https://example.com/sub/token123"

# Verbose output with node remarks
vless-extract -v "https://example.com/sub/token123"

# Decode URL-encoded remark names in the #fragment
vless-extract -d "https://example.com/sub/token123"

# Custom HWID (device identifier)
vless-extract -hwid "a1b2c3d4e5f60718293a4b5c6d7e8f90" "https://example.com/sub/token123"

# Pipe / stdin support
curl -s "https://example.com/sub/token123" | vless-extract
```

### Windows (CMD / PowerShell)

```cmd
vless-extract.exe "https://example.com/sub/token123"
```
*Note: Double-clicking `vless-extract.exe` launches interactive mode.*

### Python Script

```bash
python3 vless_extract.py "https://example.com/sub/token123"
```

---

## Options

| Flag | Default | Description |
| :--- | :--- | :--- |
| `-hy2` | `false` | Include Hysteria 2 links |
| `-hy2-only` | `false` | Extract only Hysteria 2 links |
| `-all` | `false` | Extract all supported links (VLESS + Hysteria 2) |
| `-o <file>` | `""` | Output file path to write extracted links |
| `-v` | `false` | Verbose output displaying remark and link details |
| `-d` | `false` | Decode percent-encoded remarks in `#fragment` |
| `-hwid <id>`| Auto | Specify a custom HWID header |
| `-k` | `false` | Skip SSL certificate verification |
| `-pause` | `false` | Wait for Enter key before exiting |

---

## Building from Source

Requires Go 1.20+:

```bash
# Linux
go build -trimpath -ldflags="-s -w" -o vless-extract main.go

# Windows (cross-compile)
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o vless-extract.exe main.go
```
