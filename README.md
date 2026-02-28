# Coraza WAF Lab

This lab utilizes **Coraza**, a high-performance Web Application Firewall rebuilt in Go, providing a modern alternative to the classic C++ ModSecurity.

## Key Features
- **Native Go Engine**: Leverages the speed and safety of the Coraza Go library.
- **Caddy Server**: Uses Caddy as the web server and reverse proxy.
- **OWASP CRS v4**: Compatible with the latest Core Rule Set.
- **Blocking Mode**: WAF is configured to block malicious requests.

## Architecture
- **WAF Engine**: gbe0/coraza (Coraza WAF with Caddy)
- **Reverse Proxy**: Caddy
- **Target App**: OWASP Juice Shop
- **Port**: 8080

## Quick Start

1. **Spin up the environment**:
   ```bash
   docker-compose up -d
   ```

2. **Run the Attack Replay**:
   ```bash
   ./replay_and_report.sh
   ```

   Or use PowerShell:
   ```powershell
   .\replay_and_report.ps1
   ```

## Configuration Files
- `docker-compose.yml`: Container orchestration.
- `replay_and_report.sh`: Bash script to replay attacks and generate report.
- `replay_and_report.py`: Python script that parses WAF logs and generates attack_report.md.
- `attack_report.md`: Generated report showing detected/blocked attacks.

## Test Attacks
The following attack types are tested:
- SQL Injection (OR 1=1)
- XSS (Script Tag)
- Path Traversal (etc/passwd)
- Command Injection (whoami)

## Why Coraza?
Coraza is designed to be a drop-in replacement for ModSecurity but with the benefits of a modern Go codebase: better memory safety, easier extensibility, and compatibility with ModSecurity's SecLang.
