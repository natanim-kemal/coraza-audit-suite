# Coraza WAF Audit Suite

A comprehensive security monitoring and testing environment for **Coraza WAF**, featuring a real-time dashboard and an extensive attack suite.

## Key Features

- **Native Go Engine**: Leverages the high-performance Coraza WAF library.
- **Security Dashboard**: Real-time web UI for monitoring threat landscapes, rule matches, and audit logs.
- **Stateful Live Feed**: Intelligent log streaming that appends new threats without UI flickering.
- **48-Payload Attack Suite**: Advanced PowerShell testing suite covering SQLi, XSS, RCE, LFI, SSRF, and Prototype Pollution.
- **OWASP CRS v4**: Fully integrated with the latest Core Rule Set.
- **Automated Reporting**: Generates instant Markdown analysis of WAF performance.

## Architecture

- **WAF Engine**: `gbe0/coraza` (Coraza + Caddy)
- **Target Application**: OWASP Juice Shop
- **Dashboard Backend**: Python 3 (Internal API)
- **Frontend**: Vanilla JS / CSS (Tailored Aesthetic)
- **Log Management**: Docker Audit Log Tail (1000 lines)

## Quick Start

### 1. Spin up the WAF & Juice Shop
```bash
docker-compose up -d
```

### 2. Start the Security Dashboard
```bash
python dashboard.py
```
> Access the UI at `http://localhost:8081`

### 3. Execute Attack Suite
```powershell
.\attack_suite.ps1
```

## Core Components

- **`dashboard.py`**: The brain of the dashboard, parsing Docker logs and serving the monitoring API.
- **`index.html`**: The main monitor interface with real-time stats and live log feed.
- **`attack_suite.ps1`**: A sophisticated testing script with 48 distinct security payloads.
- **`coraza.conf`**: Optimized WAF engine configuration.
- **`replay_and_report.py`**: Standalone analysis tool that generates `attack_report.md`.

## Security Lab Focus
This suite is designed to test WAF efficacy against modern attack vectors including:
- **SQL Injection**: Login bypass, union-based, and blind SQLi.
- **XSS**: Script injection, event handlers, and iframe-based attacks.
- **Modern Vectors**: Prototype Pollution, SSTI, Log4Shell, and NoSQLi.
- **Protocol Abuse**: CRLF injection and HTTP splitting.

## Dashboard Access
- **Main View**: `http://localhost:8081/index.html`
- **Rules Inventory**: `http://localhost:8081/rules.html`
- **Engine Config**: `http://localhost:8081/config.html`
