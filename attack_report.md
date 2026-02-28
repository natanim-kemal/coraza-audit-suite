# Coraza WAF Attack Analysis Report
Generated on: 2026-02-28 21:08:34

| Status | URI | Rule ID | Message | Matched Data |
| :--- | :--- | :--- | :--- | :--- |
| 403 | `/ftp/../../../../etc/passwd` | **930100** | Path Traversal Attack (/../) or (/.../) | `/../ found within REQUEST_URI_RAW: /ftp/../../../../etc/passwd` |
| 403 | `/ftp/../../../../etc/passwd` | **930110** | Path Traversal Attack (/../) or (/.../) | `/../ found within REQUEST_URI: /ftp/../../../../etc/passwd` |
| 403 | `/ftp/../../../../etc/passwd` | **949110** | Inbound Anomaly Score Exceeded (Total Score: 30) | `-` |
| 403 | `/rest/products/search?q=|whoami` | **932105** | Remote Command Execution: Unix Command Injection | `|whoami found within ARGS:q: |whoami` |
| 403 | `/rest/products/search?q=|whoami` | **932115** | Remote Command Execution: Windows Command Injection | `|whoami found within ARGS:q: |whoami` |
| 403 | `/rest/products/search?q=%27%20OR%201%3D1--` | **942100** | SQL Injection Attack Detected via libinjection | `s&1c found within ARGS:q: ' OR 1=1--` |
| 403 | `/rest/products/search?q=<script>alert(1)</script>` | **941100** | XSS Attack Detected via libinjection | `XSS data found within ARGS:q: <script>alert(1)</script>` |
| 403 | `/rest/products/search?q=<script>alert(1)</script>` | **941110** | XSS Filter - Category 1: Script Tag Vector | `<script> found within ARGS:q: <script>alert(1)</script>` |
| 403 | `/rest/products/search?q=<script>alert(1)</script>` | **941160** | NoScript XSS InjectionChecker: HTML Injection | `<script found within ARGS:q: <script>alert(1)</script>` |