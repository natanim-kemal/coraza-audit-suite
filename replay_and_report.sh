#!/bin/bash

echo "Starting Coraza WAF Replay..."
echo "Replaying: SQLi - OR 1=1"
curl -s -i --path-as-is "http://localhost:8080/rest/products/search?q=%27%20OR%201%3D1--" -o /dev/null

echo "Replaying: XSS - Script Tag"
curl -s -i --path-as-is "http://localhost:8080/rest/products/search?q=<script>alert(1)</script>" -o /dev/null

echo "Replaying: Path Traversal - etc/passwd"
curl -s -i --path-as-is "http://localhost:8080/ftp/../../../../etc/passwd" -o /dev/null

echo "Replaying: Command Injection - whoami"
curl -s -i --path-as-is "http://localhost:8080/rest/products/search?q=|whoami" -o /dev/null

echo "Replay complete."
python3 replay_and_report.py
