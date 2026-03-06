import http.server
import socketserver
import json
import subprocess
import re
import os

PORT = 8081
BASE_DIR = os.path.dirname(os.path.abspath(__file__)) or "."
os.chdir(BASE_DIR)

def parse_waf_logs():
    result = subprocess.run(
        ["docker", "logs", "--tail", "1000", "modintel-coraza-waf-1"],
        capture_output=True, text=True
    )
    logs = result.stdout + result.stderr
    logs = logs.replace('\\"', '"')

    attacks = []

    lines = logs.split('\n')
    for line in lines:
        if 'Coraza' in line and '[id ' in line:
            id_match = re.search(r'\[id\s+"(\d+)"\]', line)
            uri_match = re.search(r'\[uri\s+"([^"]+)"\]', line)
            msg_match = re.search(r'\[msg\s+"([^"]+)"\]', line)
            data_match = re.search(r'Matched Data:([^"]+)"', line)
            severity_match = re.search(r'\[severity\s+"([^"]+)"\]', line)
            tag_matches = re.findall(r'\[tag\s+"([^"]+)"\]', line)
            file_match = re.search(r'\[file\s+"([^"]+)"\]', line)
            transaction_match = re.search(r'\[(?:unique_id|transaction)\s+"([^"]+)"\]', line)
            if not transaction_match:
                transaction_match = re.search(r'transaction\s+"([^"]+)"', line)

            if id_match and uri_match:
                rule_id = id_match.group(1)
                uri = uri_match.group(1)
                msg = msg_match.group(1) if msg_match else "Attack Detected"
                data = data_match.group(1).strip() if data_match else "-"
                severity = severity_match.group(1) if severity_match else "UNKNOWN"
                tags = tag_matches if tag_matches else []
                rule_file = file_match.group(1) if file_match else "-"
                tx_id = transaction_match.group(1) if transaction_match else "N/A"

                attacks.append({
                    "status": 403,
                    "uri": uri,
                    "rule_id": rule_id,
                    "message": msg,
                    "matched_data": data,
                    "severity": severity,
                    "tags": tags,
                    "rule_file": rule_file,
                    "tx_id": tx_id
                })

    return attacks


def get_config():
    config_path = os.path.join(BASE_DIR, "coraza.conf")
    directives = []
    raw = ""
    try:
        with open(config_path, "r") as f:
            raw = f.read()
        for line in raw.split('\n'):
            stripped = line.strip()
            if stripped and not stripped.startswith('#'):
                parts = stripped.split(None, 1)
                if len(parts) >= 1:
                    directives.append({
                        "directive": parts[0],
                        "value": parts[1] if len(parts) > 1 else "",
                        "raw": stripped
                    })
    except FileNotFoundError:
        pass

    compose_path = os.path.join(BASE_DIR, "docker-compose.yml")
    compose_raw = ""
    try:
        with open(compose_path, "r") as f:
            compose_raw = f.read()
    except FileNotFoundError:
        pass

    return {"directives": directives, "config_raw": raw, "compose_raw": compose_raw}


class DashboardHandler(http.server.SimpleHTTPRequestHandler):
    def _send_json(self, data, status=200):
        self.send_response(status)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode('utf-8'))

    def do_GET(self):
        if self.path == '/api/logs':
            self._send_json({"attacks": parse_waf_logs()})

        elif self.path == '/api/rules':
            attacks = parse_waf_logs()
            rules = {}
            for a in attacks:
                rid = a["rule_id"]
                if rid not in rules:
                    rules[rid] = {
                        "rule_id": rid,
                        "message": a["message"],
                        "severity": a["severity"],
                        "tags": a["tags"],
                        "rule_file": a["rule_file"],
                        "hit_count": 0,
                        "uris": []
                    }
                rules[rid]["hit_count"] += 1
                if a["uri"] not in rules[rid]["uris"]:
                    rules[rid]["uris"].append(a["uri"])
            self._send_json({"rules": list(rules.values())})

        elif self.path == '/api/config':
            self._send_json(get_config())

        elif self.path == '/api/replay':
            try:
                subprocess.Popen(["powershell.exe", "-ExecutionPolicy", "Bypass", "-File", "attack_suite.ps1"])
                self._send_json({"status": "success", "message": "Attack suite started"})
            except Exception as e:
                self._send_json({"status": "error", "message": str(e)}, 500)

        elif self.path == '/api/clear':
            try:
                subprocess.run(["docker", "compose", "up", "-d", "--force-recreate", "waf"], check=True)
                self._send_json({"status": "success", "message": "Logs cleared"})
            except Exception as e:
                self._send_json({"status": "error", "message": str(e)}, 500)

        elif self.path == '/':
            self.path = '/index.html'
            return http.server.SimpleHTTPRequestHandler.do_GET(self)
        else:
            return http.server.SimpleHTTPRequestHandler.do_GET(self)


print(f"Starting server on http://localhost:{PORT}")
with socketserver.TCPServer(("", PORT), DashboardHandler) as httpd:
    httpd.serve_forever()
