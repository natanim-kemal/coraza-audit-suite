import subprocess
import re
import os
from datetime import datetime

# Use current directory
os.chdir(os.path.dirname(os.path.abspath(__file__)) or ".")

result = subprocess.run(
    ["docker", "logs", "--tail", "200", "modintel-coraza-waf-1"],
    capture_output=True, text=True
)
logs = result.stdout + result.stderr

logs = logs.replace('\\"', '"')

seen = set()
report_lines = [
    "# Coraza WAF Attack Analysis Report",
    f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
    "",
    "| Status | URI | Rule ID | Message | Matched Data |",
    "| :--- | :--- | :--- | :--- | :--- |"
]

lines = logs.split('\n')
for line in lines:
    if 'Coraza' in line and '[id ' in line:
        id_match = re.search(r'\[id\s+"(\d+)"\]', line)
        uri_match = re.search(r'\[uri\s+"([^"]+)"\]', line)
        msg_match = re.search(r'\[msg\s+"([^"]+)"\]', line)
        data_match = re.search(r'Matched Data:([^"]+)"', line)
        
        if id_match and uri_match:
            rule_id = id_match.group(1)
            uri = uri_match.group(1)
            msg = msg_match.group(1) if msg_match else "Attack Detected"
            data = data_match.group(1).strip() if data_match else "-"
            
            if rule_id not in seen:
                seen.add(rule_id)
                report_lines.append(f"| 403 | `{uri}` | **{rule_id}** | {msg} | `{data}` |")

if len(report_lines) == 5:
    report_lines.append("| - | No attack data found in logs | - | - | - |")

with open("attack_report.md", "w") as f:
    f.write("\n".join(report_lines))

print("Report generated: attack_report.md")
