# 🔍 Log File Analyzer

A Python tool that analyzes server log files to detect suspicious activity and potential intrusion attempts.

## Features
- Detects failed login attempts
- Extracts and counts unique IP addresses
- Flags suspicious IPs with 3+ attempts
- Shows detailed failed login entries

## Usage
```bash
python log_analyzer.py
```

## Example Output
Total Lines Analyzed : 12
Failed Login Attempts: 10
Unique IPs Detected : 6

⚠️ Suspicious IPs:
→ 192.168.1.10 — 3 attempts
→ 203.0.113.5 — 4 attempts

## Technologies
- Python
- Regex (re module)
- Log Analysis
- Intrusion Detection Concepts
