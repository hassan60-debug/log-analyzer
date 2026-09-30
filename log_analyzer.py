import re
from collections import Counter
import datetime

def analyze_log(filename):
    print(f"\n{'='*50}")
    print(f"  Log File Analyzer")
    print(f"  Time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*50}\n")

    failed_logins = []
    ip_addresses = []
    suspicious_ips = []

    try:
        with open(filename, 'r') as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"  Error: File '{filename}' not found.")
        return

    for line in lines:
        # Extract IP addresses
        ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
        if ip_match:
            ip_addresses.append(ip_match.group())

        # Detect failed logins
        if 'failed' in line.lower() or 'invalid' in line.lower() or 'error' in line.lower():
            failed_logins.append(line.strip())

    # Count IP occurrences
    ip_counts = Counter(ip_addresses)

    # Flag IPs with more than 3 attempts
    for ip, count in ip_counts.items():
        if count >= 3:
            suspicious_ips.append((ip, count))

    # Results
    print(f"  Total Lines Analyzed : {len(lines)}")
    print(f"  Failed Login Attempts: {len(failed_logins)}")
    print(f"  Unique IPs Detected  : {len(ip_counts)}")

    if suspicious_ips:
        print(f"\n  ⚠️  Suspicious IPs (3+ attempts):")
        for ip, count in suspicious_ips:
            print(f"   → {ip} — {count} attempts")
    else:
        print(f"\n  ✅ No suspicious activity detected")

    if failed_logins:
        print(f"\n  Failed Login Entries:")
        for entry in failed_logins[:5]:  # Show max 5
            print(f"   → {entry}")

    print(f"\n{'='*50}\n")

# Run
filename = input("Enter log filename (e.g. sample.log): ")
analyze_log(filename)
