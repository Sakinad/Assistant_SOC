import csv
import json

def clean(row):
    return {k.strip(): v.strip() for k, v in row.items()}

def find_rows(path, labels=None, contains=None, limit=5):
    found = []
    with open(path, encoding="latin-1") as f:
        reader = csv.DictReader(f)
        for row in reader:
            row = clean(row)
            label = row.get("Label", "")
            if contains and contains in label:
                found.append(row)
            elif labels and label in labels:
                found.append(row)
            if len(found) >= limit:
                break
    return found

alerts = []

# brute_force — CICIDS2017 Tuesday (FTP-Patator / SSH-Patator)
rows = find_rows("cicids2017/Tuesday-WorkingHours.pcap_ISCX.csv", labels=["FTP-Patator", "SSH-Patator"])
for r in rows:
    dur_s = round(int(r["Flow Duration"]) / 1_000_000, 2)
    alerts.append({
        "alert": f"Network flow to port {r['Destination Port']} lasting {dur_s}s with {r['Total Fwd Packets']} outbound and {r['Total Backward Packets']} inbound packets, flagged as {r['Label']} credential guessing traffic.",
        "category": "brute_force", "severity": "high", "mitre": "T1110"
    })

# port_scan — CICIDS2017 Friday PortScan
rows = find_rows("cicids2017/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv", labels=["PortScan"])
for r in rows:
    dur_s = round(int(r["Flow Duration"]) / 1_000_000, 2)
    alerts.append({
        "alert": f"Short network flow to port {r['Destination Port']} lasting {dur_s}s with only {r['Total Fwd Packets']} packet(s) exchanged, consistent with a port scanning probe.",
        "category": "port_scan", "severity": "medium", "mitre": "T1046"
    })

# sql_injection — CICIDS2017 Thursday WebAttacks
rows = find_rows("cicids2017/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv", contains="Sql Injection")
for r in rows:
    dur_s = round(int(r["Flow Duration"]) / 1_000_000, 2)
    alerts.append({
        "alert": f"HTTP flow to port {r['Destination Port']} lasting {dur_s}s with {r['Total Fwd Packets']} requests sent, matching a known SQL injection web attack pattern.",
        "category": "sql_injection", "severity": "critical", "mitre": "T1190"
    })

# benign — CICIDS2017 Monday
rows = find_rows("cicids2017/Monday-WorkingHours.pcap_ISCX.csv", labels=["BENIGN"])
for r in rows:
    dur_s = round(int(r["Flow Duration"]) / 1_000_000, 4)
    alerts.append({
        "alert": f"Normal network flow to port {r['Destination Port']} lasting {dur_s}s with {r['Total Fwd Packets']} packets, classified as benign traffic.",
        "category": "benign", "severity": "low", "mitre": "none"
    })

# privilege_escalation — OTRF (fodhelper.exe / consent.exe, vrai événement Sysmon)
priv_esc = [
    "Sysmon detected fodhelper.exe spawning consent.exe with elevated privileges on host WORKSTATION5.theshire.local, consistent with a UAC bypass technique.",
    "Registry value set under HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command, followed by fodhelper.exe execution with SYSTEM-level token on host WORKSTATION5.theshire.local.",
    "Successful sudo to ROOT executed on host victime-ubuntu by user sakina, immediately followed by creation of a new user account.",
    "Sudo misconfiguration exploited to escalate from standard user to root on host victime-ubuntu.",
    "Service account unexpectedly granted domain admin rights on host dc-primary01 outside of change window.",
]
for a in priv_esc:
    alerts.append({"alert": a, "category": "privilege_escalation", "severity": "critical", "mitre": "T1548"})

# data_exfiltration — OTRF (EC2 proxy -> S3)
exfil = [
    "Adversary abused a misconfigured EC2 reverse proxy to obtain instance profile keys and exfiltrate files from an S3 bucket.",
    "Host db-srv04 uploaded 2.3 GB of data to an unknown external IP over HTTPS outside business hours.",
    "DNS tunneling detected: host ws-dev07 sending unusually large volumes of DNS queries to external domain.",
    "Unusual outbound FTP transfer of customer database backup detected from host db-backup01 to external IP 203.0.113.44.",
    "Sensitive files compressed into a password-protected archive then uploaded to a file-sharing website from host legal-ws01.",
]
for a in exfil:
    alerts.append({"alert": a, "category": "data_exfiltration", "severity": "critical", "mitre": "T1041"})

# phishing — non couvert par les datasets choisis, écrit à la main (signalé à Fati)
phishing = [
    "User reported a suspicious email claiming to be from IT support requesting password reset via external link.",
    "Email gateway blocked a message with a spoofed sender domain mimicking company-finance.com, containing a malicious attachment.",
    "Employee clicked a link in an email impersonating a shipping company, leading to a credential-harvesting page.",
    "Bulk email campaign detected impersonating CEO, requesting urgent wire transfer from finance department.",
    "Suspicious QR code embedded in email redirects to a fake Microsoft 365 login page.",
]
for a in phishing:
    alerts.append({"alert": a, "category": "phishing", "severity": "high", "mitre": "T1566"})

# ransomware — non couvert par les datasets choisis, écrit à la main (signalé à Fati)
ransomware = [
    "Mass file encryption detected on host file-srv01, hundreds of files renamed with .locked extension within 3 minutes.",
    "Ransom note file 'README_DECRYPT.txt' created in multiple directories on host finance-ws12.",
    "Shadow copy deletion command executed on host backup-srv02 shortly before mass file modification.",
    "Endpoint detection flagged a process rapidly reading and rewriting thousands of files with high entropy content on host hr-ws05.",
    "Network share showing abnormal write activity consistent with encryption behavior from host marketing-ws03.",
]
for a in ransomware:
    alerts.append({"alert": a, "category": "ransomware", "severity": "critical", "mitre": "T1486"})

with open("data/alerts_cyber.jsonl", "w", encoding="utf-8") as f:
    for i, a in enumerate(alerts, 1):
        entry = {"id": f"alert-{i:02d}", **a}
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")

print(len(alerts), "alertes écrites dans data/alerts_cyber.jsonl")
