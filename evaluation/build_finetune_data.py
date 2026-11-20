#!/usr/bin/env python3
"""Construit le dataset de fine-tuning (semaine 4) : triage d'alertes SOC au format JSON.

Chaque exemple est une conversation (system / user / assistant) avec EXACTEMENT le meme prompt
que celui du benchmark (evaluate.py), pour que le modele fine-tune soit evalue dans les memes
conditions. La reponse attendue est un JSON {category, severity, mitre, explanation}.

Le dataset est genere a partir de gabarits (8 categories x 10 gabarits) avec des valeurs
aleatoires (IP, machines, comptes, compteurs). Les explications ne citent QUE des elements
presents dans l'alerte, ce qui entraine le modele a ne rien inventer.

Garde-fous :
  - 2 gabarits par categorie sont reserves a la validation (formulations jamais vues a l'entrainement) ;
  - toute alerte trop proche d'une alerte des jeux de test (alerts_cyber, alerts_soc_logs) est supprimee.

Usage : python evaluation/build_finetune_data.py
"""
import argparse
import json
import random
import re
from collections import Counter
from pathlib import Path
from types import SimpleNamespace

from evaluate import SYSTEM_PROMPT, alert_prompt, load_valid_mitre, parse_alert, unsupported_entities

HERE = Path(__file__).resolve().parent

HOSTP = ["web", "db", "app", "mail", "fs", "dc", "vpn", "dev", "hr", "fin", "build", "bk", "proxy", "api"]
USERS = ["farid", "hana", "ilyas", "jamal", "karim", "laila", "mehdi", "nadia", "omar", "rania",
         "sara", "tarik", "yassine", "zineb", "amine", "salma", "reda", "imane", "adil", "meryem"]
SVCS = ["svc_sql", "svc_web", "svc_backup2", "svc_monitor", "svc_deploy", "svc_etl"]
SERVICES = ["nginx", "postgresql", "cron", "docker", "apache2", "redis"]
PAGES = ["/products.php", "/item", "/view.php", "/news.asp", "/catalog", "/profile.php"]
LOGIN_PATHS = ["/wp-login.php", "/admin/login", "/api/auth", "/owa/auth.owa", "/portal/signin"]
LOOKALIKE = ["c0mpany-helpdesk.com", "micros0ft-support.net", "secure-payroll-portal.com",
             "it-helpdesk-verify.org", "docs-share-login.com", "account-recovery-center.net"]
SUBJECTS = ["Urgent: verify your password", "Your mailbox is almost full", "Invoice overdue",
            "Action required: account suspended", "New voicemail message", "Shared document waiting for you"]
DOCS = ["Invoice", "Purchase_Order", "Salary_Report", "Contract", "Shipping_Notice", "Timesheet"]
EXTS = ["locked", "encrypted", "crypt", "enc", "ryk", "zzz"]
NOTES = ["README_DECRYPT.txt", "HOW_TO_RESTORE.txt", "RECOVER_FILES.html", "DECRYPT_INSTRUCTIONS.txt"]
FAMILIES = ["BlackCat", "Akira", "Royal", "Conti", "Hive"]
DEPTS = ["finance", "hr", "sales", "legal", "engineering"]
EXFIL_DOMS = ["transfer-files.example.net", "quickshare.example.org", "anon-drop.example.com", "cloudbox-free.example.net"]
BADZONES = ["ns.tunnel-zone.example", "dns.datapipe.example", "x.cdn-update.example"]
PROCS_UAC = ["fodhelper.exe", "eventvwr.exe", "computerdefaults.exe"]
WIN_CVES = ["CVE-2023-21768", "CVE-2022-37969", "CVE-2024-30088"]
LINUX_CVES = ["CVE-2021-4034", "CVE-2021-3156", "CVE-2023-0386"]
SUID_BINS = ["find", "vim", "python3"]
VENDORS = ["newsletter.trusted-vendor.example", "updates.softvendor.example", "news.industry-weekly.example"]


def make_slots(rnd):
    g = SimpleNamespace()
    pub = ["203.0.113", "198.51.100", "192.0.2"]
    g.eip, g.eip2 = (f"{rnd.choice(pub)}.{rnd.randint(2, 250)}" for _ in range(2))
    g.iip, g.iip2 = (f"{rnd.choice(['10.%d.%d' % (rnd.randint(0, 30), rnd.randint(0, 30)), '192.168.%d' % rnd.randint(0, 20)])}.{rnd.randint(2, 250)}" for _ in range(2))
    g.net = f"10.{rnd.randint(0, 30)}.{rnd.randint(0, 30)}.0/24"
    g.h, g.h2 = (f"{rnd.choice(HOSTP)}-{rnd.randint(1, 29):02d}" for _ in range(2))
    while g.h2 == g.h:
        g.h2 = f"{rnd.choice(HOSTP)}-{rnd.randint(1, 29):02d}"
    g.ws, g.ws2 = (f"WS-{rnd.randint(100, 499)}" for _ in range(2))
    g.u, g.svc = rnd.choice(USERS), rnd.choice(SVCS)
    g.n = rnd.choice([rnd.randint(8, 60), rnd.randint(60, 400)])
    g.m, g.sec, g.k = rnd.randint(2, 30), rnd.randint(3, 60), rnd.randint(4, 40)
    g.port, g.pid, g.p2 = rnd.choice([22, 80, 443, 445, 3389, 8080]), rnd.randint(1000, 9999), rnd.choice([1024, 10000, 65535])
    g.gb, g.x, g.size, g.s = round(rnd.uniform(0.8, 40), 1), rnd.randint(8, 60), rnd.randint(2000, 90000), rnd.choice([3, 5, 10])
    g.page, g.path, g.dom = rnd.choice(PAGES), rnd.choice(LOGIN_PATHS), rnd.choice(LOOKALIKE)
    g.subj, g.file = rnd.choice(SUBJECTS), f"{rnd.choice(DOCS)}_{rnd.randint(2024, 2026)}.docm"
    g.sender = f"{rnd.choice(['support', 'hr', 'payroll', 'it-desk'])}@{g.dom}"
    g.ext, g.note, g.family, g.dept = rnd.choice(EXTS), rnd.choice(NOTES), rnd.choice(FAMILIES), rnd.choice(DEPTS)
    g.btc, g.xdom, g.bz = rnd.choice(["0.3", "0.5", "1.2", "2"]), rnd.choice(EXFIL_DOMS), rnd.choice(BADZONES)
    g.t = f"{rnd.randint(0, 5):02d}:{rnd.randint(0, 59):02d}"
    g.t1, g.t2 = f"{rnd.randint(0, 3):02d}:00", f"{rnd.randint(4, 6):02d}:00"
    g.uacp, g.suid = rnd.choice(PROCS_UAC), rnd.choice(SUID_BINS)
    g.wcve, g.lcve = rnd.choice(WIN_CVES), rnd.choice(LINUX_CVES)
    g.service, g.vend = rnd.choice(SERVICES), rnd.choice(VENDORS)
    g.arch = f"{rnd.choice(['payroll', 'customers', 'projects', 'backup'])}_{rnd.randint(1, 12):02d}.zip"
    return g


# ------------------------------------------------------------------ gabarits : (alerte, severite, mitre, explication)
BF, PS, SQ, PH, RW, EX, PE, BE = ("brute_force", "port_scan", "sql_injection", "phishing",
                                 "ransomware", "data_exfiltration", "privilege_escalation", "benign")

def bf1(g): return (f"auth.log {g.h}: pam_unix(sshd:auth) authentication failure; rhost={g.eip} user={g.u}; repeated {g.n} times in the last {g.m} minutes.", "high" if g.n >= 100 else "medium", "T1110", f"{g.n} repeated authentication failures for {g.u} from {g.eip} on {g.h} indicate a brute-force attempt.")
def bf2(g): return (f"Security analytics: source {g.eip} accumulated {g.n} failed SSH authentications against {g.h} and then opened an interactive session as {g.u}.", "critical", "T1110", f"{g.eip} failed {g.n} times and then got a session as {g.u} on {g.h}, so the brute force probably succeeded.")
def bf3(g): return (f"SIEM correlation rule excessive-logon-failures fired for {g.u} on {g.h}: {g.n} Event 4625 entries from {g.eip} over {g.m} minutes, zero successes.", "high" if g.h.startswith("dc") else "medium", "T1110", f"{g.n} failed logons for {g.u} from {g.eip} on {g.h} indicate password guessing.")
def bf4(g): return (f"RDP service on {g.h} received {g.n} failed authentication attempts from {g.eip} in {g.m} minutes using {g.k} different usernames.", "high", "T1110", f"{g.k} usernames tried from {g.eip} against RDP on {g.h} indicate password spraying.")
def bf5(g): return (f"Access log {g.h}: {g.eip} requested {g.path} with method POST {g.n} times in {g.m} minutes; every response was HTTP 401 and the submitted username was {g.u}.", "high" if g.n >= 300 else "medium", "T1110", f"{g.n} rejected login POSTs from {g.eip} for {g.u} on {g.path} show credential guessing.")
def bf6(g): return (f"VPN gateway {g.h}: {g.n} authentication failures for {g.k} distinct accounts from {g.eip} within {g.m} minutes.", "high", "T1110", f"{g.k} accounts failing {g.n} times from {g.eip} on {g.h} indicate password spraying against the VPN.")
def bf7(g): return (f"Service account {g.svc} was locked out on {g.h} after {g.n} bad password attempts originating from {g.iip}.", "medium", "T1110", f"The lockout of {g.svc} on {g.h} after {g.n} bad passwords from {g.iip} indicates password guessing.")
def bf8(g): return (f"Fail2ban banned {g.eip} after {g.n} failed SSH logins on {g.h}.", "medium", "T1110", f"{g.eip} made {g.n} failed SSH logins on {g.h}, a brute-force attempt that was blocked.")
def bf9(g): return (f'rule.description="Multiple authentication failures" agent.name={g.h} data.srcip={g.eip} data.attempts={g.n} data.timeframe={g.m}m', "high" if g.n >= 100 else "medium", "T1110", f"{g.n} authentication failures from {g.eip} on {g.h} in {g.m} minutes indicate brute force.")
def bf10(g): return (f"Domain controller {g.h} logged {g.n} Kerberos pre-authentication failures (EventID 4771) for account {g.u} from {g.iip} in {g.m} minutes.", "high", "T1110", f"{g.n} Kerberos pre-authentication failures for {g.u} from {g.iip} indicate password guessing against the domain.")

def ps1(g): return (f"Netfilter log {g.h}: {g.k} connection attempts rejected from {g.eip}, each targeting a new port, over {g.sec} seconds.", "low", "T1046", f"{g.eip} hit {g.k} different ports on {g.h} in {g.sec} seconds, which looks like port scanning.")
def ps2(g): return (f"NIDS: workstation {g.iip} issued half-open connection probes toward every address in {g.net} on the first {g.p2} ports.", "medium", "T1046", f"{g.iip} is probing the whole {g.net} range, which is internal reconnaissance.")
def ps3(g): return (f"Flow analysis: {g.iip} contacted {g.k} different machines on the SMB port 445 during {g.m} minutes; the majority of attempts were reset.", "medium", "T1046", f"{g.iip} tried port 445 on {g.k} machines, a sweep looking for SMB services.")
def ps4(g): return (f"Sensor {g.h}: ICMP port unreachable replies were generated {g.k} times in {g.sec} seconds for UDP datagrams coming from {g.eip}.", "low", "T1046", f"{g.eip} sent UDP datagrams to {g.k} closed ports on {g.h}, which is a UDP port scan.")
def ps5(g): return (f"Web server {g.h} logged {g.k} requests from {g.eip} with the user agent Nmap Scripting Engine probing different URLs.", "low", "T1046", f"{g.eip} used Nmap Scripting Engine against {g.h}, which is service discovery.")
def ps6(g): return (f"IDS rule sequential-port-access: {g.eip} -> {g.h}, ports {g.port}-{g.port + g.k}, no payload exchanged.", "low", "T1046", f"{g.eip} touched ports {g.port} through {g.port + g.k} on {g.h} without sending data, which indicates a port scan.")
def ps7(g): return (f"{g.eip} sent SYN packets to port {g.port} on {g.k} different hosts of the DMZ in {g.sec} seconds.", "low", "T1046", f"{g.eip} swept port {g.port} across {g.k} DMZ hosts, a scan for exposed services.")
def ps8(g): return (f"Zeek notice Scan::Port_Scan: source {g.eip} scanned {g.k} ports on {g.h}.", "low", "T1046", f"Zeek reports that {g.eip} scanned {g.k} ports on {g.h}.")
def ps9(g): return (f"Network flow logs show {g.iip} touching {g.k} unique ports on {g.h2} within {g.sec} seconds, with very small packets and no payload.", "medium", "T1046", f"{g.iip} touched {g.k} ports on {g.h2} with empty packets, typical of internal port scanning.")
def ps10(g): return (f"Honeypot {g.h} received connection attempts on {g.k} different ports from {g.eip} in {g.sec} seconds.", "low", "T1046", f"{g.eip} tried {g.k} ports on the honeypot {g.h}, which is scanning activity.")

def sq1(g): return (f"ModSecurity rule 942100 triggered by {g.eip} on {g.h}: argument id contains a SQL tautology; transaction denied (403).", "medium", "T1190", f"ModSecurity denied a request from {g.eip} whose id argument contains a SQL tautology, a blocked injection attempt.")
def sq2(g): return (f"Nginx log {g.h}: {g.eip} requested {g.page}?id=-1 UNION ALL SELECT 1,user(),database() and received a {g.size}-byte HTTP 200 reply.", "high", "T1190", f"The UNION ALL SELECT request from {g.eip} got a {g.size}-byte HTTP 200 reply, so database information may have leaked.")
def sq3(g): return (f"Authentication anomaly on {g.h}: login form submitted from {g.eip} with the password field set to ' OR ''=' and a session was granted to an administrator without valid credentials.", "critical", "T1190", f"The login from {g.eip} used a SQL injection payload and was granted an administrator session on {g.h}.")
def sq4(g): return (f"{g.h} application error log: MySQL exception 1064 raised for a request from {g.eip} to {g.page} with the parameter value {g.n}'.", "medium", "T1190", f"A stray quote in a parameter from {g.eip} raised a MySQL syntax exception on {g.h}, typical of injection probing.")
def sq5(g): return (f"Response time anomaly: requests from {g.eip} to {g.page} that embed a SLEEP({g.s}) call were each delayed by about {g.s} seconds.", "high", "T1190", f"The delays after SLEEP({g.s}) payloads from {g.eip} indicate time-based SQL injection.")
def sq6(g): return (f"{g.h} web log: {g.n} requests from {g.eip} with user agent sqlmap against {g.page} in {g.m} minutes.", "high", "T1190", f"sqlmap requests from {g.eip} against {g.page} indicate automated SQL injection.")
def sq7(g): return (f"Database audit on {g.h}: a query containing '; DROP TABLE' was received through the web application account {g.u} from {g.eip}.", "high", "T1190", f"A stacked DROP TABLE query from {g.eip} through the web application account {g.u} is a SQL injection attempt.")
def sq8(g): return (f"Web log on {g.h}: {g.k} requests to {g.page} from {g.eip} with payloads AND 1=1 and AND 1=2 and different response sizes.", "high", "T1190", f"The AND 1=1 and AND 1=2 payloads from {g.eip} with different responses indicate blind SQL injection.")
def sq9(g): return (f"HTTP 500 responses on {g.h} after {g.eip} sent updatexml() and extractvalue() payloads to {g.page}.", "high", "T1190", f"updatexml() and extractvalue() payloads from {g.eip} causing errors on {g.h} indicate error-based SQL injection.")
def sq10(g): return ("API gateway " + g.h + " rejected a JSON body with the username admin' OR 1=1 -- from " + g.eip + " (HTTP 400).", "medium", "T1190", f"The OR 1=1 payload in the username sent by {g.eip} is a SQL injection attempt that was rejected.")

def ph1(g): return (f"Secure email gateway verdict phishing for a message from {g.sender}: subject '{g.subj}', embedded URL http://{g.dom}/verify, delivery blocked.", "medium", "T1566", f"The blocked email from {g.sender} uses a lookalike domain and a credential-themed lure.")
def ph2(g): return (f"Identity provider flagged {g.u}: a login to the corporate portal came minutes after the user visited {g.dom} from an email link and typed their password there.", "high", "T1566", f"{g.u} typed a password on {g.dom} after an email link and the portal login followed, so the credentials were probably phished.")
def ph3(g): return (f"Web filter: {g.k} distinct users opened {g.dom} within {g.m} minutes; all had received the message titled '{g.subj}'.", "high", "T1566", f"{g.k} users who received '{g.subj}' opened {g.dom}, which indicates a phishing campaign.")
def ph4(g): return (f"Sandbox verdict malicious for the document {g.file} (macro downloader) that reached {g.k} inboxes from an external sender; no user opened it yet.", "medium", "T1566", f"The sandbox flagged {g.file} as a malicious macro document sent to {g.k} inboxes but not opened yet.")
def ph5(g): return (f"Business email compromise suspicion reported by {g.u}: a message that looks like it comes from the CEO demands an urgent payment; its real domain is {g.dom}.", "medium", "T1566", f"The message imitates the CEO but comes from {g.dom}, a business email compromise phishing attempt.")
def ph6(g): return (f"Employee {g.u} reported an email with a QR code that redirects to a fake login page at {g.dom}.", "medium", "T1566", f"The QR code in the email reported by {g.u} leads to a fake login page at {g.dom}.")
def ph7(g): return (f"EDR: {g.file} opened by {g.u} on {g.ws} from an email attachment spawned powershell.exe.", "high", "T1566", f"{g.u} opened {g.file} from an email and it spawned powershell.exe on {g.ws}, consistent with a malicious attachment.")
def ph8(g): return (f"Mail gateway: {g.k} messages failed SPF and DKIM checks while claiming to be from {g.dom}, all asking recipients to reset their password.", "medium", "T1566", f"{g.k} spoofed messages claiming to be from {g.dom} and asking for password resets are phishing.")
def ph9(g): return (f"{g.k} employees received an SMS asking them to confirm a package delivery on {g.dom}; {g.u} reported it to the help desk.", "medium", "T1566", f"The SMS sent to {g.k} employees sends them to {g.dom}, a smishing lure reported by {g.u}.")
def ph10(g): return (f"User {g.u} granted mailbox access to an unknown application after clicking a link in an email from {g.sender}.", "high", "T1566", f"{g.u} granted mailbox access to an unknown app after an email from {g.sender}, a consent phishing attack.")

def rw1(g): return (f"Storage alert on {g.h}: {g.n * 10} objects now carry the new suffix .{g.ext} and every folder contains {g.note}.", "critical", "T1486", f"The new suffix .{g.ext} on {g.n * 10} objects and the file {g.note} on {g.h} indicate ransomware encryption.")
def rw2(g): return (f"EDR on {g.ws}: backup snapshots were removed under the account {g.u}, then a burst of file writes produced unreadable documents and a payment demand.", "critical", "T1486", f"Snapshot removal by {g.u} followed by unreadable documents and a payment demand on {g.ws} indicates ransomware.")
def rw3(g): return (f"FIM entropy alarm: {g.n * 10} files in the {g.dept} directory of {g.h} became high-entropy within {g.m} minutes, and a demand for payment was left behind.", "critical", "T1486", f"{g.n * 10} files turning high-entropy and a payment demand on {g.h} indicate ransomware encrypting the {g.dept} directory.")
def rw4(g): return (f"Endpoint protection quarantined a {g.family} loader on {g.ws}, but several user documents were already encrypted.", "critical", "T1486", f"A {g.family} ransomware loader on {g.ws} was quarantined after it had already encrypted documents.")
def rw5(g): return (f"Help desk received tickets from {g.ws} and {g.ws2}: documents have a new .{g.ext} suffix and a screen asks for {g.btc} BTC.", "critical", "T1486", f"Documents with a .{g.ext} suffix on {g.ws} and {g.ws2} and a {g.btc} BTC demand indicate ransomware.")
def rw6(g): return (f"Backup server {g.h} reported {g.n} backup files deleted and the backup catalog encrypted at {g.t}.", "critical", "T1486", f"The encrypted backup catalog and {g.n} deleted backups on {g.h} indicate ransomware targeting recovery.")
def rw7(g): return (f"Process svchost32.exe on {g.ws} rewrote {g.n * 5} files per minute with the extension .{g.ext}; user {g.u} reported inaccessible documents.", "critical", "T1486", f"A process on {g.ws} rewriting files to .{g.ext} and {g.u} losing access to documents indicate ransomware.")
def rw8(g): return (f"Network share on {g.h} shows abnormal write activity: {g.n * 10} files changed to unreadable content in {g.m} minutes.", "critical", "T1486", f"{g.n * 10} files becoming unreadable in {g.m} minutes on {g.h} is consistent with ransomware encryption.")
def rw9(g): return (f"Database server {g.h}: {g.k} database files renamed to .{g.ext}; service stopped; text file {g.note} found in the data directory.", "critical", "T1486", f"Database files renamed to .{g.ext} and {g.note} on {g.h} indicate a ransomware attack.")
def rw10(g): return (f"Users in the {g.dept} department cannot open files; all files on {g.h} now end with .{g.ext} and a ransom message demands payment.", "critical", "T1486", f"Files ending in .{g.ext} on {g.h} and a ransom message show ransomware affecting the {g.dept} department.")

def ex1(g): return (f"Egress anomaly: {g.h} transferred {g.gb} GB to {g.eip} using TLS between {g.t1} and {g.t2}, roughly {g.x} times its normal outbound traffic.", "high", "T1041", f"{g.h} sent {g.gb} GB to {g.eip}, about {g.x} times its normal volume, which suggests data exfiltration.")
def ex2(g): return (f"Data loss prevention: {g.u} moved {g.n * 20} client records into a private online drive.", "high", "T1567", f"{g.u} moved {g.n * 20} client records to a private online drive, which is data exfiltration.")
def ex3(g): return (f"Resolver telemetry: {g.ws} issued {g.n * 10} TXT lookups with long random-looking labels under {g.bz} during {g.m} minutes.", "high", "T1048", f"Long random TXT lookups from {g.ws} under {g.bz} indicate data exfiltration through DNS tunneling.")
def ex4(g): return (f"Firewall session: {g.h} pushed the file {g.arch} ({g.gb} GB) to the external FTP server {g.eip} outside working hours.", "high", "T1048", f"{g.h} sent {g.arch} to {g.eip} over FTP outside working hours, which suggests exfiltration.")
def ex5(g): return (f"Web gateway: {g.u} sent {g.gb} GB of zipped content to {g.xdom} at {g.t}.", "high", "T1567", f"{g.u} sent {g.gb} GB to {g.xdom}, an anonymous file-sharing site, which indicates exfiltration.")
def ex6(g): return (f"Sensitive files on {g.ws} were compressed into a password-protected archive and then uploaded to {g.xdom} by user {g.u}.", "high", "T1567", f"{g.u} archived sensitive files on {g.ws} with a password and uploaded them to {g.xdom}, a staged exfiltration.")
def ex7(g): return (f"Netflow: {g.h} sent {g.gb} GB to {g.eip} over TCP port {g.port} in {g.m} minutes with a constant beaconing interval.", "high", "T1041", f"{g.h} sends {g.gb} GB to {g.eip} at regular intervals, which suggests exfiltration over a command channel.")
def ex8(g): return (f"Database export on {g.h} by {g.u} produced {g.arch} ({g.gb} GB), transferred over SFTP to {g.eip}.", "high", "T1048", f"The export {g.arch} was sent over SFTP to {g.eip}, an unexpected destination, which suggests exfiltration.")
def ex9(g): return (f"Firewall: outbound transfer of {g.gb} GB from {g.h} to {g.eip} on port {g.port}, the first connection to this destination ever seen.", "high", "T1041", f"{g.h} sent {g.gb} GB to {g.eip}, a never-seen destination, which suggests data exfiltration.")
def ex10(g): return (f"CASB alert: {g.u} shared {g.n} confidential documents from the corporate drive with an external personal account at {g.xdom}.", "high", "T1567", f"{g.u} shared {g.n} confidential documents with an external account at {g.xdom}, which is data exfiltration.")

def pe1(g): return (f"Linux audit: account {g.u} modified its group membership with usermod to join sudo and immediately opened a root shell on host {g.h}.", "high", "T1098", f"{g.u} added their own account to the sudo group and then became root on {g.h}.")
def pe2(g): return (f"Endpoint detection on {g.ws}: a process started by {g.u} at medium integrity now runs as NT AUTHORITY SYSTEM after a token-stealing exploit matching {g.wcve}.", "high", "T1068", f"A process of {g.u} escalated to SYSTEM on {g.ws} with an exploit matching {g.wcve}.")
def pe3(g): return (f"Linux EDR: {g.u} executed /usr/bin/{g.suid} with the setuid bit and obtained an interactive shell whose effective uid is 0 on {g.h}.", "high", "T1548", f"{g.u} abused the setuid binary {g.suid} to get a root shell on {g.h}.")
def pe4(g): return (f"Elevation without prompt: {g.u} on {g.ws} triggered {g.uacp} with a hijacked registry key, producing a high-integrity process in a standard session.", "high", "T1548", f"{g.uacp} was abused to bypass UAC and elevate privileges for {g.u} on {g.ws}.")
def pe5(g): return (f"Auditd: user {g.u} edited /etc/sudoers on {g.h} to add NOPASSWD: ALL for their own account.", "high", "T1548", f"{g.u} gave their own account passwordless sudo on {g.h}, which is privilege escalation.")
def pe6(g): return (f"Service account {g.svc} was added to the Domain Admins group on {g.h} by user {g.u} outside any change window.", "critical", "T1098", f"{g.u} added {g.svc} to Domain Admins on {g.h} outside a change window, a serious privilege escalation.")
def pe7(g): return (f"Auditd: web server account www-data spawned /bin/sh with uid=0 on {g.h} after exploiting {g.lcve}.", "critical", "T1068", f"The web account www-data became root on {g.h} by exploiting {g.lcve}.")
def pe8(g): return (f"Windows Security 4732: user {g.u} was added to the local Administrators group on {g.ws} from a non-admin session.", "high", "T1098", f"{g.u} was added to the local Administrators group on {g.ws} from a non-admin session.")
def pe9(g): return (f"dmesg on {g.h} shows a crash followed by uid=0 for the shell of {g.u}; an exploit for {g.lcve} was found in the user's home directory.", "critical", "T1068", f"{g.u} escalated to root on {g.h} using an exploit for {g.lcve}.")
def pe10(g): return (f"Sysmon: {g.uacp} spawned consent.exe with a high integrity level without a UAC prompt on {g.ws} for user {g.u}.", "high", "T1548", f"{g.uacp} spawned consent.exe with high integrity and no UAC prompt for {g.u} on {g.ws}, a UAC bypass.")

def be1(g): return (f"Access report: {g.u} authenticated to {g.h} with an SSH key from the office address {g.iip} during the 9-to-5 shift.", "low", "none", f"{g.u} used an SSH key from the office address {g.iip} during working hours, which is normal.")
def be2(g): return (f"Backup orchestrator: nightly job for {g.h} finished with status OK and shipped {g.gb} GB to storage appliance {g.iip2}.", "low", "none", f"The nightly backup from {g.h} to {g.iip2} finished normally and is routine.")
def be3(g): return (f"Patch management: {g.k} OS security updates were applied to {g.ws}; restart pending after hours.", "low", "none", f"Applying {g.k} security updates on {g.ws} is routine maintenance.")
def be4(g): return (f"Authorized vulnerability scan from the security scanner {g.iip} against subnet {g.net} during the approved maintenance window.", "low", "none", f"The scan from {g.iip} is authorized and inside the approved maintenance window, so it is not an attack.")
def be5(g): return (f"Password expiry notice: {g.u} updated their credentials on {g.h} through the self-service portal.", "low", "none", f"{g.u} changed their own password through the self-service portal, which is a normal action.")
def be6(g): return (f"One failed SSH login for user {g.u} from {g.iip} on {g.h}, followed by a successful login a few seconds later.", "low", "none", f"A single failed login followed by a success for {g.u} on {g.h} looks like a typing mistake.")
def be7(g): return (f"Sudo executed by administrator {g.u} on {g.h} to restart the {g.service} service during the scheduled change window.", "low", "none", f"{g.u} used sudo on {g.h} to restart {g.service} inside a scheduled change window, which is normal administration.")
def be8(g): return (f"Internal monitoring probe {g.iip} sent ICMP echo requests to {g.k} hosts every {g.m} minutes as part of normal availability checks.", "low", "none", f"The ICMP checks from {g.iip} are routine availability monitoring.")
def be9(g): return (f"Employee {g.u} received a newsletter from the known vendor domain {g.vend}, verified by SPF and DKIM; the link points to the vendor's official site.", "low", "none", f"The newsletter from {g.vend} passed SPF and DKIM and links to the official site, so it is legitimate.")
def be10(g): return (f"Large file transfer of {g.gb} GB from {g.h} to the approved internal backup server {g.h2} at {g.t}, as scheduled by the backup policy.", "low", "none", f"The transfer from {g.h} to the approved backup server {g.h2} follows the backup policy.")

TEMPLATES = {
    BF: [bf1, bf2, bf3, bf4, bf5, bf6, bf7, bf8, bf9, bf10],
    PS: [ps1, ps2, ps3, ps4, ps5, ps6, ps7, ps8, ps9, ps10],
    SQ: [sq1, sq2, sq3, sq4, sq5, sq6, sq7, sq8, sq9, sq10],
    PH: [ph1, ph2, ph3, ph4, ph5, ph6, ph7, ph8, ph9, ph10],
    RW: [rw1, rw2, rw3, rw4, rw5, rw6, rw7, rw8, rw9, rw10],
    EX: [ex1, ex2, ex3, ex4, ex5, ex6, ex7, ex8, ex9, ex10],
    PE: [pe1, pe2, pe3, pe4, pe5, pe6, pe7, pe8, pe9, pe10],
    BE: [be1, be2, be3, be4, be5, be6, be7, be8, be9, be10],
}
N_HOLDOUT = 2  # gabarits reserves a la validation, par categorie


# ------------------------------------------------------------------ anti-contamination
def norm_tokens(text):
    text = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", " ip ", text.lower())
    text = re.sub(r"\d+", "0", text)
    return set(re.findall(r"[a-z0]+", text))


def jaccard(a, b):
    return len(a & b) / len(a | b) if a | b else 0.0


def load_test_alerts(data_dir):
    texts = []
    for fname in ("alerts_cyber.jsonl", "alerts_soc_logs.jsonl"):
        p = data_dir / fname
        if p.exists():
            texts += [json.loads(l)["alert"] for l in open(p, encoding="utf-8") if l.strip()]
    return texts


def to_record(alert, sev, mitre, expl, cat, tname):
    target = json.dumps({"category": cat, "severity": sev, "mitre": mitre, "explanation": expl}, ensure_ascii=False)
    return {"messages": [{"role": "system", "content": SYSTEM_PROMPT},
                         {"role": "user", "content": alert_prompt(alert)},
                         {"role": "assistant", "content": target}],
            "meta": {"category": cat, "template": tname, "alert": alert}}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--n-train", type=int, default=150, help="exemples d'entrainement par categorie")
    ap.add_argument("--n-val", type=int, default=15, help="exemples de validation par categorie")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--threshold", type=float, default=0.6, help="seuil de similarite avec les jeux de test")
    ap.add_argument("--data-dir", type=Path, default=HERE / "data")
    ap.add_argument("--out-dir", type=Path, default=HERE / "data" / "finetune")
    args = ap.parse_args()

    rnd = random.Random(args.seed)
    test_sets = [norm_tokens(t) for t in load_test_alerts(args.data_dir)]
    valid_ids = load_valid_mitre(args.data_dir / "mitre_attack_ids.txt")
    seen, dropped = set(), Counter()
    train, val = [], []

    for cat, fns in TEMPLATES.items():
        for split, tpls, n_total in (("train", fns[:-N_HOLDOUT], args.n_train), ("val", fns[-N_HOLDOUT:], args.n_val)):
            target_n, made, tries = n_total, 0, 0
            while made < target_n and tries < target_n * 50:
                fn = tpls[tries % len(tpls)]
                tries += 1
                alert, sev, mitre, expl = fn(make_slots(rnd))
                key = alert.lower()
                if key in seen:
                    dropped["doublon"] += 1
                    continue
                toks = norm_tokens(alert)
                if any(jaccard(toks, t) >= args.threshold for t in test_sets):
                    dropped["trop proche d'une alerte de test"] += 1
                    continue
                assert mitre == "none" or mitre in valid_ids, f"ID MITRE invalide : {mitre}"
                assert not unsupported_entities(expl, alert), f"explication non fondee ({fn.__name__}) : {expl}"
                seen.add(key)
                (train if split == "train" else val).append(to_record(alert, sev, mitre, expl, cat, fn.__name__))
                made += 1

    rnd.shuffle(train)
    rnd.shuffle(val)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    for name, rows in (("train", train), ("val", val)):
        with open(args.out_dir / f"{name}.jsonl", "w", encoding="utf-8") as f:
            for r in rows:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")

    # controle : la reponse attendue doit etre relue correctement par le parseur de evaluate.py
    bad = 0
    for r in train + val:
        gold = json.loads(r["messages"][2]["content"])
        p = parse_alert(r["messages"][2]["content"])
        bad += not (p["format_ok"] and p["category"] == gold["category"] and p["mitre"] == (gold["mitre"] if gold["mitre"] != "none" else "none"))
    stats = {"n_train": len(train), "n_val": len(val), "seed": args.seed, "parse_errors": bad,
             "dropped": dict(dropped),
             "train_by_category": dict(Counter(r["meta"]["category"] for r in train)),
             "train_by_severity": dict(Counter(json.loads(r["messages"][2]["content"])["severity"] for r in train)),
             "val_by_category": dict(Counter(r["meta"]["category"] for r in val)),
             "holdout_templates": sorted({r["meta"]["template"] for r in val})}
    (args.out_dir / "stats.json").write_text(json.dumps(stats, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"train : {len(train)} exemples | val : {len(val)} exemples | erreurs de parsing : {bad}")
    print("supprimes :", dict(dropped) or "aucun")
    print("severites (train) :", stats["train_by_severity"])
    print("\nExemples :")
    for r in train[:4]:
        print("-", r["meta"]["alert"])
        print("   ->", r["messages"][2]["content"])
    print(f"\nFichiers ecrits dans {args.out_dir}")


if __name__ == "__main__":
    main()
