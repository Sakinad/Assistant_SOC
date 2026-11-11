# Simulated Attack Log

**Environment:** Wazuh manager (`192.168.56.10`), Wazuh agent `victime-ubuntu`. Attacks were launched from Kali Linux and directly on the target machine.

## Alert Summary

| **Date** | **Attack** | **Rule ID** | **Level** | **MITRE ATT&CK Technique** |
|---|---|---:|---:|---|
| 11/11 | Suspicious account creation | 5902 | 8 | T1136 |
| 11/11 | Suspicious account deletion | 5903 | 3 | T1136 |
| 11/11 | Successful sudo execution | 5402 | 3 | T1548 |
| 11/11 | File modification (FIM) | 550 | 7 | T1565 |
| 11/11 | SSH brute-force attempts (failed logins) | 5760 | 5 | T1110 |

## Attack Details

### 1. SSH Brute-Force Attack (T1110)

**Command (executed from Kali Linux):**

```bash
hydra -l root -P mots.txt -t 4 ssh://<target-ip>
```

**Result:** Repeated alerts were generated, including:

- `sshd: authentication failed` (Rule ID: 5760)
- `PAM: User login failed` (Rule ID: 5503)

These alerts indicate repeated failed SSH authentication attempts.

### 2. Suspicious Account Creation and Deletion (T1136)

**Commands:**

```bash
sudo useradd hacker
sudo userdel hacker
```

**Result:** Wazuh generated the following alerts:

- `New user added to the system` (Rule ID: 5902)
- `Group (or user) deleted from the system` (Rule ID: 5903)

These events demonstrate the monitoring of user account creation and deletion.

### 3. Successful Sudo Execution (T1548)

**Command:**

```bash
sudo ls
```

**Result:** Wazuh generated the alert:

- `Successful sudo to ROOT executed` (Rule ID: 5402)

This event records a successful command execution using elevated privileges.

### 4. File Integrity Monitoring (FIM) (T1565)

A file monitored by Wazuh Syscheck was modified.

**Result:** Wazuh generated the following alert:

- `Integrity checksum changed` (Rule ID: 550)
- **Alert level:** 7

This was the highest alert level observed during these simulations.
