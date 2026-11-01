# SOC272 - DNS Tunneling / RDP Brute Force + Exfiltration - Incident Report

**Analyst:** Stevan Mrkšić · **Platform:** LetsDefend · **Alert:** SOC272 · **EventID:** 246 · **Date:** 2024-04-04

| Field | Value |
|---|---|
| Rule | Possible DNS Tunneling Detected |
| Severity | High → **Critical** (reassessed, see §7) |
| Host | Shirley · 172.16.20.191 · Windows 10 |
| Source IP (brute force) | 185.107.56.136 |
| Dest IP (DNS exfil) | 60.216.3.126 |
| Protocol | DNS (port 53) |
| EDR Action | N/A - endpoint unmanaged at time of detection |
| **Verdict** | **True Positive - confirmed compromise, data exfiltration executed** |

---

## 1. Alert summary

~20 DNS queries from Shirley (172.16.20.191) to 60.216.3.126:53 within 2 minutes, triggering the volumetric DNS rule. The L1 analyst note flagged that a brute-force attempt had been seen against the same host minutes earlier. The two are connected: the DNS volume is the endpoint of an RDP brute-force → initial access → defense evasion → exfiltration chain.

---

## 2. Triage questions

1. How many DNS queries, to what destination, and in what time window?
2. Is 60.216.3.126 a legitimate DNS server or a known-bad IP?
3. What was the brute-force source and did it succeed?
4. What commands did the attacker run after gaining access?
5. What data was being exfiltrated, and how?

---

## 3. Investigation

**3.1 DNS traffic volume**

Firewall logs: 172.16.20.191 → 60.216.3.126:53 (UDP), 20 connections in the 10:03–10:04 window, all outbound (Company Network → Internet). Each connection originates on a high ephemeral port from the endpoint.

**3.2 Threat intelligence on 60.216.3.126**

- AbuseIPDB: 3,554 reports from 329 distinct sources, 100% confidence of abuse. Recent report categories: SSH Brute-Force, SMTP abuse. ISP: Shandong WanDeFu (China Unicom), Jinan, China.
- VirusTotal: 10/90 engines flagged (Abuse, BitDefender=Phishing, CyRadar=Malicious, Fortinet=Malware, CriminalIP=Malicious, SOCRadar=Malicious).

Not a legitimate DNS server.

**3.3 RDP brute force - initial access**

Firewall logs (dest port 3389) from 185.107.56.136 to 172.16.20.191, starting 09:54 AM:

- 09:54 AM: EventID 4625 - logon failure, error `0xC000006A` ("user name is correct but the password is wrong"), username: `LetsDefend`.
- Repeated attempts 09:54–09:58 AM.
- 09:58 AM: EventID 4624 - **successful logon**, Logon Type 10 (RemoteInteractive/RDP), username: `LetsDefend`, source: 185[.]107.56.136.

Brute force succeeded. The attacker now has an authenticated interactive session.

**3.4 Post-compromise terminal history (09:58–10:04 AM)**

Endpoint Security terminal history for Shirley, in order:

| Time | Command | Purpose |
|---|---|---|
| 09:58:36 | `whoami /groups` | Enumerate user/group membership |
| 09:59:02 | `cd C:\Windows\System32\config` | Navigate to SAM/SYSTEM hives |
| 09:59:28 | `Get-Content .\SavedConfigHash.txt` | Read credential hash file |
| 09:59:44 | `Get-Content .\ConsoleHost_history.txt` | Read PowerShell command history (credential hunting) |
| 10:00:19 | `cd C:\Users\LetsDefend\AppData\Local\Google\` | Browse Chrome profile data (saved passwords) |
| 10:00:34 | `Set-MpPreference -DisableRealtimeMonitoring $true; Set-MpPreference -DisableScriptScanning 1; netsh firewall set opmode disable; netsh Advfirewall set allprofiles state off` | **Disable Defender real-time + script scanning + Windows Firewall entirely** |
| 10:00:42 | `cd C:\Users\LETSDE~1\Downloads` | Navigate to staging dir |
| ~10:00 | `New-Item -Path "...\Downloads\test.txt" -ItemType file` | Create staging file |
| ~10:03 | `.\test.py` | **Execute DNS tunneling exfiltration script** |

**3.5 The exfiltration script (test.py)**

Python script found in `C:\Users\LETSDE~1\Downloads\`:
- Opens a raw UDP socket
- Breaks data into 62-byte chunks
- Encodes each chunk in a DNS query packet (`www.example.com` as the domain label carrier)
- Sends to `60.216.3.126:53`, 10 iterations, with `time.sleep(0.1)` between each packet

This is textbook DNS data exfiltration - data encoded in the query payload, generating high-volume DNS traffic to a non-DNS IP. Wireshark capture confirms uniform 138-byte DNS packets from the endpoint, with exfiltrated text visible in the hex dump.

---

## 4. IOCs

| Type | Value |
|---|---|
| IPv4 (brute force / RDP) | 185[.]107.56.136 |
| IPv4 (DNS exfil destination) | 60[.]216.3.126 |
| Host | Shirley / 172.16.20.191 |
| Compromised account | LetsDefend |
| File | C:\Users\LETSDE~1\Downloads\test.py |
| File | C:\Users\LETSDE~1\Downloads\test.txt |

---

## 5. MITRE ATT&CK

| Tactic | Technique | Notes |
|---|---|---|
| Initial Access | T1133 - External Remote Services | RDP (3389) exposed to internet |
| Initial Access | T1078 - Valid Accounts: Default Accounts | Account `LetsDefend` brute-forced |
| Credential Access | T1110.001 - Brute Force: Password Guessing | ~4 mins, multiple EID 4625 events before success *(PDF lists T1110.003 Password Spraying - corrected; 0xC000006A confirms same username tested repeatedly, which is Guessing, not Spraying)* |
| Collection | T1005 - Data from Local System | SAM hive path, PowerShell history, Chrome AppData browsed *(not in PDF - added)* |
| Discovery | T1033 - System Owner/User Discovery | `whoami /groups` *(not in PDF - added)* |
| Execution | T1059.001 - PowerShell | Defender disable commands |
| Execution | T1059.006 - Python | `test.py` DNS exfil script |
| Defense Evasion | T1562.001 - Disable or Modify Tools | `Set-MpPreference -DisableRealtimeMonitoring $true` |
| Defense Evasion | T1562.004 - Disable or Modify System Firewall | `netsh Advfirewall set allprofiles state off` |
| Exfiltration | T1048.003 - Exfiltration Over Alt Protocol: Non-C2 | Data chunked into UDP/DNS packets to 60.216.3.126:53 |

---

## 6. Timeline

| Time | Event |
|---|---|
| 2024-04-04 09:54 AM | RDP brute force begins, 185.107.56.136 → Shirley:3389 |
| 09:54–09:57 AM | Multiple EID 4625 failures (valid username, wrong password) |
| 09:58 AM | EID 4624 - successful RDP logon, user `LetsDefend` |
| 09:58–10:00 AM | Attacker enumerates groups, reads SAM path, PS history, Chrome data |
| ~10:00 AM | Defender + firewall disabled via PowerShell |
| ~10:00–10:03 AM | test.py downloaded/created in Downloads, test.txt staged |
| 10:03–10:04 AM | DNS exfiltration: 20 queries to 60.216.3.126:53 in 2 minutes |
| 10:04 AM | SOC272 alert fires |

---

## 7. Verdict

**True Positive - confirmed full-chain attack.**

The DNS tunneling alert is the final stage of a 10-minute attack: RDP brute force → valid account compromised → credential collection → defense evasion → data exfiltration.

**Severity reassessed to Critical.** The original alert is "High" for DNS volume alone. Accounting for: (1) successful RDP brute-force on an internet-exposed port, (2) Defender and firewall completely disabled, (3) active data exfiltration confirmed, the correct severity is Critical.

The two attacker IPs are distinct (185.107.56.136 for RDP, 60.216.3.126 for DNS exfil) - the attacker likely used separate infrastructure for initial access and data collection, a common OpSec pattern.

---

## 8. Containment & escalation

**Immediate L1 actions:**
- Host Shirley (172.16.20.191) isolated via endpoint containment.

**Escalate to L2 with:**
- `test.py` preserved for malware analysis - the full script and its target IP
- Confirm what data was in scope at time of exfiltration (files in the LetsDefend user profile, Chrome saved passwords, PS history contents)
- Scope of the `LetsDefend` account - what other systems can it authenticate to?
- Check for any other hosts that communicated with 185.107.56.136 or 60.216.3.126
- Full disk image of Shirley before any remediation

**Remediation:**
- Disable or firewall-restrict RDP (3389) - must not be internet-accessible
- Enforce account lockout policy (EID 4625 events over 4 minutes should have locked the account before success)
- Force password reset for `LetsDefend` account and audit all accounts on the host
- Remove `test.py` and `test.txt`; re-enable Defender and firewall before bringing the host back online
- Block 185.107.56.136 and 60.216.3.126 at the perimeter; hunt for same IPs in logs across all hosts

---

*Report part of LetsDefend SOC Analyst L2 portfolio. Analyst: Stevan Mrkšić | GitHub: slim92code*
