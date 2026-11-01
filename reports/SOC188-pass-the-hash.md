# SOC188 — Pass the Hash Attack Detected — Incident Report

**Analyst:** Stevan Mrkšić · **Platform:** LetsDefend · **Alert:** SOC188 · **EventID:** 138 · **Date:** 2023-04-18

| Field | Value |
|---|---|
| Alert name | SOC188 - Pass the Hash Attack Detected |
| Severity | Critical |
| Host | London-Server · 172.16.20.10 · Windows Server 2019 |
| Affected user | LetsDefend |
| File flagged | C:\Users\LetsDefend\Downloads\mimikatz_trunk\x64\Mimikatz.exe |
| EDR action | Detected |
| Alert time | 2023-04-18 10:36 AM |

---

## 1. Alert summary

The EDR fired on Mimikatz.exe executing on London-Server. Investigation confirmed a full attack chain: brute-force initial access, Mimikatz download and execution to dump LSASS credentials, a Pass-the-Hash (PtH) injection for a privileged account (Jack-Admin), and a PsExec lateral movement attempt toward the Domain Controller — all within 30 minutes of the attacker gaining a foothold.

---

## 2. Triage questions

**Is this a false positive?** No. Mimikatz.exe with SHA256 `61c0810a23580cf492a6ba4f7654566108331e7a4134c968c2d6a05261b2d8a1` scored 61/70 on VirusTotal. Logon Type 9 (NewCredentials) with a domain account name distinct from the interactive session user is the definitive forensic marker for a Pass-the-Hash injection. There is no legitimate use case.

**How did the attacker get in?** Remote Desktop brute force from 77.73.134[.]24 (VT 18/107 malicious; AbuseIPDB: Hacking category, Vienna, Austria). Repeated EID 4625 failures from 10:07–10:20 AM, followed by EID 4624 success at 10:25 AM for user `LetsDefend`.

**Which credential was stolen?** Jack-Admin — a domain account. The EID 4624 at 10:34:42 shows `LetsDefend` as the interactive user while `Jack-Admin` appears as the Network Account Name, confirming the hash was injected into a new logon session without the plaintext password.

**Did lateral movement succeed?** Unknown — PsExec was launched toward `\Domain_Controller` at 10:36:26, but the alert fired at that moment and no logs confirm or deny whether the DC connection completed before containment.

---

## 3. Investigation

**3.1 Initial access — RDP brute force**

Between 10:07 and 10:20 AM, the attacker at 77.73.134[.]24 generated repeated EID 4625 (logon failure) events against London-Server on RDP (3389). At 10:25 AM a successful EID 4624 logon was recorded for user `LetsDefend`. No account lockout policy was enforced.

**3.2 Malware delivery — Mimikatz via browser**

At 10:31 AM the proxy log recorded a connection from London-Server to hxxps://github[.]com/gentilkiwi/mimikatz/releases, destination 140.82.121[.]3:443. Sysmon EID 15 at 10:31:51 recorded creation of `mimikatz_trunk.zip:Zone.Identifier` (Mark-of-the-Web), confirming the file was downloaded via Chrome. The archive was extracted to `C:\Users\LetsDefend\Downloads\mimikatz_trunk\`.

**3.3 Execution and credential dumping**

At 10:32:30, Sysmon EID 1 recorded Mimikatz.exe executing under user `EC2AMAZ-ILGVOIN\LetsDefend` (Product: mimikatz, Company: gentilkiwi, version 2.2.0.0). Mimikatz's primary function at this stage was LSASS memory access — extracting credential material including the NTLM hash for `Jack-Admin`.

At 10:34:42, Sysmon EID 1 recorded `cmd.exe` spawning with parent `mimikatz.exe`, followed at 10:34:47 by `whoami.exe` (parent: `cmd.exe`) — reconnaissance within the Mimikatz session.

**3.4 Pass-the-Hash confirmation**

At 10:34:42 AM, EID 4624 logged a logon event for user `LetsDefend` with **Logon Type 9 (NewCredentials)**. The **Network Account Name field shows `Jack-Admin`** — a domain account distinct from the interactive session user. Logon Type 9 is created by `runas /netonly` or hash injection: it preserves the local user identity while substituting network credentials. This is the definitive forensic indicator of the Pass-the-Hash attack.

**3.5 Lateral movement attempt**

At 10:36:26, Sysmon EID 1 recorded PsExec.exe executing the command:

```
"C:\Users\LetsDefend\Downloads\PSTools\PsExec.exe" \\Domain_Controller cmd
```

Parent process: `powershell.exe`. This is a direct attempt to open an interactive session on the Domain Controller using the injected Jack-Admin credentials. The alert fired at this moment (10:36 AM).

---

## 4. IOCs

| Indicator | Type | Notes |
|---|---|---|
| 77.73.134[.]24 | IPv4 | Attacker — RDP brute force origin; VT 18/107 malicious |
| 172.16.20.10 | IPv4 | Victim — London-Server |
| 140.82.121[.]3 | IPv4 | GitHub CDN — Mimikatz download destination |
| `61c0810a23580cf492a6ba4f7654566108331e7a4134c968c2d6a05261b2d8a1` | SHA256 | Mimikatz.exe — 61/70 VT malicious |
| hxxps://github[.]com/gentilkiwi/mimikatz/releases | URL | Mimikatz download source |
| LetsDefend | Account | Brute-forced; used to execute Mimikatz |
| Jack-Admin | Account | PtH target; domain account hash extracted via LSASS |
| C:\Users\LetsDefend\Downloads\mimikatz_trunk\x64\Mimikatz.exe | File path | Mimikatz executable |
| C:\Users\LetsDefend\Downloads\PSTools\PsExec.exe | File path | PsExec used for lateral movement attempt |

---

## 5. MITRE ATT&CK

| Tactic | Technique | Notes |
|---|---|---|
| Initial Access | T1078.003 — Valid Accounts: Local Accounts | RDP access via brute-forced LetsDefend account *(PDF lists T1078 — .003 sub-technique is more specific)* |
| Credential Access | T1110.003 — Brute Force: Password Spraying | RDP 4625 failures 10:07–10:20 AM |
| Credential Access | T1003.001 — OS Credential Dumping: LSASS Memory | Mimikatz extracted LSASS hashes *(not in PDF — added; more specific than T1003)* |
| Lateral Movement | T1550.002 — Use Alternate Authentication Material: Pass the Hash | EID 4624 Logon Type 9, Network Account Name: Jack-Admin *(not in PDF — added; this is the named technique the alert is based on yet the PDF omits it entirely)* |
| Lateral Movement | T1021.002 — Remote Services: SMB/Windows Admin Shares | PsExec to \\Domain_Controller via SMB *(not in PDF — added)* |
| Execution | T1059.003 — Command and Scripting Interpreter: Windows Command Shell | cmd.exe spawned by Mimikatz |
| Execution | T1569.002 — System Services: Service Execution | PsExec deploys PSEXESVC.exe on target host *(not in PDF — added)* |

**Note:** T1550.002 (Pass the Hash) is the central technique this alert is named after and is absent from the PDF's MITRE mapping. The EID 4624 Logon Type 9 event is the forensic proof of this technique; it is the most important finding in the case.

---

## 6. Timeline

| Time (UTC) | Event |
|---|---|
| 10:07 AM | RDP brute force begins from 77.73.134[.]24 — EID 4625 failures start |
| 10:20 AM | Brute force failures continue |
| 10:25 AM | RDP logon success — EID 4624, user LetsDefend |
| 10:31 AM | Mimikatz downloaded from GitHub via Chrome — proxy log + EID 15 (Zone.Identifier) |
| 10:32:30 AM | Mimikatz.exe executed — Sysmon EID 1; LSASS memory accessed |
| 10:34:42 AM | cmd.exe spawned by Mimikatz — Sysmon EID 1 |
| 10:34:42 AM | **EID 4624 Logon Type 9 for Jack-Admin — Pass-the-Hash injection confirmed** |
| 10:34:47 AM | whoami.exe executed (parent: cmd.exe) — reconnaissance |
| 10:36:26 AM | PsExec.exe → \\Domain_Controller cmd — lateral movement attempt |
| 10:36 AM | EDR alert fires — SOC188 triggered |

Total time from first brute-force packet to lateral movement attempt: **~29 minutes**.

---

## 7. Verdict

**True Positive — Active compromise with lateral movement attempt.**

The attacker brute-forced RDP access, downloaded and executed Mimikatz to dump LSASS credentials, performed a confirmed Pass-the-Hash injection for a privileged domain account (Jack-Admin), and within two minutes attempted to open a remote shell on the Domain Controller via PsExec. The chain is forensically complete: brute-force evidence (EID 4625/4624), download provenance (Zone.Identifier EID 15), execution evidence (Sysmon EID 1), and the PtH-specific logon event (EID 4624 Logon Type 9 with mismatched Network Account Name).

**Severity confirmed: Critical.** Domain Controller is a direct lateral movement target. If the PsExec connection to `\\Domain_Controller` succeeded before containment, the entire domain is at risk.

---

## 8. Containment & escalation

**Immediate (within the hour):**
- Isolate London-Server from the network immediately — prevent any active PsExec session to the DC from persisting.
- Determine whether the PsExec command at 10:36:26 succeeded: check Domain Controller logs for EID 4624 Logon Type 3 from 172.16.20.10 after 10:36 AM and for PSEXESVC.exe service creation.
- Disable and reset both `LetsDefend` (brute-forced) and `Jack-Admin` (PtH target) domain accounts. Invalidate all active sessions and Kerberos tickets.
- Block 77.73.134[.]24 at perimeter firewall and check all other hosts for inbound connections from this IP.

**Escalation:** Escalate to Tier 2 / IR immediately — a hash extracted from a Windows Server 2019 domain host and used in a PtH attempt against the Domain Controller is a Tier 0 threat.

**Eradication:**
- Forensic copy of London-Server disk before reimaging to preserve the LSASS dump artifact and full Mimikatz execution context.
- Full credential rotation for all domain accounts — if the attacker had time to enumerate further hashes before the alert fired, the scope of compromised credentials is unknown.
- Enforce RDP-specific protections: IP allowlisting or VPN requirement for RDP, account lockout policy (≥5 failures → 30-minute lockout), MFA on RDP where possible.
- Deploy Credential Guard on domain-joined servers — it isolates LSASS in a virtualisation-based security boundary that Mimikatz cannot read from user-mode.

---

*Report part of LetsDefend SOC Analyst L2 portfolio. Analyst: Stevan Mrkšić | GitHub: slim92code*
