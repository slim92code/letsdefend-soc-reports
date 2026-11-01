# SOC343 - WinRAR CVE-2025-8088 Path Traversal / RomCom RAT - Incident Report

**Analyst:** Stevan Mrkšić · **Platform:** LetsDefend · **Alert:** SOC343 · **Date:** 2025

| Field | Value |
|---|---|
| Rule | WinRAR CVE-2025-8088 Path Traversal / RomCom RAT |
| Severity | High |
| Category | Malware |
| Platform | LetsDefend |
| Threat Actor | UAC-0180 (RomCom) |
| CVE | CVE-2025-8088 |
| **Verdict** | **True Positive - Malware (RomCom RAT); persistence established; no lateral movement** |

---

## 1. Alert summary

A spearphishing email delivered a malicious archive exploiting **CVE-2025-8088**, a path traversal vulnerability in WinRAR. The archive extracted a malicious DLL (`msedges.dll`) outside its intended directory into the Windows Startup folder, establishing persistence via COM Hijacking. The malware has been attributed to **RomCom RAT**, operated by Russian-nexus APT group **UAC-0180**. The attack was contained and the threat actor did not achieve lateral movement or data exfiltration.

---

## 2. Triage questions

1. Was this a targeted spearphishing email or a broad campaign?
2. Did WinRAR extract `msedges.dll` to the Startup folder, or was the path traversal blocked?
3. Was the COM Hijack registry key actually created?
4. Is there evidence of C2 beacon activity?
5. Did the attacker achieve lateral movement?

---

## 3. Investigation

**3.1 Initial delivery - spearphishing lure**

The phishing email delivered a file named `Eli_Rosenfeld_CV.pdf` - a fake job application CV used as the archive lure. The choice of a CV as a lure is consistent with UAC-0180's documented targeting of HR personnel and executives who regularly open unsolicited CVs. The archive was a `.rar` file that appeared to contain a PDF.

**3.2 CVE-2025-8088 exploitation**

CVE-2025-8088 is a path traversal vulnerability in WinRAR affecting versions prior to the patched release. The vulnerability allows an archive to instruct WinRAR to extract files to arbitrary paths outside the intended extraction directory by using directory traversal sequences (`..\..\`) within the archived file paths. This bypasses WinRAR's intended extraction behavior and bypasses Mark-of-the-Web (MotW) protections, since the extracted file's path is crafted by the archive rather than derived from the downloaded container.

**3.3 Malicious DLL extraction**

The archive's path traversal entries caused WinRAR to extract `msedges.dll` to two locations:

1. `C:\Users\<victim>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\`
2. `C:\Users\<victim>\AppData\Local\Temp\`

Placing `msedges.dll` directly in the Startup folder gives the DLL an initial execution opportunity on the next user login. The filename `msedges.dll` is deliberately crafted to masquerade as a legitimate Microsoft Edge component (`msedge.dll` is a real Edge library) - a masquerading technique to reduce suspicion if the file is inspected.

**3.4 COM Hijacking - persistence**

The malware established persistence via COM Hijacking by writing the following registry key:

```
HKCU\SOFTWARE\Classes\CLSID\{<GUID>}\InprocServer32
Value: C:\Users\<victim>\AppData\...\msedges.dll
```

When any application activates the hijacked COM CLSID, Windows loads `msedges.dll` from the attacker-controlled path. Because this key is under `HKCU` (user hive), it does not require administrator privileges - the malware operates entirely within the user context.

**3.5 C2 activity**

Following persistence establishment, the RomCom RAT began beaconing to attacker-controlled C2 infrastructure. RomCom / Buggie / Marte is a well-documented RAT family associated with UAC-0180, with capabilities including remote command execution, credential theft, and data staging.

**3.6 Scope assessment**

Investigation found no evidence of lateral movement from the compromised host. No other hosts on the network were found with `msedges.dll` or the COM Hijack registry key. The attack was contained to a single endpoint.

---

## 4. IOCs

| Type | Value | Notes |
|---|---|---|
| Filename | Eli_Rosenfeld_CV.pdf | Phishing lure - fake CV archive |
| Filename | msedges.dll | RomCom RAT payload - masquerading as Edge library |
| Registry Key | `HKCU\SOFTWARE\Classes\CLSID\{GUID}\InprocServer32` | COM Hijack persistence key |
| Drop Path | `%APPDATA%\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\` | Startup persistence via path traversal |
| Drop Path | `%LOCALAPPDATA%\Temp\` | Secondary drop location |
| Malware Family | RomCom / Buggie / Marte | APT UAC-0180 (Russian-nexus) |
| CVE | CVE-2025-8088 | WinRAR path traversal vulnerability |

---

## 5. MITRE ATT&CK

| Tactic | Technique | Notes |
|---|---|---|
| Initial Access | T1566.001 - Phishing: Spearphishing Attachment | `Eli_Rosenfeld_CV.pdf` archive delivered via email *(PDF lists T1566 - T1566.001 more specific)* |
| Execution | T1203 - Exploitation for Client Execution | CVE-2025-8088 path traversal triggered during WinRAR extraction *(not in PDF - added; the CVE exploitation is the execution mechanism and is entirely absent from the PDF's MITRE table)* |
| Execution | T1204.002 - User Execution: Malicious File | User opened the archive |
| Persistence | T1546.015 - Event Triggered Execution: COM Hijacking | `HKCU\SOFTWARE\Classes\CLSID\{GUID}\InprocServer32` set to msedges.dll |
| Defense Evasion | T1036.005 - Masquerading: Match Legitimate Name or Location | msedges.dll masquerades as Microsoft Edge library *(PDF lists T1036 - T1036.005 more specific)* |

---

## 6. Timeline

| Event | Detail |
|---|---|
| Phishing email delivered | Archive containing Eli_Rosenfeld_CV.pdf lure |
| User opens archive in WinRAR | CVE-2025-8088 path traversal triggers on extraction |
| msedges.dll extracted to Startup folder | `%APPDATA%\...\Startup\msedges.dll` |
| msedges.dll extracted to Temp | `%LOCALAPPDATA%\Temp\msedges.dll` |
| COM Hijack registry key written | `HKCU\...\CLSID\{GUID}\InprocServer32` → msedges.dll |
| Next COM activation / user login | msedges.dll loaded - RomCom RAT active, C2 beacon starts |

---

## 7. Verdict

**True Positive - Malware (RomCom RAT)**

The alert correctly identified exploitation of CVE-2025-8088 via spearphishing. Persistence was established through COM Hijacking (T1546.015). No evidence of lateral movement or data exfiltration was found. Threat attributed to APT group UAC-0180 with high confidence based on malware family and TTPs.

---

## 8. Containment & escalation

**Immediate containment:**
- Isolate affected endpoint from network
- Block C2 IP/domain at perimeter firewall
- Invalidate user session tokens

**Eradication:**

```cmd
:: Remove malicious DLL from both drop locations
del /f "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\msedges.dll"
del /f "%LOCALAPPDATA%\Temp\msedges.dll"

:: Remove COM Hijack registry key
reg delete "HKCU\SOFTWARE\Classes\CLSID\{<GUID>}" /f
```

**Verification:**
- Confirm registry key deleted: `reg query HKCU\SOFTWARE\Classes\CLSID\{GUID}`
- Confirm DLL removed from both paths
- Full AV/EDR scan on affected host

**Recovery:**
1. Patch WinRAR to latest version (CVE-2025-8088 fixed in ≥ 7.x)
2. Reset user credentials (assume compromised)
3. Review email gateway - consider blocking `.rar` attachments from external senders if business justification allows
4. Re-enable endpoint in network after clean scan

**Detection hardening:**

| Source | Signal |
|---|---|
| Sysmon EID 11 | File created in `%STARTUP%` by WinRAR process |
| Sysmon EID 13 | Registry write to `HKCU\...\CLSID\{GUID}\InprocServer32` |
| Sysmon EID 1 | `winrar.exe` spawning unexpected child processes |
| Email Gateway | Archive attachment containing DLL in path with `..\..\` traversal |
| AV/EDR | Hash match - `msedges.dll` (romcom/buggie/marte family) |

---

*Report part of LetsDefend SOC Analyst L2 portfolio. Analyst: Stevan Mrkšić | GitHub: slim92code*
