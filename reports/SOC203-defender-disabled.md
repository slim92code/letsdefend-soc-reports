# SOC203 - Microsoft Defender Real-Time Protection Disabled - Incident Report

**Analyst:** Stevan Mrkšić · **Platform:** LetsDefend · **Alert:** SOC203 · **EventID:** 154 · **Date:** 2023-05-31

| Field | Value |
|---|---|
| Alert name | SOC203 - Microsoft Defender Real-time protection was disabled (Possible Malware Activity) |
| Severity | High → **Critical** (reassessed, see §7) |
| Host | Richard · 172.16.17.89 · Windows 10 · Domain: LetsDefend |
| EDR action | Disabled |
| Alert time | 2023-05-31 09:14 AM |
| Alert trigger | EventID 5001 - Defender real-time protection scanning was disabled |

---

## 1. Alert summary

Defender's real-time protection was disabled on the Windows 10 host Richard at 09:14 AM. Logs show the disabling was preceded by a successful RDP brute-force login from 146.70.45.86 two minutes earlier. After disabling Defender, the attacker downloaded and executed LaZagne - an open-source credential harvesting tool - and ran it against all local password stores, writing the output to the Desktop. Credentials from all applications stored on the host are presumed compromised.

---

## 2. Triage questions

**Is this a false positive?** No. The sequence is unambiguous: external RDP brute force → successful login → Defender disabled → credential harvester downloaded and executed. Each step is corroborated by separate log sources (OS logs, proxy logs, Sysmon EID 1).

**Who disabled Defender?** The Windows Defender Operational log (EventID 5001) records `Username: SYSTEM` - this is expected behaviour: the Defender service runs as SYSTEM and logs its own state changes under that account. The disabling was triggered by the attacker's RDP session as Richard.

**Did the credential harvest succeed?** Yes. The LaZagne command `LaZagne.exe all -oA -output C:\Users\Richard\Desktop` ran to completion at 09:17:24 AM. The output file was not visible during the RDP investigation session because the analyst connected as a different user (`LetsDefend`), not as `Richard`. The file's existence is confirmed by the process execution chain.

**Did the malware spread to other hosts?** No. LaZagne's SHA256 was searched across all endpoints in Endpoint Security and was found only on Richard (172.16.17.89).

**Is 146.70.45.86 a known malicious IP?** Low reputation but not confirmed at time of alert: VT 0/87 (clean), AbuseIPDB 1 report (Web App Attack category, filed one month prior), ISP M247 Europe SRL (Miami, FL - data center/hosting provider). The brute-force behaviour in the logs is the decisive evidence.

---

## 3. Investigation

**3.1 Initial access - RDP brute force**

OS logs show repeated RDP authentication failures from 146.70.45.86 to 172.16.17.89 (port 3389). All failures returned error code `0xC000006A` ("user name is correct but the password is wrong"), confirming the attacker had already enumerated a valid username (`Richard`) and was guessing the password. The first five attempts failed. At **09:12 AM**, EID 4624 with **Logon Type 10 (RemoteInteractive / RDP)** was recorded for user `Richard`, source IP 146.70.45.86 - the brute force succeeded.

**3.2 Defense evasion - Defender disabled**

At **09:14 AM**, EventID 5001 was written to `Applications and Services → Microsoft → Windows → Windows Defender → Operational`:

```
Username: SYSTEM
Product: Microsoft Defender Antivirus
EventID: 5001
Event Name: Microsoft Defender Antivirus Real-time Protection scanning for malware and other potentially unwanted software was disabled
```

This event triggered the SOC203 alert. Disabling Defender was the attacker's prerequisite for running a credential harvester that would otherwise be detected and blocked.

**3.3 Tool delivery - LaZagne via browser**

At **09:15:46 AM**, Sysmon EID 1 recorded `chrome.exe` executing with a referrer URL of `hxxps://github[.]com/AlessandroZ/LaZagne/releases` and a target file of `C:\Users\Richard\Downloads\LaZagne.exe`. The proxy log confirms the outbound request at **09:16 AM** to GitHub CDN.

**LaZagne.exe SHA256:** `3CC5EE93A9BA1FC57389705283B760C8BD61F35E9398BBFA3210E2BECF6D4B05`
VirusTotal: **46/70 malicious** (family labels: lazagne, hacktool, trojan, pua).

**3.4 Execution and credential harvest**

At **09:16:23 AM**, `cmd.exe` was opened (`C:\Windows\System32\cmd.exe`, user: Richard).

At **09:17:24 AM**, Sysmon EID 1 recorded LaZagne executing with the command:

```
LaZagne.exe all -oA -output C:\Users\Richard\Desktop
```

- `all` - targets every supported application module
- `-oA` - writes output in all formats (normal text, JSON, and combined)
- `-output C:\Users\Richard\Desktop` - writes credential files to the Desktop

The command ran under user `Richard`. Credential output files were written to `C:\Users\Richard\Desktop\` and contain stored passwords for all applications LaZagne's modules support. The files were not visible during remote investigation because the analyst's RDP session was authenticated as a different user.

---

## 4. IOCs

| Indicator | Type | Notes |
|---|---|---|
| 146.70.45[.]86 | IPv4 | Attacker - RDP brute force origin; VT 0/87; AbuseIPDB 1 report (Web App Attack), data center IP |
| 172.16.17.89 | IPv4 | Victim - Richard (Windows 10) |
| `3CC5EE93A9BA1FC57389705283B760C8BD61F35E9398BBFA3210E2BECF6D4B05` | SHA256 | LaZagne.exe - 46/70 VT malicious |
| hxxps://github[.]com/AlessandroZ/LaZagne/releases | URL | LaZagne download source |
| C:\Users\Richard\Downloads\LaZagne.exe | File path | LaZagne executable |
| C:\Users\Richard\Desktop\ | Path | Credential output dump location |
| Richard | Account | Brute-forced RDP account |

---

## 5. MITRE ATT&CK

| Tactic | Technique | Notes |
|---|---|---|
| Initial Access | T1133 - External Remote Services | RDP exposed to internet, brute-forced |
| Credential Access | T1110.001 - Brute Force: Password Guessing | Error 0xC000006A confirms username known, password guessed *(PDF lists T1110 - T1110.001 is more specific)* |
| Defense Evasion | T1562.001 - Impair Defenses: Disable or Modify Tools | Defender real-time protection disabled via EventID 5001 *(not in PDF - added; this is the technique the alert is named for and is entirely absent from the PDF's MITRE table)* |
| Execution | T1059.003 - Command and Scripting Interpreter: Windows Command Shell | cmd.exe used to run LaZagne *(PDF lists T1059 - T1059.003 is more specific)* |
| Credential Access | T1555 - Credentials from Password Stores | LaZagne harvests all local application password stores |

**Note:** T1562.001 (Impair Defenses: Disable or Modify Tools) is the technique this alert is built to detect - the alert name literally says "Defender Real-Time Protection Was Disabled" - yet it does not appear anywhere in the PDF's MITRE mapping. It is the first thing the attacker did after gaining access and is the precondition for the credential harvest succeeding.

---

## 6. Timeline

| Time | Event |
|---|---|
| ~09:07 AM | RDP brute force begins from 146.70.45[.]86 - EID 4625 failures, error 0xC000006A |
| 09:12 AM | RDP login success - EID 4624 Logon Type 10 (RemoteInteractive), user Richard |
| 09:14 AM | Defender real-time protection disabled - EventID 5001; **SOC203 alert fires** |
| 09:15:46 AM | Chrome downloads LaZagne from GitHub (Sysmon EID 1, referrer: GitHub LaZagne releases) |
| 09:16 AM | Proxy log confirms outbound LaZagne download request |
| 09:16:23 AM | cmd.exe opened under user Richard |
| 09:17:24 AM | **LaZagne.exe executed: `all -oA -output C:\Users\Richard\Desktop`** - credential harvest runs |

Total time from first brute-force attempt to credential dump: approximately **10 minutes**.

---

## 7. Verdict

**True Positive - Confirmed endpoint compromise with successful credential theft.**

**Severity reassessed: Critical.** The PDF rates this High. The attack chain is complete and successful: the attacker brute-forced RDP access, disabled the only local defence, downloaded and ran a credential harvester against every password store on the host, and wrote the output to disk. Every credential stored in browsers, email clients, and other applications on Richard's Windows 10 machine must be treated as compromised. The risk is elevated further by the fact that this is a domain-joined endpoint - any domain credentials cached locally are now in the attacker's hands.

---

## 8. Containment & escalation

**Immediate:**
- Isolate Richard (172.16.17.89) from the network immediately via Endpoint Security containment.
- Block 146.70.45[.]86 at perimeter firewall and search all other endpoints for inbound connections from this IP.
- Force-reset the `Richard` domain account and invalidate all active sessions. Treat every credential previously stored in Richard's browser or applications as compromised - notify affected service owners.
- Recover the LaZagne output files from `C:\Users\Richard\Desktop\` before reimaging - they confirm exactly which credentials were exfiltrated.

**Escalation:** Escalate to Tier 2 / IR. The credential output covers all applications on the host; the scope of impacted accounts is unknown until the output files are reviewed. Any domain credentials in the dump represent a potential lateral movement path.

**Eradication:**
- Reimage Richard after forensic collection. Sysmon logs and the LaZagne output files are the key artefacts to preserve.
- Re-enable Defender and audit all endpoints for EventID 5001 in the Windows Defender Operational log over the past 30 days.

**Hardening:**
- RDP must not be exposed directly to the internet. Place it behind a VPN or restrict to known management IPs only. Implement account lockout for RDP (≥5 failures → lockout).
- Enforce MFA on all remote access paths.
- Protect Defender settings: use Tamper Protection (prevents modification without MFA/admin approval) and enforce via Intune or Group Policy to require administrator elevation to disable real-time protection.
- Monitor for EventID 5001 as a high-priority alert in isolation - Defender being disabled is nearly always malicious or a serious misconfiguration and warrants immediate triage.

---

*Report part of LetsDefend SOC Analyst L2 portfolio. Analyst: Stevan Mrkšić | GitHub: slim92code*
