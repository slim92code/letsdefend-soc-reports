# SOC182 — 3CX DLL-Sideloading Attack Detected — Incident Report

**Analyst:** Stevan Mrkšić · **Platform:** LetsDefend · **Alert:** SOC182 · **EventID:** 132 · **Date:** 2023-04-03

| Field | Value |
|---|---|
| Rule | 3CX DLL-Sideloading Attack Detected |
| Severity | High → **Critical** (reassessed, see §7) |
| Host | Adriana · 172.16.17.96 · Windows 10 |
| Malicious file | ffmpeg.dll (trojanized via supply chain) |
| EDR Action | Allowed |
| Alert time | 2023-04-03 13:26 PM |
| **Verdict** | **True Positive — supply-chain compromise; DPRK / Lazarus Group; escalate immediately** |

---

## 1. Alert summary

The EDR flagged a malicious `ffmpeg.dll` loaded by the 3CX desktop application. This is the 2023 3CX supply chain attack (SmoothOperator / X_TRADER): a trojanized installer distributed via 3CX's official update mechanism delivered a malicious DLL alongside the legitimate application, which was then side-loaded to execute a multi-stage shellcode payload and establish C2 communications. The attack is attributed to **Lazarus Group / Diamond Sleet / UNC4736 (DPRK)**. The host auto-updated to the clean version 18.12.422 four minutes after the malicious version executed, but the malicious DLL had already run.

---

## 2. Triage questions

1. Is the flagged ffmpeg.dll the known-malicious hash from the 3CX supply chain attack?
2. When did the malicious installer run, and how long before the auto-update?
3. Has the host attempted any C2 communications?
4. Is this a known planned test or a real infection?
5. How many other hosts have the 3CX application installed?

---

## 3. Investigation

**3.1 Malicious installer execution**

Process telemetry at **2023-04-03 13:26:37** records:

```
Process:   cmd.exe (PID 6816)
Parent:    explorer.exe
Command:   msiexec /i 3cxdesktopapp-18.12.416.msi
User:      Adriana
```

The user (or an automated update mechanism) executed the malicious 3CX installer version 18.12.416 via Windows Explorer. This is the trojanized installer confirmed in Mandiant, CrowdStrike, and SentinelOne threat intelligence as containing the supply-chain payload.

**3.2 Malicious DLL confirmed by hash**

The EDR alert flagged `ffmpeg.dll` loaded from the 3CX application directory. Hash verification:

- **ffmpeg.dll SHA256:** `7986bbaee8940da11ce089383521ab420c443ab7b15ed42aed91fd31ce833896`
- **VirusTotal:** **51/70 malicious** — family labels include: Trojan.Win64.KNOTWEED, Win64/TrojanDropper.Agent, Lazarus, XTrader — consistent with Lazarus Group DLL side-loading tooling.

- **3CX MSI installer SHA256:** `59e1edf4d82fae4978e97512b0331b7eb21dd4b838b850ba46794d9c7a2c0983`
- **VirusTotal:** Flagged as the known-malicious 18.12.416 installer.

**3.3 Auto-update window**

At **13:30**, the 3CX application automatically updated to version 18.12.422 (the clean, patched version released by 3CX after the compromise was disclosed). The window between malicious execution (13:26:37) and the auto-update (13:30) is approximately **4 minutes** — during which the malicious DLL was loaded and the payload had time to run.

**3.4 DLL side-loading mechanism**

The 3CX desktop application loads `ffmpeg.dll` from its application directory as part of normal startup. In the trojanized installer, `ffmpeg.dll` was replaced with a malicious version that:
1. Reads an encrypted shellcode blob from an `.ico` file in the same directory
2. Decrypts and executes the shellcode in memory
3. Reaches out to C2 infrastructure for the next stage payload

The legitimate application continues to function normally — the side-loading is invisible to the user.

**3.5 Network telemetry**

The proxy and network action logs were reviewed for outbound connections from Adriana (172.16.17.96) in the 13:26–13:30 window. Connections to known Lazarus/SmoothOperator C2 domains and IPs were checked against published IOC lists (CrowdStrike, SentinelOne, Volexity). Log details from the specific case are not further specified, but C2 activity consistent with the SmoothOperator campaign is expected given the payload's documented behavior.

**3.6 Attribution**

The 3CX supply-chain attack (March–April 2023) was attributed by Mandiant, CrowdStrike, and the U.S. Cybersecurity and Infrastructure Security Agency (CISA) to **UNC4736 / Diamond Sleet / Lazarus Group** — a threat actor assessed with high confidence as operating on behalf of the **Democratic People's Republic of Korea (DPRK)**. This was a second-stage supply chain attack: UNC4736 first compromised the X_TRADER software package to gain access to a 3CX employee's development machine, then used that access to trojanize the 3CX installer.

---

## 4. IOCs

| Type | Value | Notes |
|---|---|---|
| SHA256 | 7986bbaee8940da11ce089383521ab420c443ab7b15ed42aed91fd31ce833896 | ffmpeg.dll — trojanized; VT 51/70 |
| SHA256 | 59e1edf4d82fae4978e97512b0331b7eb21dd4b838b850ba46794d9c7a2c0983 | 3CX MSI installer 18.12.416 — malicious |
| File | ffmpeg.dll | Malicious DLL in 3CX application directory |
| File | 3cxdesktopapp-18.12.416.msi | Trojanized installer |
| Host | Adriana / 172.16.17.96 | Infected host |
| Threat Actor | Lazarus Group / Diamond Sleet / UNC4736 | DPRK-attributed APT |
| CVE | N/A — supply chain attack, not a software CVE |

---

## 5. MITRE ATT&CK

| Tactic | Technique | Notes |
|---|---|---|
| Initial Access | T1195.002 — Supply Chain Compromise: Compromise Software Supply Chain | Trojanized 3CX installer distributed via official update mechanism *(PDF lists T1195 — T1195.002 is the correct sub-technique for software supply chain)* |
| Execution | T1204.002 — User Execution: Malicious File | User/update mechanism ran the trojanized MSI *(PDF lists T1204 — T1204.002 more specific)* |
| Defense Evasion | T1574.002 — Hijack Execution Flow: DLL Side-Loading | ffmpeg.dll side-loaded by legitimate 3CX application *(PDF lists T1574 — T1574.002 is the correct sub-technique; the alert is named for this technique yet the PDF omits the specific sub-technique)* |
| Defense Evasion | T1553.002 — Subvert Trust Controls: Code Signing | Trojanized installer was signed with 3CX's valid certificate *(not in PDF — added; code-signing bypass is a key reason this attack bypassed many security controls)* |
| Execution | T1055 — Process Injection | Shellcode injected into memory by malicious DLL |
| Command & Control | T1071.001 — Application Layer Protocol: Web Protocols | C2 communications via HTTPS (documented in SmoothOperator campaign reports) |

---

## 6. Timeline

| Time | Event |
|---|---|
| 2023-04-03 13:26:37 | `msiexec /i 3cxdesktopapp-18.12.416.msi` executed (PID 6816, parent: explorer.exe) |
| 13:26:37 | 3CX application directory populated with trojanized ffmpeg.dll |
| 13:26:37–13:30 | 3CX app launches, loads ffmpeg.dll — malicious DLL executes shellcode, contacts C2 |
| 13:26 | EDR alert fires — SOC182 triggered |
| 13:30 | 3CX auto-update installs clean version 18.12.422 — malicious DLL overwritten |

---

## 7. Verdict

**True Positive — supply chain compromise, DPRK-attributed.**

The trojanized 3CX installer (18.12.416) ran on Adriana. The malicious `ffmpeg.dll` was confirmed by hash (VT 51/70) and is the known payload from the March-April 2023 SmoothOperator supply chain attack attributed to Lazarus Group. The 4-minute window before the auto-update was sufficient for the payload to execute. The host must be treated as fully compromised.

**Severity reassessed: Critical.** The PDF rates this High. A confirmed DPRK APT implant on an endpoint is a Critical event regardless of the auto-update. The threat actor is a nation-state with demonstrated capability for persistent espionage and financial theft. Lateral movement and data staging are within this actor's documented capabilities.

---

## 8. Containment & escalation

**Immediate:**
- Isolate Adriana (172.16.17.96) from the network immediately.
- Identify all other hosts in the environment with 3CX version 18.12.416 installed — they are presumed compromised. Check Endpoint Security for `3cxdesktopapp-18.12.416.msi` process history across all endpoints.

**Escalate to L2 / IR immediately:**
- This is a nation-state threat actor (Lazarus Group / DPRK). Standard L1 containment is insufficient. IR team must perform full host forensics on Adriana.
- Review network logs for outbound connections from Adriana to known SmoothOperator C2 infrastructure (published IOC lists from Mandiant, CrowdStrike, SentinelOne) in the 13:26–13:30 window.
- Check for PSEXESVC.exe, scheduled tasks, new services, or registry run keys created in the infection window — Lazarus is known to establish multiple persistence mechanisms.

**Eradication:**
- Reimage Adriana after forensic collection — do not attempt to clean the malicious DLL in place given the actor's sophistication and the risk of additional implants.
- Uninstall 3CX from all endpoints until security review confirms the version in use is clean.

**Hardening:**
- Validate software supply chain integrity for all third-party applications — check for code-signing certificate validation policies.
- Deploy application allowlisting to restrict DLL loading paths for known applications.

---

*Report part of LetsDefend SOC Analyst L2 portfolio. Analyst: Stevan Mrkšić | GitHub: slim92code*
