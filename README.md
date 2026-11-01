# soc-triage

10 closed-case incident reports from the [LetsDefend](https://letsdefend.io) SOC analyst platform.

Each report follows a consistent 8-section format: Alert summary · Triage questions · Investigation · IOCs (defanged) · MITRE ATT&CK · Timeline · Verdict · Containment & escalation. Where the platform's own MITRE mapping was incomplete or used a parent technique instead of the correct sub-technique, the correction is flagged inline with *(not in PDF - added)* or *(PDF lists Txxx - corrected)*.

**Analyst:** Stevan Mrkšić - [LetsDefend profile](https://app.letsdefend.io/user/slim92code)

---

## Case Index

| # | Alert | Initial Access | Category | Severity | MITRE Note |
|---|---|---|---|---|---|
| [SOC182](reports/SOC182-3cx-dll-sideloading.md) | 3CX DLL Side-Loading | Supply chain (trojanized installer) | Malware / APT | Critical | PDF omits T1195.002 and T1574.002 sub-techniques despite naming them in the alert title |
| [SOC188](reports/SOC188-pass-the-hash.md) | Pass the Hash | RDP brute force | Credential theft / Lateral movement | Critical | T1550.002 (Pass the Hash) absent from PDF despite being the named technique |
| [SOC193](reports/SOC193-ssh-backdoor.md) | SSH Backdoor | SSH brute force | Malware / Persistence | High | T1110.003 (Spraying) corrected to T1110.001 (Guessing); SSH-specific techniques added |
| [SOC203](reports/SOC203-defender-disabled.md) | Defender Disabled | RDP brute force | Defense evasion / Credential theft | Critical | T1562.001 absent from PDF despite being the alert's namesake technique |
| [SOC262](reports/SOC262-screenconnect-auth-bypass.md) | ScreenConnect CVE-2024-1709 | Exploit public-facing app (CVE-2024-1709) | Web exploit | High | T1136.001 and T1070.004 correct sub-techniques replacing parent techniques |
| [SOC272](reports/SOC272-dns-tunneling-rdp-bruteforce.md) | DNS Tunneling + RDP BF | RDP brute force + DNS exfiltration | Network / Exfiltration | Critical | T1110.003 corrected to T1110.001; collection and discovery techniques added |
| [SOC314](reports/SOC314-ntds-exfiltration.md) | NTDS.dit Exfiltration | PowerShell / Direct Volume Access | Credential dumping | Critical | T1059.001 and T1071.001 sub-techniques added; double krbtgt reset procedure documented |
| [SOC325](reports/SOC325-unauthorized-cloud-region.md) | Unauthorized Cloud Region | Credential stuffing (leaked creds) | Cloud / IAM | Low | T1110.004 (Credential Stuffing) added; host NOT isolated - analytical restraint documented |
| [SOC338](reports/SOC338-lumma-stealer-clickfix.md) | Lumma Stealer ClickFix | Phishing link + clipboard injection | Infostealer / ClickFix | Critical | T1218.005 (mshta LOLBin) absent from PDF - core ClickFix mechanism unmapped |
| [SOC343](reports/SOC343-winrar-romcom-rat.md) | WinRAR CVE-2025-8088 / RomCom | Spearphishing archive (CVE-2025-8088) | Malware / APT | High | T1203 (CVE exploitation) absent from PDF; T1036.005 and T1566.001 sub-techniques added |

---

## What this repo demonstrates

**MITRE ATT&CK precision** - every report identifies where the original platform mapping was imprecise (parent technique instead of sub-technique) or incomplete (technique entirely missing). The corrections are the analytical differentiator, not the presence of a mapping.

**Verdict discipline** - SOC325 (cloud region) was not escalated or isolated. All API calls returned HTTP 403. Isolating the host would have provided no security benefit. The report documents why - showing threat-proportionate response rather than reflexive escalation.

**IOC hygiene** - all external IP addresses, domains, and URLs are defanged per standard convention (`[.]`, `hxxps://`).

**Evidence-first reasoning** - findings are grounded in specific log sources: Sysmon event IDs, auth.log entries, proxy logs, EID 4624/4625 logon events, registry write timestamps, SHA256 hashes with VirusTotal scores.

---

## Related work

Active Directory lab and purple-team detection exercises: [github.com/slim92code/purple-team-lab](https://github.com/slim92code/purple-team-lab)

---

*All reports are self-written analyst notes based on the LetsDefend platform's case data. Raw platform PDFs are not included. LetsDefend profile serves as provenance: [app.letsdefend.io/user/slim92code](https://app.letsdefend.io/user/slim92code)*
