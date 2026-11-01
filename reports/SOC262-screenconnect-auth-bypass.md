# SOC262 - ScreenConnect Auth Bypass (CVE-2024-1709) - Incident Report

**Analyst:** Stevan Mrkšić · **Platform:** LetsDefend · **Alert:** SOC262 · **EventID:** 229 · **Date:** 2024-02-22

| Field | Value |
|---|---|
| Rule | ScreenConnect Authentication Bypass Exploitation Detected |
| Severity | High |
| Host | ScreenConnect Server 23.9.7 · 172.16.17.65 · Windows Server 2019 |
| Source IP | 118.69.65.60 |
| EDR Action | Allowed |
| **Verdict** | **True Positive - confirmed exploitation, rogue admin account created** |

---

## 1. Alert summary

HTTP GET to `172.16.17.65:8040/SetupWizard.aspx/` from external IP `118.69.65.60`, flagged as matching CVE-2024-1709's exploitation pattern. The endpoint is only accessible during initial ScreenConnect setup; a path-traversal bug in versions ≤ 23.9.7 allows unauthenticated re-invocation of the setup wizard post-install, bypassing all authentication and enabling arbitrary admin account creation.

---

## 2. Triage questions

1. Did the request actually succeed, or was it blocked/reset?
2. Was a new admin account created in `User.xml`?
3. Is there any post-exploitation process activity on the server?
4. Is `118.69.65.60` known-malicious or a pentest IP?
5. Is this a planned test?

---

## 3. Investigation

**3.1 Traffic analysis**

Firewall logs show four connections from `118.69.65.60` to `172.16.17.65:8040` between 13:28–13:39 on 2024-02-22. Raw log for the triggering request:

```
Request URL:           172.16.17.65:8040/SetupWizard.aspx/
User-Agent:            python-requests/2.28.1
Request Method:        GET
Device Action:         Permitted
HTTP Response Status:  200
```

HTTP 200 with no block - the request was served. User-Agent `python-requests/2.28.1` indicates an automated exploit script, not a browser. Direction: Internet → Company Network.

**3.2 Threat intelligence**

`118.69.65.60` was flagged by 8 VirusTotal engines and listed in LetsDefend threat feeds as a known malicious IP. No planned-test email found for this date.

**3.3 Endpoint - rogue account created**

EDR logs show that within 1 minute of the initial HTTP hit, ScreenConnect dropped a transient `.xml` file in `C:\Windows\Temp\ScreenConnect\23.9.7.8804\` (immediately deleted - confirmed via Security EID 4663, `ScreenConnect.Service.exe`, Access: DELETE). This is the intermediate stage file that the Huntress blog documented as recoverable via disk forensics.

`C:\Program Files (x86)\ScreenConnect\App_Data\User.xml` was then modified, adding:

```
Username:  VdEPyNT
Email:     VdEPyNT@gmail.com
Role:      Control Administrator
Created:   2024-02-22T13:40:18.7513699Z
```

`Control Administrator` is the highest ScreenConnect role - full remote access to all managed endpoints.

**3.4 Process chain**

`csc.exe` (C# compiler) spawned from `ScreenConnect.Service.exe` in `C:\Program Files (x86)\ScreenConnect\Bin\` - consistent with the exploit compiling a payload during setup-wizard abuse.

**3.5 Was the attack successful?**

Yes. HTTP 200 confirmed. Rogue admin confirmed in `User.xml`. The attacker holds a `Control Administrator` account with the ability to connect to any machine managed by this ScreenConnect instance.

---

## 4. IOCs

| Type | Value |
|---|---|
| IPv4 | 118.69.65[.]60 |
| URI | 172[.]16[.]17[.]65:8040/SetupWizard[.]aspx/ |
| Username | VdEPyNT |
| Email | VdEPyNT@gmail[.]com |
| File | C:\Program Files (x86)\ScreenConnect\App_Data\User.xml |
| File | C:\Windows\Temp\ScreenConnect\23.9.7.8804\7c2ab463-b95c-43c0-82fe-5f323f69b948.xml |
| CVE | CVE-2024-1709 |

---

## 5. MITRE ATT&CK

| Tactic | Technique | Notes |
|---|---|---|
| Initial Access | T1190 - Exploit Public-Facing Application | CVE-2024-1709 against ScreenConnect 23.9.7 |
| Persistence | T1136.001 - Create Account: Local Account | Rogue admin "VdEPyNT" in User.xml *(PDF lists T1136; .001 is more precise)* |
| Privilege Escalation | T1068 - Exploitation for Privilege Escalation | Auth bypass grants Control Administrator without credentials |
| Defense Evasion | T1070.004 - Indicator Removal: File Deletion | Temp .xml stage file deleted immediately post-exploit *(PDF maps T1562 Impair Defenses here - T1070.004 is the correct sub-technique for file deletion artifact)* |

---

## 6. Timeline

| Time (UTC) | Event |
|---|---|
| 2024-02-22 13:28 | First firewall hit: 118.69.65[.]60 → 172.16.17.65:8040 |
| 2024-02-22 13:31 | Second firewall hit |
| 2024-02-22 13:39 | Alert trigger - GET /SetupWizard.aspx/, HTTP 200, Device Permitted |
| 2024-02-22 13:40:18 | Rogue admin VdEPyNT created in User.xml |
| 2024-02-22 13:45 | EID 4663 - temp stage .xml deleted by ScreenConnect.Service.exe |

---

## 7. Verdict

**True Positive - confirmed exploitation.** The attack succeeded: HTTP 200 returned, rogue `Control Administrator` account created. The attacker holds persistent privileged access to every endpoint managed by this ScreenConnect instance. This is not a scan or an attempt - it is a completed intrusion.

Severity correctly rated **High** and stands. If this ScreenConnect instance manages production hosts, the blast radius is potentially the entire managed estate.

---

## 8. Containment & escalation

**Immediate L1 actions:**
- Host ScreenConnect Server 23.9.7 (172.16.17.65) isolated from network via EDR containment toggle.
- Delete rogue account VdEPyNT from `User.xml` before bringing the server back online.

**Escalate to L2 with:**
- Full list of all endpoints managed by this ScreenConnect instance (blast-radius scope)
- `User.xml` preserved for forensics - confirms exact creation timestamp and rogue account details
- Check ScreenConnect audit logs for any remote sessions initiated by VdEPyNT after account creation

**Remediation:**
- Patch ScreenConnect to version ≥ 23.9.8 (CVE-2024-1709 fixed)
- Block 118.69.65[.]60 at perimeter firewall
- Audit all managed endpoints for signs of lateral movement initiated from the ScreenConnect server during the 13:40–13:45 window
- Enforce MFA on all ScreenConnect admin accounts
- Restrict `/SetupWizard.aspx` endpoint access to localhost at the web server level as a defence-in-depth measure

---

*Report part of LetsDefend SOC Analyst L2 portfolio. Analyst: Stevan Mrkšić | GitHub: slim92code*
