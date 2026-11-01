# SOC325 — Unauthorized Cloud Region Access Attempt — Incident Report

**Analyst:** Stevan Mrkšić · **Platform:** LetsDefend · **Alert:** SOC325 · **EventID:** 303 · **Date:** 2024-09-24

| Field | Value |
|---|---|
| Rule | Unauthorized Cloud Region Access Attempt |
| Severity | Low |
| Source IP | 134.209.145.73 |
| Target IP | 52.15.206.21 (AWS · Ubuntu 20.04.02) |
| Compromised account | test@letsdefend[.]io |
| Target region | Asia-Pacific Mumbai (ap-south-1) |
| All request results | HTTP 403 — Blocked by geo-restriction |
| **Verdict** | **True Positive — credential stuffing attempt; no breach; host NOT isolated** |

---

## 1. Alert summary

All API calls to AWS region ap-south-1 (Mumbai) from an external IP using account `test@letsdefend.io` were denied with HTTP 403. The source IP is a known-bad DigitalOcean proxy used in credential stuffing attacks. Threat intelligence confirms the account credentials were leaked in a data breach indexed on September 22, 2024 — two days before this alert. The geo-restriction policy blocked every request, meaning no data was accessed and no resources were provisioned. The host was deliberately not isolated — the attacker achieved nothing.

---

## 2. Triage questions

1. Did any request succeed, or were all blocked?
2. Is the source IP known-malicious?
3. How were the credentials obtained?
4. Is this region normally used by this account?
5. Does isolation of the target host provide any additional security benefit given all requests were blocked?

---

## 3. Investigation

**3.1 Threat intelligence on source IP**

- 134.209.145[.]73: AbuseIPDB **8,079 reports** from multiple sources, **100% confidence of abuse**. ISP: DigitalOcean LLC, India region. Consistently flagged for port scanning, brute force, and credential-stuffing activity against cloud management APIs.
- VirusTotal: **11/94 engines** flagged the IP as malicious.

This is not a first-time offender — the IP is among the most-reported abuse IPs for cloud API credential stuffing.

**3.2 Credential compromise intelligence**

LetsDefend threat intelligence feeds confirm that `test@letsdefend.io` credentials were published in a leaked credential dataset indexed on **September 22, 2024** — two days before this alert. This is consistent with credential-stuffing methodology: attackers acquire leaked credential lists and immediately test them against cloud management APIs using automated tooling.

**3.3 Access attempt analysis**

All requests from 134.209.145[.]73 using account `test@letsdefend.io` targeted the AWS ap-south-1 (Mumbai) region. The account's geo-restriction policy does not permit access from the Asia-Pacific Mumbai region. Every request returned **HTTP 403 (Forbidden)**:

| Request | Result |
|---|---|
| Authenticate with account test@letsdefend.io | HTTP 403 |
| Enumerate resources in ap-south-1 | HTTP 403 |
| Attempt resource creation in ap-south-1 | HTTP 403 |

No HTTP 200 responses were recorded. The attacker was not able to list, read, modify, or create any resources. The geo-restriction policy functioned as designed.

**3.4 Target host assessment**

The target IP 52.15.206[.]21 is an AWS EC2 Ubuntu 20.04.02 instance. Because all API requests were blocked before reaching the instance level, no interaction with the host's operating system or services occurred. The alert fired correctly based on the unauthorized region access pattern, but the underlying event represents a failed attack, not a successful one.

---

## 4. IOCs

| Type | Value | Notes |
|---|---|---|
| IPv4 | 134.209.145[.]73 | Attacker — DigitalOcean India; AbuseIPDB 8,079 reports / 100%; VT 11/94 |
| IPv4 | 52.15.206[.]21 | Target — AWS EC2 Ubuntu 20.04.02 (ap-south-1) |
| Account | test[@]letsdefend[.]io | Compromised via credential leak indexed Sep 22 2024 |
| Cloud region | ap-south-1 (Asia-Pacific Mumbai) | Geo-restricted; all requests blocked |

---

## 5. MITRE ATT&CK

| Tactic | Technique | Notes |
|---|---|---|
| Resource Development | T1586 — Compromise Accounts | Account test@letsdefend.io obtained via credential leak |
| Initial Access | T1078 — Valid Accounts | Valid credentials used for cloud API authentication attempt |
| Initial Access | T1078.001 — Valid Accounts: Default Accounts | Default/test account targeted *(PDF lists T1078.001)* |
| Initial Access | T1133 — External Remote Services | Cloud management API accessed from internet |
| Initial Access | T1535 — Unused/Unsupported Cloud Regions | Attempted access to geo-restricted region ap-south-1 |
| Credential Access | T1110.004 — Brute Force: Credential Stuffing | Leaked credential list used for automated API authentication *(not in PDF — added; more specific than T1078 for this attack pattern)* |

---

## 6. Timeline

| Time | Event |
|---|---|
| 2024-09-22 | Credentials for test@letsdefend.io published in leaked dataset (indexed by LetsDefend CTI) |
| 2024-09-24 | Attacker loads credential list into automated tooling |
| 2024-09-24 | API authentication requests from 134.209.145[.]73 to AWS ap-south-1 using test@letsdefend.io |
| 2024-09-24 | All requests return HTTP 403 — geo-restriction blocks access |
| 2024-09-24 | SOC325 alert fires (unauthorized region access pattern) |

---

## 7. Verdict

**True Positive — credential stuffing using leaked credentials; geo-restriction blocked all access.**

This alert is correctly classified as a True Positive: real, leaked credentials were used in a real authentication attempt from a known-malicious IP targeting a restricted cloud region. However, the impact is zero — the geo-restriction policy blocked every request and the attacker did not access, enumerate, or modify any cloud resources.

**Host NOT isolated.** The target EC2 instance (52.15.206[.]21) was not isolated. Isolating it would provide no additional security benefit: the attacker was stopped at the API level before any request reached the instance. Isolating the host in this context would cause unnecessary service disruption with no corresponding risk reduction. Analytical restraint is the correct response.

The high-priority follow-on action is credential remediation, not host containment.

---

## 8. Containment & escalation

**Priority action — credential remediation:**
- Immediately revoke or rotate the credentials for `test@letsdefend.io` — the account's password is known to the attacker.
- Audit the account's permissions: a `test` account with cloud API access represents an unnecessary attack surface. If the account is not required, disable it.
- Review AWS CloudTrail for any successful API calls from this account in the 24 hours preceding the alert — the geo-restriction blocked Mumbai, but the attacker may have also tested other regions.

**Perimeter controls:**
- Block 134.209.145[.]73 at the cloud WAF / security group level.
- Enforce MFA on all cloud management accounts — credential stuffing fails when a second factor is required.

**Preventive hardening:**
- Expand geo-restriction policy to cover all non-used AWS regions — restrict to only the specific regions this account legitimately operates in.
- Enable AWS GuardDuty or equivalent CSPM alerting for impossible travel and credential anomaly patterns.
- Integrate cloud API authentication events with SIEMfor correlation against known-breach credential lists on a continuous basis.

**No escalation required.** The attack was fully contained by existing controls. Document and close.

---

*Report part of LetsDefend SOC Analyst L2 portfolio. Analyst: Stevan Mrkšić | GitHub: slim92code*
