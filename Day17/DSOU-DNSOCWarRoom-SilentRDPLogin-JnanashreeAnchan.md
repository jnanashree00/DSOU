# SOC Triage Report
### SOC-2026-1005-01 | Operation Silent RDP Login

**Analyst:** Jnanashree Anchan | **Program:** GraySentinel DSOU | **Date:** 5 October 2026

---

## Alert Details

| Field | Value |
|---|---|
| **Alert ID** | SOC-2026-1005-01 |
| **Rule** | Multiple failed RDP logons followed by a successful RemoteInteractive logon, a privileged session, PowerShell, and an outbound connection |
| **Severity** | Critical |
| **Host** | HR-WS-017 (HR workstation) |
| **Platform** | Wazuh SIEM, Windows Security, Sysmon, PowerShell logging |
| **CVE / CVSS** | Not applicable. This is credential and access abuse, behavior based. |

---

## Verdict

**Confirmed suspicious. This is not a simple brute force to dismiss or a false positive. Failed RDP attempts, then a successful RemoteInteractive logon, a privileged session, PowerShell, and an outbound connection is hands-on-keyboard access, and the employee denies using RDP, which points to a compromised account. Do NOT close this as brute force noise and do NOT wait. Isolate HR-WS-017 and preserve the live session before the attacker moves further.**

The Windows Defender "no malware detected" result does not clear this. The attack uses valid credentials and native PowerShell, so there is no malicious file for signature antivirus to flag. The user's denial that they connected over RDP is the strongest single signal here.

---


| Field | Detail |
|---|---|
| **WHAT** | An attacker brute forced or reused valid credentials to log into HR-WS-017 over RDP, gained a privileged session, ran PowerShell, and made an outbound connection. |
| **WHEN** | Monday 5 October 2026, morning. Failed attempts then a successful logon, with process and network activity following. Exact times to be read from Wazuh. |
| **WHERE** | HR-WS-017, an HR workstation, accessed remotely (Logon Type 10) from an unusual source IP. |
| **WHO** | The employee's account, but the employee denies connecting over RDP, so this is most likely an attacker using the account's credentials. |
| **WHY** | Initial access and a foothold. RDP with valid credentials gives interactive, privileged control to run commands and move laterally. |
| **HOW** | Repeated failed RDP (4625), a successful RemoteInteractive logon (4624 Type 10), special privileges (4672), a new process (4688), PowerShell (4104), and an outbound connection (Sysmon 3). |

---

## Attack Chain

| Timestamp | Log Event | Attack Phase |
|---|---|---|
| T0 | 4625 multiple failed RDP logons | Credential access, brute force or guessing |
| T0 plus | 4624 successful logon Type 10 from an unusual IP | Initial access over RDP |
| T0 plus | 4672 special privileges assigned | Privileged session |
| T0 plus | 4688 and Sysmon 1 new suspicious process | Execution |
| T0 plus | 4104 PowerShell script block logged | Execution, PowerShell |
| T0 plus | Sysmon 3 outbound connection | Command and control |

Note: the jump from many 4625 failures to a 4624 success is the brute force to access transition, and the user's denial makes legitimate use unlikely. Exact times from Wazuh.

---

## Mission 01 — Initial Triage

| Item to Establish | Why It Matters | Where to Find It |
|---|---|---|
| **Username in the successful login** | Identifies whose credentials were used | 4624 |
| **Source IP** | The attacker origin to block and pivot on | 4624 IpAddress, firewall |
| **Source hostname** | Attributes the source machine | 4624 WorkstationName |
| **Number of failed attempts** | Shows the brute force scale | 4625 count |
| **Exact successful-login timestamp** | Anchors the timeline | 4624 |
| **Logon Type** | Confirms this is RDP (Type 10) | 4624 LogonType |
| **Whether MFA was involved** | Shows if MFA was bypassed or absent | IdP, Conditional Access logs |
| **Whether the account normally uses RDP** | Baseline to judge the anomaly | Prior 4624, asset role |
| **Destination hostname or IP** | The outbound target | Sysmon 3, firewall |
| **Process created after login** | The attacker's first action | 4688, Sysmon 1 |
| **PowerShell command line** | Intent and payload | 4104, 4688 |
| **Privileges assigned** | How powerful the session is | 4672 |
| **Recent password changes** | Detects account takeover prep | AD, 4723, 4724 |
| **Recent authentication activity** | The account's wider usage | 4624, 4625, 4768 |
| **Same source IP against other endpoints** | Campaign scope | SIEM search |

---

## Mission 02 — Hunting Hypotheses

**H1: An attacker obtained valid credentials and accessed HR-WS-017 through RDP.**

| Field | Details |
|---|---|
| **Evidence Required** | Auth logs showing failures then success, unusual source IP reputation, the user's login history, RDP session details |
| **Data Sources** | Windows Security, Wazuh, VPN and firewall logs, identity provider |
| **Expected Indicators** | Unusual source IP, abnormal login time, multiple failures, a successful RDP authentication |
| **False Positives** | A legitimate remote employee, IT admin activity, approved remote support software |
| **Conclusion** | Strongly supported. Failures to success from an unusual IP, plus the user's denial, fit credential compromise. Primary hypothesis. |

**H2: The RDP activity was legitimate administrative access.**

| Field | Details |
|---|---|
| **Evidence Required** | A known admin account, an approved source workstation, a change ticket, an expected maintenance window, normal admin behavior |
| **Data Sources** | AD admin groups, change management, asset inventory, prior logs |
| **Expected Indicators** | An admin account, an expected source, a matching ticket |
| **False Positives** | This is the benign hypothesis itself |
| **Conclusion** | Unlikely. The account is an HR user's, not an admin's, no change ticket is referenced, and the user denies the session. Reject unless a change record surfaces. |

**H3: The RDP session was an initial access point for further compromise.**

| Field | Details |
|---|---|
| **Evidence Required** | PowerShell execution, new process creation, credential access, network discovery, SMB connections, additional auth, suspicious outbound, persistence |
| **Data Sources** | 4104, 4688, Sysmon 1 and 3, 4624, share and mailbox audit |
| **Expected Indicators** | PowerShell beaconing out, lateral SMB or RDP, new persistence |
| **False Positives** | A legitimate remote admin running scripts |
| **Conclusion** | Supported and the most dangerous. PowerShell and an outbound connection right after login point to hands-on-keyboard follow-on. Treat as an active intrusion. |

---

## Mission 03 — Build the Attack Timeline

| Stage | Evidence |
|---|---|
| **Multiple failed RDP attempts** | 4625 burst for the account |
| **Successful RDP authentication** | 4624 Type 10 from the source IP |
| **Privileged session created** | 4672 special privileges |
| **Suspicious process execution** | 4688, Sysmon 1 |
| **PowerShell activity** | 4104 script block |
| **Network connection** | Sysmon 3 outbound |
| **Internal resource access** | 5140, 5145, 4663 on shares |
| **Additional authentication** | later 4624 or 4768 for the account |

| Question | Finding |
|---|---|
| **Who logged in?** | The HR user's account per 4624, but the user denies connecting. |
| **Where did it originate?** | The source IP in 4624, an unusual external address. |
| **Was the source IP normal?** | No. It is not a known source for this user. |
| **Was the account expected to use RDP?** | Check the baseline. HR workstation users typically do not RDP in. |
| **What process executed first?** | The 4688 and Sysmon 1 process after login, likely a shell or loader. |
| **Did PowerShell run?** | Yes, 4104 captured the script block. |
| **What command line?** | Decode the PowerShell from 4104 and 4688, looking for encoding or a download. |
| **Did the host talk to another internal system?** | Check Sysmon 3 and 5140 for lateral connections. |
| **Did the account authenticate elsewhere?** | Hunt the account across the fleet. |

---

## Mission 04 — Detection Engineering

**Detection Name:** Suspicious RDP to PowerShell Chain

| Field | Details |
|---|---|
| **Telemetry** | Windows Security (4624, 4625, 4672, 4688), Sysmon (1, 3), PowerShell 4104 |
| **Relevant Fields** | SourceIP, DestinationHost, Username, LogonType, ProcessName, ParentProcess, CommandLine, timestamp |
| **Detection Logic** | A successful 4624 with LogonType 10 from an unusual IP, preceded by a burst of 4625 failures for the same account, followed within a short window by PowerShell (4104, or 4688 powershell.exe) from that session. Raise high, and critical when an outbound connection follows. |
| **Severity** | High |
| **False Positives** | IT administrators, approved remote support, remote employees, scheduled maintenance. Allowlist known admin source IPs and jump hosts. |
| **Analyst Response** | Validate the user and source IP, review the RDP session, investigate the PowerShell, check lateral movement, and isolate the endpoint if compromise is confirmed. |

---

## MITRE ATT&CK

| Technique | ID | Relevance |
|---|---|---|
| **Brute Force** | T1110 | Multiple failed RDP logons before success |
| **Remote Services: RDP** | T1021.001 | The RemoteInteractive logon over RDP |
| **Valid Accounts** | T1078 | The user's credentials used by the attacker |
| **Command and Scripting Interpreter: PowerShell** | T1059.001 | PowerShell run after the logon |
| **Application Layer Protocol** | T1071 | The outbound connection from the session |
| **Remote Services: SMB and Windows Admin Shares** | T1021.002 | Likely lateral movement path to hunt |

---

## Impact

**CRITICAL.** An HR workstation has been accessed interactively by an attacker using a user's valid credentials, with a privileged session, PowerShell, and an outbound connection. The risks are access to HR data such as PII and payroll, lateral movement using the account, and a foothold that persists because it rests on valid credentials rather than malware. The employee's denial confirms the session is not sanctioned. Treat this as an active intrusion with potential data exposure.

---

## Actions

| Action Category | Details |
|---|---|
| **CONTAIN** | Isolate HR-WS-017 at the network level, terminate the active RDP session, and block the source IP. |
| **PRESERVE** | Capture a memory image, the RDP, Security, and PowerShell logs, the process tree, and the network connections, before any change. |
| **INVESTIGATE** | Decode the PowerShell, scope the outbound destination, review HR file access, and find lateral movement and other endpoints hit by the same IP or account. |
| **ERADICATE** | Remove any persistence found, after evidence is captured. |
| **ROTATE** | Reset the user's password and any credentials reachable from the host, and verify MFA. |
| **BLOCK** | Block the source IP at the firewall and tighten RDP exposure with NLA, MFA, and jump host restrictions. |
| **ESCALATE** | Notify the IR lead, the HR data owner, and management. |

---

## Mission 05 — Lateral Movement Hunt

| Hunt Item | What to Look For | Where to Hunt |
|---|---|---|
| **SMB connections** | Lateral file and share access | 5140, 5145, Sysmon 3 |
| **RDP to other systems** | Pivoting over RDP | 4624 Type 10 on other hosts |
| **New Logon Type 3 events** | Network logons from the host | 4624 Type 3 |
| **Additional Logon Type 10 events** | More RDP sessions | 4624 Type 10 |
| **Remote PowerShell** | WinRM on 5985 | 4104, WinRM logs |
| **PsExec-like activity** | Service creation for remote exec | 7045, 4697, Sysmon 1 |
| **Remote process creation** | Processes on other hosts | 4688, Sysmon 1 on targets |
| **Credential access** | LSASS access or dumping | Sysmon 10, EDR |
| **Unusual account usage** | The account on new hosts | 4624 across the fleet |
| **Access to HR documents** | Reads on HR shares | 4663, file auditing |
| **Connections to domain controllers** | Reaching DCs | 4624 on DCs, Sysmon 3 |
| **Connections to file servers** | Reaching file servers | 5140, Sysmon 3 |
| **Same source IP across endpoints** | Campaign scope | SIEM |
| **Same PowerShell across endpoints** | Shared tooling | SIEM |

**Senior hunt question: if the attacker used valid credentials, what proves the account was compromised even with no malware detected?**

The proof is in the deviation from the user's own baseline across five layers, none of which need a malware signature. Authentication: a successful RDP logon from a source IP, country, ASN, or device the user has never used, at an abnormal time, preceded by failed attempts, and denied by the user. Behaviour: the session does things this user never does, such as using RDP at all or holding a privileged session. Process: the first process after login is a shell or an encoded PowerShell, not the user's normal applications. Network: an outbound connection to an unfamiliar external host right after login, off the user's baseline. File access: reads on HR files or shares the user does not normally touch, or bulk access. Taken together, these deviations prove account misuse, which is why identity and behaviour analytics, not antivirus, is what catches valid-account abuse.

---

## Mission 06 — Incident Containment

- [ ] HR-WS-017 isolated
- [ ] Active RDP session terminated
- [ ] User account reviewed
- [ ] Password reset considered
- [ ] MFA status verified
- [ ] Source IP investigated
- [ ] RDP logs preserved
- [ ] PowerShell logs preserved
- [ ] Process tree captured
- [ ] Network connections documented
- [ ] HR file access reviewed
- [ ] Other endpoints searched
- [ ] Same username activity searched
- [ ] Same source IP searched
- [ ] Relevant SIEM queries preserved
- [ ] Endpoint forensic evidence preserved
- [ ] Business owner informed

---

## Senior SOC Question

**Which gives stronger context: a single "successful RDP login," or the chain of failed RDP attempts to successful login to privileged session to PowerShell to internal network access?**

The correlated chain, by far. A lone "successful RDP login" is close to meaningless, since thousands happen legitimately every day, so alerting on it alone is pure noise that gets ignored. The chain tells a story: failures then success (brute force or credential stuffing), a privileged session, PowerShell, then an outbound connection, with each step adding context. Event correlation links separate weak signals into one strong one. Behavioural baselines show the login and the actions deviate from this user's norm. Process context (PowerShell right after login), identity context (an HR user rather than an admin, from an unusual IP), and network context (an outbound to an unknown host) each move it from possible to probable. The result is high detection confidence and low false positives: any single event fires constantly and is usually benign, but the full sequence is rare and almost always malicious. A detection built on the chain catches the real intrusion while staying quiet on the thousands of normal logins.

---

## References

- [MITRE ATT&CK T1110: Brute Force](https://attack.mitre.org/techniques/T1110/)
- [MITRE ATT&CK T1021.001: Remote Services, RDP](https://attack.mitre.org/techniques/T1021/001/)
- [MITRE ATT&CK T1078: Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- [MITRE ATT&CK T1059.001: Command and Scripting Interpreter, PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [Wazuh Documentation: Windows monitoring and log analysis](https://documentation.wazuh.com/)
- [Sigma: generic detection rule format for SIEM](https://sigmahq.io/)

---

**Status:** Active incident. Containment in progress, RDP session terminated, evidence preservation underway, escalated to the IR lead, lateral movement scope under review.
