# SOC Triage Report
### SOC-2026-1007-01 | Operation Ghost Ticket

**Analyst:** Jnanashree Anchan | **Program:** GraySentinel DSOU | **Date:** 7 October 2026

---

## Alert Details

| Field | Value |
|---|---|
| **Alert ID** | SOC-2026-1007-01 |
| **Rule** | Service account interactive logon from an unusual workstation, with Kerberos ticket spikes, admin share access, a new service, and a cleared audit log |
| **Severity** | Critical |
| **Identity and Host** | svc-backup (backup service account), source WS-FIN-17 (finance workstation) |
| **Platform** | Wazuh, Windows Security, Sysmon, EDR, Active Directory, Kerberos logs |
| **CVE / CVSS** | Not applicable. This is identity and Kerberos abuse, behavior based. |

---

## Verdict

**Confirmed suspicious service account abuse, not a misfiring backup job. svc-backup, a backup account that should never interactively log in to an employee workstation, authenticated interactively on WS-FIN-17 after failed attempts, gained special privileges, spawned PowerShell from an unusual parent, generated a spike of Kerberos TGT and service-ticket requests, accessed an administrative share, created a new service, and then cleared the security audit log. That is credential abuse to discovery to lateral movement to persistence to defense evasion, aimed at domain level access. Do NOT dismiss this as a backup job, and do NOT just delete the account. Contain the identity in a controlled way and preserve evidence first.**

The EDR "no known malware" result does not clear this. The attack uses a valid account and native tooling (PowerShell, Kerberos, Windows services), so there is no malicious file to flag. The real signal is the identity anomaly, a backup account interactively logging into a finance workstation, exactly as the SOC lead said: investigate the identity, not the malware.

---


| Field | Detail |
|---|---|
| **WHAT** | The svc-backup service account was used interactively on a finance workstation to run PowerShell, request Kerberos tickets in volume, access an admin share, create a service, and clear the audit log. |
| **WHEN** | Wednesday 7 October 2026, morning, over a window of roughly 15 to 30 minutes. Exact times from Wazuh. |
| **WHERE** | WS-FIN-17, a finance employee's workstation, with Kerberos and share activity reaching toward servers and the domain. |
| **WHO** | svc-backup, a backup service account, used from a workstation it never logs into. The real operator is an attacker holding its credentials. |
| **WHY** | Lateral movement and privilege escalation toward domain control, using a privileged service identity as the vehicle. |
| **HOW** | Failed then successful logon (4625, 4624), special privileges (4672), PowerShell from an unusual parent (4688), TGT and service-ticket spikes (4768, 4769), admin share access (5140), a new service (7045), and an audit log clear (1102). |

---

## Attack Chain

| Timestamp | Log Event | Attack Phase |
|---|---|---|
| T0 | 4625 multiple failed authentications | Credential access |
| T0 plus | 4624 successful logon by svc-backup from WS-FIN-17 | Initial access, service account abuse |
| T0 plus | 4672 special privileges assigned | Privileged session |
| T0 plus | 4688 powershell.exe from an unusual parent | Execution |
| T0 plus | 4768 and 4769 TGT and service-ticket spikes | Discovery and lateral movement over Kerberos |
| T0 plus | 5140 administrative share accessed | Lateral movement |
| T0 plus | 7045 new service created | Persistence and remote execution |
| T0 plus | 1102 security audit log cleared | Defense evasion |

Note: the log clear at the end is the tell that this was deliberate. Not every event in the window is necessarily the attacker's, so correlate before attributing, but these events share one identity, one source host, and a tight window, which ties them together.

---

## Mission 01 — Asset and Identity Discovery

| Item to Establish | Why It Matters | Where to Find It |
|---|---|---|
| **Owner of svc-backup** | Who is accountable and expected to use it | AD, IAM, service catalog |
| **Service or human account** | A service account should never interactively log in | AD account type, naming |
| **Where it is normally used** | Baseline of legitimate hosts | Logon history, backup infrastructure |
| **Should interactive logon be allowed** | Interactive use is the core anomaly | GPO, Deny log on locally policy |
| **Privileges it holds** | The blast radius if abused | AD group membership |
| **Password last rotated** | Stale credentials ease compromise | AD PasswordLastSet |
| **Local administrator rights** | Whether it can do damage locally | Local admin groups, LAPS |
| **User logged into WS-FIN-17** | The legitimate user versus the service account | 4624 |
| **Parent-child process relationships** | What spawned PowerShell | Sysmon 1, 4688 |
| **New services and scheduled tasks** | Persistence on the host | 7045, 4698 |
| **Network connections and PowerShell** | C2, targets, and attacker actions | Sysmon 3, 4104 |
| **DCs, critical and file servers, backup infra** | What svc-backup can reach | CMDB, backup config, AD |
| **Systems accessed by svc-backup** | Scope of movement | 4624, 4769 across the fleet |

**Identity Attack Surface Map**

| Node | Privilege | Normal Behavior | Suspicious Behavior |
|---|---|---|---|
| **User (finance employee, WS-FIN-17)** | Standard user | Logs into their own workstation | Not the actor here, but their host is the launch point |
| **Workstation (WS-FIN-17)** | Standard endpoint | Runs finance apps, no privileged service logons | Hosts an interactive svc-backup logon and PowerShell |
| **Service Account (svc-backup)** | Backup, likely broad server access | Runs automated backups non-interactively | Interactive logon, special privileges, Kerberos spikes |
| **Server (file and app servers)** | Backup targets | Receive scheduled backups from svc-backup | Admin share access and a new service outside the backup window |
| **Domain Controller** | Domain authority | Authenticates svc-backup for backup tasks only | Target of Kerberos ticket requests and potential privileged access |

---

## Mission 02 — Hunting Hypotheses

**H1: svc-backup credentials are compromised and being used interactively from WS-FIN-17.**

| Field | Details |
|---|---|
| **Evidence Required** | 4624 and 4625 for svc-backup, the logon type, source IP, auth protocol, the account's usage baseline, EDR process telemetry |
| **Data Sources** | Windows Security, Wazuh, Active Directory, EDR |
| **Expected Indicators** | An interactive logon by a service account from a non-approved host after failed attempts |
| **False Positives** | Legitimate backup administration or emergency maintenance |
| **Conclusion** | Strongly supported. A backup service account interactively logging into a finance workstation is outside its purpose entirely. Primary hypothesis. |

**H2: The compromised identity is being used to access additional Windows systems.**

| Field | Details |
|---|---|
| **Evidence Required** | 4624, 4672, 5140 and 5145, 4768, 4769, remote service activity, admin share access showing WS-FIN-17 to a file server to an app server to a DC |
| **Data Sources** | Windows Security, Kerberos logs, share audit |
| **Expected Indicators** | The identity reaching successive servers, admin share access, service tickets for new targets |
| **False Positives** | Authorized administration or a scheduled backup window |
| **Conclusion** | Supported. The admin share access and Kerberos spikes point to movement toward servers and the DC. Active. |

**H3: The attacker is transitioning from the service identity toward privileged domain access.**

| Field | Details |
|---|---|
| **Evidence Required** | Privileged group membership changes, unusual Kerberos activity, new service creation, credential access indicators, DC authentication patterns, account modifications |
| **Data Sources** | AD, 4768 and 4769, 7045, EDR, 4728 and 4732 |
| **Expected Indicators** | Attempts to reach a DC or add privileges, Kerberos ticket abuse such as Kerberoasting or ticket forging |
| **False Positives** | Authorized privileged maintenance |
| **Conclusion** | Supported as the goal. The chain is clearly aimed at domain access. Treat as escalation in progress. |

---

## Mission 03 — Detection Engineering

**Detection Name:** Suspicious Service Account Interactive Logon

| Field | Details |
|---|---|
| **Telemetry** | Windows Security, Wazuh, EDR, Active Directory, Kerberos logs |
| **Relevant Events** | 4624, 4625, 4672, 4768, 4769 |
| **Relevant Fields** | Account, LogonType, SourceHost, approved host list, privileged activity, timestamp |
| **Detection Logic** | account is a known service account AND interactive logon is true AND source host is not in the approved host list AND privileged activity follows, then alert HIGH. Escalate to CRITICAL when followed by admin share access, new service creation, privileged group modification, DC access, or security log clearing. |
| **Severity** | High, raised to Critical with any of the escalators above |
| **False Positives** | Approved maintenance, backup troubleshooting, disaster recovery, authorized admin intervention. Allowlist approved hosts and maintenance windows. |
| **Analyst Response** | Validate the account owner, confirm the source workstation, check recent auth history, review the process tree, determine lateral movement, isolate the identity per IR, and hunt for other affected systems. |

---

## Mission 04 — Lateral Movement and Persistence Hunt

| Hunt Item | What to Look For | Where to Hunt |
|---|---|---|
| **New Windows services** | PsExec-style persistence or remote exec | 7045, 4697 |
| **Scheduled tasks** | Persistence | 4698 |
| **New local administrators** | Local privilege persistence | local admin group changes |
| **New domain accounts** | Attacker created accounts | 4720, AD |
| **Group membership changes** | Escalation | 4728, 4732, 4756 |
| **Remote admin share access** | Lateral movement | 5140, 5145 |
| **PowerShell execution** | Attacker actions | 4104 |
| **WMI activity** | Lateral exec or persistence | Sysmon, WMI logs |
| **Unusual RDP** | Pivoting | 4624 Type 10 |
| **Kerberos anomalies** | Ticket abuse | 4768, 4769 |
| **Security log clearing** | Defense evasion | 1102 |
| **New or modified firewall rules** | Evasion or access | 4946 to 4948 |
| **Credential material accessed** | Dumping | Sysmon 10 (LSASS), EDR |

**Critical question: if svc-backup is confirmed compromised, should you immediately delete the account?**

No. Immediate deletion feels decisive but it loses evidence and can make things worse. Active sessions: deleting the account does not reliably kill the attacker's existing sessions or Kerberos tickets, which keep working until they expire, so deletion alone may not cut access. Backup dependencies: svc-backup runs production backups, so deleting it breaks the backup pipeline and can leave the business with no recovery capability exactly when it is most needed. Evidence preservation: deletion destroys the account object and its attributes, which are forensic evidence of what was done and when. Persistence: if the attacker already planted services, tasks, local admins, or other accounts, removing svc-backup does nothing about those and may cut the thread that leads to them. The correct move is controlled containment: disable the account rather than delete it, or apply deny interactive logon, kill its active sessions and revoke its tickets, isolate WS-FIN-17, and rotate its credential. Credential rotation: rotate svc-backup and any shared or service credentials it may have exposed, and plan the backup service cutover so a recovery path is preserved. So contain and disable, preserve, rotate, hunt persistence, then decide on removal. Never delete first.

---

## Mission 05 — Kerberos and Identity Hunt

| Event | What to Establish | In This Case |
|---|---|---|
| **4768 TGT Request** | Who requested it, from which host, when, is the source normal | svc-backup requested TGTs from WS-FIN-17, a host it never uses, in a short burst |
| **4769 Service Ticket** | Unusual service access, high volume, new targets, odd account-to-service pairs | A spike of service tickets, likely for admin shares and server services, consistent with movement or Kerberoasting |
| **4672 Special Privileges** | Which account, on which host, was it expected | svc-backup received special privileges on WS-FIN-17, which is not expected for a backup account on an employee workstation |

**Identity chain:** svc-backup (identity) to WS-FIN-17 (source host) to a TGT then service tickets (ticket) to admin shares and server services, and possibly the DC (target service) to special privileges and local admin (privilege) to a new service and the log clear (action). The Kerberos burst is the connective tissue between the foothold and the lateral movement.

---

## Mission 06 — Timeline Reconstruction

| Time | Event | Attack Phase |
|---|---|---|
| 09:01 | First failed authentication (4625) | Credential abuse, attempt |
| 09:03 | Successful svc-backup logon (4624) from WS-FIN-17 | Initial access |
| 09:05 | PowerShell from an unusual parent (4688) | Discovery and execution |
| 09:08 | Kerberos activity increases (4768, 4769) | Discovery and lateral movement prep |
| 09:11 | Administrative share accessed (5140) | Lateral movement |
| 09:14 | New service created (7045) | Persistence |
| 09:18 | Security log cleared (1102) | Defense evasion |

This maps to initial access, credential abuse, discovery, lateral movement, persistence, and defense evasion over roughly 17 minutes. Correlate before concluding: the events belong to one incident because they share the svc-backup identity, the WS-FIN-17 source, and a tight contiguous window. Any legitimate activity in the same window should be separated out by account and host before it is attributed to the attacker.

---

## Mission 07 — False Positive Challenge

| Case | Scenario | Verdict | Why |
|---|---|---|---|
| **A** | Backup account logs into a backup server | Benign | Right identity, right host, right purpose |
| **B** | Backup account logs into a finance employee workstation | Suspicious | Right identity, wrong host and purpose |
| **C** | Backup account accesses multiple servers during the backup window | Potentially benign | Volume fits the expected window and role |
| **D** | Backup account accesses a DC right after PowerShell from an employee workstation | High risk | Wrong host, wrong behavior, and escalation toward the domain |

**Correlation logic:** a single off-baseline event like Case B raises suspicion but is not conclusive on its own. Confidence jumps to high when you correlate four anomalies at once: a service account acting outside its type (identity), from a host it never uses (source), doing non-backup actions such as PowerShell and admin share access (behavior), outside any backup window and heading toward privileged targets (privilege and time). One anomaly is an alert. Four correlated anomalies, as in Case D and as in this incident, are an incident.

---

## Mission 08 — Incident Response

**First 15 minutes**

- [ ] Validate the identity (owner and purpose of svc-backup)
- [ ] Identify the source host (WS-FIN-17)
- [ ] Preserve volatile evidence (memory, process tree, sessions)
- [ ] Check active sessions and Kerberos tickets
- [ ] Confirm affected systems
- [ ] Begin containment per IR policy (disable, do not delete)

**First 1 hour**

- [ ] Investigate svc-backup activity in full
- [ ] Review the authentication timeline
- [ ] Hunt lateral movement (shares, services, Kerberos)
- [ ] Identify persistence (services, tasks, accounts)
- [ ] Review DC telemetry
- [ ] Protect critical and privileged accounts

**First 24 hours**

- [ ] Rotate compromised credentials and plan the backup service cutover
- [ ] Review all privileged accounts
- [ ] Hunt across the environment for the same identity, source, and pattern
- [ ] Review endpoint telemetry
- [ ] Validate backup integrity
- [ ] Search for persistence
- [ ] Preserve forensic evidence with chain of custody

---

## Mission 09 — Attack Path Map

| Transition | Evidence | MITRE Technique | Confidence |
|---|---|---|---|
| **Compromised credential to WS-FIN-17** | 4625 failures then a 4624 success from an unusual host | T1110 Brute Force, T1078 Valid Accounts | High |
| **WS-FIN-17 to service account abuse** | svc-backup interactive logon, 4672, 4688 PowerShell from an unusual parent | T1078 Valid Accounts, T1059.001 PowerShell | High |
| **Service account to Kerberos auth** | 4768 and 4769 TGT and service-ticket spikes | T1558 Steal or Forge Kerberos Tickets (possible Kerberoasting, T1558.003) | Medium to High |
| **Kerberos to lateral movement** | 5140 admin share access, service tickets for new targets | T1021.002 Remote Services, SMB and Windows Admin Shares | High |
| **Lateral movement to privileged server** | 7045 new service, remote execution | T1543.003 Create or Modify System Service, T1569.002 Service Execution | Medium |
| **Privileged server to domain controller** | Kerberos and auth directed toward the DC, privileged access attempts | T1021 Remote Services, T1078 Valid Accounts | Medium |
| **Defense evasion across the chain** | 1102 security audit log cleared | T1070.001 Clear Windows Event Logs | High |

---

## Impact and Risk Assessment

**CRITICAL.** A privileged backup service account is being driven interactively from a finance workstation through discovery, Kerberos abuse, lateral movement, persistence, and log clearing, all aimed at the domain. The blast radius is large: svc-backup likely holds broad access to servers and backups, and the trajectory points at domain compromise. The cleared audit log shows intent to hide. The business impact includes potential domain takeover, compromise of backup integrity (the last line of recovery), and data exposure.

| Risk | Rating | Evidence |
|---|---|---|
| **Identity Risk** | Critical | A privileged service account used interactively from a non-approved host after failed logons |
| **Lateral Movement Risk** | High | Admin share access and Kerberos service-ticket spikes toward servers |
| **Persistence Risk** | High | A new service created (7045), with tasks and accounts still being hunted |
| **Domain Compromise Risk** | High | Kerberos and auth activity aimed at the DC, not yet confirmed at the DC itself |
| **Business Impact** | Critical | A backup account compromise threatens recovery capability and domain control |
| **Overall Severity** | Critical | Correlated identity, lateral movement, persistence, and evasion signals |

---

## Senior SOC Question

**Which is more dangerous: a privileged account with 500 authentication events all from its normal systems, or a privileged service account with only 3 events but from a workstation it has never used?**

The three events from the never-before-seen workstation, decisively. Behavioural baseline: frequency alone is a weak signal, because 500 events from normal systems is the account's baseline, expected and benign, while 3 events that break the baseline are the anomaly. Identity context: account type matters, since a service account is non-interactive by design and bound to specific systems, so any deviation is meaningful in a way a busy admin's volume is not. Source context: the originating host can matter more than volume, because a privileged identity appearing on a host it has never touched is exactly how lateral movement and credential theft look, no matter how few events it generates. Correlation: a few related events (unusual host plus service account plus privileged action) correlate into a high-confidence story, whereas thousands of isolated, baseline-matching alerts carry little information. Detection engineering: to cut both alert fatigue and missed compromise, SOC should baseline each privileged identity's normal hosts and behaviors and alert on deviation rather than on raw volume, so the noisy-but-normal 500 stays quiet and the quiet-but-abnormal 3 fires. Volume is noise, context is signal.

---

## Final SOC Question

**If the attacker uses a legitimate service account, what exactly makes the activity malicious?**

Nothing about the credential itself is malicious. svc-backup is a real account using its real password and native tools. What makes it malicious is the context, the combination of five things that do not fit. Identity: a service account acting interactively, which it never should. Source: a finance workstation it has never used. Behavior: PowerShell, admin share access, service creation, and log clearing, none of which are backup tasks. Privilege: special privileges and movement toward the domain. Time: outside any backup window, in a tight hands-on burst. Any one of these could be explained away, but together they are unmistakable. This is why detection for valid-account abuse cannot rely on signatures or usernames, it has to score identity plus source plus behavior plus privilege plus time against the account's own baseline. The malice is in the pattern, not the credential.

---

## References

- [MITRE ATT&CK T1078: Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- [MITRE ATT&CK T1558: Steal or Forge Kerberos Tickets](https://attack.mitre.org/techniques/T1558/)
- [MITRE ATT&CK T1021.002: Remote Services, SMB and Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/)
- [MITRE ATT&CK T1070.001: Indicator Removal, Clear Windows Event Logs](https://attack.mitre.org/techniques/T1070/001/)
- [Wazuh Documentation: Windows monitoring and log analysis](https://documentation.wazuh.com/)
- [Sigma: generic detection rule format for SIEM](https://sigmahq.io/)

---

**Status:** Active incident. svc-backup being disabled with sessions and tickets revoked, WS-FIN-17 isolated, evidence preserved, escalated to the IR lead, domain and backup integrity under review.
