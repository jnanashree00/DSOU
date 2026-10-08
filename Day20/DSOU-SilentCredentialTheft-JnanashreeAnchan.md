# SOC Triage Report
### SOC-2026-1008-01 | Operation Silent Credential Theft

**Analyst:** Jnanashree Anchan | **Program:** GraySentinel DSOU | **Date:** 8 October 2026

---

## Alert Details

| Field | Value |
|---|---|
| **Alert ID** | SOC-2026-1008-01 |
| **Rule** | A process accessing LSASS on a finance workstation, with failed and successful authentication, explicit credentials, remote file-server access, and Kerberos ticket anomalies |
| **Severity** | Critical |
| **Host** | FIN-WS-117 (finance workstation) |
| **Platform** | Wazuh, Windows Security, Sysmon, EDR, Active Directory |
| **CVE / CVSS** | Not applicable. This is credential access and valid-account abuse, behavior based. |

---

## Verdict

**Confirmed suspected credential theft and lateral movement, not a false positive. A process accessed LSASS on FIN-WS-117, the signature of credential dumping, and the stolen credentials are already in use: a Logon Type 3 to FILE-SRV-03, explicit credentials, Kerberos service-ticket anomalies, and the same account appearing on a second workstation. The user denies accessing any server. Do NOT close this as benign and do NOT reimage FIN-WS-117 yet, because the source process, the LSASS access evidence, and the authentication trail must be preserved first.**

The EDR flagged credential-access behavior, but the follow-on uses valid accounts and native lateral movement, so there is no malware verdict to lean on. The key signals are the LSASS access and the user's denial of the server activity. The detection that matters is which process accessed LSASS and in what context, not that lsass.exe exists.

---

| Field | Detail |
|---|---|
| **WHAT** | A process dumped credentials from LSASS on FIN-WS-117, and those credentials were used to authenticate to FILE-SRV-03 and from a second workstation. |
| **WHEN** | Thursday 8 October 2026, morning, with the events clustered within minutes. Exact times from Wazuh. |
| **WHERE** | FIN-WS-117, a finance workstation, reaching FILE-SRV-03 and a second endpoint. |
| **WHO** | The finance user's account, but the user denies the server access, so an attacker is using the stolen credentials. |
| **WHY** | Credential theft for lateral movement and access to finance resources. |
| **HOW** | A suspicious process with an unusual parent accessed LSASS (Sysmon 10), then explicit credentials (4648) and a Type 3 logon (4624) reached FILE-SRV-03, with Kerberos service tickets (4769) and reuse on another host. |

---

## Attack Chain

| Timestamp | Log Event | Attack Phase |
|---|---|---|
| T0 | Sysmon 1 and 4688 suspicious process from an unusual parent | Execution |
| T0 plus | Sysmon 10 process accessed lsass.exe | Credential access, LSASS dump |
| T0 plus | 4625 failed then 4624 successful Logon Type 3 to FILE-SRV-03 | Lateral movement |
| T0 plus | 4648 logon with explicit credentials | Use of stolen credentials |
| T0 plus | 4672 special privileges assigned | Privileged access |
| T0 plus | 4769 unusual Kerberos service tickets | Lateral movement over Kerberos |
| T0 plus | Same account authenticates from another workstation | Spread |

Note: Sysmon 10 LSASS access followed by explicit-credential logons to a file server is the dump-then-reuse pattern, and the user's denial makes legitimate use unlikely. Correlate before attributing, but these events share one account, one origin host, and a tight window.

---

## Mission 01 — Initial Triage

| Item to Establish | Why It Matters | Where to Find It |
|---|---|---|
| **Username on FIN-WS-117** | The account at risk | 4624 |
| **Hostname and IP** | Identifies the endpoint | Asset inventory, 4624 |
| **Exact process that accessed lsass.exe** | The credential dumping tool | Sysmon 10 SourceImage |
| **PID and parent process** | Process lineage and how it launched | Sysmon 1, 4688 |
| **Process command line** | Intent and tooling | 4688, Sysmon 1 |
| **Timestamp of LSASS access** | Anchors the timeline | Sysmon 10 |
| **Legitimate or unexpected process** | Rules out EDR and AV | Signature, hash, allowlist |
| **User's recent logon history** | Baseline | 4624, 4625 |
| **Source and destination systems** | The movement path | 4624, Sysmon 3 |
| **Logon types observed** | Type 3 indicates network or lateral | 4624 LogonType |
| **Failed vs successful authentication** | Brute force versus success | 4625, 4624 |
| **Files or shares accessed** | Data exposure | 5140, 5145, 4663 |
| **Privileged accounts involved** | Blast radius | 4672, AD |
| **Same activity on other endpoints** | Spread | SIEM search |
| **EDR and AV credential-access detections** | The confirming signal | EDR console |

**Primary question:** was the LSASS access legitimate system behavior, authorised security software, or credential-access activity? This is the triage decision point, and it is answered by identifying the source process and validating its signature and hash.

---

## Mission 02 — Hunting Hypotheses

**H1: FIN-WS-117 experienced credential-access activity targeting LSASS.**

| Field | Details |
|---|---|
| **Evidence Required** | LSASS process-access telemetry, the process name and hash, the parent-child relationship, the command line, EDR alerts |
| **Data Sources** | Sysmon, Windows Security, EDR, Wazuh |
| **Expected Indicators** | An unexpected process accessing LSASS, suspicious ancestry, unusual privilege use |
| **False Positives** | EDR and AV agents, Windows security components, legitimate admin tools |
| **Conclusion** | Strongly supported. An unexpected process accessing LSASS with suspicious ancestry fits credential dumping. Primary hypothesis. |

**H2: The authentication activity was legitimate administrative activity.**

| Field | Details |
|---|---|
| **Evidence Required** | An admin ticket or change record, account ownership, the source workstation, the auth timeline, remote admin software |
| **Data Sources** | Windows Event Logs, Active Directory, EDR, change management |
| **Expected Indicators** | A known admin, an approved window, an expected source, a normal auth pattern |
| **False Positives** | Service accounts, scheduled tasks, backup software |
| **Conclusion** | Unlikely. This is a finance user's account, the user denies the server access, and there is no change record. Reject unless a ticket surfaces. |

**H3: Credentials from FIN-WS-117 were abused to access internal resources.**

| Field | Details |
|---|---|
| **Evidence Required** | Logon events, Kerberos activity, SMB connections, account usage, access to sensitive shares |
| **Data Sources** | Domain controller logs, Windows Security, file-server logs, Wazuh |
| **Expected Indicators** | The same account from unusual hosts, multiple auth attempts, new destinations, unusual access to sensitive resources |
| **False Positives** | VPN changes, remote-work activity, IT administration |
| **Conclusion** | Supported and the active risk. The account reaching FILE-SRV-03 and a second workstation after the LSASS access shows the stolen credentials in use. Treat as active lateral movement. |

---

## Mission 03 — Authentication Timeline Hunt

| Stage | Evidence |
|---|---|
| **User logs into FIN-WS-117** | 4624 for the finance user |
| **Suspicious process starts** | Sysmon 1, 4688, unusual parent |
| **Process accesses LSASS** | Sysmon 10, SourceImage to lsass.exe |
| **Authentication attempts begin** | 4625 failures |
| **Successful Logon Type 3** | 4624 Type 3 |
| **Access to FILE-SRV-03** | 5140, 4663 on the server |
| **Kerberos service ticket activity** | 4769 |
| **Same account on another endpoint** | 4624 on a second workstation |

| Question | Finding |
|---|---|
| **Which user account?** | The finance user's account, but the user denies the server access. |
| **What process accessed LSASS?** | The Sysmon 10 SourceImage. Pull its name, hash, and path. |
| **Signed and trusted?** | Check the signature and hash. A credential dumper is typically unsigned or a renamed tool. |
| **Process parent?** | The unusual parent from Sysmon 1, such as an Office app or a script. |
| **Execution expected?** | No. It is unexpected on a finance workstation. |
| **Which systems did the account reach?** | FILE-SRV-03 and a second workstation. |
| **Successful or failed?** | Both, failures then a success. |
| **Logon Type 3 observed?** | Yes, to FILE-SRV-03. |
| **Explicit credentials used?** | Yes, 4648. |
| **Sensitive shares accessed?** | Check 5140 and 4663 on finance shares at FILE-SRV-03. |
| **Same account on another workstation?** | Yes, shortly after. |
| **Unusual privilege assignment?** | Yes, 4672 special privileges. |

---

## Mission 04 — Detection Engineering

**Detection Name:** Suspicious LSASS Process Access

| Field | Details |
|---|---|
| **Telemetry** | Sysmon Event 10, Windows Security events, EDR process telemetry |
| **Relevant Fields** | SourceImage, TargetImage, GrantedAccess, ProcessId, SourceProcessId, User, CommandLine, Hash, Signature status |
| **Detection Logic** | TargetImage is lsass.exe AND SourceImage is not an approved security or Windows process AND SourceImage is unusual for the endpoint, optionally AND GrantedAccess includes dump-capable rights such as 0x1010 or 0x1410, then raise HIGH. The detection keys on which process accessed LSASS and in what context, not on the existence of lsass.exe. |
| **Severity** | High |
| **False Positives** | EDR and AV agents, approved security tools, Windows diagnostic components, legitimate admin software. Allowlist known security product images and hashes. |
| **Analyst Response** | Identify the source process, validate its signature and hash, review the parent-child relationship, check the command line, review the user context, hunt the same process and hash across endpoints, correlate with authentication activity, and escalate if credential abuse is suspected. |

---

## MITRE ATT&CK

| Technique | ID | Relevance |
|---|---|---|
| **OS Credential Dumping: LSASS Memory** | T1003.001 | A process accessed LSASS to dump credentials |
| **OS Credential Dumping** | T1003 | Credential access from the host |
| **Valid Accounts** | T1078 | Stolen credentials reused to authenticate |
| **Use Alternate Authentication Material: Pass the Hash** | T1550.002 | The explicit-credential logon (4648) reusing stolen material |
| **Use Alternate Authentication Material: Pass the Ticket** | T1550.003 | The Kerberos service-ticket anomalies (4769) |
| **Remote Services: SMB and Windows Admin Shares** | T1021.002 | The Type 3 logon to FILE-SRV-03 |

---

## Impact

**CRITICAL.** Credentials were dumped from a finance workstation and are already in use to reach a file server and a second endpoint. The risk is theft of finance data, broader lateral movement using the stolen credentials, and escalation toward privileged or domain access. Critically, those credentials now live in the attacker's hands, so they survive a reimage of FIN-WS-117, which is why rotation matters more than rebuilding the host. The user's denial confirms the activity is not sanctioned. Treat this as an active intrusion with credential compromise and data exposure.

---

## Actions

| Action Category | Details |
|---|---|
| **CONTAIN** | Isolate FIN-WS-117, suspend the affected account's sessions, and block the suspicious process by hash across EDR. |
| **PRESERVE** | Capture a memory image, the suspicious process and its hash, the Sysmon 10 LSASS access evidence, the Security and EDR logs, and the authentication trail, before any reimage. |
| **INVESTIGATE** | Identify the dumping tool, scope the FILE-SRV-03 access and finance shares touched, follow the account to the second workstation, and find the same process, hash, and account elsewhere. |
| **ERADICATE** | Remove the tool and any persistence, after evidence is captured. |
| **ROTATE** | Reset the affected account and any credentials that were resident in LSASS on that host, since dumped credentials outlive the endpoint. |
| **BLOCK** | Block the process hash and any attacker source IPs, and enable LSASS protection (RunAsPPL, Credential Guard) to defeat future dumping. |
| **ESCALATE** | Notify the IR lead, the finance data owner, and management. |

---

## Mission 05 — Account and Lateral Movement Hunt

| Hunt Item | What to Look For | Where to Hunt |
|---|---|---|
| **Logon Type 3 activity** | Network logons from the account | 4624 Type 3 |
| **Explicit credential usage** | Pass-the-hash style auth | 4648 |
| **Failed authentication bursts** | Brute force or spraying | 4625 |
| **Successful logons from unusual hosts** | Spread | 4624 |
| **SMB connections** | Lateral file access | 5140, 5145 |
| **Access to finance shares** | Data exposure | 4663, file audit |
| **RDP attempts** | Pivoting | 4624 Type 10 |
| **Remote administration** | Remote execution | 4104, 7045, WinRM |
| **Kerberos service ticket anomalies** | Pass the ticket | 4769 |
| **Privileged account usage** | Escalation | 4672, AD |
| **Same account on multiple endpoints** | Spread | 4624 across the fleet |
| **Same process or hash across endpoints** | The tool spreading | EDR hunt |
| **Unusual access to sensitive documents** | Data theft | 4663 |
| **New processes created remotely** | Remote execution | 4688, Sysmon 1 |
| **Auth immediately after the suspicious process** | The dump-then-auth link | Correlate Sysmon 10 and 4624 timing |

**Senior hunt question: if credentials may have been accessed from FIN-WS-117, which other systems should SOC investigate?**

Any system where the stolen credentials could be reused, expanding outward from the host. FIN-WS-117 is the origin, so it is preserved first. The domain controller must be checked, because the credentials authenticate there, and the DC logs (4768, 4769, 4624) are the authoritative record of every system the account touched, which is the real map of where the identity went. FILE-SRV-03 is confirmed reached, so its share and file access are reviewed to scope data exposure. Other workstations matter because the same account already appeared on a second one, and the same dumping tool, by hash, may have run elsewhere. What distinguishes lateral movement from legitimate administration is context: lateral movement shows the account on hosts it never normally uses, authentication immediately following a credential-access event, explicit-credential or pass-the-ticket logons, access to resources the user does not normally touch, and the same tool hash spreading. Legitimate administration has a change ticket, a known admin account, approved source hosts, a maintenance window, and no preceding LSASS access. The LSASS dump right before the authentications is the line between the two.

---

## Mission 06 — Incident Containment

- [ ] FIN-WS-117 network isolation verified
- [ ] User account status reviewed
- [ ] Privileged accounts identified
- [ ] Suspicious process preserved
- [ ] Process hash calculated
- [ ] LSASS access evidence preserved
- [ ] Authentication timeline created
- [ ] FILE-SRV-03 activity reviewed
- [ ] Domain controller logs preserved
- [ ] Same account searched across endpoints
- [ ] Same process or hash searched across endpoints
- [ ] Suspicious source IPs identified
- [ ] Relevant EDR telemetry preserved
- [ ] Security logs preserved
- [ ] Endpoint forensic evidence preserved
- [ ] Business owner informed

Do not immediately reimage the workstation. Before remediation, preserve enough evidence to answer how the activity started, what process performed the suspicious action, which account was involved, and where that account authenticated afterward. Reimaging first erases the process, the LSASS access record, and the local timeline, and it does nothing about the credentials that are already stolen.

---

## Mission 07 — Correlation Challenge

| Event | Alone | Correlated |
|---|---|---|
| **A** | A suspicious process accesses LSASS, could be a tool false positive | The credential source |
| **B** | 5 minutes later, same user does a Type 3 logon to FILE-SRV-03, a normal logon | Stolen-credential reuse right after the dump |
| **C** | 10 minutes later, the same account authenticates from another workstation, mobility | The credential spreading |
| **D** | FILE-SRV-03 access to a sensitive finance folder, normal file access | The objective, data theft |

No single event confirms compromise. But the sequence of process activity, then credential access, then authentication, then sensitive resource access tells one story that none of the events carry alone, because it adds timing, identity, and causality. A logon is benign until it follows a LSASS dump by five minutes under the same identity. Investigated in isolation, these are four dismissible low-confidence alerts. Correlated, they are one high-confidence incident. The value is in the links between the events, not the events themselves.

---

## Senior SOC Question

**Which gives stronger context: a process accessing LSASS, or suspicious LSASS access then authentication then internal server access then sensitive file access?**

The chain, clearly. Context: a lone LSASS access is ambiguous, because legitimate security tools touch LSASS constantly, so without context it is as likely benign as malicious. Sequence: the order is the evidence, since a dump followed by authentication followed by server access followed by sensitive file access is a kill chain where each step explains the next. User identity: the same account threading through every step turns separate events into one actor's activity. Process lineage: knowing the parent of the process that touched LSASS, an Office app or a script versus a signed security agent, is what separates an attack from a product. Host relationships: the identity moving from FIN-WS-117 to a file server to another workstation is the shape of lateral movement, invisible in any single host's logs. Behavioural anomalies: each step deviates from the user's baseline, and the deviations compound. Reducing false positives: correlation is what makes the detection precise, because any one signal fires often and is usually benign, but the full sequence is rare and almost always real, so the SOC chases one true incident instead of four noisy alerts. Modern detection engineering scores the chain, not the single event.

---

## References

- [MITRE ATT&CK T1003.001: OS Credential Dumping, LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)
- [MITRE ATT&CK T1078: Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- [MITRE ATT&CK T1550.002: Use Alternate Authentication Material, Pass the Hash](https://attack.mitre.org/techniques/T1550/002/)
- [MITRE ATT&CK T1021.002: Remote Services, SMB and Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/)
- [Wazuh Documentation: Windows monitoring and log analysis](https://documentation.wazuh.com/)
- [Sigma: generic detection rule format for SIEM](https://sigmahq.io/)

---

**Status:** Active incident. FIN-WS-117 isolated, the affected account's sessions suspended and credentials being rotated, evidence preserved, escalated to the IR lead, lateral movement and data exposure scope under review.
