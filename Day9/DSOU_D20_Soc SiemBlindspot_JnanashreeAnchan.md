# SOC Triage Report
### SOC-2026-0922-20 | SIEM Blindspot — The Silent Domain Controller
**Analyst:** Jnanashree Anchan | **Program:** GraySentinel DSOU | **Date:** 22 September 2026

---

## Alert Details

| Field | Value |
|---|---|
| Alert ID | SOC-2026-0922-20 |
| Rule | SIEM Blindspot — DC-02-PRD: No Logs Received for 48 Hours + Prior Event IDs 1102, 4624, 4688 |
| Severity | CRITICAL |
| Host | DC-02-PRD (Domain Controller — Production) |
| Platform | Wazuh SIEM / Windows Active Directory |

---

## Verdict

**TRUE POSITIVE — Suspected Domain Controller Compromise. Blindspot Attack. Do NOT reinstall Wazuh agent before forensic preservation.**

---



| | |
|---|---|
| **WHAT** | SIEM log gap on a Domain Controller, preceded by audit log clearance, anonymous logon with SeDebugPrivilege, and Mimikatz execution disguised as svchost.exe |
| **WHEN** | 20 Sep 2026, 02:14 AM IST — last log received from DC-02-PRD. 48-hour silence follows. |
| **WHERE** | DC-02-PRD — Production Domain Controller |
| **WHO** | Unknown threat actor — credentials unknown; activity indicates Domain Admin level access |
| **WHY** | Credential dumping (LSASS access via Mimikatz), log tampering to erase evidence, and likely DCSync or lateral movement to remaining DCs |
| **HOW** | 1. Anonymous logon with SeDebugPrivilege gained (Event 4624 + 4672) → 2. Mimikatz executed as renamed svchost.exe (Event 4688) → 3. Audit logs cleared (Event 1102) → 4. Wazuh agent stopped/killed to create 48-hour SIEM blindspot |

---

## Attack Chain

| Timestamp | Log Event | Attack Phase |
|---|---|---|
| 20 Sep 02:14 AM IST | 4624 — Anonymous Logon + SeDebugPrivilege on DC-02-PRD | Initial Access / Privilege Escalation |
| 20 Sep 02:14 AM IST | 4688 — mimikatz.exe renamed as svchost.exe executed on DC-02-PRD | Credential Dumping |
| 20 Sep 02:14 AM IST | 1102 — Audit log cleared on DC-02-PRD | Defense Evasion / Log Tampering |
| 20 Sep 02:14 AM IST | Wazuh agent goes silent — last log received | SIEM Blindspot Created |
| 20 Sep 02:14 AM+ IST | 48-hour log gap — no visibility into DC-02-PRD activity | Lateral Movement / Persistence (undetected window) |

---

## Asset Discovery

| Asset Item | Why It Matters | Where to Find It |
|---|---|---|
| Role of DC-02-PRD | Primary DC compromise = full domain compromise; RODC = limited blast radius | AD Sites and Services, CMDB, AD topology diagram |
| Internet exposure | DC should never be internet-facing; if it is, attack surface is far wider | Firewall rules, network diagrams, perimeter scan |
| Wazuh agent status and version | Understanding how the agent was stopped (killed, service disabled, uninstalled) tells us if it was intentional | Wazuh Manager — agent status panel, Windows Services log on DC-02-PRD |
| Last patch cycle and EDR status | Unpatched DC or absent EDR expands attacker options; AV saying "No Threat" is not a clearance | WSUS/SCCM patch reports, EDR console, AV management |
| Domain Admin / DCSync rights | Who holds these rights is the blast radius — attacker with DCSync can dump all hashes | Active Directory — AdminSDHolder, DACL on domain root object |
| Recent logon activity on DC-02-PRD | Identify attacker sessions, lateral movement from other hosts, pass-the-hash | Windows Security Event 4624, 4648, 4768 on DC-02-PRD |
| Service accounts running on DC-02-PRD | Kerberoastable accounts are a persistence and lateral movement vector | AD Users and Computers, Wazuh, EDR |
| Recent GPO changes | Attackers modify GPO to deploy payloads or disable security controls domain-wide | Group Policy Management Console, AD audit log (Event 5136) |
| NTLM / Kerberos auth logs around 02:14 AM | Identify what the attacker authenticated to after gaining access | Event IDs 4768, 4769, 4776 on DC-02-PRD and other DCs |
| Network connections from DC-02-PRD | Identify C2, lateral movement to other DCs or workstations | Firewall logs, Sysmon Event ID 3, NetFlow / VPC flow logs |

---

## Hunting Hypotheses

**H1: Security logs were cleared to hide credential access on the Domain Controller**

Hypothesis: The attacker cleared Windows audit logs (Event 1102) immediately after dumping credentials via Mimikatz to destroy forensic evidence of their actions on DC-02-PRD.

| Field | Details |
|---|---|
| **Evidence Required** | Event ID 1102 (Audit log cleared) with the clearing account identified; Event ID 4688 showing mimikatz.exe or suspicious svchost.exe execution immediately before the clear; Event ID 4624 / 4672 showing the logon session that performed both actions; absence of expected Event IDs (4768, 4769, 4776) in the gap |
| **Data Sources** | Windows Security Event Log (preserved from before clearance), Sysmon logs forwarded to Wazuh before the agent went silent, any offsite log backup or SIEM buffer |
| **Expected Indicators** | 1102 event with a non-standard or service account as the clearing identity; temporal correlation: 4688 (Mimikatz) → 1102 (clear) within seconds; SeDebugPrivilege (4672) granted to the logon session that performed the clear |
| **False Positives** | Scheduled log rotation scripts run by IT operations — typically documented and do not coincide with suspicious process execution; legitimate admin clearing logs during maintenance — must be verified against change management records |
| **Conclusion** | Event ID 1102 combined with prior Mimikatz execution and anonymous logon is not a maintenance event. This is confirmed defense evasion. The clearing account identity in the 1102 event must be identified and investigated. |

---

**H2: Wazuh agent was intentionally stopped or disabled to create SIEM blindness before lateral movement**

Hypothesis: After achieving privilege on DC-02-PRD, the attacker stopped or killed the Wazuh agent process to prevent detection of subsequent activity — lateral movement to other DCs, DCSync, or credential reuse across the domain.

| Field | Details |
|---|---|
| **Evidence Required** | Windows Service Control Manager event showing Wazuh agent service stopped (Event ID 7036); Event ID 4689 or 4688 showing the Wazuh agent process (wazuh-agent.exe) killed; the identity of the account that stopped the service; on other DCs: increased authentication events (4768, 4769) from DC-02-PRD's IP during the 48-hour window |
| **Data Sources** | Windows System Event Log on DC-02-PRD, Wazuh Manager (last heartbeat, disconnection reason), other DCs' authentication logs, EDR telemetry |
| **Expected Indicators** | Wazuh agent service stopped by a non-standard account or at an unusual time; service stop occurs within seconds of the 1102 log clear; other DCs show authentication requests from DC-02-PRD or new admin accounts during the blindspot window; Pass-the-Hash indicators on other systems (Event 4624 with logon type 3, NTLM, from DC-02-PRD IP) |
| **False Positives** | Wazuh agent crash due to genuine software bug — but a crash does not explain the preceding Event IDs 1102, 4624, and 4688; scheduled agent restart during maintenance — verify against change management |
| **Conclusion** | An agent crash is possible in isolation but cannot explain the three preceding high-severity events. The combination of Mimikatz execution, log clearance, and agent silence is a deliberate attack sequence, not a bug. |

---

**H3: A malicious service account or scheduled task was created for persistence after compromise**

Hypothesis: During the 48-hour blindspot window, the attacker created a backdoor — a new Domain Admin account, a rogue service account, or a scheduled task on DC-02-PRD — ensuring persistent access even if their initial session is terminated.

| Field | Details |
|---|---|
| **Evidence Required** | Event ID 4720 (new user account created) in the 48-hour window; Event ID 4728 (member added to security-enabled global group, e.g. Domain Admins); Event ID 4698 (scheduled task created) on DC-02-PRD; AD object changes: new accounts with AdminCount=1, DCSync rights, or Key Credential Link added to existing accounts; new services registered (Event ID 7045) |
| **Data Sources** | AD audit log (Events 4720, 4728, 5136), Scheduled Task log on DC-02-PRD, Wazuh (if any logs were forwarded before agent went silent), EDR if deployed |
| **Expected Indicators** | New accounts created outside business hours with names mimicking system accounts (svc-update, WinUpdate, DC-Admin); accounts added to Domain Admins or Enterprise Admins during the blindspot window; scheduled tasks pointing to executables in temp directories or encoded PowerShell; DCSync permissions granted to a non-standard account on the domain root object |
| **False Positives** | Legitimate IT operations creating service accounts — must be verified against change management and IAM request records; scheduled tasks created by deployment tools (SCCM, Ansible) — verify against known deployment schedules |
| **Conclusion** | Any new accounts, group membership changes, or scheduled tasks created during the 48-hour window that are not in the change management record must be treated as attacker persistence until proven otherwise. |

---

## Detection Engineering

**Detection Name:** Domain Controller SIEM Blindspot — Log Gap Combined with Prior Tampering Indicators

| Field | Details |
|---|---|
| **Telemetry** | Wazuh agent heartbeat monitor, Windows Event Log (Security, System), Sysmon |
| **Relevant Fields** | agent.id, agent.name, last_keepalive, event.code, winlog.event_id, process.name, user.name, host.name |
| **Detection Logic** | ALERT when: (1) Wazuh agent on any host tagged as Domain Controller stops sending logs for more than 15 minutes (heartbeat gap), AND (2) the last events received from that agent within the preceding 30 minutes include any of: Event ID 1102 (audit log cleared), Event ID 4688 with process name matching mimikatz or known credential tools (including renamed variants flagged by hash), Event ID 4624 with LogonType=3 and AuthPackage=NTLM from an external IP, Event ID 4672 (SeDebugPrivilege assigned). A log gap alone on a non-critical host may be a bug. A log gap on a DC immediately after these events is a confirmed blindspot attack. |
| **Severity** | Critical |
| **False Positives** | Genuine Wazuh agent crash on DC during unrelated maintenance — must be correlated against the preceding event context; if the last events are routine, re-evaluate as low severity |
| **Analyst Response** | 1. Do NOT restart or reinstall the Wazuh agent — this overwrites forensic artefacts / 2. Isolate DC-02-PRD from the network immediately / 3. Preserve disk image and memory before any changes / 4. Check other DCs for authentication anomalies during the blindspot window / 5. Pull logs from any offsite SIEM buffer, backup log collector, or firewall NetFlow for the 48-hour window / 6. Escalate to L2/IR — suspected full domain compromise |

---

## Identity and Persistence Hunt

| Hunt Item | What to Look For | Where |
|---|---|---|
| New Domain Admins created | Event ID 4728 — member added to Domain Admins or Enterprise Admins during blindspot window | AD audit log, SIEM |
| DCSync permission changes | DS-Replication-Get-Changes or DS-Replication-Get-Changes-All granted to non-standard accounts on the domain root object | AD DACL audit (Event 5136), BloodHound / ADExplorer snapshot |
| Shadow Credentials | Key Credential Link (msDS-KeyCredentialLink) added to existing high-value accounts | AD attribute audit, Event 5136 on the account object |
| Golden Ticket indicators | KRBTGT account password last changed — if not reset after suspected compromise, attacker's Golden Ticket is still valid | AD — KRBTGT account properties; check for Event 4769 with unusual ticket encryption (RC4 where AES expected) |
| New service accounts | Accounts created with SPNs set (Kerberoastable), or accounts with AdminCount=1 not in known admin list | AD Users and Computers, PowerShell: Get-ADUser -Filter * -Properties AdminCount, ServicePrincipalName |
| Scheduled tasks on DC-02-PRD | Task Scheduler log (Event 4698) for tasks created during blindspot window, especially tasks pointing to temp paths or encoded commands | Windows Task Scheduler log, Wazuh, EDR |
| New GPO or logon scripts | New or modified GPOs, especially those modifying startup scripts, logon scripts, or disabling security controls | Group Policy Management Console, AD audit log (Event 5136 on GPO objects) |

**ONE thing to do before bringing Wazuh agent back online:**

Preserve a full forensic disk image of DC-02-PRD.

Reinstalling or restarting the Wazuh agent modifies the filesystem — timestamps change, artefacts in temp directories may be overwritten, and the agent's own installation process writes new files. If the attacker installed a rootkit, a persistence mechanism, or modified system binaries, those artefacts exist only until something writes over them. The disk image must be captured first, before any software is installed, restarted, or modified on DC-02-PRD. Memory should also be captured if possible — credential material and injected code live in RAM and are lost on restart. The disk image is the evidence. Everything else — remediation, agent reinstall, patching — comes after.

---

## MITRE ATT&CK

| Technique | ID | Relevance |
|---|---|---|
| OS Credential Dumping: LSASS Memory | T1003.001 | Mimikatz execution to dump domain credentials from LSASS |
| Indicator Removal: Clear Windows Event Logs | T1070.001 | Event ID 1102 — audit logs cleared to destroy forensic evidence |
| Impair Defenses: Disable or Modify Tools | T1562.001 | Wazuh agent stopped to create SIEM blindspot |
| Valid Accounts: Domain Accounts | T1078.002 | Anonymous logon with SeDebugPrivilege — elevated domain credential used |
| DCSync | T1003.006 | Suspected during blindspot window — attacker with Domain Admin can replicate all password hashes |
| Create Account: Domain Account | T1136.002 | Suspected persistence — new accounts created during blindspot |
| Scheduled Task/Job | T1053.005 | Suspected persistence mechanism on DC-02-PRD |
| Masquerading | T1036 | Mimikatz renamed as svchost.exe to evade process-name-based detection |

---

## Impact

**CRITICAL** — Domain Controller compromise with credential dumping capability means every account in the domain must be treated as potentially compromised. A Golden Ticket may already exist. The 48-hour blindspot means attacker dwell time and lateral movement scope are unknown.

---

## Actions

| Action Category | Details |
|---|---|
| **CONTAIN** | Isolate DC-02-PRD from the network immediately (do not power off — preserve memory); block all outbound connections from DC-02-PRD IP at the firewall |
| **PRESERVE** | Capture full forensic disk image and memory dump of DC-02-PRD before any changes; preserve all existing logs in Wazuh and on any offsite collector |
| **INVESTIGATE** | Review all other DCs for authentication anomalies during the 48-hour window; pull firewall NetFlow for DC-02-PRD connections; identify the clearing account from Event 1102 |
| **ERADICATE** | Remove all attacker persistence (new accounts, scheduled tasks, GPO changes, shadow credentials) identified in the hunt; rebuild DC-02-PRD from clean image if compromise is confirmed |
| **ROTATE** | Reset KRBTGT password TWICE (48 hours apart to invalidate all Kerberos tickets); reset all Domain Admin and privileged account passwords; rotate all service account credentials |
| **BLOCK** | Block the anonymous logon source if an external IP is identified; enforce Restricted Admin Mode for RDP; disable NTLM where possible |
| **ESCALATE** | L2/IR Team immediately — this is a suspected full domain compromise; notify AD owner and CISO; consider engaging external DFIR |

---

## Closure Checklist

- [ ] DC-02-PRD isolation status verified
- [ ] Forensic disk image and memory dump preserved before any changes
- [ ] Event IDs 1102, 4624, 4672, 4688, 4720, 4728, 4768, 4776 reviewed from preserved logs
- [ ] Credential dump activity (Mimikatz / LSASS access) fully investigated
- [ ] Clearing account from Event 1102 identified and investigated
- [ ] Domain Admin group membership audit completed — all unexpected members removed
- [ ] KRBTGT double-reset performed (reset 1 → wait 10 hours → reset 2)
- [ ] All privileged and service account passwords reset
- [ ] DCSync rights audit completed — DS-Replication permissions reviewed on domain root
- [ ] Shadow Credentials (msDS-KeyCredentialLink) checked on all privileged accounts
- [ ] New scheduled tasks and services on DC-02-PRD reviewed and removed if unauthorised
- [ ] New GPO changes reviewed and reverted if unauthorised
- [ ] Network lateral movement to other DCs investigated — 48-hour window covered
- [ ] Evidence preserved for forensics and potential legal/regulatory requirements
- [ ] Monitoring rules deployed for DC log gaps and log tampering
- [ ] Wazuh agent reinstalled only after disk image preserved and IR sign-off
- [ ] AD owner and business stakeholders informed
- [ ] Post-incident report drafted with full timeline

---

## Senior SOC Question

**What is more dangerous for a SOC — a Domain Controller that generates 10,000 alerts, or one that generates ZERO alerts for 48 hours?**

A Domain Controller that generates ZERO alerts for 48 hours is significantly more dangerous.

From a Detection Engineering perspective, 10,000 alerts is a signal problem — noisy rules, poor tuning, too many false positives. That is manageable. You tune the rules, suppress the noise, and the real threats surface. The DC is generating data. You have visibility.

Zero alerts for 48 hours is a visibility problem, and visibility problems are invisible by definition. You cannot detect what you cannot see. A sophisticated attacker does not trigger alerts — they silence the logging mechanism first, then operate freely. Every action they take during the blindspot window — credential dumping, lateral movement, persistence, DCSync — happens in complete silence. By the time the SOC notices the gap, the attacker may have already replicated every password hash in the domain, established multiple persistence mechanisms, and exited.

The 10,000-alert DC tells you something is happening. The zero-alert DC tells you nothing — and that silence may be the loudest indicator of all. Detection Engineering must treat prolonged log absence from critical infrastructure as an alert in itself, not as a technical issue to hand to IT.

---

**Status:** Escalated to L2/IR. DC-02-PRD isolated. Forensic preservation in progress. Wazuh agent reinstall on hold pending IR sign-off.