# SOC Triage Report
### SOC-2026-0923-21 | SIEM Blindspot — The Silent File Server
**Analyst:** Jnanashree Anchan | **Program:** GraySentinel DSOU | **Date:** 23 September 2026

---

## Alert Details

| Field | Value |
|---|---|
| Alert ID | SOC-2026-0923-21 |
| Rule | SIEM Blindspot — FS-01-PRD: No Logs Received for 36 Hours + Prior Event IDs 5140, 5145, 4688, 1102 |
| Severity | CRITICAL |
| Host | FS-01-PRD (File Server — Production) |
| Platform | Wazuh SIEM / Windows |

---

## Verdict

**TRUE POSITIVE — Suspected File Server Compromise. Blindspot Attack. Do NOT reinstall Wazuh agent before forensic preservation.**

---


| | |
|---|---|
| **WHAT** | SIEM log gap on a production file server, preceded by SYSVOL share access, sensitive file share access, encoded PowerShell execution, and audit log clearance |
| **WHEN** | 21 Sep 2026, 11:52 PM IST — last log received from FS-01-PRD. 36-hour silence follows. |
| **WHERE** | FS-01-PRD — Production File Server |
| **WHO** | Unknown threat actor — activity indicates privileged access with the ability to clear audit logs and stop the SIEM agent |
| **WHY** | Data staging and exfiltration from sensitive file shares, log tampering to erase evidence, and likely lateral movement to backup infrastructure |
| **HOW** | 1. SYSVOL and sensitive share accessed (Events 5140, 5145) → 2. Encoded PowerShell executed (Event 4688) → 3. Audit logs cleared (Event 1102) → 4. Wazuh agent stopped to create 36-hour SIEM blindspot |

---

## Attack Chain

| Timestamp | Log Event | Attack Phase |
|---|---|---|
| 21 Sep 11:52 PM IST | 5140 — Network share accessed (SYSVOL) on FS-01-PRD | Reconnaissance / Data Access |
| 21 Sep 11:52 PM IST | 5145 — Detailed file share access on sensitive folder | Data Staging |
| 21 Sep 11:52 PM IST | 4688 — powershell.exe with encoded command executed | Execution / Lateral Movement |
| 21 Sep 11:52 PM IST | 1102 — Audit log cleared on FS-01-PRD | Defense Evasion / Log Tampering |
| 21 Sep 11:52 PM IST | Wazuh agent goes silent — last log received | SIEM Blindspot Created |
| 21 Sep 11:52 PM+ IST | 36-hour log gap — no visibility into FS-01-PRD activity | Exfiltration / Persistence (undetected window) |

---

## Mission 01: Asset Discovery

| Asset Item | Why It Matters | Where to Find It |
|---|---|---|
| Role of FS-01-PRD | File server vs DFS vs print server determines what data is at risk and what lateral movement paths exist | CMDB, server documentation, AD topology |
| Internet exposure | File server should never be internet-facing; SMB exposure is catastrophic | Firewall rules, network diagrams, perimeter scan |
| Wazuh agent status and version | How the agent was stopped tells us if it was intentional — killed, service disabled, or uninstalled | Wazuh Manager — agent status panel, Windows Services log on FS-01-PRD |
| Last patch cycle and EDR status | Unpatched file server or absent EDR expands attacker options; AV saying "No Threat" is not a clearance | WSUS/SCCM patch reports, EDR console, AV management |
| Who has local admin / Backup Operator rights | These rights allow shadow copy deletion, log clearing, and full share access — they define the blast radius | Local Administrators group, AD — Backup Operators group |
| Recent logon activity on FS-01-PRD | Identify attacker sessions, pass-the-hash, lateral movement from other hosts | Windows Security Event 4624, 4648 on FS-01-PRD |
| Service accounts running on FS-01-PRD | Service accounts with excessive share permissions are a persistence and data access vector | AD Users and Computers, Wazuh, EDR |
| Recent share permission changes | Attackers modify share permissions to grant themselves or Everyone full access | Event ID 5136 on share objects, File Server Resource Manager |
| SMB / NTLM auth logs around 11:52 PM | Identify the source of the share access and what credentials were used | Event IDs 5140, 5145, 4624, 4776 on FS-01-PRD |
| Network connections from FS-01-PRD | Identify data exfiltration destinations or lateral movement to backup infrastructure | Firewall logs, Sysmon Event ID 3, NetFlow / VPC flow logs |

---

## Mission 02: Hunting Hypotheses

**H1: Security logs were cleared to hide data staging and exfiltration from the file server**

Hypothesis: The attacker accessed sensitive file shares (Events 5140, 5145), staged data using an encoded PowerShell command (Event 4688), then cleared the audit logs (Event 1102) to destroy evidence of what was accessed and copied.

| Field | Details |
|---|---|
| **Evidence Required** | Event ID 1102 (Audit log cleared) with the clearing account identified; Event IDs 5140 and 5145 showing which shares and files were accessed; Event ID 4688 showing the encoded PowerShell command and its decoded content; network connections from FS-01-PRD to external or unexpected IPs in the window before the clear |
| **Data Sources** | Windows Security Event Log (preserved from before clearance), Sysmon logs forwarded to Wazuh before agent went silent, firewall NetFlow, any offsite log backup or SIEM buffer |
| **Expected Indicators** | 5145 events showing bulk access to sensitive folders immediately before the 1102 clear; encoded PowerShell (-EncodedCommand) decoded to a file copy, compression, or exfiltration command; outbound connections from FS-01-PRD to cloud storage, FTP, or unknown IPs; 1102 event with a non-standard account as the clearing identity |
| **False Positives** | Scheduled log rotation scripts run by IT operations — typically documented, run under known accounts, and do not coincide with share access and encoded PowerShell; legitimate admin clearing logs during maintenance — must be verified against change management |
| **Conclusion** | Event 1102 following bulk share access and encoded PowerShell execution is not a maintenance event. The encoded command must be decoded and the clearing account identity in 1102 must be identified. Any outbound connection from FS-01-PRD during this window is a confirmed exfiltration indicator. |

---

**H2: Wazuh agent was intentionally stopped to create SIEM blindness before lateral movement to backup infrastructure**

Hypothesis: After gaining privileged access on FS-01-PRD, the attacker stopped the Wazuh agent to prevent detection of subsequent activity — specifically lateral movement to backup servers or NAS infrastructure connected to the file server.

| Field | Details |
|---|---|
| **Evidence Required** | Event ID 7036 showing Wazuh agent service stopped; Event ID 4688 or 4689 showing wazuh-agent.exe killed; the account identity that stopped the service; on backup servers and connected infrastructure: authentication events from FS-01-PRD's IP or newly used credentials during the 36-hour window |
| **Data Sources** | Windows System Event Log on FS-01-PRD, Wazuh Manager (last heartbeat, disconnection reason), backup server authentication logs, EDR telemetry |
| **Expected Indicators** | Wazuh agent service stopped by a non-standard account within seconds of the 1102 log clear; authentication requests on backup infrastructure from FS-01-PRD IP during the blindspot window; shadow copy deletion commands (vssadmin delete shadows) in Sysmon or EDR telemetry; access to backup share paths from FS-01-PRD |
| **False Positives** | Wazuh agent crash due to genuine software bug — but a crash does not explain the preceding 5140, 5145, 4688, and 1102 events; scheduled agent restart during maintenance — verify against change management |
| **Conclusion** | A crash is possible in isolation but the four preceding high-severity events make this a deliberate sequence. The focus of lateral movement here would be backup infrastructure — attackers target backups specifically to destroy recovery capability before deploying ransomware or to maintain persistent access. |

---

**H3: A malicious scheduled task or service was created for persistence after file server compromise**

Hypothesis: During the 36-hour blindspot window, the attacker created a persistence mechanism on FS-01-PRD — a scheduled task, a new service, or a startup key modification — to maintain access even if their initial session is terminated.

| Field | Details |
|---|---|
| **Evidence Required** | Event ID 4698 (scheduled task created) on FS-01-PRD during the blindspot window; Event ID 7045 (new service installed); Registry modifications to Run/RunOnce keys (Event 4657 or Sysmon Event ID 13); Event ID 4720 (new local user account created) |
| **Data Sources** | Windows Task Scheduler log, Windows System Event Log (7045), Sysmon registry event logs, AD audit log, EDR if deployed |
| **Expected Indicators** | Scheduled tasks created outside business hours pointing to executables in temp directories or with encoded PowerShell commands; new services with names mimicking system services (WindowsUpdate, SvcHost32); Run key entries pointing to non-standard paths; new local admin accounts with names similar to existing accounts |
| **False Positives** | Legitimate scheduled tasks created by deployment tools (SCCM, Ansible) — verify against known deployment schedules; software updates creating new services — verify against change management |
| **Conclusion** | Any scheduled task, service, or startup key created during the 36-hour blindspot window that is not in the change management record must be treated as attacker persistence until proven otherwise. |

---

## Mission 03: Detection Engineering

**Detection Name:** File Server SIEM Blindspot — Log Gap Combined with Prior Share Access and Tampering Indicators

| Field | Details |
|---|---|
| **Telemetry** | Wazuh agent heartbeat monitor, Windows Event Log (Security, System), Sysmon |
| **Relevant Fields** | agent.id, agent.name, last_keepalive, event.code, winlog.event_id, process.name, process.command_line, user.name, host.name, share.name |
| **Detection Logic** | ALERT when: (1) Wazuh agent on any host tagged as File Server stops sending logs for more than 15 minutes (heartbeat gap), AND (2) the last events received from that agent within the preceding 30 minutes include any of: Event ID 1102 (audit log cleared), Event ID 4688 with a Base64-encoded command line (-EncodedCommand or -enc flag), Event ID 5140 or 5145 showing access to sensitive share paths (SYSVOL, admin shares, backup shares), Event ID 4672 (SeDebugPrivilege or Backup Privilege assigned). A log gap alone on a non-critical host may be a bug. A log gap on a file server immediately after share access, encoded PowerShell, and log clearance is a confirmed blindspot attack. |
| **Severity** | Critical |
| **False Positives** | Genuine Wazuh agent crash during unrelated maintenance — must be correlated against the preceding event context; if the last events are routine, re-evaluate as low severity |
| **Analyst Response** | 1. Do NOT restart or reinstall the Wazuh agent — this overwrites forensic artefacts / 2. Isolate FS-01-PRD from the network immediately / 3. Preserve disk image and memory before any changes / 4. Decode the PowerShell -EncodedCommand from the preserved 4688 event / 5. Pull firewall NetFlow for FS-01-PRD outbound connections during the 36-hour window / 6. Check backup infrastructure for access from FS-01-PRD IP / 7. Escalate to L2/IR |

---

## Mission 04: Identity and Persistence Hunt

| Hunt Item | What to Look For | Where |
|---|---|---|
| New local admin accounts | Event ID 4720 (new local account created), accounts added to local Administrators group | Windows Security log, Local Users and Groups |
| SMB share permission changes | Share permissions changed to Everyone / Full Control, or new share created | Event 5136, File Server Resource Manager, share audit |
| Shadow copies deleted | vssadmin delete shadows, wmic shadowcopy delete commands executed on FS-01-PRD | Sysmon Event ID 1, EDR telemetry, VSS admin logs |
| New scheduled tasks | Task Scheduler log (Event 4698) for tasks created during blindspot window, especially pointing to temp paths or encoded commands | Windows Task Scheduler log, Wazuh, EDR |
| New services installed | Event ID 7045 — new service installed outside of normal deployment windows | Windows System Event Log |
| Startup folder / Run key modifications | New entries in HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run or Startup folders | Sysmon Event ID 13, Registry audit (Event 4657) |
| PowerShell history and script block logs | Review PowerShell Operational log (Event 4104) for script block content forwarded before agent went silent | Windows PowerShell Operational log, Wazuh |

**ONE thing to do before bringing Wazuh agent back online:**

Preserve a full forensic disk image of FS-01-PRD.

Reinstalling or restarting the Wazuh agent modifies the filesystem — timestamps change, artefacts in temp directories may be overwritten, and the agent's installation process writes new files. If the attacker deployed a persistence mechanism, modified system binaries, or staged data in a temp location, those artefacts exist only until something writes over them. The encoded PowerShell command from Event 4688 may also have dropped files that only exist on disk — decoding that command is one of the first steps, and those files need to be captured before anything else touches the system. The disk image is the evidence. Everything else — remediation, agent reinstall, patching — comes after.

---

## MITRE ATT&CK

| Technique | ID | Relevance |
|---|---|---|
| Network Share Discovery | T1135 | Event 5140 — attacker enumerated and accessed SYSVOL and sensitive shares |
| Data from Network Shared Drive | T1039 | Event 5145 — files accessed from sensitive share during staging window |
| Command and Scripting Interpreter: PowerShell | T1059.001 | Event 4688 — encoded PowerShell command executed to evade detection |
| Indicator Removal: Clear Windows Event Logs | T1070.001 | Event 1102 — audit logs cleared to destroy forensic evidence |
| Impair Defenses: Disable or Modify Tools | T1562.001 | Wazuh agent stopped to create SIEM blindspot |
| Scheduled Task/Job | T1053.005 | Suspected persistence mechanism on FS-01-PRD during blindspot window |
| Create Account: Local Account | T1136.001 | Suspected persistence — new local admin accounts may have been created |
| Inhibit System Recovery | T1490 | Suspected shadow copy deletion to remove recovery options |
| Exfiltration Over C2 Channel | T1041 | Encoded PowerShell likely used to exfiltrate staged data |

---

## Impact

**CRITICAL** — A compromised file server with 36 hours of undetected access means the full scope of data accessed, staged, and exfiltrated is unknown. If shadow copies were deleted, recovery options are limited. If backup infrastructure was reached during the blindspot window, the entire backup chain may be compromised.

---

## Actions

| Action Category | Details |
|---|---|
| **CONTAIN** | Isolate FS-01-PRD from the network immediately (do not power off — preserve memory); block all outbound connections from FS-01-PRD IP at the firewall |
| **PRESERVE** | Capture full forensic disk image and memory dump of FS-01-PRD before any changes; preserve all existing Wazuh logs and any offsite log buffer |
| **INVESTIGATE** | Decode the Base64 PowerShell command from Event 4688; identify the clearing account from Event 1102; pull firewall NetFlow for FS-01-PRD outbound connections during the 36-hour window; check backup infrastructure for access from FS-01-PRD |
| **ERADICATE** | Remove all attacker persistence (new accounts, scheduled tasks, services, Run key entries, share permission changes) identified in the hunt; verify shadow copies — restore from clean backup if deleted |
| **ROTATE** | Reset all service account passwords with access to FS-01-PRD; reset local admin credentials; rotate any credentials that may have been accessible from the server |
| **BLOCK** | Block any external IPs identified in outbound connections during the blindspot window; enforce SMB signing; restrict access to admin shares |
| **ESCALATE** | L2/IR Team immediately — suspected data exfiltration from production file server; notify file server owner and CISO; assess data breach notification requirements |

---

## Mission 05: Closure Checklist

- [ ] FS-01-PRD isolation status verified
- [ ] Forensic disk image and memory dump preserved before any changes
- [ ] Event IDs 1102, 5140, 5145, 4688, 4672, 4720, 7045 reviewed from preserved logs
- [ ] Encoded PowerShell command from Event 4688 decoded and analysed
- [ ] Clearing account from Event 1102 identified and investigated
- [ ] Data staging and exfiltration activity investigated — scope of data accessed determined
- [ ] Local admin group membership audit completed — all unexpected accounts removed
- [ ] Backup infrastructure access reviewed — 36-hour window covered
- [ ] Shadow copies verified — restore status confirmed
- [ ] Service accounts and scheduled tasks on FS-01-PRD reviewed and cleaned
- [ ] Persistence (scheduled task / service / Run key / startup folder) investigated and removed
- [ ] Share permissions audited — unauthorised changes reverted
- [ ] Network lateral movement to other servers investigated
- [ ] Evidence preserved for forensics and potential legal/regulatory requirements
- [ ] Data breach notification requirements assessed with legal/compliance
- [ ] Monitoring rules deployed for file server log gaps and share access anomalies
- [ ] Wazuh agent reinstalled only after disk image preserved and IR sign-off
- [ ] File server owner and business stakeholders informed
- [ ] Post-incident report drafted with full timeline

---

## Senior SOC Question

**What is more dangerous for a SOC — a File Server that generates 10,000 alerts, or one that generates ZERO alerts for 36 hours?**

A File Server that generates ZERO alerts for 36 hours is significantly more dangerous.

10,000 alerts is a noise problem. The file server is generating data — you can tune the rules, filter the false positives, and surface real threats. You have visibility, and visibility is manageable.

Zero alerts for 36 hours is an invisibility problem. You cannot tune what you cannot see. A file server going silent after share access, encoded PowerShell, and log clearance means an attacker operated freely for a day and a half — accessing files, staging data, possibly exfiltrating, possibly reaching backup infrastructure — with no detection possible. By the time the SOC notices the gap, the attacker may have already copied everything they wanted and deleted the shadow copies behind them.

The 10,000-alert file server is loud but visible. The zero-alert file server is quiet and gone. Detection Engineering must treat a prolonged log gap from a file server holding sensitive data as a critical alert in itself — not a technical issue to escalate to IT.

---

**Status:** Escalated to L2/IR. FS-01-PRD isolated. Forensic preservation in progress. Wazuh agent reinstall on hold pending IR sign-off.