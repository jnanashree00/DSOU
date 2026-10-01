# SOC Triage Report
### SOC-2026-0930-01 | Operation Phantom PowerShell

**Analyst:** Jnanashree Anchan | **Program:** GraySentinel DSOU | **Date:** 30 September 2026

---

## Alert Details

| Field | Value |
|---|---|
| **Alert ID** | SOC-2026-0930-01 |
| **Rule** | Office application spawning encoded PowerShell, with an outbound connection and finance share access |
| **Severity** | Critical |
| **Host** | FIN-WS-042 (finance workstation) |
| **Platform** | Wazuh SIEM, Windows Security, Sysmon, PowerShell logging |
| **CVE / CVSS** | Not applicable. This is phishing and macro execution, behavior based. |

---

## Verdict

**Confirmed suspicious. This is not a false positive and not routine Excel use. excel.exe spawning an encoded powershell.exe, an outbound connection, and finance file access together are a malicious macro delivering a PowerShell payload. Do NOT close this as benign and do NOT reimage FIN-WS-042 yet, because the attachment, the decoded command, the destination, and the scope of file access still need to be captured.**

The Windows Defender "No Threat Found" result does not clear this. A macro that launches base64 encoded PowerShell is behavior, not a known file signature, so signature antivirus has little to match. The user opening an Excel attachment is the delivery step, not an innocent explanation.

---


| Field | Detail |
|---|---|
| **WHAT** | A malicious Excel attachment ran a macro that launched an encoded PowerShell command, which made an outbound connection and accessed finance files on FILE-SRV-02. |
| **WHEN** | Wednesday 30 September 2026, morning. The process, network, and file events cluster close together. Exact times to be read from Wazuh. |
| **WHERE** | FIN-WS-042, a finance workstation, reaching the finance share on FILE-SRV-02. |
| **WHO** | The logged in finance user opened the attachment, which is the user execution step. The operator behind the payload is external and not yet identified. |
| **WHY** | Likely initial access and data theft. Gain code execution through a macro, beacon out, and reach finance data. |
| **HOW** | Phishing email with an Excel attachment, a macro that spawns encoded PowerShell, an outbound connection, a network logon to the file server, and multiple file accesses on the finance share. |

---

## Attack Chain

| Timestamp | Log Event | Attack Phase |
|---|---|---|
| T0 | Email with Excel attachment received | Phishing, initial access |
| T0 plus | Sysmon 1: excel.exe spawns powershell.exe | User execution, malicious macro |
| T0 plus | 4688: powershell.exe with an encoded command | Execution, obfuscated PowerShell |
| T0 plus | 4104: script block logging flags the decoded script | Execution, script block evidence |
| T0 plus | Sysmon 3: outbound connection to an external IP | Command and control |
| T0 plus | 4624: Logon Type 3 to FILE-SRV-02 | Lateral access to the file server |
| T0 plus | 4663: multiple file accesses on the finance share | Collection, data access |

Note: times from Wazuh. The order above is the reconstructed sequence.

---

## Mission 01 — Initial Triage

| Item to Establish | Why It Matters | Where to Find It |
|---|---|---|
| **User logged into FIN-WS-042** | Identifies the victim and the account at risk | 4624, 4648, endpoint |
| **Attachment name and file type** | Confirms the delivery vector and lets you hunt other inboxes | Mail gateway, user mailbox |
| **Excel to PowerShell parent-child** | The core proof of a malicious macro | Sysmon 1, 4688 parent fields |
| **Exact PowerShell command line** | Shows intent and the payload | 4688, 4104 script block |
| **Whether -EncodedCommand was used** | Obfuscation is a strong malicious signal | 4688 command line, 4104 |
| **PowerShell execution timestamp** | Anchors the timeline | 4688, Sysmon 1 |
| **Destination IP or domain** | The C2 to block and pivot on | Sysmon 3, firewall, proxy |
| **Files accessed on FILE-SRV-02** | Scopes the data exposure | 4663, 5145 on the server |
| **User's normal working pattern** | Baseline to judge how abnormal this is | Manager, prior logs |
| **Other recipients of the same email** | Scope of the phishing campaign | Mail gateway search |
| **Hash of the Excel attachment** | Lets you hunt the file across the fleet | EDR, mail gateway |
| **Recent authentication for the user** | Detects credential misuse | 4624, 4625, 4768 |

---

## Mission 02 — Hunting Hypotheses

**H1: FIN-WS-042 was compromised through a malicious Excel attachment that launched PowerShell.**

| Field | Details |
|---|---|
| **Evidence Required** | excel.exe as the parent of powershell.exe, an encoded command, the attachment in the mailbox, macro content |
| **Data Sources** | Sysmon 1, 4688, 4104, mail gateway |
| **Expected Indicators** | Office spawns PowerShell with -enc, the script block shows download or execute behavior |
| **False Positives** | A legitimate Office add in or macro that calls PowerShell, which is rare on a finance workstation |
| **Conclusion** | Strongly supported. The parent-child relationship plus encoding fit maldoc delivery. Primary hypothesis. |

**H2: The PowerShell activity is legitimate administrative automation.**

| Field | Details |
|---|---|
| **Evidence Required** | The command matches a known admin task, a signed script, a scheduled job, or an RMM tool, run in an admin or service context |
| **Data Sources** | 4688, 4104, Task Scheduler, software inventory |
| **Expected Indicators** | A known script path, no Office parent, no external beacon |
| **False Positives** | This is the benign hypothesis itself |
| **Conclusion** | Unlikely. Legitimate automation is not launched by Excel, is not base64 encoded, and does not beacon to an unknown IP. Reject unless a known tool is identified. |

**H3: The compromised workstation was used to access finance files and establish outbound communication.**

| Field | Details |
|---|---|
| **Evidence Required** | Logon Type 3 to FILE-SRV-02, 4663 on finance files, a sustained outbound connection, signs of staging |
| **Data Sources** | 4624, 4663, 5145, Sysmon 3, proxy |
| **Expected Indicators** | PowerShell reaching the share shortly after execution, bytes out to the external IP |
| **False Positives** | Normal finance file use by the same user, so check the timing against the PowerShell run |
| **Conclusion** | Supported and the most damaging. File access right after execution points to collection. Treat as active data exposure. |

---

## Mission 03 — Process and Command-Line Hunt

| Stage | Evidence |
|---|---|
| **Email received** | Mail gateway log, attachment in the user mailbox |
| **Excel opened** | Office recent files, Sysmon 1 for excel.exe |
| **PowerShell spawned** | Sysmon 1, excel.exe as parent of powershell.exe |
| **Encoded command executed** | 4688 with -EncodedCommand, 4104 decoded script block |
| **Network connection** | Sysmon 3, outbound from the PowerShell PID |
| **File access** | 4624 Type 3 to FILE-SRV-02, then 4663 on finance files |
| **Additional authentication** | Later 4624 or 4768 for the user on other hosts |

| Question | Finding and Next Step |
|---|---|
| **What started PowerShell?** | excel.exe, per Sysmon 1. That parent is the macro and the strongest single indicator. |
| **What command-line arguments?** | powershell.exe with -EncodedCommand. Decode the base64 from 4104 to recover the real script and any URL. |
| **Hidden or non-interactive?** | Encoded payloads usually pair with -WindowStyle Hidden and -NonInteractive. Confirm the full flags from the 4688 command line. |
| **Did it create another process?** | Check Sysmon 1 for children of the PowerShell PID, such as a dropped exe, rundll32, or cmd. |
| **Did it download or execute a file?** | The Sysmon 3 outbound suggests a second stage. Check Sysmon 11 for a written file and any follow on execution. |
| **Which destination?** | The external IP from Sysmon 3. Enrich with reputation and whois, then block. |
| **Seen on other endpoints?** | Hunt the IP, domain, and the encoded command pattern across the fleet and the mail gateway. |

---

## Mission 04 — Detection Engineering

**Detection Name:** Office Application Spawning Encoded PowerShell

| Field | Details |
|---|---|
| **Telemetry** | Sysmon 1 (process create with parent), Windows Security 4688, PowerShell 4104 |
| **Relevant Fields** | ParentImage, Image, CommandLine, OriginalFileName, User |
| **Detection Logic** | ParentImage in (winword.exe, excel.exe, powerpnt.exe, outlook.exe) AND Image ends with powershell.exe or pwsh.exe. Raise higher when CommandLine contains -enc, -EncodedCommand, -w hidden, IEX, DownloadString, or FromBase64String. Correlate with a following Sysmon 3 outbound from the same PowerShell PID. |
| **Severity** | High, raised to Critical when an outbound connection or file share access follows |
| **False Positives** | Legitimate Office add ins or macros that call PowerShell. Allowlist known signed automation. |
| **Analyst Response** | Isolate the host, pull the attachment and the command line, block the destination, and scope file access and other recipients. |

This detection keys on the parent-child relationship, not the presence of PowerShell alone, which is what keeps it high fidelity.

---

## MITRE ATT&CK

| Technique | ID | Relevance |
|---|---|---|
| **Phishing: Spearphishing Attachment** | T1566.001 | Malicious Excel attachment delivery |
| **User Execution: Malicious File** | T1204.002 | User opened the attachment and ran the macro |
| **Command and Scripting Interpreter: PowerShell** | T1059.001 | Encoded PowerShell launched by Excel |
| **Application Layer Protocol** | T1071 | PowerShell outbound connection to an external IP |
| **Remote Services: SMB and Windows Admin Shares** | T1021.002 | Logon Type 3 from the workstation to FILE-SRV-02 |
| **Data from Network Shared Drive** | T1039 | Multiple file accesses on the finance share |

---

## Impact

**CRITICAL.** A finance workstation executed attacker supplied PowerShell through a malicious document, reached out to external infrastructure, and accessed finance data on a shared server. The risks are theft of finance files, a foothold for lateral movement using the user's access, and a phishing campaign that may have reached other staff. If credentials or data were exfiltrated, the impact widens quickly. Treat this as a live intrusion with potential data exposure, not a single noisy alert.

---

## Actions

| Action Category | Details |
|---|---|
| **CONTAIN** | Isolate FIN-WS-042 at the network level and block the external IP or domain at the perimeter. Consider disabling the user session. |
| **PRESERVE** | Capture a memory image of FIN-WS-042, the Excel attachment, the 4104 PowerShell logs, and the relevant Security and Sysmon logs, before any reimage. |
| **INVESTIGATE** | Decode the PowerShell, find any second stage, scope the files accessed on FILE-SRV-02, enrich the destination, and find other recipients and matching hashes. |
| **ERADICATE** | Remove the payload and any persistence, such as run keys or scheduled tasks, after evidence is captured. |
| **ROTATE** | Reset the user's credentials and any secrets reachable from the host. |
| **BLOCK** | Block the destination IP or domain and the attachment hash across mail and EDR. |
| **ESCALATE** | Notify the IR lead, the finance data owner, and management. Engage email security to pull the campaign. |

---

## Mission 05 — Lateral Movement and Data Access Hunt

| Hunt Item | What to Look For | Where to Hunt |
|---|---|---|
| **SMB to internal servers** | The host or PowerShell reaching other servers | 5140, 5145, Sysmon 3 |
| **New Logon Type 3 events** | Network logons sourced from FIN-WS-042 | 4624 Type 3 |
| **Finance and shared folder access** | Reads on sensitive shares | 4663, 5145 on FILE-SRV-02 |
| **RDP attempts** | 3389 logons from the host | 4624 Type 10, 4625 |
| **Remote PowerShell** | WinRM activity on 5985 | 4104, WinRM logs, Sysmon 3 |
| **Remote process creation** | Processes spawned on other hosts | 4688, Sysmon 1 on targets |
| **Credential access** | LSASS access or dumping tools | Sysmon 10, EDR |
| **Unusual account usage** | The user's account on new hosts | 4624 across the fleet |
| **Access to sensitive documents** | Opens of finance documents | 4663, file auditing |
| **Same indicators on other endpoints** | The command pattern or IP elsewhere | SIEM hunt |

**Before reimaging FIN-WS-042, collect the host and volatile evidence first.**

Capture a memory image, the running process tree, and the open network connections, because the decoded PowerShell, any injected code, the live C2 socket, and an in memory second stage exist only in RAM and are gone after a wipe. Also preserve the Excel attachment and its hash, the full command line and 4104 script block logs, Office recent file and macro artifacts, prefetch, any scheduled tasks or run keys for persistence, and the relevant Security and Sysmon logs. The reasoning is simple: reimaging is the fastest way to lose the only copy of the payload, the destination, the persistence, and the proof of what was accessed. Without that evidence you cannot confirm what was taken, block the infrastructure, hunt the campaign on other hosts, or show the box was truly cleaned. Capture first, then reimage.

---

## Mission 06 — Incident Containment

- [ ] FIN-WS-042 network isolation verified
- [ ] User account status reviewed
- [ ] Malicious email identified
- [ ] Attachment preserved
- [ ] File hash calculated
- [ ] PowerShell command captured and decoded
- [ ] Destination IP or domain investigated
- [ ] FILE-SRV-02 access reviewed
- [ ] Other recipients of the email identified
- [ ] Same hash searched across endpoints
- [ ] Same command-line pattern searched in the SIEM
- [ ] Relevant logs preserved
- [ ] Endpoint forensic evidence preserved
- [ ] Business owner informed

---

## Senior SOC Question

**Which gives the SOC stronger context: a PowerShell process running on a workstation, or Excel then PowerShell then a network connection then file access?**

The correlated chain, by a wide margin. A lone PowerShell process means almost nothing on its own, because PowerShell runs constantly for legitimate administration and software, so it is high volume and low fidelity. The chain of Excel to PowerShell to an outbound connection to finance file access is a story: an Office document spawned a shell, the shell called out, and then finance data was touched. Each link is weak alone, but together they describe both intent and impact, which is exactly what a detection should fire on. From a detection engineering view, correlating the parent-child relationship and the sequence turns noisy single events into a high fidelity signal with few false positives, and it tells the analyst not just that something ran but what it did and what is now at risk. Detections built on relationships and sequence beat detections built on the presence of a single tool.

---

## References

- [MITRE ATT&CK T1566.001: Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)
- [MITRE ATT&CK T1204.002: User Execution, Malicious File](https://attack.mitre.org/techniques/T1204/002/)
- [MITRE ATT&CK T1059.001: Command and Scripting Interpreter, PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [MITRE ATT&CK T1039: Data from Network Shared Drive](https://attack.mitre.org/techniques/T1039/)
- [Wazuh Documentation: Windows monitoring and log analysis](https://documentation.wazuh.com/)
- [Sigma: generic detection rule format for SIEM](https://sigmahq.io/)

---

**Status:** Active incident. Containment in progress, evidence preservation underway, escalated to the IR lead, phishing campaign scope under review.
