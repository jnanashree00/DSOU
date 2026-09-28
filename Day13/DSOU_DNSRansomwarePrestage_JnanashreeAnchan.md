# SOC Triage Report
### SOC-2026-0928-01 | Ransomware Pre-Stage: The Silent Encryptor

**Analyst:** Jnanashree Anchan | **Program:** GraySentinel DSOU | **Date:** 28 September 2026

---

## Alert Details

| Field | Value |
|---|---|
| **Alert ID** | SOC-2026-0928-01 |
| **Rule** | Mass file rename with ransom extension, shadow copy deletion, and audit log clear on a file server |
| **Severity** | Critical |
| **Host** | FILE-SRV-02 (Windows file server) |
| **Platform** | Wazuh SIEM, Sysmon, Windows Security logs |
| **CVE / CVSS** | Not applicable. This is behavior based, and the host is reported patched. |

---

## Verdict

**Confirmed active ransomware encryption in progress on FILE-SRV-02 (LockBit style). This is not a file sync issue. Do NOT power off or reboot the host before a memory capture is taken, because the encryption keys may still be in RAM and are lost on shutdown.**

The "No Threat Found" result from antivirus does not clear the host. Signature antivirus routinely misses living off the land behavior like vssadmin, bcdedit, and native file operations. The combination of a ransom extension, sub minute mass renames, recovery inhibition, and a cleared audit log is a ransomware playbook, not a sync fault.

---


| Field | Detail |
|---|---|
| **WHAT** | Active ransomware encrypting files on the Finance share. Files renamed with a .lockbit extension, shadow copies deleted, boot recovery disabled, and the audit log cleared. |
| **WHEN** | Monday 28 September 2026, morning. Multiple renames inside a 60 second window, with encryption still ongoing at alert time. |
| **WHERE** | FILE-SRV-02, starting in C:\Shares\Finance. The SMB access spike suggests other shares and hosts are in scope. |
| **WHO** | Not yet attributed. A process on FILE-SRV-02 is performing the renames. A compromised service account with share write access is the leading theory. |
| **WHY** | Financial impact. Encrypt business data for extortion, with recovery deliberately inhibited to force payment. |
| **HOW** | Mass file rename and encryption, vssadmin delete shadows, bcdedit recoveryenabled No, and an Event 1102 log clear to slow the response. |

---

## Attack Chain

| Timestamp | Log Event | Attack Phase |
|---|---|---|
| T0 | 5145 SMB detailed file share access spike | Access and staging over SMB |
| T0 plus seconds | 4688 vssadmin.exe delete shadows /all /quiet | Inhibit System Recovery |
| T0 plus seconds | 4688 bcdedit.exe /set {default} recoveryenabled No | Inhibit System Recovery |
| T0 plus under 60s | Sysmon 11 mass renames to .lockbit (invoice_2026.xlsx.lockbit) | Data Encrypted for Impact |
| T0 plus after encryption | 1102 Windows audit log cleared | Defense Evasion, indicator removal |

Note: exact clock times should be read from Wazuh. The order above is the reconstructed sequence. Recovery inhibition running just before the rename burst is the tell that this was a planned encryption run, not routine file activity.

---

## Mission 01 — Asset Discovery

| Asset Item | Why It Matters | Where to Find It |
|---|---|---|
| **Role of FILE-SRV-02** | Plain file server, DFS node, or department share sets the blast radius and which data is hit | CMDB, AD computer object, DFS management |
| **Departments and users on its shares** | Tells you who is affected and who to notify | Share and NTFS permissions, DFS namespace, AD groups |
| **Wazuh agent status and version** | Confirms whether the telemetry is trustworthy or already tampered | Wazuh manager agent list |
| **Last patch cycle and EDR status** | Shows if a gap or a disabled EDR helped the actor | Patch management, EDR console |
| **Encrypting process, PID and parent chain** | Identifies the encryptor and how it launched | Sysmon 1 and 11, EDR process tree |
| **Recent logon activity** | Points to the account used and a possible source host | 4624, 4625, 4672 on FILE-SRV-02 |
| **Service accounts with write access to shares** | Tests the compromised service account theory | Share and NTFS ACLs, AD |
| **Backup status and last good restore point** | Decides whether recovery is possible after shadow deletion | Backup console, offsite backup logs |
| **SMB session activity at encryption start** | Reveals the source of the writes and any spread | 5140, 5145, Wazuh SMB events |
| **Network connections in the last 7 days** | Surfaces command and control and lateral targets | Sysmon 3, firewall logs, EDR network view |

---

## Mission 02 — Hunting Hypotheses

**H1: Ransomware has already encrypted part of FILE-SRV-02 and is spreading to other shares.**

| Field | Details |
|---|---|
| **Evidence Required** | Encrypted files beyond Finance, .lockbit spread across share paths, ransom notes, SMB writes reaching other hosts |
| **Data Sources** | Sysmon 11, Wazuh FIM, 5145 and 5140 SMB, EDR |
| **Expected Indicators** | Rapid rename bursts across multiple paths, one process touching thousands of files, ransom note drops |
| **False Positives** | Bulk legitimate file moves, archival jobs, DFS replication storms |
| **Conclusion** | Strongly supported by the rename burst and SMB spike. Treat as live until the spread scope is confirmed. |

**H2: A compromised service account with share write access is deploying the encryptor.**

| Field | Details |
|---|---|
| **Evidence Required** | Service account logon at encryption time, file writes owned by that account, unusual source host or off hours activity |
| **Data Sources** | 4624 and 4672, 5145 share access, share ACLs, EDR user context of the process |
| **Expected Indicators** | One service or automation account writing across Finance and other shares, network logon from an unexpected host |
| **False Positives** | A normal backup or batch account doing scheduled bulk writes |
| **Conclusion** | Plausible and quick to test. Pull the process owner and the 5145 subject account first. |

**H3: Shadow copy and recovery deletion are a precursor to domain wide deployment.**

| Field | Details |
|---|---|
| **Evidence Required** | vssadmin and bcdedit run on other hosts, a staged binary on a share, a GPO or scheduled task pushing the encryptor |
| **Data Sources** | 4688 across the fleet, Sysmon, GPO change logs, scheduled task events 4698 |
| **Expected Indicators** | The same recovery inhibition commands on more than one host, a shared binary hash across hosts |
| **False Positives** | Admin maintenance using vssadmin, storage cleanup scripts |
| **Conclusion** | High risk. Recovery inhibition is classic pre encryption staging, so hunt this pattern fleet wide right away. |

---

## Mission 03 — Detection Engineering

**Detection Name:** Ransomware Encryption and Recovery Inhibition on File Server

| Field | Details |
|---|---|
| **Telemetry** | Sysmon Event 11 (file create and rename), Sysmon Event 1 (process create), Windows Security 4688, Wazuh FIM |
| **Relevant Fields** | TargetFilename, Image, ProcessId, host, CommandLine, NewProcessName, SubjectUserName |
| **Detection Logic** | High rate of distinct TargetFilename changes by a single Image within 60s (for example over 50) OR TargetFilename ending in a known ransom extension. Correlate with 4688 where NewProcessName is vssadmin.exe, bcdedit.exe, or wbadmin.exe and CommandLine matches "delete shadows", "recoveryenabled no", or "delete catalog". Raise to critical when an encryption burst and recovery inhibition hit the same host within 5 minutes. |
| **Severity** | Critical |
| **False Positives** | Backup software, bulk migrations, disk cleanup windows. Tune with an allowlist of known backup and admin accounts and hosts. |
| **Analyst Response** | Isolate the host at the network level, identify and suspend the process, capture memory, preserve logs, then run the containment playbook. |

---

## Mission 04 — Identity and Persistence Hunt

| Hunt Item | What to Look For | Where to Hunt |
|---|---|---|
| **Ransom notes** | README.txt, DECRYPT.txt, or restore instruction files in share roots | Sysmon 11, FIM, share directories |
| **Encryptor binary** | New or unsigned executable in Temp, ProgramData, or a share | Sysmon 1, EDR, hash reputation |
| **Scheduled tasks** | New tasks set to re run encryption | 4698, schtasks, Task Scheduler |
| **New services** | A service installed for persistence | 7045, 4697 |
| **Run key or startup** | Autorun entries added under Run keys or the Startup folder | Sysmon 13, registry autoruns |
| **Service account misuse** | An account writing where it never normally does | 4624, 4672, 5145 |
| **Recovery deletion** | Confirmed shadow copy removal and bcdedit changes | 4688, vssadmin activity |
| **Lateral movement** | Writes or logons to other file servers or domain controllers | 4624, 5140, Sysmon 3 |

**The ONE thing to do before shutting FILE-SRV-02 down: capture a full memory image first.**

Ransomware often holds its file encryption keys, the running encryptor process, injected code, and live network connections in RAM. A shutdown or reboot wipes all of that, and with it any chance of recovering keys or reconstructing exactly what the process did. So the correct move is to isolate the host at the network level, by pulling the cable or disabling the switch port, which stops the spread over SMB while keeping the process alive, and only then take the memory capture, followed by a disk image. Powering off to "stop it" trades away the best forensic evidence and can still leave recovery impossible if backups were already deleted.

---

## MITRE ATT&CK

| Technique | ID | Relevance |
|---|---|---|
| **Data Encrypted for Impact** | T1486 | Mass rename to .lockbit on the Finance share |
| **Inhibit System Recovery** | T1490 | vssadmin delete shadows and bcdedit recoveryenabled No |
| **Indicator Removal: Clear Windows Event Logs** | T1070.001 | Event 1102, audit log cleared |
| **SMB and Windows Admin Shares** | T1021.002 | SMB detailed access spike, likely the spread vector |
| **Valid Accounts** | T1078 | Suspected compromised service account with share write access |

---

## Impact

**CRITICAL.** A production Finance file server is being actively encrypted, and the attacker has already deleted shadow copies and disabled boot recovery, so local rollback is likely gone. Clearing the audit log shows an intent to blind the SOC and buy time. If the encryptor is reaching other shares over SMB, this can become a domain wide event within hours. Business impact includes loss of Finance data, downtime for every department mapped to FILE-SRV-02, and a real extortion risk if data was also stolen before encryption.

---

## Actions

| Action Category | Details |
|---|---|
| **CONTAIN** | Isolate FILE-SRV-02 at the network level without powering it off. Disable the affected SMB shares to stop further writes. |
| **PRESERVE** | Capture volatile memory, then a disk image. Export Sysmon, Security, and EDR logs before they roll or are cleared again. |
| **INVESTIGATE** | Identify the encryptor process and parent chain, the account running it, the source host over SMB, and every path already encrypted. |
| **ERADICATE** | Suspend then kill the encryptor process, quarantine the binary by hash across the fleet, and remove any persistence found in Mission 04. |
| **ROTATE** | Reset the suspected service account and any credentials used on the host. Rotate privileged accounts if they touched FILE-SRV-02. |
| **BLOCK** | Block the binary hash on EDR and any command and control IPs or domains at the firewall and proxy. |
| **ESCALATE** | Notify the IR lead, the Finance asset owner, and management. Loop in legal and comms if data theft is suspected. |

---

## Mission 05 — Closure Checklist

- [ ] FILE-SRV-02 network isolation verified
- [ ] Memory capture and disk image preserved
- [ ] Sysmon, Security, and EDR telemetry preserved
- [ ] Event IDs 1102, 4688, 5145, and Sysmon 11 reviewed
- [ ] Encryptor binary identified and quarantined
- [ ] Shadow copy and backup deletion investigated
- [ ] Service account credentials rotated
- [ ] Lateral movement from FILE-SRV-02 reviewed
- [ ] Persistence (scheduled task, service, Run key) investigated
- [ ] Evidence preserved for forensics with chain of custody
- [ ] Detection tuned for ransomware encryption behavior
- [ ] Business and asset owner informed

---

## Senior SOC Question

**What is more dangerous: a file server that generates 10,000 file rename alerts, or one that generates ZERO file rename alerts for 48 hours?**

The zero alerts case is more dangerous. Ten thousand alerts is noisy and painful to triage, but it means the sensor is alive and you have visibility. You can group, sort, and rate limit that noise, and the signal is clearly in there. Zero rename alerts for 48 hours on a busy file server is not proof of calm. On a server where users save files all day, silence usually means the telemetry stopped: the Wazuh agent is down, Sysmon logging was disabled, the rule broke, or an attacker cleared and suppressed the logs, which is exactly the 1102 behavior in this incident. From a detection engineering view, absence of expected telemetry is itself an alert condition. You should monitor agent heartbeats and expected event baselines, and fire on a sudden drop to zero, so a dead or muted sensor pages you instead of hiding a live intrusion. Noise you can tune. Blindness you cannot.

---

## References

- [MITRE ATT&CK T1486: Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
- [MITRE ATT&CK T1490: Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/)
- [MITRE ATT&CK T1070.001: Clear Windows Event Logs](https://attack.mitre.org/techniques/T1070/001/)
- [Wazuh Documentation: Sysmon integration and log analysis](https://documentation.wazuh.com/)
- [Sigma: generic detection rule format for SIEM](https://sigmahq.io/)
- [CISA StopRansomware: guidance and response resources](https://www.cisa.gov/stopransomware)

---

**Status:** Active incident. Containment in progress, evidence preservation underway, escalated to the IR lead.