# SOC Triage Report
### SOC-2026-1013-01 | Pass-the-Hash: The Silent Lateral Movement

**Analyst:** Jnanashree Anchan | **Program:** GraySentinel DSOU | **Date:** 13 October 2026

---

## Alert Details

| Field | Value |
|---|---|
| **Alert ID** | SOC-2026-1013-01 |
| **Rule** | The svc_backup service account authenticating to multiple servers over NTLM (not Kerberos) with network logons from WS-201, special privileges assigned, and access to ADMIN$ and C$ shares |
| **Severity** | Critical |
| **Hosts** | DC-01-PRD and FILE-SRV-01 (targets), WS-201 (source) |
| **Account** | svc_backup (service account) |
| **Platform** | Wazuh, Sysmon, Windows Security, Active Directory, EDR |
| **CVE / CVSS** | Not applicable. This is valid-account abuse and alternate-authentication-material use, behavior based. |

---

## Verdict

**Confirmed Pass-the-Hash lateral movement, not a service-account sync issue and not a false positive. The svc_backup account is authenticating to DC-01-PRD and FILE-SRV-01 over NTLM rather than Kerberos, with Type 3 network logons originating from WS-201 and immediate access to ADMIN$ and C$ shares. NTLM authentication for a service account hitting admin shares on multiple servers from a single workstation is the signature of a stolen NTLM hash being replayed, not a password that fell out of sync. Do NOT reset the svc_backup password yet, because the source of the hash (patient zero), the full scope of systems it reached, and the volatile evidence must be established first, and a premature reset tips the attacker without removing their access.**

The servers being patched and antivirus returning "No Threat Found" does not clear this. Pass-the-Hash uses valid credentials and native SMB, so there is no malware signature to catch and nothing unpatched to exploit; the attack is authentication abuse, invisible to AV and patch state. The detection that matters is NTLM where Kerberos is expected, a privileged account moving between servers from an unusual source, and admin-share access, not the fact that svc_backup logged on.

---

| Field | Detail |
|---|---|
| **WHAT** | The svc_backup NTLM hash is being replayed from WS-201 to authenticate to DC-01-PRD and FILE-SRV-01 and reach their ADMIN$ and C$ shares. |
| **WHEN** | Tuesday 13 October 2026, morning, with the logons clustered across multiple servers. Exact times from Wazuh. |
| **WHERE** | Source WS-201, targets DC-01-PRD and FILE-SRV-01, over SMB to ADMIN$ and C$. |
| **WHO** | The svc_backup service account, but the pattern (NTLM, multiple servers, one source workstation) indicates an attacker replaying its hash, not legitimate backup activity. |
| **WHY** | Lateral movement toward privileged and domain resources, likely a precursor to payload deployment or ransomware over SMB. |
| **HOW** | A stolen NTLM hash (likely dumped from LSASS) is replayed: Type 3 NTLM logons (4624, 4776) with special privileges (4672) from WS-201, then SMB to ADMIN$ (Sysmon 3, 5140). |

---

## Attack Chain

| Timestamp | Log Event | Attack Phase |
|---|---|---|
| T0 (prior) | NTLM hash of svc_backup obtained, likely LSASS dump on WS-201 or a server | Credential access |
| T0 | 4624 Type 3 network logon from WS-201 | Lateral movement |
| T0 plus | 4624 and 4776 NTLM authentication for svc_backup (not Kerberos) | Use of stolen hash |
| T0 plus | 4672 special privileges assigned to the logon | Privileged access |
| T0 plus | Sysmon 3 SMB connection to \\FILE-SRV-01\ADMIN$ | Lateral movement over SMB |
| T0 plus | 5140 network share accessed (ADMIN$, C$) | Admin-share access |

Note: NTLM for an account that should use Kerberos, from one workstation into multiple servers' admin shares, is the replay-the-hash pattern. Correlate before attributing, but the authentication protocol, the single source host, and the admin-share targets line up as Pass-the-Hash.

---

## Mission 01 — Asset Discovery

| Item to Establish | Why It Matters | Where to Find It |
|---|---|---|
| **Role of svc_backup (backup operator, service account)** | Its legitimate scope and whether multi-server admin access is expected | AD, service documentation |
| **Which servers svc_backup logs into** | Maps the normal baseline against today's targets | 4624 across the fleet, AD |
| **Is NTLM expected in this environment** | NTLM where Kerberos is the norm is the core anomaly | Auth baselines, GPO |
| **Wazuh agent status and version on WS-201** | Whether the source host's telemetry is complete | Agent status |
| **Last patch cycle and EDR status on WS-201** | Confirms sensor health on patient-zero candidate | Patch management, EDR console |
| **Recent logon activity for svc_backup** | When the abnormal pattern began | 4624, 4776 history |
| **Local admin rights of svc_backup across servers** | The blast radius if the hash is replayed | AD, local groups audit |
| **SMB session activity around alert time** | What was accessed or written on the shares | 5140, 5145, Sysmon 3 |
| **Who uses WS-201** | Whether the source host is a plausible origin or itself compromised | Asset inventory, 4624 |
| **Network connections from WS-201 over 7 days** | Full spread and whether more servers were touched | SIEM, NetFlow |

**Deliverable:** an Asset Context Map covering svc_backup (role, expected servers, admin rights), WS-201 (user, patch and EDR state), and the target servers. **Primary question:** is svc_backup's activity its legitimate backup function, or an attacker replaying its NTLM hash? That is answered by whether NTLM is expected, whether the source host and target set match the account's baseline, and by finding where the hash was first stolen.

---

## Mission 02 — Hunting Hypotheses

**H1: The NTLM hash of svc_backup was captured via an LSASS dump and is being replayed for lateral movement across servers.**

| Field | Details |
|---|---|
| **Evidence Required** | An LSASS access event on a host holding svc_backup credentials, then NTLM logons (4624 Type 3, 4776) from WS-201 to multiple servers |
| **Data Sources** | Sysmon (Event 10), Windows Security, Wazuh, EDR |
| **Expected Indicators** | A prior credential-access event, NTLM instead of Kerberos, one source host reaching many servers, 4672 special privileges |
| **False Positives** | Legacy applications that genuinely require NTLM, approved backup jobs that use the account broadly |
| **Conclusion** | Strongly supported. NTLM replay from a single workstation into multiple servers fits Pass-the-Hash. Primary hypothesis; confirm by finding the LSASS dump (patient zero). |

**H2: A compromised service account with local admin rights is being used to access ADMIN$ shares and deploy payloads.**

| Field | Details |
|---|---|
| **Evidence Required** | ADMIN$ and C$ access (5140, 5145), files written to the shares, new services or tasks created remotely |
| **Data Sources** | Windows Security, Sysmon, SMB logs, EDR |
| **Expected Indicators** | Admin-share writes, new service installs (7045), remote scheduled tasks (4698), binaries dropped to C$ |
| **False Positives** | Legitimate software deployment or backup tooling that uses admin shares |
| **Conclusion** | Supported and the active risk. svc_backup reaching ADMIN$ and C$ on multiple servers is the delivery path; check the shares for written payloads and remote execution. |

**H3: The Pass-the-Hash activity is a precursor to domain-wide ransomware deployment over SMB.**

| Field | Details |
|---|---|
| **Evidence Required** | Spread pattern across servers and DCs, staging of an executable, mass SMB connections, access to a DC |
| **Data Sources** | DC logs, Windows Security, SMB logs, EDR, NetFlow |
| **Expected Indicators** | The account fanning out to many hosts, a payload staged on shares, DC access, a rapid burst of SMB sessions |
| **False Positives** | Legitimate mass administration or patch deployment windows |
| **Conclusion** | Plausible and the worst case. A privileged account moving to a DC over SMB is a classic pre-ransomware stage; treat scope as urgent and check for staging and DC compromise. |

---

## Mission 03 — Detection Engineering

**Detection Name:** Pass-the-Hash / NTLM Lateral Movement

| Field | Details |
|---|---|
| **Telemetry** | Windows Security (4624, 4672, 4776), Sysmon (Event 3 network connect), SMB/file-share auditing (5140, 5145), EDR |
| **Relevant Fields** | TargetUserName, LogonType, AuthenticationPackageName, LmPackageName, IpAddress/WorkstationName, ShareName, PrivilegeList, ProcessName |
| **Detection Logic** | IF a 4624 Type 3 logon uses NTLM (AuthenticationPackageName NTLM, or a 4776 validation) for an account that normally authenticates via Kerberos AND the same account authenticates to multiple servers from a single source host within a short window AND the logon is followed by ADMIN$ or C$ access (5140) or special privileges (4672), THEN raise HIGH to CRITICAL. Key on NTLM-where-Kerberos-is-expected plus one-source-to-many-servers, not on NTLM alone, which some legacy apps still use. |
| **Severity** | Critical when the account is privileged or a domain controller is a target |
| **False Positives** | Legacy applications and appliances that require NTLM, vulnerability scanners, approved backup or deployment accounts that legitimately touch many servers. Baseline each service account's normal source hosts and target set, and allowlist known NTLM-dependent apps. |
| **Analyst Response** | Confirm the authentication protocol and source host, map every server the account reached, identify where the hash was stolen, check admin shares for written payloads, hunt the account and source host across the fleet, and escalate for coordinated credential containment. |

---

## MITRE ATT&CK

| Technique | ID | Relevance |
|---|---|---|
| **Use Alternate Authentication Material: Pass the Hash** | T1550.002 | The stolen NTLM hash replayed to authenticate |
| **Remote Services: SMB/Windows Admin Shares** | T1021.002 | ADMIN$ and C$ access for lateral movement |
| **Valid Accounts: Domain Accounts** | T1078.002 | svc_backup credentials abused as a valid account |
| **OS Credential Dumping: LSASS Memory** | T1003.001 | Likely source of the svc_backup hash |
| **Lateral Tool Transfer** | T1570 | Candidate payload staging over the admin shares |
| **Lateral Movement (tactic)** | TA0008 | The overall objective across DC-01-PRD and FILE-SRV-01 |

---

## Mission 04 — Identity & Persistence Hunt

Hunt for what the attacker may have left across the targeted servers.

- [ ] New local admin accounts on target servers (4720, 4732)
- [ ] ADMIN$ and C$ share access anomalies (5140, 5145)
- [ ] New services installed via SMB (7045)
- [ ] Scheduled tasks created remotely (4698)
- [ ] WMI event subscription persistence
- [ ] Credential material in PowerShell history (4104)
- [ ] Lateral movement to other servers and domain controllers
- [ ] svc_backup privilege escalation or group changes

**Critical question: if Pass-the-Hash is confirmed, what is the ONE thing you must do before resetting the svc_backup password?**

Scope the full compromise first: identify patient zero (the host where the hash was stolen, likely an LSASS dump on WS-201 or a server) and map every system the hash reached, while preserving volatile evidence from the affected hosts. The reason is that resetting the password is a one-time tripwire. It invalidates the current hash, but it also tips the attacker that they are detected, and if done before the scope is known it buys nothing: the attacker still holds any other credentials dumped from the same hosts, still has whatever persistence they planted (new services, scheduled tasks, local admins), and can simply re-dump and continue, now aware they are being hunted. Worse, resetting only svc_backup while leaving patient zero in place means the hash is re-stolen on the next logon. So the one prerequisite is knowing the blast radius, which systems and which accounts, so the reset can be done for every compromised credential at once, coordinated with isolating patient zero and removing persistence. Capture memory and SMB evidence before that reset, because it is also what proves how the hash was obtained. (Note: service and privileged accounts are then reset twice, per the closure checklist, to fully clear cached hashes.)

---

## Impact

**CRITICAL.** A privileged service account's hash is being replayed across production servers including a domain controller, which puts the domain itself at risk. If the hash reached DC-01-PRD, the attacker is one step from domain-wide control, and the admin-share access is the delivery path for payloads or ransomware across every reachable host. Because the credential is already stolen, it survives a reimage of any single host, so coordinated credential rotation and finding patient zero matter more than rebuilding one server. Treat this as an active intrusion with privileged credential compromise and imminent lateral spread.

---

## Actions

| Action Category | Details |
|---|---|
| **SCOPE** | Identify patient zero and map every server the svc_backup hash reached before any reset, using DC logs and fleet-wide NTLM searches. |
| **PRESERVE** | Capture memory and disk images from WS-201 and the targeted servers, and preserve the 4624, 4672, 4776, 5140, and Sysmon 3 events and SMB records. |
| **CONTAIN** | Isolate WS-201 and the affected servers (DC coordinated with AD owners), after scope and evidence are secured, or immediately if active destruction is seen. |
| **INVESTIGATE** | Find the LSASS dump source, check ADMIN$ and C$ for staged payloads, review remote service and task creation, and follow the account to any other servers and DCs. |
| **ROTATE** | Reset svc_backup twice, along with every credential exposed on patient zero, in one coordinated action; consider KRBTGT and tier-0 review if a DC was reached. |
| **ERADICATE** | Remove any persistence (services, tasks, WMI, rogue admins) after evidence capture. |
| **BLOCK** | Disable NTLM where feasible for the account, block the source host, and tighten admin-share access. |
| **ESCALATE** | Notify the IR lead and the AD/domain owner immediately given DC involvement, and raise fleet-wide NTLM-anomaly monitoring. |

---

## Mission 05 — Incident Closure

- [ ] WS-201 isolation status verified
- [ ] Affected servers isolation status verified
- [ ] Memory capture and disk image preserved
- [ ] Sysmon logs, Security logs, and EDR telemetry preserved
- [ ] Event IDs 4624, 4672, 4776, 5140, and Sysmon 3 reviewed
- [ ] NTLM authentication anomalies investigated
- [ ] svc_backup password rotated (twice)
- [ ] Local admin group membership audit done
- [ ] Lateral movement from WS-201 reviewed
- [ ] Persistence (scheduled task, service, WMI) investigated
- [ ] Evidence preserved for forensics
- [ ] Monitoring increased for NTLM anomalies (rule tuning)
- [ ] Business and AD owner informed

---

## Senior SOC Question

**What is more dangerous for a SOC: a server generating 10,000 NTLM authentication alerts, or a server generating ZERO NTLM authentication alerts for 48 hours?**

From a detection-engineering view, the quiet server is usually the more dangerous one. Ten thousand NTLM alerts is almost certainly a tuning problem, a legacy application or an appliance that authenticates over NTLM constantly, and while the volume is painful it is visible and fixable by baselining that source and allowlisting it. Its danger is indirect: it trains analysts to ignore NTLM alerts, so the one real Pass-the-Hash event drowns in the noise. Zero NTLM alerts for 48 hours is more dangerous because the silence is ambiguous and the two explanations look identical on the dashboard: either the server genuinely saw no NTLM activity, or the SOC has lost visibility into it. The causes of false silence are exactly what an attacker benefits from, a stopped or starved Sysmon service, an audit policy that never enabled logon or share auditing, a disconnected EDR sensor, or an agent that is not forwarding, and a careful operator can keep Pass-the-Hash low and slow, a handful of logons that look like normal service traffic, producing almost nothing alarming while moving laterally. This case shows it: the servers were patched, AV-clean, and the activity looked like a service account doing its job, yet it was hash replay into a domain controller. The lesson is that alert volume measures noise, not security, and absence of NTLM alerts is only reassuring when backed by positive proof of telemetry health, a recent agent heartbeat, the expected baseline of logon and share events still arriving, and auditing confirmed on for 4624, 4776, and 5140. A server is only safely quiet when you can prove it would have spoken if there were something to say.

---

## References

- [MITRE ATT&CK T1550.002: Use Alternate Authentication Material, Pass the Hash](https://attack.mitre.org/techniques/T1550/002/)
- [MITRE ATT&CK TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008/)
- [MITRE ATT&CK T1021.002: Remote Services, SMB and Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/)
- [Wazuh Documentation: Windows auditing](https://documentation.wazuh.com/)
- [SigmaHQ: Pass-the-Hash detection rule format](https://sigmahq.io/)
- [CISA: identifying and mitigating lateral movement](https://www.cisa.gov/)

---

**Status:** Active incident. Scope being established before any credential reset, patient zero (LSASS dump source) under investigation, WS-201 and the targeted servers flagged for memory capture and isolation, svc_backup slated for coordinated double rotation across all exposed credentials, and the DC involvement escalated to the AD owner with a fleet-wide NTLM-anomaly hunt open.
