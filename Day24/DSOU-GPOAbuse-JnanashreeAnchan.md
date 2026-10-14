# SOC Triage Report
### SOC-2026-1014-01 | GPO Abuse: The Silent Domain-Wide Push

**Analyst:** Jnanashree Anchan | **Program:** GraySentinel DSOU | **Date:** 14 October 2026

---

## Alert Details

| Field | Value |
|---|---|
| **Alert ID** | SOC-2026-1014-01 |
| **Rule** | A newly created GPO linked to the domain root pushing a SYSVOL startup script and a SYSTEM scheduled task to all domain machines, created around an off-hours logon and a privilege assignment to helpdesk_01 |
| **Severity** | Critical |
| **Host** | DC-01-PRD (domain controller), WS-045 (source) |
| **Account** | helpdesk_01 |
| **Platform** | Wazuh, Windows Security, Sysmon, Active Directory, SYSVOL |
| **CVE / CVSS** | Not applicable. This is Group Policy and domain-policy abuse, behavior based. |

---

## Verdict

**Confirmed malicious GPO abuse for domain-wide persistence, not a software deployment and not a false positive. A new GPO was created and linked to the domain root (5136), and it pushes a SYSVOL startup script (sync.bat) and a SYSTEM-level scheduled task (schtasks.exe /create /s * /ru SYSTEM) to every domain-joined machine. The creation coincides with an off-hours Type 3 logon from WS-045 and a special-privilege assignment to helpdesk_01, a help-desk account that should not be creating domain-root GPOs. Do NOT delete the GPO yet, because its contents, the SYSVOL payload, the link scope, and the list of machines that have already applied it must be captured first, and deletion stops future pushes but does not undo what has already run.**

The DC being patched and antivirus returning "No Threat Found" does not clear this. GPO abuse uses legitimate Active Directory functionality, there is no malware to detect and nothing unpatched to exploit, so AV silence here means no signature matched, not that nothing is wrong. The detection that matters is an unexpected account creating a GPO linked to the domain root that delivers a startup script and a SYSTEM task, not that a GPO exists.

---

| Field | Detail |
|---|---|
| **WHAT** | A new GPO linked to the domain root pushes sync.bat (SYSVOL startup script) and a SYSTEM scheduled task to all domain machines, creating domain-wide persistence. |
| **WHEN** | Wednesday 14 October 2026, with the GPO created around an off-hours logon. Exact times from Wazuh. |
| **WHERE** | DC-01-PRD, the GPO linked at the domain root, payload staged in \\SYSVOL\domain\Policies\{GUID}\Machine\Scripts\Startup\. |
| **WHO** | helpdesk_01, with an off-hours logon from WS-045; a help-desk account creating a domain-root GPO indicates compromise or abused delegation, not routine admin. |
| **WHY** | Domain-wide persistence and code execution as SYSTEM on every machine, likely a precursor to mass payload or ransomware deployment. |
| **HOW** | An off-hours Type 3 logon (4624) from WS-045 with special privileges (4672) created and linked a GPO (5136), staged sync.bat (Sysmon 11), and pushed a SYSTEM scheduled task (4688). |

---

## Attack Chain

| Timestamp | Log Event | Attack Phase |
|---|---|---|
| T0 | 4624 Type 3 off-hours logon from WS-045 | Initial access / staging |
| T0 plus | 4672 special privileges assigned to helpdesk_01 | Privileged access |
| T0 plus | 5136 directory object modified, new GPO under CN=Policies | GPO creation |
| T0 plus | 5136 GPO linked to the domain root | Domain-wide scoping |
| T0 plus | Sysmon 11 sync.bat created in SYSVOL Startup scripts | Persistence payload staged |
| T0 plus | 4688 schtasks.exe /create /s * /ru SYSTEM pushed via GPO | Domain-wide SYSTEM execution |

Note: a new GPO linked at the domain root that drops a SYSVOL startup script and a SYSTEM scheduled task is the GPO-persistence pattern, and the off-hours help-desk logon makes legitimate change unlikely. Correlate before attributing, but the creation, the root link, and the SYSVOL payload are one coordinated action.

---

## Mission 01 — Asset Discovery

| Item to Establish | Why It Matters | Where to Find It |
|---|---|---|
| **Role of DC-01-PRD (PDC emulator, GPO owner)** | Whether this DC is the authoritative source for GPO changes | AD, FSMO roles |
| **Account that created or modified the GPO** | The actor behind the change | 5136, GPO creation metadata |
| **Whether helpdesk_01 should have GPO creation rights** | A help-desk account with GPO rights is the core anomaly | AD delegation, GPO ACLs |
| **Wazuh agent status and version on DC-01-PRD** | Whether DC telemetry is complete | Agent status |
| **Last patch cycle and EDR status on DC-01-PRD** | Confirms sensor health on the DC | Patch management, EDR console |
| **Group Policy change audit over the last 7 days** | Whether this is isolated or part of a series | 5136, 5137, GPO version history |
| **GPO scope: which OUs, users, computers are targeted** | The blast radius of the push | GPO links, 5136 link events |
| **Contents of sync.bat in SYSVOL** | What is actually being executed domain-wide | \\SYSVOL\...\Scripts\Startup\, file analysis |
| **Recent logon activity for helpdesk_01** | Whether the account is compromised and from where | 4624, 4625 |
| **Network connections from WS-045 over 7 days** | Whether the source host is the staging point and what else it touched | SIEM, NetFlow |

**Deliverable:** an Asset Context Map for DC-01-PRD (role, GPO ownership), the GPO (creator, scope, SYSVOL payload), and the helpdesk_01/WS-045 origin. **Primary question:** is the new GPO a sanctioned software deployment or malicious domain-wide persistence? That is answered by who created it, whether that account should have GPO rights, the GPO's scope, and the contents of sync.bat.

---

## Mission 02 — Hunting Hypotheses

**H1: A malicious GPO was created to push a startup script that installs persistence or malware domain-wide.**

| Field | Details |
|---|---|
| **Evidence Required** | The 5136 GPO creation and domain-root link, the sync.bat payload in SYSVOL, the pushed SYSTEM scheduled task |
| **Data Sources** | Windows Security (5136), Sysmon (Event 11), SYSVOL, Wazuh |
| **Expected Indicators** | A new GPO at the domain root, a startup script in SYSVOL, a SYSTEM task pushed to all machines, created by an unexpected account |
| **False Positives** | A legitimate, change-controlled software-deployment GPO created by an authorised admin in a maintenance window |
| **Conclusion** | Strongly supported. A domain-root GPO delivering a SYSVOL startup script and a SYSTEM task, created by a help-desk account off-hours, fits malicious domain-wide persistence. Primary hypothesis; confirm by analysing sync.bat. |

**H2: A compromised help-desk account with delegated GPO rights is being used for privilege escalation and lateral movement.**

| Field | Details |
|---|---|
| **Evidence Required** | helpdesk_01's logon trail, its GPO and delegation rights, the off-hours WS-045 logon, any onward access |
| **Data Sources** | Windows Security (4624, 4672), AD delegation, EDR |
| **Expected Indicators** | A help-desk account with GPO creation rights, off-hours logon from an unusual host, special privileges assigned, access beyond its role |
| **False Positives** | A help-desk admin legitimately granted GPO rights working an approved off-hours change |
| **Conclusion** | Supported and the identity angle. The off-hours logon and special-privilege assignment to a help-desk account creating a domain-root GPO indicate the account is compromised or its delegation is being abused. Check whether GPO rights were recently delegated. |

**H3: The GPO modification is a precursor to ransomware deployment across all domain-joined machines.**

| Field | Details |
|---|---|
| **Evidence Required** | The payload's behaviour, whether it stages or fetches an executable, the breadth of the GPO scope, timing |
| **Data Sources** | SYSVOL script contents, Sysmon, EDR, proxy/DNS |
| **Expected Indicators** | A script that downloads or launches a binary, a domain-wide scope, a SYSTEM task timed to trigger broadly |
| **False Positives** | A legitimate mass-deployment script that installs approved software |
| **Conclusion** | Plausible and the worst case. A SYSTEM-level script pushed to every machine is the ideal ransomware delivery mechanism; treat scope as urgent and analyse sync.bat for a payload or download. |

---

## Mission 03 — Detection Engineering

**Detection Name:** Malicious GPO Creation / Modification on a Domain Controller

| Field | Details |
|---|---|
| **Telemetry** | Windows Security (5136, 5137 directory object create/modify), Sysmon (Event 11 SYSVOL file create), process creation (4688), logon (4624, 4672) |
| **Relevant Fields** | ObjectDN (CN=Policies), SubjectUserName, OperationType, AttributeLDAPDisplayName (gPLink, gPCFileSysPath), TargetFilename (SYSVOL Scripts), ProcessCommandLine |
| **Detection Logic** | IF a GPO object is created or modified (5136 under CN=Policies) by an account not in the approved GPO-admin set OR a gPLink change links a GPO to the domain root or a sensitive OU AND within a correlated window a startup/logon script appears in SYSVOL (Sysmon 11) or a SYSTEM scheduled task is pushed (4688 schtasks /ru SYSTEM), THEN raise CRITICAL. Key on who made the change and the domain-root link plus a SYSVOL payload, not on GPO changes alone, which happen legitimately. |
| **Severity** | Critical when linked at the domain root or created by a non-GPO-admin account |
| **False Positives** | Authorised GPO changes and software deployments by GPO admins in change windows, legitimate logon/startup scripts. Allowlist the approved GPO-admin accounts and baseline normal change windows and SYSVOL script paths. |
| **Analyst Response** | Identify the creating account and whether it should have GPO rights, capture the GPO contents and SYSVOL payload, determine the link scope and which machines applied it, unlink before deleting after evidence capture, and escalate for domain-wide containment. |

---

## MITRE ATT&CK

| Technique | ID | Relevance |
|---|---|---|
| **Domain or Tenant Policy Modification: Group Policy Modification** | T1484.001 | The malicious GPO creation and domain-root link |
| **Domain or Tenant Policy Modification** | T1484 | Abuse of domain policy for control |
| **Scheduled Task/Job: Scheduled Task** | T1053.005 | The SYSTEM scheduled task pushed via GPO |
| **Boot or Logon Initialization Scripts** | T1037 | The SYSVOL startup script (sync.bat) |
| **Valid Accounts: Domain Accounts** | T1078.002 | The compromised or abused helpdesk_01 account |
| **Account Manipulation** | T1098 | Possible delegation changes granting GPO rights |

---

## Mission 04 — Identity & Persistence Hunt

Hunt for what the attacker may have left across the domain.

- [ ] New GPOs created in the last 7 days (5136, 5137)
- [ ] GPOs linked to the domain root or sensitive OUs (gPLink changes)
- [ ] Startup and logon scripts in SYSVOL
- [ ] Scheduled tasks created via GPO (4698, 4688 schtasks)
- [ ] New local admin accounts pushed via GPO
- [ ] Delegation changes on GPO rights (5136 on GPO ACLs, 4662)
- [ ] SYSVOL file modifications (Sysmon 11)
- [ ] Lateral movement to other domain controllers

**Critical question: if a malicious GPO is confirmed, what is the ONE thing you must do before deleting it?**

Preserve the evidence and scope the impact first: capture the GPO object and its settings, the SYSVOL payload (sync.bat and any linked files), the gPLink/scope, and the 5136 audit trail, and determine which machines have already applied the GPO and run its script and task. The reason is that deletion is irreversible and only stops future propagation; it does nothing about what has already executed. A GPO linked at the domain root is pulled and applied by machines across the domain on their refresh cycle, so by the time the SOC sees it, sync.bat and the SYSTEM scheduled task have very likely already run on many hosts. Deleting the GPO erases the record of exactly what was pushed, which is the forensic key to knowing what to remediate, and it leaves the persistence (the scheduled task, any dropped payload, any new local admins) in place on every machine that already applied it, now with no GPO to trace them back to. So before deleting: image or export the GPO and SYSVOL contents, build the list of affected machines from gpupdate and task-creation events, and only then unlink and remove it, pairing removal with cleanup of the persistence it planted. Unlinking first (rather than deleting) stops further spread while preserving the object for analysis.

---

## Impact

**CRITICAL.** A GPO linked at the domain root means code execution as SYSTEM on every domain-joined machine, which is effectively domain-wide compromise through a single trusted mechanism. The SYSVOL startup script and the SYSTEM scheduled task give durable persistence on all of them, and the setup is the classic delivery path for mass ransomware. Because the persistence is pushed to every machine that applies the policy, removing the GPO alone does not clean the endpoints, and a help-desk account with GPO rights suggests the attacker already holds privileged delegation. Treat this as an active, domain-wide intrusion with imminent mass-execution risk.

---

## Actions

| Action Category | Details |
|---|---|
| **PRESERVE** | Capture the GPO object and settings, the SYSVOL payload (sync.bat), the gPLink scope, and the 5136/4688/Sysmon 11 events, and image DC-01-PRD before any change. |
| **SCOPE** | Build the list of machines that have already applied the GPO and run its script and task, from gpupdate and task-creation events across the fleet. |
| **CONTAIN** | Unlink the GPO from the domain root immediately to stop further propagation (do not delete yet), and isolate WS-045 and DC-01-PRD as warranted. |
| **INVESTIGATE** | Analyse sync.bat for payload or download behaviour, confirm how helpdesk_01 got GPO rights, review delegation changes, and check for other new GPOs and DCs touched. |
| **ERADICATE** | After evidence capture, remove the GPO and clean the persistence it planted (scheduled task, scripts, any new admins) on every affected host. |
| **ROTATE** | Reset helpdesk_01 and review GPO-admin delegation; if the DC or krbtgt is implicated, escalate to tier-0 credential review. |
| **ESCALATE** | Notify the IR lead and the AD owner immediately given domain-root and DC involvement, and raise GPO-change monitoring. |

---

## Mission 05 — Incident Closure

- [ ] DC-01-PRD isolation status verified
- [ ] Wazuh logs and Sysmon preserved (disk image)
- [ ] Event IDs 5136, 4688, 4624, and 4672 reviewed
- [ ] Malicious GPO identified and unlinked
- [ ] SYSVOL script contents analysed
- [ ] helpdesk_01 account password rotated
- [ ] GPO delegation rights audit done
- [ ] Domain Admin group membership audit done
- [ ] Persistence (scheduled task, service, startup) investigated
- [ ] Lateral movement to other DCs reviewed
- [ ] Evidence preserved for forensics
- [ ] Monitoring increased for GPO changes (rule tuning)
- [ ] Business and AD owner informed

---

## Senior SOC Question

**What is more dangerous for a SOC: a Domain Controller generating 10,000 GPO change alerts, or one generating ZERO GPO change alerts for 48 hours?**

From a detection-engineering view, the quiet DC is usually the more dangerous one. Ten thousand GPO change alerts is almost certainly a tuning problem, an over-broad 5136 rule firing on every attribute touch during normal replication and administration, and while the volume is painful it is visible and fixable by scoping the rule to meaningful changes (gPLink, new GPO objects, SYSVOL script writes) and allowlisting the approved GPO admins. Its danger is indirect: it buries the one real malicious change in noise so an analyst tunes it out. Zero GPO change alerts for 48 hours is more dangerous because the silence is ambiguous, and the two explanations look identical on the dashboard: either no GPOs genuinely changed, or the SOC has lost visibility into the DC. The causes of false silence are exactly what an attacker benefits from, a stopped or starved Sysmon service, directory-service auditing never enabled for 5136, a disconnected EDR sensor, or an agent not forwarding, and GPO abuse is quiet by nature, a single policy change that AV ignores and that looks like routine administration. This case proves it: the DC was patched, AV-clean, and the change looked like a software deployment, yet it was domain-wide persistence. The lesson is that alert volume measures noise, not security, and absence of GPO alerts is only reassuring when backed by positive proof of telemetry health, a recent agent heartbeat, directory-service and SYSVOL auditing confirmed on, and the expected baseline of benign change events still arriving. A DC is only safely quiet when you can prove it would have spoken if there were something to say.

---

## References

- [MITRE ATT&CK T1484.001: Domain or Tenant Policy Modification, Group Policy Modification](https://attack.mitre.org/techniques/T1484/001/)
- [MITRE ATT&CK T1484: Domain or Tenant Policy Modification](https://attack.mitre.org/techniques/T1484/)
- [MITRE ATT&CK T1053: Scheduled Task/Job](https://attack.mitre.org/techniques/T1053/)
- [Wazuh Documentation: Windows auditing](https://documentation.wazuh.com/)
- [SigmaHQ: GPO modification detection rule format](https://sigmahq.io/)
- [CISA: Active Directory hardening guidance](https://www.cisa.gov/)

---

**Status:** Active incident. The malicious GPO slated to be unlinked from the domain root (not yet deleted) after the GPO and SYSVOL payload are preserved, the list of already-applied machines being built for remediation, helpdesk_01 flagged for reset and its GPO delegation under review, DC-01-PRD imaged, and domain-root/DC involvement escalated to the AD owner with GPO-change monitoring raised.
