# SOC Triage Report
### SOC-2026-1006-01 | Operation Ghost Admin

**Analyst:** Jnanashree Anchan | **Program:** GraySentinel DSOU | **Date:** 6 October 2026

---

## Alert Details

| Field | Value |
|---|---|
| **Alert ID** | SOC-2026-1006-01 |
| **Rule** | Privileged group change and PowerShell after an unusual authentication to a domain controller, with an LDAP query spike |
| **Severity** | Critical |
| **Host** | DC-02 (domain controller) |
| **Platform** | SIEM, Windows Security, EDR, Active Directory, network |
| **CVE / CVSS** | Not applicable. This is identity and privilege abuse, behavior based. |

---

## Verdict

**Confirmed privileged identity compromise in progress on DC-02, not a plain account compromise to fix with a password reset. A valid account logged in from an unusual workstation, a member was added to a privileged group, PowerShell ran, and LDAP enumeration spiked, which is credential access to privilege escalation to directory recon, the setup for domain wide lateral movement. Do NOT just reset the password, because that alone leaves the added group membership, any persistence, live sessions, and other stolen credentials intact. Preserve the evidence and map the full identity attack path first.**

The EDR "no malware detected" result does not clear this. The attack uses valid credentials and native tooling (PowerShell, LDAP) on a domain controller, so there is no malicious file for EDR to flag. The real alarm is the privileged group addition right after an unusual logon, not the failed attempts.

---

## 5W1H

| Field | Detail |
|---|---|
| **WHAT** | An attacker used a valid account to authenticate to DC-02 from an unusual host, added a member to a privileged group, ran PowerShell, and performed heavy LDAP enumeration. |
| **WHEN** | Tuesday 6 October 2026, within the last 12 hours. Exact times to be read from the SIEM. |
| **WHERE** | DC-02, a domain controller, accessed from an unusual workstation, with authentication also coming from a server that normally performs no interactive logons. |
| **WHO** | A valid account, most likely compromised, then escalated by adding a member to a privileged group. The true actor is external and not yet identified. |
| **WHY** | Privilege escalation and domain control. Gain a privileged identity, enumerate the directory, and set up lateral movement. |
| **HOW** | Failed then successful logon (4625, 4624), special privileges (4672), a privileged group addition (4728, 4732), PowerShell (4104), and an LDAP query spike for directory recon. |

---

## Attack Chain

| Timestamp | Log Event | Attack Phase |
|---|---|---|
| T0 | Multiple failed logons (4625) | Credential access, guessing |
| T0 plus | Successful logon from an unusual workstation (4624) | Initial access, valid account |
| T0 plus | Special privileges assigned (4672) | Privileged session |
| T0 plus | Member added to a privileged group (4728, 4732) | Privilege escalation and persistence |
| T0 plus | PowerShell launched (4104) | Execution |
| T0 plus | LDAP query spike | Discovery, directory enumeration |
| T0 plus | Auth from a server with no normal interactive logons | Lateral movement staging |

Note: the privileged group change right after an unusual logon is the escalation, and the LDAP spike is directory recon ahead of lateral movement. Times from the SIEM.

---

## Mission 01 — Asset and Identity Discovery

| Item to Establish | Why It Matters | Where to Find It |
|---|---|---|
| **Role of DC-02 (domain, FSMO)** | A DC compromise is domain wide; an FSMO holder widens it further | AD, netdom query fsmo |
| **Affected user account** | Identifies whose identity was used | 4624 |
| **Privileged group membership** | Shows what access the identity now holds | AD membership, 4728, 4732 |
| **Source workstation of the auth** | The attacker origin | 4624 WorkstationName and IP |
| **Logon type and auth protocol** | Interactive vs network, Kerberos vs NTLM | 4624 LogonType, 4768, 4776 |
| **Recent password changes** | Detects takeover prep | AD, 4723, 4724 |
| **Recent group membership changes** | The escalation event itself | 4728, 4732, 4756 |
| **Service accounts interacting with DC-02** | A service account abuse path | 4624 service logons, AD |
| **Recent PowerShell activity** | The attacker's actions | 4104, 4688 |
| **LDAP authentication and query activity** | Directory recon | DC directory service logs, 1644, EDR |
| **Network connections from the suspicious workstation** | C2 and lateral targets | Sysmon 3, firewall |
| **Recent admin activity on domain controllers** | Baseline against the anomaly | 4672, 4624 on DCs |

**Identity Attack Surface Map**

| Node | In This Case |
|---|---|
| **USER** | The compromised valid account |
| **WORKSTATION** | The unusual source workstation the logon came from |
| **CREDENTIAL** | Valid credentials, no malware, likely stolen or guessed |
| **PRIVILEGED GROUP** | The group a member was just added to, such as Domain Admins |
| **DOMAIN CONTROLLER** | DC-02, now authenticating that identity |
| **LATERAL MOVEMENT** | Auth from a server with no normal interactive logons, plus LDAP recon to pick targets |

---

## Mission 02 — Hunting Hypotheses

**H1: An attacker obtained valid credentials and authenticated from an unusual workstation.**

| Field | Details |
|---|---|
| **Evidence Required** | Authentication from an unusual workstation, the logon type, source IP and hostname, abnormal timing, failures then success |
| **Data Sources** | Windows Security (4624, 4625), SIEM, VPN and firewall, identity provider |
| **Expected Indicators** | An unusual source, odd hours, brute force then a success |
| **False Positives** | Legitimate remote admin, help desk, server migration |
| **Conclusion** | Supported. The unusual workstation logon after failures fits credential compromise. This is the entry point. |

**H2: The attacker obtained access to a privileged group before attempting lateral movement.**

| Field | Details |
|---|---|
| **Evidence Required** | Privileged group membership changes, new admin accounts, unexpected role assignments, auth after the privilege change, PowerShell, admin network connections |
| **Data Sources** | 4728, 4732, 4756, AD, 4104, Sysmon 3 |
| **Expected Indicators** | A member added to a privileged group right after the logon, then privileged actions |
| **False Positives** | Approved admin changes with a ticket, scheduled maintenance |
| **Conclusion** | Strongly supported and the pivotal event. The group addition is the escalation. Confirm who added whom and whether a change ticket exists. |

**H3: The compromised identity was used to access additional servers.**

| Field | Details |
|---|---|
| **Evidence Required** | SMB activity, remote services, PowerShell logs, auth patterns, destination hosts, the server with no normal interactive logons |
| **Data Sources** | Windows Security, EDR, 5140, 5145, 4624, 7045 |
| **Expected Indicators** | The privileged identity reaching other servers, remote execution, SMB to file servers or DCs |
| **False Positives** | Normal administration during a maintenance window |
| **Conclusion** | Supported. The anomalous server authentication and the LDAP recon point to lateral movement staging. Treat as active and hunt the fleet. |

---

## Mission 03 — Detection Engineering

**Detection Name:** Privileged Identity Anomaly

| Field | Details |
|---|---|
| **Telemetry** | Windows Security, EDR, Active Directory, network |
| **Relevant Events** | 4624, 4625, 4672, 4728, 4732, 7045 |
| **Relevant Fields** | Account, SourceIP, SourceHost, LogonType, DestinationHost, PrivilegedGroup, timestamp |
| **Detection Logic** | A privileged account authenticates from an unusual workstation, AND/OR the authentication is followed by a privileged group change (4728, 4732) or remote administration (7045, remote PowerShell). Raise a high-priority investigation alert, critical when the target is a DC and a group change follows. |
| **Severity** | High |
| **False Positives** | Approved administrator activity, scheduled maintenance, help desk operations, server migration, emergency response. Allowlist known admin hosts and change windows. |
| **Analyst Response** | Validate the chain USER to SOURCE HOST to LOGON to PRIVILEGE CHANGE to DESTINATION HOST. |

---

## Mission 04 — Identity and Persistence Hunt

| Hunt Item | What to Look For | Where to Hunt |
|---|---|---|
| **New domain or local accounts** | Attacker created accounts | 4720, 4741, AD |
| **Privileged group membership changes** | The escalation and any others | 4728, 4732, 4756 |
| **New services** | Persistence via services | 7045, 4697 |
| **Scheduled tasks** | Persistence via tasks | 4698 |
| **PowerShell persistence** | Profile scripts, WMI subscriptions | 4104, Sysmon |
| **Suspicious Run or Startup entries** | Autorun persistence | Sysmon 13, registry |
| **Remote administration** | Remote PowerShell, PsExec | 4104, 7045, WinRM |
| **Service account abuse** | Service accounts doing odd or interactive logons | 4624, AD |
| **Unusual Kerberos authentication** | Golden or silver tickets, odd TGT and TGS | 4768, 4769 |
| **Repeated auth from new hosts** | Spread of the identity | 4624 across the fleet |

**Critical question: if the compromised password is reset, what else must SOC investigate before declaring containment?**

A password reset alone does not contain this, because the attacker already escalated and may hold access that survives the reset. Before declaring containment, SOC must handle five things. Active sessions: a reset does not kill live Kerberos tickets or logged-in sessions, so revoke and expire them. Privileged groups: the member added to the privileged group keeps that access regardless of the password, so remove it and audit every recent group change. Persistence: hunt and remove new accounts, services, scheduled tasks, Run keys, and WMI subscriptions the attacker may have planted. Service accounts: if a service account was abused or exposed, reset those too, since they often hold high privilege and no MFA. Other compromised credentials: the LDAP recon and any credential access may have exposed more accounts, and on a domain controller the KRBTGT hash may be at risk, which would require a double KRBTGT reset. Only once sessions, privileges, persistence, service accounts, and the wider credential blast radius are all handled is the incident contained.

---

## MITRE ATT&CK

| Technique | ID | Relevance |
|---|---|---|
| **Brute Force** | T1110 | The multiple failed logons before success |
| **Valid Accounts** | T1078 | The compromised account used to authenticate |
| **Account Manipulation** | T1098 | A member added to a privileged group |
| **Permission Groups Discovery: Domain Groups** | T1069.002 | The LDAP query spike enumerating directory groups |
| **Command and Scripting Interpreter: PowerShell** | T1059.001 | PowerShell run after the logon |
| **Remote Services** | T1021 | Lateral movement from the privileged identity |

---

## Impact

**CRITICAL.** A domain controller has authenticated a compromised identity that was then escalated into a privileged group, with directory recon already underway. This is effectively a domain level compromise: privileged group membership plus DC access can lead to full domain control, and the LDAP enumeration is scoping lateral targets. A password reset alone will not contain it. If the KRBTGT or other DC secrets were touched, recovery widens to a KRBTGT reset and a full privileged access review. Treat this as an active domain compromise.

---

## Actions

| Action Category | Details |
|---|---|
| **CONTAIN** | Isolate the source workstation and the anomalous server, terminate the privileged identity's active sessions and tickets, and revert the unauthorized group membership. Do not rely on a password reset alone. |
| **PRESERVE** | Capture the SIEM timeline, Windows Security and EDR telemetry, the DC logs, and the LDAP query logs, before any change. |
| **INVESTIGATE** | Confirm who was added to which group and by whom, decode the PowerShell, scope the LDAP recon and the destination hosts, and find other accounts touched. |
| **ERADICATE** | Remove the added group membership and any persistence (accounts, services, tasks, Run keys), after evidence is captured. |
| **ROTATE** | Reset the compromised account and any exposed privileged and service accounts, and consider a double KRBTGT reset if DC secrets are at risk. |
| **BLOCK** | Block the source host, restrict DC logon rights to tier-0 admins from privileged access workstations, and enforce MFA for privileged access. |
| **ESCALATE** | Notify the IR lead, the identity and AD owner, and management. Treat as a domain level incident. |

---

## Mission 05 — Incident Closure

- [ ] Affected identity identified
- [ ] Source workstation isolated or validated
- [ ] All privileged group changes reviewed
- [ ] Authentication timeline reconstructed
- [ ] Failed and successful logons correlated
- [ ] PowerShell activity investigated
- [ ] Lateral movement investigated
- [ ] Domain controller activity reviewed
- [ ] Persistence mechanisms checked
- [ ] Service accounts reviewed
- [ ] EDR telemetry preserved
- [ ] SIEM timeline preserved
- [ ] Additional compromised accounts identified
- [ ] Credentials rotated where required
- [ ] Monitoring increased for privileged identities
- [ ] Business and identity owner informed

---

## Senior SOC Question

**Which is more dangerous: an attacker generating thousands of failed authentication attempts, or one successful authentication using a privileged identity from an unusual host?**

The single successful privileged authentication, by a wide margin. Signal: thousands of failures are loud and obvious, easy to detect and often just noise or an already blocked brute force, while one successful privileged logon is quiet and blends into normal activity, so it is the one that slips past. Privilege: the failures by definition achieved nothing, whereas a successful privileged identity already holds the keys, and from a domain controller that can mean the entire domain. Blast radius: a locked out account affects one account, but a compromised privileged identity on a DC can reach every system, every account, and the directory itself. Detection engineering: this is exactly why detections must not just count failures but alert on successful privileged authentications from unusual hosts, on privileged group changes, and on deviations from the admin baseline. The failures tell you someone is knocking, the one success tells you someone is inside with the master key. Volume is a distraction, privilege and context are what matter.

---

## References

- [MITRE ATT&CK T1078: Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- [MITRE ATT&CK T1098: Account Manipulation](https://attack.mitre.org/techniques/T1098/)
- [MITRE ATT&CK T1069.002: Permission Groups Discovery, Domain Groups](https://attack.mitre.org/techniques/T1069/002/)
- [MITRE ATT&CK T1021: Remote Services](https://attack.mitre.org/techniques/T1021/)
- [Microsoft Learn: Advanced Audit Policy Configuration for AD DS](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/advanced-audit-policy-configuration)
- [Sigma: generic detection rule format for SIEM](https://sigmahq.io/)

---

**Status:** Active incident. Containment in progress, privileged sessions and the unauthorized group change being reverted, evidence preservation underway, escalated to the IR lead as a suspected domain compromise.
