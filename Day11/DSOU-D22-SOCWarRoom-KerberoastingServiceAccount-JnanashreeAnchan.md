# SOC Triage Report
### SOC-2026-0924-22 | Kerberos Abuse — The Silent Service Account
**Analyst:** Jnanashree Anchan | **Program:** GraySentinel DSOU | **Date:** 24 September 2026

---

## Alert Details

| Field | Value |
|---|---|
| Alert ID | SOC-2026-0924-22 |
| Rule | Kerberoasting — svc_sql_backup: 300+ TGS requests in 15 minutes with RC4 encryption |
| Severity | CRITICAL |
| Host | DC-01-PRD (Domain Controller — Production) |
| Platform | Wazuh SIEM / Windows Active Directory |

---

## Verdict

**TRUE POSITIVE — Suspected Kerberoasting. Do NOT rotate the service account password before investigation. A blind password reset destroys evidence and does not address the attacker's likely offline cracking or lateral movement.**

---

## 5W1H

| | |
|---|---|
| **WHAT** | A service account made 300+ Kerberos TGS (service ticket) requests in 15 minutes, many with RC4 encryption, alongside pre-authentication failures across multiple accounts |
| **WHEN** | Thursday morning, 24 Sep 2026 — 300+ requests inside a 15-minute window |
| **WHERE** | DC-01-PRD (Production Domain Controller); source workstation WS-114 |
| **WHO** | Activity attributed to `svc_sql_backup`; the true actor is a user or process on WS-114 requesting tickets for many SPNs |
| **WHY** | To harvest service tickets encrypted with the service account's password hash, then crack them offline to recover plaintext service account passwords |
| **HOW** | 1. Logon Type 3 from WS-114 (Event 4624) → 2. Bulk TGS requests for many SPNs, forced to RC4 (Event 4769) → 3. Pre-auth failures across accounts (Event 4771) suggesting enumeration → 4. Tickets taken offline for cracking |

---

## Why This Is Kerberoasting, Not a Password Problem

IT's instinct to rotate the password is the wrong first move. Kerberoasting does not exploit a weak or old password directly on the wire. Any authenticated domain user can request a TGS for any account that has a Service Principal Name (SPN) registered. The Domain Controller returns that ticket encrypted with the target service account's password hash. The attacker takes the ticket offline and brute-forces the password with no further contact with the DC, so no lockout and no further alerts fire.

The RC4 encryption is the tell. RC4 (etype 0x17) is far faster to crack than AES. An attacker deliberately requests RC4 to make offline cracking practical. A legitimate application does not suddenly switch to RC4 for 300 tickets.

A password rotation alone assumes the attacker has not already cracked the hash. If they have, they already hold the plaintext, and a single rotation may come too late. The investigation must come first.

---

## Mission 01 — Asset Discovery

| Asset Item | Why It Matters | Where to Find It |
|---|---|---|
| Role of DC-01-PRD | PDC Emulator vs RODC changes what is at risk. An RODC does not hold all secrets; a full PDC does | AD topology, `netdom query fsmo`, CMDB |
| What svc_sql_backup is tied to | Identifies the real application and expected behaviour, so anomalies stand out | CMDB, SQL server config, service owner |
| Is the account Kerberoastable | Confirms whether an SPN is registered, which is the precondition for the attack | `setspn -L svc_sql_backup`, AD attribute servicePrincipalName |
| Password age and complexity | An old, short service account password cracks quickly. A 25+ character managed password resists it | AD account properties, pwdLastSet attribute |
| Encryption types allowed | If RC4 is permitted, cracking is easy. AES-only accounts are far harder | msDS-SupportedEncryptionTypes attribute |
| Hosts requesting TGS for this SPN | Normally one or two known app servers. A workstation like WS-114 is a red flag | Event 4769 Client Address field, Wazuh |
| Recent logon activity for the account | Detects whether the cracked credential is already being used elsewhere | Events 4624, 4625, 4768 across the domain |
| Group membership | A service account in Domain Admins is a catastrophic blast radius | AD Users and Computers, `net group` |
| Delegation settings | Unconstrained or RBCD delegation turns a cracked account into a domain-wide pivot | msDS-AllowedToDelegateTo, userAccountControl flags |
| Network connections from WS-114 (7 days) | Identifies where the attacker on WS-114 has reached and what they touched | Firewall logs, Sysmon Event 3, NetFlow |

---

## Mission 02 — Hunting Hypotheses

**H1: The service account password was cracked offline after Kerberoasting and is now used for lateral movement**

Hypothesis: The attacker harvested the RC4 TGS tickets, cracked `svc_sql_backup` offline, and is now authenticating with the recovered plaintext to move laterally.

| Field | Details |
|---|---|
| **Evidence Required** | Successful logons (Event 4624) for svc_sql_backup on hosts it never normally touches; the account authenticating from WS-114 or other workstations; access to SQL, file, or backup servers outside its normal pattern |
| **Data Sources** | Windows Security logs across the domain, Wazuh, EDR, authentication logs on member servers |
| **Expected Indicators** | svc_sql_backup logon Type 3 to new hosts after the TGS burst; access to shares or databases outside its baseline; process execution under the service account context on unexpected machines |
| **False Positives** | A genuine backup job that legitimately runs across many SQL servers; a scheduled maintenance window expanding the account's normal footprint |
| **Conclusion** | If svc_sql_backup appears on hosts outside its baseline after the TGS burst, the password is cracked and in use. This escalates from Kerberoasting to active compromise and forces a double password rotation plus containment. |

---

**H2: An attacker is password spraying domain accounts, using Kerberos pre-auth failures as the signal**

Hypothesis: The 4771 pre-authentication failures across multiple accounts indicate a spraying or enumeration attempt separate from, or alongside, the Kerberoasting.

| Field | Details |
|---|---|
| **Evidence Required** | Event 4771 across many distinct accounts from the same source; a pattern of one or few password attempts per account to avoid lockout; the same source address as the TGS requests |
| **Data Sources** | Event 4771 and 4768 on DC-01-PRD, Wazuh correlation, source IP from the ticket requests |
| **Expected Indicators** | Pre-auth failures spread across dozens of accounts from WS-114; low attempt count per account; timing clustered with the Kerberoasting burst |
| **False Positives** | A user with a stale cached password on a phone or mapped drive generating repeated failures; a misconfigured service retrying with an old password |
| **Conclusion** | If 4771 failures span many accounts from one source with few attempts each, this is enumeration or spraying, not one user mistyping. Combined with the Kerberoasting it points to a single actor doing broad credential access from WS-114. |

---

**H3: The service account has excessive privileges and is being used for DCSync or replication abuse**

Hypothesis: If svc_sql_backup holds replication rights or Domain Admin, the attacker may attempt DCSync to pull password hashes directly rather than relying only on offline cracking.

| Field | Details |
|---|---|
| **Evidence Required** | Event 4662 with the DS-Replication-Get-Changes / Get-Changes-All GUIDs; replication requests from a non-DC host; svc_sql_backup holding rights it should not have |
| **Data Sources** | Event 4662 on DC-01-PRD, AD ACL audit, group membership review, Wazuh |
| **Expected Indicators** | DS-Replication access requested by svc_sql_backup or from WS-114; the account being a member of Domain Admins or having replication ACLs; hash pull activity |
| **False Positives** | Legitimate replication between actual Domain Controllers; a backup or identity-sync product that genuinely holds replication rights (must be documented) |
| **Conclusion** | If the account has replication rights it should not have, or DCSync activity appears from a non-DC, the incident is a full domain compromise. Every credential, including KRBTGT, must be treated as exposed. |

---

## Mission 03 — Detection Engineering

**Detection Name:** Kerberoasting — Bulk TGS Requests with RC4 from a Single Account

| Field | Details |
|---|---|
| **Telemetry** | Windows Security Event Log (Event 4769) forwarded to Wazuh from all Domain Controllers |
| **Relevant Fields** | event.code (4769), TicketEncryptionType, ServiceName (SPN), TargetUserName, IpAddress (client), TicketOptions |
| **Detection Logic** | ALERT when a single account requests TGS tickets (4769) for a high number of distinct SPNs within a short window, AND the TicketEncryptionType is RC4 (0x17), AND the requesting client address is not on the known service-host allowlist. Pseudo logic: count(distinct ServiceName) by TargetUserName over 15m >= 20 AND TicketEncryptionType == 0x17 AND IpAddress NOT IN (approved_app_servers). Raise severity when the client is a workstation subnet. |
| **Severity** | High to Critical (Critical when the source is a user workstation and encryption is RC4) |
| **False Positives** | Vulnerability scanners (BloodHound-style tools run by the security team) generating similar patterns during authorised assessments; a legitimate app server enumerating services. Both are reduced by the client allowlist and change-management awareness |
| **Analyst Response** | 1. Confirm the SPN list and client address from the 4769 events / 2. Check whether the source host should ever request these tickets / 3. Pull logon activity for the targeted service accounts / 4. Review encryption types allowed on those accounts / 5. If confirmed, isolate the source host, begin the identity hunt, and prepare a double password rotation |

---

## Mission 04 — Identity and Persistence Hunt

| Hunt Item | What to Look For | Where |
|---|---|---|
| New SPNs on privileged accounts | An attacker registers an SPN on a high-privilege account to Kerberoast it next | Event 4738 (account changed), servicePrincipalName attribute, AD audit |
| Service account password changes | Unexpected pwdLastSet changes that the attacker made, or that hide their tracks | pwdLastSet attribute, Event 4724 / 4723 |
| New members in Domain Admins / Enterprise Admins | The clearest sign of privilege escalation and persistence | Event 4728 / 4732, group membership audit |
| DCSync permission changes | DS-Replication rights granted to a non-DC principal | Event 4662, AD ACL review on the domain object |
| Golden Ticket indicators | Whether KRBTGT was reset recently, and TGTs with abnormal lifetimes | KRBTGT pwdLastSet, ticket lifetime anomalies |
| New scheduled tasks on DC-01-PRD | Persistence created on the DC during the incident window | Event 4698, Task Scheduler log |
| Delegation changes on service accounts | Unconstrained or RBCD delegation added to enable a pivot | msDS-AllowedToDelegateTo, userAccountControl, Event 4738 |
| Unusual TGS requests from non-service hosts | Workstations requesting service tickets they should never need | Event 4769 client address, Wazuh |

**The ONE thing to do before resetting the svc_sql_backup password:**

Determine the full scope of what the account can access and whether the credential is already in use, by reviewing its logon activity, group membership, and delegation settings across the domain.

The reason is that a password reset is a one-way action that both alerts the attacker and destroys the current state. If the account holds delegation rights or excessive group membership, rotating the password alone leaves those pivot paths open. If the attacker has already cracked and used the credential, a single rotation is insufficient and a double rotation plus session revocation is required. And the reset itself will change pwdLastSet and Kerberos ticket behaviour, which can erase the very evidence needed to prove what happened. Understanding the blast radius first is what turns a blind reset into a controlled remediation.

---

## MITRE ATT&CK

| Technique | ID | Relevance |
|---|---|---|
| Steal or Forge Kerberos Tickets: Kerberoasting | T1558.003 | The core activity — bulk RC4 TGS requests for offline cracking |
| Credential Access (tactic) | TA0006 | The attacker's objective is to recover service account credentials |
| Brute Force: Password Cracking | T1110.002 | Offline cracking of the harvested RC4 tickets |
| Account Discovery: Domain Account | T1087.002 | Pre-auth failures across accounts suggest enumeration |
| OS Credential Dumping: DCSync | T1003.006 | Considered under H3 if the account holds replication rights |
| Valid Accounts: Domain Accounts | T1078.002 | Use of the cracked service account for lateral movement |

---

## Impact

**CRITICAL** — A service account is a stable, often over-privileged identity. If svc_sql_backup is cracked, the attacker gains a foothold that survives user password changes and blends into normal automation. If the account has delegation or replication rights, the blast radius extends to the whole domain, up to and including KRBTGT and Golden Ticket persistence.

---

## Actions

| Action Category | Details |
|---|---|
| **CONTAIN** | Isolate WS-114 from the network (preserve memory, do not power off); monitor svc_sql_backup for any new authentication and be ready to disable it |
| **PRESERVE** | Capture disk and memory image of WS-114; preserve Wazuh and Sysmon logs and the DC Security event log before anything changes |
| **INVESTIGATE** | Review Events 4769, 4771, 4624, 4768, 4662 for the incident window; identify every SPN requested and the source; determine password age and encryption type on the targeted accounts |
| **ERADICATE** | Remove any attacker persistence found (new SPNs, scheduled tasks, group additions, delegation changes) |
| **ROTATE** | Reset svc_sql_backup password twice (to clear the Kerberos ticket cache); force AES-only encryption on the account; rotate any other targeted service accounts. Consider KRBTGT double-reset if domain compromise is confirmed |
| **HARDEN** | Move to group Managed Service Accounts (gMSA) with long managed passwords; disable RC4 where possible; apply least privilege to service accounts |
| **ESCALATE** | L2/IR immediately; notify the AD owner and the svc_sql_backup application owner; assess domain-wide exposure |

---

## Mission 05 — Incident Closure Checklist

- [ ] DC-01-PRD role confirmed and isolation status of WS-114 verified
- [ ] Wazuh logs and Sysmon preserved (disk image of WS-114)
- [ ] Event IDs 4769, 4771, 4624, 4672, 4720, 4728, 4768 reviewed
- [ ] Kerberoasting activity investigated — full SPN and source list documented
- [ ] Service account password rotated twice
- [ ] Encryption type on targeted accounts set to AES-only
- [ ] Domain Admin / Enterprise Admin group membership audit done
- [ ] KRBTGT double-reset considered and decision recorded
- [ ] SPN inventory reviewed across privileged accounts
- [ ] Delegation settings (unconstrained / constrained / RBCD) reviewed
- [ ] Persistence (scheduled task / service / new account) investigated
- [ ] Network lateral movement to other DCs and servers reviewed
- [ ] Evidence preserved for forensics and potential legal requirements
- [ ] Monitoring increased for Kerberos anomalies; detection rule tuned
- [ ] Migration of service accounts to gMSA planned
- [ ] Business and AD owner informed
- [ ] Post-incident report drafted with full timeline

---

## Senior SOC Question

**What is more dangerous for a SOC — a Domain Controller that generates 10,000 Kerberos alerts, or one that generates ZERO Kerberos alerts for 48 hours?**

A Domain Controller that generates ZERO Kerberos alerts for 48 hours is far more dangerous.

10,000 alerts is a tuning problem. The DC is producing telemetry, which means you have visibility. You can baseline normal Kerberos volume, filter the noise, and surface the real anomalies. Detection Engineering exists precisely to turn a loud stream into a signal. The data is there to work with.

Zero alerts for 48 hours is a visibility problem, and on a Domain Controller that is the worst kind. A DC is one of the busiest Kerberos endpoints in the environment. It authenticates users and services constantly, so it should never be silent. Zero Kerberos events for two days does not mean nothing happened; it almost always means logging was disabled, the agent was stopped, or events are not reaching the SIEM. An attacker who has silenced Kerberos auditing on a DC has removed the single best source for detecting Kerberoasting, Golden Tickets, and DCSync, and can then operate freely.

From a Detection Engineering perspective, the lesson is that the absence of alerts is itself an alert. A prolonged Kerberos logging gap on a Domain Controller must be treated as a critical detection in its own right, with a heartbeat rule that fires when expected event volume drops to zero. Loud is tunable. Silent is blind.

---

**Status:** Escalated to L2/IR. WS-114 isolation in progress. Password rotation on hold pending scope determination. Kerberos monitoring increased on all Domain Controllers.
