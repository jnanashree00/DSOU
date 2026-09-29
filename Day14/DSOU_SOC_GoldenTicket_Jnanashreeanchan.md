# SOC Triage Report
### SOC-2026-0929-01 | Golden Ticket: The Silent KRBTGT Abuse

**Analyst:** Jnanashree Anchan | **Date:** 29 September 2026

---

## Alert Details

| Field | Value |
|---|---|
| **Alert ID** | SOC-2026-0929-01 |
| **Rule** | Kerberos ticket anomalies on a domain controller: many TGS for one user, RC4 tickets, and a forwarded log gap |
| **Severity** | Critical |
| **Host** | DC-01-PRD (production domain controller) |
| **Platform** | Wazuh SIEM, Windows Security, Sysmon |
| **CVE / CVSS** | Not applicable. This is credential and ticket abuse, and the DC is reported patched. |

---

## Verdict

**Confirmed suspected Golden Ticket abuse on DC-01-PRD. A forged Kerberos TGT signed with the KRBTGT hash is granting privileged, domain wide access. This is not clock skew and not an NTP problem. Do NOT reset KRBTGT, reboot, or let IT "fix NTP" yet, because a single premature KRBTGT reset does not fully evict the attacker and it destroys the live timeline before the scope is known.**

The "No Threat Found" antivirus result does not clear this. A Golden Ticket is a forged authentication artifact, not malware on disk, so signature antivirus has nothing to match. The RC4 tickets, the burst of service tickets for one user, access that outlives the logon session, and a clean two hour log gap are a forged ticket pattern, not a time sync fault.

---


| Field | Detail |
|---|---|
| **WHAT** | A forged Kerberos TGT (Golden Ticket) used to request many service tickets and reach 20 or more services as a privileged identity, alongside a suspicious log gap. |
| **WHEN** | Tuesday 29 September 2026, morning. A forwarded event gap from 02:00 to 04:00 IST overnight, with ticket activity ongoing at alert time. |
| **WHERE** | DC-01-PRD, a production domain controller. The access is sourced from workstation WS-088. |
| **WHO** | A single user account requesting multiple service tickets with special privileges. The true owner is not confirmed, and the activity is most likely an attacker using a forged ticket rather than the real user. |
| **WHY** | Privilege and persistence. A Golden Ticket gives long lived, domain wide access that survives ordinary account password resets. |
| **HOW** | KRBTGT hash compromise, likely from earlier Domain Admin or DCSync access, then a TGT forged offline with RC4 (0x17), used to pull service tickets (4769) without matching TGT requests (4768), with the log gap hiding part of the window. |

---

## Attack Chain

| Timestamp | Log Event | Attack Phase |
|---|---|---|
| Prior to incident | KRBTGT hash obtained via DCSync or Domain Admin access | Credential Access, earlier compromise |
| 02:00 to 04:00 IST | Forwarded event gap, no events from DC-01-PRD | Defense Evasion, log tampering |
| T0 | 4624 Logon Type 3 from WS-088 | Network access to the DC |
| T0 | 4672 Special privileges assigned to new logon | Privileged use of the forged ticket |
| T0 | 4769 many TGS, single user, RC4 0x17 | Golden Ticket use, Kerberos abuse |
| T0 | 4634 Logoff, tickets valid beyond the session | Persistence through a long lived TGT |

Note: the tell is a burst of 4769 service ticket requests with no matching 4768 TGT request on any DC. A Golden Ticket is forged offline, so the KDC never issued that TGT. Exact clock times should be read from Wazuh.

---

## Mission 01 — Asset Discovery

| Asset Item | Why It Matters | Where to Find It |
|---|---|---|
| **Role of DC-01-PRD (PDC Emulator, FSMO holder)** | An FSMO holder is the highest value DC and widens the blast radius | netdom query fsmo, AD |
| **Which account is requesting the tickets** | Identifies the forged identity in use | 4769 account fields, Wazuh |
| **Is that account privileged (DA or service)** | Sets how much access the forged ticket grants | AD group membership |
| **KRBTGT password last reset date** | An old KRBTGT hash stays usable for forging and drives remediation | Get-ADUser krbtgt -Properties PasswordLastSet |
| **Kerberos policy: ticket lifetime and renewal** | Baseline to spot the abnormally long lived forged ticket | Default Domain Policy GPO |
| **Which services were accessed and from where** | Scopes lateral movement and the real targets | 4769 service names, 5140 and 5145, EDR |
| **Recent logon activity on DC-01-PRD** | Surfaces source hosts and accounts | 4624, 4625, 4672 |
| **Domain Admin and Enterprise Admin membership** | Detects privileged accounts added for persistence | AD, 4728, 4732, 4756 |
| **Trust relationships (child, parent, forest)** | A forged ticket can be extended across trusts | AD Domains and Trusts |
| **Network connections from WS-088 in 7 days** | Identifies the operator host and any command and control | Sysmon 3, firewall, EDR |

---

## Mission 02 — Hunting Hypotheses

**H1: The KRBTGT hash was compromised and a Golden Ticket is forging TGTs for privileged access.**

| Field | Details |
|---|---|
| **Evidence Required** | 4769 bursts with no matching 4768, RC4 tickets in an AES domain, TGT lifetime beyond policy, access as a privileged identity |
| **Data Sources** | Windows Security 4768, 4769, 4624, 4672, Wazuh, DC memory |
| **Expected Indicators** | One user, many service SPNs, 0x17 encryption, tickets valid past logoff, no TGT issued by the KDC |
| **False Positives** | Legitimate service accounts with many SPNs, apps still using RC4, long running service sessions |
| **Conclusion** | Strongly supported. The RC4 tickets, the 4769 pattern, and the log gap fit a Golden Ticket. Treat as active. |

**H2: A service account with excessive SPNs is being Kerberoasted and used for lateral movement.**

| Field | Details |
|---|---|
| **Evidence Required** | 4769 for SPN heavy service accounts requested with RC4 for offline cracking, then that account logging on elsewhere |
| **Data Sources** | 4769 with service SPNs, later 4624 from new hosts, EDR |
| **Expected Indicators** | A workstation pulling many service SPNs at once, then cracked credentials reused for logon |
| **False Positives** | Vulnerability scanners, normal service ticket usage |
| **Conclusion** | Possible and overlaps with the SPN activity, but the privileged access and beyond session tickets point past plain roasting toward ticket forging. Keep as secondary. |

**H3: The event log gap is deliberate tampering to hide ticket forging and escalation.**

| Field | Details |
|---|---|
| **Evidence Required** | A forwarded event gap with no maintenance window, agent healthy before and after, other hosts logging normally in that window |
| **Data Sources** | Wazuh manager, WEF subscription health, agent heartbeat, 1102 and 4719 if present |
| **Expected Indicators** | A clean two hour hole only on DC-01-PRD, no reboot logged, agent up on both sides of the gap |
| **False Positives** | Agent outage, WEF backlog, a real DC maintenance window |
| **Conclusion** | The targeted gap around the ticket activity fits deliberate evasion. Confirm agent health to rule out a plain outage. |

---

## Mission 03 — Detection Engineering

**Detection Name:** Forged Kerberos TGT (Golden Ticket) Activity on Domain Controller

| Field | Details |
|---|---|
| **Telemetry** | Windows Security on all DCs (4768, 4769, 4624, 4672), Wazuh, forwarded events |
| **Relevant Fields** | TargetUserName, ServiceName, TicketEncryptionType, TicketOptions, IpAddress, LogonType, event time |
| **Detection Logic** | Flag 4769 where TicketEncryptionType is 0x17 (RC4) for a user account in an AES domain. OR a burst of 4769 for one TargetUserName across many distinct ServiceName in a short window with no preceding 4768 for that user on any DC. OR a TGT lifetime beyond domain policy. Raise critical when RC4 4769 and 4672 come from a single non service account and no matching 4768 exists. |
| **Severity** | Critical |
| **False Positives** | Legacy apps and accounts still using RC4, service accounts with many SPNs, appliances that pre request tickets. Tune with an RC4 allowlist and a known service account list. |
| **Analyst Response** | Isolate the session source, preserve DC memory and logs, scope affected accounts and DCs, then prepare a double KRBTGT reset. |

---

## Mission 04 — Identity and Persistence Hunt

| Hunt Item | What to Look For | Where to Hunt |
|---|---|---|
| **KRBTGT reset history** | An old or never reset KRBTGT, meaning a usable stale hash | Get-ADUser krbtgt PasswordLastSet |
| **New Domain or Enterprise Admins** | Privileged accounts added for persistence | 4728, 4732, 4756, AD group audit |
| **DCSync permission changes** | DS-Replication rights granted to non DC principals | 4662 with replication GUIDs, AD ACLs |
| **Golden Ticket indicators** | TGT lifetime anomalies, RC4, 4769 with no 4768 | 4768, 4769, ticket lifetime |
| **Silver Ticket indicators** | Service ticket use with no matching 4769 on the DC | Service host logs versus DC logs |
| **New service accounts with SPNs** | Fresh SPNs for roasting or silver tickets | setspn, AD, 4741 |
| **Scheduled tasks on DC-01-PRD** | Persistence through tasks | 4698, Task Scheduler |
| **Trust key modifications** | Cross domain forging via trust keys | AD trusts, 4706, 4716 |

**The ONE thing to do before resetting KRBTGT: preserve evidence and fully scope the privileged compromise first.**

Before touching KRBTGT, capture a memory image of DC-01-PRD, the current ticket state, and a confirmed list of affected accounts and domain controllers, and verify the attacker no longer holds Domain Admin or DCSync rights. There are two reasons. First, a KRBTGT reset invalidates every outstanding TGT across the domain at once, which disrupts services and wipes the live forensic picture, so the evidence has to be secured before that happens. Second, if the attacker still has Domain Admin or DCSync when you reset, they simply pull the new KRBTGT hash and forge fresh Golden Tickets, so the reset buys nothing. Once evidence is preserved and the foothold is closed, reset KRBTGT twice, waiting for the ticket lifetime between the two resets, so the account password history is fully cycled.

---

## MITRE ATT&CK

| Technique | ID | Relevance |
|---|---|---|
| **Steal or Forge Kerberos Tickets: Golden Ticket** | T1558.001 | Forged TGT, RC4 tickets, access beyond the session |
| **Steal or Forge Kerberos Tickets: Silver Ticket** | T1558.002 | Possible forged service tickets, secondary hypothesis |
| **Steal or Forge Kerberos Tickets: Kerberoasting** | T1558.003 | SPN heavy 4769 requests, the lateral movement hypothesis |
| **OS Credential Dumping: DCSync** | T1003.006 | Likely method used to obtain the KRBTGT hash |
| **Indicator Removal: Clear Windows Event Logs** | T1070.001 | The two hour forwarded event gap |

---

## Impact

**CRITICAL.** A production domain controller is being accessed with a forged Kerberos ticket, which means full, domain wide, privileged control that ordinary password resets do not remove. A Golden Ticket is durable persistence: it stays valid until KRBTGT is reset twice, and if trust keys were touched it can reach across domains in the forest. The two hour log gap shows intent to hide the activity. Business impact includes potential compromise of every account and service in the domain, and a real risk that recovery requires a controlled KRBTGT reset and a full privileged access review, not a quick fix.

---

## Actions

| Action Category | Details |
|---|---|
| **CONTAIN** | Isolate WS-088 at the network level and restrict DC-01-PRD to management access. Do not reboot or change NTP yet. |
| **PRESERVE** | Capture memory on DC-01-PRD and WS-088, then disk images. Export Security, Sysmon, and forwarded logs before the gap widens. |
| **INVESTIGATE** | Confirm the missing 4768, the RC4 tickets, and the services reached. Find how the KRBTGT hash was obtained and which DCs and accounts are affected. |
| **ERADICATE** | Remove attacker persistence: rogue admins, DCSync rights, scheduled tasks. Then reset KRBTGT twice within the ticket lifetime. |
| **ROTATE** | KRBTGT twice, plus any exposed Domain Admin and service accounts and the impersonated account. |
| **BLOCK** | Block WS-088 and any known operator IPs. Move privileged services off RC4 where possible. |
| **ESCALATE** | Notify the IR lead, the AD and identity owner, and management. Treat as a domain compromise and weigh a forest wide response. |

---

## Mission 05 — Closure Checklist

- [ ] DC-01-PRD isolation status verified
- [ ] Wazuh logs and Sysmon preserved as a disk image
- [ ] Event IDs 4769, 4624, 4672, 4634, 4768, 4771 reviewed
- [ ] KRBTGT password reset twice, with the required wait between resets
- [ ] Golden Ticket and Silver Ticket indicators investigated
- [ ] Domain Admin group membership audited
- [ ] Service accounts and SPN inventory reviewed
- [ ] Trust relationships reviewed
- [ ] Persistence (scheduled task, service) investigated
- [ ] Lateral movement to other DCs reviewed
- [ ] Evidence preserved for forensics with chain of custody
- [ ] Monitoring tuned for Kerberos anomalies
- [ ] Business and AD owner informed

---

## Senior SOC Question

**What is more dangerous: a domain controller that generates 10,000 Kerberos alerts, or one that generates ZERO Kerberos alerts for 2 hours?**

The zero alerts case is more dangerous, and this incident is the proof. A domain controller issues Kerberos tickets constantly, so on a busy DC zero events for two hours does not mean quiet, it means the telemetry stopped or was suppressed. That is exactly the 02:00 to 04:00 gap here, sitting right where the forging most likely happened. Ten thousand alerts is painful to triage, but the sensor is alive and the signal is somewhere in the noise, so you can filter, rate limit, and hunt. Zero is blindness, and an attacker who can produce a clean two hour hole on a DC has both privileged access and the intent to hide. From a detection engineering view, absence of expected telemetry must itself be an alert: monitor agent and WEF heartbeats and set a floor on expected 4768 and 4769 volume, so a silent DC pages you instead of covering an intrusion. Noise you can tune. Silence you cannot see through.

---

## References

- [MITRE ATT&CK T1558.001: Golden Ticket](https://attack.mitre.org/techniques/T1558/001/)
- [MITRE ATT&CK T1558.002: Silver Ticket](https://attack.mitre.org/techniques/T1558/002/)
- [MITRE ATT&CK T1003.006: OS Credential Dumping, DCSync](https://attack.mitre.org/techniques/T1003/006/)
- [Microsoft Learn: AD Forest Recovery, reset the krbtgt password](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password)
- [Wazuh Documentation: Windows auditing and log analysis](https://documentation.wazuh.com/)
- [Sigma: generic detection rule format for SIEM](https://sigmahq.io/)

---

**Status:** Active incident. Containment in progress, evidence preservation underway, escalated to the IR lead as a suspected domain compromise.