# SOC Triage Report
### SOC-2026-1015-01 | Shadow Credentials: The Silent Key Credential Link

**Analyst:** Jnanashree Anchan | **Program:** GraySentinel DSOU | **Date:** 15 October 2026

---

## Alert Details

| Field | Value |
|---|---|
| **Alert ID** | SOC-2026-1015-01 |
| **Rule** | The msDS-KeyCredentialLink attribute modified on an AD account, alongside directory-replication access, Whisker/Rubeus execution on WS-330, and an off-hours logon with special privileges for svc_helpdesk |
| **Severity** | Critical |
| **Host** | DC-01-PRD (domain controller), WS-330 (source) |
| **Account** | svc_helpdesk (actor), plus the target account whose key link was modified |
| **Platform** | Wazuh, Windows Security, Sysmon, Active Directory, AD CS |
| **CVE / CVSS** | Not applicable. This is Key Credential Link (Shadow Credentials) abuse, behavior based. |

---

## Verdict

**Confirmed Shadow Credentials attack, not a schema update and not a false positive. The msDS-KeyCredentialLink attribute on an AD account was modified (5136), and Whisker.exe and Rubeus.exe, the exact tools that add a shadow key and then redeem it via PKINIT, were seen running on WS-330 (4688) from an unsigned binary in C:\Temp\ (Sysmon 1), alongside directory-replication access (4662) and an off-hours privileged logon for svc_helpdesk (4624, 4672). This is an attacker writing their own certificate-based credential onto an account to authenticate as it and obtain a TGT, persistence that does not need the account's password. Do NOT remove the Key Credential Link yet, because the attribute value (the attacker's certificate) must be preserved as evidence first, and removal alone does not evict an attacker who has already minted a ticket or extracted the NT hash.**

The DC being patched and antivirus returning "No Threat Found" does not clear this. Shadow Credentials abuses legitimate AD and certificate functionality, there is no exploit and nothing unpatched, so AV silence here means no signature matched, not that nothing is wrong. The detection that matters is an unexpected account writing msDS-KeyCredentialLink on a target, with Whisker/Rubeus present, not that an AD attribute changed.

---

| Field | Detail |
|---|---|
| **WHAT** | An attacker added a certificate-based credential (msDS-KeyCredentialLink) to an AD account so they can authenticate as it via PKINIT and obtain a TGT without the password. |
| **WHEN** | Thursday 15 October 2026, around an off-hours logon. Exact times from Wazuh. |
| **WHERE** | DC-01-PRD (the attribute write), driven from WS-330 running Whisker and Rubeus. |
| **WHO** | svc_helpdesk, with an off-hours logon from WS-330; a help-desk account writing key credentials to another account indicates compromise or abused write rights, not routine admin. |
| **WHY** | Stealthy persistence and privilege escalation: a durable, password-independent way to log on as the target, likely a privileged account. |
| **HOW** | Whisker wrote a shadow key to the target's msDS-KeyCredentialLink (5136), then Rubeus can redeem it via PKINIT for a TGT; run from an unsigned binary in C:\Temp\ (Sysmon 1) under an off-hours privileged logon (4624, 4672), with replication access (4662). |

---

## Attack Chain

| Timestamp | Log Event | Attack Phase |
|---|---|---|
| T0 | 4624 Type 3 off-hours logon from WS-330 | Initial access / staging |
| T0 plus | 4672 special privileges assigned to svc_helpdesk | Privileged access |
| T0 plus | Sysmon 1 unsigned binary spawned from C:\Temp\ | Tooling execution |
| T0 plus | 4688 Whisker.exe / Rubeus.exe detected on WS-330 | Shadow-credential tooling |
| T0 plus | 5136 msDS-KeyCredentialLink modified on the target account | Credential implant |
| T0 plus | 4662 replicating directory changes / object access | Abuse of write rights, possible further access |

Note: a msDS-KeyCredentialLink write combined with Whisker and Rubeus on the source host is the Shadow Credentials pattern, and the off-hours help-desk logon makes a legitimate change unlikely. Correlate before attributing, but the attribute write, the tooling, and the privileged logon are one coordinated action.

---

## Mission 01 — Asset Discovery

| Item to Establish | Why It Matters | Where to Find It |
|---|---|---|
| **Role of DC-01-PRD (PDC emulator, schema master)** | Whether this DC is authoritative for the change and for AD CS | AD, FSMO roles |
| **Which account's msDS-KeyCredentialLink was modified** | The target of the persistence, and its value | 5136, the target object's attribute |
| **Whether the target account is privileged** | The blast radius if the attacker can log on as it | AD group membership |
| **Which account performed the modification** | The actor behind the write | 5136 SubjectUserName |
| **Wazuh agent status and version on DC-01-PRD** | Whether DC telemetry is complete | Agent status |
| **Last patch cycle and EDR status on DC-01-PRD** | Confirms sensor health on the DC | Patch management, EDR console |
| **AD CS (Certificate Services) configuration** | Shadow Credentials relies on PKINIT and the PKI being usable | AD CS, CA config |
| **Recent PKINIT / certificate authentication logs** | Whether the shadow key was already redeemed for a TGT | 4768 with certificate info, CA logs |
| **Logon activity for svc_helpdesk around the alert** | Whether the account is compromised and from where | 4624, 4625 |
| **Network connections from WS-330 over 7 days** | Whether the source host is the staging point and what else it touched | SIEM, NetFlow |

**Deliverable:** an Asset Context Map for DC-01-PRD (role, AD CS state), the target account (privilege, the modified key value), and the svc_helpdesk/WS-330 origin. **Primary question:** is the msDS-KeyCredentialLink change a legitimate device registration (Windows Hello for Business) or a Shadow Credentials attack? That is answered by who wrote it, whether Whisker/Rubeus ran, whether the target or actor should be doing this, and whether PKINIT followed.

---

## Mission 02 — Hunting Hypotheses

**H1: Shadow Credentials were added to a privileged account to obtain a TGT and persist without a password reset.**

| Field | Details |
|---|---|
| **Evidence Required** | The 5136 msDS-KeyCredentialLink write, the target's privilege, a following PKINIT TGT request (4768 with certificate), Whisker/Rubeus execution |
| **Data Sources** | Windows Security (5136, 4768), Sysmon, AD CS, Wazuh |
| **Expected Indicators** | A key-credential write on a privileged account, a certificate-based TGT request shortly after, the tooling present |
| **False Positives** | Legitimate Windows Hello for Business or device registration writing a key credential |
| **Conclusion** | Strongly supported. A key-credential write plus Whisker/Rubeus plus an off-hours privileged logon is Shadow Credentials. Primary hypothesis; confirm the target privilege and any PKINIT redemption. |

**H2: A compromised help-desk account with AD write rights is being used to escalate privileges via Key Credential Link abuse.**

| Field | Details |
|---|---|
| **Evidence Required** | svc_helpdesk's write permissions over the target, its logon trail, the off-hours WS-330 logon, the attribute change it made |
| **Data Sources** | Windows Security (4624, 4672, 5136), AD ACLs, EDR |
| **Expected Indicators** | A help-desk account with write access to a privileged object, off-hours logon from an unusual host, special privileges, the key-credential write |
| **False Positives** | A help-desk admin legitimately delegated to manage device credentials in an approved window |
| **Conclusion** | Supported and the identity angle. A help-desk account writing key credentials to a privileged account is escalation via delegated or stolen rights. Check whether svc_helpdesk should have that write access, and whether it is compromised. |

**H3: Shadow Credentials are a precursor to Golden Ticket forging using certificate-based authentication.**

| Field | Details |
|---|---|
| **Evidence Required** | Whether the attacker reached krbtgt or DCSync rights, the replication access (4662), any DCSync, krbtgt activity |
| **Data Sources** | DC logs (4662, 4768, 4769), AD CS, EDR |
| **Expected Indicators** | Shadow credentials on a high-privilege account, replication/DCSync access, signs of krbtgt hash extraction |
| **False Positives** | Legitimate replication between DCs, authorised administration |
| **Conclusion** | Plausible and the worst case. The 4662 replication access alongside the shadow key suggests the attacker may be reaching for krbtgt via DCSync, which would enable Golden Tickets. Treat as urgent and check for DCSync and krbtgt exposure. |

---

## Mission 03 — Detection Engineering

**Detection Name:** Shadow Credentials / Key Credential Link Abuse on a Domain Controller

| Field | Details |
|---|---|
| **Telemetry** | Windows Security (5136 directory object modify, 4662 object access, 4768 TGT with certificate), Sysmon (Event 1), EDR |
| **Relevant Fields** | ObjectClass, AttributeLDAPDisplayName (msDS-KeyCredentialLink), SubjectUserName, TargetUserName, OperationType, Image/OriginalFileName (Whisker, Rubeus), CertificateInfo on 4768 |
| **Detection Logic** | IF a 5136 event modifies msDS-KeyCredentialLink on an account AND the writer is not an approved device-registration service or the target is a privileged account OR within a correlated window Whisker/Rubeus executes (4688, Sysmon 1) or a PKINIT certificate-based TGT (4768 with certificate info) is requested for the target, THEN raise CRITICAL. Key on who modified the attribute and on the Whisker/Rubeus or PKINIT correlation, not on msDS-KeyCredentialLink changes alone, which occur with Windows Hello. |
| **Severity** | Critical when the target is privileged or the writer is not an approved service |
| **False Positives** | Windows Hello for Business enrollment and legitimate device registration, which write key credentials normally. Baseline the approved registration services and devices, and allowlist them; alert on writes by other principals or onto privileged accounts. |
| **Analyst Response** | Identify the target and the writing account, capture the msDS-KeyCredentialLink value, check for a following PKINIT TGT, confirm whether svc_helpdesk should have the write right, hunt other key-credential changes, and escalate for credential containment. |

---

## MITRE ATT&CK

| Technique | ID | Relevance |
|---|---|---|
| **Account Manipulation** | T1098 | Writing msDS-KeyCredentialLink to persist on the account |
| **Steal or Forge Authentication Certificates** | T1649 | The shadow certificate credential used for PKINIT |
| **Steal or Forge Kerberos Tickets** | T1558 | Redeeming the shadow key via PKINIT for a TGT |
| **Valid Accounts: Domain Accounts** | T1078.002 | The compromised or abused svc_helpdesk account |
| **Steal or Forge Kerberos Tickets: Golden Ticket** | T1558.001 | The possible end goal via DCSync of krbtgt |
| **Domain or Tenant Policy Modification** | T1484 | Abuse of directory rights for control |

---

## Mission 04 — Identity & Persistence Hunt

Hunt for what the attacker may have left across the domain.

- [ ] msDS-KeyCredentialLink modifications in the last 7 days (5136)
- [ ] New certificate templates published (AD CS)
- [ ] PKINIT authentication anomalies (4768 with certificate info)
- [ ] New Domain Admins or Enterprise Admins (4728, 4756)
- [ ] DCSync permission changes (replication rights on the domain object)
- [ ] Golden Ticket indicators (check whether krbtgt was reset / its hash exposed)
- [ ] Scheduled tasks on DC-01-PRD (4698)
- [ ] Unsigned binaries in C:\Temp\ on WS-330 (Sysmon 1)

**Critical question: if Shadow Credentials are confirmed, what is the ONE thing you must do before removing the Key Credential Link?**

Preserve the evidence first: capture the msDS-KeyCredentialLink attribute value (the attacker's certificate and device/key GUID) and the 5136 audit record of who wrote it, before clearing the attribute. The reason is that the attribute value is the forensic proof of the attack, it identifies the attacker's key and ties the activity to the writing account, and once you overwrite or clear the attribute that evidence is gone for good. Equally important, removing the Key Credential Link only stops future certificate-based logons; it does not evict an attacker who has already redeemed it. If they already ran Rubeus to get a TGT via PKINIT, that ticket is valid until it expires regardless of the attribute, and if they used UnPAC-the-hash to recover the account's NT hash, that hash survives until the account's password is reset. So the one prerequisite is capturing the attribute value, which also tells you the attack happened and therefore that you must go further: reset the target account's password (and krbtgt if DCSync is in play), not just delete the link. Capture, then remove the link, then rotate.

---

## Impact

**CRITICAL.** Shadow Credentials is stealthy, durable persistence: the attacker can authenticate as the target account at will, without the password, and if the target is privileged this is a direct route to escalation. The replication access alongside it raises the prospect of DCSync and krbtgt theft, which would enable Golden Tickets and full domain control. Because the attacker may already hold a TGT or the account's NT hash, simply deleting the key link does not clean the compromise, which is why evidence capture and credential rotation matter more than the attribute removal alone. A help-desk account able to write key credentials to privileged accounts means the attacker already holds dangerous rights. Treat this as an active intrusion with privileged-persistence and domain-takeover risk.

---

## Actions

| Action Category | Details |
|---|---|
| **PRESERVE** | Capture the msDS-KeyCredentialLink value (certificate and key GUID), the 5136 write record, the Whisker/Rubeus binaries and Sysmon 1 events, and image DC-01-PRD and WS-330 before any change. |
| **SCOPE** | Check for a following PKINIT TGT (4768 with certificate) and any DCSync/replication abuse, and search for other key-credential writes across the domain. |
| **CONTAIN** | Isolate WS-330, disable or closely watch svc_helpdesk, and, after evidence capture, remove the malicious Key Credential Link from the target. |
| **INVESTIGATE** | Confirm the target's privilege, how svc_helpdesk got write rights, the AD CS configuration, and whether a TGT or NT hash was already obtained. |
| **ROTATE** | Reset the target account's password (twice if a service or privileged account), reset svc_helpdesk, and reset krbtgt twice if DCSync/replication abuse is confirmed. |
| **ERADICATE** | Remove the shadow certificate, revoke any issued certificates, and clean tooling and persistence after evidence capture. |
| **ESCALATE** | Notify the IR lead and the AD owner immediately given DC and AD CS involvement, and raise monitoring on msDS-KeyCredentialLink and PKINIT. |

---

## Mission 05 — Incident Closure

- [ ] DC-01-PRD isolation status verified
- [ ] Wazuh logs and Sysmon preserved (disk image)
- [ ] Event IDs 5136, 4662, 4688, 4624, and 4672 reviewed
- [ ] msDS-KeyCredentialLink modifications investigated
- [ ] Malicious certificate removed
- [ ] svc_helpdesk account password rotated
- [ ] AD CS configuration audit done
- [ ] Domain Admin group membership audit done
- [ ] Persistence (scheduled task, service, certificate) investigated
- [ ] Lateral movement to other DCs reviewed
- [ ] Evidence preserved for forensics
- [ ] Monitoring increased for AD attribute changes (rule tuning)
- [ ] Business and AD owner informed

---

## Senior SOC Question

**What is more dangerous for a SOC: a Domain Controller generating 10,000 AD attribute change alerts, or one generating ZERO AD attribute change alerts for 48 hours?**

From a detection-engineering view, the quiet DC is usually the more dangerous one. Ten thousand AD attribute change alerts is almost certainly a tuning problem, a broad 5136 rule firing on every routine attribute touch during normal operation, and while the volume is painful it is visible and fixable by scoping the rule to the attributes that matter (msDS-KeyCredentialLink, group membership, ACLs) and allowlisting the approved change sources. Its danger is indirect: it buries the one malicious change, like a single key-credential write, in a flood an analyst learns to ignore. Zero AD attribute change alerts for 48 hours is more dangerous because the silence is ambiguous, and the two explanations look identical on the dashboard: either nothing sensitive genuinely changed, or the SOC has lost visibility into the DC. The causes of false silence are exactly what an attacker benefits from, directory-service auditing never enabled for 5136, a stopped or starved Sysmon service, a disconnected EDR sensor, or an agent not forwarding, and Shadow Credentials is quiet by design, a single attribute write that AV ignores and that looks like a legitimate device registration. This case proves it: the DC was patched, AV-clean, and the change looked like a schema update, yet it was stealthy privileged persistence. The lesson is that alert volume measures noise, not security, and absence of attribute-change alerts is only reassuring when backed by positive proof of telemetry health, a recent agent heartbeat, directory-service auditing confirmed on for the sensitive attributes, and the expected baseline of benign changes still arriving. A DC is only safely quiet when you can prove it would have spoken if there were something to say.

---

## References

- [MITRE ATT&CK T1098: Account Manipulation](https://attack.mitre.org/techniques/T1098/)
- [MITRE ATT&CK T1558: Steal or Forge Kerberos Tickets](https://attack.mitre.org/techniques/T1558/)
- [MITRE ATT&CK T1649: Steal or Forge Authentication Certificates](https://attack.mitre.org/techniques/T1649/)
- [MITRE ATT&CK T1484: Domain or Tenant Policy Modification](https://attack.mitre.org/techniques/T1484/)
- [Wazuh Documentation: Windows auditing](https://documentation.wazuh.com/)
- [SigmaHQ: Shadow Credentials detection rule format](https://sigmahq.io/)

---

**Status:** Active incident. The msDS-KeyCredentialLink value being preserved before removal, a PKINIT/DCSync check underway to see whether a TGT or krbtgt was already obtained, WS-330 isolated and svc_helpdesk flagged for reset and a write-rights review, DC-01-PRD imaged, and DC/AD CS involvement escalated to the AD owner with attribute-change monitoring raised.
