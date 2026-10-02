# SOC Triage Report
### Operation Invisible OAuth

**Analyst:** Jnanashree Anchan | **Program:** GraySentinel DSOU | **Date:** 1 October 2026

---

## Alert Details

| Field | Value |
|---|---|
| **Rule** | Illicit OAuth consent with high risk Graph permissions, followed by bulk mailbox and SharePoint access |
| **Severity** | Critical |
| **Identity and Host** | priya.sharma@corp.internal (Entra ID), device HR-WS-089 |
| **Platform** | Microsoft Sentinel, Wazuh, Entra ID logs, Graph activity logs, Sysmon |
| **CVE / CVSS** | Not applicable. This is identity and consent abuse, behavior based. |

---

## Verdict

**Confirmed Illicit Consent Grant, not MFA fatigue to be closed. An attacker from a Nigerian ASN got an MFA approval, consented a malicious enterprise app ("DocuSign-Prod-Viewer") with Mail.Read, Files.Read.All, and offline_access, and used the resulting Graph token to read the mailbox and pull 47 finance files. Do NOT just revoke the token and do NOT reset the password alone, because the app consent and its refresh token survive both. Preserve the consent and Graph evidence, then revoke consent, kill all refresh tokens, and delete the app.**

The Windows Defender "No Threat Found" result does not clear this. The attack lives in the identity and token layer, not on the endpoint, so endpoint antivirus has nothing to detect. The user pressing Approve is the entry point, not an innocent explanation.

---

| Field | Detail |
|---|---|
| **WHAT** | An illicit OAuth app consent gave an attacker delegated Graph access to the user's mailbox and SharePoint, used to bulk read email and exfiltrate 47 finance files. |
| **WHEN** | 1 October 2026, 08:14 to 08:31, a tight 17 minute window. |
| **WHERE** | The Entra ID tenant, from a Nigerian ASN IP (167.x.x.x), targeting the Finance-Board-2026 SharePoint site. Device HR-WS-089. |
| **WHO** | The priya.sharma account, consented by the user through an MFA fatigue approval. The operator is external, from Nigeria, confirmed by impossible travel against an India login. |
| **WHY** | Persistent data access and exfiltration. offline_access grants a refresh token, so the access lasts independent of the user's password. |
| **HOW** | MFA fatigue approval, user consent to a lookalike enterprise app, high risk delegated permissions, then Graph API mailbox and SharePoint reads. |

---

## Attack Chain

| Timestamp | Log Event | Attack Phase |
|---|---|---|
| 08:10 | Entra ID sign-in from India | Baseline, legitimate user |
| 08:14:22 | MFA prompt approved from 167.x.x.x (Nigeria ASN) | Initial access, MFA fatigue |
| 08:15:04 | New enterprise app "DocuSign-Prod-Viewer" consented (Mail.Read, Files.Read.All, offline_access) | Persistence, Illicit Consent Grant |
| 08:17:33 | Graph API bulk Mailbox List and Message Read from the app | Collection, mailbox access |
| 08:22:11 | Sysmon 3: Outlook.exe to Microsoft Graph with a new OAuth token | Token use |
| 08:29:45 | DLP: 47 files read from SharePoint Finance-Board-2026 via Graph | Exfiltration, data access |
| 08:31:02 | Impossible travel flagged (India 08:10, Nigeria 08:14) | Detection signal |

Note: times from Entra ID and Sentinel. The Nigerian ASN and the impossible travel confirm the approval did not come from the user.

---

## Mission 01 — Initial Triage

| Item to Establish | Why It Matters | Where to Find It |
|---|---|---|
| **Username and Entra ID Object ID** | Ties every log together and identifies the account | Entra ID users |
| **MFA push time and user location** | Confirms the approval was not the user | Sign-in and MFA logs |
| **Source IP 167.x.x.x reputation and ASN** | Confirms attacker infrastructure (Nigeria ASN) | Threat intel, sign-in logs |
| **OAuth App ID, name, publisher, consent type** | Identifies the app and whether the publisher is verified | Entra ID enterprise apps, audit logs |
| **Permissions granted** | Shows the blast radius of the delegated access | Consent grant, app registration |
| **Who consented, user or admin** | User consent is the attack path here | Audit log consent event |
| **Graph API call volume and endpoints** | Scopes what the token actually did | Graph activity logs |
| **Mailboxes and SharePoint sites accessed** | Scopes the data exposure | Graph logs, DLP, audit |
| **HR-WS-089 process tree at 08:14** | Checks for an infostealer or local compromise | Sysmon, EDR |
| **User's normal consent pattern** | Baseline to judge the anomaly | Entra ID audit history |
| **Other users who consented the same App ID** | Scope of the campaign | Entra ID enterprise apps |
| **Hash of the file or link that led to the prompt** | Finds the phishing lure | Mail gateway, EDR |
| **Conditional Access policy applied** | Explains why MFA was the only gate | CA policies, sign-in logs |

---

## Mission 02 — Hunting Hypotheses

**H1: The user fell for MFA fatigue and the attacker performed an Illicit Consent Grant for persistent Graph access.**

| Field | Details |
|---|---|
| **Evidence Required** | MFA approval from a foreign ASN, user consent to a new app with high risk permissions, unverified publisher, offline_access granted |
| **Data Sources** | Entra ID audit and sign-in logs, consent grant records |
| **Expected Indicators** | A consent event seconds after the MFA approval, an app name impersonating a known brand |
| **False Positives** | A genuine new app the user legitimately adopted |
| **Conclusion** | Strongly supported. The sequence and the Nigeria ASN fit Illicit Consent Grant. Primary hypothesis. |

**H2: The OAuth app is a legitimate IT approved app and the high Graph usage is normal sync.**

| Field | Details |
|---|---|
| **Evidence Required** | The app is admin approved, publisher verified, in the approved catalog, usage matches a known sync pattern |
| **Data Sources** | Enterprise app catalog, publisher verification, audit logs |
| **Expected Indicators** | Verified publisher, admin consent, stable historical usage |
| **False Positives** | This is the benign hypothesis itself |
| **Conclusion** | Reject. The app was user consented, appeared minutes after a foreign MFA approval, and bulk read finance files at once, none of which fits a sanctioned app. |

**H3: The compromised token is being used for business email compromise and SharePoint exfiltration.**

| Field | Details |
|---|---|
| **Evidence Required** | Mailbox rules or forwarding created, bulk SharePoint downloads, token reused from the attacker ASN |
| **Data Sources** | Graph logs, mailbox audit, DLP |
| **Expected Indicators** | 47 files pulled from Finance-Board, new inbox rules, reads from the Nigerian ASN |
| **False Positives** | Legitimate bulk file access by the user, so check timing and source IP |
| **Conclusion** | Supported and the most damaging. The DLP hit and the Graph reads show active exfiltration. Treat as live data loss. |

---

## Mission 03 — Identity and OAuth Hunt

| Stage | Evidence |
|---|---|
| **MFA push sent** | Sign-in log, MFA push event |
| **MFA approved** | 08:14:22 approval from 167.x.x.x |
| **OAuth app consented** | 08:15:04 consent for DocuSign-Prod-Viewer |
| **Graph token issued** | Token grant with Mail.Read, Files.Read.All, offline_access |
| **Mailbox access via Graph** | 08:17:33 bulk message reads |
| **SharePoint access via Graph** | 08:29:45 47 files from Finance-Board-2026 |
| **Possible data exfil** | DLP alert, bytes out to the attacker |

| Question | Finding |
|---|---|
| **MFA push from attacker IP?** | Yes. The approval came from 167.x.x.x (Nigeria ASN), not the user's India location. |
| **What app, publisher verified?** | "DocuSign-Prod-Viewer", a lookalike of DocuSign. Check publisher verification, almost certainly unverified. |
| **Permissions high risk?** | Yes. Mail.Read (full mailbox), Files.Read.All (all SharePoint and OneDrive), offline_access (persistent refresh token). |
| **User or admin consent?** | User consented, which is the attack path. Tenant user consent settings should be locked down. |
| **Which Graph endpoints?** | Mailbox list and message read, then SharePoint file reads. Pull the full endpoint list from Graph activity logs. |
| **How many emails and files?** | 47 files from Finance-Board-2026 per DLP. The email read count to be confirmed from Graph logs. |
| **Token from a different IP?** | Yes. The token was used from the Nigerian ASN, and impossible travel confirms it. |
| **Same App ID consented by others?** | Hunt the App ID tenant wide to find other victims. |

---

## Mission 04 — Detection Engineering

**Detection Name:** Illicit OAuth Consent with High Risk Permissions and Graph Abuse

| Field | Details |
|---|---|
| **Telemetry** | Entra ID Audit Logs, Sign-in Logs, Graph Activity Logs |
| **Relevant Fields** | appId, appDisplayName, consentType, permissions, ipAddress, user, userAgent, graphEndpoint |
| **Detection Logic** | Trigger when a consent grant is user consented AND the permissions include high risk delegated scopes (Mail.Read, Files.Read.All, Mail.ReadWrite, offline_access) AND the consent or sign-in originates from an anomalous IP, ASN, or impossible travel. Raise critical when the same app makes a burst of Graph read calls within minutes of consent. |
| **Severity** | High, raised to Critical with immediate Graph bulk reads |
| **False Positives** | Legitimate IT approved apps like DocuSign or Zoom. Allowlist verified publishers and admin consented apps. |
| **Analyst Response** | Validate the publisher and verification status, review the permissions and consent type, check the source IP and ASN, pull the Graph endpoints and volume, and contain if unverified. |

This keys on user consent plus high risk permissions plus an anomalous IP, not on app creation alone, which is what keeps it high fidelity.

---

## MITRE ATT&CK

| Technique | ID | Relevance |
|---|---|---|
| **Multi-Factor Authentication Request Generation** | T1621 | MFA fatigue push to get the approval |
| **Steal Application Access Token** | T1528 | Illicit consent grant to a malicious OAuth app |
| **Valid Accounts: Cloud Accounts** | T1078.004 | Compromised Entra ID account used for access |
| **Use Alternate Authentication Material: Application Access Token** | T1550.001 | Using the stolen OAuth token against Graph |
| **Email Collection** | T1114 | Bulk mailbox message reads via Graph |
| **Data from Information Repositories: SharePoint** | T1213.002 | 47 files read from the Finance-Board SharePoint site |

---

## Impact

**CRITICAL.** An attacker holds persistent, token based access to a user's mailbox and all of their SharePoint and OneDrive files, including a finance board site, and that access is independent of the user's password because offline_access grants a refresh token. 47 finance files have already been exfiltrated. The risks are ongoing data theft, business email compromise, the same app consented across other users, and access that survives a password reset. Treat this as an active cloud identity breach with confirmed data loss.

---

## Actions

| Action Category | Details |
|---|---|
| **CONTAIN** | Force sign-out and revoke all refresh tokens for the user, disable and delete the malicious enterprise app, revoke its consent tenant wide, and block 167.x.x.x. |
| **PRESERVE** | Export the Entra ID audit and sign-in logs, the Graph activity logs with the accessed file list, and the DLP alerts, before revoking, since revoking changes state. |
| **INVESTIGATE** | Scope the Graph endpoints and the 47 files, check for inbox rules and forwarding, enumerate the user's other consents and other users of the same App ID, and verify HR-WS-089 for an infostealer. |
| **ERADICATE** | Remove the app registration and any persistence such as inbox rules, after evidence is captured. |
| **ROTATE** | Force a password reset and MFA re-registration, and review privileged consents. |
| **BLOCK** | Block the source IP and ASN, and tighten user consent settings so users cannot consent to high risk apps. |
| **ESCALATE** | Notify the IR lead, the HR head, and the Finance-Board data owner. Review the DLP hit on the 47 files for regulatory exposure. |

---

## Mission 05 — Lateral and Data Access Hunt

| Hunt Item | What to Look For | Where to Hunt |
|---|---|---|
| **Other apps consented by the user (7 days)** | Additional malicious consents | Entra ID audit logs |
| **Same App ID across other users** | Campaign scope | Enterprise apps, consent grants |
| **Graph access to other SharePoint sites** | Wider data exposure | Graph activity logs |
| **Mailbox forwarding rules** | Persistence and exfiltration | Mailbox audit, Graph |
| **OAuth token replay from a different ASN** | Token reuse | Sign-in logs, Graph |
| **New inbox rules** | Hidden exfiltration | Mailbox audit |
| **Teams chat access via Graph** | Further data access | Graph logs |
| **SharePoint and OneDrive downloads** | Exfiltration volume | Graph, DLP |
| **Same MFA source IP for other users** | Other targets | Sign-in logs |
| **Additional OAuth apps for persistence** | More footholds | Enterprise apps |

**Before revoking the token, collect the evidence and scope the consent first, because revoke alone is not enough.**

Preserve the Graph activity logs (the exact mailbox and SharePoint items accessed, so the breach can be scoped and notification duties met), the consent grant record (app ID, permissions, consent type, timestamp), the sign-in logs (source IPs and ASNs), and a list of any inbox rules, forwarding, or other apps the user consented. Capture this first, because revoking changes state and you lose the ability to prove what was taken. Revoke alone is not enough for three reasons. The app was granted offline_access, so it holds a refresh token that mints new access tokens, and revoking one access token leaves the refresh token working. The malicious app and its consent live in the tenant independent of the user's password, so a password reset does not remove them. And the attacker may have added inbox rules or consented more apps as backup persistence. Full remediation is to revoke the app consent, revoke all refresh tokens, delete the app registration, remove any rules, then reset the password and re-register MFA.

---

## Mission 06 — Incident Containment

- [ ] User account force sign-out and all refresh tokens revoked
- [ ] Source IP 167.x.x.x blocked
- [ ] Malicious enterprise app "DocuSign-Prod-Viewer" disabled and deleted
- [ ] OAuth consent for the App ID revoked tenant wide
- [ ] Other high risk consents by the same user reviewed and revoked
- [ ] HR-WS-089 isolated and checked for an infostealer
- [ ] Entra ID audit and sign-in logs preserved
- [ ] Graph API logs preserved with the accessed file list
- [ ] Mailbox checked for forwarding and exfiltration rules
- [ ] Other users targeted with the same MFA fatigue identified
- [ ] DLP alerts for the 47 files reviewed
- [ ] Password reset forced and MFA re-registered
- [ ] HR head and the Finance-Board data owner informed
- [ ] Same app name pattern searched tenant wide

---

## Senior SOC Question

**Which gives the SOC stronger context: a single MFA approved event from an unusual country, or MFA approve then OAuth consent grant with Mail.Read then Graph large read then SharePoint bulk access?**

The correlated chain, clearly. A lone MFA approval from an unusual country is a single anomaly that could be travel, a VPN, or a false positive, so on its own it is low fidelity and easy to dismiss as fatigue. The chain of MFA approve to consent grant to Graph bulk read to SharePoint bulk access tells the whole story: the approval led to a persistent app grant, the grant was used to read mail, and then finance files were taken. Each event is weak alone, but together they show intent, persistence, and impact. In modern cloud attacks the boundary is not the login, it is the token. MFA only proves someone approved a prompt once, and once an OAuth app holds a delegated token with offline_access it keeps access without ever seeing MFA again. That is exactly why MFA alone is not a security boundary, and why detection has to correlate the identity event, the consent grant, and the Graph activity, because the damage happens at the token and data layer, not at the sign-in.

---

## References

- [MITRE ATT&CK T1528: Steal Application Access Token](https://attack.mitre.org/techniques/T1528/)
- [MITRE ATT&CK T1078: Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- [MITRE ATT&CK T1621: Multi-Factor Authentication Request Generation](https://attack.mitre.org/techniques/T1621/)
- [Microsoft Entra: Act on an overprivileged or suspicious application](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/manage-application-permissions)
- [Microsoft Entra: User and admin consent overview](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/user-admin-consent-overview)
- [Sigma: detection rules for Entra ID and more](https://github.com/SigmaHQ/sigma)

---

**Status:** Active incident. Containment in progress, evidence preservation underway, escalated to the IR lead, consent and token revocation and campaign scoping pending.
