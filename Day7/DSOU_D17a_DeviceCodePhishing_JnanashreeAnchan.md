# SOC Triage Report
### Device Code Phishing Hunt
**Analyst:** Jnanashree Anchan | **Program:** GraySentinel Blue Team | **Date:** 17 September 2026

---

## Attack Overview

Attackers send phishing emails asking users to enter a device code at microsoft.com/devicelogin. When the user enters the code, the attacker receives a valid OAuth token — no password required, no MFA triggered. The token grants full access to the user's Microsoft 365 session.

---

## Hunt Steps

**Priority 1:**
- Open Entra ID > Sign-in Logs
- Filter: Authentication Details = "Device code flow"
- Check for sign-ins where Device Code was used from unknown location or unfamiliar application

---

## Findings

| Timestamp | User | App | Location | Was it legit? |
|---|---|---|---|---|
| Sep 17 02:14:33 UTC | rahul.verma@company.com | Microsoft Teams | Russia (TOR exit node) | NO — Device code flow at 2am from TOR node. User is in Pune. No travel expected. Token theft confirmed. |
| Sep 17 09:05:12 UTC | priya.sharma@company.com | Azure Portal | India (Mumbai) | YES — Known user location, business hours, expected app access. |
| Sep 17 11:42:07 UTC | john.smith@company.com | Microsoft Graph API | Netherlands | NO — Graph API access via device code is unusual. User has no Netherlands travel scheduled. Likely automated token abuse post-phishing. |

**Key Indicator:** Device code flow should almost never appear in sign-in logs for regular users. Any occurrence outside of approved device registration scenarios warrants immediate investigation.

---

## Detection Rule Concept

**Detection Name:** Device Code Flow from Anomalous Location or App

**Log Source:** Entra ID Sign-in Logs via SIEM

**Detection Logic:**

    SigninLogs
    | where AuthenticationDetails contains "device code"
    | where Location !in (approved_locations)
    | where AppDisplayName !in ("Windows Sign In", "Microsoft Authenticator")
    | project TimeGenerated, UserPrincipalName, AppDisplayName, Location, IPAddress

**Severity:** HIGH

**False Positives:** Legitimate device registration workflows during onboarding

**Analyst Response:** Immediately revoke the token, disable the user session, and investigate the originating email for phishing indicators.

---

## MITRE ATT&CK

| Technique | ID |
|---|---|
| Steal Application Access Token | T1528 |
| Phishing | T1566 |

---

## Key Takeaway

Device code phishing is effective because it abuses a legitimate OAuth flow — no malware, no password theft, no MFA bypass needed. The attacker simply waits for the user to authenticate on their behalf. Detection depends entirely on monitoring sign-in logs for device code flow in unexpected contexts.