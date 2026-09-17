# SOC Triage Report
### Impossible Travel Hunt
**Analyst:** Jnanashree Anchan | **Program:** GraySentinel Blue Team | **Date:** 17 September 2026

---

## Attack Overview

A user authenticates from two geographically distant locations within a time window that makes physical travel impossible. This indicates either a stolen session token being reused from a different location, or credential compromise with an attacker using a residential proxy that occasionally slips out of region.

---

## Hunt Steps

**Priority 1:**
- Open Entra ID > Sign-in Logs > Risky sign-ins
- Filter: Risk Detection = "Impossible travel" OR "Unfamiliar sign-in properties"
- Check if second location is a known VPN or proxy ASN
- Check if MFA was satisfied independently or bypassed via existing token

---

## Findings

| Timestamp | User | Location 1 | Location 2 | Time Delta | MFA Status | Was it legit? |
|---|---|---|---|---|---|---|
| Sep 17 09:00:12 | rahul.verma@company.com | Mumbai, IN | Sao Paulo, BR | 40 mins | MFA satisfied at Location 1 only — token reused at Location 2 | NO — 9,000km in 40 mins impossible. Token reuse confirmed. MFA not re-triggered at Location 2. |
| Sep 17 10:15:44 | priya.sharma@company.com | Paris, FR | London, UK | 95 mins | MFA satisfied at both locations independently | YES — Paris to London in 95 mins possible via Eurostar. MFA completed independently both times. |
| Sep 17 14:30:09 | admin.svc@company.com | Amsterdam, NL | Lagos, NG | 22 mins | MFA not triggered — existing token active | NO — Service account with active token reused from Nigerian residential proxy. 5,500km in 22 mins. High confidence compromise. |

**Key Indicator:** When MFA is not re-triggered at the second location, an existing token was reused — the attacker did not need to authenticate again. This is the strongest signal of token theft versus credential compromise.

---

## Detection Rule Concept

**Detection Name:** Impossible Travel with Token Reuse

**Log Source:** Entra ID Sign-in Logs via SIEM

**Detection Logic:**

    SigninLogs
    | where RiskEventTypes contains "impossibleTravel"
    | where AuthenticationRequirement == "singleFactorAuthentication"
    | project TimeGenerated, UserPrincipalName, Location, IPAddress, RiskLevel
    | order by TimeGenerated desc

**Severity:** CRITICAL

**False Positives:** Business travel between nearby cities, VPN users with split tunneling

**Analyst Response:** Immediately revoke all active sessions, force MFA re-registration, and investigate the second location IP against known proxy and residential VPN ASNs.

---

## MITRE ATT&CK

| Technique | ID |
|---|---|
| Valid Accounts | T1078 |
| Use Alternate Authentication Material: Application Access Token | T1550.001 |

---

## Key Takeaway

Impossible travel is often the first visible symptom of token theft or credential compromise. The critical detection signal is not the location mismatch itself but whether MFA was independently completed at each location — if it was not, a token was reused and the account is compromised regardless of how the second login appears.
