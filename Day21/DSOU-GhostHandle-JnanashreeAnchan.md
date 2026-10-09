# SOC Triage Report
### SOC-2026-1009-01 | Operation Ghost Handle

**Analyst:** Jnanashree Anchan | **Program:** GraySentinel DSOU | **Date:** 9 October 2026

---

## Alert Details

| Field | Value |
|---|---|
| **Alert ID** | SOC-2026-1009-01 |
| **Rule** | A process accessing lsass.exe on WS-427, with a suspicious parent-child process creation, a new .dmp file in a user-writable directory, an EDR credential-access flag, and failed logons followed by a successful privileged logon |
| **Severity** | High |
| **Host** | WS-427 (workstation) |
| **Platform** | Wazuh, Windows Security, Sysmon, EDR |
| **CVE / CVSS** | Not applicable. This is credential-access behavior, not a vulnerability exploit. |

---

## Verdict

**Strongly suspected LSASS credential dumping, pending correlation, not a false positive. WS-427 shows the full dump signature stacked together: a process accessing lsass.exe (Sysmon 10), a new .dmp file written to a user-writable directory (Sysmon 11), an EDR credential-access flag, and failed logons resolving into a successful privileged logon. Any one of these is ambiguous, but together they are the shape of a credential dump followed by use of the stolen material. The compromise is not yet confirmed, and per the brief it must not be called confirmed until the source process and dump file are validated, so the immediate action is to preserve volatile evidence and correlate, while containing WS-427 if the activity is still active.**

The IT note that antivirus detected nothing does not clear the host. Signature AV routinely misses credential dumping done with signed binaries, renamed tools, or living-off-the-land techniques, so "No Threat Found" is the absence of a signature match, not the absence of an attack. The detection that matters is which process accessed LSASS, in what context, and whether the .dmp file it produced contains credential material, not that lsass.exe exists or that AV stayed quiet.

---

| Field | Detail |
|---|---|
| **WHAT** | A process on WS-427 accessed LSASS memory and a .dmp file appeared in a user-writable directory, consistent with credential dumping, followed by a successful privileged logon after failed attempts. |
| **WHEN** | Friday 9 October 2026, morning, with the events clustered in a short window. Exact times from Wazuh. |
| **WHERE** | WS-427. Any onward authentication destinations to be established from the logs. |
| **WHO** | The primary user of WS-427 and a privileged account seen in the authentication logs, both to be confirmed; ownership and authorisation are open questions. |
| **WHY** | Likely credential theft to enable privileged access and potential lateral movement. |
| **HOW** | A suspicious process with an unusual parent (Sysmon 1, 4688) accessed lsass.exe (Sysmon 10) and wrote a .dmp file (Sysmon 11), with failed then successful privileged logons (4625, 4624, 4672) in the same window. |

---

## Attack Chain

| Timestamp | Log Event | Attack Phase |
|---|---|---|
| T0 | Sysmon 1 and 4688, suspicious process from an unusual parent | Execution |
| T0 plus | Sysmon 10, process accessed lsass.exe | Credential access, LSASS dump |
| T0 plus | Sysmon 11, new .dmp file in a user-writable directory | Credential access, dump artifact |
| T0 plus | 4625 failed logons | Authentication attempts |
| T0 plus | 4624 successful logon with a privileged account | Privileged access |
| T0 plus | 4672 special privileges assigned | Privileged access |

Note: Sysmon 10 LSASS access paired with a Sysmon 11 .dmp write in a user-writable path is the dump-to-disk pattern, and the privileged logon right after is what turns a suspicious access into a probable credential-reuse event. Correlate before attributing, but these events share one host, one tight window, and a single execution chain.

---

## Mission 01 — Asset & Context Discovery

| Item to Establish | Why It Matters | Where to Find It |
|---|---|---|
| **Business role of WS-427** | Sets the value of what is at risk and the expected baseline | Asset inventory, CMDB |
| **Primary user and account privileges** | Whether a privileged identity is exposed | Asset inventory, AD, 4624 |
| **Process that accessed lsass.exe** | The candidate credential-dumping tool | Sysmon 10 SourceImage |
| **Parent process of that process** | Process lineage and how it launched | Sysmon 1, 4688 |
| **Command line, hash, signer, execution time** | Intent, identity, and whether it is trusted | Sysmon 1, 4688, signature and hash lookup |
| **Credential Guard or LSA Protection state** | Whether LSASS was hardened against dumping | Host config, RunAsPPL and Credential Guard status |
| **What Sysmon, Windows Security, Wazuh, and EDR show** | Corroboration across independent sources | SIEM, EDR console |
| **The .dmp file: created, modified, accessed** | Confirms a dump artifact and its handling | Sysmon 11, file audit, 4663 |
| **Authentication activity before and after the alert** | Links the dump to credential use | 4625, 4624, 4672 |
| **Outbound connections to unfamiliar hosts** | Possible exfiltration or C2 | Sysmon 3, firewall, proxy |
| **Wazuh agent telemetry completeness** | Whether the picture is whole or has blind spots | Agent status, event continuity |

**Deliverable:** an Asset Context Map (WS-427 role, user, privileges, hardening state) and an Initial Evidence Timeline ordering the Sysmon, Security, and EDR events. **Primary question:** was the LSASS access legitimate system behavior, authorised security software, or credential-access activity? That decision is answered by identifying the source process, validating its signature and hash, and confirming what the .dmp file contains.

---

## Mission 02 — Three Hunting Hypotheses

**H1: LSASS Credential Dumping.** An unauthorized process accessed LSASS memory to obtain credential material.

| Field | Details |
|---|---|
| **Evidence Required** | Sysmon 10 process-access telemetry, process name, hash and signer, parent-child relationship, the .dmp artifact, EDR credential-access telemetry |
| **Data Sources** | Wazuh, Sysmon, Windows Security, EDR |
| **Expected Indicators** | Suspicious access rights to lsass.exe, abnormal process ancestry, an unexpected .dmp file in a writable path |
| **False Positives** | Authorized security tools, approved diagnostic or crash-dump software |
| **Conclusion** | Strongly supported. An unexpected process accessing LSASS with an abnormal parent and producing a .dmp file fits credential dumping. Primary hypothesis, confirm by validating the process and the dump contents. |

**H2: Suspicious Signed-Binary Execution.** A script or another process launched a legitimate Windows binary as part of a credential-access chain.

| Field | Details |
|---|---|
| **Evidence Required** | Process-creation records, command-line arguments, parent-child relationships, PowerShell and script logs |
| **Data Sources** | Sysmon 1, Windows Event 4688, PowerShell logs, EDR |
| **Expected Indicators** | A signed Windows binary launched by an unusual parent, unexpected command-line arguments, abnormal file activity around it |
| **False Positives** | Legitimate administrative scripts, software installers, patch tooling |
| **Conclusion** | Open, investigate. If the LSASS access came through a signed binary proxied by a script, the signature alone will look clean, so the parent and command line decide whether it was authorized. |

**H3: Credential Abuse & Lateral Movement.** Credentials may have been exposed or misused to reach additional systems.

| Field | Details |
|---|---|
| **Evidence Required** | Authentication events, logon types, source addresses, privileged-account activity, onward connections |
| **Data Sources** | Windows Security logs, domain controller logs, Wazuh, EDR |
| **Expected Indicators** | Unusual logons, unexpected privileged access, the privileged account appearing on hosts it does not normally use |
| **False Positives** | Approved remote administration, scheduled service activity, VPN or remote-work patterns |
| **Conclusion** | Supported and the forward risk. The failed-then-successful privileged logon is the first sign; establish whether the account moved beyond WS-427 using the DC logs before treating spread as confirmed. |

---

## Mission 03 — Detection Engineering

**Detection Name:** LSASS Access + Dump Artifact Correlation

| Field | Details |
|---|---|
| **Telemetry** | Sysmon (Event 10 process access, Event 11 file create), Windows Security, EDR, Wazuh |
| **Relevant Fields** | Image, TargetImage, GrantedAccess, SourceImage, ParentImage, CommandLine, TargetFilename, Hashes, User, UtcTime |
| **Detection Logic** | IF a process accesses lsass.exe (Sysmon 10, TargetImage is lsass.exe) AND the source process is unusual or violates the approved process baseline AND a suspicious .dmp file or related credential-access behavior is observed within a correlated time window (Sysmon 11 TargetFilename, or an EDR credential-access flag), THEN raise HIGH or CRITICAL depending on the combined evidence and the privileges of the account involved. Key on which process accessed LSASS and in what context, not on the existence of lsass.exe. |
| **Severity** | High, raised to Critical when a privileged account authenticates in the same window |
| **False Positives** | Approved EDR tools, endpoint diagnostics, authorized security testing, legitimate crash-dump collection. Allowlist known security product images and hashes rather than hard-coding a single access mask. |
| **Analyst Response** | 1. Validate the process identity and execution chain. 2. Preserve relevant telemetry and volatile evidence. 3. Isolate the endpoint when the risk warrants it. 4. Investigate privileged authentication and lateral movement. 5. Escalate confirmed credential exposure for identity containment. |

Important: do not rely on one event or a single hard-coded access mask. Validate telemetry coverage and correlate multiple independent signals, because a lone Sysmon 10 event is noisy and a single access right is easy to evade.

---

## MITRE ATT&CK

| Technique | ID | Relevance |
|---|---|---|
| **OS Credential Dumping: LSASS Memory** | T1003.001 | A process accessed LSASS to dump credential material |
| **OS Credential Dumping** | T1003 | Credential access from the host |
| **System Binary Proxy Execution** | T1218 | H2, a signed binary possibly proxied by a script in the access chain |
| **Valid Accounts** | T1078 | The successful privileged logon after failed attempts, possible reuse of stolen credentials |
| **Brute Force** | T1110 | The burst of failed logons preceding the success |
| **Remote Services** | T1021 | Candidate path if the privileged account moves beyond WS-427 |

---

## Mission 04 — Identity & Persistence Hunt

Investigate whether the suspected activity left additional evidence on or beyond WS-427.

- [ ] Dump files in Temp, Public, AppData, and other writable locations
- [ ] Suspicious scheduled tasks (4698)
- [ ] Unexpected service installations (7045)
- [ ] Run keys and Startup folder modifications
- [ ] WMI event subscriptions
- [ ] Newly created local administrator accounts (4720, 4732)
- [ ] Suspicious PowerShell history and script execution (4104)
- [ ] Unexpected privileged logons (4672)
- [ ] Remote service creation or other lateral movement indicators
- [ ] Evidence of credential reuse across endpoints

**Critical Incident Question: if LSASS dumping is confirmed, what must you do before rebooting WS-427?**

Preserve volatile evidence first. Coordinate an appropriate memory acquisition, where feasible and authorized, before rebooting, because a reboot destroys the live process, the open handles to LSASS, and anything resident only in memory, which is often the strongest proof of what was taken. The .dmp file on disk and the Sysmon and Security logs are preserved in parallel. That said, evidence preservation must not delay containment when the attacker still has active access: if the threat is live, isolate WS-427 at the network level immediately and acquire memory from the contained host. Follow the IR team's forensic procedures, and document integrity (hashes, chain of custody) for everything collected.

---

## Impact

**HIGH, rising to Critical if credential use is confirmed.** If the dump succeeded, whatever credentials were resident in LSASS on WS-427 are now exposed, including the privileged account seen authenticating. Those credentials live in the attacker's hands and survive a reimage of WS-427, so rotation matters more than rebuilding the host. The forward risk is privileged access, lateral movement to systems the account can reach, and escalation toward domain resources. The scope is not yet bounded, which is why the DC logs and a fleet-wide search for the same process and account are the priority before the host is cleaned.

---

## Actions

| Action Category | Details |
|---|---|
| **CONTAIN** | Isolate WS-427 if the activity is active, suspend the privileged account's sessions, and block the suspicious process by hash across EDR. |
| **PRESERVE** | Acquire a memory image before reboot, and preserve the suspicious process and its hash, the .dmp file, the Sysmon 10 and 11 evidence, the Security and EDR logs, and the authentication trail. |
| **INVESTIGATE** | Identify the source process and validate its signer and hash, confirm what the .dmp contains, reconstruct the parent-child chain, and follow the privileged account across the DC and other endpoints. |
| **ERADICATE** | Remove the tool and any persistence found in Mission 04, after evidence is captured. |
| **ROTATE** | Reset the privileged account and any credentials that were resident in LSASS on WS-427, since dumped credentials outlive the endpoint. |
| **BLOCK** | Block the process hash and any attacker source IPs, and enable LSASS protection (RunAsPPL, Credential Guard) to defeat future dumping. |
| **ESCALATE** | Notify the IR lead and the WS-427 asset owner, and escalate for identity containment once credential exposure is confirmed. |

---

## Mission 05 — Incident Closure Checklist

- [ ] Endpoint isolation status verified
- [ ] Memory acquisition and disk evidence preserved, where feasible
- [ ] Sysmon, Windows Security, Wazuh, and EDR logs collected
- [ ] Process-access and process-creation events correlated
- [ ] Suspicious files, including the .dmp, identified and preserved for analysis
- [ ] Credential exposure scope assessed
- [ ] Affected credentials revoked or rotated as appropriate
- [ ] Privileged sessions and tokens addressed
- [ ] Lateral movement investigated across relevant systems
- [ ] Persistence mechanisms investigated
- [ ] Forensic evidence integrity documented
- [ ] Detection rules tuned and tested
- [ ] Asset owner and incident response lead informed
- [ ] Recovery validated before returning the endpoint to service

---

## Senior SOC Challenge

**Which endpoint is more concerning: one generating 10,000 LSASS access alerts, or one generating zero LSASS access alerts for 48 hours?**

The quiet one, in most cases, because alert volume measures noise, not security. Ten thousand LSASS access alerts is almost certainly a tuning problem: legitimate security tools touch LSASS constantly, so a flood usually means the rule is firing on approved software and needs an allowlist, not that an attack is in progress. It is loud, but it is visible, and visible problems get fixed. Zero alerts for 48 hours is the dangerous case, because there are two very different reasons for silence and they look identical from the dashboard: either the endpoint is genuinely healthy, or the SOC has gone blind to it. The things that produce false silence are exactly the things an attacker wants: a stopped or starved Sysmon service, an EDR sensor that is disabled or disconnected, a Wazuh agent that is not forwarding, a Sysmon config that never captured Event 10 in the first place, or a rule that silently failed. The difference between "no suspicious activity" and "no visibility" cannot be read from the absence of alerts; it has to be proven. To distinguish a quiet, healthy endpoint from a blind one, the SOC needs positive evidence of telemetry health: a recent agent heartbeat and event-forwarding timestamp, a benign baseline of expected events still arriving (logons, process creations), the Sysmon service running with the expected config hash, the EDR sensor reporting active, and periodic known-good test events that should always generate a log. An endpoint is only safely "quiet" when its silence is backed by proof that it would have spoken if there were something to say.

---

## References

- [MITRE ATT&CK T1003.001: OS Credential Dumping, LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)
- [MITRE ATT&CK TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006/)
- [MITRE ATT&CK T1218: System Binary Proxy Execution](https://attack.mitre.org/techniques/T1218/)
- [Wazuh Documentation](https://documentation.wazuh.com/)
- [SigmaHQ](https://sigmahq.io/)

---

**Status:** Active triage. WS-427 flagged for isolation pending confirmation, the privileged account under review, memory and disk evidence being preserved before any reboot, telemetry health being validated, and the privileged logon trail being correlated across the domain controller before compromise is called confirmed.
