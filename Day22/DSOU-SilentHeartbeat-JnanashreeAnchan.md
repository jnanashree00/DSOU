# SOC Triage Report
### SOC-2026-1012-01 | C2 Beaconing: The Silent Heartbeat

**Analyst:** Jnanashree Anchan | **Program:** GraySentinel DSOU | **Date:** 12 October 2026

---

## Alert Details

| Field | Value |
|---|---|
| **Alert ID** | SOC-2026-1012-01 |
| **Rule** | Regular fixed-interval HTTPS connections from WS-442 to an external IP, same size and same timing, from a process named OneDriveSync.exe running out of C:\Users\Public\ |
| **Severity** | High |
| **Host** | WS-442 (workstation) |
| **Platform** | Wazuh, Sysmon, Windows Security, EDR, Firewall/Proxy |
| **CVE / CVSS** | Not applicable. This is command-and-control beaconing behavior, not a vulnerability exploit. |

---

## Verdict

**Confirmed C2 beaconing, not a OneDrive sync issue and not a false positive. WS-442 is sending an HTTPS request to the same external IP every 60 seconds at the same size, which is the textbook signature of an automated beacon rather than human or application traffic. The process behind it, OneDriveSync.exe, is running from C:\Users\Public\, not the real OneDrive install path, is unsigned, and was spawned by explorer.exe, so it is a masquerading implant using a trusted-sounding name. Do NOT reinstall OneDrive and do NOT isolate WS-442 yet, because volatile evidence, the implant process, its memory, and the live C2 channel, must be captured first.**

The host being patched and antivirus returning "No Threat Found" does not clear it. Beaconing implants routinely evade signature AV by living in a signed-looking or renamed binary and blending into normal HTTPS, so AV silence here means no signature matched, not that nothing is wrong. The detection that matters is the regularity of the callback and the identity and location of the process making it, not the fact that an executable called OneDriveSync.exe is talking to the internet.

---

| Field | Detail |
|---|---|
| **WHAT** | WS-442 is beaconing over HTTPS to an external IP on a fixed 60-second interval with constant payload size, driven by a masquerading binary (OneDriveSync.exe) in C:\Users\Public\. |
| **WHEN** | Monday 12 October 2026, morning, with the callbacks recurring on a steady 60-second cadence. Exact times from Wazuh. |
| **WHERE** | WS-442, reaching 185.xx.xx.xx:443 and resolving cdn-update-sync[.]com. |
| **WHO** | The primary user of WS-442, to be confirmed; the activity is driven by the implant process, not deliberate user action. |
| **WHY** | Maintain a covert command-and-control channel, likely toward data exfiltration or follow-on tasking. |
| **HOW** | An unsigned binary spawned from explorer.exe (4688, Sysmon 1) makes repeated allowed HTTPS connections (Sysmon 3, 5156) to an external host after resolving a lookalike CDN domain (Sysmon 22). |

---

## Attack Chain

| Timestamp | Log Event | Attack Phase |
|---|---|---|
| T0 | Sysmon 1 and 4688, unsigned OneDriveSync.exe spawned from explorer.exe, running from C:\Users\Public\ | Execution, masquerading |
| T0 plus | Sysmon 22, DNS query for cdn-update-sync[.]com | C2, domain resolution |
| T0 plus | Sysmon 3, network connection to 185.xx.xx.xx:443 | C2, channel established |
| T0 plus | 5156, Windows Filtering Platform allowed the connection (repeated) | C2, recurring callback |
| T0 plus 60s, repeating | Same-size HTTPS request every 60 seconds | C2, beaconing |

Note: a process name that mimics OneDrive but runs from C:\Users\Public\ while being unsigned, combined with a fixed-interval same-size callback, is the beaconing-via-masquerade pattern. Correlate before attributing, but the regularity, the process origin, and the lookalike domain line up as one implant.

---

## Mission 01 — Asset Discovery

| Item to Establish | Why It Matters | Where to Find It |
|---|---|---|
| **Role of WS-442 (developer, finance, remote worker)** | Sets the value at risk and the expected traffic baseline | Asset inventory, CMDB |
| **Primary user of WS-442** | Whose context the implant is running in | Asset inventory, 4624 |
| **Wazuh agent status and version** | Whether telemetry is complete and current | Agent status |
| **Last patch cycle and EDR status** | Confirms patch state and whether the EDR sensor is healthy | Patch management, EDR console |
| **Process making the HTTPS requests (PID, hash, signature)** | Identifies the implant and whether it is trusted | Sysmon 1, 3, EDR |
| **Recent logon activity** | Establishes a user baseline and any anomalous access | 4624, 4625 |
| **Installed software and browser extensions** | Rules out a legitimate sync tool or a rogue extension | Software inventory, browser profile |
| **Proxy and firewall logs for 185.xx.xx.xx** | Volume, duration, and regularity of the callbacks | Proxy, firewall |
| **DNS history for cdn-update-sync[.]com** | When resolution started and how often it recurs | DNS logs, Sysmon 22 |
| **Network connections from WS-442 over the last 7 days** | Whether the beacon predates today and its full pattern | SIEM, NetFlow |

**Deliverable:** an Asset Context Map for WS-442 (role, user, patch and EDR state) plus the implant's identity (process, path, hash, signer). **Primary question:** is the recurring HTTPS traffic a legitimate sync or update service, or an automated C2 beacon? That is answered by the regularity of the callback and by validating the process name against its real path, signature, and hash.

---

## Mission 02 — Hunting Hypotheses

**H1: A C2 implant is beaconing to an external server over HTTPS with fixed jitter and payload size.**

| Field | Details |
|---|---|
| **Evidence Required** | The recurring Sysmon 3 connections, interval and size regularity, the process name, hash and signer, the resolved domain |
| **Data Sources** | Wazuh, Sysmon, firewall and proxy logs, EDR |
| **Expected Indicators** | A fixed interval (60s) with near-constant payload size, an unsigned process, a lookalike C2 domain, repeated 5156 allows |
| **False Positives** | Legitimate sync, update, or telemetry agents that poll on a schedule (OneDrive, antivirus, software updaters) |
| **Conclusion** | Strongly supported. The 60-second same-size callback from an unsigned binary in C:\Users\Public\ is beaconing, not sync. Primary hypothesis. |

**H2: A malicious binary masquerading as a legitimate sync tool is maintaining persistence and exfiltrating data.**

| Field | Details |
|---|---|
| **Evidence Required** | The file path and signature of OneDriveSync.exe, its parent process, any persistence entries, outbound data volume |
| **Data Sources** | Sysmon 1, Windows Event 4688, autoruns/scheduled tasks, proxy byte counts |
| **Expected Indicators** | A trusted-sounding name in a non-standard path, unsigned, spawned by explorer.exe, a persistence mechanism, outbound transfers larger than a heartbeat |
| **False Positives** | A genuinely misinstalled sync client, portable apps run from a user directory |
| **Conclusion** | Supported. The name-versus-path mismatch and the unsigned binary fit a masquerading implant; confirm persistence and measure outbound volume to assess exfiltration. |

**H3: A compromised browser extension or scheduled task is generating covert outbound traffic at regular intervals.**

| Field | Details |
|---|---|
| **Evidence Required** | Installed browser extensions, scheduled tasks, the true owner of the outbound connections |
| **Data Sources** | Browser profile, Task Scheduler (4698), Sysmon 1 process ancestry |
| **Expected Indicators** | A recently added extension or task timed to the callback interval, traffic owned by a browser or task host rather than OneDriveSync.exe |
| **False Positives** | Legitimate extensions and scheduled update tasks that poll periodically |
| **Conclusion** | Less likely as the root cause. The traffic is attributed to OneDriveSync.exe, not a browser or task host, but check for a scheduled task as the persistence that relaunches the implant. |

---

## Mission 03 — Detection Engineering

**Detection Name:** C2 Beaconing / Periodic Callback from an Endpoint

| Field | Details |
|---|---|
| **Telemetry** | Sysmon (Event 3 network connect, Event 22 DNS, Event 1 process create), Windows Security 5156, firewall/proxy logs, EDR network telemetry |
| **Relevant Fields** | Image, OriginalFileName, Signed, SourceIp, DestinationIp, DestinationPort, QueryName, connection timestamp and byte count, ParentImage |
| **Detection Logic** | IF an endpoint makes repeated outbound connections to the same external destination AND the inter-connection interval is near-constant (low jitter, for example a 60s period) with near-constant payload size over a rolling window AND the source process is unsigned or runs from an unusual path such as C:\Users\Public\ or AppData, THEN raise HIGH. Score on the regularity of the callback and the identity and location of the process, not on the destination port (443) alone, which is normal for most traffic. |
| **Severity** | High, raised to Critical if outbound data volume exceeds a heartbeat or persistence is confirmed |
| **False Positives** | Legitimate sync, update, and telemetry agents that poll on a timer. Allowlist known-good signed updaters by hash and path, and baseline their intervals so a renamed binary in the wrong path still stands out. |
| **Analyst Response** | Identify the process, validate its signature, path, and hash, measure the interval and payload regularity, resolve and reputation-check the destination domain and IP, hunt the same binary and domain across the fleet, and escalate if a beacon is confirmed. |

---

## MITRE ATT&CK

| Technique | ID | Relevance |
|---|---|---|
| **Application Layer Protocol: Web Protocols** | T1071.001 | HTTPS used as the C2 transport |
| **Encrypted Channel** | T1573 | TLS on 443 hides the beacon content |
| **Exfiltration Over C2 Channel** | T1041 | The channel is the likely exfiltration path |
| **Masquerading: Match Legitimate Name or Location** | T1036.005 | OneDriveSync.exe impersonating the real sync client |
| **Scheduled Task/Job** | T1053.005 | Candidate persistence that relaunches the implant |
| **Ingress Tool Transfer** | T1105 | The unsigned binary delivered into C:\Users\Public\ |

---

## Mission 04 — Identity & Persistence Hunt

Hunt for what the attacker may have left on WS-442.

- [ ] Suspicious scheduled tasks (4698)
- [ ] New services installed (7045)
- [ ] Run key or Startup folder modifications
- [ ] WMI event subscription persistence
- [ ] New local administrator accounts (4720, 4732)
- [ ] The malicious binary in C:\Users\Public\ or AppData, with its hash
- [ ] DLL sideloading or other unsigned binaries
- [ ] Credential material in PowerShell history (4104)

**Critical question: if C2 beaconing is confirmed on WS-442, what is the ONE thing you must do before isolating it?**

Capture volatile memory (and the live network state) first. Isolation cuts the C2 channel, and that single act can destroy the most valuable evidence: the implant's configuration, its encryption keys, the in-memory C2 profile, decrypted tasking, and any injected code live only in RAM, and pulling the network can trip a watchdog or kill-switch that wipes the implant or makes it go dormant. A memory image taken while the beacon is still active preserves the C2 address, the beacon interval and jitter, and often the decrypted payload, which is what lets the SOC fingerprint the implant and hunt it across the fleet. The on-disk binary and logs are preserved in parallel. The one caveat is active, destructive behavior: if the host is actively exfiltrating or spreading right now, contain immediately and acquire memory from the contained host, following the IR team's forensic order. Document integrity (hashes, chain of custody) for everything collected.

---

## Impact

**HIGH, rising to Critical if exfiltration or spread is confirmed.** A confirmed C2 channel means WS-442 is under external control, and the beacon is the attacker's foothold for tasking, credential theft, and data exfiltration over the same encrypted channel. Because the implant masquerades as OneDrive and survived a patched, AV-clean host, the same binary and domain may be present on other endpoints, so scope is an open question until the fleet is searched. The forward risk is data loss over the C2 channel and lateral movement from WS-442.

---

## Actions

| Action Category | Details |
|---|---|
| **PRESERVE** | Capture a memory image while the beacon is live, then preserve the OneDriveSync.exe binary and its hash, the Sysmon 1/3/22 and 5156 events, the proxy and DNS records, and the process ancestry, before isolation. |
| **CONTAIN** | After memory capture, isolate WS-442, and if active exfiltration is seen, contain immediately and image the contained host. |
| **INVESTIGATE** | Confirm the implant identity (path, signer, hash), measure the beacon interval and payload size, reputation-check 185.xx.xx.xx and cdn-update-sync[.]com, and find the same binary and domain across the fleet. |
| **ERADICATE** | Terminate the implant process and remove any persistence found in Mission 04, after evidence is captured. |
| **BLOCK** | Block cdn-update-sync[.]com at DNS and 185.xx.xx.xx at the firewall, and block the binary hash across EDR. |
| **ROTATE** | Reset the WS-442 user's password and any credentials that may have been exposed on the host. |
| **ESCALATE** | Notify the IR lead and the WS-442 asset owner, and raise fleet-wide monitoring for the same beacon pattern. |

---

## Mission 05 — Incident Closure

- [ ] WS-442 isolation status verified
- [ ] Memory capture and disk image preserved
- [ ] Sysmon logs, Security logs, and EDR telemetry preserved
- [ ] Event IDs 4688, 5156, Sysmon 1, Sysmon 3, and Sysmon 22 reviewed
- [ ] C2 domain and IP blocked at DNS and firewall
- [ ] Malicious process identified and terminated
- [ ] User account password rotated
- [ ] Persistence (scheduled task, service, WMI) investigated
- [ ] Lateral movement from WS-442 reviewed
- [ ] Evidence preserved for forensics
- [ ] Monitoring increased for beaconing behavior (rule tuning)
- [ ] Business and asset owner informed

---

## Senior SOC Question

**What is more dangerous for a SOC: an endpoint generating 10,000 outbound connection alerts, or an endpoint generating zero outbound connection alerts for 48 hours?**

From a detection-engineering view, the quiet endpoint is usually the more dangerous one. Ten thousand alerts is a noise problem: it is almost certainly an over-broad rule firing on legitimate traffic, and while it is painful, it is visible, measurable, and fixable by tuning and allowlisting. The real failure is that it buries true positives, so the danger is indirect, an analyst tunes it out and misses the one real hit in the flood. Zero alerts for 48 hours is more dangerous because silence is ambiguous, and the two explanations look identical on the dashboard: either the endpoint genuinely had no suspicious outbound activity, or the SOC has gone blind to it. The things that cause false silence are exactly what an attacker wants, a stopped or starved Sysmon service, a disconnected EDR sensor, a Wazuh agent that is not forwarding, a Sysmon config that never captured Event 3, or a rule that silently failed, and a well-built beacon is designed to look like nothing, low and slow, blended into normal HTTPS, so it can produce near-zero alerts while fully active. This case is the proof: WS-442 was patched, AV-clean, and generating almost nothing that looked alarming, yet it was beaconing every 60 seconds. The lesson is that alert volume measures noise, not security, and absence of alerts is only reassuring when it is backed by positive proof of telemetry health, a recent agent heartbeat, expected baseline events still arriving, the Sysmon service running with the expected config, and the EDR sensor reporting active. An endpoint is only safely "quiet" when you can prove it would have spoken if there were something to say.

---

## References

- [MITRE ATT&CK T1071: Application Layer Protocol](https://attack.mitre.org/techniques/T1071/)
- [MITRE ATT&CK T1041: Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/)
- [MITRE ATT&CK T1053: Scheduled Task/Job](https://attack.mitre.org/techniques/T1053/)
- [Wazuh Documentation: Sysmon integration](https://documentation.wazuh.com/)
- [SigmaHQ: detection rule format for suspicious network connections](https://sigmahq.io/)
- [CISA: identifying and mitigating command-and-control activity](https://www.cisa.gov/)

---

**Status:** Active incident. WS-442 flagged for memory capture before isolation, the implant process and the C2 indicators (185.xx.xx.xx, cdn-update-sync[.]com) identified for blocking, persistence and lateral movement under review, and a fleet-wide hunt for the same beacon pattern opened.
