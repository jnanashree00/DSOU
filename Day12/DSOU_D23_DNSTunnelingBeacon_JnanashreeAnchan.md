# SOC Triage Report
### SOC-2026-0925-23 | DNS Tunneling - The Silent Beacon
**Analyst:** Jnanashree Anchan | **Program:** GraySentinel DSOU | **Date:** 25 September 2026

---

## Alert Details

| Field | Value |
|---|---|
| Alert ID | SOC-2026-0925-23 |
| Rule | DNS Tunneling — WS-207: 4,000+ DNS queries in 2 hours with long TXT-record subdomains |
| Severity | CRITICAL |
| Host | WS-207 (Internal Workstation); DNS-01-PRD (DNS Server) |
| Platform | Wazuh SIEM / Windows / Sysmon |

---

## Verdict

**TRUE POSITIVE — Suspected DNS tunneling and C2 beaconing. Do NOT flush the DNS cache. A cache flush destroys the query evidence and does nothing to stop the beaconing process on WS-207. "No Threat Found" from AV and a patched host do not clear this.**

---

| | |
|---|---|
| **WHAT** | A workstation sent 4,000+ DNS queries in 2 hours, including many TXT-record lookups with long random subdomains to an external domain |
| **WHEN** | Friday morning, 25 Sep 2026 — 4,000+ queries over a 2-hour window; a Logon Type 2 also occurred outside business hours |
| **WHERE** | WS-207 (internal workstation), queries traversing DNS-01-PRD to `tunnel-domain[.]xyz` |
| **WHO** | A process on WS-207 acting under a logged-in user; the true operator is external, using DNS as the control channel |
| **WHY** | To run a covert command-and-control channel and exfiltrate data encoded inside DNS queries, bypassing controls that watch HTTP but trust DNS |
| **HOW** | 1. Logon Type 2 outside hours (Event 4624) → 2. A process issues high-volume DNS queries (Sysmon 22) → 3. Data encoded in long subdomains, answers returned in TXT records → 4. WFP allows the UDP 53 traffic (Event 5156) because DNS is rarely blocked |

---

## Why This Is Tunneling, Not a Caching Issue

IT's instinct to flush the cache is wrong on two counts. A cache flush clears stored answers; it does not stop the process that is generating the queries, so the beaconing simply continues. And flushing destroys the local resolver evidence that shows what was asked.

DNS tunneling works because DNS is almost always allowed outbound. Firewalls block strange HTTP, but UDP 53 to a resolver looks normal, which is exactly why Event 5156 shows the connection allowed. The attacker encodes data into the subdomain of each query (`a8f3k2m9x1.tunnel-domain[.]xyz`) and receives instructions or acknowledgements back inside TXT records, which can carry arbitrary text. The tells here are the volume (4,000+ in 2 hours is far above any human browsing), the long random subdomains (encoded data, not real hostnames), the heavy use of TXT records (rare in normal user traffic), and a single external domain receiving nearly all of it.

"No Threat Found" from AV means only that the binary is not in a signature database. A custom or living-off-the-land tunneling tool has no signature. A patched host is not a clean host.

---

## Mission 01 — Asset Discovery

| Asset Item | Why It Matters | Where to Find It |
|---|---|---|
| Role of DNS-01-PRD | Internal resolver vs forwarder vs AD-integrated changes where logging lives and how queries leave the network | AD topology, DNS server config, CMDB |
| Who WS-207 belongs to | Identifies the user, expected behaviour, and whether the out-of-hours logon makes sense | CMDB, asset inventory, HR/desk assignment |
| Wazuh agent status and version | Confirms telemetry is actually flowing and was not tampered with | Wazuh Manager agent panel |
| Last patch cycle and EDR status | A patched host with AV saying clean means signatures failed. EDR behaviour data is what matters here | WSUS/SCCM, EDR console |
| Process making the queries (PID, parent) | The single most important pivot. Names the malicious process and how it was launched | Sysmon Event 22 (QueryName + Image + PID), EDR |
| Recent logon activity on WS-207 | The out-of-hours Logon Type 2 needs to be tied to a user or shown as attacker-driven | Event 4624 / 4625 on WS-207 |
| Accounts logged in over last 7 days | Detects shared use, stolen credentials, or an unexpected account | Event 4624 history, Wazuh |
| Installed software and browser extensions | A malicious extension or app can be the beaconing source | Program list, browser profile, Sysmon 1 |
| DNS query volume baseline for WS-207 | 4,000 in 2 hours only means something against a normal baseline of a few hundred a day | Historical DNS logs, Wazuh |
| Network connections over last 7 days | Shows any second channel or lateral movement beyond DNS | Firewall logs, Sysmon Event 3, NetFlow |

---

## Mission 02 — Hunting Hypotheses

**H1: A malicious process on WS-207 is using DNS tunneling for C2 and data exfiltration**

Hypothesis: A process on the host encodes data into DNS queries to an attacker-controlled domain and receives commands back in TXT records.

| Field | Details |
|---|---|
| **Evidence Required** | Sysmon 22 events tying a specific process (Image, PID) to the queries; long encoded subdomains under one domain; TXT record queries; a consistent beacon interval; Sysmon 3 or firewall data showing UDP 53 only to the internal resolver |
| **Data Sources** | Sysmon (Event 22 DNS, Event 1 process, Event 3 network), Wazuh, DNS server logs, firewall logs |
| **Expected Indicators** | One non-browser process generating thousands of queries; high-entropy subdomains; TXT-heavy traffic; a single external domain dominating; regular timing between queries |
| **False Positives** | Some antivirus, EDR and telemetry agents use DNS-like lookups legitimately; CDNs and cloud apps produce long subdomains. These resolve to known vendor domains and lack the encoded-data pattern |
| **Conclusion** | If one process is tied to high-volume, high-entropy, TXT-heavy queries to a single unknown domain, this is confirmed tunneling. Identify the process and its persistence before containment. |

---

**H2: A compromised browser extension or scheduled task is generating covert DNS beacons**

Hypothesis: The beaconing is driven not by an obvious binary but by a malicious browser extension or a scheduled task calling out on an interval.

| Field | Details |
|---|---|
| **Evidence Required** | The parent process of the Sysmon 22 events being a browser (chrome.exe, msedge.exe) or a scheduled-task host (svchost with a task, or a script engine); a recently added extension; a scheduled task created near the first beacon |
| **Data Sources** | Sysmon Event 1 (parent/child), browser extension inventory, Task Scheduler log (Event 4698), Wazuh |
| **Expected Indicators** | DNS queries whose parent is a browser or taskhost rather than a standalone binary; a new or unknown extension ID; a scheduled task pointing to a script or encoded command; beacon timing matching a task trigger |
| **False Positives** | Legitimate extensions and enterprise scheduled tasks that phone home; update checkers. Verified against known-good extension IDs and change management |
| **Conclusion** | If the query source traces to an extension or scheduled task, that mechanism is both the C2 driver and the persistence. It must be removed, not just the network blocked. |

---

**H3: An insider or red team tool is performing DNS-based recon or payload delivery**

Hypothesis: The activity is a DNS-based tool (for example iodine, dnscat2, or a C2 framework's DNS channel) run by an insider or an unannounced red team engagement.

| Field | Details |
|---|---|
| **Evidence Required** | Tool signatures in process names or command lines; the logged-in user's role and whether they have any reason to run such a tool; any authorised red team notification for this window |
| **Data Sources** | Sysmon Event 1 command lines, PowerShell ScriptBlock logs (Event 4104), change management and red team records, HR context |
| **Expected Indicators** | Known DNS-tunneling tool names or flags; execution from Temp or AppData; an interactive out-of-hours session matching the Logon Type 2; no corresponding authorised test |
| **False Positives** | A sanctioned red team exercise that was not communicated to L1; a sysadmin using a diagnostic tool |
| **Conclusion** | Confirm against the red team calendar first. If no authorisation exists, treat as malicious insider or external compromise and preserve evidence for potential HR or legal action. |

---

## Mission 03 — Detection Engineering

**Detection Name:** DNS Tunneling — High-Volume, High-Entropy Queries from a Single Host

| Field | Details |
|---|---|
| **Telemetry** | Sysmon Event 22 (DNS query) and DNS server query logs forwarded to Wazuh; firewall UDP 53 logs |
| **Relevant Fields** | QueryName, Image, ProcessId, host.name, RecordType, query length, query count per host over time |
| **Detection Logic** | ALERT when a single host exceeds a query-volume threshold to one parent domain in a short window (for example > 500 queries to the same registered domain in 1 hour), AND the average subdomain length or entropy is high, AND/OR the ratio of TXT (or NULL) record queries is abnormally high. Pseudo logic: count(QueryName) by host.name, registered_domain over 1h > 500 AND avg(subdomain_entropy) > threshold AND RecordType IN (TXT, NULL) ratio > 30%. Raise severity when the source process is not a browser or known resolver. |
| **Severity** | High to Critical (Critical when a single non-browser process drives it to an unknown external domain) |
| **False Positives** | Antivirus and EDR cloud lookups, CDNs, and some SaaS apps use long or high-volume DNS. Reduced with an allowlist of known vendor domains and by excluding known agent processes |
| **Analyst Response** | 1. Identify the source process from Sysmon 22 (Image, PID) / 2. Check the domain reputation (VirusTotal, threat intel) / 3. Confirm the encoding pattern and TXT ratio / 4. Pull persistence and logon context / 5. Capture memory, then block the domain and isolate. Order matters: capture before isolate |

---

## Mission 04 — Identity and Persistence Hunt

| Hunt Item | What to Look For | Where |
|---|---|---|
| Suspicious scheduled tasks | Tasks created near the first beacon, pointing to scripts, encoded commands, or Temp paths | Event 4698, Task Scheduler log |
| New services installed | Unexpected services, especially with random or system-mimicking names | Event 7045, Windows System log |
| Run key / Startup folder changes | New autorun entries pointing to non-standard paths | Sysmon Event 13, registry audit (Event 4657), Startup folder |
| Malicious browser extensions | Recently added or unknown extension IDs, especially with broad permissions | Browser profile, extension inventory |
| PowerShell history and ScriptBlock logs | Encoded commands, download cradles, or DNS-tool invocation | Event 4104 PowerShell Operational log |
| New local admin accounts | Accounts created or added to Administrators during the window | Event 4720 / 4732, local groups |
| DLL sideloading / unsigned binaries | Unsigned executables or suspicious DLLs in Temp or AppData | Sysmon Event 1 / 7, EDR |
| WMI event subscriptions | Permanent WMI subscriptions used for stealthy persistence | Sysmon Event 19/20/21, WMI repository |

**The ONE thing to do before isolating WS-207:**

Capture a live memory image of WS-207 while it is still running and still connected.

The reason is that the most valuable evidence for a DNS tunneling case lives in volatile memory: the running malicious process, its command line, injected code, encryption keys, the C2 domain and any decoded commands, and active network state. Isolation often triggers the malware to stop beaconing, and pulling the network cable or powering off loses everything in RAM. A memory capture taken before isolation preserves the process and its C2 configuration so the domain, the tool, and the scope of exfiltration can be identified. Disk imaging and blocking come after. Capture the volatile state first, because you only get one chance at it.

---

## MITRE ATT&CK

| Technique | ID | Relevance |
|---|---|---|
| Application Layer Protocol: DNS | T1071.004 | The core technique — DNS used as the covert C2 channel |
| Application Layer Protocol | T1071 | Parent technique for C2 over a common protocol |
| Exfiltration Over C2 Channel | T1041 | Data encoded into DNS queries and sent out over the same channel |
| Command and Scripting Interpreter: PowerShell | T1059.001 | Possible launcher for the beaconing, checked in ScriptBlock logs |
| Scheduled Task/Job | T1053.005 | Candidate persistence under H2 |
| Event Triggered Execution: WMI Event Subscription | T1546.003 | Stealthy persistence checked in the hunt |
| Valid Accounts | T1078 | Out-of-hours Logon Type 2 may indicate credential misuse |

---

## Impact

**CRITICAL**   A confirmed DNS C2 channel means an external operator has interactive control of an internal workstation and a working exfiltration path that bypasses HTTP-focused controls. The scope of data already sent out over DNS is unknown until the process and its history are analysed, and the same channel could be used to pull additional payloads or move laterally.

---

## Actions

| Action Category | Details |
|---|---|
| **PRESERVE** | Capture live memory of WS-207 before any containment; then image the disk; preserve Sysmon, DNS server and firewall logs |
| **INVESTIGATE** | Identify the source process and parent from Sysmon 22; check the domain against threat intel; measure the exfiltration volume; review the out-of-hours logon |
| **CONTAIN** | After memory capture, isolate WS-207 from the network; terminate the malicious process |
| **BLOCK** | Sinkhole or block `tunnel-domain[.]xyz` and any related domains at the DNS server and firewall; block the resolver path for the host if needed |
| **ERADICATE** | Remove persistence found in the hunt (scheduled task, service, Run key, extension, WMI subscription); remove the malicious binary |
| **ROTATE** | Rotate the password of every account used on WS-207; review what those accounts can reach |
| **ESCALATE** | L2/IR immediately; notify the asset owner; assess data-exfiltration and breach-notification requirements with legal if sensitive data left the network |

---

## Mission 05 — Incident Closure Checklist

- [ ] WS-207 isolation status verified (after memory capture)
- [ ] Live memory capture and disk image preserved
- [ ] Sysmon logs, DNS logs and firewall logs preserved
- [ ] Event IDs 4624, 4688, 5156, Sysmon 22, Sysmon 3 reviewed
- [ ] Malicious process identified and terminated
- [ ] C2 domain and any related IPs blocked at DNS and firewall
- [ ] Exfiltration volume and data scope assessed
- [ ] User account passwords rotated
- [ ] Persistence (scheduled task / service / WMI / extension / Run key) investigated and removed
- [ ] Lateral movement from WS-207 reviewed
- [ ] Evidence preserved for forensics and potential legal requirements
- [ ] Monitoring increased for DNS anomalies; detection rule tuned
- [ ] DNS query baseline established for future detection
- [ ] Business and asset owner informed
- [ ] Post-incident report drafted with full timeline

---

## Senior SOC Question

**What is more dangerous for a SOC — a workstation that generates 10,000 DNS alerts, or one that generates ZERO DNS alerts for 48 hours?**

A workstation that generates ZERO DNS alerts for 48 hours is far more dangerous.

10,000 DNS alerts is a tuning problem. The host is producing telemetry, so you have visibility. You can baseline it, filter the noise, and pull the real tunneling pattern out of the volume. In this very case, it was a high volume of DNS activity that exposed the beacon. Loud is workable.

Zero DNS alerts for 48 hours from an active workstation is almost impossible under normal operation. A workstation in use constantly resolves names for browsing, updates, and internal services. Total silence usually means the Sysmon DNS logging was disabled, the Wazuh agent was stopped, or events stopped reaching the SIEM. An attacker who has silenced DNS telemetry has removed the exact signal that catches tunneling, and can then run a slow, low-volume beacon with no chance of detection.

From a Detection Engineering perspective, the lesson is that a sudden drop to zero is itself a detection. A loud host can be tuned; a silent host has to be explained. The SOC needs a heartbeat rule that fires when a normally active host stops sending DNS telemetry, because in tunneling cases the most dangerous beacon is the quiet one you can no longer see.

---

## Resources

| Reference | Link |
|---|---|
| MITRE ATT&CK — DNS Tunneling (T1071.004) | https://attack.mitre.org/techniques/T1071/004/ |
| MITRE ATT&CK — Application Layer Protocol (T1071) | https://attack.mitre.org/techniques/T1071/ |
| MITRE ATT&CK — Exfiltration Over C2 Channel (T1041) | https://attack.mitre.org/techniques/T1041/ |
| Wazuh — Sysmon Integration | https://documentation.wazuh.com/ |
| Sigma Rule — Suspicious DNS Query | https://sigmahq.io/ |
| CISA — DNS Security Guidance | https://www.cisa.gov/ |

---

**Status:** Escalated to L2/IR. Memory capture in progress before isolation. C2 domain pending block at DNS and firewall. DNS anomaly monitoring increased across the workstation fleet.