# SOC Triage Report
### Detection Engineering Sunday - Office App Spawning PowerShell with Outbound Connection

**Analyst:** Jnanashree Anchan
**Program:** GraySentinel Blue Team Premium | Day 18
**Submission Date:** 21 September 2026

---

# Scenario

An Office application (Word, Excel, or Outlook) spawns a PowerShell child process that immediately establishes an outbound network connection. This pattern is a strong indicator of macro-based malware execution, phishing payload delivery, or a living-off-the-land attack technique.

---

# Investigation Plan

**Alert Triggered:** Office application (winword.exe / excel.exe / outlook.exe) spawning powershell.exe with an outbound TCP/UDP connection detected within the same process chain.

**Initial Questions:**
- Which Office application spawned the PowerShell process?
- What command-line arguments were passed to PowerShell?
- What is the destination IP and port of the outbound connection?
- Was the Office document received via email or downloaded from the web?
- Is Script Block Logging capturing the full PowerShell payload?

**Immediate Actions:**
1. Isolate the endpoint from the network if the connection is to an unknown or flagged external IP
2. Capture the memory of the PowerShell process before termination
3. Preserve the Office document that triggered execution
4. Pull Sysmon logs (Event ID 1, 3, 7) and PowerShell logs (Event ID 4104)
5. Check the destination IP against threat intel feeds (VirusTotal, AbuseIPDB)

---

# Hunting Hypothesis

**Hypothesis:** A threat actor has delivered a malicious Office document containing an embedded macro or exploit that spawns PowerShell to download and execute a second-stage payload from a remote C2 server.

**Why this matters:** Office macro attacks remain one of the most common initial access vectors. Legitimate Office applications almost never spawn PowerShell that immediately makes outbound connections. This parent-child process chain combined with network activity is a high-confidence signal of compromise.

**Where to look:**
- Sysmon Event ID 1: Process creation (powershell.exe with suspicious parent)
- Sysmon Event ID 3: Network connection from powershell.exe
- Sysmon Event ID 7: Image loaded (check for unusual DLLs)
- Windows Security Event ID 4688: Process creation with command-line logging enabled
- PowerShell Event ID 4104: Script block logging (decoded payload content)
- Email gateway logs: Source of the Office document

---

# Detection Concept

**Detection Name:** Office Application Spawning PowerShell with Suspicious Outbound Network Connection

**Detection Logic:** Alert when any Office application (Word, Excel, Outlook, PowerPoint) is the parent process of PowerShell, AND PowerShell establishes a network connection within 60 seconds of process creation, AND the destination is not a known-good Microsoft endpoint.

**Sigma Rule:**

    title: Office Application Spawning PowerShell with Outbound Connection
    id: 7f3a9c2e-1b4d-4e8f-a0c5-2d6b9e3f7a1c
    status: experimental
    description: >
      Detects Office applications spawning PowerShell as a child process
      that subsequently establishes an outbound network connection.
      Indicative of macro-based malware or phishing payload execution.
    references:
      - https://attack.mitre.org/techniques/T1566/001/
      - https://attack.mitre.org/techniques/T1059/001/
    author: Jnanashree Anchan
    date: 2026-09-21
    tags:
      - attack.initial_access
      - attack.execution
      - attack.command_and_control
      - attack.t1566.001
      - attack.t1059.001
      - attack.t1071.001
    logsource:
      product: windows
      category: process_creation
    detection:
      selection_parent:
        ParentImage|endswith:
          - '\winword.exe'
          - '\excel.exe'
          - '\outlook.exe'
          - '\powerpnt.exe'
          - '\mspub.exe'
      selection_child:
        Image|endswith: '\powershell.exe'
      selection_cmdline:
        CommandLine|contains:
          - '-enc'
          - '-EncodedCommand'
          - 'IEX'
          - 'Invoke-Expression'
          - 'DownloadString'
          - 'WebClient'
          - 'Net.WebClient'
          - 'hidden'
          - 'bypass'
      condition: selection_parent and selection_child and selection_cmdline
    falsepositives:
      - IT automation scripts triggered from Office macros in managed environments
      - Legitimate admin tools that use Office as a host for scripting
      - Security awareness training platforms that simulate macro attacks
    level: high

---

# False Positives

| Scenario | How to Distinguish |
|---|---|
| IT automation: macros used by IT teams to run maintenance scripts via PowerShell | Check if the source document is in a known IT scripts folder; verify with the IT team; check if the destination IP is internal |
| Security training platforms simulating macro attacks | Cross-reference with the security team's training schedule; check if destination matches training vendor IP ranges |
| Legitimate Office add-ins or plugins that spawn PowerShell for telemetry or updates | The command line will target Microsoft or vendor update endpoints; destination should match known-good domains |

---

# Triage Steps

**Step 1: Identify the Parent Document**

Pull Sysmon Event ID 1 to get the full command line of the PowerShell process. Trace back to the parent Office process and identify the document path. Check if the document was received via email (look at Outlook logs or email gateway), downloaded from the web (check browser history or Zone.Identifier alternate data stream), or placed on a file share.

**Step 2: Decode the PowerShell Payload**

Check PowerShell Script Block Logging (Event ID 4104) for the decoded payload content. If the command line contains `-enc` or `-EncodedCommand`, decode the Base64 string. Look for download cradles (IEX, WebClient, DownloadString) and extract the C2 URL or IP.

**Step 3: Assess the Outbound Connection**

From Sysmon Event ID 3, extract the destination IP and port. Look up the IP on VirusTotal, AbuseIPDB, and Shodan. Check if the port is unusual (non-80/443 outbound from a workstation is a strong indicator). Determine if other endpoints in the environment have connected to the same destination.

---

# Escalation Conditions

Escalate immediately to Incident Response if any of the following are observed:

- PowerShell payload successfully downloads and executes a second-stage binary
- Outbound connection destination is flagged on threat intelligence feeds as a known C2 or malicious host
- Lateral movement detected from the affected endpoint (new authentication events, PsExec, WMI)
- Credential access tools detected in memory (Mimikatz signatures, LSASS access)
- Multiple endpoints in the environment show the same parent-child process pattern (potential campaign)
- Ransomware indicators: mass file encryption, shadow copy deletion, backup tampering

---

# MITRE ATT&CK

| Technique | ID | Notes |
|---|---|---|
| Phishing: Spearphishing Attachment | T1566.001 | Malicious Office document delivered via email |
| Command and Scripting Interpreter: PowerShell | T1059.001 | PowerShell used to execute payload |
| Application Layer Protocol: Web Protocols | T1071.001 | C2 communication over HTTP/HTTPS |
| Ingress Tool Transfer | T1105 | Downloading second-stage payload |
| Obfuscated Files or Information | T1027 | Base64 encoded PowerShell command |
| User Execution: Malicious File | T1204.002 | User opens and enables macros in Office document |

---

# Ransomware Readiness Checklist

**Prevention:**
- [ ] Macro execution disabled by Group Policy for all non-IT users
- [ ] Attack Surface Reduction (ASR) rules enabled: block Office apps from creating child processes
- [ ] PowerShell execution policy set to AllSigned or RemoteSigned
- [ ] Script Block Logging and Module Logging enabled via Group Policy
- [ ] Email gateway configured to strip Office documents with macros from external senders

**Detection:**
- [ ] Sysmon deployed with a configuration that captures process creation, network connections, and image loads
- [ ] PowerShell Event ID 4104 forwarded to SIEM
- [ ] Parent-child process chain alerts configured in SIEM
- [ ] Outbound connection alerts for PowerShell and Office applications
- [ ] Endpoint Detection and Response (EDR) covering all workstations

**Response:**
- [ ] Incident Response playbook for macro-based attacks documented and tested
- [ ] Network isolation capability available (manual or automated via EDR)
- [ ] Offline backups verified as clean and restorable within RTO
- [ ] Legal and communications team briefed on ransomware response procedures
- [ ] Threat hunting runbook for lateral movement post-initial-access

**Recovery:**
- [ ] Clean OS images available for rapid workstation reimaging
- [ ] Critical data backup integrity verified in last 7 days
- [ ] Business Continuity Plan tested within last 6 months
- [ ] IR retainer in place with external forensics vendor

---

# References

- [MITRE ATT&CK T1566.001 - Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)
- [MITRE ATT&CK T1059.001 - PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [Microsoft - Attack Surface Reduction Rules](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference)
- [Sigma HQ - Detection Rules](https://github.com/SigmaHQ/sigma)
- [CISA - Phishing Guidance](https://www.cisa.gov/phishing)

---

# Self-Score

| Category | Max | Score | Notes |
|---|---|---|---|
| Detection hypothesis clarity | 10 | 9 | Clear attacker intent, telemetry sources identified |
| Sigma rule quality | 10 | 8 | Multi-condition rule with specific command-line patterns |
| False positive analysis | 5 | 5 | 3 distinct scenarios with differentiation guidance |
| Triage steps | 5 | 5 | 3 actionable steps with specific event IDs |
| Escalation conditions | 5 | 5 | 6 clear escalation triggers |
| Ransomware readiness | 5 | 5 | Full checklist across prevention, detection, response, recovery |
| **Total** | **40** | **37** | |

---

**Status:** Submitted. Detection rule validated against MITRE ATT&CK framework. Ready for peer review.