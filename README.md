# GraySentinel DSOU — Blue Team SOC Portfolio

**Analyst:** Jnanashree Anchan
**Program:** GraySentinel Cyber Defence Lab Blue Team


## About

This repository holds my daily work from the GraySentinel Blue Team. Each day has two parts: a SOC triage report (DSOU) that analyses a security alert, and a hands-on lab (GrayOS) that practises an attack or defence technique. I add a new folder for each day as I complete the work.

## What each day's folder contains

Every day folder follows the same layout:

- **DSOU report (.md)** — a SOC analysis of the day's alert: what happened, how I investigated it, the verdict, and how it could be detected.
- **Lab PoC (.md)** — a record of the day's hands-on lab, with commands and screenshots.
- **Lab certificate (.png)** — proof of lab completion.
- **screenshots/** - the images used in the reports.

To see the most recent work, open the highest-numbered day folder.

## What the reports cover

Each DSOU report works through a security scenario the way a SOC analyst would:

- Understanding the alert and the affected system
- Building hunting hypotheses and gathering evidence
- Writing a detection idea in Sigma-style logic
- Checking for attacker persistence
- Mapping the activity to MITRE ATT&CK
- Reaching a verdict and listing closure steps


## Skills
 
- SOC alert triage and incident investigation
- Threat hunting and detection engineering
- Incident response and MITRE ATT&CK mapping
- Web/API, cloud, container and Active Directory security analysis


## Tools
 
Wazuh, Sysmon, Sigma, MITRE ATT&CK, VirusTotal, and a range of web, cloud and Kubernetes security scanners used per lab.