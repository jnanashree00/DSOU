# DSOU Day 14 | Quishing Detection | 14 Sept 2026
**Analyst:** Jnanashree Anchan | **Program:** GraySentinel Blue Team

---

## Executive Summary
A QR code phishing email targeting Microsoft 365 credentials was identified. A malicious QR code embedded in a PDF attachment bypassed URL scanners by hiding the phishing URL inside an image.

---

## Email Header Analysis

| Field | Value |
|---|---|
| From | accounts@supplier-invoices[.]net |
| Sending IP | 185.220.101.47 |
| SPF | FAIL |
| DKIM | FAIL |
| DMARC | FAIL (p=reject) |

---

## QR URL + Final Phish Domain
**URL:** `hxxps://m365-login-verify[.]com/auth?session=INV2026-09-14`  
**Domain:** m365-login-verify[.]com  

![VirusTotal](screenshots/virustotal.png)  
![URLScan](screenshots/urlscan.png)

---

## MITRE ATT&CK
- T1566.002 — Spearphishing Link
- T1204.001 — Malicious Link

---

## IOCs

| Type | Value |
|---|---|
| IP | 185.220.101.47 |
| URL | hxxps://m365-login-verify[.]com/auth?session=INV2026-09-14 |
| Domain | m365-login-verify[.]com |
| Hash (synthetic) | d4f8a2c1b9e3f7a0c2d5e8b1f4a7c0d3e6b9f2a5 |
| Attachment | Invoice_INV-2026-09-14.pdf |

---

## Actions
**Block:** IP 185.220.101.47, domains supplier-invoices[.]net and m365-login-verify[.]com  
**User Awareness:** Alert staff on quishing technique. Never scan QR codes from unsolicited emails.

---

*Note: Synthetic .eml sample used for demonstration. No live environment available.*
