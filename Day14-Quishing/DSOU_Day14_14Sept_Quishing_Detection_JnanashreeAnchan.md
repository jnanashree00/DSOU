# DSOU Day 14 | QR Code Phishing (Quishing) Detection | 14 Sept 2026
**Analyst:** Jnanashree Anchan | **Program:** GraySentinel Blue Team

---

## Executive Summary
A QR code phishing (quishing) email targeting Microsoft 365 credentials was identified and analysed. The attacker embedded a malicious QR code inside a PDF attachment to bypass URL scanning tools, redirecting victims to a credential harvesting page hosted on AWS infrastructure.

---

## Email Header Analysis

| Field | Value |
|---|---|
| From | accounts@supplier-invoices[.]net |
| To | john.smith@company.com |
| Subject | ACTION REQUIRED: Invoice #INV-2026-09-14 - Scan to Verify |
| Date | 14 Sep 2026 08:42:31 UTC |
| Sending IP | 185.220.101.47 |
| SPF | FAIL |
| DKIM | FAIL |
| DMARC | FAIL (p=reject) |

All three email authentication checks failed, confirming a spoofed sender domain.

---

## QR Code Analysis

The PDF attachment contained a QR code redirecting to:

`hxxps://m365-login[.]com`

The domain mimics a legitimate Microsoft 365 login page, designed to harvest credentials from victims who scan with their mobile device, bypassing endpoint email security that cannot parse QR codes embedded in images.

**QR Code:**

![QR Code](screenshots/qr-code.png)

**VirusTotal Result:** Flagged by 4 vendors as phishing and fraud. Hosted on AWS at IP 13.53.140.86.

![VirusTotal](screenshots/virustotal.png)

**URLScan.io Result:** Could not scan the domain, consistent with anti-analysis techniques used by phishing infrastructure to evade automated scanning.

![URLScan](screenshots/urlscan.png)

---

## Why Quishing Bypasses Security Tools

Traditional email security scans URLs in email body and attachments. A QR code is an image and the malicious URL is hidden inside it. It cannot be extracted or scanned automatically. The victim's personal mobile device, which has no corporate security controls, performs the scan and opens the phishing page outside the corporate network perimeter.

---

## MITRE ATT&CK

| Technique | ID | Description |
|---|---|---|
| Phishing: Spearphishing Link | T1566.002 | Malicious QR code in PDF redirecting to phishing URL |
| User Execution: Malicious Link | T1204.001 | Victim scans QR code and opens credential harvesting page |
| Credentials from Web Browser | T1555.003 | Credential harvesting via fake M365 login page |

---

## Hunting Query — Microsoft Sentinel KQL

```kql
EmailAttachmentInfo
| where FileType == "pdf"
| where Subject contains "QR" or Subject contains "scan"
| join EmailEvents on NetworkMessageId
| where ThreatTypes has "Phish"
```

This query identifies emails with PDF attachments where the subject references QR codes or scanning, flagged as phishing by Microsoft Defender. Note: query not executed in live environment — documented for detection engineering reference.

---

## IOCs

| Type | Value |
|---|---|
| Sender Domain | supplier-invoices[.]net |
| Sending IP | 185.220.101.47 |
| Phishing Domain | m365-login[.]com |
| Hosting IP | 13.53.140.86 |
| Infrastructure | AWS Route53 |
| Attachment | Invoice_INV-2026-09-14.pdf |
| File Hash (synthetic) | d4f8a2c1b9e3f7a0c2d5e8b1f4a7c0d3e6b9f2a5 |
| Domain Registered | 2021-05-14 |
| VirusTotal Detections | 4/90 — Phishing and Fraud |

---

## Recommended Actions

**Block:**
- IP 185.220.101.47 and 13.53.140.86 on email gateway and firewall
- Domains supplier-invoices[.]net and m365-login[.]com
- Hash of malicious PDF attachment

**Detect:**
- Deploy hunting query in Microsoft Sentinel
- Enable QR code URL extraction in email security gateway
- Alert on PDF attachments with embedded QR codes from external senders

**User Awareness:**
- Notify all staff about quishing technique
- Advise never to scan QR codes received via email without verification
- Report suspicious emails to SOC immediately

---

*Note: Synthetic .eml sample used for demonstration purposes. IOCs based on real threat intelligence from VirusTotal.*

---

**Status:** Contained. IOCs blocked. User awareness initiated.