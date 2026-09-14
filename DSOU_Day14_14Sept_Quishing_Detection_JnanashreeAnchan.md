DSOU_Day14_14Sept_Quishing_Detection_JnanashreeAnchan

Executive Summary

A QR code phishing (quishing) email was identified targeting company Microsoft 365 credentials. The attacker embedded a malicious QR code inside a PDF attachment to bypass URL scanning tools, redirecting victims to a credential harvesting page.

Email Header Analysis

Field	Value
From	accounts@supplier-invoices[.]net
To	john.smith@company.com
Subject	ACTION REQUIRED: Invoice #INV-2026-09-14 - Scan to Verify
Date	14 Sep 2026 08:42:31 UTC
Sending IP	185.220.101.47
SPF	FAIL
DKIM	FAIL
DMARC	FAIL (p=reject)

All three email authentication checks failed, confirming a spoofed sender domain.

QR Code Analysis

The PDF attachment contained a QR code redirecting to:

hxxps://m365-login-verify[.]com/auth?session=INV2026-09-14

The domain mimics a legitimate Microsoft 365 login page. It is designed to harvest credentials from victims who scan with their mobile device, bypassing endpoint email security that cannot parse QR codes embedded in images.

VirusTotal Result: [screenshot attached]
URLScan.io Result: [screenshot attached]

Why Quishing Bypasses Security Tools

Traditional email security scans URLs in email body and attachments. A QR code is an image and the malicious URL is hidden inside it. It cannot be extracted or scanned automatically. The victim's personal mobile device, which has no corporate security controls, performs the scan and opens the phishing page outside the corporate network perimeter.

MITRE ATT&CK

Technique	ID	Description
Phishing: Spearphishing Attachment	T1566.001	PDF attachment containing malicious QR code
User Execution: Malicious File	T1204.002	Victim scans QR code and opens phishing URL
Credentials from Web Browser	T1555.003	Credential harvesting via fake M365 login page

Hunting Query — Microsoft Sentinel KQL

kql
EmailAttachmentInfo
| where FileType == "pdf"
| where Subject contains "QR" or Subject contains "scan"
| join EmailEvents on NetworkMessageId
| where ThreatTypes has "Phish"

This query identifies emails with PDF attachments where the subject references QR codes or scanning, flagged as phishing by Microsoft Defender. Useful for hunting similar quishing campaigns across the organisation.

IOCs

Type	Value
Sender Domain	supplier-invoices[.]net
Sending IP	185.220.101.47
Phishing URL	hxxps://m365-login-verify[.]com/auth?session=INV2026-09-14
Phishing Domain	m365-login-verify[.]com
Attachment	Invoice_INV-2026-09-14.pdf
File Hash (synthetic)	d4f8a2c1b9e3f7a0c2d5e8b1f4a7c0d3e6b9f2a5

Recommended Actions

Block:

IP 185.220.101.47 on email gateway and firewall
Domain supplier-invoices[.]net and m365-login-verify[.]com
Hash of malicious PDF attachment

Detect:

Deploy hunting query in Sentinel to identify similar emails
Enable QR code scanning capability in email security gateway
Alert on emails with PDF attachments containing embedded URLs

User Awareness:

Notify all staff about quishing technique
Advise never to scan QR codes received via email without verification
Report suspicious QR code emails to SOC immediately

Status: Contained. IOCs blocked. User awareness initiated.
