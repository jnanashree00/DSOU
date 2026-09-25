# GrayOS – Day 11 Lab PoC
Operation Cloud Sweep: AWS Misconfiguration Detection and Remediation

**Analyst:** Jnanashree Anchan | **Date:** 25 September 2026

---

This lab audits a GraySentinel AWS account for misconfigurations using AWS CLI, Pacu, ScoutSuite and CloudSploit. Findings are consolidated into reports, fixed with a remediation script, and packaged as a hashed evidence archive for submission.

---

## Key Concepts

| Term / Concept | Description |
|---|---|
| AWS CLI | Command-line tool for managing AWS services such as S3, IAM, EC2 and CloudTrail |
| Pacu | AWS exploitation framework used to enumerate IAM, S3 and EC2 and find misconfigurations |
| ScoutSuite | Multi-cloud auditing tool that produces an HTML report with findings and risk levels per service |
| CloudSploit | Node.js cloud scanner that checks S3, IAM policies, EC2 security groups, RDS encryption and more |
| S3 Public Access | Buckets should not be public. Block Public Access settings and bucket policies restrict access |
| Security Groups | EC2 security groups should not allow 0.0.0.0/0 for SSH or RDP. Access must be limited to known IP ranges |
| CloudTrail | AWS audit logging of API activity. If disabled, there is no record of who did what in the account |
| Remediation Script | A script that applies the fixes for detected misconfigurations in a repeatable way |

---

# Phase 1
Environment Setup: AWS CLI, Pacu, ScoutSuite, CloudSploit

**Command:** `sudo apt-get update`

<img src="screenshots/phase1-01-apt-update.png" alt="apt-get update" width="550">

**Command:** `sudo apt-get install awscli -y`

<img src="screenshots/phase1-02-install-awscli.png" alt="Install AWS CLI" width="550">

**Command:** `aws --version`

<img src="screenshots/phase1-03-aws-version.png" alt="AWS CLI version" width="400">

**Command:** `aws configure --profile graysentinel`

<img src="screenshots/phase1-04-aws-configure.png" alt="AWS configure profile" width="550">

**Command:** `sudo apt install pipx -y`

<img src="screenshots/phase1-05-install-pipx.png" alt="Install pipx" width="550">

**Command:** `pipx install git+https://github.com/RhinoSecurityLabs/pacu.git`

<img src="screenshots/phase1-06-install-pacu.png" alt="Install Pacu" width="550">

**Command:** `pacu --help`

<img src="screenshots/phase1-07-pacu-help.png" alt="Pacu help" width="400">

**Command:** `sudo apt install scoutsuite -y`

<img src="screenshots/phase1-08-install-scoutsuite.png" alt="Install ScoutSuite" width="550">

**Command:** `git clone https://github.com/nccgroup/ScoutSuite.git`

<img src="screenshots/phase1-09-clone-scoutsuite.png" alt="Clone ScoutSuite" width="550">

**Command:** `sudo apt install nodejs npm -y`

<img src="screenshots/phase1-10-install-nodejs.png" alt="Install Node.js and npm" width="550">

**Command:** `git clone https://github.com/aquasecurity/cloudsploit.git`

<img src="screenshots/phase1-11-clone-cloudsploit.png" alt="Clone CloudSploit" width="550">

**Command:** `cd cloudsploit && npm install`

<img src="screenshots/phase1-12-npm-install.png" alt="CloudSploit npm install" width="400">

**Command:** `mkdir -p ~/cloud_audit`

<img src="screenshots/phase1-13-mkdir.png" alt="Create audit directory" width="400">

All four tools are installed and ready. AWS CLI 2.15.0 is configured with a dedicated `graysentinel` profile (region us-east-1, JSON output), so every scan runs against the same account. Pacu 1.2.0 is installed in an isolated pipx environment, ScoutSuite 5.14.0 is available, and CloudSploit dependencies installed with 0 vulnerabilities.

---

# Phase 2
Scanning and Detection: S3, Pacu, ScoutSuite, CloudSploit

**Command:** `aws s3api get-public-access-block --bucket your-bucket-name`

<img src="screenshots/phase2-01-public-access-block.png" alt="S3 public access block" width="700">

**Command:** `aws s3api get-bucket-policy-status --bucket your-bucket-name`

<img src="screenshots/phase2-02-bucket-policy-status.png" alt="S3 bucket policy status" width="700">

**Command:** `aws s3 ls --profile graysentinel`

<img src="screenshots/phase2-03-s3-ls.png" alt="List S3 buckets" width="550">

**Command:** `aws s3api get-bucket-acl --bucket your-bucket-name`

<img src="screenshots/phase2-04-bucket-acl.png" alt="S3 bucket ACL" width="700">

The bucket has `BlockPublicAcls` and `IgnorePublicAcls` set to true, but `BlockPublicPolicy` and `RestrictPublicBuckets` are false. This means a bucket policy can still make the bucket public. `aws s3 ls` lists 5 buckets: logs, data, backup, public-assets and internal.

**Note:** `get-bucket-policy-status` and `get-bucket-acl` returned the same output as `get-public-access-block`. In a real environment these return different data (an `IsPublic` flag and the ACL grants). This looks like a simulation limitation.

**Command:** `pacu`

<img src="screenshots/phase2-05-pacu-launch.png" alt="Launch Pacu" width="400">

**Command:** `new_session graysentinel_audit`

<img src="screenshots/phase2-06-pacu-session.png" alt="Pacu new session" width="400">

**Command:** `run iam__enum_users`

<img src="screenshots/phase2-07-iam-enum-users.png" alt="Pacu IAM user enumeration" width="550">

**Command:** `run s3__enum_buckets`

<img src="screenshots/phase2-08-s3-enum-buckets.png" alt="Pacu S3 bucket enumeration" width="550">

**Command:** `run aws__enum_all`

<img src="screenshots/phase2-09-enum-all.png" alt="Pacu full enumeration" width="550">

Pacu found 3 IAM users (cloud-admin, graysentinel-audit, s3-readonly) and flagged 2 public buckets: `graysentinel-logs` and `graysentinel-public-assets`. The full enumeration reported 6 EC2 instances (2 with public IPs), 1 unencrypted RDS database, CloudTrail disabled, and 12 misconfigurations in total.

**Note:** Pacu enumerated 4 buckets, while `aws s3 ls` listed 5. `graysentinel-internal` does not appear in the Pacu results, so its access status is unverified and should be checked manually.

**Command:** `scout aws --profile graysentinel --services s3 iam ec2 rds`

<img src="screenshots/phase2-10-scoutsuite-services.png" alt="ScoutSuite targeted scan" width="550">

**Command:** `scout aws --profile graysentinel`

<img src="screenshots/phase2-11-scoutsuite-full.png" alt="ScoutSuite full scan" width="550">

**Command:** `node index.js --cloud aws --profile graysentinel`

<img src="screenshots/phase2-12-cloudsploit.png" alt="CloudSploit scan" width="700">

ScoutSuite's full scan covered 23 services and reported 12 high, 8 medium and 5 low findings. CloudSploit ran 45 plugins and failed 5 checks: public S3 access, an overly permissive IAM policy, a security group open to 0.0.0.0/0, RDS encryption disabled, and CloudTrail disabled. All three tools agree on the same core issues.

---

# Phase 3
Report Generation: HTML, JSON, CSV

**Command:** `ls ~/ScoutSuite-report/`

<img src="screenshots/phase3-01-ls-scoutsuite-report.png" alt="ScoutSuite report files" width="550">

**Command:** `firefox ~/ScoutSuite-report/scoutsuite-report.html`

<img src="screenshots/phase3-02-firefox-report.png" alt="Open ScoutSuite HTML report" width="400">

**Command:** `python3 graysentinel_cloud_report.py findings.json json`

<img src="screenshots/phase3-03-report-json.png" alt="Generate JSON report" width="550">

**Command:** `python3 graysentinel_cloud_report.py findings.json csv`

<img src="screenshots/phase3-04-report-csv.png" alt="Generate CSV report" width="550">

**Command:** `cat > graysentinel_report.json <<EOF`

<img src="screenshots/phase3-05-report-json-content.png" alt="JSON report content" width="700">

**Command:** `cat > remediation_script.sh <<EOF`

<img src="screenshots/phase3-06-remediation-script.png" alt="Remediation script" width="700">

**Command:** `chmod +x remediation_script.sh`

<img src="screenshots/phase3-07-chmod.png" alt="Make script executable" width="400">

**Command:** `./remediation_script.sh`

<img src="screenshots/phase3-08-run-remediation.png" alt="Run remediation script" width="550">

The raw scan output from three tools is turned into usable formats: the HTML report for visual review, JSON for tools and automation, and CSV for spreadsheets or ticket import. The results are consolidated into 7 unique findings, 3 of them Critical.

**Note:** the script reports "7 misconfigurations fixed", but only the two S3 fixes (Block Public Access and AES256 encryption) contain real `aws` commands. The EC2, CloudTrail, IAM, RDS and root MFA steps are `echo` lines only. In a real audit, those 5 fixes would still be open and must be applied and verified separately.

---

# Phase 4
PoC Summary and Remediation: Checklist and Fixes

**Command:** `cat > findings_summary.md <<EOF`

<img src="screenshots/phase4-01-findings-summary.png" alt="Findings summary" width="700">

**Command:** `cat > achievement_checklist.md <<EOF`

<img src="screenshots/phase4-02-achievement-checklist.png" alt="Achievement checklist" width="700">

**Command:** `tree graysentinel_cloud_audit/`

<img src="screenshots/phase4-03-tree.png" alt="Audit directory tree" width="700">

**Command:** `echo "Rank: Cyber Commando"`

<img src="screenshots/phase4-04-rank.png" alt="Rank promotion" width="400">

The 7 findings and their fixes:

- **Critical:** Public S3 bucket (block public access), EC2 security group open to 0.0.0.0/0 (restrict CIDR), root account MFA disabled (enable MFA)
- **High:** S3 without server-side encryption (enable AES256), overly permissive IAM policy (least privilege), unencrypted RDS database (enable encryption)
- **Medium:** CloudTrail disabled (enable CloudTrail)

---

# Phase 5
Final Submission: Package and Submit

**Command:** `cat > final_submission.md <<EOF`

<img src="screenshots/phase5-01-final-submission.png" alt="Final submission document" width="700">

**Command:** `tar -czvf cloud_audit_complete.tar.gz graysentinel_cloud_audit/`

<img src="screenshots/phase5-02-tar-archive.png" alt="Create evidence archive" width="700">

**Command:** `sha256sum cloud_audit_complete.tar.gz`

<img src="screenshots/phase5-03-sha256.png" alt="SHA-256 hash" width="400">

**Command:** `echo "Day 11 Cloud Audit complete." | mail -s "Day 11 Submission" marcus@graysentinel.com`

<img src="screenshots/phase5-04-mail-submission.png" alt="Mail submission" width="400">

All deliverables (ScoutSuite report, JSON and CSV reports, findings summary, checklist and remediation script) are packed into one archive. The SHA-256 hash proves the package has not been changed after creation, and the submission was sent to Marcus.

---

# Summary

| Phase | Action | Tool | Outcome |
|---|---|---|---|
| 1 | Installed and configured cloud audit tools | AWS CLI, pipx, apt, npm | AWS CLI, Pacu, ScoutSuite and CloudSploit ready; `graysentinel` profile set |
| 2 | Scanned S3, IAM, EC2, RDS and CloudTrail | AWS CLI, Pacu, ScoutSuite, CloudSploit | 2 public buckets, open security group, unencrypted RDS, CloudTrail disabled |
| 3 | Generated reports and ran remediation | Python, Bash | HTML, JSON and CSV reports; S3 fixes applied, 5 fixes still manual |
| 4 | Documented findings and remediation plan | cat, tree | 7 findings (3 Critical, 3 High, 1 Medium) with a fix for each |
| 5 | Packaged and submitted evidence | tar, sha256sum, mail | Hashed archive submitted to Marcus |

Three different scanners pointed to the same core problems: public S3 data, SSH/RDP open to the internet, no encryption on RDS, no MFA on root, and no CloudTrail logging. The most important lesson is to verify rather than trust tool output. One bucket was missed by Pacu, and the remediation script claimed 7 fixes while only 2 were actually applied.