# GrayOS – Day 12 Lab PoC
Operation Cluster Sweep: Kubernetes Security Deep-Dive

**Analyst:** Jnanashree Anchan | **Date:** 26 September 2026

---

This lab audits a Kubernetes cluster and its container images using five tools: kube-hunter, kube-bench, Trivy, Syft and Grype. Findings from cluster scanning, CIS benchmarking, image vulnerability scanning and SBOM analysis are consolidated into reports, documented with remediation, and packaged as a hashed evidence archive.

---

## Key Concepts

| Term / Concept | Description |
|---|---|
| kube-hunter | Kubernetes penetration testing tool that finds weaknesses in a cluster through active and passive scanning |
| kube-bench | Checks a cluster's configuration against the CIS Kubernetes Benchmark |
| Trivy | Vulnerability scanner for container images, filesystems and Kubernetes manifests |
| Syft | Generates a Software Bill of Materials (SBOM) listing every component in an image or filesystem |
| Grype | Vulnerability scanner that reads an SBOM and matches its packages against vulnerability databases |
| CIS Benchmark | Center for Internet Security guidelines for secure Kubernetes cluster configuration |
| SBOM | Software Bill of Materials: a full list of components in an artifact, used to track vulnerabilities |
| Pod Security Admission | Kubernetes admission controller that enforces Pod Security Standards, replacing Pod Security Policies |

---

# Phase 1
Environment Setup: kube-hunter, kube-bench, Trivy, Syft, Grype

**Command:** `sudo apt-get update`

<img src="screenshots/phase1-01-apt-update.png" alt="apt-get update" width="550">

**Command:** `sudo apt-get install python3-pip -y`

<img src="screenshots/phase1-02-install-pip.png" alt="Install python3-pip" width="550">

**Command:** `pip3 install kube-hunter --break-system-packages`

<img src="screenshots/phase1-03-install-kube-hunter.png" alt="Install kube-hunter" width="600">

**Command:** `kube-hunter --help`

<img src="screenshots/phase1-04-kube-hunter-help.png" alt="kube-hunter help" width="700">

**Command:** `curl -L .../kube-bench_0.9.3_linux_amd64.deb -o kube-bench.deb`

<img src="screenshots/phase1-05-download-kube-bench.png" alt="Download kube-bench" width="700">

**Command:** `sudo dpkg -i kube-bench.deb` and `kube-bench version`

<img src="screenshots/phase1-06-install-kube-bench-version.png" alt="Install kube-bench and version" width="600">

**Command:** `sudo apt-get install trivy -y` and `trivy --version`

<img src="screenshots/phase1-07-install-trivy-version.png" alt="Install Trivy and version" width="550">

**Command:** `curl -sSfL .../syft/install.sh | sudo sh` and `syft version`

<img src="screenshots/phase1-08-install-syft-version.png" alt="Install Syft and version" width="600">

**Command:** `curl -sSfL .../grype/install.sh | sudo sh` and `grype version`

<img src="screenshots/phase1-09-install-grype-version.png" alt="Install Grype and version" width="600">

All five tools are installed and verified: kube-hunter 0.6.8, kube-bench 0.9.3, Trivy 0.52.2, Syft 1.12.0 and Grype 0.80.0. Trivy shows its vulnerability database dated 22 August 2026, which matters because the scan is only as current as the last database update.

---

# Phase 2
Scanning and Detection

**Command:** `kube-hunter --remote 192.168.1.100`

<img src="screenshots/phase2-01-kube-hunter-remote.png" alt="kube-hunter remote scan" width="600">

**Command:** `kube-hunter --pod --active`

<img src="screenshots/phase2-02-kube-hunter-pod-active.png" alt="kube-hunter pod active scan" width="600">

The remote scan found the Kubelet API exposed on port 10250 (Medium), anonymous API access allowed (Low), and etcd reachable from the network (High). The internal pod scan, running in active mode, found a Dashboard exposed with default credentials (High), Pod Security Policies disabled (Medium), and secrets not encrypted at rest (Medium). Exposed etcd and a default-credential Dashboard are the most serious, since either can hand over the whole cluster.

**Command:** `kube-bench run --json > kube-bench-report.json`

<img src="screenshots/phase2-03-kube-bench-run.png" alt="kube-bench run" width="600">

**Command:** `trivy image --format json --output trivy-nginx-report.json nginx:latest`

<img src="screenshots/phase2-04-trivy-image.png" alt="Trivy image scan" width="600">

**Command:** `syft nginx:latest -o json > sbom-nginx.json`

<img src="screenshots/phase2-05-syft-sbom.png" alt="Syft SBOM generation" width="550">

**Command:** `grype sbom:sbom-nginx.json -o json > grype-report.json`

<img src="screenshots/phase2-06-grype-scan.png" alt="Grype SBOM scan" width="550">

kube-bench runs the CIS Benchmark and saves the results as JSON. Trivy scans the nginx:latest image directly for CVEs. Syft then builds an SBOM of the same image, and Grype scans that SBOM. The Syft plus Grype pair separates the two jobs: Syft records what is in the image, and Grype decides what in that list is vulnerable. The SBOM can be re-scanned later without rebuilding the image, so new CVEs against old images are caught.


---

# Phase 3
Report Generation

**Command:** `cat > graysentinel-k8s-audit.sh <<EOF`

<img src="screenshots/phase3-01-audit-script.png" alt="Audit script content" width="700">

**Command:** `chmod +x graysentinel-k8s-audit.sh`

<img src="screenshots/phase3-02-chmod.png" alt="Make script executable" width="400">

**Command:** `./graysentinel-k8s-audit.sh`

<img src="screenshots/phase3-03-run-audit.png" alt="Run audit script" width="600">

**Command:** `python3 graysentinel_k8s_report.py`

<img src="screenshots/phase3-04-html-report.png" alt="Generate HTML report" width="600">

The audit script wraps all five tools into one run and writes every report into a single dated directory. The Python script then parses the kube-hunter, kube-bench, Trivy and Grype outputs into one consolidated HTML report. This turns four separate JSON files into a single view a reviewer can read.

---

# Phase 4
PoC Summary and Remediation

**Command:** `cat > k8s_misconfigurations.md <<EOF`

<img src="screenshots/phase4-01-misconfigurations.png" alt="Misconfigurations table" width="700">

**Command:** `cat > achievement_checklist.md <<EOF`

<img src="screenshots/phase4-02-checklist.png" alt="Achievement checklist" width="700">

**Command:** `ls -la graysentinel-k8s-audit-*`

<img src="screenshots/phase4-03-ls-audit-dir.png" alt="List audit directory" width="600">

**Command:** `echo "Rank: Cyber Commando (K8s)"`

<img src="screenshots/phase4-04-rank.png" alt="Rank promotion" width="400">

The nine findings and their fixes:

- **Critical:** API server anonymous auth (`--anonymous-auth=false`), Kubelet API exposed (restrict port 10250), etcd unencrypted and exposed (enable TLS, restrict network), Dashboard exposed with default credentials (remove or secure)
- **High:** container running as root (use a non-root user), image with critical CVEs (update the base image), RBAC overly permissive (least privilege), Pod Security Policies disabled (enable Pod Security Admission)
- **Medium:** secrets not encrypted (enable encryption at rest)

---

# Phase 5
Final Submission: Package and Submit

**Command:** `cat > final_submission.md <<EOF`

<img src="screenshots/phase5-01-final-submission.png" alt="Final submission document" width="700">

**Command:** `tar -czvf k8s_audit_complete.tar.gz graysentinel-k8s-audit-*`

<img src="screenshots/phase5-02-tar-archive.png" alt="Create evidence archive" width="600">

**Command:** `sha256sum k8s_audit_complete.tar.gz`

<img src="screenshots/phase5-03-sha256.png" alt="SHA-256 hash" width="700">

**Command:** `echo "Day 12 K8s Audit complete." | mail -s "Day 12 Submission" marcus@graysentinel.com`

<img src="screenshots/phase5-04-mail-submission.png" alt="Mail submission" width="400">

All six report files are packed into one archive. The SHA-256 hash proves the package has not changed since it was created, and the submission was sent to Marcus.

---

# Summary

| Phase | Action | Tool | Outcome |
|---|---|---|---|
| 1 | Installed and verified Kubernetes security tools | pip, dpkg, apt, curl | kube-hunter, kube-bench, Trivy, Syft, Grype ready |
| 2 | Scanned cluster and nginx image | kube-hunter, kube-bench, Trivy, Syft, Grype | Exposed etcd, default-cred Dashboard, image CVEs, unencrypted secrets |
| 3 | Automated the audit and built a unified report | Bash, Python | One dated directory and a consolidated HTML report |
| 4 | Documented findings and remediation | cat, ls | 9 findings (4 Critical, 4 High, 1 Medium) with a fix for each |
| 5 | Packaged and submitted evidence | tar, sha256sum, mail | Hashed archive submitted to Marcus |

The lab covers two layers of Kubernetes security: the cluster itself (kube-hunter and kube-bench against exposed APIs, etcd and CIS settings) and the images that run on it (Trivy, Syft and Grype against CVEs in packages). The Syft-then-Grype flow is the key idea: build the SBOM once, then scan it whenever the vulnerability database updates, so old images are re-checked against new CVEs without a rebuild.