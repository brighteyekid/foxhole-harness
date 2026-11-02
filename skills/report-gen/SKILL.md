---
name: report-gen
description: "Professional pentest report generation: full engagement reports, single finding documents, executive summaries, evidence formatting, CVSS scoring, remediation tracking. Use when documenting findings or generating reports."
---

# SKILL — report-gen

## Purpose
Generate professional, evidence-backed penetration test reports from raw findings. Covers full engagement reports, single finding documents, executive summaries, and remediation dossiers. Every claim in the report has an evidence reference. Every remediation is specific and actionable.

## When to load
- Engagement is complete and findings need to be documented
- Asked to generate, write, or format a pentest report
- Need to produce a finding document for a single vulnerability
- Need to format evidence, request/response pairs, or extraction receipts
- Need an executive summary or remediation tracker

---

## Severity rating system

### CVSS v3.1 based
| Severity | CVSS Range | Color | SLA |
|---|---|---|---|
| Critical | 9.0 – 10.0 | Red | Fix immediately / within 24h |
| High | 7.0 – 8.9 | Orange | Fix within 7 days |
| Medium | 4.0 – 6.9 | Yellow | Fix within 30 days |
| Low | 0.1 – 3.9 | Blue | Fix within 90 days |
| Informational | N/A | Grey | Fix at discretion |

### CVSS vector shorthand
```
AV: Network(N) / Adjacent(A) / Local(L) / Physical(P)
AC: Low(L) / High(H)
PR: None(N) / Low(L) / High(H)
UI: None(N) / Required(R)
S:  Unchanged(U) / Changed(C)
C:  None(N) / Low(L) / High(H)
I:  None(N) / Low(L) / High(H)
A:  None(N) / Low(L) / High(H)

Example: AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H = 10.0 (Critical)
```

---

## Report structure

### Full engagement report template

---

```markdown
# Penetration Test Report

**Target:**         <scope — IPs, domains, application>
**Report date:**    <date>
**Test period:**    <start> to <end>
**Conducted by:**   pi / fox
**Classification:** CONFIDENTIAL — FOR AUTHORIZED RECIPIENTS ONLY
**Report version:** 1.0

---

## Table of Contents
1. Executive Summary
2. Scope and Methodology
3. Attack Chain Narrative
4. Findings
5. Evidence Index
6. Remediation Tracker
7. Appendix

---

## 1. Executive Summary

### Engagement overview
<2-3 sentences: what was tested, why, and over what period>

### Overall risk rating
**[CRITICAL / HIGH / MEDIUM / LOW]**
<One paragraph: the most severe finding and its business impact in plain language. No technical jargon. Explain what an attacker could do, not what the vulnerability is called.>

### Key findings summary
| # | Title | Severity | Status |
|---|---|---|---|
| F-01 | <title> | Critical | Open |
| F-02 | <title> | High | Open |

### Top remediation priorities
1. **[Immediate]** <action> — prevents <business impact>
2. **[This week]** <action> — prevents <business impact>
3. **[This month]** <action> — prevents <business impact>

### Positive observations
<What the target does well — this builds trust and shows balance>

---

## 2. Scope and Methodology

### In-scope targets
| Target | Type | Notes |
|---|---|---|
| <IP/domain> | Web app / API / network | <any constraints> |

### Out-of-scope
- <explicitly excluded targets>

### Testing approach
- Black box / grey box / white box
- External / internal / both

### Phases executed
| Phase | Description | Tools used |
|---|---|---|
| Passive recon | DNS, OSINT, CT logs | subfinder, dnsx, crt.sh, wayback |
| Active recon | Port scan, fingerprinting | nmap, httpx, naabu, whatweb |
| Content discovery | Dir/file brute force | ffuf, katana |
| Vulnerability research | CVE research, PoC testing | NVD, ExploitDB, nuclei |
| Exploitation | Manual exploitation | Custom scripts, Metasploit |
| Post-exploitation | Privilege escalation, data access | Manual |

---

## 3. Attack Chain Narrative

<Write this as a story — how an attacker progressed from zero access to the highest impact point. This is the most important section for executives.>

**Starting point:** External attacker with no credentials, internet access only.

**Step 1:** Passive reconnaissance revealed subdomain `dev.<target>` via Certificate Transparency logs. This host was not listed in the scope document but resolves to the same IP range.

**Step 2:** Active scanning of `dev.<target>` identified an Apache Tomcat 9.0.30 installation on port 8080, running without authentication on the manager interface.

**Step 3:** Default credentials `tomcat:tomcat` were accepted on the Tomcat Manager application, granting authenticated access to the deployment interface.

**Step 4:** A malicious WAR file containing a JSP web shell was deployed via the Manager interface. This provided command execution as the `tomcat` service account on the underlying Linux server.

**Step 5:** Enumeration of the server revealed a world-readable `/opt/app/config.properties` file containing plaintext database credentials for the production MySQL database.

**Step 6:** The database credentials were used to authenticate to the MySQL instance directly. The `users` table was extracted, containing 15,000 user records including bcrypt password hashes and email addresses.

**Outcome:** Full unauthenticated compromise of the production database from an internet-accessible forgotten development server, resulting in access to all user data.

```mermaid
graph LR
    A[Internet attacker] --> B[CT log: dev.target.com]
    B --> C[Tomcat 9.0.30 on :8080]
    C --> D[Default creds: tomcat:tomcat]
    D --> E[WAR file deployment]
    E --> F[RCE as tomcat user]
    F --> G[config.properties - DB creds]
    G --> H[MySQL - 15k user records]
```

---

## 4. Findings

<!-- Repeat this block for each finding -->

---

### F-01: <Finding Title>

**Severity:** Critical
**CVSS Score:** 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
**CWE:** CWE-798 (Use of Hard-coded Credentials) / CWE-<N>
**CVE:** CVE-YYYY-NNNNN (if applicable)
**Affected component:** `https://dev.target.com:8080/manager/html`
**Evidence IDs:** E-01, E-02
**Status:** Open

#### Description
<What the vulnerability is, why it exists, and where it is located. Explain for a developer who will fix it.>

Apache Tomcat's manager web application was accessible from the internet on `dev.target.com:8080` and protected only by default credentials (`tomcat:tomcat`). The manager application allows authenticated users to deploy arbitrary Java web application archives (WAR files), which are executed by the Tomcat runtime. An attacker who authenticates to this interface can deploy a malicious WAR file and achieve remote code execution on the underlying server.

#### Evidence

**Request — authentication with default credentials:**
```http
GET /manager/html HTTP/1.1
Host: dev.target.com:8080
Authorization: Basic dG9tY2F0OnRvbWNhdA==

HTTP/1.1 200 OK
Server: Apache-Coyote/1.1
Content-Type: text/html;charset=utf-8

<html><head><title>Tomcat Web Application Manager</title>
```

**Command execution proof:**
```
$ curl "http://dev.target.com:8080/shell/shell.jsp?cmd=id"

uid=998(tomcat) gid=998(tomcat) groups=998(tomcat)
```

**Hostname and network confirmation:**
```
$ curl "http://dev.target.com:8080/shell/shell.jsp?cmd=hostname%20-I"

10.0.1.45 172.16.0.8
```

#### Impact
An unauthenticated remote attacker can execute arbitrary commands on the server as the `tomcat` service account. This enables:
- Full read/write access to all files accessible by the tomcat user
- Access to application source code, configuration files, and database credentials
- Lateral movement to other internal systems via the `10.0.1.0/24` network
- Persistent backdoor installation

#### Steps to reproduce
1. Navigate to `http://dev.target.com:8080/manager/html`
2. When prompted for credentials, enter username `tomcat` and password `tomcat`
3. Under "WAR file to deploy", upload a malicious WAR file containing a JSP web shell
4. Click "Deploy" — the application deploys to `/shell/`
5. Access `http://dev.target.com:8080/shell/shell.jsp?cmd=id` to confirm command execution

#### Remediation
1. **Immediately:** Remove or restrict network access to port 8080 on `dev.target.com` — this host should not be internet-accessible
2. **Immediately:** Change all Tomcat manager credentials from defaults
3. **Short-term:** Disable the Tomcat Manager application entirely if not required for production operations — comment out or remove `manager` from `conf/tomcat-users.xml`
4. **Short-term:** Restrict manager access by IP in `conf/Catalina/localhost/manager.xml` using `RemoteAddrValve`
5. **Long-term:** Implement a WAF rule blocking access to `/manager/` from external IPs

#### References
- https://tomcat.apache.org/tomcat-9.0-doc/manager-howto.html
- https://owasp.org/www-project-web-security-testing-guide/
- CWE-798: https://cwe.mitre.org/data/definitions/798.html

---

<!-- Repeat F-02, F-03, etc. -->

---

## 5. Evidence Index

| ID | Type | Description | Location | SHA256 |
|---|---|---|---|---|
| E-01 | HTTP request/response | Tomcat auth with default creds | loot/e-01-tomcat-auth.txt | <hash> |
| E-02 | HTTP request/response | RCE proof — id command output | loot/e-02-rce-proof.txt | <hash> |
| E-03 | File | /opt/app/config.properties | loot/e-03-config.txt | <hash> |
| E-04 | Database dump | users table — 15,000 records | loot/data/users-dump.sql | <hash> |

---

## 6. Remediation Tracker

| ID | Title | Severity | Recommended fix | Effort | Priority | Status |
|---|---|---|---|---|---|---|
| F-01 | Tomcat default creds + internet exposure | Critical | Restrict network access + change creds | Low | Immediate | Open |
| F-02 | <title> | High | <fix> | Medium | This week | Open |

---

## 7. Appendix

### A — Tools used
| Tool | Version | Purpose |
|---|---|---|
| nmap | 7.94 | Port scanning and service fingerprinting |
| httpx | 1.3.7 | HTTP probing and tech detection |
| ffuf | 2.1.0 | Content discovery |
| nuclei | 3.1.0 | Automated vulnerability scanning |
| Custom JSP web shell | N/A | Command execution proof |

### B — Methodology reference
OWASP Testing Guide v4.2: https://owasp.org/www-project-web-security-testing-guide/

### C — Glossary
- **RCE:** Remote Code Execution — ability to run arbitrary commands on a remote system
- **WAR:** Web Application Archive — Java deployment package
- **CVE:** Common Vulnerabilities and Exposures — standardized vulnerability identifier
```

---

## Single finding document template

For documenting individual findings as they are confirmed during an engagement:

```markdown
# FINDING: <title>

Date confirmed: <date>
Tester: pi / fox
Status: confirmed

## Summary
<One sentence: what it is and where it is>

## Severity
**<Critical/High/Medium/Low/Informational>**
CVSS: <score> (<vector>)

## Affected component
<exact URL, IP, parameter, function>

## Evidence
```
<exact request>

<exact response>
```

## Impact
<what an attacker can do>

## Remediation
<specific fix>

## References
<CVE, advisory, CWE>
```

---

## Evidence formatting standards

### HTTP request/response
```
=== REQUEST ===
POST /api/login HTTP/1.1
Host: target.com
Content-Type: application/json
Content-Length: 42

{"username":"admin'--","password":"anything"}

=== RESPONSE ===
HTTP/1.1 200 OK
Content-Type: application/json

{"token":"eyJhbGciOiJIUzI1NiJ9...","role":"admin"}
```

### Command execution proof
```
=== COMMAND ===
curl "http://target.com/shell.php?cmd=id%20%26%26%20hostname%20%26%26%20whoami"

=== OUTPUT ===
uid=33(www-data) gid=33(www-data) groups=33(www-data)
target-prod-01
www-data
```

### File extraction receipt
```
=== FILE EXTRACTED ===
Source:   /opt/app/.env
Method:   LFI via ?file=../../../../opt/app/.env
Size:     847 bytes
SHA256:   a1b2c3d4...
Stored:   loot/data/env-file.txt

=== CONTENTS ===
DB_HOST=10.0.1.100
DB_USER=appuser
DB_PASS=Sup3rS3cr3t!
DB_NAME=production
AWS_KEY=AKIA...
AWS_SECRET=...
```

---

## Output format
- Primary: `report.md` in engagement workspace root
- All evidence files in `loot/` with SHA256 hashes
- Raw scan output in `recon/` subdirectories
- Convert to PDF: `pandoc report.md -o report.pdf --pdf-engine=wkhtmltopdf`
- Convert to DOCX: `pandoc report.md -o report.docx`

---

## Rules
- Every finding needs at minimum one evidence reference — no undocumented claims
- Distinguish observed from inferred — never state impact that wasn't demonstrated
- Remediation must be specific: not "sanitize input" but "use PDO prepared statements: `$stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?'); $stmt->execute([$id]);`"
- Executive summary is for non-technical readers — no CVE IDs, no technical jargon
- Technical findings are for developers — include exact file, line, and fix
- Never include raw secrets or full key material in the report — use redacted references pointing to loot path
- Credentials go in `loot/credentials/` — report body shows only `[REDACTED — see loot/credentials/db-creds.txt]`
- All evidence files should have SHA256 hashes recorded for integrity