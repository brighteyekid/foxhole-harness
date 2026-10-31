---
description: "Exhaustive web application recon: passive DNS/OSINT, subdomain enum, port scan, HTTP fingerprinting, content discovery, JS analysis, parameter discovery. Use at start of any web app engagement."
---

# SKILL — web-recon

## Purpose
Exhaustive web application reconnaissance. Produces a complete target profile covering infrastructure, technology stack, attack surface, endpoints, authentication mechanisms, and prioritized vectors — ready for vulnerability research and exploitation phases.

## When to load
- Given a URL or domain to recon
- Starting a web app pentest or bug bounty engagement
- Need to map endpoints, tech stack, or attack surface
- Preparing for exploitation — need complete picture first
- Asked to "look at", "check", "recon", or "map" a web target

---

## Phase 0 — Setup

```bash
# Create workspace
TARGET="target.com"
mkdir -p ~/recon_$(date +%s)_${TARGET}/{recon/{dns,subdomains,ports,http,tech,osint,js},vulns/{confirmed,potential,research},exploits/{working,attempted},loot/{credentials,data,flags}}
cd ~/recon_*_${TARGET}

# Set variables
export TARGET="target.com"
export TARGET_IP=$(dig +short $TARGET | head -1)
echo "Target: $TARGET | IP: $TARGET_IP"
```

---

## Phase 1 — Passive intelligence (zero packets to target)

### DNS enumeration
```bash
# All record types
for type in A AAAA MX NS TXT SOA CNAME SRV CAA DNSKEY; do
  echo "=== $type ===" && dig $TARGET $type +short
done | tee recon/dns/all-records.txt

# Zone transfer attempt against every nameserver
for ns in $(dig $TARGET NS +short); do
  echo "=== Zone transfer attempt: $ns ===" 
  dig axfr $TARGET @$ns
done | tee recon/dns/zone-transfers.txt

# Reverse DNS on target IP range
for i in $(seq 1 254); do
  host ${TARGET_IP%.*}.$i 2>/dev/null | grep -v "not found"
done | tee recon/dns/reverse-dns.txt
```

### Certificate Transparency — subdomain harvest
```bash
# crt.sh
curl -s "https://crt.sh/?q=%25.$TARGET&output=json" \
  | jq -r '.[].name_value' \
  | sed 's/\*\.//g' \
  | sort -u \
  | tee recon/subdomains/crtsh.txt

# Certspotter
curl -s "https://api.certspotter.com/v1/issuances?domain=$TARGET&include_subdomains=true&expand=dns_names" \
  | jq -r '.[].dns_names[]' \
  | sort -u \
  | tee recon/subdomains/certspotter.txt

# Combine
cat recon/subdomains/*.txt | sort -u > recon/subdomains/all-passive.txt
echo "[+] Passive subdomains found: $(wc -l < recon/subdomains/all-passive.txt)"
```

### WHOIS and ASN
```bash
# Domain WHOIS
whois $TARGET | tee recon/osint/whois-domain.txt

# IP WHOIS
whois $TARGET_IP | tee recon/osint/whois-ip.txt

# ASN lookup
curl -s "https://ipinfo.io/$TARGET_IP/json" | tee recon/osint/ipinfo.json
curl -s "https://api.hackertarget.com/aslookup/?q=$TARGET_IP" | tee recon/osint/asn.txt

# Find all IPs in the same ASN
ASN=$(cat recon/osint/ipinfo.json | jq -r '.org' | grep -oP 'AS\d+')
curl -s "https://api.hackertarget.com/aslookup/?q=$ASN" | tee recon/osint/asn-ranges.txt
```

### Web archive
```bash
# Wayback Machine URL harvest
curl -s "https://web.archive.org/cdx/search/cdx?url=*.$TARGET/*&output=text&fl=original&collapse=urlkey&limit=5000" \
  | sort -u | tee recon/osint/wayback-urls.txt

# Extract interesting paths from archive
cat recon/osint/wayback-urls.txt | grep -iE "\.(php|asp|aspx|cfm|jsp|do|action|json|xml|yaml|yml|env|git|bak|sql|conf|config|log|key|pem)" \
  | tee recon/osint/wayback-interesting.txt

# GAU (get all URLs)
gau $TARGET --threads 5 --o recon/osint/gau-urls.txt 2>/dev/null || \
  echo "[!] gau not available — using wayback only"
```

### Google dorks
```
site:$TARGET ext:php
site:$TARGET ext:env OR ext:config OR ext:yml OR ext:sql
site:$TARGET inurl:admin OR inurl:login OR inurl:dashboard
site:$TARGET inurl:api
site:$TARGET "index of /"
site:$TARGET "error" OR "exception" OR "stack trace"
"$TARGET" filetype:pdf OR filetype:xlsx OR filetype:docx
"$TARGET" inurl:"/wp-content/uploads/"
"@$TARGET" email harvesting
"$TARGET" site:pastebin.com OR site:github.com OR site:gitlab.com
```

---

## Phase 2 — Subdomain enumeration (active)

```bash
# subfinder
subfinder -d $TARGET -all -o recon/subdomains/subfinder.txt

# amass passive
amass enum -passive -d $TARGET -o recon/subdomains/amass.txt 2>/dev/null || \
  echo "[!] amass not available"

# DNS wordlist brute force
ffuf -u "https://FUZZ.$TARGET" \
  -w /home/fox/SecLists/Discovery/DNS/subdomains-top1million-110000.txt \
  -mc 200,301,302,307,401,403 \
  -o recon/subdomains/ffuf-dns.json -of json \
  -t 50 2>/dev/null

# Combine all sources
cat recon/subdomains/*.txt recon/subdomains/crtsh.txt recon/subdomains/certspotter.txt \
  | grep -v "^\*" | sort -u > recon/subdomains/all.txt
echo "[+] Total unique subdomains: $(wc -l < recon/subdomains/all.txt)"

# Resolve and probe all
dnsx -l recon/subdomains/all.txt -a -cname -o recon/dns/resolved.txt -silent
httpx -l recon/dns/resolved.txt \
  -title -tech-detect -status-code -content-length -follow-redirects \
  -o recon/http/live-subdomains.txt -silent
echo "[+] Live HTTP services: $(wc -l < recon/http/live-subdomains.txt)"

# Check for subdomain takeover
for sub in $(cat recon/subdomains/all.txt); do
  cname=$(dig +short CNAME $sub)
  if [ ! -z "$cname" ]; then
    # Check if CNAME target resolves
    if ! dig +short $cname | grep -q "[0-9]"; then
      echo "[!] POTENTIAL TAKEOVER: $sub -> $cname" | tee -a recon/vulns/potential/subdomain-takeover.txt
    fi
  fi
done
```

---

## Phase 3 — Port and service discovery

```bash
# Quick web port scan first
naabu -host $TARGET \
  -p 80,443,8080,8443,8888,3000,4000,5000,9090,9443,10000,8000,8001,8008,8800 \
  -o recon/ports/web-ports.txt -silent

# Full TCP scan (background — takes time)
nmap -sV -sC -p- --min-rate 3000 --open -oA recon/ports/full-tcp $TARGET_IP &

# Top 1000 ports quick scan
nmap -sV --open -oA recon/ports/top1000 $TARGET_IP

# Service-specific checks
# SMB
nmap -p 445 --script smb-vuln* $TARGET_IP -oA recon/ports/smb
# SSL/TLS
nmap -p 443,8443 --script ssl-enum-ciphers,ssl-heartbleed,ssl-poodle $TARGET_IP
# HTTP methods
nmap -p 80,443 --script http-methods $TARGET_IP

echo "[+] Open ports: $(grep "open" recon/ports/top1000.nmap | grep -v "filtered" | wc -l)"
```

---

## Phase 4 — HTTP fingerprinting (run per live host)

```bash
URL="https://$TARGET"

# Full header analysis
curl -sI $URL | tee recon/tech/headers.txt
echo ""
echo "=== Security headers check ==="
for header in "Strict-Transport-Security" "Content-Security-Policy" "X-Frame-Options" "X-Content-Type-Options" "X-XSS-Protection" "Referrer-Policy" "Permissions-Policy"; do
  val=$(curl -sI $URL | grep -i "^$header:")
  if [ -z "$val" ]; then
    echo "[MISSING] $header"
  else
    echo "[PRESENT] $val"
  fi
done

# Technology detection
httpx -u $URL -tech-detect -title -status-code -content-length -follow-redirects -verbose 2>&1 \
  | tee recon/tech/httpx.txt

# whatweb
whatweb $URL -v | tee recon/tech/whatweb.txt

# Favicon hash fingerprint
curl -sL $URL/favicon.ico -o /tmp/favicon.ico
md5sum /tmp/favicon.ico
# Look up hash at: https://wiki.owasp.org/index.php/OWASP_favicon_database

# Default disclosure files
echo "=== Checking disclosure files ==="
for path in \
  robots.txt sitemap.xml crossdomain.xml \
  .well-known/security.txt .well-known/change-password \
  manifest.json browserconfig.xml \
  CHANGELOG.txt CHANGELOG.md readme.html readme.txt README.md \
  wp-login.php wp-config.php wp-includes/version.php \
  /joomla.xml /administrator/ \
  /RELEASE-NOTES.txt /VERSION /version.txt \
  /info.php /phpinfo.php /test.php \
  /server-status /server-info \
  /.git/HEAD /.git/config /.svn/entries \
  /.env /.env.local /.env.production /.env.backup \
  /config.php /config.yml /config.json /settings.py \
  /web.config /applicationHost.config \
  /WEB-INF/web.xml /META-INF/MANIFEST.MF \
  /actuator /actuator/env /actuator/health /actuator/mappings \
  /swagger.json /swagger-ui.html /api-docs /openapi.json \
  /.DS_Store /Thumbs.db; do
  code=$(curl -so /dev/null -w "%{http_code}" -L "$URL/$path" --max-time 5)
  if [[ "$code" == "200" ]]; then
    echo "[200] $path" | tee -a recon/http/disclosure-files.txt
  elif [[ "$code" == "403" ]]; then
    echo "[403-BLOCKED] $path" | tee -a recon/http/disclosure-files.txt
  fi
done
```

---

## Phase 5 — Authentication surface mapping

```bash
# Find all login/auth endpoints
for path in \
  /login /signin /sign-in /auth /authenticate \
  /admin /administrator /admin/login /admin/signin \
  /dashboard /panel /control /manage /management \
  /wp-admin /wp-login.php \
  /user/login /account/login /members/login \
  /api/login /api/auth /api/v1/auth /api/v1/login \
  /oauth/authorize /oauth/token \
  /saml/login /sso /sso/login \
  /register /signup /sign-up /create-account \
  /forgot-password /reset-password /password-reset; do
  code=$(curl -so /dev/null -w "%{http_code}" -L "$URL$path" --max-time 5)
  if [[ "$code" != "404" && "$code" != "000" ]]; then
    echo "[$code] $path" | tee -a recon/http/auth-endpoints.txt
  fi
done

# Check for default credentials on discovered services
# (document for testing phase — do not test yet)
cat recon/tech/whatweb.txt recon/tech/httpx.txt | grep -iE "wordpress|joomla|drupal|magento|shopify|jenkins|grafana|kibana|elasticsearch|tomcat|weblogic|jboss|struts" | tee recon/tech/cms-detected.txt
```

---

## Phase 6 — Content discovery

```bash
# Main directory brute force
ffuf -u "$URL/FUZZ" \
  -w /home/fox/SecLists/Discovery/Web-Content/raft-large-directories.txt \
  -mc 200,201,204,301,302,307,401,403 \
  -fc 404 \
  -o recon/http/dirs.json -of json \
  -t 40 -rate 100

# File discovery
ffuf -u "$URL/FUZZ" \
  -w /home/fox/SecLists/Discovery/Web-Content/raft-large-files.txt \
  -mc 200,201,204,301,302 \
  -o recon/http/files.json -of json \
  -t 40 -rate 100

# API endpoint discovery
ffuf -u "$URL/FUZZ" \
  -w /home/fox/SecLists/Discovery/Web-Content/api/api-endpoints.txt \
  -mc 200,201,204,301,302,401,403 \
  -o recon/http/api-endpoints.json -of json \
  -t 40

# API versioning brute force
ffuf -u "$URL/api/FUZZ/" \
  -w /home/fox/SecLists/Discovery/Web-Content/api/api-seen-in-wild.txt \
  -mc 200,201,204,301,302,401,403 \
  -o recon/http/api-versions.json -of json

# Backup file discovery
ffuf -u "$URL/FUZZ" \
  -w /home/fox/SecLists/Discovery/Web-Content/raft-large-files.txt \
  -e .bak,.backup,.old,.orig,.copy,.tmp,.swp,.gz,.tar,.zip,.sql,.dump \
  -mc 200 \
  -o recon/http/backups.json -of json

# Extract all 200 results
cat recon/http/dirs.json recon/http/files.json recon/http/api-endpoints.json 2>/dev/null \
  | jq -r '.results[] | select(.status==200) | .url' | sort -u \
  | tee recon/http/all-200.txt
```

---

## Phase 7 — JavaScript and API analysis

```bash
# Spider the application
katana -u $URL \
  -jc -kf all \
  -d 5 \
  -o recon/http/katana-urls.txt \
  -silent 2>/dev/null || \
  echo "[!] katana not available — using wayback data"

# Download all JS files
mkdir -p recon/js
for jsurl in $(cat recon/http/katana-urls.txt | grep "\.js$" | sort -u | head -50); do
  filename=$(echo $jsurl | md5sum | cut -d' ' -f1)
  curl -sL "$jsurl" -o "recon/js/$filename.js"
done
echo "[+] Downloaded $(ls recon/js/*.js 2>/dev/null | wc -l) JS files"

# Extract endpoints from JS
grep -ohP "(https?://[^\s\"']+|/[a-zA-Z0-9_\-/]+)" recon/js/*.js 2>/dev/null \
  | grep -v "cdn\|jquery\|bootstrap\|analytics\|google\|facebook" \
  | sort -u | tee recon/js/js-endpoints.txt

# Hunt for secrets in JS
echo "=== Potential secrets in JS ==="
grep -ohiP "(api[_-]?key|apikey|secret|token|password|auth|bearer|aws|s3|stripe|twilio|sendgrid|mailchimp)\s*[=:]\s*['\"][^'\"]{8,}['\"]" \
  recon/js/*.js 2>/dev/null | tee recon/loot/js-secrets.txt

# GraphQL detection
for gqlpath in /graphql /graphiql /api/graphql /v1/graphql /gql; do
  code=$(curl -so /dev/null -w "%{http_code}" -X POST "$URL$gqlpath" \
    -H "Content-Type: application/json" \
    -d '{"query":"{__typename}"}')
  if [[ "$code" == "200" ]]; then
    echo "[!] GraphQL endpoint found: $gqlpath" | tee -a recon/http/graphql.txt
    # Introspection query
    curl -s -X POST "$URL$gqlpath" \
      -H "Content-Type: application/json" \
      -d '{"query":"{ __schema { types { name fields { name } } } }"}' \
      | tee recon/http/graphql-schema.json
  fi
done
```

---

## Phase 8 — Parameter and input discovery

```bash
# Extract all parameters from collected URLs
cat recon/osint/wayback-urls.txt recon/http/katana-urls.txt 2>/dev/null \
  | grep "?" | grep -oP "\?.*" | tr '&' '\n' | cut -d'=' -f1 | tr -d '?' \
  | sort -u | tee recon/http/parameters.txt
echo "[+] Unique parameters found: $(wc -l < recon/http/parameters.txt)"

# Arjun — hidden parameter discovery on key endpoints
arjun -u "$URL/api/endpoint" -oJ recon/http/arjun-params.json 2>/dev/null || \
  echo "[!] arjun not available"
```

---

## Phase 9 — Target profile output

Write `recon/target-profile.md`:

```markdown
# Target Profile: <domain>
Generated: <date>
Tester: pi / fox

## Infrastructure
- Primary IP: 
- Additional IPs: 
- ASN / Hosting provider: 
- CDN detected: yes/no (provider)
- WAF detected: yes/no (vendor/product)
- Load balancer: yes/no

## Subdomains (live)
| Subdomain | IP | Status | Title | Tech |
|---|---|---|---|---|

## Technology Stack
- Web server: 
- Framework / language: 
- Database (inferred): 
- CMS / platform: 
- JS frameworks: 
- Authentication: 
- CDN: 
- Analytics: 

## Open Ports / Services
| Port | Service | Version | Notes |
|---|---|---|---|

## Authentication endpoints
| Path | Type | Notes |
|---|---|---|

## Interesting endpoints
| URL | Status | Notes |
|---|---|---|

## Sensitive files found
| Path | Status | Content |
|---|---|---|

## Secrets / credentials found
| Location | Type | Value (redacted) |
|---|---|---|

## Security headers
| Header | Present | Value |
|---|---|---|

## Attack surface summary (ranked)
1. <highest value vector with reason>
2. 
3. 

## Next phase recommendation
<exploitation approach based on findings>
```

---

## Rules
- Save all raw output to workspace immediately — never rely on context
- Record every 200, 403, and 401 — 403 means the path exists
- Negative results are findings — document them
- After each phase emit a one-line summary before moving to next
- Do not begin exploitation during recon — complete the profile first
- If WAF is detected, note it and plan bypass approach before proceeding