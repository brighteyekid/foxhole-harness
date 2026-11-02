---
name: web-recon
description: "Elite web reconnaissance methodology: passive DNS, certificate transparency, OSINT, subdomain enumeration, port scanning, HTTP fingerprinting, content discovery, JavaScript analysis, cloud storage enumeration, API security recon, infrastructure/cloud recon, social engineering surface, and fully automated recon pipeline. Load at the start of any web engagement."
---

# WEB RECON SKILL

## PHASE 0 — WORKSPACE AND TOOL DISCOVERY

```bash
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
TARGET_DOMAIN="${1:-target.com}"
WORKSPACE=~/recon_${TIMESTAMP}_${TARGET_DOMAIN//[^a-zA-Z0-9]/_}

mkdir -p $WORKSPACE/{recon/{dns,subdomains,ports,http,tech,osint,js/{downloaded,sourcemaps,chunks,secrets},cloud,mobile,cicd,api},vulns/{confirmed,potential,research},exploits/{working,attempted},loot/{credentials,data,flags}}

echo "[*] Workspace: $WORKSPACE"
echo "[*] Target: $TARGET_DOMAIN"
echo "[*] Started: $(date)" > $WORKSPACE/continuous.md

for tool in nmap masscan dig host whois curl wget python3 go \
  subfinder amass assetfinder findomain dnsx httpx nuclei ffuf gobuster \
  wfuzz nikto whatweb katana hakrawler gau waybackurls gospider arjun \
  jq theHarvester trufflehog s3scanner subzy subjack wafw00f naabu; do
  if which $tool >/dev/null 2>&1; then echo "[+] $tool: $(which $tool)"
  else echo "[-] $tool: missing"; fi
done | tee $WORKSPACE/tools_available.txt

TARGET_HOST=$(echo "$TARGET_DOMAIN" | sed 's|https\?://||' | sed 's|/.*||')
echo "$TARGET_HOST" > $WORKSPACE/target_host.txt
dig +short $TARGET_HOST A | tee $WORKSPACE/recon/dns/target_ips.txt
TARGET_IP=$(head -1 $WORKSPACE/recon/dns/target_ips.txt)
echo "[*] Primary IP: $TARGET_IP"
```

---

## PHASE 1 — PASSIVE DNS RECONNAISSANCE

```bash
TARGET="target.com"

# All DNS record types
for rtype in A AAAA MX NS TXT SOA CNAME SRV CAA DNSKEY TLSA NAPTR; do
  echo "=== $rtype ===" >> $WORKSPACE/recon/dns/all_records.txt
  dig $TARGET $rtype +noall +answer +time=5 2>/dev/null >> $WORKSPACE/recon/dns/all_records.txt
done

# Zone transfer against every NS
for ns in $(dig $TARGET NS +short 2>/dev/null | sed 's/\.$//'); do
  dig axfr $TARGET @$ns 2>/dev/null >> $WORKSPACE/recon/dns/zone_transfers.txt
  dig axfr $TARGET @$ns 2>/dev/null | grep -v "^;" | awk '{print $1}' | \
    sed 's/\.$//; /^$/d' >> $WORKSPACE/recon/subdomains/zone_transfer_subs.txt
done

# Certificate Transparency
curl -s "https://crt.sh/?q=%25.$TARGET&output=json" 2>/dev/null | \
  jq -r '.[].name_value' | sed 's/\*\.//g' | tr ',' '\n' | sort -u \
  > $WORKSPACE/recon/subdomains/crtsh.txt
echo "[*] crt.sh: $(wc -l < $WORKSPACE/recon/subdomains/crtsh.txt) subdomains"

# Subfinder
subfinder -d $TARGET -o $WORKSPACE/recon/subdomains/subfinder.txt -all -silent -timeout 30 2>/dev/null

# Amass passive
amass enum -passive -d $TARGET -o $WORKSPACE/recon/subdomains/amass_passive.txt -timeout 5 2>/dev/null

# Assetfinder + findomain
assetfinder --subs-only $TARGET 2>/dev/null > $WORKSPACE/recon/subdomains/assetfinder.txt
findomain -t $TARGET -q 2>/dev/null > $WORKSPACE/recon/subdomains/findomain.txt

# Consolidate and resolve
cat $WORKSPACE/recon/subdomains/*.txt 2>/dev/null | \
  grep -v "^\*" | grep "\.$TARGET$\|^$TARGET$" | \
  sort -u > $WORKSPACE/recon/subdomains/all_subdomains.txt
echo "[*] Total unique: $(wc -l < $WORKSPACE/recon/subdomains/all_subdomains.txt)"

dnsx -l $WORKSPACE/recon/subdomains/all_subdomains.txt \
  -o $WORKSPACE/recon/subdomains/resolved.txt -a -cname -resp -silent 2>/dev/null

# DNS brute-force
for wl in /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
          /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt; do
  [ -f "$wl" ] && WORDLIST="$wl" && break
done
[ -n "$WORDLIST" ] && gobuster dns -d $TARGET -w $WORDLIST \
  -o $WORKSPACE/recon/subdomains/gobuster_dns.txt -t 50 --timeout 5s 2>/dev/null

# Web archive URLs
gau --providers wayback,commoncrawl,otx,urlscan $TARGET \
  > $WORKSPACE/recon/osint/gau_urls.txt 2>/dev/null
waybackurls $TARGET > $WORKSPACE/recon/osint/wayback_urls.txt 2>/dev/null

# Reverse DNS
while read ip; do
  host $ip 2>/dev/null >> $WORKSPACE/recon/dns/reverse_dns.txt
done < $WORKSPACE/recon/dns/target_ips.txt

# Takeover check
subzy run --targets $WORKSPACE/recon/subdomains/resolved.txt 2>/dev/null | \
  tee $WORKSPACE/recon/subdomains/takeover_check.txt
```

---

## PHASE 2 — OSINT AND WHOIS

```bash
TARGET="target.com"

whois $TARGET | tee $WORKSPACE/recon/osint/whois_domain.txt
whois $TARGET_IP | tee $WORKSPACE/recon/osint/whois_ip.txt

# ASN + IP info
curl -s "https://ipinfo.io/$TARGET_IP/json" | \
  jq '{ip,org,city,country,hostname}' | tee $WORKSPACE/recon/osint/ipinfo.txt

curl -s "https://api.bgpview.io/ip/$TARGET_IP" | \
  jq '.data | {asn:.prefixes[0].asn.asn, org:.prefixes[0].asn.name, prefix:.prefixes[0].prefix}' | \
  tee $WORKSPACE/recon/osint/asn.txt

# Shodan passive
curl -s "https://internetdb.shodan.io/$TARGET_IP" | jq . | tee $WORKSPACE/recon/osint/shodan.txt

# Google dorks (run manually)
cat > $WORKSPACE/recon/osint/google_dorks.txt << EOF
site:$TARGET
site:$TARGET filetype:pdf OR filetype:docx OR filetype:xlsx
site:$TARGET inurl:admin OR inurl:login OR inurl:dashboard
site:$TARGET inurl:api OR inurl:swagger OR inurl:graphql
site:$TARGET "error" OR "exception" OR "stack trace"
site:$TARGET intitle:"index of"
site:$TARGET inurl:.env OR inurl:config OR inurl:backup
"@$TARGET" email
"$TARGET" site:pastebin.com
"$TARGET" site:github.com password OR secret OR key OR token
"$TARGET" site:trello.com OR site:docs.google.com
EOF

# theHarvester
theHarvester -d $TARGET -b bing,duckduckgo,google,linkedin,yahoo \
  -f $WORKSPACE/recon/osint/harvester.html 2>/dev/null

# Extract interesting archived URLs
cat $WORKSPACE/recon/osint/gau_urls.txt 2>/dev/null | \
  grep -iE "\.(php|asp|aspx|jsp|cgi|do|action|cfm|pl|py|rb)(\?|$)" | sort -u \
  > $WORKSPACE/recon/osint/interesting_urls.txt
cat $WORKSPACE/recon/osint/gau_urls.txt 2>/dev/null | \
  grep -iE "admin|login|dashboard|panel|config|backup|upload|api|token|key|secret|password" | \
  sort -u >> $WORKSPACE/recon/osint/interesting_urls.txt
```

---

## PHASE 3 — PORT SCANNING AND SERVICE DISCOVERY

```bash
TARGET_IP="1.2.3.4"

# Top-1000 ports fast
nmap -sV -sC -T4 --top-ports 1000 $TARGET_IP \
  -oA $WORKSPACE/recon/ports/nmap_top1000 2>/dev/null

# Full port scan (background)
nmap -sV -T4 -p- $TARGET_IP -oA $WORKSPACE/recon/ports/nmap_full 2>/dev/null &

# UDP critical ports
nmap -sU -T4 -p 53,67,68,69,123,161,162,500,514,1900,5353 $TARGET_IP \
  -oA $WORKSPACE/recon/ports/nmap_udp 2>/dev/null

# Naabu fast port discovery
naabu -host $TARGET_IP -p - -o $WORKSPACE/recon/ports/naabu_all.txt 2>/dev/null

# Service-specific deep scans
nmap -sV -p 22 --script=ssh-auth-methods,ssh2-enum-algos $TARGET_IP 2>/dev/null \
  -oN $WORKSPACE/recon/ports/ssh_detail.txt
nmap -sV -p 445,139 --script=smb-os-discovery,smb2-security-mode,smb-enum-shares,smb-vuln-ms17-010 \
  $TARGET_IP -oN $WORKSPACE/recon/ports/smb_detail.txt 2>/dev/null

# Database exposure check
for port in 3306 5432 1433 27017 6379 9200 5984 2379 2375 2376; do
  STATUS=$(nmap -p $port --open $TARGET_IP 2>/dev/null | grep -c "open")
  [ "$STATUS" -gt 0 ] && echo "[!!] Exposed service on port $port" | \
    tee -a $WORKSPACE/recon/ports/database_exposure.txt
done
```

---

## PHASE 4 — HTTP FINGERPRINTING

```bash
TARGET="https://target.com"

# httpx comprehensive fingerprint
httpx -u $TARGET -title -tech-detect -status-code -content-length \
  -web-server -ip -cname -cdn -probe -silent \
  -o $WORKSPACE/recon/http/httpx_fingerprint.json -json 2>/dev/null

# All subdomains fingerprint
httpx -l $WORKSPACE/recon/subdomains/resolved.txt \
  -title -tech-detect -status-code -content-length -web-server -ip -cdn \
  -o $WORKSPACE/recon/http/all_subdomains_http.json -json -silent -threads 50 2>/dev/null

# Manual header extraction
curl -sI $TARGET | tee $WORKSPACE/recon/http/headers.txt

# Security headers audit
curl -sI $TARGET | grep -iE \
  "strict-transport-security|content-security-policy|x-frame-options|x-content-type-options|referrer-policy|permissions-policy|x-xss-protection" | \
  tee $WORKSPACE/recon/http/security_headers.txt

HEADERS_RAW=$(curl -sI $TARGET 2>/dev/null)
for header in "Strict-Transport-Security" "Content-Security-Policy" "X-Frame-Options" \
              "X-Content-Type-Options" "Referrer-Policy" "Permissions-Policy"; do
  if ! echo "$HEADERS_RAW" | grep -qi "$header"; then
    echo "[-] MISSING: $header" >> $WORKSPACE/recon/http/missing_security_headers.txt
  fi
done

# Favicon hash fingerprinting
pip install mmh3 -q 2>/dev/null
FAVICON_HASH=$(curl -sk "$TARGET/favicon.ico" 2>/dev/null | python3 -c "
import sys,mmh3,codecs
favicon=sys.stdin.buffer.read()
if favicon:
    b64=codecs.encode(favicon,'base64').decode()
    print(mmh3.hash(b64))
" 2>/dev/null)
echo "Favicon hash: $FAVICON_HASH" | tee $WORKSPACE/recon/tech/favicon_hash.txt
echo "Shodan query: http.favicon.hash:$FAVICON_HASH" >> $WORKSPACE/recon/tech/favicon_hash.txt

# whatweb
whatweb -a 3 $TARGET --log-json=$WORKSPACE/recon/tech/whatweb.json 2>/dev/null

# WAF detection
wafw00f $TARGET -o $WORKSPACE/recon/tech/waf.txt 2>/dev/null

# Default files probe
for path in /robots.txt /sitemap.xml /sitemap_index.xml /.well-known/security.txt \
            /crossdomain.xml /manifest.json /.htaccess /.htpasswd /web.config \
            /package.json /composer.json /.travis.yml /Dockerfile /docker-compose.yml \
            /README.md /CHANGELOG.md /phpinfo.php /info.php /test.php \
            /wp-config.php /wp-config.php.bak /configuration.php; do
  STATUS=$(curl -sk -o /dev/null -w "%{http_code}" "$TARGET$path" 2>/dev/null)
  [ "$STATUS" != "404" ] && [ "$STATUS" != "000" ] && \
    echo "[$STATUS] $path" >> $WORKSPACE/recon/http/default_files.txt && \
    curl -sk "$TARGET$path" -o "$WORKSPACE/recon/http/$(echo $path | tr '/' '_').txt" 2>/dev/null
done
cat $WORKSPACE/recon/http/default_files.txt
```

---

## PHASE 5 — CORS TESTING

```bash
TARGET="https://target.com"

declare -A CORS_TESTS
CORS_TESTS["null"]="null"
CORS_TESTS["evil"]="https://evil.com"
CORS_TESTS["subdomain_prefix"]="https://target.com.evil.com"
CORS_TESTS["arbitrary"]="https://notreal.target.com"
CORS_TESTS["reflected"]="https://attacker.com"

echo "=== CORS Testing ===" > $WORKSPACE/vulns/potential/cors_test.txt
for name in "${!CORS_TESTS[@]}"; do
  origin="${CORS_TESTS[$name]}"
  for endpoint in / /api/ /api/user /api/v1/user /api/me; do
    response=$(curl -sk -I "$TARGET$endpoint" -H "Origin: $origin" 2>/dev/null)
    acao=$(echo "$response" | grep -i "access-control-allow-origin" | tr -d '\r')
    acac=$(echo "$response" | grep -i "access-control-allow-credentials" | tr -d '\r')
    if [ -n "$acao" ]; then
      echo "[$name] $endpoint — ACAO: $acao | ACAC: $acac" >> $WORKSPACE/vulns/potential/cors_test.txt
      if echo "$acac" | grep -qi "true" && (echo "$acao" | grep -qi "evil\|attacker\|$origin"); then
        echo "[!!] VULNERABLE CORS: $endpoint (creds reflected)" >> $WORKSPACE/vulns/potential/cors_test.txt
      fi
    fi
  done
done
```

---

## PHASE 6 — CONTENT DISCOVERY

```bash
TARGET="https://target.com"

# Directory brute force
for wl in /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt \
          /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
          /usr/share/seclists/Discovery/Web-Content/common.txt \
          /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt; do
  [ -f "$wl" ] && DIRLIST="$wl" && break
done

[ -n "$DIRLIST" ] && ffuf -u "$TARGET/FUZZ" -w $DIRLIST \
  -ac -mc 200,201,202,204,301,302,303,307,401,403,405,500 \
  -t 50 -timeout 10 -rate 100 \
  -o $WORKSPACE/recon/http/ffuf_dirs.json -of json 2>/dev/null

# Sensitive paths
for path in /.env /.env.local /.env.production /.env.backup \
            /config.php /config.yml /settings.py \
            /.git/HEAD /.git/config /.svn/entries \
            /api/swagger.json /api/openapi.json /swagger-ui.html /api-docs \
            /actuator /actuator/env /actuator/mappings /actuator/health \
            /console /h2-console /phpinfo.php \
            /wp-config.php /wp-config.php.bak /configuration.php; do
  STATUS=$(curl -sk -o /dev/null -w "%{http_code}" "$TARGET$path" 2>/dev/null)
  [ "$STATUS" = "200" ] && echo "[!!] [$STATUS] $path" | tee -a $WORKSPACE/loot/data/sensitive_files.txt && \
    curl -sk "$TARGET$path" > "$WORKSPACE/loot/data/$(echo $path | tr '/' '_').txt" 2>/dev/null
done

# Backup file hunting
for ext in .bak .backup .old .orig .copy .1 .tmp .swp .save .zip .tar.gz .sql .db; do
  for base in index config settings database admin app main; do
    STATUS=$(curl -sk -o /dev/null -w "%{http_code}" "$TARGET/${base}${ext}" 2>/dev/null)
    [ "$STATUS" = "200" ] && echo "[200] ${base}${ext}" | tee -a $WORKSPACE/recon/http/backup_files.txt
  done
done

# .git exposure + dump
GIT_STATUS=$(curl -sk -o /dev/null -w "%{http_code}" "$TARGET/.git/HEAD" 2>/dev/null)
if [ "$GIT_STATUS" = "200" ]; then
  echo "[!!] .git directory EXPOSED!"
  git-dumper "$TARGET/.git/" $WORKSPACE/loot/data/git_dump 2>/dev/null || \
  for gfile in HEAD config COMMIT_EDITMSG FETCH_HEAD index packed-refs \
               info/refs logs/HEAD logs/refs/heads/main logs/refs/heads/master; do
    mkdir -p "$WORKSPACE/loot/data/git_dump/$(dirname $gfile)" 2>/dev/null
    curl -sk "$TARGET/.git/$gfile" -o "$WORKSPACE/loot/data/git_dump/$gfile" 2>/dev/null
  done
fi

# API endpoint discovery
for base in api v1 v2 v3 graphql rest rpc service services; do
  for path in "" /users /user /admin /auth /login /token /swagger /docs /openapi.json; do
    STATUS=$(curl -sk -o /dev/null -w "%{http_code}" "$TARGET/$base$path" 2>/dev/null)
    [ "$STATUS" != "404" ] && [ "$STATUS" != "000" ] && \
      echo "[$STATUS] /$base$path" >> $WORKSPACE/recon/api/endpoints_discovered.txt
  done
done
```

---

## PHASE 7 — JAVASCRIPT ANALYSIS

```bash
TARGET="https://target.com"

# Download all JS files
curl -sk $TARGET | \
  grep -oP '(?:src=")[^"]*\.js[^"]*' | sed 's/src="//g' | while read js_path; do
    [ "${js_path:0:4}" != "http" ] && js_url="${TARGET}${js_path}" || js_url="$js_path"
    filename=$(echo "$js_path" | sed 's|.*/||' | sed 's/[?#].*//')
    curl -sk "$js_url" -o "$WORKSPACE/recon/js/downloaded/$filename" 2>/dev/null
  done

# Katana deep crawl
katana -u $TARGET -d 5 -jc -kf all \
  -o $WORKSPACE/recon/js/katana_js_urls.txt 2>/dev/null

# Secret hunting in JS
find $WORKSPACE/recon/js/downloaded -name "*.js" 2>/dev/null | while read jsfile; do
  # API keys and tokens
  grep -oP '(?:api_key|apikey|api-key|secret|token|password|auth|bearer|authorization)["\s:=]+["\x27]?[a-zA-Z0-9_\-/+]{16,}' \
    "$jsfile" 2>/dev/null >> $WORKSPACE/recon/js/secrets/all_secrets.txt
  # AWS keys
  grep -oP 'AKIA[A-Z0-9]{16}' "$jsfile" 2>/dev/null >> $WORKSPACE/recon/js/secrets/aws_keys.txt
  # Internal endpoints
  grep -oP '"(?:https?://[^"]+|/api/[a-zA-Z0-9/_.-]+(?:\?[^"]*)?)"' "$jsfile" 2>/dev/null | \
    grep -v "cdn\|fonts\|\.png\|\.jpg\|\.css" | sort -u >> $WORKSPACE/recon/js/secrets/js_endpoints.txt
done

# Source map extraction
find $WORKSPACE/recon/js/downloaded -name "*.js" 2>/dev/null | while read jsfile; do
  sourcemap=$(grep -oP '//# sourceMappingURL=([^\s]+)' "$jsfile" | cut -d= -f2)
  if [ -n "$sourcemap" ]; then
    [ "${sourcemap:0:4}" != "http" ] && mapurl="$TARGET/$sourcemap" || mapurl="$sourcemap"
    curl -sk "$mapurl" | python3 -c "
import json,sys,os
data=json.load(sys.stdin)
for i,src in enumerate(data.get('sources',[])):
    content=(data.get('sourcesContent') or ['']*(i+1))[i]
    name=os.path.basename(src.replace('../','').replace('webpack://',''))
    if content:
        with open(f'$WORKSPACE/recon/js/sourcemaps/src_{i}_{name}','w') as f: f.write(content)
        print(f'  Extracted: {src}')
" 2>/dev/null
  fi
done

# trufflehog
trufflehog filesystem $WORKSPACE/recon/js/downloaded/ --no-verification \
  --json 2>/dev/null > $WORKSPACE/recon/js/secrets/trufflehog.json
echo "[*] trufflehog findings: $(python3 -c "import json; data=open('$WORKSPACE/recon/js/secrets/trufflehog.json').read(); print(len([l for l in data.strip().split('\n') if l]))" 2>/dev/null)"
```

---

## PHASE 8 — CLOUD STORAGE ENUMERATION

```bash
COMPANY="targetcompany"

# Generate S3 bucket names
python3 - << 'EOF'
company = "COMPANY_NAME"
words = ["dev","staging","prod","production","test","backup","data","assets","media",
         "static","files","uploads","downloads","images","docs","logs","archive","config",
         "internal","private","public","admin","api","cdn","deploy","release","builds",
         "artifacts","terraform","tf","lambda","secrets","credentials","keys"]
buckets = set([company])
for w in words:
    buckets.update([f"{company}-{w}",f"{company}.{w}",f"{w}-{company}",f"{company}{w}"])
with open("/tmp/s3_buckets.txt","w") as f: f.write("\n".join(sorted(buckets)))
print(f"Generated {len(buckets)} names")
EOF

# Check S3 buckets
while read bucket; do
  STATUS=$(curl -sk -o /dev/null -w "%{http_code}" "https://${bucket}.s3.amazonaws.com/" 2>/dev/null)
  case $STATUS in
    200) echo "[!!] PUBLIC S3: $bucket" | tee -a $WORKSPACE/recon/cloud/s3_public.txt
         curl -sk "https://${bucket}.s3.amazonaws.com/?list-type=2&max-keys=20" | \
           grep -oP '<Key>[^<]+</Key>' | head -20 >> $WORKSPACE/recon/cloud/s3_public.txt ;;
    403) echo "[+] EXISTS (private): $bucket" >> $WORKSPACE/recon/cloud/s3_private.txt ;;
  esac
done < /tmp/s3_buckets.txt

# GCS buckets
while read bucket; do
  STATUS=$(curl -sk -o /dev/null -w "%{http_code}" "https://storage.googleapis.com/$bucket/" 2>/dev/null)
  [ "$STATUS" = "200" ] && echo "[!!] PUBLIC GCS: $bucket" | tee -a $WORKSPACE/recon/cloud/gcs_public.txt
done < /tmp/s3_buckets.txt

# Firebase
for app in $COMPANY ${COMPANY}app ${COMPANY}-app ${COMPANY}dev; do
  STATUS=$(curl -sk -o /dev/null -w "%{http_code}" "https://${app}.firebaseio.com/.json" 2>/dev/null)
  [ "$STATUS" = "200" ] && echo "[!!] PUBLIC Firebase: $app" | tee -a $WORKSPACE/recon/cloud/firebase_public.txt && \
    curl -sk "https://${app}.firebaseio.com/.json" | python3 -m json.tool | head -50 >> \
    $WORKSPACE/recon/cloud/firebase_public.txt
done

# Azure Blob
while read bucket; do
  STATUS=$(curl -sk -o /dev/null -w "%{http_code}" "https://${bucket}.blob.core.windows.net/" 2>/dev/null)
  [ "$STATUS" = "200" ] || [ "$STATUS" = "400" ] && \
    echo "[+] Azure Blob exists: $bucket" >> $WORKSPACE/recon/cloud/azure_storage.txt
done < /tmp/s3_buckets.txt
```

---

## PHASE 9 — EMPLOYEE AND EMAIL HARVESTING

```bash
TARGET="target.com"
COMPANY=$(echo $TARGET | cut -d. -f1)

# theHarvester
theHarvester -d $TARGET -b bing,google,yahoo -f $WORKSPACE/recon/osint/emails.html 2>/dev/null

# Hunter.io
HUNTER_KEY="your-key"
curl -s "https://api.hunter.io/v2/domain-search?domain=$TARGET&api_key=$HUNTER_KEY" | \
  jq '{pattern:.data.pattern,emails:[.data.emails[].value]}' | \
  tee $WORKSPACE/recon/osint/hunter_emails.json

# GitHub org members
curl -s "https://api.github.com/orgs/$COMPANY/members?per_page=100" \
  -H "Authorization: token $GITHUB_TOKEN" 2>/dev/null | \
  jq '.[].login' 2>/dev/null | tee $WORKSPACE/recon/osint/github_org_members.txt

# HIBP breach check
HIBP_KEY="your-hibp-key"
[ -f $WORKSPACE/recon/osint/emails.txt ] && while read email; do
  result=$(curl -s "https://haveibeenpwned.com/api/v3/breachedaccount/$email" \
    -H "hibp-api-key: $HIBP_KEY" -H "User-Agent: pi-recon" 2>/dev/null)
  [ -n "$result" ] && echo "[BREACHED] $email: $result" | tee -a $WORKSPACE/recon/osint/breaches.txt
  sleep 1.5
done < $WORKSPACE/recon/osint/emails.txt
```

---

## PHASE 10 — COOKIE AND SESSION ANALYSIS

```bash
TARGET="https://target.com"

curl -sk -c /tmp/cookies.txt $TARGET -o /dev/null 2>/dev/null
cat /tmp/cookies.txt | tee $WORKSPACE/recon/http/cookies.txt

python3 << 'PYEOF'
import base64, json, re

with open("/tmp/cookies.txt") as f:
    lines = [l for l in f if not l.startswith('#') and l.strip()]

for line in lines:
    parts = line.strip().split('\t')
    if len(parts) < 7: continue
    domain,flag,path,secure,expiry,name,value = (parts+['']*(7-len(parts)))[:7]
    issues = []
    if secure.lower() != 'true': issues.append("MISSING Secure flag")
    if value.count('.') == 2 and len(value) > 50:
        try:
            p = value.split('.')
            header = json.loads(base64.b64decode(p[0]+'==').decode())
            payload = json.loads(base64.b64decode(p[1]+'==').decode())
            issues.append(f"JWT alg:{header.get('alg','?')} sub:{payload.get('sub','?')} role:{payload.get('role','?')}")
        except: pass
    try:
        decoded = base64.b64decode(value+'==').decode('utf-8',errors='ignore')
        if '{' in decoded or 'user' in decoded.lower():
            issues.append(f"Base64 contains: {decoded[:80]}")
    except: pass
    if issues: print(f"[{name}]: {', '.join(issues)}")
PYEOF
```

---

## PHASE 11 — SECURITY HEADERS AND TLS

```bash
TARGET="https://target.com"

# TLS via nmap
nmap --script ssl-cert,ssl-enum-ciphers,ssl-dh-params -p 443 \
  $(echo $TARGET | sed 's|https\?://||') \
  -oN $WORKSPACE/recon/http/tls_analysis.txt 2>/dev/null

# HTTP methods
curl -sk -X OPTIONS $TARGET -i | grep "Allow:" | tee $WORKSPACE/recon/http/allowed_methods.txt
for method in PUT DELETE PATCH TRACE CONNECT; do
  STATUS=$(curl -sk -o /dev/null -w "%{http_code}" -X $method $TARGET 2>/dev/null)
  echo "[$STATUS] $method" >> $WORKSPACE/recon/http/http_methods.txt
done
```

---

## PHASE 12 — SUBDOMAIN TAKEOVER

```bash
declare -A TAKEOVER_SIGS
TAKEOVER_SIGS["github"]="There isn't a GitHub Pages site here"
TAKEOVER_SIGS["heroku"]="No such app"
TAKEOVER_SIGS["shopify"]="Sorry, this shop is currently unavailable"
TAKEOVER_SIGS["fastly"]="Fastly error: unknown domain"
TAKEOVER_SIGS["pantheon"]="The gods are wise, but do not know of the site"
TAKEOVER_SIGS["tumblr"]="Whatever you were looking for doesn't currently exist"
TAKEOVER_SIGS["zendesk"]="Help Center Closed"
TAKEOVER_SIGS["unbounce"]="The requested URL was not found"
TAKEOVER_SIGS["surge"]="project not found"
TAKEOVER_SIGS["bitbucket"]="Repository not found"
TAKEOVER_SIGS["s3"]="NoSuchBucket"
TAKEOVER_SIGS["azure"]="No web app was found"

while read subdomain; do
  CNAME=$(dig +short CNAME $subdomain 2>/dev/null)
  if [ -n "$CNAME" ]; then
    BODY=$(curl -sk "https://$subdomain" 2>/dev/null)
    for service in "${!TAKEOVER_SIGS[@]}"; do
      echo "$BODY" | grep -qiE "${TAKEOVER_SIGS[$service]}" && \
        echo "[!!] TAKEOVER: $subdomain → $CNAME ($service)" | \
        tee -a $WORKSPACE/vulns/potential/subdomain_takeover.txt
    done
  fi
done < $WORKSPACE/recon/subdomains/all_subdomains.txt 2>/dev/null
```

---

## PHASE 13 — CI/CD AND DEVTOOLS EXPOSURE

```bash
TARGET="https://target.com"

# .env files
for env_path in /.env /.env.local /.env.development /.env.staging /.env.production \
               /.env.example /.env.sample /.env.backup /.env.bak; do
  STATUS=$(curl -sk -o /tmp/env_test -w "%{http_code}" "$TARGET$env_path" 2>/dev/null)
  if [ "$STATUS" = "200" ]; then
    echo "[!!] Exposed: $env_path"
    cat /tmp/env_test | grep -iE "key|secret|password|token|api|db|database|mysql|postgres|mongo|redis" | \
      tee -a $WORKSPACE/loot/credentials/env_files.txt
  fi
done

# Jenkins detection
for path in /jenkins /jenkins/script /jenkins/login /jenkins/api/json \
            /:8080/jenkins /:8080 /ci /hudson; do
  STATUS=$(curl -sk -o /dev/null -w "%{http_code}" "$TARGET$path" 2>/dev/null)
  [ "$STATUS" != "404" ] && [ "$STATUS" != "000" ] && \
    echo "[$STATUS] Jenkins/CI: $path" | tee -a $WORKSPACE/recon/cicd/jenkins.txt
done

# Docker daemon exposed
for port in 2375 2376; do
  HOST=$(echo $TARGET | sed 's|https\?://||')
  STATUS=$(curl -sk -o /dev/null -w "%{http_code}" "http://$HOST:$port/containers/json" 2>/dev/null)
  [ "$STATUS" = "200" ] && echo "[!!] Docker daemon on port $port!" | \
    tee $WORKSPACE/vulns/confirmed/docker_exposed.txt && \
    curl -sk "http://$HOST:$port/images/json" | jq '.[].RepoTags' >> \
    $WORKSPACE/vulns/confirmed/docker_exposed.txt
done

# Kubernetes ports
HOST=$(echo $TARGET | sed 's|https\?://||')
for port in 6443 8443 8080 10250 10255 2379; do
  STATUS=$(curl -sk -o /dev/null -w "%{http_code}" "https://$HOST:$port/api" 2>/dev/null)
  [ "$STATUS" = "200" ] && echo "[!!] K8s/etcd on port $port!" | \
    tee -a $WORKSPACE/vulns/confirmed/k8s_exposed.txt
done

# Terraform state files
for path in /terraform.tfstate /.terraform.tfstate /infra/terraform.tfstate \
            /infrastructure/terraform.tfstate /deploy/terraform.tfstate; do
  STATUS=$(curl -sk -o /tmp/tfstate -w "%{http_code}" "$TARGET$path" 2>/dev/null)
  if [ "$STATUS" = "200" ]; then
    echo "[!!] Terraform state: $path"
    python3 -c "
import json
try:
    s=json.load(open('/tmp/tfstate'))
    for r in s.get('resources',[]):
        for i in r.get('instances',[]):
            for k,v in i.get('attributes',{}).items():
                if any(kw in k.lower() for kw in ['password','secret','key','token','cred','private']) and v:
                    print(f'  [{r[\"type\"]}.{r[\"name\"]}] {k}={str(v)[:80]}')
except Exception as e: print(e)
" 2>/dev/null | tee -a $WORKSPACE/loot/credentials/terraform_state.txt
  fi
done
```

---

## PHASE 14 — MOBILE APP RECON

```bash
TARGET="target.com"
COMPANY=$(echo $TARGET | cut -d. -f1)

# APK analysis (if downloaded)
if [ -f /tmp/app.apk ]; then
  mkdir -p $WORKSPACE/recon/mobile/apktool_out
  apktool d /tmp/app.apk -o $WORKSPACE/recon/mobile/apktool_out 2>/dev/null

  # Extract API endpoints
  grep -rE "https?://[a-zA-Z0-9._/-]+" $WORKSPACE/recon/mobile/apktool_out/res/ 2>/dev/null | \
    grep -v "schemas.android\|w3.org\|example.com" | sort -u \
    > $WORKSPACE/recon/mobile/apk_endpoints.txt

  # Hunt secrets
  grep -rE "api_key|apikey|secret|token|password|key=" $WORKSPACE/recon/mobile/apktool_out/ 2>/dev/null | \
    grep -v "^\s*//" | sort -u > $WORKSPACE/recon/mobile/apk_secrets.txt

  # strings from dex
  strings $WORKSPACE/recon/mobile/apktool_out/classes.dex 2>/dev/null | \
    grep -iE "https?://[a-zA-Z0-9._/-]+" | sort -u >> $WORKSPACE/recon/mobile/apk_endpoints.txt
fi
```

---

## PHASE 15 — API SECURITY RECON

### 15.1 OpenAPI / Swagger Discovery

```bash
TARGET="https://target.com"

API_DOCS_PATHS=(
  "/swagger.json" "/swagger.yaml" "/swagger/v1/swagger.json"
  "/api/swagger.json" "/api/swagger.yaml" "/api/v1/swagger.json"
  "/openapi.json" "/openapi.yaml" "/api/openapi.json"
  "/api-docs" "/api-docs.json" "/swagger-ui.html" "/swagger-ui"
  "/v1/api-docs" "/v2/api-docs" "/redoc" "/api/redoc" "/docs"
)

for path in "${API_DOCS_PATHS[@]}"; do
  STATUS=$(curl -sk -o /tmp/api_test -w "%{http_code}" "$TARGET$path" 2>/dev/null)
  if [ "$STATUS" = "200" ]; then
    SIZE=$(wc -c < /tmp/api_test)
    echo "[200] $path ($SIZE bytes)" | tee -a $WORKSPACE/recon/api/api_docs.txt
    cp /tmp/api_test "$WORKSPACE/recon/api/$(echo $path | tr '/' '_').json"
  fi
done

# Parse Swagger to extract endpoints and auth requirements
find $WORKSPACE/recon/api -name "*.json" -size +100c 2>/dev/null | head -3 | while read f; do
  python3 << PYEOF
import json
try:
    spec = json.load(open("$f"))
    for path, methods in spec.get('paths',{}).items():
        for method, detail in methods.items():
            if method in ('get','post','put','delete','patch','options'):
                auth = 'AUTH' if detail.get('security') else 'NOAUTH'
                params = [p['name'] for p in detail.get('parameters',[]) if p.get('in')=='query']
                print(f"[{auth}] {method.upper()} {path} params={params}")
except Exception as e: pass
PYEOF
done

# Hunt Postman collections on GitHub
curl -s "https://api.github.com/search/code?q=$(echo $TARGET | sed 's|https\?://||')+filename:postman_collection" \
  -H "Authorization: token $GITHUB_TOKEN" 2>/dev/null | \
  jq '.items[] | {file:.name, repo:.repository.full_name, url:.html_url}' | \
  tee $WORKSPACE/recon/api/postman_github.txt
```

### 15.2 GraphQL Deep Recon

```bash
TARGET="https://target.com"

# Find GraphQL endpoint
for path in /graphql /graphql/v1 /api/graphql /gql /query /graphiql /graphql-playground; do
  STATUS=$(curl -sk -o /dev/null -w "%{http_code}" -X POST "$TARGET$path" \
    -H "Content-Type: application/json" -d '{"query":"{__typename}"}' 2>/dev/null)
  [ "$STATUS" = "200" ] && echo "[+] GraphQL: $path" | tee -a $WORKSPACE/recon/api/graphql.txt
done

GQL_URL="$TARGET/graphql"

# Full introspection
curl -sk -X POST "$GQL_URL" -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { queryType{name} mutationType{name} types { name kind description fields { name description args { name type { name kind ofType{name kind} } } } } } }"}' | \
  python3 -m json.tool > $WORKSPACE/recon/api/graphql_schema.json 2>/dev/null

# Extract query names
jq -r '.data.__schema.queryType.fields[]?.name' $WORKSPACE/recon/api/graphql_schema.json 2>/dev/null | \
  tee $WORKSPACE/recon/api/graphql_queries.txt

# Field suggestion (works when introspection disabled)
curl -sk -X POST "$GQL_URL" -H "Content-Type: application/json" \
  -d '{"query":"{ __typ { name } }"}' | jq '.errors[].extensions.suggestedTypeNames' 2>/dev/null

# Batching detection
curl -sk -X POST "$GQL_URL" -H "Content-Type: application/json" \
  -d '[{"query":"{__typename}"},{"query":"{__typename}"},{"query":"{__typename}"}]' | \
  python3 -m json.tool 2>/dev/null && echo "[+] GraphQL batching enabled!"

# GraphQL IDOR + sensitive field probing
for id in $(seq 1 10); do
  result=$(curl -sk -X POST "$GQL_URL" -H "Content-Type: application/json" \
    -d "{\"query\":\"{ user(id: \\\"$id\\\") { id email role password apiKey permissions } }\"}" 2>/dev/null)
  echo "$result" | jq '.data.user' 2>/dev/null | grep -v "^null$" && \
    echo "$result" >> $WORKSPACE/loot/data/graphql_idor.txt
done

# clairvoyance schema recovery when introspection disabled
python3 -m clairvoyance "$GQL_URL" -o $WORKSPACE/recon/api/graphql_recovered.json 2>/dev/null || \
  echo "[-] clairvoyance not available"
```

### 15.3 WebSocket Discovery

```bash
TARGET="https://target.com"

curl -sk $TARGET | grep -iE "ws://|wss://|websocket|socket\.io" | \
  tee $WORKSPACE/recon/api/websocket_refs.txt

for path in /ws /websocket /socket /socket.io /ws/v1 /api/ws /live /realtime /notifications; do
  RESPONSE=$(curl -sk -o /dev/null -w "%{http_code}" "$TARGET$path" \
    -H "Upgrade: websocket" -H "Connection: Upgrade" \
    -H "Sec-WebSocket-Version: 13" \
    -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" 2>/dev/null)
  [ "$RESPONSE" = "101" ] && echo "[+] WebSocket: $path" | tee -a $WORKSPACE/recon/api/websocket_endpoints.txt
done
echo "[*] Manual test: wscat -c wss://$(echo $TARGET | sed 's|https\?://||')/ws"
```

### 15.4 CORS + Rate Limit + API Key Hunting

```bash
TARGET="https://target.com"

# API key hunting in JS files
find $WORKSPACE/recon/js/downloaded -name "*.js" 2>/dev/null | \
  xargs grep -oP '(?:x-api-key|api.key|apiKey|api_key)\s*[:=]\s*["\x27][a-zA-Z0-9_\-]{16,}' 2>/dev/null | \
  tee $WORKSPACE/recon/api/api_keys_in_js.txt

# AWS key pattern
find $WORKSPACE/recon/js/downloaded -name "*.js" 2>/dev/null | \
  xargs grep -oP 'AKIA[A-Z0-9]{16}' 2>/dev/null | \
  tee $WORKSPACE/recon/api/aws_keys_in_js.txt

# OAuth endpoints
for path in /oauth /oauth2 /oauth/token /oauth2/token /.well-known/openid-configuration \
            /.well-known/oauth-authorization-server /connect/token /auth/oauth; do
  STATUS=$(curl -sk -o /dev/null -w "%{http_code}" "$TARGET$path" 2>/dev/null)
  [ "$STATUS" != "404" ] && echo "[$STATUS] OAuth: $path" | tee -a $WORKSPACE/recon/api/oauth_endpoints.txt
done

# Rate limit test (login endpoint)
echo "Testing rate limit..."
for i in $(seq 1 25); do
  STATUS=$(curl -sk -o /dev/null -w "%{http_code}" -X POST "$TARGET/api/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"wrongpass123"}' 2>/dev/null)
  echo "Request $i: $STATUS"
  [ "$STATUS" = "429" ] && echo "[+] Rate limiting at request $i" && break
  [ "$STATUS" = "423" ] && echo "[+] Lockout at request $i" && break
done | tee $WORKSPACE/recon/api/rate_limit_test.txt
```

---

## PHASE 16 — INFRASTRUCTURE AND CLOUD DEEP RECON

### 16.1 AWS SSRF Chain

```bash
# AWS IMDSv1 (via SSRF — these are the URLs to fetch through the SSRF endpoint)
IMDS_URLS=(
  "http://169.254.169.254/latest/meta-data/"
  "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
  "http://169.254.169.254/latest/meta-data/instance-id"
  "http://169.254.169.254/latest/user-data"
  "http://169.254.169.254/latest/dynamic/instance-identity/document"
)
for url in "${IMDS_URLS[@]}"; do
  echo "SSRF_URL: $url" >> $WORKSPACE/recon/cloud/aws_imds_probes.txt
done

# IMDSv2 chain (two requests via SSRF):
cat >> $WORKSPACE/recon/cloud/aws_imds_probes.txt << 'EOF'
# IMDSv2 Step 1 — PUT for token:
# SSRF PUT http://169.254.169.254/latest/api/token  Header: X-aws-ec2-metadata-token-ttl-seconds: 21600
# IMDSv2 Step 2 — GET with token:
# SSRF GET http://169.254.169.254/latest/meta-data/iam/security-credentials/  Header: X-aws-ec2-metadata-token: <TOKEN_FROM_STEP_1>
# Once role name obtained:
# SSRF GET http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE_NAME>
# Returns: AccessKeyId, SecretAccessKey, Token
# Use: export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_SESSION_TOKEN=...
# Verify: aws sts get-caller-identity
# Loot: aws s3 ls && aws iam list-users && aws ec2 describe-instances
EOF

# GCP metadata
cat >> $WORKSPACE/recon/cloud/aws_imds_probes.txt << 'EOF'
# GCP Metadata (via SSRF):
# GET http://metadata.google.internal/computeMetadata/v1/  Header: Metadata-Flavor: Google
# GET http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token  Header: Metadata-Flavor: Google
# Returns: access_token for GCP APIs
EOF

# Azure IMDS
cat >> $WORKSPACE/recon/cloud/aws_imds_probes.txt << 'EOF'
# Azure IMDS (via SSRF):
# GET http://169.254.169.254/metadata/instance?api-version=2021-02-01  Header: Metadata: true
# GET http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/  Header: Metadata: true
# Returns: access_token for Azure management API
EOF
```

### 16.2 Kubernetes Recon

```bash
HOST=$(echo ${TARGET:-"target.com"} | sed 's|https\?://||')

# K8s API server
for port in 6443 8443 8080 443; do
  STATUS=$(curl -sk -o /dev/null -w "%{http_code}" "https://$HOST:$port/api" 2>/dev/null)
  [ "$STATUS" = "200" ] && echo "[!!] K8s API on $port" | tee -a $WORKSPACE/recon/cloud/k8s.txt && \
    curl -sk "https://$HOST:$port/api/v1/namespaces" | jq '.items[].metadata.name' 2>/dev/null >> \
    $WORKSPACE/recon/cloud/k8s.txt
done

# Kubelet (unauthenticated in old clusters = immediate code exec)
for port in 10250 10255; do
  STATUS=$(curl -sk -o /dev/null -w "%{http_code}" "https://$HOST:$port/pods" 2>/dev/null)
  if [ "$STATUS" = "200" ]; then
    echo "[!!] Kubelet EXPOSED on $port — pod exec available!" | tee -a $WORKSPACE/vulns/confirmed/k8s_exposed.txt
    # List all pods
    curl -sk "https://$HOST:$port/pods" | jq '.items[] | {name:.metadata.name, ns:.metadata.namespace}' | \
      head -20 >> $WORKSPACE/vulns/confirmed/k8s_exposed.txt
    # Execute command in pod (if write kubelet):
    # curl -sk "https://$HOST:10250/run/<namespace>/<pod>/<container>" -d "cmd=id"
  fi
done

# etcd
STATUS=$(curl -sk -o /dev/null -w "%{http_code}" "http://$HOST:2379/v2/keys/" 2>/dev/null)
[ "$STATUS" = "200" ] && echo "[!!] etcd EXPOSED — all k8s secrets available!" | \
  tee $WORKSPACE/vulns/confirmed/etcd_exposed.txt && \
  curl -sk "http://$HOST:2379/v2/keys/?recursive=true" | python3 -m json.tool | head -100 >> \
  $WORKSPACE/vulns/confirmed/etcd_exposed.txt
```

---

## PHASE 17 — SOCIAL ENGINEERING RECON

### 17.1 Employee Enumeration

```bash
TARGET="target.com"
COMPANY=$(echo $TARGET | cut -d. -f1)

# GitHub employees
curl -s "https://api.github.com/search/users?q=$COMPANY+in:company&per_page=30" \
  -H "Authorization: token $GITHUB_TOKEN" 2>/dev/null | \
  jq '.items[] | {login:.login,name:.name,company:.company,email:.email}' | \
  tee $WORKSPACE/recon/osint/github_employees.txt

# LinkedIn (manual search URLs)
cat > $WORKSPACE/recon/osint/linkedin_searches.txt << EOF
https://www.linkedin.com/search/results/people/?keywords=$COMPANY
https://www.linkedin.com/company/$COMPANY/people/
site:linkedin.com/in "$COMPANY"
EOF

# HackerOne program staff
curl -s "https://hackerone.com/graphql" -X POST \
  -H "Content-Type: application/json" \
  -d "{\"query\":\"{ team(handle: \\\"$COMPANY\\\") { members { edges { node { user { username } } } } } }\"}" 2>/dev/null | \
  jq '.data.team.members.edges[].node.user.username' 2>/dev/null | \
  tee $WORKSPACE/recon/osint/h1_team.txt
```

### 17.2 Internal Tool Exposure

```bash
TARGET_DOMAIN="target.com"
COMPANY=$(echo $TARGET_DOMAIN | cut -d. -f1)

# Check common internal tool subdomains
for subdomain in docs wiki confluence help desk jira gitlab github jenkins ci staging dev \
                 intranet internal vpn remote support admin portal status monitoring; do
  STATUS=$(curl -sk -o /dev/null -w "%{http_code}" "https://$subdomain.$TARGET_DOMAIN" 2>/dev/null)
  [ "$STATUS" != "404" ] && [ "$STATUS" != "000" ] && \
    echo "[$STATUS] $subdomain.$TARGET_DOMAIN" | tee -a $WORKSPACE/recon/osint/internal_tools.txt
done

# Notion public pages (search)
echo "Manual: https://www.notion.so/search?q=$COMPANY" >> $WORKSPACE/recon/osint/internal_tools.txt
echo "Manual: site:notion.so $COMPANY" >> $WORKSPACE/recon/osint/internal_tools.txt

# Trello public boards
echo "Manual: site:trello.com $COMPANY" >> $WORKSPACE/recon/osint/internal_tools.txt
```

### 17.3 SPF/DMARC Analysis for Phishing

```bash
TARGET="target.com"

echo "=== Email Security ===" > $WORKSPACE/recon/osint/email_security.txt

SPF=$(dig $TARGET TXT +short 2>/dev/null | grep "v=spf1")
echo "SPF: ${SPF:-NONE}" >> $WORKSPACE/recon/osint/email_security.txt
[ -z "$SPF" ] && echo "[!!] NO SPF — domain spoofing possible" >> $WORKSPACE/recon/osint/email_security.txt
echo "$SPF" | grep -qE "\+all|\?all" && echo "[!!] WEAK SPF — spoofing possible" >> $WORKSPACE/recon/osint/email_security.txt

DMARC=$(dig _dmarc.$TARGET TXT +short 2>/dev/null)
echo "DMARC: ${DMARC:-NONE}" >> $WORKSPACE/recon/osint/email_security.txt
[ -z "$DMARC" ] && echo "[!!] NO DMARC — no enforcement" >> $WORKSPACE/recon/osint/email_security.txt
echo "$DMARC" | grep -qE "p=none" && echo "[!!] DMARC p=none — monitor only, spoofing works" >> $WORKSPACE/recon/osint/email_security.txt

for selector in default google mail email k1 s1 s2 dkim selector1 selector2 smtp; do
  DKIM=$(dig ${selector}._domainkey.$TARGET TXT +short 2>/dev/null | grep "v=DKIM")
  [ -n "$DKIM" ] && echo "DKIM [$selector]: $DKIM" >> $WORKSPACE/recon/osint/email_security.txt
done

cat $WORKSPACE/recon/osint/email_security.txt
```

---

## PHASE 18 — AUTOMATED FULL RECON SCRIPT

```bash
#!/usr/bin/env bash
# full_recon.sh — Automated complete engagement recon
# Usage: ./full_recon.sh target.com [LHOST]
# Requires: subfinder dnsx httpx ffuf gau waybackurls katana nuclei nmap curl jq python3

TARGET="${1:?Usage: $0 target.com}"
LHOST="${2:-}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
WORKSPACE=~/recon_${TIMESTAMP}_${TARGET//[^a-zA-Z0-9]/_}
GITHUB_TOKEN="${GITHUB_TOKEN:-}"

# === SETUP ===
mkdir -p $WORKSPACE/{recon/{dns,subdomains,ports,http,tech,osint,js/{downloaded,secrets},cloud,api,cicd},vulns/{confirmed,potential,research},exploits/{working,attempted},loot/{credentials,data,flags}}

exec > >(tee -a $WORKSPACE/continuous.md) 2>&1
echo "=== RECON STARTED: $TARGET at $(date) ==="
echo "=== Workspace: $WORKSPACE ==="

TARGET_HOST=$(echo "$TARGET" | sed 's|https\?://||' | sed 's|/.*||')
TARGET_IP=$(dig +short $TARGET_HOST A | head -1)
echo "[*] Host: $TARGET_HOST"
echo "[*] IP: $TARGET_IP"

# === PHASE 1: PASSIVE SUBDOMAIN ENUM (parallel) ===
echo "=== PHASE 1: PASSIVE DNS ==="
(
  subfinder -d $TARGET_HOST -o $WORKSPACE/recon/subdomains/subfinder.txt -all -silent -timeout 30 2>/dev/null &
  assetfinder --subs-only $TARGET_HOST > $WORKSPACE/recon/subdomains/assetfinder.txt 2>/dev/null &
  curl -s "https://crt.sh/?q=%25.$TARGET_HOST&output=json" 2>/dev/null | \
    jq -r '.[].name_value' | sed 's/\*\.//g' | tr ',' '\n' | sort -u \
    > $WORKSPACE/recon/subdomains/crtsh.txt &
  for rtype in A AAAA MX NS TXT SOA CNAME SRV CAA; do
    dig $TARGET_HOST $rtype +noall +answer 2>/dev/null >> $WORKSPACE/recon/dns/all_records.txt
  done &
  gau --providers wayback,commoncrawl,otx,urlscan $TARGET_HOST \
    > $WORKSPACE/recon/osint/gau_urls.txt 2>/dev/null &
  whois $TARGET_HOST > $WORKSPACE/recon/osint/whois.txt 2>/dev/null &
  wait
)

# Zone transfers
for ns in $(dig $TARGET_HOST NS +short 2>/dev/null | sed 's/\.$//'); do
  dig axfr $TARGET_HOST @$ns 2>/dev/null | awk '{print $1}' | \
    sed 's/\.$//;/^$/d' >> $WORKSPACE/recon/subdomains/zone_transfer.txt
done

# Consolidate subdomains
cat $WORKSPACE/recon/subdomains/*.txt 2>/dev/null | \
  grep -v "^\*" | grep "\.$TARGET_HOST$\|^$TARGET_HOST$" | \
  sort -u > $WORKSPACE/recon/subdomains/all_subdomains.txt
SUBDOMAIN_COUNT=$(wc -l < $WORKSPACE/recon/subdomains/all_subdomains.txt)
echo "[+] Subdomains: $SUBDOMAIN_COUNT"

# Resolve
dnsx -l $WORKSPACE/recon/subdomains/all_subdomains.txt \
  -o $WORKSPACE/recon/subdomains/resolved.txt -a -cname -resp -silent 2>/dev/null
echo "[+] Resolved: $(wc -l < $WORKSPACE/recon/subdomains/resolved.txt)"

# === PHASE 2: ACTIVE RECON (parallel) ===
echo "=== PHASE 2: ACTIVE RECON ==="
(
  # Port scan main target
  nmap -sV -sC -T4 --top-ports 1000 $TARGET_IP \
    -oA $WORKSPACE/recon/ports/nmap_top1000 2>/dev/null &
  # HTTP fingerprint all subdomains
  httpx -l $WORKSPACE/recon/subdomains/resolved.txt \
    -title -tech-detect -status-code -web-server -ip -cdn \
    -o $WORKSPACE/recon/http/all_hosts.json -json -silent -threads 50 2>/dev/null &
  # WAF detection
  wafw00f "https://$TARGET_HOST" -o $WORKSPACE/recon/tech/waf.txt 2>/dev/null &
  wait
)

# === PHASE 3: CONTENT DISCOVERY ===
echo "=== PHASE 3: CONTENT DISCOVERY ==="
BASE_URL="https://$TARGET_HOST"

# ffuf directories
DIRLIST=""
for wl in /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
          /usr/share/seclists/Discovery/Web-Content/common.txt \
          /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt; do
  [ -f "$wl" ] && DIRLIST="$wl" && break
done

[ -n "$DIRLIST" ] && ffuf -u "$BASE_URL/FUZZ" -w $DIRLIST \
  -ac -mc 200,201,204,301,302,401,403,405 -t 50 -timeout 10 -rate 80 \
  -o $WORKSPACE/recon/http/ffuf_dirs.json -of json -silent 2>/dev/null

# Sensitive files
for path in /.env /.git/HEAD /api/swagger.json /swagger-ui.html /actuator /actuator/env \
            /phpinfo.php /wp-config.php /config.php /.env.production; do
  STATUS=$(curl -sk -o /dev/null -w "%{http_code}" "$BASE_URL$path" 2>/dev/null)
  [ "$STATUS" = "200" ] && echo "[!!] EXPOSED: $path" | tee -a $WORKSPACE/loot/data/sensitive_files.txt && \
    curl -sk "$BASE_URL$path" > "$WORKSPACE/loot/data/$(echo $path | tr '/' '_').txt" 2>/dev/null
done

# === PHASE 4: JS ANALYSIS ===
echo "=== PHASE 4: JS ANALYSIS ==="
curl -sk "$BASE_URL" | grep -oP '(?:src=")[^"]*\.js[^"]*' | sed 's/src="//g' | \
  while read js; do
    [ "${js:0:4}" != "http" ] && js="$BASE_URL$js"
    fname=$(echo "$js" | sed 's|.*/||;s/[?#].*//')
    curl -sk "$js" -o "$WORKSPACE/recon/js/downloaded/$fname" 2>/dev/null
  done

# Secret search
find $WORKSPACE/recon/js/downloaded -name "*.js" 2>/dev/null | \
  xargs grep -oP '(?:api_key|apikey|secret|token|password|auth|bearer)["\s:=]+["\x27]?[a-zA-Z0-9_\-/+]{16,}' \
  2>/dev/null > $WORKSPACE/recon/js/secrets/js_secrets.txt
grep -oP 'AKIA[A-Z0-9]{16}' $WORKSPACE/recon/js/downloaded/*.js 2>/dev/null >> $WORKSPACE/loot/credentials/aws_keys.txt

# === PHASE 5: CLOUD RECON (parallel) ===
echo "=== PHASE 5: CLOUD RECON ==="
COMPANY=$(echo $TARGET_HOST | cut -d. -f1)
(
  # S3 buckets
  for suffix in "" -dev -prod -staging -backup -data -assets -media -static -files -uploads; do
    bucket="${COMPANY}${suffix}"
    STATUS=$(curl -sk -o /dev/null -w "%{http_code}" "https://${bucket}.s3.amazonaws.com/" 2>/dev/null)
    [ "$STATUS" = "200" ] && echo "[!!] PUBLIC S3: $bucket" | tee -a $WORKSPACE/recon/cloud/s3_public.txt
    [ "$STATUS" = "403" ] && echo "[+] S3 exists: $bucket" >> $WORKSPACE/recon/cloud/s3_private.txt
  done &
  # Firebase
  for app in $COMPANY ${COMPANY}app ${COMPANY}-app; do
    STATUS=$(curl -sk -o /dev/null -w "%{http_code}" "https://${app}.firebaseio.com/.json" 2>/dev/null)
    [ "$STATUS" = "200" ] && echo "[!!] PUBLIC Firebase: $app" | tee -a $WORKSPACE/recon/cloud/firebase.txt
  done &
  wait
)

# === PHASE 6: NUCLEI SCANNING ===
echo "=== PHASE 6: NUCLEI ==="
nuclei -u "https://$TARGET_HOST" \
  -t ~/.nuclei-templates/ \
  -severity critical,high,medium \
  -o $WORKSPACE/vulns/potential/nuclei.txt \
  -silent 2>/dev/null | head -50

# === PHASE 7: API RECON ===
echo "=== PHASE 7: API RECON ==="
for path in /swagger.json /api/swagger.json /openapi.json /api/openapi.json \
            /api-docs /swagger-ui.html /graphql; do
  STATUS=$(curl -sk -o /dev/null -w "%{http_code}" "$BASE_URL$path" 2>/dev/null)
  [ "$STATUS" = "200" ] && echo "[+] API docs: $path" | tee -a $WORKSPACE/recon/api/found.txt && \
    curl -sk "$BASE_URL$path" > "$WORKSPACE/recon/api/$(echo $path | tr '/' '_').txt" 2>/dev/null
done

# GraphQL introspection
STATUS=$(curl -sk -o /dev/null -w "%{http_code}" -X POST "$BASE_URL/graphql" \
  -H "Content-Type: application/json" -d '{"query":"{__typename}"}' 2>/dev/null)
[ "$STATUS" = "200" ] && echo "[+] GraphQL found!" | tee -a $WORKSPACE/recon/api/found.txt && \
  curl -sk -X POST "$BASE_URL/graphql" -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { queryType{name} types { name kind } } }"}' | \
  python3 -m json.tool > $WORKSPACE/recon/api/graphql_schema.json 2>/dev/null

# === GENERATE SUMMARY ===
echo ""
echo "=== RECON COMPLETE: $(date) ==="
echo "=== TARGET PROFILE ===" | tee $WORKSPACE/target-profile.md
{
echo "# Target Profile: $TARGET_HOST"
echo "Date: $(date)"
echo ""
echo "## Core"
echo "- Domain: $TARGET_HOST"
echo "- IP: $TARGET_IP"
echo "- ASN: $(curl -s https://ipinfo.io/$TARGET_IP/org 2>/dev/null)"
echo ""
echo "## Subdomains"
echo "- Total: $SUBDOMAIN_COUNT"
echo "- Resolved: $(wc -l < $WORKSPACE/recon/subdomains/resolved.txt 2>/dev/null)"
echo ""
echo "## Open Ports"
grep "open" $WORKSPACE/recon/ports/nmap_top1000.nmap 2>/dev/null | awk '{print "- "$0}'
echo ""
echo "## Technologies"
jq -r '.tech[]? // empty' $WORKSPACE/recon/http/all_hosts.json 2>/dev/null | sort -u | while read t; do echo "- $t"; done
echo ""
echo "## WAF"
cat $WORKSPACE/recon/tech/waf.txt 2>/dev/null | grep -v "^#"
echo ""
echo "## Cloud"
cat $WORKSPACE/recon/cloud/s3_public.txt 2>/dev/null | head -10
cat $WORKSPACE/recon/cloud/firebase.txt 2>/dev/null | head -5
echo ""
echo "## High-Value Findings"
cat $WORKSPACE/loot/data/sensitive_files.txt 2>/dev/null
cat $WORKSPACE/vulns/confirmed/*.txt 2>/dev/null | head -20
echo ""
echo "## Nuclei Findings"
cat $WORKSPACE/vulns/potential/nuclei.txt 2>/dev/null | head -20
} | tee -a $WORKSPACE/target-profile.md

echo ""
echo "[*] Full workspace: $WORKSPACE"
echo "[*] Summary: $WORKSPACE/target-profile.md"
echo "[*] Continuous log: $WORKSPACE/continuous.md"
```

---

## KEY SOURCES REFERENCE

| Source | URL | Use For |
|---|---|---|
| crt.sh | https://crt.sh | CT log subdomain enum |
| Shodan | https://shodan.io | Passive port/service data |
| Censys | https://search.censys.io | Host/cert search |
| URLScan | https://urlscan.io | JS/endpoint discovery |
| VirusTotal | https://virustotal.com | Passive subdomain enum |
| SecurityTrails | https://securitytrails.com | DNS history |
| FOFA | https://fofa.info | China-hosted asset search |
| Hunter.io | https://hunter.io | Email format detection |
| HIBP | https://haveibeenpwned.com | Breach checking |
| BuiltWith | https://builtwith.com | Technology profiling |
| Wappalyzer | https://wappalyzer.com | Tech fingerprint |
| nomi-sec | https://github.com/nomi-sec/PoC-in-GitHub | PoC index |
| CISA KEV | https://cisa.gov/known-exploited-vulnerabilities | Active exploitation |
