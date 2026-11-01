# FOXHOLE HARNESS

An offensive security opencode harness. Installs a fully configured boss agent + pi agent with 8 offensive security skills, 10 MCP servers, and auto-allow permissions on any Linux or macOS system in one command.

## What it installs

**Boss agent** — primary agent for all general tasks. Routes security work directly to pi without re-delegation.

**Pi agent** — autonomous offensive security operator. Runs authorized engagements end-to-end: recon, enumeration, vulnerability research, exploitation, post-exploitation, reporting. Auto-loads 8 skills at session start.

**8 pi skills:**
- `exploit-research` — CVE/NVD/ExploitDB research, PoC hunting, ranked attack queue
- `web-recon` — full web app recon: passive DNS, subdomain enum, HTTP fingerprinting, JS analysis
- `payload-craft` — complete payload library: reverse shells, web shells, SQLi, XSS, SSRF, LFI, XXE, SSTI, deserialization, WAF bypass
- `report-gen` — professional pentest report generation with evidence tracking
- `zeroday` — novel vuln discovery from scratch: fuzzing, source analysis, chain construction
- `chain-detection` — exploit chain construction from confirmed findings, 23-chain taxonomy
- `engagement-logger` — continuous.md logging protocol, cross-session resume
- `waf-bypass` — WAF fingerprinting, origin IP discovery, per-vendor evasion techniques

**10 MCP servers:**
- memory, filesystem, fetch, git, duckduckgo, playwright, sqlite, github, time, sequential-thinking

## Requirements

- [opencode](https://opencode.ai) installed
- Node.js + npx
- `uv` / `uvx` — `curl -LsSf https://astral.sh/uv/install.sh | sh`
- A GitHub personal access token (for GitHub MCP)

## Install

```bash
git clone https://github.com/brighteyekid/foxhole-harness 
cd foxhole-harness
chmod +x install.sh
./install.sh --github-token <your-github-token>
```

Optional flags:
```bash
./install.sh --github-token <token> --model <model-string>
```

Default model is `anthropic-middleware/sonnet5`. Override with `--model` for any opencode-supported model.

## Post-install

1. Run `opencode`
2. Click the agent switcher (bottom left)
3. Select `pi` (red) for offensive security work
4. Select `boss` (default) for everything else

Pi auto-loads all 8 skills before your first message.

## Pentest tools (recommended)

Pi works best with these installed:

```bash
# Ubuntu/Debian
sudo apt install nmap gobuster sqlmap dnsutils

# Go tools
go install github.com/ffuf/ffuf/v2@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest

# Python
pip install wafw00f

# SecLists
git clone https://github.com/danielmiessler/SecLists ~/SecLists
```

## Structure

```
foxhole-harness/
├── install.sh              # one-shot installer
├── README.md
├── config/
│   ├── opencode.json       # MCP servers, model, permissions
│   ├── AGENTS.md           # global engineering standards + security routing rules
│   ├── instruction.md      # pi base system prompt
│   ├── agents/
│   │   └── pi.md           # pi agent definition
│   └── prompts/
│       ├── base.md
│       ├── behavior.md
│       ├── doctrine.md
│       └── offense-full.md
└── skills/
    ├── exploit-research/SKILL.md
    ├── web-recon/SKILL.md
    ├── payload-craft/SKILL.md
    ├── report-gen/SKILL.md
    ├── zeroday/SKILL.md
    ├── chain-detection/SKILL.md
    ├── engagement-logger/SKILL.md
    └── waf-bypass/SKILL.md
```

## Update existing install

```bash
git pull
./install.sh
```

Existing config is overwritten. Back up any local customizations before updating.

## Notes

- GitHub token is stored at `~/.config/opencode/github.key` (chmod 600)
- SQLite MCP database is at `~/.config/opencode/data/opencode.db`
- Pi agent permissions are auto-allow — no confirmation prompts for bash commands
- Boss agent routes all security tasks directly to pi without asking
