#!/usr/bin/env bash
set -euo pipefail

# ─────────────────────────────────────────────────────────────
# FOXHOLE HARNESS — opencode installer
# Installs the full pi agent + boss config on any Linux/macOS system
# Usage: ./install.sh [--github-token <token>] [--model <model>]
# ─────────────────────────────────────────────────────────────

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OPENCODE_DIR="$HOME/.config/opencode"
SKILLS_DIR="$HOME/.agents/skills"
DATA_DIR="$OPENCODE_DIR/data"
AGENTS_DIR="$OPENCODE_DIR/agents"
PROMPTS_DIR="$OPENCODE_DIR/prompts"

GITHUB_TOKEN=""
MODEL="anthropic-middleware/sonnet5"

# ── parse args ──────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case $1 in
    --github-token) GITHUB_TOKEN="$2"; shift 2 ;;
    --model)        MODEL="$2";         shift 2 ;;
    *)              shift ;;
  esac
done

# ── colors ───────────────────────────────────────────────────
RED='\033[0;31m'
GRN='\033[0;32m'
CYN='\033[0;36m'
DIM='\033[2m'
RST='\033[0m'

log()  { echo -e "${CYN}[foxhole]${RST} $*"; }
ok()   { echo -e "${GRN}[ok]${RST} $*"; }
warn() { echo -e "${RED}[warn]${RST} $*"; }

echo ""
echo -e "${RED}███████╗ ██████╗ ██╗  ██╗██╗  ██╗ ██████╗ ██╗     ███████╗${RST}"
echo -e "${RED}██╔════╝██╔═══██╗╚██╗██╔╝██║  ██║██╔═══██╗██║     ██╔════╝${RST}"
echo -e "${RED}█████╗  ██║   ██║ ╚███╔╝ ███████║██║   ██║██║     █████╗  ${RST}"
echo -e "${RED}██╔══╝  ██║   ██║ ██╔██╗ ██╔══██║██║   ██║██║     ██╔══╝  ${RST}"
echo -e "${RED}██║     ╚██████╔╝██╔╝ ██╗██║  ██║╚██████╔╝███████╗███████╗${RST}"
echo -e "${RED}╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚══════╝${RST}"
echo -e "${DIM}        opencode offensive harness installer${RST}"
echo ""

# ── check dependencies ───────────────────────────────────────
log "Checking dependencies..."

check_cmd() {
  if command -v "$1" &>/dev/null; then
    ok "$1 found"
  else
    warn "$1 not found — $2"
  fi
}

check_cmd opencode "install from https://opencode.ai"
check_cmd node     "install from https://nodejs.org"
check_cmd npx      "comes with node"
check_cmd uvx      "install uv: curl -LsSf https://astral.sh/uv/install.sh | sh"
check_cmd git      "install with your package manager"

# ── detect OS ────────────────────────────────────────────────
OS="linux"
if [[ "$OSTYPE" == "darwin"* ]]; then
  OS="macos"
fi
log "Detected OS: $OS"

# ── create directory structure ───────────────────────────────
log "Creating directory structure..."
mkdir -p "$OPENCODE_DIR"
mkdir -p "$SKILLS_DIR"
mkdir -p "$DATA_DIR"
mkdir -p "$AGENTS_DIR"
mkdir -p "$PROMPTS_DIR"
ok "Directories created"

# ── install config files ─────────────────────────────────────
log "Installing config files..."

# AGENTS.md (global engineering standards + security routing)
cp "$REPO_DIR/config/AGENTS.md" "$OPENCODE_DIR/AGENTS.md"
ok "AGENTS.md installed"

# instruction.md (pi agent system prompt base)
cp "$REPO_DIR/config/instruction.md" "$OPENCODE_DIR/instruction.md"
ok "instruction.md installed"

# prompts/
cp "$REPO_DIR/config/prompts/"*.md "$PROMPTS_DIR/"
ok "prompts installed ($(ls "$REPO_DIR/config/prompts/"*.md | wc -l | tr -d ' ') files)"

# agents/pi.md
cp "$REPO_DIR/config/agents/pi.md" "$AGENTS_DIR/pi.md"
ok "pi agent installed"

# ── install opencode.json ────────────────────────────────────
log "Installing opencode.json..."

# resolve $USER in the config
sed "s|\$USER|$USER|g" "$REPO_DIR/config/opencode.json" > "$OPENCODE_DIR/opencode.json"

# inject model if overridden
if [[ "$MODEL" != "anthropic-middleware/sonnet5" ]]; then
  if command -v python3 &>/dev/null; then
    python3 -c "
import json
with open('$OPENCODE_DIR/opencode.json') as f:
    d = json.load(f)
d['model'] = '$MODEL'
with open('$OPENCODE_DIR/opencode.json', 'w') as f:
    json.dump(d, f, indent=2)
"
    ok "Model set to $MODEL"
  fi
fi

ok "opencode.json installed"

# ── install github token if provided ─────────────────────────
if [[ -n "$GITHUB_TOKEN" ]]; then
  log "Installing GitHub token..."
  echo -n "$GITHUB_TOKEN" > "$OPENCODE_DIR/github.key"
  chmod 600 "$OPENCODE_DIR/github.key"
  ok "GitHub token saved to $OPENCODE_DIR/github.key"
else
  warn "No GitHub token provided. GitHub MCP will not work."
  warn "Run: echo -n '<your-token>' > $OPENCODE_DIR/github.key"
fi

# ── install skills ───────────────────────────────────────────
log "Installing pi skills..."

SKILLS=(
  "exploit-research"
  "web-recon"
  "payload-craft"
  "report-gen"
  "zeroday"
  "chain-detection"
  "engagement-logger"
  "waf-bypass"
)

for skill in "${SKILLS[@]}"; do
  src="$REPO_DIR/skills/$skill/SKILL.md"
  dst="$SKILLS_DIR/$skill/SKILL.md"
  mkdir -p "$SKILLS_DIR/$skill"
  if [[ -f "$src" ]]; then
    cp "$src" "$dst"
    ok "skill: $skill ($(wc -l < "$src") lines)"
  else
    warn "skill not found: $skill"
  fi
done

# ── install pentest tools (optional) ────────────────────────
echo ""
log "Checking pentest tools..."

TOOLS=(
  "nmap:nmap"
  "ffuf:go install github.com/ffuf/ffuf/v2@latest"
  "gobuster:sudo apt install gobuster / brew install gobuster"
  "subfinder:go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  "httpx:go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
  "nuclei:go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
  "katana:go install github.com/projectdiscovery/katana/cmd/katana@latest"
  "wafw00f:pip install wafw00f"
  "sqlmap:sudo apt install sqlmap / brew install sqlmap"
  "dig:sudo apt install dnsutils / brew install bind"
)

MISSING=()
for entry in "${TOOLS[@]}"; do
  cmd="${entry%%:*}"
  hint="${entry#*:}"
  if command -v "$cmd" &>/dev/null; then
    ok "$cmd"
  else
    warn "$cmd missing — $hint"
    MISSING+=("$cmd")
  fi
done

if [[ ${#MISSING[@]} -gt 0 ]]; then
  echo ""
  warn "${#MISSING[@]} tools missing. Install them for full pi capability."
fi

# ── SecLists check ───────────────────────────────────────────
echo ""
log "Checking SecLists..."
if [[ -d "$HOME/SecLists" ]]; then
  ok "SecLists found at ~/SecLists"
elif [[ -d "/usr/share/seclists" ]]; then
  ok "SecLists found at /usr/share/seclists"
else
  warn "SecLists not found. Install: git clone https://github.com/danielmiessler/SecLists ~/SecLists"
fi

# ── done ─────────────────────────────────────────────────────
echo ""
echo -e "${GRN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}"
echo -e "${GRN}  FOXHOLE HARNESS INSTALLED${RST}"
echo -e "${GRN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}"
echo ""
echo -e "  Config:  ${CYN}$OPENCODE_DIR${RST}"
echo -e "  Skills:  ${CYN}$SKILLS_DIR${RST} (${#SKILLS[@]} pi skills)"
echo -e "  Agents:  ${CYN}$AGENTS_DIR${RST}"
echo ""
echo -e "  Start opencode:  ${CYN}opencode${RST}"
echo -e "  Switch to pi:    ${CYN}agent switcher → pi (red)${RST}"
echo ""
echo -e "${DIM}  Boss agent handles all general tasks.${RST}"
echo -e "${DIM}  Pi agent handles all offensive security tasks.${RST}"
echo -e "${DIM}  Pi auto-loads 8 skills at session start.${RST}"
echo ""