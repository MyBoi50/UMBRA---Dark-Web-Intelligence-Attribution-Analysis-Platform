# UMBRA V3.1 — KALI LINUX OPERATIONAL GUIDE
### NIA / Law Enforcement Use Only | Dark Web Intelligence Platform
---

## OVERVIEW

This guide covers the complete operational procedure for running UMBRA V3.1 on Kali Linux — from system preparation and hardening to execution, analysis, and secure shutdown. Follow every step in order.

---

## PHASE 1 — SYSTEM PREPARATION

### 1.1 Update and Harden Kali

```bash
# Full system update
sudo apt update && sudo apt full-upgrade -y

# Install required packages
sudo apt install -y tor torsocks python3-pip python3-venv \
    nodejs npm curl wget git ufw apparmor apparmor-utils \
    net-tools nmap macchanger

# Disable unnecessary network services
sudo systemctl disable bluetooth avahi-daemon cups 2>/dev/null
sudo systemctl stop bluetooth avahi-daemon cups 2>/dev/null
```

### 1.2 Harden the Network (UFW Firewall)

```bash
# Enable UFW and deny all by default
sudo ufw default deny incoming
sudo ufw default deny outgoing

# Only allow Tor and loopback traffic
sudo ufw allow out on lo
sudo ufw allow in on lo
sudo ufw allow out 9050/tcp   # Tor SOCKS proxy
sudo ufw allow out 9051/tcp   # Tor control port
sudo ufw allow out 443/tcp    # Tor directory (HTTPS)
sudo ufw allow out 80/tcp     # Tor directory (HTTP, fallback)

# Allow backend API only on loopback (NEVER expose to network)
sudo ufw allow in on lo to any port 8000

sudo ufw enable
sudo ufw status verbose
```

### 1.3 MAC Address Randomization (if running on hardware)

```bash
# Identify interface
ip link show

# Randomize MAC before connecting to any network
sudo ip link set <INTERFACE> down
sudo macchanger -r <INTERFACE>
sudo ip link set <INTERFACE> up

# Verify
macchanger -s <INTERFACE>
```
Replace `<INTERFACE>` with your interface name (e.g., `eth0`, `wlan0`).

---

## PHASE 2 — TOR CONFIGURATION

### 2.1 Configure Tor for UMBRA

```bash
sudo nano /etc/tor/torrc
```

Add or ensure these lines are present:

```
# SOCKS proxy for application use
SOCKSPort 127.0.0.1:9050

# Control port for new circuit requests
ControlPort 9051
CookieAuthentication 1

# Prevent DNS leaks
DNSPort 53
AutomapHostsOnResolve 1
AutomapHostsSuffixes .onion,.exit

# Strict isolation (prevents circuit reuse across targets)
IsolateDestAddr 1
IsolateDestPort 1

# Longer circuit timeouts for hidden services
CircuitBuildTimeout 60
LearnCircuitBuildTimeout 0

# Entry node country restrictions (India/preferred)
# EntryNodes {in},{us},{de} StrictNodes 1   # Optional: pin entry nodes

# Increase connection limits for hidden service crawling
MaxCircuitDirtiness 600
NewCircuitPeriod 30
```

### 2.2 Start and Verify Tor

```bash
# Start Tor
sudo systemctl start tor
sudo systemctl enable tor

# Wait 10 seconds for circuit building
sleep 10

# Verify Tor is working
curl --socks5-hostname 127.0.0.1:9050 http://check.torproject.org/api/ip

# Expected output:
# {"IsTor":true,"IP":"x.x.x.x"}
```

If you don't see `"IsTor":true`, do not proceed. Check logs:
```bash
sudo journalctl -u tor -n 50
```

---

## PHASE 3 — PYTHON ENVIRONMENT SETUP

### 3.1 Create Isolated Virtual Environment

```bash
# Create working directory
mkdir -p ~/umbra && cd ~/umbra

# Create virtual environment (isolated from system Python)
python3 -m venv .venv

# Activate it — ALWAYS activate before working
source .venv/bin/activate

# Verify activation
which python3
# Should show: /root/umbra/.venv/bin/python3
```

### 3.2 Install Python Dependencies

```bash
pip install --upgrade pip

pip install fastapi uvicorn "requests[socks]" PySocks stem \
    beautifulsoup4 lxml pydantic mmh3

# Verify critical packages
python3 -c "import fastapi, requests, socks, stem, bs4; print('All dependencies OK')"
```

---

## PHASE 4 — FRONTEND SETUP (React)

### 4.1 Install Node.js and Dependencies

```bash
# Check Node version (need 18+)
node --version

# If outdated, install via nvm:
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash
source ~/.bashrc
nvm install 20
nvm use 20

# Create React app
cd ~/umbra
npx create-react-app frontend --template javascript
cd frontend

# Install required packages
npm install d3

# Replace the default App.jsx with the UMBRA frontend
cp /path/to/umbra_v3_frontend.jsx src/App.jsx

# Start development server (localhost only)
npm start
# Opens at http://localhost:3000
```

> **Security note**: React dev server binds to localhost by default. Never expose port 3000 externally.

---

## PHASE 5 — RUNNING UMBRA V3.1

### 5.1 Pre-flight Checklist (Run Every Session)

```bash
# [1] Verify Tor is active
curl --socks5-hostname 127.0.0.1:9050 http://check.torproject.org/api/ip | python3 -m json.tool

# [2] Check no DNS leaks (all DNS must go through Tor)
sudo netstat -tuln | grep ':53'

# [3] Verify firewall
sudo ufw status | head -20

# [4] Check no unexpected network connections
ss -tuln
```

### 5.2 Start the Backend

```bash
cd ~/umbra
source .venv/bin/activate

# Start backend
python3 umbra_v3_backend.py

# Expected output:
# ============================================================
#   UMBRA V3.1 — Dark Web Intelligence Platform
#   NIA / Law Enforcement Use Only
# ============================================================
#   API: http://localhost:8000
#   Docs: http://localhost:8000/docs
```

Backend API confirms at: `http://localhost:8000/docs`

### 5.3 Start the Frontend (separate terminal)

```bash
cd ~/umbra/frontend
npm start
# Browser opens at http://localhost:3000
```

### 5.4 Verify Full Stack

In the UI, click **CHECK TOR**. You should see:
```
TOR ACTIVE · <exit_node_ip>
```

If not, the backend cannot reach Tor. Check port 9050.

---

## PHASE 6 — CONDUCTING AN ANALYSIS

### 6.1 Target Entry

1. Open `http://localhost:3000`
2. Click **CHECK TOR** — must show TOR ACTIVE
3. Paste the `.onion` URL in the target field
4. Click **▶ CONNECT TOR → FETCH → 13-MODULE ANALYSIS**

### 6.2 What Gets Extracted

| Module | What It Finds |
|--------|---------------|
| IP Intelligence | IPv4+IPv6 from all proxy headers + page source |
| X-Forwarded-For | Full proxy chain, position 0 = real client IP |
| RFC 7239 Forwarded | `for=` parameter extraction, IPv6 brackets |
| X-Real-IP / CF-Connecting-IP | Single real-IP headers |
| PGP Keyserver | Fingerprint → email → identity chain |
| GitHub/Reddit | Username → real name/email/location |
| Analytics IDs | GA/FB/Stripe → links to clearnet identity |
| Favicon Hash | Shodan query to find same server on clearnet |
| Stylometry | Language fingerprint, writing style |
| Blockchain | BTC balance, exchange label → KYC process |

### 6.3 Interpreting IP Intelligence Results

**CRITICAL — Header leaks** (red badge):
- Operator's hidden service is running behind a **misconfigured reverse proxy**
- The leftmost IP in X-Forwarded-For chain (`chain_position: 0`) is the **real client IP**
- IPv6 addresses are equally valid — geolocate them immediately
- RFC 7239 `for=` parameter = same significance as X-Forwarded-For position 0

**RESIDENTIAL IP** (green badge):
- Not a VPN or datacenter
- Send legal process **directly to the ISP** for subscriber identity
- Include: IP address, date, time (UTC), port if available

**DATACENTER IP** (orange badge):
- VPS or cloud hosting (DigitalOcean, Hetzner, OVH, etc.)
- Send **abuse request** to hosting provider's abuse team
- Many providers respond to court orders and emergency disclosure requests

**VPN/PROXY IP** (red badge):
- Known VPN exit node — operator is using a VPN
- Still document: request subscriber records from VPN provider via MLAT if foreign
- Many VPN providers log under legal pressure

### 6.4 Requesting a New Tor Circuit

```bash
# Via UI: Click NEW CIRCUIT button

# Via command line:
echo -e 'AUTHENTICATE ""\r\nSIGNAL NEWNYM\r\nQUIT' | nc 127.0.0.1 9051
```

---

## PHASE 7 — LEGAL PROCESS GUIDANCE (India LEA Framework)

### 7.1 For Domestic Indian IPs (BSNL, Airtel, Jio, etc.)

Issue a **Section 91 CrPC notice** or formal legal demand to the ISP with:
- IP address (verbatim from UMBRA report)
- Date and time (UTC, convert to IST = UTC+5:30)
- Protocol (TCP/HTTP)
- Request: subscriber name, address, account registration details, billing information

### 7.2 For Foreign Hosting Providers

Submit a **Mutual Legal Assistance Treaty (MLAT)** request through:
- **US providers** (AWS, DigitalOcean, Google): US-India MLAT via MHA
- **EU providers** (Hetzner, OVH): Bilateral agreements via CBI/MHA
- **Emergency disclosures**: Most major providers have 24-hour emergency escalation for imminent threat situations

### 7.3 For Cryptocurrency Exchanges

- Binance, Coinbase, Kraken: Have formal LEA portals
- Indian exchanges (WazirX, CoinDCX): Direct court order sufficient
- Provide the BTC address and request: KYC documents, linked bank accounts, transaction history, login IP logs

### 7.4 For PGP Email Providers

- ProtonMail (Switzerland): Swiss legal process required; emergency provision exists
- Gmail/Google: US legal process / emergency disclosure
- Document the email address exactly as found in PGP key

---

## PHASE 8 — SAVING EVIDENCE

### 8.1 Export Report

The backend returns full JSON. Save via:

```bash
# Save from API directly
curl -s -X POST http://localhost:8000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"onion_url":"http://target.onion"}' \
  > evidence_$(date +%Y%m%d_%H%M%S)_target.json

# Verify the file
python3 -m json.tool evidence_*.json > /dev/null && echo "Valid JSON"
```

### 8.2 Secure Evidence Storage

```bash
# Create encrypted evidence container (VeraCrypt recommended)
# Or encrypt with GPG:
gpg --symmetric --cipher-algo AES256 evidence_*.json

# Hash for chain of custody
sha256sum evidence_*.json > evidence_*.sha256
cat evidence_*.sha256
```

### 8.3 Screenshot the Attribution Graph

1. Open the **⬡ ATTRIBUTION GRAPH** tab in the UI
2. Use **Ctrl+Shift+S** (Kali screenshot) or browser's print-to-PDF
3. Save with timestamp in filename

---

## PHASE 9 — OPERATIONAL SECURITY (OpSec)

### 9.1 Before Every Session

```bash
# Rotate Tor identity
sudo systemctl restart tor
sleep 15
curl --socks5-hostname 127.0.0.1:9050 http://check.torproject.org/api/ip
```

### 9.2 During Session

- **Never** open any links returned in results on the same machine
- **Never** use the same Tor circuit for multiple targets
- **Never** expose port 8000 or 3000 outside localhost
- Click **NEW CIRCUIT** between each target scan
- Do not log in to any personal accounts during session

### 9.3 Verify No DNS Leaks

```bash
# All DNS should route through Tor — no direct DNS queries
sudo tcpdump -i any port 53 -n &
# Browse for 30 seconds, then check — should show only 127.0.0.1 queries
kill %1
```

### 9.4 Firewall Kill Switch (prevent IP exposure if Tor drops)

```bash
# Create kill switch script
cat > ~/umbra/killswitch.sh << 'EOF'
#!/bin/bash
echo "[!] Activating firewall kill switch..."
sudo ufw default deny outgoing
sudo ufw default deny incoming
sudo ufw allow out on lo
sudo ufw allow in on lo
sudo ufw reload
echo "[!] All external traffic blocked. Restart Tor and re-enable rules to resume."
EOF
chmod +x ~/umbra/killswitch.sh

# Run if Tor drops unexpectedly:
# ~/umbra/killswitch.sh
```

---

## PHASE 10 — SECURE SHUTDOWN

### 10.1 End-of-Session Procedure (run in order)

```bash
# 1. Stop frontend
#    Press Ctrl+C in the npm terminal

# 2. Stop backend
#    Press Ctrl+C in the python terminal

# 3. Deactivate virtual environment
deactivate

# 4. Stop Tor
sudo systemctl stop tor

# 5. Clear system clipboard
xdotool key ctrl+shift+u && echo -n "" | xclip -selection clipboard 2>/dev/null || true

# 6. Clear bash history for this session
history -c && history -w

# 7. Shred any temporary files
find /tmp -name "*.json" -exec shred -u {} \; 2>/dev/null
find ~/umbra -name "*.log" -exec shred -u {} \; 2>/dev/null

# 8. If evidence files are no longer needed immediately:
# shred -u evidence_*.json

# 9. Restore firewall to default session state
sudo ufw status
```

### 10.2 Full Session Wipe (if required by operational policy)

```bash
# Wipe working directory (preserves venv)
shred -u ~/umbra/*.json 2>/dev/null
shred -u ~/umbra/*.log 2>/dev/null

# Clear shell history
cat /dev/null > ~/.bash_history
history -c

# Sync and clear page cache
sync
sudo sh -c 'echo 3 > /proc/sys/vm/drop_caches'
```

---

## QUICK REFERENCE — COMMAND CHEATSHEET

```bash
# ── START SESSION ──────────────────────────────────
sudo systemctl start tor
sleep 10
curl --socks5-hostname 127.0.0.1:9050 http://check.torproject.org/api/ip

cd ~/umbra && source .venv/bin/activate
python3 umbra_v3_backend.py &          # background

cd frontend && npm start &             # background
# UI opens at http://localhost:3000

# ── DURING SESSION ─────────────────────────────────
# New Tor circuit between targets:
echo -e 'AUTHENTICATE ""\r\nSIGNAL NEWNYM\r\nQUIT' | nc 127.0.0.1 9051

# Direct IP geolocation test:
curl http://localhost:8000/api/geo/203.0.113.1

# RFC 7239 / proxy chain test:
curl "http://localhost:8000/api/proxy-test?x_forwarded_for=203.0.113.1,10.0.0.1,198.51.100.5"

# ── SAVE EVIDENCE ───────────────────────────────────
curl -s -X POST http://localhost:8000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"onion_url":"http://TARGET.onion"}' \
  > evidence_$(date +%Y%m%d_%H%M%S).json

# ── END SESSION ─────────────────────────────────────
kill $(lsof -t -i:8000) 2>/dev/null
kill $(lsof -t -i:3000) 2>/dev/null
deactivate
sudo systemctl stop tor
history -c && history -w
```

---

## TROUBLESHOOTING

| Symptom | Cause | Fix |
|---------|-------|-----|
| `IsTor: false` | Tor not running | `sudo systemctl start tor && sleep 15` |
| Backend unreachable | Wrong port or not started | `python3 umbra_v3_backend.py` in venv |
| `Connection failed: socks5h://` | Tor not at 9050 | Check `sudo netstat -tuln | grep 9050` |
| All IPs return `fail` | ip-api.com rate limit | Wait 60 sec (45 req/min limit) |
| No IPv6 in results | Target has no IPv6 leaks | Normal — not all sites leak IPv6 |
| npm: module not found | Not in frontend dir | `cd ~/umbra/frontend && npm install` |
| `ModuleNotFoundError` | venv not activated | `source ~/umbra/.venv/bin/activate` |
| Site returns 404/403 | Site offline or blocking | Try new circuit, verify URL |

---

*UMBRA V3.1 | NIA / Law Enforcement Use Only | Classification: RESTRICTED*
*Prepared for official use — unauthorized access or use is prohibited*
