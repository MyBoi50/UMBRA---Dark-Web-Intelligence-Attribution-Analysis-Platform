#!/bin/bash
# UMBRA — One-command setup script
# Usage: chmod +x setup.sh && ./setup.sh

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║  UMBRA Dark Web Intelligence Platform    ║"
echo "║  Setup Script — Law Enforcement Only     ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# 1. Install Python deps
echo "[1/4] Installing Python dependencies..."
pip install fastapi uvicorn "requests[socks]" stem anthropic httpx "beautifulsoup4" lxml --quiet
echo "      ✓ Python deps installed"

# 2. Check Tor
echo "[2/4] Checking Tor..."
if command -v tor &> /dev/null; then
    echo "      ✓ Tor binary found"
elif [ -d "/Applications/Tor Browser.app" ]; then
    echo "      ✓ Tor Browser found (macOS)"
else
    echo "      ⚠ Tor not found. Install options:"
    echo "        Ubuntu/Debian: sudo apt install tor && sudo service tor start"
    echo "        macOS:         brew install tor && brew services start tor"
    echo "        Or: Open Tor Browser (keeps SOCKS5 on 127.0.0.1:9050)"
fi

# 3. Check ANTHROPIC_API_KEY
echo "[3/4] Checking API key..."
if [ -z "$ANTHROPIC_API_KEY" ]; then
    echo "      ⚠ ANTHROPIC_API_KEY not set."
    echo "        Set it: export ANTHROPIC_API_KEY=sk-ant-api03-..."
    echo "        Or enter it in the frontend UI."
else
    echo "      ✓ ANTHROPIC_API_KEY is set"
fi

# 4. Start backend
echo "[4/4] Starting UMBRA backend..."
echo ""
echo "  ✓ Backend will start at: http://localhost:8000"
echo "  ✓ API docs at:           http://localhost:8000/docs"
echo "  ✓ Open umbra_frontend.jsx in Claude.ai (as React artifact)"
echo "  ✓ Click CHECK TOR to verify Tor connectivity"
echo "  ✓ Paste .onion URL and click FETCH + ANALYZE"
echo ""
echo "  Press Ctrl+C to stop"
echo ""

python umbra_backend.py
