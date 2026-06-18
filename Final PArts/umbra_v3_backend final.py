#!/usr/bin/env python3
"""
UMBRA V3.2 — Dark Web Intelligence Platform
NIA / Law Enforcement Use Only

NEW in v3.2:
  • Active IP Discovery Engine (correlation attack)
    - DNS resolution of ALL clearnet domains in page source
    - HackerTarget secondary resolver (geo-restriction bypass)
    - Reverse IP lookup (co-hosted domains)
    - CSP / meta / JS URL extraction for hidden domain references
    - Shodan + Censys query generation (favicon, title, server, analytics ID)
    - VirusTotal / SecurityTrails historical DNS links
  • Merged discovered IPs into ip_intelligence and attribution graph

Install:
    pip install fastapi uvicorn "requests[socks]" PySocks stem \
                beautifulsoup4 lxml pydantic mmh3

Run: python umbra_v3_backend.py
Docs: http://localhost:8000/docs
"""

import re
import json
import time
import hashlib
import logging
import os
import socket
import ipaddress
import concurrent.futures
from collections import Counter
from typing import Optional
from datetime import datetime
from urllib.parse import quote

import requests
from bs4 import BeautifulSoup
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# ══════════════════════════════════════════════
# CONFIGURATION
# ══════════════════════════════════════════════
TOR_PROXY = "socks5h://127.0.0.1:9050"
TIMEOUT   = 35
UA        = "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("umbra")

# ── Reliable HTTP with retry/backoff ─────────────────────────────────────────
def _get(url: str, retries: int = 2, backoff: float = 1.2, **kwargs) -> requests.Response:
    """Wrapper for requests.get with retry, backoff, and rate-limit handling."""
    kwargs.setdefault("timeout", 12)
    kwargs.setdefault("headers", {}).update({"User-Agent": UA})
    last_exc = None
    for attempt in range(retries + 1):
        try:
            r = requests.get(url, **kwargs)
            if r.status_code == 429:
                wait = backoff * (2 ** attempt)
                log.warning(f"Rate limited by {url[:40]} — waiting {wait:.1f}s")
                time.sleep(wait)
                continue
            return r
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
            last_exc = e
            if attempt < retries:
                time.sleep(backoff * (attempt + 1))
    raise last_exc or requests.exceptions.RequestException(f"Failed after {retries+1} attempts: {url[:60]}")

# ── In-memory geo cache (avoids duplicate lookups in same session) ─────────
_GEO_CACHE: dict = {}

def _cached_geo(ip: str) -> dict:
    if ip not in _GEO_CACHE:
        _GEO_CACHE[ip] = None  # sentinel to prevent concurrent duplicate calls
    return _GEO_CACHE.get(ip)

def _store_geo(ip: str, result: dict):
    _GEO_CACHE[ip] = result

# ── In-memory scan store (cross-case correlation) ──────────────────────────
_SCAN_HISTORY: list = []   # list of {url, timestamp, intelligence, pii_hashes}

def _record_scan(url: str, intelligence: dict, pii: list):
    """Store scan summary for cross-case correlation queries."""
    _SCAN_HISTORY.append({
        "url":           url,
        "timestamp":     datetime.utcnow().isoformat() + "Z",
        "confidence":    intelligence.get("attribution_confidence_pct", 0),
        "threat":        intelligence.get("threat_level", "UNKNOWN"),
        "region":        intelligence.get("probable_region", ""),
        "pii_count":     len(pii),
        "pii_types":     list(set(p.get("type","") for p in pii)),
        # Store hashed artifact values for cross-case reuse detection
        "artifact_hashes": [
            hashlib.sha256(p.get("value","").encode()).hexdigest()[:12]
            for p in pii if p.get("type") not in ("IPv4 Address","IPv6 Address")
        ],
    })


# ── Weighted attribution formula (NIA format) ─────────────────────────────
def compute_attribution_score(evidence_items: list) -> dict:
    """
    Weighted multi-factor attribution scoring.
    Formula matches what human analysts use — direct identity evidence
    carries far more weight than behavioral or technical correlation.

        score = Σ (weight_i × found_i) / Σ weight_i  ×  100

    Confidence bands:
        80–100 → DEFINITIVE  — multiple convergent chains, legal action warranted
        60–79  → STRONG      — sufficient for legal process initiation
        40–59  → MODERATE    — corroboration recommended
        20–39  → WEAK        — intelligence value, investigation in early stage
        0–19   → MINIMAL     — insufficient for attribution
    """
    total_weight = sum(e.get("weight", 0) for e in evidence_items)
    found_weight  = sum(e.get("weight", 0) for e in evidence_items if e.get("present"))
    score = round((found_weight / total_weight) * 100) if total_weight else 0

    if score >= 80:   band, note = "DEFINITIVE", "Convergent independent evidence chains. Warrant/legal action recommended."
    elif score >= 60: band, note = "STRONG",     "Sufficient for legal process initiation. Document all evidence chains."
    elif score >= 40: band, note = "MODERATE",   "Significant leads. Additional corroboration recommended before legal action."
    elif score >= 20: band, note = "WEAK",       "Early-stage intelligence. Continue developing leads."
    else:             band, note = "MINIMAL",    "Insufficient for attribution. Use Shodan/urlscan queries to develop initial leads."

    return {"score": score, "band": band, "note": note,
            "found_weight": found_weight, "total_weight": total_weight}

app = FastAPI(title="UMBRA V3", version="3.1.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

class AnalyzeRequest(BaseModel):
    onion_url: str
    anthropic_api_key: Optional[str] = ""  # kept for schema compat, no longer required

# ══════════════════════════════════════════════
# ENGINE 1: TOR FETCH
# ══════════════════════════════════════════════
def tor_session():
    s = requests.Session()
    s.proxies = {"http": TOR_PROXY, "https": TOR_PROXY}
    s.headers.update({"User-Agent": UA})
    return s

def check_tor():
    try:
        r = tor_session().get("http://check.torproject.org/api/ip", timeout=15)
        d = r.json()
        return {"running": True, "tor_ip": d.get("IP"), "is_tor": d.get("IsTor", False)}
    except Exception as e:
        return {"running": False, "error": str(e)}

def fetch_onion(url: str):
    if not url.startswith("http"):
        url = "http://" + url
    t0 = time.time()
    try:
        r = tor_session().get(url, timeout=TIMEOUT, allow_redirects=True)
        try:
            content = r.text
        except Exception:
            content = r.content.decode("utf-8", errors="replace")
        return {
            "success": True,
            "url": str(r.url),
            "status_code": r.status_code,
            "page_source": content,
            "headers": dict(r.headers),
            "headers_str": "\n".join(f"{k}: {v}" for k, v in r.headers.items()),
            "content_length": len(content),
            "redirect_chain": [str(u.url) for u in r.history] + [str(r.url)],
            "elapsed_seconds": round(time.time() - t0, 2),
            "server_fingerprint": r.headers.get("Server", ""),
        }
    except requests.exceptions.ConnectTimeout:
        return {"success": False, "error": "Connection timed out. Site may be offline."}
    except requests.exceptions.ConnectionError as e:
        return {"success": False, "error": f"Connection failed: {e}. Is Tor at 127.0.0.1:9050?"}
    except Exception as e:
        return {"success": False, "error": str(e)}

# ══════════════════════════════════════════════
# ENGINE 2: PII EXTRACTION (30 patterns)
# ══════════════════════════════════════════════

# IPv4 – full strict octet match
_IPV4_PAT = r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"

# IPv6 – covers full, compressed (::), and mixed IPv4-mapped forms
_IPV6_CORE = (
    r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,7}:"
    r"|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}"
    r"|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}"
    r"|:(?::[0-9a-fA-F]{1,4}){1,7}"
    r"|::(?:[fF]{4}(?::0{1,4})?:)?" + _IPV4_PAT
    + r"|(?:[0-9a-fA-F]{1,4}:){1,4}:" + _IPV4_PAT
)
_IPV6_PAT = r"(?<![:\w])(?:" + _IPV6_CORE + r")(?![:\w])"

PII_PATTERNS = [
    ("Email Address",         r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b",              "CRITICAL"),
    ("Bitcoin (P2PKH)",       r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b",                                "CRITICAL"),
    ("Bitcoin (Bech32)",      r"\bbc1[a-z0-9]{39,59}\b",                                              "CRITICAL"),
    ("Ethereum Address",      r"\b0x[a-fA-F0-9]{40}\b",                                               "CRITICAL"),
    ("Monero Address",        r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b",                               "CRITICAL"),
    ("Litecoin Address",      r"\b[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}\b",                               "HIGH"),
    ("Telegram Handle",       r"(?:t\.me/|telegram\.me/|@)([a-zA-Z][a-zA-Z0-9_]{4,31})\b",           "CRITICAL"),
    ("Telegram Group",        r"t\.me/[a-zA-Z0-9_+]+",                                               "HIGH"),
    ("Onion v3 Address",      r"\b[a-z2-7]{56}\.onion\b",                                             "HIGH"),
    ("Onion v2 Address",      r"\b[a-z2-7]{16}\.onion\b",                                             "MEDIUM"),
    ("IPv4 Address",          _IPV4_PAT,                                                               "CRITICAL"),
    ("IPv6 Address",          _IPV6_PAT,                                                               "CRITICAL"),
    ("Phone (Indian)",        r"(?:\+91[\-\s]?)?[6-9]\d{9}\b",                                        "HIGH"),
    ("Phone (International)", r"\+[1-9]\d{7,14}\b",                                                   "HIGH"),
    ("Clearnet URL",          r"https?://(?!.*\.onion)[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+",       "CRITICAL"),
    ("PGP Key Block",         r"-----BEGIN PGP PUBLIC KEY BLOCK-----[\s\S]+?-----END PGP PUBLIC KEY BLOCK-----", "HIGH"),
    ("PGP Key ID",            r"\b(?:0x)?[A-F0-9]{8,16}\b",                                           "MEDIUM"),
    ("Wickr ID",              r"(?:wickr)[\:\s#@]+([a-zA-Z0-9._\-]{3,40})\b",                         "HIGH"),
    ("Session/Signal ID",     r"(?:signal|session)[\:\s#@]+([a-zA-Z0-9._\-]{3,60})\b",                "HIGH"),
    ("Jabber/XMPP",           r"\b[a-z0-9._%+\-]+@(?:jabber|xmpp|conversations)\.[a-z]{2,}\b",       "HIGH"),
    ("Google Analytics UA",   r"\bUA-\d{4,10}-\d{1,4}\b",                                             "CRITICAL"),
    ("Google Analytics GA4",  r"\bG-[A-Z0-9]{8,12}\b",                                               "CRITICAL"),
    ("Facebook Pixel",        r"fbq\s*\(\s*[\"']init[\"']\s*,\s*[\"']?(\d{10,20})",                   "CRITICAL"),
    ("AWS S3 Bucket",         r"\b[a-z0-9.\-]+\.s3(?:[\.-][a-z0-9-]+)?\.amazonaws\.com\b",            "CRITICAL"),
    ("Stripe Key",            r"\bpk_(?:live|test)_[a-zA-Z0-9]{20,60}\b",                             "CRITICAL"),
    ("SimpleX Link",          r"simplex\.chat/[a-zA-Z0-9/\-_#]+",                                     "HIGH"),
    ("SimpleX Invitation",    r"simplex:/contact#[a-zA-Z0-9/+=]+",                                    "HIGH"),
    ("I2P Address",           r"\b[a-zA-Z0-9\-]+\.i2p\b",                                             "MEDIUM"),
    ("Briar/Ricochet",        r"(?:ricochet|briar):[a-z2-7]{16,56}",                                  "HIGH"),
]

# Private/loopback ranges — skip these
_PRIVATE_NETS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("255.255.255.255/32"),
]

def is_public_ip(ip_str: str) -> bool:
    """Return True if the string is a valid, routable public IP (v4 or v6)."""
    try:
        addr = ipaddress.ip_address(ip_str.strip("[]"))
        return not any(addr in net for net in _PRIVATE_NETS)
    except ValueError:
        return False

def extract_pii(text: str) -> list:
    findings, seen = [], set()
    for ptype, pattern, risk in PII_PATTERNS:
        for m in re.finditer(pattern, text, re.IGNORECASE | re.MULTILINE):
            val = m.group(0).strip()
            key = (ptype, val)
            if key in seen or len(val) < 4:
                continue
            # For IPs, drop private/loopback
            if ptype in ("IPv4 Address", "IPv6 Address") and not is_public_ip(val):
                continue
            seen.add(key)
            findings.append({
                "type": ptype, "value": val, "risk": risk,
                "context": text[max(0, m.start()-50):m.end()+50].strip()
            })
    return findings

# ══════════════════════════════════════════════════════════════════════════════
# ENGINE 3: IP INTELLIGENCE — IPv4 + IPv6, RFC 7239, proxy chain
# ══════════════════════════════════════════════════════════════════════════════

def geolocate_ip(ip: str) -> dict:
    """
    Geolocation via ip-api.com (free, no key, supports IPv4 + IPv6).
    Results are cached in-memory to avoid duplicate lookups.
    """
    clean = ip.strip().strip("[]")
    cached = _cached_geo(clean)
    if cached:
        return cached
    try:
        fields = ("status,message,country,countryCode,region,regionName,city,"
                  "zip,lat,lon,timezone,isp,org,as,asname,proxy,hosting,query")
        r = _get(
            f"http://ip-api.com/json/{clean}?fields={fields}"
        )
        d = r.json()
        if d.get("status") == "fail":
            return {"success": False, "ip": clean, "error": d.get("message", "Lookup failed")}

        notes = []
        if d.get("proxy"):
            notes.append("VPN/PROXY DETECTED — known proxy or VPN exit node")
        if d.get("hosting"):
            notes.append("HOSTING/DATACENTER — likely VPS/cloud, not residential")
        isp_lower = (d.get("isp") or "").lower()
        hosting_providers = [
            "digitalocean", "linode", "vultr", "amazon", "google", "ovh",
            "hetzner", "cloudflare", "contabo", "serverius", "frantech",
            "leaseweb", "m247", "choopa", "zenlayer", "sharktech",
        ]
        if any(x in isp_lower for x in hosting_providers):
            notes.append(f"Cloud/hosting provider: {d.get('isp')} — submit abuse/legal request")
        elif not d.get("proxy") and not d.get("hosting"):
            notes.append(f"Residential ISP: {d.get('isp')} — submit legal process for subscriber identity")

        result = {
            "success": True, "ip": clean,
            "ip_version": 6 if ":" in clean else 4,
            "country": d.get("country"), "country_code": d.get("countryCode"),
            "region": d.get("regionName"), "city": d.get("city"), "postal": d.get("zip"),
            "lat": d.get("lat"), "lon": d.get("lon"),
            "timezone": d.get("timezone"),
            "isp": d.get("isp"), "org": d.get("org"),
            "asn": d.get("as"), "asn_name": d.get("asname"),
            "is_proxy": d.get("proxy", False),
            "is_hosting": d.get("is_hosting", d.get("hosting", False)),
            "google_maps_url": f"https://www.google.com/maps?q={d.get('lat')},{d.get('lon')}",
            "google_maps_embed": f"https://maps.google.com/maps?q={d.get('lat')},{d.get('lon')}&z=12&output=embed",
            "investigation_notes": notes,
            "legal_action": f"Legal process → {d.get('isp', 'ISP')} for subscriber identity records",
        }
        _store_geo(clean, result)
        return result
    except Exception as e:
        return {"success": False, "ip": clean, "error": str(e)}


# ── RFC 7239 parser ────────────────────────────────────────────────────────────
def _parse_rfc7239_forwarded(value: str) -> list:
    """
    Parse RFC 7239 'Forwarded' header.
    Format: for=192.0.2.60;proto=http, for="[2001:db8::1]";host=example.com
    Returns list of dicts: {ip, proto, host, by}
    """
    entries = []
    for segment in value.split(","):
        segment = segment.strip()
        params = {}
        for part in segment.split(";"):
            part = part.strip()
            if "=" in part:
                k, _, v = part.partition("=")
                params[k.strip().lower()] = v.strip().strip('"')
        ip_raw = params.get("for", "")
        # IPv6 in RFC 7239 is wrapped in brackets: [2001:db8::1]
        ip_clean = ip_raw.strip("[]").split(":")[0] if "." in ip_raw and "[" not in ip_raw else ip_raw.strip("[]")
        # For IPv6 brackets
        if ip_raw.startswith("["):
            ip_clean = ip_raw.strip("[]")
        elif ":" in ip_raw and not ip_raw.startswith("["):
            # might be IPv6 without brackets or IPv4:port
            parts = ip_raw.rsplit(":", 1)
            if len(parts) == 2 and parts[1].isdigit():
                ip_clean = parts[0]  # strip port
            else:
                ip_clean = ip_raw
        if ip_clean:
            entries.append({
                "ip": ip_clean,
                "proto": params.get("proto", ""),
                "host": params.get("host", ""),
                "by": params.get("by", ""),
            })
    return entries


def _extract_ips_from_header_value(value: str) -> list:
    """Extract all valid public IPs (v4 + v6) from any header value string."""
    found = []
    # IPv4
    for m in re.finditer(_IPV4_PAT, value):
        ip = m.group(0)
        if is_public_ip(ip):
            found.append(ip)
    # IPv6 (also strip surrounding brackets)
    for m in re.finditer(_IPV6_PAT, value, re.IGNORECASE):
        ip = m.group(0).strip("[]")
        if is_public_ip(ip):
            found.append(ip)
    return found


def extract_proxy_ips_from_headers(headers_raw: dict) -> list:
    """
    Comprehensive extraction of real/leaked IPs from ALL proxy-related headers.

    Priority/source mapping:
      CRITICAL  X-Forwarded-For   — full proxy chain, leftmost = client real IP
      CRITICAL  Forwarded (RFC7239) — structured; for= is real client
      CRITICAL  X-Real-IP         — single real IP (nginx/HAProxy)
      CRITICAL  CF-Connecting-IP  — Cloudflare real client IP
      CRITICAL  True-Client-IP    — Akamai / enterprise CDN real IP
      HIGH      X-Cluster-Client-IP, X-Client-IP, X-Originating-IP
      MEDIUM    Via               — intermediate proxy hostnames/IPs
    """
    h = {k.lower(): v for k, v in headers_raw.items()}
    results = []
    seen_ips = set()

    def add(ip, source, priority, chain_pos=None):
        if ip in seen_ips or not is_public_ip(ip):
            return
        seen_ips.add(ip)
        entry = {"ip": ip, "source": source, "priority": priority}
        if chain_pos is not None:
            entry["chain_position"] = chain_pos
        results.append(entry)

    # ── X-Forwarded-For (comma-separated chain) ────────────────────────────
    xff = h.get("x-forwarded-for", "")
    if xff:
        parts = [p.strip() for p in xff.split(",")]
        for pos, part in enumerate(parts):
            ips = _extract_ips_from_header_value(part)
            for ip in ips:
                if pos == 0:
                    src = "X-Forwarded-For [0] — CLIENT REAL IP LEAK (CRITICAL)"
                    pri = "CRITICAL"
                else:
                    src = f"X-Forwarded-For [{pos}] — proxy hop {pos}"
                    pri = "HIGH"
                add(ip, src, pri, chain_pos=pos)

    # ── RFC 7239 Forwarded header ─────────────────────────────────────────
    fwd = h.get("forwarded", "")
    if fwd:
        for i, entry in enumerate(_parse_rfc7239_forwarded(fwd)):
            ip = entry["ip"]
            src = (f"Forwarded (RFC 7239) for= entry [{i}]"
                   + (f" proto={entry['proto']}" if entry['proto'] else "")
                   + (f" host={entry['host']}" if entry['host'] else ""))
            pri = "CRITICAL" if i == 0 else "HIGH"
            add(ip, src, pri, chain_pos=i)

    # ── Single-IP headers ─────────────────────────────────────────────────
    for hdr, label, prio in [
        ("x-real-ip",           "X-Real-IP — nginx/HAProxy real client IP",          "CRITICAL"),
        ("cf-connecting-ip",    "CF-Connecting-IP — Cloudflare real client IP",       "CRITICAL"),
        ("true-client-ip",      "True-Client-IP — Akamai/CDN real client IP",        "CRITICAL"),
        ("x-cluster-client-ip", "X-Cluster-Client-IP — cluster proxy real client",   "HIGH"),
        ("x-client-ip",         "X-Client-IP — proxy real client",                   "HIGH"),
        ("x-originating-ip",    "X-Originating-IP — mail/app server origin",         "HIGH"),
        ("fastly-client-ip",    "Fastly-Client-IP — Fastly CDN real client",         "HIGH"),
    ]:
        val = h.get(hdr, "")
        if val:
            for ip in _extract_ips_from_header_value(val):
                add(ip, label, prio)

    # ── Via header (intermediate proxy chain) ──────────────────────────────
    via = h.get("via", "")
    if via:
        for ip in _extract_ips_from_header_value(via):
            add(ip, "Via — intermediate proxy/gateway IP", "MEDIUM")

    return results


def geolocate_all_ips(pii_findings: list, header_findings: list, headers_raw: dict = None) -> list:
    """
    Geolocate ALL public IPs from:
      1. Proxy header leaks (X-Forwarded-For, RFC 7239, X-Real-IP, etc.)
      2. Page source / PII extraction (IPv4 + IPv6)
    """
    to_check = []
    seen = set()

    # ── 1. Header proxy chain (highest priority) ──────────────────────────
    raw_headers = headers_raw or {}
    for entry in extract_proxy_ips_from_headers(raw_headers):
        ip = entry["ip"]
        if ip not in seen:
            seen.add(ip)
            to_check.append(entry)

    # ── Fallback: legacy header_findings list (in case raw dict unavailable)
    if not raw_headers:
        for h in header_findings:
            val = h.get("value", "")
            field = h.get("field", "")
            if field in ("X-Forwarded-For", "X-Real-IP", "CF-Connecting-IP",
                         "True-Client-IP", "Forwarded"):
                for ip in _extract_ips_from_header_value(val):
                    if ip not in seen:
                        seen.add(ip)
                        to_check.append({
                            "ip": ip,
                            "source": f"{field} HEADER LEAK — CRITICAL",
                            "priority": "CRITICAL"
                        })

    # ── 2. IPs from page source (IPv4 + IPv6) ────────────────────────────
    for p in pii_findings:
        if p["type"] in ("IPv4 Address", "IPv6 Address"):
            ip = p["value"].strip("[]")
            if ip not in seen and is_public_ip(ip):
                seen.add(ip)
                to_check.append({"ip": ip, "source": f"Page source ({p['type']})", "priority": "HIGH"})

    # ── Geolocate (respect ip-api.com 45 req/min free limit) ─────────────
    results = []
    for entry in to_check[:12]:
        geo = geolocate_ip(entry["ip"])
        geo["source"] = entry["source"]
        geo["priority"] = entry["priority"]
        if "chain_position" in entry:
            geo["chain_position"] = entry["chain_position"]
        results.append(geo)
        time.sleep(0.45)
    return results


# ══════════════════════════════════════════════════════════════════════════════
# ENGINE 3b: ACTIVE IP DISCOVERY — Multi-API Correlation Attack
# ══════════════════════════════════════════════════════════════════════════════
#
# HONEST ASSESSMENT FOR NIA:
#   A correctly configured Tor v3 hidden service NEVER exposes its IP in
#   headers or page source — that is Tor's cryptographic guarantee.
#
#   Real-world deanonymisation uses CORRELATION:
#     • Most operators have a clearnet footprint (mirror site, CDN, analytics)
#     • DNS resolution of clearnet domains → real hosting IP
#     • urlscan.io: search by page title/fingerprint → finds clearnet matches
#     • Shodan InternetDB: no-key API → ports/hostnames for any IP
#     • ipinfo.io: no-key geolocation + org/ASN/hostname
#     • HackerTarget: secondary DNS + reverse IP
#
#   This engine calls ALL free no-key APIs automatically.
# ══════════════════════════════════════════════════════════════════════════════

_COMMON_CDN_DOMAINS = {
    "ajax.googleapis.com", "fonts.googleapis.com", "fonts.gstatic.com",
    "cdnjs.cloudflare.com", "cdn.jsdelivr.net", "unpkg.com",
    "code.jquery.com", "stackpath.bootstrapcdn.com", "maxcdn.bootstrapcdn.com",
    "cdn.cloudflare.com", "use.fontawesome.com", "kit.fontawesome.com",
    "static.cloudflareinsights.com", "challenges.cloudflare.com",
    "www.googletagmanager.com", "www.google-analytics.com",
    "connect.facebook.net", "platform.twitter.com",
    "cdn.shopify.com", "assets.shopifycdn.com",
}

def _is_cdn_domain(domain: str) -> bool:
    d = domain.lower()
    if d in _COMMON_CDN_DOMAINS:
        return True
    for cdn in ["cloudflare", "akamai", "fastly", "amazonaws", "cloudfront",
                "googleapis", "gstatic", "jquery", "bootstrapcdn", "jsdelivr",
                "shopify", "shopifycdn", "fontawesome", "unpkg"]:
        if cdn in d:
            return True
    return False


# ── Free API: ipinfo.io (50k/month, no key) ──────────────────────────────────
def ipinfo_lookup(ip: str) -> dict:
    """
    ipinfo.io — free tier, no API key for basic use.
    Returns: city, region, country, org (ISP+ASN), hostname, lat/lon.
    More reliable than ip-api.com for some ranges.
    """
    try:
        r = requests.get(
            f"https://ipinfo.io/{ip}/json",
            timeout=8, headers={"User-Agent": UA, "Accept": "application/json"}
        )
        if r.status_code != 200:
            return {"success": False, "ip": ip}
        d = r.json()
        if "bogon" in d or not d.get("country"):
            return {"success": False, "ip": ip, "error": "bogon/private"}
        loc = d.get("loc", ",").split(",")
        lat = float(loc[0]) if loc[0] else None
        lon = float(loc[1]) if len(loc) > 1 and loc[1] else None
        org = d.get("org", "")  # format: "AS12345 ISP Name"
        asn, isp = ("", org)
        if org.startswith("AS"):
            parts = org.split(" ", 1)
            asn = parts[0]
            isp = parts[1] if len(parts) > 1 else org
        return {
            "success": True, "ip": ip, "source_api": "ipinfo.io",
            "country": d.get("country"), "country_code": d.get("country"),
            "region": d.get("region"), "city": d.get("city"),
            "postal": d.get("postal"), "timezone": d.get("timezone"),
            "lat": lat, "lon": lon,
            "hostname": d.get("hostname", ""),
            "isp": isp, "org": org, "asn": asn,
            "google_maps_url": f"https://www.google.com/maps?q={lat},{lon}" if lat else "",
        }
    except Exception as e:
        return {"success": False, "ip": ip, "error": str(e)}


# ── Free API: Shodan InternetDB (no key required) ─────────────────────────────
def internetdb_lookup(ip: str) -> dict:
    """
    Shodan InternetDB — completely free, no key.
    Returns open ports, hostnames, CVEs, CPEs, tags for any IP.
    Hostnames often reveal the operator's domain even without DNS.
    """
    try:
        r = requests.get(
            f"https://internetdb.shodan.io/{ip}",
            timeout=8, headers={"User-Agent": UA}
        )
        if r.status_code == 404:
            return {"ip": ip, "found": False}
        if r.status_code != 200:
            return {"ip": ip, "found": False, "error": f"HTTP {r.status_code}"}
        d = r.json()
        return {
            "ip": ip, "found": True,
            "hostnames": d.get("hostnames", []),
            "ports": d.get("ports", []),
            "cpes": d.get("cpes", []),
            "tags": d.get("tags", []),
            "vulns": d.get("vulns", []),
        }
    except Exception as e:
        return {"ip": ip, "found": False, "error": str(e)}


# ── Free API: urlscan.io search (100/day, no key for search) ─────────────────
def urlscan_search(query: str, size: int = 5) -> list:
    """
    urlscan.io — completely free search, no API key required.
    Searches millions of scanned pages by title, JS hash, domain, etc.
    Returns: ip, domain, country, asn, server, screenshot URL.
    This is the MOST POWERFUL free tool for finding clearnet mirrors.
    """
    try:
        r = requests.get(
            f"https://urlscan.io/api/v1/search/?q={requests.utils.quote(query)}&size={size}",
            timeout=12,
            headers={"User-Agent": UA, "Accept": "application/json"}
        )
        if r.status_code != 200:
            return []
        data = r.json()
        results = []
        for res in data.get("results", []):
            page = res.get("page", {})
            ip = page.get("ip", "")
            if ip and is_public_ip(ip):
                results.append({
                    "ip":         ip,
                    "domain":     page.get("domain", ""),
                    "url":        page.get("url", ""),
                    "country":    page.get("country", ""),
                    "asn":        page.get("asn", ""),
                    "server":     page.get("server", ""),
                    "screenshot": res.get("screenshot", ""),
                    "scan_time":  res.get("task", {}).get("time", ""),
                    "scan_url":   f"https://urlscan.io/result/{res.get('task',{}).get('uuid','')}/",
                })
        return results
    except Exception as e:
        log.warning(f"[urlscan] {query}: {e}")
        return []


# ── Free API: HackerTarget DNS + Reverse IP ───────────────────────────────────
def hackertarget_dns(domain: str) -> list:
    """HackerTarget DNS lookup — returns A/AAAA records. Free, no key."""
    clean = domain.strip().lower()
    if _is_cdn_domain(clean):
        return []
    try:
        r = requests.get(
            f"https://api.hackertarget.com/dnslookup/?q={clean}",
            timeout=12, headers={"User-Agent": UA}
        )
        if r.status_code != 200 or "error" in r.text.lower():
            return []
        ips = re.findall(_IPV4_PAT, r.text)
        return [ip for ip in set(ips) if is_public_ip(ip)]
    except Exception:
        return []


def hackertarget_reverseip(ip: str) -> dict:
    """Reverse IP lookup — find all domains on same server. Free, no key."""
    try:
        r = requests.get(
            f"https://api.hackertarget.com/reverseiplookup/?q={ip}",
            timeout=12, headers={"User-Agent": UA}
        )
        if r.status_code != 200 or "error" in r.text.lower():
            return {"ip": ip, "domains": [], "success": False}
        domains = [d.strip() for d in r.text.strip().split("\n")
                   if d.strip() and "." in d and not d.strip().startswith("error")]
        return {"ip": ip, "domains": domains[:30], "count": len(domains), "success": bool(domains)}
    except Exception as e:
        return {"ip": ip, "domains": [], "success": False, "error": str(e)}


# ── DNS resolution (system + HackerTarget fallback) ───────────────────────────
def dns_resolve_domain(domain: str) -> list:
    """Resolve domain to IPs. Tries system DNS first, HackerTarget as fallback."""
    clean = re.sub(r"^https?://", "", domain).split("/")[0].strip().lower()
    if not clean or ".onion" in clean or _is_cdn_domain(clean):
        return []
    ips = []
    # System DNS
    try:
        infos = socket.getaddrinfo(clean, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        ips = list(set(info[4][0] for info in infos if is_public_ip(info[4][0])))
    except Exception:
        pass
    # HackerTarget fallback if system DNS failed
    if not ips:
        ips = hackertarget_dns(clean)
    return ips


# ── Page fingerprint extraction ───────────────────────────────────────────────
def extract_page_fingerprints(html: str, headers_raw: dict, page_intel: dict) -> dict:
    """
    Extract unique fingerprints from the page that can be searched on
    urlscan.io, Shodan, and Censys to find clearnet mirrors.
    Looks for: title, JS build IDs, CSS hashes, meta generator, custom CSS
    class names, unique JS constants, framework signatures.
    """
    fp = {"title": "", "searches": []}
    h = {k.lower(): v for k, v in headers_raw.items()}

    # Page title — single best fingerprint
    title = page_intel.get("title", "").strip()
    if title and len(title) > 6:
        fp["title"] = title
        fp["searches"].append({
            "type": "PAGE_TITLE",
            "value": title,
            "urlscan_q": f'page.title:"{title}"',
            "shodan_q":  f'http.title:"{title}"',
            "shodan_url": f'https://www.shodan.io/search?query=http.title%3A%22{requests.utils.quote(title)}%22',
            "censys_q":  f'services.http.response.html_title="{title}"',
            "confidence": "HIGH",
        })

    # Meta generator (CMS/framework version — very unique)
    gen = re.search(r'name=["\']generator["\'][^>]+content=["\']([^"\']{6,60})["\']', html, re.I)
    if not gen:
        gen = re.search(r'content=["\']([^"\']{6,60})["\'][^>]+name=["\']generator["\']', html, re.I)
    if gen:
        val = gen.group(1).strip()
        fp["searches"].append({
            "type": "META_GENERATOR",
            "value": val,
            "urlscan_q": f'page.title:"{title}" AND page.domain:*',
            "shodan_q":  f'http.html:"{val}"',
            "shodan_url": f'https://www.shodan.io/search?query=http.html%3A%22{requests.utils.quote(val)}%22',
            "confidence": "HIGH",
        })

    # Server header (if unique/versioned)
    server = h.get("server", "")
    if server and len(server) > 5 and server.lower() not in ("nginx", "apache", "iis"):
        fp["searches"].append({
            "type": "SERVER_HEADER",
            "value": server,
            "shodan_q":  f'http.server:"{server}"',
            "shodan_url": f'https://www.shodan.io/search?query=http.server%3A%22{requests.utils.quote(server)}%22',
            "confidence": "MEDIUM",
        })

    # X-Powered-By
    pwby = h.get("x-powered-by", "")
    if pwby:
        fp["searches"].append({
            "type": "X_POWERED_BY",
            "value": pwby,
            "shodan_q":  f'http.html:"{pwby}"',
            "shodan_url": f'https://www.shodan.io/search?query=http.html%3A%22{requests.utils.quote(pwby)}%22',
            "confidence": "MEDIUM",
        })

    # JS build hashes (Webpack/Vite asset fingerprints — globally unique)
    build_hashes = re.findall(r'["\'/](?:static|assets|js)/[^\s"\']+\.([\w]{5,12})\.(js|css)["\']', html)
    for bh, ext in build_hashes[:3]:
        fp["searches"].append({
            "type": f"BUILD_HASH_{ext.upper()}",
            "value": bh,
            "shodan_q":  f'http.html:"{bh}"',
            "shodan_url": f'https://www.shodan.io/search?query=http.html%3A%22{bh}%22',
            "urlscan_q": f'page.domain:* AND hash:*{bh}*',
            "confidence": "CRITICAL",
            "note": "Webpack/Vite asset hash — globally unique, same across onion and clearnet mirror"
        })

    # Next.js / React build IDs
    build_id = re.search(r'buildId["\'\s:]+["\']([a-zA-Z0-9_\-]{6,32})["\']', html)
    if build_id:
        val = build_id.group(1)
        fp["searches"].append({
            "type": "NEXTJS_BUILD_ID",
            "value": val,
            "shodan_q":  f'http.html:"{val}"',
            "shodan_url": f'https://www.shodan.io/search?query=http.html%3A%22{val}%22',
            "urlscan_q": f'page.domain:* "{val}"',
            "confidence": "CRITICAL",
            "note": "Next.js buildId is unique per deployment"
        })

    # Custom CSS class names (long unique class names from CSS-in-JS or custom frameworks)
    css_classes = re.findall(r'class=["\']([a-zA-Z][a-zA-Z0-9_-]{12,40})["\']', html)
    unique_classes = [c for c in set(css_classes)
                      if not any(generic in c.lower() for generic in
                                 ["container","wrapper","header","footer","nav","btn",
                                  "col-","row","form","input","modal","alert"])]
    if unique_classes:
        val = unique_classes[0]
        fp["searches"].append({
            "type": "UNIQUE_CSS_CLASS",
            "value": val,
            "shodan_q":  f'http.html:"{val}"',
            "shodan_url": f'https://www.shodan.io/search?query=http.html%3A%22{val}%22',
            "confidence": "HIGH",
        })

    # Analytics IDs (already in infra but duplicate here for urlscan search)
    ga_ids = re.findall(r'\bUA-\d{4,10}-\d{1,4}\b|\bG-[A-Z0-9]{8,12}\b', html)
    for aid in set(ga_ids):
        fp["searches"].append({
            "type": "ANALYTICS_ID",
            "value": aid,
            "urlscan_q": f'page.domain:* "{aid}"',
            "shodan_q":  f'http.html:"{aid}"',
            "shodan_url": f'https://www.shodan.io/search?query=http.html%3A%22{requests.utils.quote(aid)}%22',
            "confidence": "CRITICAL",
            "note": "Analytics ID — same ID on clearnet site links both to operator identity"
        })

    return fp


# ── Domain extraction from every page location ────────────────────────────────
def extract_all_domains_from_page(html: str, headers_raw: dict, pii: list) -> list:
    """Extract every non-CDN clearnet domain from page source and headers."""
    domains = set()
    # href/src/action/data-* attributes
    for v in re.findall(r'(?:href|src|action|data-url|data-href|content)\s*=\s*["\']([^"\']+)', html, re.I):
        if v.startswith("http") and ".onion" not in v:
            m = re.match(r"https?://([a-zA-Z0-9\-._]+\.[a-zA-Z]{2,})", v)
            if m: domains.add(m.group(1).lower())
    # JS string literals and fetch() calls
    for url in re.findall(r'["\']https?://([a-zA-Z0-9\-._]+\.[a-zA-Z]{2,})[/"\']', html):
        if ".onion" not in url: domains.add(url.lower())
    # HTML comments (debug URLs often left here)
    for comment in re.findall(r"<!--(.*?)-->", html, re.DOTALL):
        for url in re.findall(r"https?://([a-zA-Z0-9\-._]+\.[a-zA-Z]{2,})", comment):
            if ".onion" not in url: domains.add(url.lower())
    # CSP header (lists every allowed origin — operators forget this is public)
    h = {k.lower(): v for k, v in headers_raw.items()}
    csp = h.get("content-security-policy", "") + " " + h.get("content-security-policy-report-only", "")
    for d in re.findall(r"https?://([a-zA-Z0-9\-._]+\.[a-zA-Z]{2,})", csp):
        if ".onion" not in d: domains.add(d.lower())
    # Location / Refresh redirect
    for hdr in ["location", "refresh"]:
        val = h.get(hdr, "")
        if val and "http" in val:
            m = re.search(r"https?://([a-zA-Z0-9\-._]+\.[a-zA-Z]{2,})", val)
            if m and ".onion" not in m.group(1): domains.add(m.group(1).lower())
    # PII clearnet URLs
    for p in pii:
        if p.get("type") == "Clearnet URL":
            m = re.match(r"https?://([a-zA-Z0-9\-._]+\.[a-zA-Z]{2,})", p["value"])
            if m and ".onion" not in m.group(1): domains.add(m.group(1).lower())
    return sorted(d for d in domains if not _is_cdn_domain(d))


# ── Main active discovery orchestrator ────────────────────────────────────────
def active_ip_discovery(html: str, headers_raw: dict, pii: list,
                         page_intel: dict, infra: dict) -> dict:
    """
    ACTIVE IP DISCOVERY ENGINE v3.2
    ═════════════════════════════════
    Seven parallel methods, all using free no-key APIs:

    M1  DNS resolution of clearnet domains in page (system + HackerTarget)
    M2  urlscan.io search by page title/fingerprints → direct IP in results
    M3  Shodan InternetDB enrichment for every discovered IP (ports/hostnames)
    M4  ipinfo.io geolocation (backup to ip-api.com, different data source)
    M5  Reverse IP lookup (find co-hosted operator domains)
    M6  Deep HTML fingerprint extraction for manual Shodan/Censys queries
    M7  Shodan/Censys query generation (favicon, title, build hash, analytics)
    """
    result = {
        "discovered_ips":       [],
        "domain_resolutions":   [],
        "urlscan_matches":      [],
        "internetdb_data":      [],
        "reverse_ip":           [],
        "fingerprints":         {},
        "shodan_queries":       [],
        "censys_queries":       [],
        "virustotal_urls":      [],
        "method_summary":       [],
        "all_candidate_domains": [],
    }
    seen_ips: set = set()

    def add_ip(ip: str, source_domain: str, method: str, confidence: str):
        if not ip or not is_public_ip(ip) or ip in seen_ips:
            return None
        seen_ips.add(ip)
        # Try ip-api first, then ipinfo as fallback
        geo = geolocate_ip(ip)
        if not geo.get("success"):
            geo = ipinfo_lookup(ip)
        if not geo.get("country"):
            geo["country"] = "Unknown"
        geo["source_domain"]     = source_domain
        geo["discovery_method"]  = method
        geo["confidence"]        = confidence
        geo["source"]            = f"{method} via {source_domain}" if source_domain else method
        result["discovered_ips"].append(geo)
        time.sleep(0.45)
        return geo

    # ── M1: DNS resolution ─────────────────────────────────────────────────
    candidate_domains = extract_all_domains_from_page(html, headers_raw, pii)
    result["all_candidate_domains"] = candidate_domains
    log.info(f"[IP-DISC M1] DNS: {len(candidate_domains)} candidate domains")

    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
        futures = {ex.submit(dns_resolve_domain, d): d for d in candidate_domains[:20]}
        for fut in concurrent.futures.as_completed(futures, timeout=30):
            domain = futures[fut]
            try:
                ips = fut.result()
                if ips:
                    result["domain_resolutions"].append({"domain": domain, "ips": ips})
                    for ip in ips:
                        g = add_ip(ip, domain, "DNS_RESOLUTION", "HIGH")
                        if g and g.get("success"):
                            log.info(f"[IP-DISC M1] {domain} → {ip} ({g.get('city')}, {g.get('country')})")
            except Exception:
                pass

    # ── M2: urlscan.io search ──────────────────────────────────────────────
    fp = extract_page_fingerprints(html, headers_raw, page_intel)
    result["fingerprints"] = fp

    urlscan_queries = []
    title = fp.get("title", "")
    if title:
        urlscan_queries.append(f'page.title:"{title}"')
    # Add build hash searches
    for s in fp.get("searches", []):
        if s.get("type") in ("NEXTJS_BUILD_ID", "BUILD_HASH_JS", "BUILD_HASH_CSS", "ANALYTICS_ID"):
            uq = s.get("urlscan_q")
            if uq and uq not in urlscan_queries:
                urlscan_queries.append(uq)

    log.info(f"[IP-DISC M2] urlscan.io: {len(urlscan_queries)} queries")
    for q in urlscan_queries[:4]:
        matches = urlscan_search(q, size=5)
        for m in matches:
            ip = m.get("ip", "")
            result["urlscan_matches"].append(m)
            g = add_ip(ip, m.get("domain", ""), "URLSCAN_IO_SEARCH", "HIGH")
            if g and g.get("success"):
                log.info(f"[IP-DISC M2] urlscan match: {m.get('domain')} → {ip}")
        if matches:
            time.sleep(0.5)

    # ── M3: Shodan InternetDB enrichment ───────────────────────────────────
    log.info(f"[IP-DISC M3] InternetDB enrichment for {len(seen_ips)} IPs")
    for ip in list(seen_ips)[:10]:
        idb = internetdb_lookup(ip)
        if idb.get("found"):
            result["internetdb_data"].append(idb)
            # Hostnames in InternetDB sometimes reveal operator domain
            for entry in result["discovered_ips"]:
                if entry.get("ip") == ip:
                    entry["hostnames"] = idb.get("hostnames", [])
                    entry["open_ports"] = idb.get("ports", [])
                    entry["vulns"] = idb.get("vulns", [])
            log.info(f"[IP-DISC M3] InternetDB {ip}: ports={idb.get('ports')}, hostnames={idb.get('hostnames')}")

    # ── M4: ipinfo for any still-missing geos ─────────────────────────────
    for entry in result["discovered_ips"]:
        if not entry.get("country") or entry.get("country") == "Unknown":
            geo2 = ipinfo_lookup(entry["ip"])
            if geo2.get("success"):
                entry.update({k: v for k, v in geo2.items() if v and k not in ("ip",)})

    # ── M5: Reverse IP on discovered IPs ──────────────────────────────────
    for ip in list(seen_ips)[:4]:
        rev = hackertarget_reverseip(ip)
        if rev.get("success"):
            result["reverse_ip"].append(rev)
            log.info(f"[IP-DISC M5] Reverse IP {ip}: {rev['count']} co-hosted domains")
        time.sleep(1.2)

    # ── M6/M7: Query generation (Shodan + Censys) ─────────────────────────
    h = {k.lower(): v for k, v in headers_raw.items()}
    favicon_hash = infra.get("favicon", {}).get("hash")
    shodan_queries = []

    # Favicon hash — most reliable cross-site fingerprint
    if favicon_hash:
        shodan_queries.append({
            "query":      f"http.favicon.hash:{favicon_hash}",
            "url":        f"https://www.shodan.io/search?query=http.favicon.hash%3A{favicon_hash}",
            "method":     "Favicon MurmurHash3 — finds EVERY server using same icon",
            "confidence": "CRITICAL",
        })

    # All fingerprint-based searches
    for s in fp.get("searches", []):
        sq = s.get("shodan_q", "")
        if sq:
            shodan_queries.append({
                "query":      sq,
                "url":        s.get("shodan_url", ""),
                "method":     f"{s['type']}: {s['value'][:60]}",
                "confidence": s.get("confidence", "MEDIUM"),
            })

    result["shodan_queries"] = shodan_queries

    censys_queries = []
    if title:
        censys_queries.append({
            "query": f'services.http.response.html_title="{title}"',
            "url":   f'https://search.censys.io/search?resource=hosts&q=services.http.response.html_title%3D%22{requests.utils.quote(title)}%22',
            "method": "Page title on Censys",
        })
    server_hdr = h.get("server", "")
    if server_hdr:
        censys_queries.append({
            "query": f'services.http.response.headers.server="{server_hdr}"',
            "url":   f'https://search.censys.io/search?resource=hosts&q=services.http.response.headers.server%3D%22{requests.utils.quote(server_hdr)}%22',
            "method": "Server header on Censys",
        })
    result["censys_queries"] = censys_queries

    # Historical DNS links
    vt_urls = []
    for domain in candidate_domains[:6]:
        vt_urls.append({
            "domain":         domain,
            "virustotal":     f"https://www.virustotal.com/gui/domain/{domain}/details",
            "securitytrails": f"https://securitytrails.com/domain/{domain}/history/a",
            "note": "Historical A records — find original IP before CDN was added",
        })
    result["virustotal_urls"] = vt_urls

    # ── Summary ────────────────────────────────────────────────────────────
    n = len(result["discovered_ips"])
    nd = len(candidate_domains)
    nu = len([m for m in result["urlscan_matches"] if m.get("ip")])
    result["method_summary"] = [
        f"Clearnet domains found in page: {nd}",
        f"IPs resolved via DNS: {len([g for g in result['discovered_ips'] if 'DNS' in g.get('discovery_method','')])}",
        f"IPs found via urlscan.io: {nu}",
        f"Shodan queries generated: {len(shodan_queries)}",
        f"Censys queries generated: {len(censys_queries)}",
        f"Total unique IPs discovered: {n}",
    ]
    if n == 0 and nd == 0:
        result["method_summary"].append(
            "No clearnet domains in page. Run Shodan queries manually using the fingerprints above — "
            "favicon hash and page title are the most reliable."
        )
    elif n == 0:
        result["method_summary"].append(
            f"{nd} domain(s) found — all behind CDN/Cloudflare. "
            "Check SecurityTrails historical A records and urlscan.io screenshot archive."
        )
    log.info(f"[IP-DISC] Complete — {n} IPs from {nd} domains + {nu} urlscan matches")
    return result


# ══════════════════════════════════════════════
# ENGINE 4: HTTP HEADER ANALYSIS
# ══════════════════════════════════════════════

_COMMON_CDN_DOMAINS = {
    "ajax.googleapis.com", "fonts.googleapis.com", "fonts.gstatic.com",
    "cdnjs.cloudflare.com", "cdn.jsdelivr.net", "unpkg.com",
    "code.jquery.com", "stackpath.bootstrapcdn.com", "maxcdn.bootstrapcdn.com",
    "cdn.cloudflare.com", "use.fontawesome.com", "kit.fontawesome.com",
    "static.cloudflareinsights.com", "challenges.cloudflare.com",
    "www.googletagmanager.com", "www.google-analytics.com",
    "connect.facebook.net", "platform.twitter.com",
    "cdn.shopify.com", "assets.shopifycdn.com",
}

def _is_cdn_domain(domain: str) -> bool:
    """Return True if domain is a known CDN / shared infrastructure."""
    d = domain.lower()
    if d in _COMMON_CDN_DOMAINS:
        return True
    for cdn in ["cloudflare", "akamai", "fastly", "amazonaws", "cloudfront",
                "googleapis", "gstatic", "jquery", "bootstrapcdn", "jsdelivr",
                "shopify", "shopifycdn", "fontawesome", "unpkg"]:
        if cdn in d:
            return True
    return False


def dns_resolve_domain(domain: str) -> dict:
    """
    Resolve a clearnet domain to its IP addresses using the system DNS resolver.
    This is the single most reliable method to find IPs from a dark web site
    that has clearnet presence.
    """
    clean = re.sub(r"^https?://", "", domain).split("/")[0].strip().lower()
    if not clean or ".onion" in clean or _is_cdn_domain(clean):
        return {"domain": clean, "ips": [], "skipped": True, "reason": "CDN/shared hosting — not operator infrastructure"}

    try:
        infos = socket.getaddrinfo(clean, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        ips = list(set(info[4][0] for info in infos))
        public_ips = [ip for ip in ips if is_public_ip(ip)]
        return {
            "domain": clean,
            "ips": public_ips,
            "all_resolved": ips,
            "success": bool(public_ips),
        }
    except socket.gaierror as e:
        return {"domain": clean, "ips": [], "success": False, "error": str(e)}
    except Exception as e:
        return {"domain": clean, "ips": [], "success": False, "error": str(e)}


def hackertarget_dns(domain: str) -> dict:
    """
    HackerTarget DNS lookup API — free, no key required.
    Returns A records and often returns results even when local DNS fails.
    Useful as a secondary resolver.
    """
    clean = domain.strip().lower()
    if _is_cdn_domain(clean):
        return {"domain": clean, "ips": [], "skipped": True}
    try:
        r = requests.get(
            f"https://api.hackertarget.com/dnslookup/?q={clean}",
            timeout=12, headers={"User-Agent": UA}
        )
        if r.status_code != 200 or "error" in r.text.lower():
            return {"domain": clean, "ips": [], "success": False}
        ips = re.findall(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b", r.text)
        public_ips = [ip for ip in ips if is_public_ip(ip)]
        return {"domain": clean, "ips": list(set(public_ips)), "success": bool(public_ips), "raw": r.text[:200]}
    except Exception as e:
        return {"domain": clean, "ips": [], "success": False, "error": str(e)}


def hackertarget_reverseip(ip: str) -> dict:
    """
    Reverse IP lookup — find all domains hosted on same IP.
    Often reveals operator's other sites and clearnet identity.
    """
    try:
        r = requests.get(
            f"https://api.hackertarget.com/reverseiplookup/?q={ip}",
            timeout=12, headers={"User-Agent": UA}
        )
        if r.status_code != 200 or "error" in r.text.lower() or "No records" in r.text:
            return {"ip": ip, "domains": [], "success": False}
        domains = [d.strip() for d in r.text.strip().split("\n") if d.strip() and "." in d]
        return {"ip": ip, "domains": domains[:30], "count": len(domains), "success": bool(domains)}
    except Exception as e:
        return {"ip": ip, "domains": [], "success": False, "error": str(e)}


def hackertarget_httpheaders(domain: str) -> dict:
    """
    Fetch HTTP headers from clearnet domain via HackerTarget.
    Useful when direct fetch is blocked — may reveal Server, X-Powered-By,
    and sometimes forwarding headers from the clearnet side.
    """
    clean = domain.strip().lower()
    try:
        r = requests.get(
            f"https://api.hackertarget.com/httpheaders/?q=https://{clean}",
            timeout=15, headers={"User-Agent": UA}
        )
        if r.status_code != 200 or "error" in r.text.lower():
            return {"domain": clean, "headers": "", "success": False}
        return {"domain": clean, "headers": r.text[:800], "success": True}
    except Exception as e:
        return {"domain": clean, "headers": "", "success": False, "error": str(e)}


def extract_all_domains_from_page(html: str, headers_raw: dict, pii: list) -> list:
    """
    Extract every clearnet domain reference from:
    - href/src/action attributes
    - meta content/refresh URLs
    - JavaScript fetch/XMLHttpRequest calls
    - CSS @import / url()
    - HTML comments (often contain debug URLs)
    - HTTP response headers (Location, Content-Security-Policy, etc.)
    - PII clearnet URLs already extracted
    - CSP header (lists all allowed origins — gold mine for clearnet domains)
    """
    domains = set()

    # ── URL attributes in HTML ─────────────────────────────────────────
    for attr_val in re.findall(r'(?:href|src|action|data-url|data-href|content)\s*=\s*["\']([^"\']+)', html, re.I):
        if attr_val.startswith("http") and ".onion" not in attr_val:
            m = re.match(r"https?://([a-zA-Z0-9\-._]+\.[a-zA-Z]{2,})", attr_val)
            if m: domains.add(m.group(1).lower())

    # ── JavaScript URL strings ─────────────────────────────────────────
    for url in re.findall(r'["\']https?://([a-zA-Z0-9\-._]+\.[a-zA-Z]{2,})[/"\']', html):
        if ".onion" not in url:
            domains.add(url.lower())

    # ── fetch() / XHR calls ────────────────────────────────────────────
    for url in re.findall(r'fetch\s*\(\s*["\']https?://([a-zA-Z0-9\-._]+\.[a-zA-Z]{2,})', html, re.I):
        if ".onion" not in url:
            domains.add(url.lower())

    # ── HTML comments ──────────────────────────────────────────────────
    for comment in re.findall(r"<!--(.*?)-->", html, re.DOTALL):
        for url in re.findall(r"https?://([a-zA-Z0-9\-._]+\.[a-zA-Z]{2,})", comment):
            if ".onion" not in url:
                domains.add(url.lower())

    # ── CSP header (Content-Security-Policy) — lists all origins ───────
    h = {k.lower(): v for k, v in headers_raw.items()}
    csp = h.get("content-security-policy", "") + " " + h.get("content-security-policy-report-only", "")
    if csp.strip():
        for domain_in_csp in re.findall(r"https?://([a-zA-Z0-9\-._]+\.[a-zA-Z]{2,})", csp):
            if ".onion" not in domain_in_csp:
                domains.add(domain_in_csp.lower())

    # ── Location / Refresh redirect headers ──────────────────────────
    for hdr in ["location", "refresh"]:
        val = h.get(hdr, "")
        if val and "http" in val:
            m = re.search(r"https?://([a-zA-Z0-9\-._]+\.[a-zA-Z]{2,})", val)
            if m and ".onion" not in m.group(1):
                domains.add(m.group(1).lower())

    # ── PII clearnet URLs ─────────────────────────────────────────────
    for p in pii:
        if p.get("type") == "Clearnet URL":
            m = re.match(r"https?://([a-zA-Z0-9\-._]+\.[a-zA-Z]{2,})", p["value"])
            if m and ".onion" not in m.group(1):
                domains.add(m.group(1).lower())

    # Filter out pure CDN/shared hosting — keep operator-owned domains
    operator_domains = [d for d in domains if not _is_cdn_domain(d)]
    return sorted(operator_domains)


def active_ip_discovery(html: str, headers_raw: dict, pii: list,
                         page_intel: dict, infra: dict) -> dict:
    """
    ACTIVE IP DISCOVERY ENGINE
    ═══════════════════════════
    Multi-method correlation attack to find the real IP of the hidden service.

    Method 1 — DNS Resolution of clearnet domains in page source
    Method 2 — HackerTarget DNS lookup (secondary resolver)
    Method 3 — Reverse IP lookup (find co-hosted domains)
    Method 4 — CT log domain resolution (resolve IPs from cert history)
    Method 5 — Shodan query generation (for analyst to run manually)
    Method 6 — Header clearnet domain resolution (CSP, Location, etc.)
    """
    result = {
        "discovered_ips": [],
        "domain_resolutions": [],
        "reverse_ip": [],
        "shodan_queries": [],
        "censys_queries": [],
        "virustotal_urls": [],
        "method_summary": [],
        "all_candidate_domains": [],
    }

    seen_ips = set()

    def add_ip(ip, domain, method, confidence):
        if not is_public_ip(ip) or ip in seen_ips:
            return
        seen_ips.add(ip)
        geo = geolocate_ip(ip)
        entry = {
            "ip": ip,
            "source_domain": domain,
            "discovery_method": method,
            "confidence": confidence,
            **geo,
        }
        result["discovered_ips"].append(entry)
        time.sleep(0.45)  # ip-api rate limit

    # ── Collect all candidate domains ────────────────────────────────────
    candidate_domains = extract_all_domains_from_page(html, headers_raw, pii)
    result["all_candidate_domains"] = candidate_domains
    log.info(f"[IP-DISCOVERY] {len(candidate_domains)} candidate clearnet domains found")

    # ── Method 1: Direct DNS resolution ─────────────────────────────────
    if candidate_domains:
        result["method_summary"].append(f"DNS resolution attempted for {len(candidate_domains)} domains")
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
            dns_futures = {ex.submit(dns_resolve_domain, d): d for d in candidate_domains[:20]}
            for fut in concurrent.futures.as_completed(dns_futures, timeout=30):
                try:
                    res = fut.result()
                    if res.get("ips"):
                        result["domain_resolutions"].append(res)
                        for ip in res["ips"]:
                            add_ip(ip, res["domain"], "DNS_RESOLUTION", "HIGH")
                            log.info(f"[IP-DISCOVERY] DNS: {res['domain']} → {ip}")
                except Exception:
                    pass

    # ── Method 2: HackerTarget as secondary resolver ─────────────────────
    # Only for domains that failed local DNS (could be geo-restricted)
    failed_local = [d for d in candidate_domains
                    if not any(r.get("domain") == d and r.get("ips") for r in result["domain_resolutions"])]
    if failed_local:
        for domain in failed_local[:8]:
            res = hackertarget_dns(domain)
            if res.get("ips"):
                result["domain_resolutions"].append({**res, "resolver": "hackertarget"})
                for ip in res["ips"]:
                    add_ip(ip, domain, "HACKERTARGET_DNS", "HIGH")
                    log.info(f"[IP-DISCOVERY] HackerTarget DNS: {domain} → {ip}")
            time.sleep(1.2)  # HackerTarget rate limit

    # ── Method 3: Reverse IP lookup on all discovered IPs ────────────────
    discovered_so_far = list(seen_ips)
    for ip in discovered_so_far[:5]:
        rev = hackertarget_reverseip(ip)
        if rev.get("success"):
            result["reverse_ip"].append(rev)
            log.info(f"[IP-DISCOVERY] Reverse IP {ip}: {rev['count']} co-hosted domains")
        time.sleep(1.2)

    # ── Method 4: CT log domain resolution ──────────────────────────────
    # Domains found in certificate transparency → resolve their IPs
    ct_domains = set()
    for p in pii:
        if p.get("type") == "Clearnet URL":
            m = re.match(r"https?://([a-zA-Z0-9\-._]+\.[a-zA-Z]{2,})", p["value"])
            if m: ct_domains.add(m.group(1).lower())
    # Add from infra clearnet links
    for link in page_intel.get("clearnet_links", [])[:10]:
        href = link.get("href", "")
        m = re.match(r"https?://([a-zA-Z0-9\-._]+\.[a-zA-Z]{2,})", href)
        if m and not _is_cdn_domain(m.group(1)):
            ct_domains.add(m.group(1).lower())
    for domain in list(ct_domains - set(candidate_domains))[:5]:
        res = dns_resolve_domain(domain)
        if res.get("ips"):
            result["domain_resolutions"].append({**res, "method": "CT_LOG_DOMAIN"})
            for ip in res["ips"]:
                add_ip(ip, domain, "CT_LOG_DOMAIN_RESOLUTION", "MEDIUM")

    # ── Method 5: Shodan query generation ────────────────────────────────
    # Build ready-to-paste Shodan queries using page fingerprints
    h = {k.lower(): v for k, v in headers_raw.items()}
    server_hdr  = h.get("server", "")
    powered_by  = h.get("x-powered-by", "")
    favicon_hash = infra.get("favicon", {}).get("hash")
    page_title  = page_intel.get("title", "")

    shodan_queries = []
    if favicon_hash:
        shodan_queries.append({
            "query":  f"http.favicon.hash:{favicon_hash}",
            "url":    f"https://www.shodan.io/search?query=http.favicon.hash%3A{favicon_hash}",
            "method": "Favicon MurmurHash3 — finds ALL servers using same favicon",
            "confidence": "CRITICAL",
        })
    if server_hdr and len(server_hdr) > 4 and server_hdr not in ("nginx", "Apache", "Apache/2", "nginx/1"):
        q = server_hdr.replace('"', '\\"')
        shodan_queries.append({
            "query":  f'http.server:"{q}"',
            "url":    f'https://www.shodan.io/search?query=http.server%3A%22{requests.utils.quote(server_hdr)}%22',
            "method": f"Unique Server header: {server_hdr}",
            "confidence": "HIGH",
        })
    if page_title and len(page_title) > 10:
        q = page_title[:60]
        shodan_queries.append({
            "query":  f'http.title:"{q}"',
            "url":    f'https://www.shodan.io/search?query=http.title%3A%22{requests.utils.quote(q)}%22',
            "method": f"Page title fingerprint: {q}",
            "confidence": "HIGH",
        })
    if powered_by:
        shodan_queries.append({
            "query":  f'http.html:"{powered_by}"',
            "url":    f'https://www.shodan.io/search?query=http.html%3A%22{requests.utils.quote(powered_by)}%22',
            "method": f"X-Powered-By fingerprint: {powered_by}",
            "confidence": "MEDIUM",
        })
    for cat, items in infra.get("analytics_ids", {}).items():
        for item in items:
            aid = item.get("id", "")
            if aid:
                shodan_queries.append({
                    "query":  f'http.html:"{aid}"',
                    "url":    f'https://www.shodan.io/search?query=http.html%3A%22{requests.utils.quote(aid)}%22',
                    "method": f"Analytics ID: {aid} — finds clearnet site using same tracker",
                    "confidence": "CRITICAL",
                })
    result["shodan_queries"] = shodan_queries

    # ── Method 6: Censys query generation ────────────────────────────────
    censys_queries = []
    if page_title and len(page_title) > 10:
        censys_queries.append({
            "query": f'services.http.response.html_title="{page_title[:60]}"',
            "url":   f'https://search.censys.io/search?resource=hosts&q=services.http.response.html_title%3D%22{requests.utils.quote(page_title[:60])}%22',
            "method": "Page title on Censys",
        })
    if server_hdr:
        censys_queries.append({
            "query": f'services.http.response.headers.server="{server_hdr}"',
            "url":   f'https://search.censys.io/search?resource=hosts&q=services.http.response.headers.server%3D%22{requests.utils.quote(server_hdr)}%22',
            "method": "Server header on Censys",
        })
    result["censys_queries"] = censys_queries

    # ── Method 7: VirusTotal / passive DNS URLs ───────────────────────────
    vt_urls = []
    for domain in candidate_domains[:6]:
        vt_urls.append({
            "domain": domain,
            "virustotal": f"https://www.virustotal.com/gui/domain/{domain}/details",
            "securitytrails": f"https://securitytrails.com/domain/{domain}/history/a",
            "note": "Check 'Historical IPs' — reveals IPs before CDN/proxy was added",
        })
    result["virustotal_urls"] = vt_urls

    # ── Summary ──────────────────────────────────────────────────────────
    n_discovered = len(result["discovered_ips"])
    n_domains    = len(candidate_domains)
    result["method_summary"] = [
        f"Candidate clearnet domains found in page: {n_domains}",
        f"IPs successfully resolved and geolocated: {n_discovered}",
        f"Shodan correlation queries generated: {len(shodan_queries)}",
        f"Censys queries generated: {len(censys_queries)}",
        f"Reverse IP lookups performed: {len(result['reverse_ip'])}",
        f"VirusTotal / passive DNS links: {len(vt_urls)}",
    ]
    if n_discovered == 0 and n_domains == 0:
        result["method_summary"].append(
            "ASSESSMENT: No clearnet domains found in page. "
            "Site has no external links — use Shodan favicon hash and title queries manually."
        )
    elif n_discovered == 0:
        result["method_summary"].append(
            f"ASSESSMENT: {n_domains} domain(s) found but DNS resolution returned no IPs. "
            "Domains may be behind Cloudflare. Use Shodan + historical DNS tools."
        )

    log.info(f"[IP-DISCOVERY] Complete — {n_discovered} IPs from {n_domains} domains")
    return result


# ══════════════════════════════════════════════
# ENGINE 4: HTTP HEADER ANALYSIS
# ══════════════════════════════════════════════
def analyze_headers(headers: dict) -> list:
    findings = []
    h = {k.lower(): v for k, v in headers.items()}

    if "server" in h:
        findings.append({"field": "Server", "value": h["server"], "risk": "HIGH",
            "note": f"Software fingerprint. Search CVEs for '{h['server']}'",
            "action": f'shodan.io: http.server:"{h["server"]}"'})

    if "x-powered-by" in h:
        findings.append({"field": "X-Powered-By", "value": h["x-powered-by"], "risk": "HIGH",
            "note": "Backend tech stack exposed — research known exploits for this exact version"})

    if "date" in h:
        findings.append({"field": "Date", "value": h["date"], "risk": "MEDIUM",
            "note": "Server clock → timezone fingerprint. Compare post times to map operator schedule"})

    # ── Proxy / real-IP headers ──────────────────────────────────────────
    if "x-forwarded-for" in h:
        chain = h["x-forwarded-for"]
        parts = [p.strip() for p in chain.split(",")]
        findings.append({"field": "X-Forwarded-For", "value": chain, "risk": "CRITICAL",
            "note": (f"PROXY CHAIN LEAK — {len(parts)} hop(s). "
                     f"Leftmost IP is operator real IP: {parts[0]}. "
                     "Hidden service is running behind a reverse proxy — severe OPSEC failure."),
            "action": f"IMMEDIATELY geolocate: {parts[0]} (client) + {', '.join(parts[1:])} (proxies)"})

    if "forwarded" in h:
        entries = _parse_rfc7239_forwarded(h["forwarded"])
        ips = [e["ip"] for e in entries if e.get("ip")]
        findings.append({"field": "Forwarded (RFC 7239)", "value": h["forwarded"], "risk": "CRITICAL",
            "note": f"RFC 7239 structured proxy header — {len(entries)} entry/entries. "
                    f"Extracted IPs: {', '.join(ips) or 'see raw value'}",
            "action": f"Geolocate extracted for= IPs: {', '.join(ips)}"})

    if "x-real-ip" in h:
        findings.append({"field": "X-Real-IP", "value": h["x-real-ip"], "risk": "CRITICAL",
            "note": "nginx/HAProxy real client IP header — high-confidence real operator IP",
            "action": f"Geolocate immediately: {h['x-real-ip']}"})

    if "cf-connecting-ip" in h:
        findings.append({"field": "CF-Connecting-IP", "value": h["cf-connecting-ip"], "risk": "CRITICAL",
            "note": "Cloudflare real client IP — site is behind Cloudflare. This is operator's true IP.",
            "action": f"Geolocate: {h['cf-connecting-ip']}"})

    if "true-client-ip" in h:
        findings.append({"field": "True-Client-IP", "value": h["true-client-ip"], "risk": "CRITICAL",
            "note": "Akamai/enterprise CDN real client IP header",
            "action": f"Geolocate: {h['true-client-ip']}"})

    if "via" in h:
        findings.append({"field": "Via", "value": h["via"], "risk": "HIGH",
            "note": "Intermediate proxy/CDN infrastructure revealed — may expose upstream server"})

    if "x-generator" in h:
        findings.append({"field": "X-Generator", "value": h["x-generator"], "risk": "MEDIUM",
            "note": "CMS version — search NVD/CVE for vulnerabilities in this exact version"})

    if "content-language" in h:
        findings.append({"field": "Content-Language", "value": h["content-language"], "risk": "MEDIUM",
            "note": f"Server locale '{h['content-language']}' corroborates operator geographic region"})

    if "set-cookie" in h:
        findings.append({"field": "Set-Cookie", "value": h["set-cookie"][:200], "risk": "MEDIUM",
            "note": "Inspect for clearnet domain attributes, session ID patterns, insecure flags"})

    if "last-modified" in h:
        findings.append({"field": "Last-Modified", "value": h["last-modified"], "risk": "MEDIUM",
            "note": "File timestamp reveals operator's active hours and update schedule"})

    if "x-runtime" in h:
        findings.append({"field": "X-Runtime", "value": h["x-runtime"], "risk": "LOW",
            "note": "Server processing time — fingerprints backend load and framework"})

    if "etag" in h:
        findings.append({"field": "ETag", "value": h["etag"], "risk": "LOW",
            "note": "On some old Apache configs ETag leaks inode number revealing filesystem info"})

    if not any(k in h for k in ["strict-transport-security", "x-frame-options", "content-security-policy"]):
        findings.append({"field": "Missing Security Headers", "value": "No HSTS / XFO / CSP", "risk": "LOW",
            "note": "Low technical sophistication — default config, likely self-hosted"})

    return findings


# ══════════════════════════════════════════════
# ENGINE 5: STYLOMETRY
# ══════════════════════════════════════════════
FUNC_WORDS = ["the","be","to","of","and","a","in","that","have","it","for","not","on","with",
              "he","as","you","do","at","this","but","his","by","from","they","we","say","her",
              "she","or","an","will","my","one","all","would","there","their","what","so","if",
              "about","who","which","me","when","make","can","time","no","just","know","take",
              "into","your","some","could","them","see","than","then","now","look","only"]

def analyze_stylometry(text: str) -> Optional[dict]:
    clean = re.sub(r"<[^>]+>", " ", text)
    clean = re.sub(r"\s+", " ", clean).strip()
    if len(clean) < 100:
        return None
    sentences = [s.strip() for s in re.split(r"[.!?]+", clean) if len(s.strip()) > 10]
    words = re.findall(r"\b[a-z']{2,}\b", clean.lower())
    chars = re.sub(r"[^a-zA-Z]", "", clean)
    if not words:
        return None
    freq = Counter(words)
    unique = set(words)
    ttr = len(unique) / len(words)
    hapax = sum(1 for f in freq.values() if f == 1)
    hapax_ratio = hapax / len(unique) if unique else 0
    m1 = len(words)
    m2 = sum(f * f for f in freq.values())
    yules_k = round(10000 * (m2 - m1) / (m1 * m1), 2) if m1 > 0 else 0
    v1, v, n = hapax, len(unique), len(words)
    honores_r = round((100 * (v1 / (1 - v1/v))) / n, 2) if v > 0 and v1 != v and n > 0 else 0
    func_profile = {w: round(freq.get(w, 0) / len(words) * 1000, 3) for w in FUNC_WORDS}
    trigrams = Counter()
    for i in range(len(chars) - 2):
        tg = chars[i:i+3].lower()
        if re.match(r"^[a-z]{3}$", tg):
            trigrams[tg] += 1
    hindi   = bool(re.search(r"\b(?:bhai|yaar|kya|aur|nahi|hai|kar|karo|matlab|sahi|thik|wala|mera|tera|hoga|karna|chahiye|abhi|bahut|iska)\b", clean, re.I))
    russian = bool(re.search(r"\b(?:tovar|nakrutka|obnal|mule|drop|klad|zakupit|prodayom|kupit|prodat|tovar)\b", clean, re.I))
    spanish = bool(re.search(r"\b(?:que|como|para|esto|precio|comprar|vender|también|servicio)\b", clean, re.I))
    brit    = bool(re.search(r"\b(?:colour|favour|honour|behaviour|realise|organisation|catalogue|centre|cheque|defence)\b", clean, re.I))
    amer    = bool(re.search(r"\b(?:color|favor|honor|behavior|realize|organization|catalog|center|check|defense)\b", clean, re.I))
    if hindi:     lang = "Hindi/Hinglish — Indian subcontinent"
    elif russian: lang = "Russian — Eastern European"
    elif spanish: lang = "Spanish — Latin America / Spain"
    elif brit:    lang = "British English"
    elif amer:    lang = "American English"
    else:         lang = "Inconclusive"
    richness = ("Very high — academic/professional" if ttr > 0.80 else
                "High — educated writer" if ttr > 0.65 else
                "Moderate — average writer" if ttr > 0.50 else
                "Low — limited vocabulary / translated")
    return {
        "word_count": len(words), "unique_words": len(unique),
        "sentence_count": len(sentences), "char_count": len(chars),
        "ttr": round(ttr, 4),
        "avg_sentence_length": round(len(words) / max(len(sentences), 1), 2),
        "avg_word_length": round(sum(len(w) for w in words) / len(words), 2),
        "hapax_legomena": hapax, "hapax_ratio": round(hapax_ratio, 4),
        "yules_k": yules_k, "honores_r": honores_r,
        "vocabulary_richness": richness,
        "top_function_words": sorted(func_profile.items(), key=lambda x: x[1], reverse=True)[:15],
        "top_trigrams": trigrams.most_common(10),
        "punctuation": {
            "commas": len(re.findall(r",", clean)),
            "exclamations": len(re.findall(r"!", clean)),
            "questions": len(re.findall(r"\?", clean)),
            "ellipsis": len(re.findall(r"\.\.\.", clean)),
            "all_caps_words": len(re.findall(r"\b[A-Z]{3,}\b", clean)),
        },
        "language": {
            "hindi_romanized": hindi, "russian_patterns": russian,
            "spanish_patterns": spanish, "british_spelling": brit,
            "american_spelling": amer, "likely_native_language": lang,
        },
        "cross_match_note": "Export top_function_words + top_trigrams into JGAAP or stylo (R) for cross-document authorship attribution",
    }


# ══════════════════════════════════════════════
# ENGINE 6: PAGE INTELLIGENCE
# ══════════════════════════════════════════════
def extract_page_intel(html: str, url: str) -> dict:
    soup = BeautifulSoup(html, "lxml")
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()
    plain = soup.get_text(separator=" ", strip=True)
    all_links = [{"href": a.get("href", ""), "text": a.get_text(strip=True)[:80]} for a in soup.find_all("a", href=True)]
    clearnet_links = [l for l in all_links if l["href"].startswith("http") and ".onion" not in l["href"]]
    onion_links    = [l for l in all_links if ".onion" in l["href"]]
    meta = {}
    for m in soup.find_all("meta"):
        name = m.get("name") or m.get("property") or m.get("http-equiv", "")
        content = m.get("content", "")
        if name and content:
            meta[name] = content
    title_tag = soup.find("title")
    favicon = ""
    for link in soup.find_all("link"):
        rel = link.get("rel", [])
        if "icon" in rel or "shortcut" in rel:
            favicon = link.get("href", "")
            break
    hl = html.lower()
    platforms = []
    if "wordpress" in hl or "wp-content" in hl: platforms.append("WordPress")
    if "flask" in hl or "werkzeug" in hl:        platforms.append("Flask (Python)")
    if "django" in hl:                            platforms.append("Django (Python)")
    if "laravel" in hl:                           platforms.append("Laravel (PHP)")
    if "drupal" in hl:                            platforms.append("Drupal")
    if "opencart" in hl:                          platforms.append("OpenCart")
    if "woocommerce" in hl:                       platforms.append("WooCommerce")
    categories = []
    if re.search(r"\b(?:drug|narcotic|cocaine|heroin|meth|fentanyl|mdma|cannabis|pills|ketamine|lsd|amphetamine)\b", hl):
        categories.append("Narcotics Market")
    if re.search(r"\b(?:weapon|gun|rifle|pistol|ammo|firearm|explosive|grenade|ak47)\b", hl):
        categories.append("Weapons Market")
    if re.search(r"\b(?:carding|cvv|dumps|fullz|credit card|bank log|cc shop|debit card)\b", hl):
        categories.append("Financial Fraud / Carding")
    if re.search(r"\b(?:passport|fake id|driver.?s license|counterfeit|ssn|aadhaar|pan card)\b", hl):
        categories.append("Counterfeit Documents")
    if re.search(r"\b(?:data breach|database leak|hacked|dox|credentials|combo list|stealer logs)\b", hl):
        categories.append("Data Leaks / Breaches")
    if re.search(r"\b(?:hitman|assassination|murder for hire|contract kill)\b", hl):
        categories.append("Violence for Hire")
    if re.search(r"\b(?:ransomware|malware|rat|exploit|0day|botnet|stealers|crypter)\b", hl):
        categories.append("Cybercrime / Malware")
    if re.search(r"\b(?:human trafficking|escort service|smuggling|migration)\b", hl):
        categories.append("Human Trafficking / Smuggling")
    scripts = soup.find_all("script")
    ext_scripts = [s.get("src", "") for s in scripts if s.get("src") and ".onion" not in s.get("src", "") and s.get("src", "").startswith("http")]
    ga_ids = list(set(re.findall(r"UA-\d{4,10}-\d{1,4}|G-[A-Z0-9]{8,12}", html)))
    return {
        "title": title_tag.get_text(strip=True) if title_tag else "",
        "plain_text": plain[:6000],
        "all_text_for_analysis": plain,
        "clearnet_links": clearnet_links[:20],
        "onion_links": onion_links[:20],
        "all_links_count": len(all_links),
        "meta_tags": meta,
        "platform_signals": platforms,
        "category_signals": categories,
        "analytics_ids": ga_ids,
        "favicon_url": favicon,
        "external_scripts": ext_scripts[:10],
        "has_js": len(scripts) > 0,
    }


# ══════════════════════════════════════════════
# ENGINE 7: CERTIFICATE TRANSPARENCY
# ══════════════════════════════════════════════
def query_ct(domain: str) -> dict:
    clean = re.sub(r"^https?://", "", domain).split("/")[0].strip()
    if not clean or ".onion" in clean:
        return {"error": "Provide a clearnet domain from page source"}
    try:
        r = requests.get(f"https://crt.sh/?q={clean}&output=json", timeout=15)
        if r.status_code != 200:
            return {"error": f"crt.sh returned HTTP {r.status_code}"}
        data = r.json()
        seen, unique = set(), []
        for c in data:
            key = f"{c.get('common_name')}_{c.get('issuer_name')}"
            if key not in seen:
                seen.add(key)
                unique.append({
                    "common_name": c.get("common_name"),
                    "issuer": c.get("issuer_name"),
                    "not_before": c.get("not_before"),
                    "not_after": c.get("not_after"),
                    "san_domains": c.get("name_value", "").split("\n"),
                })
        all_domains = set()
        for c in unique:
            for d in c.get("san_domains", []):
                if d.strip():
                    all_domains.add(d.strip())
        return {
            "domain": clean,
            "total_certs": len(data),
            "unique_certs": len(unique),
            "results": unique[:20],
            "all_san_domains": sorted(all_domains),
            "first_seen": min((c.get("not_before", "") for c in data), default=""),
            "shodan_query": f"ssl.cert.subject.cn:{clean}",
            "investigation_note": f"Run on Shodan: ssl.cert.subject.cn:{clean} — may reveal hosting IP",
        }
    except Exception as e:
        return {"error": str(e)}


# ══════════════════════════════════════════════
# ENGINE 8: BLOCKCHAIN FORENSICS
# ══════════════════════════════════════════════
def query_btc(address: str) -> dict:
    if not address or len(address) < 25:
        return {"error": "Invalid address"}
    try:
        r = requests.get(f"https://blockchair.com/bitcoin/dashboards/address/{address}", timeout=15)
        if r.status_code != 200:
            return {"error": f"Blockchair HTTP {r.status_code}", "manual_url": f"https://oxt.me/address/{address}"}
        d = r.json().get("data", {}).get(address, {}).get("address", {})
        if not d:
            return {"error": "No address data returned", "manual_url": f"https://oxt.me/address/{address}"}
        return {
            "address": address,
            "balance_btc": d.get("balance", 0) / 1e8,
            "total_received_btc": d.get("received", 0) / 1e8,
            "total_spent_btc": d.get("spent", 0) / 1e8,
            "transaction_count": d.get("transaction_count", 0),
            "first_seen": d.get("first_seen_receiving"),
            "last_seen": d.get("last_seen_spending"),
            "unspent_outputs": d.get("unspent_output_count", 0),
            "links": {
                "oxt_me": f"https://oxt.me/address/{address}",
                "blockchair": f"https://blockchair.com/bitcoin/address/{address}",
                "blockchain_com": f"https://www.blockchain.com/explorer/addresses/btc/{address}",
            },
            "investigation_note": "Run through Chainalysis Reactor or OXT.me for UTXO cluster analysis. Identify exchange deposits for KYC legal process.",
        }
    except Exception as e:
        return {"error": str(e)}

def query_wallet_label(address: str) -> dict:
    try:
        r = requests.get(
            f"https://www.walletexplorer.com/api/1/address?address={address}&caller=UMBRA-LEA",
            timeout=15, headers={"User-Agent": UA}
        )
        if r.status_code == 200:
            d = r.json()
            label = d.get("label", "")
            exchanges = ["binance","kraken","coinbase","localbitcoin","paxful","okx","huobi","bybit","gate","bitfinex","kucoin"]
            is_exchange = any(x in label.lower() for x in exchanges) if label else False
            return {
                "found": bool(label), "label": label, "wallet_id": d.get("wallet_id"),
                "is_exchange": is_exchange,
                "legal_note": f"Send legal process to {label} for KYC subscriber identity" if is_exchange else "",
            }
        return {"found": False}
    except Exception:
        return {"found": False}


# ══════════════════════════════════════════════
# ENGINE 9: IDENTITY CORRELATION
# ══════════════════════════════════════════════
def search_github(username: str) -> dict:
    clean = re.sub(r"[^a-zA-Z0-9._-]", "", username)
    if len(clean) < 3:
        return {"found": False}
    try:
        r = requests.get(f"https://api.github.com/users/{clean}", headers={"User-Agent": UA}, timeout=10)
        if r.status_code == 200:
            d = r.json()
            return {
                "found": True, "platform": "GitHub",
                "username": d.get("login"), "display_name": d.get("name"),
                "email": d.get("email"), "location": d.get("location"),
                "company": d.get("company"), "bio": d.get("bio"),
                "public_repos": d.get("public_repos", 0),
                "created_at": d.get("created_at"),
                "profile_url": f"https://github.com/{clean}",
                "confidence": "HIGH" if (d.get("email") or d.get("name")) else "MEDIUM",
                "pii_found": [x for x in [d.get("email"), d.get("name"), d.get("location")] if x],
            }
        elif r.status_code == 404:
            sr = requests.get(f"https://api.github.com/search/users?q={quote(clean)}&per_page=3", headers={"User-Agent": UA}, timeout=10)
            if sr.status_code == 200:
                items = sr.json().get("items", [])
                if items:
                    return {"found": True, "platform": "GitHub Search", "matches": [{"login": i["login"], "url": i["html_url"]} for i in items], "confidence": "MEDIUM"}
        return {"found": False}
    except Exception as e:
        return {"found": False, "error": str(e)}

def search_reddit(username: str) -> dict:
    clean = re.sub(r"[^a-zA-Z0-9_-]", "", username)
    if not clean:
        return {"found": False}
    try:
        r = requests.get(f"https://www.reddit.com/user/{clean}/about.json",
                         headers={"User-Agent": "UMBRA-LEA/3.1"}, timeout=10)
        if r.status_code == 200:
            d = r.json().get("data", {})
            import datetime as dt_mod
            created = d.get("created_utc")
            created_str = dt_mod.datetime.fromtimestamp(created).isoformat() if created else None
            return {
                "found": True, "platform": "Reddit",
                "username": d.get("name"), "karma": d.get("total_karma", 0),
                "comment_karma": d.get("comment_karma", 0),
                "created_at": created_str, "is_mod": d.get("is_mod", False),
                "profile_url": f"https://reddit.com/u/{clean}",
                "confidence": "HIGH",
            }
        return {"found": False}
    except Exception as e:
        return {"found": False, "error": str(e)}

def search_pgp(query: str) -> dict:
    try:
        r = requests.get(f"https://keys.openpgp.org/vks/v1/search?q={quote(query)}",
                         headers={"User-Agent": UA}, timeout=10)
        if r.status_code == 200:
            data = r.json()
            keys = []
            for cert in data.get("results", [])[:10]:
                for uid in cert.get("userids", []):
                    entry = {
                        "fingerprint": cert.get("fingerprint", ""),
                        "identity": uid.get("primary_uid", ""),
                        "created": cert.get("created", ""),
                        "algorithm": cert.get("algo", ""),
                    }
                    em = re.search(r"<([^>]+)>", uid.get("primary_uid", ""))
                    if em:
                        entry["email_in_key"] = em.group(1)
                    keys.append(entry)
            return {
                "found": len(keys) > 0, "platform": "OpenPGP Keyserver",
                "keys_found": len(keys), "keys": keys,
                "confidence": "CRITICAL" if any(k.get("email_in_key") for k in keys) else "MEDIUM",
            }
        return {"found": False}
    except Exception as e:
        return {"found": False, "error": str(e)}

def generate_dorks(value: str, vtype: str) -> list:
    q = value.replace('"', '\\"')
    qq = f'"{q}"'
    base = [{"query": qq, "url": f"https://www.google.com/search?q={quote(qq)}"}]
    extra = []
    if vtype in ("username", "telegram"):
        extra = [
            f'"{q}" site:reddit.com', f'"{q}" site:github.com', f'"{q}" site:pastebin.com',
            f'"{q}" email OR contact OR mail', f'"{q}" bitcoin OR crypto OR monero',
            f'"{q}" site:bitcointalk.org', f'"{q}" telegram OR signal OR wickr',
        ]
    elif vtype == "email":
        extra = [f'"{q}" site:pastebin.com', f'"{q}" breach OR leak OR password', f'"{q}" username OR alias']
    elif vtype == "btc":
        extra = [f'"{q}" site:bitcointalk.org', f'"{q}" vendor OR market OR forum', f'"{q}" site:pastebin.com']
    return base + [{"query": e, "url": f"https://www.google.com/search?q={quote(e)}"} for e in extra]

def correlate_identities(pii_findings: list) -> dict:
    results = {
        "github": [], "reddit": [], "pgp_keyserver": [],
        "wallet_labels": [], "google_dorks": [], "high_confidence_leads": [],
    }
    seen_users, seen_emails, seen_btc = set(), set(), set()

    for art in pii_findings:
        atype = art.get("type", "")
        val   = art.get("value", "").strip()

        if atype == "Telegram Handle":
            user = val.lstrip("@").split("/")[-1].strip()
            if user and len(user) >= 3 and user not in seen_users:
                seen_users.add(user)
                gh = search_github(user)
                if gh.get("found"):
                    gh["source_artifact"] = val
                    results["github"].append(gh)
                    if gh.get("pii_found"):
                        results["high_confidence_leads"].append({
                            "type": "Username→GitHub PII", "artifact": val,
                            "finding": f"GitHub: PII found: {gh['pii_found']}",
                            "url": gh.get("profile_url"), "confidence": "HIGH"})
                rd = search_reddit(user)
                if rd.get("found"):
                    rd["source_artifact"] = val
                    results["reddit"].append(rd)
                    results["high_confidence_leads"].append({
                        "type": "Username→Reddit Account", "artifact": val,
                        "finding": f"Reddit: {rd['karma']} karma, since {str(rd.get('created_at',''))[:10]}",
                        "url": rd.get("profile_url"), "confidence": "MEDIUM"})
                results["google_dorks"].append({"artifact": val, "type": "username", "queries": generate_dorks(user, "username")})
                time.sleep(0.5)

        elif atype == "Email Address" and val not in seen_emails:
            seen_emails.add(val)
            eu = val.split("@")[0]
            if len(eu) >= 3 and eu not in seen_users:
                seen_users.add(eu)
                gh = search_github(eu)
                if gh.get("found"):
                    gh["source_artifact"] = val; results["github"].append(gh)
                rd = search_reddit(eu)
                if rd.get("found"):
                    rd["source_artifact"] = val; results["reddit"].append(rd)
            pgp = search_pgp(val)
            if pgp.get("found"):
                pgp["source_artifact"] = val
                results["pgp_keyserver"].append(pgp)
                for k in pgp.get("keys", []):
                    if k.get("email_in_key"):
                        results["high_confidence_leads"].append({
                            "type": "Email→PGP Real Identity", "artifact": val,
                            "finding": f"PGP key contains email: {k['email_in_key']}", "confidence": "CRITICAL"})
            results["google_dorks"].append({"artifact": val, "type": "email", "queries": generate_dorks(val, "email")})
            time.sleep(0.4)

        elif atype == "PGP Key ID":
            pgp = search_pgp(val)
            if pgp.get("found"):
                pgp["source_artifact"] = val
                results["pgp_keyserver"].append(pgp)
                for k in pgp.get("keys", []):
                    if k.get("email_in_key"):
                        results["high_confidence_leads"].append({
                            "type": "PGP Key→Real Email", "artifact": val,
                            "finding": f"Key registered to: {k['email_in_key']}", "confidence": "CRITICAL"})
            time.sleep(0.3)

        elif "Bitcoin" in atype and val not in seen_btc:
            seen_btc.add(val)
            wl = query_wallet_label(val)
            results["wallet_labels"].append({"address": val, **wl})
            if wl.get("is_exchange"):
                results["high_confidence_leads"].append({
                    "type": "BTC→Exchange Wallet", "artifact": val,
                    "finding": f"Address is {wl.get('label')} — submit legal process for KYC identity",
                    "confidence": "CRITICAL"})
            results["google_dorks"].append({"artifact": val, "type": "btc", "queries": generate_dorks(val, "btc")})
            time.sleep(0.4)

    return results


# ══════════════════════════════════════════════
# ENGINE 10: INFRASTRUCTURE FINGERPRINTING
# ══════════════════════════════════════════════
def fingerprint_infra(html: str, headers: dict, base_url: str = "", favicon_url: str = "") -> dict:
    analytics = {}
    ga_ua  = list(set(re.findall(r"UA-\d{4,10}-\d{1,4}", html)))
    ga4    = list(set(re.findall(r"G-[A-Z0-9]{8,12}", html)))
    fb     = list(set(re.findall(r"fbq\s*\(\s*[\"']init[\"']\s*,\s*[\"']?(\d{10,20})", html)))
    stripe = list(set(re.findall(r"pk_(?:live|test)_[a-zA-Z0-9]{20,60}", html)))
    s3     = list(set(re.findall(r"([a-z0-9.\-]+)\.s3(?:[\.-][a-z0-9-]+)?\.amazonaws\.com", html)))

    if ga_ua: analytics["google_analytics_ua"] = [{"id": x, "shodan": f'http.html:"{x}"', "dork": f'"{x}"', "note": "Search internet for same GA ID — links to operator clearnet site"} for x in ga_ua]
    if ga4:   analytics["google_analytics_4"]  = [{"id": x, "dork": f'"{x}"', "note": "GA4 property — search for sites using same property"} for x in ga4]
    if fb:    analytics["facebook_pixel"]       = [{"id": x, "fb_ads": f"https://www.facebook.com/ads/library/?q={x}", "note": "Facebook Pixel ID — may expose ad account"} for x in fb]
    if stripe:analytics["stripe_keys"]          = [{"key": k[:24]+"...", "type": "live" if "pk_live" in k else "test", "note": "Legal process to Stripe for merchant identity"} for k in stripe]
    if s3:    analytics["aws_s3_buckets"]        = [{"bucket": b, "url": f"https://{b}.s3.amazonaws.com/", "note": "Check for public file listing"} for b in s3]

    favicon_result = {"found": False}
    if favicon_url:
        try:
            import mmh3, base64
            domain_match = re.match(r"(https?://[^/]+)", base_url)
            if favicon_url.startswith("http"):        full_fav = favicon_url
            elif favicon_url.startswith("/") and domain_match: full_fav = domain_match.group(1) + favicon_url
            else:                                      full_fav = base_url.rstrip("/") + "/" + favicon_url.lstrip("/")
            r = requests.get(full_fav, timeout=10, headers={"User-Agent": UA})
            if r.status_code == 200:
                b64 = base64.encodebytes(r.content).decode()
                fhash = mmh3.hash(b64)
                favicon_result = {
                    "found": True, "hash": fhash,
                    "md5": hashlib.md5(r.content).hexdigest(),
                    "size_bytes": len(r.content),
                    "shodan_query": f"http.favicon.hash:{fhash}",
                    "shodan_url": f"https://www.shodan.io/search?query=http.favicon.hash%3A{fhash}",
                    "note": "Run Shodan query to find all clearnet/darknet servers using this exact favicon",
                }
        except ImportError:
            favicon_result = {"found": False, "note": "Install mmh3: pip install mmh3"}
        except Exception as e:
            favicon_result = {"found": False, "error": str(e)}

    scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I)
    ext_scripts = [s for s in scripts if s.startswith("http") and ".onion" not in s]
    libs = []
    for lib, pat in [("jQuery", r"jquery[/-]([\d.]+)"), ("Bootstrap", r"bootstrap[/-]([\d.]+)"), ("React", r"react[/-]([\d.]+)"), ("Vue.js", r"vue[/-]([\d.]+)")]:
        m = re.search(pat, html, re.I)
        if m:
            libs.append({"library": lib, "version": m.group(1)})
    script_fp = hashlib.sha256("|".join(sorted(scripts)).encode()).hexdigest()[:16]

    h_str = json.dumps(headers).lower() + html.lower()
    cdn = []
    for name, pat in [("Cloudflare", r"cloudflare|cf-ray"), ("AWS CloudFront", r"cloudfront\.net|x-amz-cf-id"), ("Fastly", r"fastly"), ("Akamai", r"akamaiedge")]:
        if re.search(pat, h_str):
            cdn.append({"cdn": name, "note": f"{name} detected — request abuse records"})

    cross = []
    for cat, items in analytics.items():
        for item in items:
            cross.append({"type": "Analytics ID", "value": item.get("id"), "action": "Search internet for other sites using same ID", "shodan": item.get("shodan", "")})
    if favicon_result.get("found"):
        cross.append({"type": "Favicon Hash", "value": str(favicon_result.get("hash")), "shodan": favicon_result["shodan_query"], "shodan_url": favicon_result.get("shodan_url"), "action": "Search Shodan for servers sharing this favicon"})

    return {
        "analytics_ids": analytics, "favicon": favicon_result,
        "js_libraries": {"detected": libs, "external_scripts": ext_scripts, "fingerprint": script_fp, "note": "Same fingerprint across onion sites = same operator"},
        "cdn_detection": cdn, "cross_site_indicators": cross,
    }


# ══════════════════════════════════════════════
# ENGINE 11: ATTRIBUTION GRAPH (D3-compatible)
# ══════════════════════════════════════════════
def build_graph(target_url, pii, correlation, infra, headers_findings, ip_results, active_disc=None):
    nodes, edges = {}, []
    counter = [0]

    def nid():
        counter[0] += 1
        return f"n{counter[0]}"

    def node(label, ntype, data=None, risk="MEDIUM"):
        key = f"{ntype}:{label}"
        if key not in nodes:
            nodes[key] = {"id": nid(), "label": str(label)[:55], "type": ntype, "risk": risk, "data": data or {}}
        return nodes[key]["id"]

    def edge(s, t, rel, conf="MEDIUM"):
        if s and t and s != t:
            edges.append({"source": s, "target": t, "relation": rel, "confidence": conf})

    root = node(target_url, "onion_site", {"url": target_url}, "CRITICAL")

    for p in pii:
        t, v, r = p["type"], p["value"], p["risk"]
        if "Email" in t:            edge(root, node(v, "email", {}, r), "contains", "HIGH")
        elif "Telegram" in t:       edge(root, node(v.lstrip("@"), "telegram", {"raw": v}, r), "contacts_via", "HIGH")
        elif "Bitcoin" in t:        edge(root, node(v[:22]+"...", "btc_address", {"full": v}, r), "payment_via", "HIGH")
        elif "Ethereum" in t:       edge(root, node(v[:16]+"...", "eth_address", {"full": v}, r), "payment_via", "HIGH")
        elif "Monero" in t:         edge(root, node(v[:16]+"...", "xmr_address", {"full": v}, r), "payment_via", "HIGH")
        elif "IPv4" in t or "IPv6" in t: edge(root, node(v, "ip_address", {"source": "Page source"}, "CRITICAL"), "hosted_at", "CRITICAL")
        elif "Analytics" in t:      edge(root, node(v, "analytics_id", {}, "CRITICAL"), "tracked_by", "CRITICAL")
        elif "Clearnet" in t:
            d = re.sub(r"https?://", "", v).split("/")[0]
            if d and len(d) > 3:
                edge(root, node(d, "domain", {"url": v}, r), "links_to", "HIGH")
        elif "PGP" in t and "Block" not in t:
            edge(root, node(v, "pgp_key", {}, r), "signed_with", "MEDIUM")

    for h in headers_findings:
        field = h.get("field", "")
        val   = h.get("value", "")
        if field in ("X-Forwarded-For", "Forwarded (RFC 7239)", "X-Real-IP", "CF-Connecting-IP", "True-Client-IP"):
            for ip in _extract_ips_from_header_value(val):
                if is_public_ip(ip):
                    n = node(ip, "ip_address", {"source": f"{field} LEAK"}, "CRITICAL")
                    edge(root, n, "real_ip_leak", "CRITICAL")
        elif field == "Server":
            edge(root, node(val, "server_software", {}, "HIGH"), "runs_on", "HIGH")

    for geo in ip_results:
        if geo.get("success"):
            ip_key = f"ip_address:{geo['ip']}"
            ip_n_id = nodes.get(ip_key, {}).get("id") or node(geo["ip"], "ip_address", {"source": geo.get("source", "")}, "CRITICAL")
            if geo.get("city") or geo.get("country"):
                loc = f"{geo.get('city', '?')}, {geo.get('region', '')}, {geo.get('country', '')}"
                loc_id = node(loc, "location", {
                    "lat": geo.get("lat"), "lon": geo.get("lon"),
                    "isp": geo.get("isp"), "maps": geo.get("google_maps_url")
                }, "HIGH")
                edge(ip_n_id, loc_id, "located_in", "HIGH")
            if geo.get("isp"):
                isp_id = node(geo["isp"], "isp", {
                    "asn": geo.get("asn"), "is_vpn": geo.get("is_proxy"),
                    "is_hosting": geo.get("is_hosting")
                }, "HIGH")
                edge(ip_n_id, isp_id, "belongs_to", "HIGH")

    for gh in correlation.get("github", []):
        if gh.get("found"):
            u = gh.get("username") or (gh.get("matches", [{}])[0].get("login") if gh.get("matches") else "")
            if u:
                gn = node(u, "github_profile", {
                    "url": gh.get("profile_url", ""), "display_name": gh.get("display_name", ""),
                    "location": gh.get("location", ""), "email": gh.get("email", "")
                }, "HIGH")
                src = gh.get("source_artifact", "")
                matched = False
                for k, nd in nodes.items():
                    if nd["label"] in src or src.lstrip("@") in nd["label"]:
                        edge(nd["id"], gn, "same_identity", "HIGH"); matched = True; break
                if not matched:
                    edge(root, gn, "same_identity", "HIGH")
                if gh.get("email"):
                    edge(gn, node(gh["email"], "email", {"source": "GitHub profile"}, "CRITICAL"), "registered_with", "CRITICAL")
                if gh.get("location"):
                    edge(gn, node(gh["location"], "location", {}, "HIGH"), "located_in", "HIGH")

    for rd in correlation.get("reddit", []):
        if rd.get("found"):
            rn = node(rd.get("username", ""), "reddit_profile", {
                "url": rd.get("profile_url", ""), "karma": rd.get("karma", 0),
                "created": rd.get("created_at", "")
            }, "MEDIUM")
            edge(root, rn, "same_identity", "MEDIUM")

    for pr in correlation.get("pgp_keyserver", []):
        if pr.get("found"):
            for k in pr.get("keys", []):
                fn = node(k.get("fingerprint", "")[:16], "pgp_key", {"identity": k.get("identity", "")}, "HIGH")
                edge(root, fn, "signed_with", "HIGH")
                if k.get("email_in_key"):
                    edge(fn, node(k["email_in_key"], "email", {"source": "PGP key"}, "CRITICAL"), "registered_with", "CRITICAL")

    for wl in correlation.get("wallet_labels", []):
        if wl.get("found") and wl.get("label"):
            ln = node(wl["label"], "exchange", {"legal_note": wl.get("legal_note", "")}, "CRITICAL")
            for k, nd in nodes.items():
                if nd["type"] == "btc_address" and wl.get("address", "") in nd.get("data", {}).get("full", ""):
                    edge(nd["id"], ln, "deposited_to", "CRITICAL"); break

    for cat, items in infra.get("analytics_ids", {}).items():
        for item in items:
            an = node(item.get("id", ""), "analytics_id", {"type": cat, "note": item.get("note", "")}, "CRITICAL")
            edge(root, an, "tracked_by", "CRITICAL")

    nlist = list(nodes.values())
    high_val = [e for e in edges if e.get("relation") in ("real_ip_leak","registered_with","same_identity","deposited_to","located_in")]

    return {
        "nodes": nlist, "edges": edges,
        "stats": {
            "total_nodes": len(nlist), "total_edges": len(edges),
            "critical_nodes": sum(1 for n in nlist if n["risk"] == "CRITICAL"),
            "node_types": list(set(n["type"] for n in nlist)),
        },
        "high_value_paths": high_val,
    }


# ══════════════════════════════════════════════════════════════════════════════
# ENGINE 12: RULE-BASED OSINT INTELLIGENCE BRIEF  (replaces Claude API)
# ══════════════════════════════════════════════════════════════════════════════

def _score_opsec(pii, headers, ip_results, infra, page_intel) -> tuple[int, list]:
    """Return (opsec_score 1-10, deductions[]) — higher = better OPSEC."""
    score = 10
    deductions = []

    # Real-IP leaks via headers — catastrophic
    critical_headers = [h for h in headers if h.get("risk") == "CRITICAL" and "leak" in h.get("note", "").lower()]
    if critical_headers:
        score -= 4
        deductions.append(f"CRITICAL: Real IP leaked via {', '.join(h['field'] for h in critical_headers)}")

    # Analytics IDs — links site to clearnet identity
    for cat in infra.get("analytics_ids", {}).values():
        if cat:
            score -= 2
            deductions.append("HIGH: Analytics tracker ID found — cross-site identity linkage possible")
            break

    # Clearnet URLs in page source
    clearnet = page_intel.get("clearnet_links", [])
    if clearnet:
        score -= 1
        deductions.append(f"HIGH: {len(clearnet)} clearnet link(s) found in page source")

    # Server/stack disclosure
    if any(h.get("field") == "Server" for h in headers):
        score -= 1
        deductions.append("MEDIUM: Server software version disclosed in headers")

    # No security headers
    if any("Missing Security Headers" in h.get("field", "") for h in headers):
        score -= 1
        deductions.append("LOW: No HSTS/CSP/XFO headers — default/unconfigured server")

    # Residential IPs exposed
    residential = [g for g in ip_results if g.get("success") and not g.get("is_proxy") and not g.get("is_hosting")]
    if residential:
        score -= 3
        deductions.append(f"CRITICAL: {len(residential)} residential IP(s) exposed — direct subscriber identity lookup possible")

    return max(1, min(10, score)), deductions


def osint_brief_engine(url, page_intel, pii, headers, stylo, correlation, ip_results, infra=None, active_disc=None) -> str:
    """
    Rule-based OSINT intelligence brief for NIA analysts.
    No LLM API required — pure deterministic analysis of collected data.
    """
    infra = infra or {}
    ts    = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    lines = []
    W     = "═" * 68

    def section(title):
        lines.append(f"\n{W}")
        lines.append(f"  {title}")
        lines.append(W)

    lines.append(f"{'='*68}")
    lines.append(f"  UMBRA V3 — OSINT INTELLIGENCE BRIEF")
    lines.append(f"  TARGET : {url}")
    lines.append(f"  GENERATED : {ts} UTC")
    lines.append(f"  CLASSIFICATION : LEA / NIA USE ONLY")
    lines.append(f"{'='*68}")

    # ── 1. SITE OVERVIEW ────────────────────────────────────────────────────
    section("1. SITE OVERVIEW")
    title = page_intel.get("title", "N/A")
    cats  = page_intel.get("category_signals", [])
    plats = page_intel.get("platform_signals", [])
    lines.append(f"  Site Title   : {title or '(none)'}")
    lines.append(f"  Categories   : {', '.join(cats) or 'Undetermined'}")
    lines.append(f"  Platform     : {', '.join(plats) or 'Unknown'}")
    lines.append(f"  Total PII    : {len(pii)} artifacts extracted")
    lines.append(f"  Clearnet URLs: {len(page_intel.get('clearnet_links', []))} found in page source")
    lines.append(f"  Onion Links  : {len(page_intel.get('onion_links', []))} (possible mirrors/affiliates)")

    # ── 2. OPERATOR IP PROFILE ───────────────────────────────────────────────
    section("2. OPERATOR IP & GEOLOCATION PROFILE")
    public_ips = [g for g in ip_results if g.get("success")]
    header_ips = [g for g in public_ips if "Header" in g.get("source", "") or "LEAK" in g.get("source", "") or "RFC" in g.get("source", "") or "Forwarded" in g.get("source", "") or "Real-IP" in g.get("source", "") or "Connecting" in g.get("source", "")]
    page_ips   = [g for g in public_ips if "Page source" in g.get("source", "")]

    if not public_ips:
        lines.append("  NO PUBLIC IPs EXTRACTED")
        lines.append("  → Hidden service is correctly configured (no IP leakage detected)")
        lines.append("  → Pursue via: PGP keys, analytics IDs, clearnet links, blockchain analysis")
    else:
        if header_ips:
            lines.append(f"  ⚠ IP HEADER LEAKAGE DETECTED — {len(header_ips)} IP(s) from proxy headers")
            for g in header_ips:
                v6tag = " [IPv6]" if g.get("ip_version") == 6 else ""
                lines.append(f"")
                lines.append(f"  IP           : {g['ip']}{v6tag}")
                lines.append(f"  Source       : {g['source']}")
                lines.append(f"  Location     : {g.get('city','?')}, {g.get('region','')}, {g.get('country','?')} ({g.get('country_code','')})")
                lines.append(f"  Coordinates  : {g.get('lat','?')}, {g.get('lon','?')}")
                lines.append(f"  Timezone     : {g.get('timezone','?')}")
                lines.append(f"  ISP          : {g.get('isp','?')}")
                lines.append(f"  ASN          : {g.get('asn','?')}")
                lines.append(f"  VPN/Proxy    : {'YES' if g.get('is_proxy') else 'NO'}")
                lines.append(f"  Hosting/DC   : {'YES' if g.get('is_hosting') else 'NO'}")
                lines.append(f"  Maps         : {g.get('google_maps_url','')}")
                for note in g.get("investigation_notes", []):
                    lines.append(f"  NOTE         : {note}")
                lines.append(f"  LEGAL ACTION : {g.get('legal_action','')}")

        if page_ips:
            lines.append(f"\n  {len(page_ips)} IP(s) found in PAGE SOURCE:")
            for g in page_ips:
                v6tag = " [IPv6]" if g.get("ip_version") == 6 else ""
                lines.append(f"    • {g['ip']}{v6tag} → {g.get('city','?')}, {g.get('country','?')} | ISP: {g.get('isp','?')} | VPN: {g.get('is_proxy','?')}")

    # ── 2b. ACTIVE IP DISCOVERY ────────────────────────────────────────────────
    if active_disc:
        section("2b. ACTIVE IP DISCOVERY — Correlation Attack Results")
        disc_ips = active_disc.get("discovered_ips", [])
        domains  = active_disc.get("all_candidate_domains", [])
        shodan_q = active_disc.get("shodan_queries", [])

        for s in active_disc.get("method_summary", []):
            lines.append(f"  {s}")

        if domains:
            lines.append(f"\n  Clearnet domains extracted from page ({len(domains)}):")
            for d in domains[:15]:
                lines.append(f"    • {d}")

        if disc_ips:
            lines.append(f"\n  IPs resolved via DNS correlation ({len(disc_ips)}):")
            for g in disc_ips:
                if g.get("success"):
                    v6tag = " [IPv6]" if g.get("ip_version") == 6 else ""
                    lines.append(f"")
                    lines.append(f"  IP           : {g['ip']}{v6tag}")
                    lines.append(f"  Method       : {g.get('discovery_method','DNS_RESOLUTION')}")
                    lines.append(f"  Source Domain: {g.get('source_domain','')}")
                    lines.append(f"  Location     : {g.get('city','?')}, {g.get('region','')}, {g.get('country','?')}")
                    lines.append(f"  ISP          : {g.get('isp','?')}")
                    lines.append(f"  VPN/Proxy    : {'YES' if g.get('is_proxy') else 'NO'}")
                    lines.append(f"  Hosting/DC   : {'YES' if g.get('is_hosting') else 'NO'}")
                    if g.get("google_maps_url"):
                        lines.append(f"  Maps         : {g.get('google_maps_url','')}")
                    lines.append(f"  LEGAL ACTION : {g.get('legal_action','')}")
        else:
            lines.append("\n  No IPs discovered via DNS — use Shodan queries below:")

        if shodan_q:
            lines.append(f"\n  Shodan correlation queries (paste into shodan.io):")
            for q in shodan_q:
                lines.append(f"    [{q['confidence']}] {q['query']}")
                lines.append(f"             → {q['method']}")
                lines.append(f"             → {q['url']}")

        censys_q = active_disc.get("censys_queries", [])
        if censys_q:
            lines.append(f"\n  Censys queries:")
            for q in censys_q:
                lines.append(f"    {q['query']}")
                lines.append(f"    → {q['url']}")

        vt_urls = active_disc.get("virustotal_urls", [])
        if vt_urls:
            lines.append(f"\n  Historical DNS (check before CDN was added):")
            for v in vt_urls[:4]:
                lines.append(f"    {v['domain']}")
                lines.append(f"    → VirusTotal: {v['virustotal']}")
                lines.append(f"    → SecurityTrails: {v['securitytrails']}")
    section("3. TOP DE-ANONYMIZATION LEADS (Priority Order)")
    leads = correlation.get("high_confidence_leads", [])
    priority_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    leads_sorted = sorted(leads, key=lambda x: priority_order.get(x.get("confidence", "LOW"), 3))

    # Build lead list from all data sources
    all_leads = []

    # IPs from headers → ISP legal process
    for g in header_ips:
        if not g.get("is_proxy") and not g.get("is_hosting"):
            all_leads.append({
                "priority": "CRITICAL",
                "action": f"Legal process to '{g.get('isp')}' for subscriber identity for IP {g['ip']}",
                "detail": f"Residential IP in {g.get('city')}, {g.get('country')} — direct deanonymization path",
            })
        elif g.get("is_hosting"):
            all_leads.append({
                "priority": "HIGH",
                "action": f"Abuse/legal request to hosting provider '{g.get('isp')}' for account owning IP {g['ip']}",
                "detail": f"Datacenter/VPS IP in {g.get('city')}, {g.get('country')} — server owner identity obtainable via abuse team",
            })

    # Analytics IDs → clearnet site linkage
    for cat, items in infra.get("analytics_ids", {}).items():
        for item in items:
            all_leads.append({
                "priority": "CRITICAL",
                "action": f"Search all internet for other sites using {cat} ID: {item.get('id')}",
                "detail": f"Same analytics ID on a clearnet site links operator's dark market to their real identity. Dork: {item.get('dork','')}",
            })

    # PGP with emails
    for pgp in correlation.get("pgp_keyserver", []):
        for k in pgp.get("keys", []):
            if k.get("email_in_key"):
                all_leads.append({
                    "priority": "CRITICAL",
                    "action": f"PGP key fingerprint {k.get('fingerprint','')[:16]} registered to email: {k['email_in_key']}",
                    "detail": f"Query email provider for subscriber records. Identity: {k.get('identity','')}",
                })

    # GitHub/Reddit matches
    for gh in correlation.get("github", []):
        if gh.get("found") and (gh.get("email") or gh.get("location")):
            all_leads.append({
                "priority": "HIGH",
                "action": f"GitHub profile found: {gh.get('profile_url','')}",
                "detail": f"Name: {gh.get('display_name','')} | Email: {gh.get('email','')} | Location: {gh.get('location','')}",
            })

    # Pre-scored leads from correlation engine
    all_leads += [{"priority": l.get("confidence","MEDIUM"), "action": l.get("type",""), "detail": l.get("finding","")} for l in leads_sorted]

    # Clearnet links → CT log lookup
    clearnet = page_intel.get("clearnet_links", [])
    if clearnet:
        sample = clearnet[0].get("href", "")
        domain = re.sub(r"https?://", "", sample).split("/")[0]
        if domain:
            all_leads.append({
                "priority": "HIGH",
                "action": f"Query crt.sh for domain: {domain}",
                "detail": f"Certificate transparency logs may reveal hosting IP and additional domains. Try: https://crt.sh/?q={domain}",
            })

    # Blockchain
    btc_pii = [p for p in pii if "Bitcoin" in p.get("type", "")]
    if btc_pii:
        all_leads.append({
            "priority": "HIGH",
            "action": f"Blockchain cluster analysis on {len(btc_pii)} BTC address(es)",
            "detail": "Use OXT.me or Chainalysis for UTXO clustering. Identify exchange deposits for KYC legal process.",
        })

    all_leads_sorted = sorted(all_leads, key=lambda x: priority_order.get(x.get("priority","LOW"),3))
    for i, lead in enumerate(all_leads_sorted[:8], 1):
        lines.append(f"\n  [{i}] [{lead['priority']}] {lead['action']}")
        lines.append(f"      → {lead['detail']}")

    if not all_leads_sorted:
        lines.append("  No high-confidence leads generated. Pursue manual OSINT investigation.")

    # ── 4. OPERATOR PROFILE ─────────────────────────────────────────────────
    section("4. OPERATOR PROFILE ASSESSMENT")

    # Language
    lang = "Unknown"
    if stylo:
        lang = stylo.get("language", {}).get("likely_native_language", "Unknown")
        ttr  = stylo.get("ttr", 0)
        wc   = stylo.get("word_count", 0)
        asl  = stylo.get("avg_sentence_length", 0)
        vr   = stylo.get("vocabulary_richness", "Unknown")
        lines.append(f"  Language Background : {lang}")
        lines.append(f"  Vocabulary Richness : {vr}")
        lines.append(f"  Word Count Analyzed : {wc} | Avg Sentence Len: {asl}")
        lines.append(f"  Type-Token Ratio    : {ttr:.4f} (higher = more diverse vocabulary)")
    else:
        lines.append("  Language Background : Insufficient text for stylometric analysis")

    # Geographic location from IPs
    locs = [f"{g.get('city','?')}, {g.get('country','?')}" for g in public_ips if g.get("success") and g.get("city")]
    if locs:
        lines.append(f"  Probable Location   : {'; '.join(set(locs))}")
    else:
        lines.append("  Probable Location   : Undetermined (no IP geolocation data)")

    # Technical skill from platform + header analysis
    skill_score = 5
    if any("WordPress" in p for p in page_intel.get("platform_signals", [])):
        skill_score -= 1
    if header_ips:
        skill_score -= 2
    if infra.get("analytics_ids"):
        skill_score -= 1
    if page_intel.get("external_scripts"):
        skill_score -= 1
    if not page_intel.get("clearnet_links"):
        skill_score += 1
    skill_label = ("Expert (7-10)" if skill_score >= 7 else
                   "Intermediate (4-6)" if skill_score >= 4 else
                   "Novice (1-3)")
    lines.append(f"  Technical Skill     : {max(1,min(10,skill_score))}/10 — {skill_label}")

    # Timezone clue from server Date header
    date_hdr = next((h for h in headers if h.get("field") == "Date"), None)
    if date_hdr:
        lines.append(f"  Server Timestamp    : {date_hdr['value']} — compare across requests to determine active hours")

    # Content-Language hint
    cl_hdr = next((h for h in headers if h.get("field") == "Content-Language"), None)
    if cl_hdr:
        lines.append(f"  Content-Language    : {cl_hdr['value']} — corroborates operator geographic region")

    # ── 5. OPSEC ASSESSMENT ─────────────────────────────────────────────────
    section("5. OPSEC SOPHISTICATION RATING")
    opsec_score, deductions = _score_opsec(pii, headers, ip_results, infra, page_intel)
    stars = "★" * opsec_score + "☆" * (10 - opsec_score)
    lines.append(f"  Rating: {opsec_score}/10  {stars}")
    lines.append(f"  Assessment: {'Well-hardened — no obvious leaks' if opsec_score >= 8 else 'Moderate — some leakage' if opsec_score >= 5 else 'POOR — multiple critical OPSEC failures'}")
    for d in deductions:
        lines.append(f"    ✗ {d}")
    if not deductions:
        lines.append("    ✓ No major OPSEC failures detected in this scan")

    # ── 6. PII SUMMARY ──────────────────────────────────────────────────────
    section("6. PII ARTIFACT SUMMARY")
    type_counts = Counter(p["type"] for p in pii)
    for ptype, cnt in sorted(type_counts.items(), key=lambda x: -x[1]):
        risk = next((p["risk"] for p in pii if p["type"] == ptype), "?")
        lines.append(f"  [{risk:8s}] {ptype:35s} × {cnt}")

    # ── 7. HTTP HEADER INTELLIGENCE ─────────────────────────────────────────
    section("7. HTTP HEADER INTELLIGENCE")
    crit_headers = [h for h in headers if h.get("risk") in ("CRITICAL", "HIGH")]
    for h in crit_headers:
        lines.append(f"  [{h['risk']:8s}] {h['field']}: {str(h['value'])[:80]}")
        lines.append(f"            {h.get('note','')}")

    # ── 8. LEGAL ACTION MATRIX ──────────────────────────────────────────────
    section("8. LEGAL ACTION MATRIX (India LEA Framework)")
    lines.append("  MLAT requests may be required for foreign service providers.")
    lines.append("")

    for g in public_ips:
        if g.get("success"):
            if not g.get("is_proxy") and not g.get("is_hosting"):
                lines.append(f"  • IP {g['ip']} → Direct ISP legal process to: {g.get('isp')} ({g.get('country')})")
                lines.append(f"    Request: Subscriber name, address, account creation date for IP at timestamp")
            elif g.get("is_hosting"):
                lines.append(f"  • IP {g['ip']} → Abuse/MLAT to hosting provider: {g.get('isp')} ({g.get('country')})")
                lines.append(f"    Request: VPS account details, payment records, KYC if available")

    for pgp in correlation.get("pgp_keyserver", []):
        for k in pgp.get("keys", []):
            if k.get("email_in_key"):
                em = k["email_in_key"]
                domain = em.split("@")[-1] if "@" in em else ""
                lines.append(f"  • Email {em} → Legal process to email provider: {domain}")
                lines.append(f"    Request: Registration IP, name, recovery email, device fingerprints")

    for gh in correlation.get("github", []):
        if gh.get("found") and gh.get("profile_url"):
            lines.append(f"  • GitHub {gh.get('profile_url')} → Legal process to GitHub/Microsoft")
            lines.append(f"    Request: Registration email, IP logs, payment info (if Pro account)")

    # ── 9. IMMEDIATE ACTION ITEMS ────────────────────────────────────────────
    section("9. IMMEDIATE ACTION ITEMS")
    actions = []
    if header_ips:
        actions.append(f"1. IMMEDIATE — Geolocate + ISP legal process for header-leaked IPs: {', '.join(g['ip'] for g in header_ips)}")
    for cat, items in infra.get("analytics_ids", {}).items():
        for item in items:
            actions.append(f"2. Run Shodan/Google dork for analytics ID: {item.get('id')} to find linked clearnet sites")
    if infra.get("favicon", {}).get("found"):
        actions.append(f"3. Run Shodan: {infra['favicon']['shodan_query']} — find all servers sharing this favicon")
    ct_domains = [re.sub(r"https?://","",l["href"]).split("/")[0] for l in clearnet if l.get("href","").startswith("http")]
    if ct_domains:
        actions.append(f"4. Query crt.sh for: {ct_domains[0]} and run Shodan ssl.cert.subject.cn query")
    if btc_pii:
        actions.append(f"5. Submit {len(btc_pii)} BTC address(es) to Chainalysis/OXT.me for cluster analysis")
    pgp_emails = [k.get("email_in_key") for pgp in correlation.get("pgp_keyserver",[]) for k in pgp.get("keys",[]) if k.get("email_in_key")]
    if pgp_emails:
        actions.append(f"6. Send legal process to email provider for: {pgp_emails[0]}")
    for i, a in enumerate(actions, 1):
        lines.append(f"  {a}")
    if not actions:
        lines.append("  • No immediate critical actions identified — proceed with manual OSINT")

    lines.append(f"\n{'='*68}")
    lines.append(f"  END OF BRIEF — UMBRA V3 | {ts}")
    lines.append(f"{'='*68}")

    return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════════
# ENGINE 13: OPSEC FAILURE DETECTOR
# ══════════════════════════════════════════════════════════════════════════════
def detect_opsec_failures(pii: list, headers: list, page_intel: dict,
                           stylometry: dict, ip_results: list,
                           active_disc: dict, infra: dict) -> dict:
    """
    Systematically detect every operational security failure.
    Each failure is categorized, scored, and linked to actionable intelligence.
    Returns a structured list of failures with severity + exploitation path.
    """
    failures = []
    score_deduction = 0  # starts at 100

    def fail(category, title, detail, evidence, severity, action, score_hit):
        nonlocal score_deduction
        score_deduction += score_hit
        failures.append({
            "category":  category,
            "title":     title,
            "detail":    detail,
            "evidence":  evidence,
            "severity":  severity,
            "action":    action,
            "score_hit": score_hit,
        })

    # ── Category: Network / Infrastructure ─────────────────────────────────
    for h in headers:
        if h.get("field") in ("X-Forwarded-For", "X-Real-IP", "CF-Connecting-IP",
                               "True-Client-IP", "Forwarded (RFC 7239)"):
            fail("NETWORK", f"Real IP leaked via {h['field']}",
                 "Hidden service running behind misconfigured reverse proxy. "
                 "The proxy is forwarding the operator's real IP in HTTP headers.",
                 h.get("value", "")[:100], "CRITICAL",
                 f"Immediately geolocate and submit legal process for: {h.get('value','')[:60]}",
                 25)

    residential = [g for g in ip_results if g.get("success") and
                   not g.get("is_proxy") and not g.get("is_hosting")]
    for g in residential:
        fail("NETWORK", f"Residential IP exposed: {g['ip']}",
             f"Non-VPN, non-datacenter IP geolocated to {g.get('city')}, {g.get('country')}. "
             "Direct ISP legal process will yield subscriber identity.",
             f"IP: {g['ip']} | ISP: {g.get('isp')} | {g.get('city')}, {g.get('country')}",
             "CRITICAL",
             f"Legal process to {g.get('isp')} for subscriber records for {g['ip']}",
             20)

    # ── Category: Identity Reuse ────────────────────────────────────────────
    email_pii = [p for p in pii if p.get("type") == "Email Address"]
    for ep in email_pii:
        fail("IDENTITY", f"Real email address exposed: {ep['value']}",
             "Operator used a traceable email address. This enables keyserver lookup, "
             "provider legal process, and cross-platform identity correlation.",
             ep["value"], "CRITICAL",
             f"Legal process to {ep['value'].split('@')[-1]}; search keyservers for {ep['value']}",
             20)

    tg_pii = [p for p in pii if p.get("type") == "Telegram Handle"]
    for tp in tg_pii:
        fail("IDENTITY", f"Telegram handle exposed: {tp['value']}",
             "Telegram accounts are linked to phone numbers. Legal process to Telegram "
             "yields subscriber phone, which links to a real SIM registration.",
             tp["value"], "CRITICAL",
             f"Legal process to Telegram for phone number linked to: {tp['value']}",
             15)

    # ── Category: Analytics / Tracking ────────────────────────────────────
    for cat, items in infra.get("analytics_ids", {}).items():
        for item in items:
            fail("TRACKING", f"Analytics tracker reuse: {item.get('id')}",
                 f"Operator left a {cat} tracking ID in the onion site. "
                 "The same ID almost certainly exists on their clearnet site, "
                 "linking both sites to the same identity.",
                 f"{cat}: {item.get('id')}",
                 "CRITICAL",
                 f"Search all internet for other sites using {cat} ID: {item.get('id')}. "
                 "Dork: \"{item.get('id')}\" site:google.com",
                 18)

    # ── Category: Clearnet Exposure ────────────────────────────────────────
    clearnet = page_intel.get("clearnet_links", [])
    if clearnet:
        domains = list(set(re.sub(r"https?://","",l.get("href","")).split("/")[0]
                           for l in clearnet if l.get("href","").startswith("http")))
        fail("EXPOSURE", f"{len(domains)} clearnet domain(s) linked from page",
             "Operator explicitly linked to clearnet infrastructure from the onion site. "
             "These domains can be resolved to IPs and subpoenaed.",
             ", ".join(domains[:5]),
             "HIGH",
             f"Resolve and subpoena: {', '.join(domains[:3])}; query CT logs for certificate history",
             10)

    ext_scripts = infra.get("js_libraries", {}).get("external_scripts", [])
    if ext_scripts:
        fail("EXPOSURE", f"External clearnet scripts loaded ({len(ext_scripts)})",
             "Page loads JavaScript from clearnet servers. These servers see the real IP of "
             "every visitor and the onion service identity leaks in the Referer header.",
             ", ".join(ext_scripts[:3]),
             "HIGH",
             f"Subpoena access logs from script host: {ext_scripts[0]}",
             12)

    # ── Category: PGP Key Misuse ───────────────────────────────────────────
    pgp_blocks = [p for p in pii if p.get("type") == "PGP Key Block"]
    if pgp_blocks:
        fail("IDENTITY", "PGP public key block present in page",
             "Operator published a PGP key. Keys often contain real name and email. "
             "Cross-reference with public keyservers for associated identity data.",
             f"{len(pgp_blocks)} PGP key block(s) found",
             "HIGH",
             "Extract fingerprint from key block; search keys.openpgp.org and keybase.io",
             8)

    # ── Category: Server Fingerprint ──────────────────────────────────────
    server_h = next((h for h in headers if h.get("field") == "Server"), None)
    if server_h and "/" in server_h.get("value",""):
        val = server_h.get("value","")
        fail("FINGERPRINT", f"Exact server version disclosed: {val}",
             "Operator left default server headers. Exact version string enables CVE lookup "
             "and Shodan cross-matching to find the same server on the clearnet.",
             val, "MEDIUM",
             f"Shodan: http.server:\"{val}\" — find clearnet servers with identical config",
             5)

    # ── Category: Language / Timezone Opsec ───────────────────────────────
    if stylometry:
        lang = stylometry.get("language", {}).get("likely_native_language", "")
        if lang and lang not in ("Inconclusive", "American English", "British English"):
            fail("BEHAVIORAL", f"Non-English native language detected: {lang}",
                 "Writing patterns indicate a non-English native speaker. "
                 "This narrows the suspect population and corroborates geographic indicators.",
                 f"Language signal: {lang}", "MEDIUM",
                 "Cross-reference with geographic data from IPs/PGP/email to confirm region",
                 3)

    date_h = next((h for h in headers if h.get("field") == "Date"), None)
    if date_h:
        fail("BEHAVIORAL", "Server timestamp exposes timezone",
             "HTTP Date header reveals server clock timezone. Comparing timestamps across "
             "multiple requests maps the operator's active hours and working schedule.",
             date_h.get("value",""), "MEDIUM",
             "Collect timestamps over multiple days; plot activity histogram to determine timezone",
             3)

    # ── Category: Cryptocurrency ──────────────────────────────────────────
    btc_pii = [p for p in pii if "Bitcoin" in p.get("type","")]
    if btc_pii:
        fail("FINANCIAL", f"{len(btc_pii)} Bitcoin address(es) exposed",
             "BTC addresses enable transaction graph analysis. UTXO clustering can link "
             "the operator's wallet to exchange deposits, yielding KYC identity.",
             ", ".join(p["value"][:20]+"..." for p in btc_pii[:3]),
             "HIGH",
             "Submit addresses to Chainalysis/OXT.me; identify exchange deposits for legal process",
             6)

    # ── Calculate OPSEC score ──────────────────────────────────────────────
    opsec_score = max(0, min(100, 100 - score_deduction))
    if opsec_score >= 80:
        rating = "SOPHISTICATED"
        color  = "LOW"
    elif opsec_score >= 55:
        rating = "MODERATE"
        color  = "MEDIUM"
    elif opsec_score >= 30:
        rating = "POOR"
        color  = "HIGH"
    else:
        rating = "CRITICAL FAILURES"
        color  = "CRITICAL"

    by_severity = {
        "CRITICAL": [f for f in failures if f["severity"]=="CRITICAL"],
        "HIGH":     [f for f in failures if f["severity"]=="HIGH"],
        "MEDIUM":   [f for f in failures if f["severity"]=="MEDIUM"],
        "LOW":      [f for f in failures if f["severity"]=="LOW"],
    }

    return {
        "opsec_score":     opsec_score,
        "opsec_rating":    rating,
        "opsec_color":     color,
        "failure_count":   len(failures),
        "failures":        failures,
        "by_severity":     {k: len(v) for k,v in by_severity.items()},
        "critical_actions": [f["action"] for f in by_severity["CRITICAL"]],
    }


# ══════════════════════════════════════════════════════════════════════════════
# ENGINE 14: BEHAVIORAL TIMELINE & TIMEZONE ANALYSIS
# ══════════════════════════════════════════════════════════════════════════════
def behavioral_analysis(html: str, headers_raw: dict, page_intel: dict,
                         stylometry: dict) -> dict:
    """
    Extract all temporal signals to build operator behavior profile:
    - Server timestamps → active timezone
    - Post/forum timestamps → activity window
    - Content update patterns → working hours
    - Language patterns → geographic region
    - Writing velocity → experience level
    """
    timeline = []
    timezone_signals = []
    activity = {}

    h = {k.lower(): v for k, v in headers_raw.items()}

    # ── HTTP Date header ────────────────────────────────────────────────────
    if h.get("date"):
        timeline.append({"source": "HTTP Date header", "value": h["date"],
                          "note": "Server clock at time of fetch"})
        # Try to extract UTC offset
        tz_m = re.search(r'([+-]\d{4}|GMT|UTC)', h["date"])
        if tz_m:
            timezone_signals.append({"signal": "HTTP Date offset", "value": tz_m.group(1)})

    if h.get("last-modified"):
        timeline.append({"source": "Last-Modified header", "value": h["last-modified"],
                          "note": "Last time content was changed — reveals active period"})

    # ── Timestamps in page source ──────────────────────────────────────────
    # ISO 8601
    for ts in re.findall(r'\b(20\d{2}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2})?(?:[+-]\d{4}|Z)?)\b', html)[:10]:
        timeline.append({"source": "ISO timestamp in page", "value": ts, "note": "Content/post timestamp"})

    # Unix timestamps (10-digit, recent)
    for ts in re.findall(r'\b(1[5-9]\d{8})\b', html)[:5]:
        try:
            dt = datetime.utcfromtimestamp(int(ts)).strftime("%Y-%m-%d %H:%M UTC")
            timeline.append({"source": "Unix timestamp in page", "value": ts,
                              "note": f"Decoded: {dt}"})
        except Exception:
            pass

    # Human-readable dates
    for ts in re.findall(r'\b(\d{1,2}[\/\-]\d{1,2}[\/\-]20\d{2})\b', html)[:5]:
        timeline.append({"source": "Date in page source", "value": ts, "note": "Explicit date reference"})

    # ── Timezone clues ──────────────────────────────────────────────────────
    tz_keywords = {
        r'\bIST\b': "Indian Standard Time (UTC+5:30)",
        r'\bMSK\b': "Moscow Time (UTC+3)",
        r'\bCET\b|\bCEST\b': "Central European Time",
        r'\bEST\b|\bEDT\b': "US Eastern Time",
        r'\bPST\b|\bPDT\b': "US Pacific Time",
        r'\bGMT\b': "Greenwich Mean Time",
        r'\bCST\b': "China Standard Time or US Central",
    }
    for pattern, label in tz_keywords.items():
        if re.search(pattern, html + str(headers_raw)):
            timezone_signals.append({"signal": "TZ keyword", "value": label})

    # ── Content language signals ────────────────────────────────────────────
    lang_profile = {}
    if stylometry:
        lang_profile = {
            "likely_language":    stylometry.get("language", {}).get("likely_native_language", "Unknown"),
            "hindi_detected":     stylometry.get("language", {}).get("hindi_romanized", False),
            "russian_detected":   stylometry.get("language", {}).get("russian_patterns", False),
            "vocabulary_richness":stylometry.get("vocabulary_richness", "Unknown"),
            "avg_sentence_len":   stylometry.get("avg_sentence_length", 0),
            "yules_k":            stylometry.get("yules_k", 0),
        }

    # ── Activity window estimation ──────────────────────────────────────────
    # Extract hours from all timestamps
    hours = []
    for entry in timeline:
        h_match = re.search(r'\b(\d{2}):\d{2}', entry["value"])
        if h_match:
            hours.append(int(h_match.group(1)))

    activity_window = {}
    if hours:
        from collections import Counter as _C
        hour_counts = _C(hours)
        peak = hour_counts.most_common(1)[0][0] if hour_counts else None
        activity_window = {
            "observed_hours_utc": sorted(set(hours)),
            "peak_hour_utc":      peak,
            "estimated_local":    f"~{peak}:00 UTC server time" if peak else "Insufficient data",
        }

    # ── Meta tag temporal signals ──────────────────────────────────────────
    for meta_name in ["article:published_time", "article:modified_time",
                       "og:updated_time", "date", "revised"]:
        val = page_intel.get("meta_tags", {}).get(meta_name)
        if val:
            timeline.append({"source": f"Meta tag: {meta_name}", "value": val,
                              "note": "Publication/modification timestamp from meta tags"})

    return {
        "timeline":          timeline,
        "timezone_signals":  timezone_signals,
        "activity_window":   activity_window,
        "language_profile":  lang_profile,
        "behavioral_summary": _summarize_behavior(timezone_signals, lang_profile, activity_window),
    }


def _summarize_behavior(tz_signals, lang_profile, activity) -> list:
    summary = []
    lang = lang_profile.get("likely_language", "")
    if lang and lang != "Unknown":
        summary.append(f"Language: {lang}")
    if lang_profile.get("hindi_detected"):
        summary.append("Hindi/Hinglish patterns → Indian subcontinent likely")
    if lang_profile.get("russian_detected"):
        summary.append("Russian vocabulary patterns → Eastern European likely")
    for tz in tz_signals:
        summary.append(f"Timezone indicator: {tz['value']}")
    if activity.get("peak_hour_utc") is not None:
        h = activity["peak_hour_utc"]
        summary.append(f"Peak activity at {h:02d}:00 UTC")
        # Estimate local timezone
        if 0 <= h <= 6:
            summary.append("Active hours suggest UTC-0 to UTC+2 (Europe/Africa)")
        elif 7 <= h <= 11:
            summary.append("Active hours suggest UTC+5 to UTC+9 (Asia/India)")
        elif 12 <= h <= 17:
            summary.append("Active hours suggest UTC+0 (if late night) or UTC-5 to UTC-8 (Americas)")
    return summary


# ══════════════════════════════════════════════════════════════════════════════
# ENGINE 15: INTELLIGENCE SCORING CORE
# ══════════════════════════════════════════════════════════════════════════════
def intelligence_scoring(pii: list, headers: list, ip_results: list,
                          correlation: dict, infra: dict, stylometry: dict,
                          active_disc: dict, opsec: dict, behavioral: dict,
                          page_intel: dict) -> dict:
    """
    Weighted attribution confidence engine.

    Formula (matches real-world intelligence assessment weighting):
      identity_score = (
          pgp_identity    * 0.30  +   # PGP key with verified email
          direct_email    * 0.25  +   # Email exposed directly
          username_reuse  * 0.20  +   # Same handle on clearnet platforms
          infra_match     * 0.12  +   # Analytics ID / favicon cross-site
          residential_ip  * 0.08  +   # ISP-level IP (legal process path)
          crypto_link     * 0.05      # Exchange-tagged wallet
      )
    Additional signals add to a secondary corroboration score.
    """
    # ── Primary identity signals (direct attribution) ─────────────────────
    pgp_emails = [k.get("email_in_key") for pgp in correlation.get("pgp_keyserver",[])
                  for k in pgp.get("keys",[]) if k.get("email_in_key")]
    pgp_identity = bool(pgp_emails)

    direct_email = any(p.get("type") == "Email Address" for p in pii)

    github_with_pii = [g for g in correlation.get("github",[])
                       if g.get("found") and (g.get("email") or g.get("name") or g.get("location"))]
    reddit_match    = [r for r in correlation.get("reddit",[]) if r.get("found")]
    username_reuse  = bool(github_with_pii or reddit_match)

    has_analytics   = bool(infra.get("analytics_ids"))
    favicon_match   = bool(infra.get("favicon",{}).get("hash"))
    infra_match     = has_analytics or favicon_match

    residential_ips = [g for g in ip_results if g.get("success") and
                       not g.get("is_proxy") and not g.get("is_hosting")]
    residential_ip  = bool(residential_ips)

    exchange_wallets = [w for w in correlation.get("wallet_labels",[]) if w.get("is_exchange")]
    crypto_link      = bool(exchange_wallets)

    # ── Weighted formula ──────────────────────────────────────────────────
    primary_score = (
        (0.30 if pgp_identity   else 0) +
        (0.25 if direct_email   else 0) +
        (0.20 if username_reuse else 0) +
        (0.12 if infra_match    else 0) +
        (0.08 if residential_ip else 0) +
        (0.05 if crypto_link    else 0)
    )

    # ── Corroborating signals (up to 0.20 additional boost) ──────────────
    corroboration = 0.0
    corroboration_notes = []

    btc_pii = [p for p in pii if "Bitcoin" in p.get("type","")]
    if btc_pii:
        corroboration += 0.03
        corroboration_notes.append(f"{len(btc_pii)} BTC address(es) — blockchain forensics path")

    telegram = [p for p in pii if p.get("type") == "Telegram Handle"]
    if telegram:
        corroboration += 0.04
        corroboration_notes.append(f"Telegram handle {telegram[0]['value']} — phone number legal process")

    if behavioral.get("timezone_signals"):
        corroboration += 0.02
        corroboration_notes.append("Timezone signal corroborates geographic assessment")

    lang = stylometry.get("language",{}).get("likely_native_language","") if stylometry else ""
    if lang and lang not in ("Inconclusive","Unknown"):
        corroboration += 0.02
        corroboration_notes.append(f"Language signal: {lang}")

    active_ips = active_disc.get("discovered_ips",[]) if active_disc else []
    if active_ips:
        corroboration += 0.04
        corroboration_notes.append(f"{len(active_ips)} IP(s) via clearnet domain resolution")

    hosting_ips = [g for g in ip_results if g.get("success") and g.get("is_hosting")]
    if hosting_ips and not residential_ips:
        corroboration += 0.03
        corroboration_notes.append(f"Hosting provider IP — abuse team legal path")

    clearnet = page_intel.get("clearnet_links",[])
    if clearnet:
        corroboration += 0.02
        corroboration_notes.append(f"{len(clearnet)} clearnet link(s) — CT/WHOIS investigation")

    corroboration = min(0.20, corroboration)
    raw_confidence = min(1.0, primary_score + corroboration)
    confidence_pct = round(raw_confidence * 100)

    # ── Attribution strength ──────────────────────────────────────────────
    if confidence_pct >= 80:
        strength = "STRONG"
        strength_note = "Multiple independent chains converge. Suitable for initiating legal process."
    elif confidence_pct >= 55:
        strength = "MODERATE"
        strength_note = "Significant evidence present. Additional corroboration strengthens case."
    elif confidence_pct >= 30:
        strength = "DEVELOPING"
        strength_note = "Early-stage leads identified. Continue investigation to build the case."
    else:
        strength = "INSUFFICIENT"
        strength_note = "Insufficient attribution evidence. Use Shodan/urlscan queries to develop leads."

    # ── Threat level ──────────────────────────────────────────────────────
    categories = page_intel.get("category_signals", [])
    threat_map = {
        "Narcotics Market":            ("HIGH",     "Active narcotics distribution platform"),
        "Weapons Market":              ("CRITICAL",  "Illegal weapons trade"),
        "Financial Fraud / Carding":   ("HIGH",     "Financial crime facilitator"),
        "Counterfeit Documents":       ("HIGH",     "Document forgery operation"),
        "Data Leaks / Breaches":       ("HIGH",     "Data trafficking"),
        "Violence for Hire":           ("CRITICAL",  "Threat to human life"),
        "Cybercrime / Malware":        ("HIGH",     "Cybercrime infrastructure"),
        "Human Trafficking / Smuggling":("CRITICAL", "Serious organised crime"),
    }
    threat_level, threat_note = "UNDETERMINED", "Market category not identified"
    for cat in categories:
        if cat in threat_map:
            lvl, note = threat_map[cat]
            order = ["LOW","MEDIUM","HIGH","CRITICAL"]
            if order.index(lvl) > order.index(threat_level.replace("UNDETERMINED","LOW")):
                threat_level, threat_note = lvl, note

    # ── Sophistication ─────────────────────────────────────────────────────
    opsec_score = opsec.get("opsec_score", 50) if opsec else 50
    sophistication = (
        "ADVANCED"      if opsec_score >= 80 else
        "INTERMEDIATE"  if opsec_score >= 55 else
        "NOVICE"        if opsec_score >= 30 else
        "CARELESS"
    )

    # ── Geographic signals ─────────────────────────────────────────────────
    geo_signals = []
    for g in ip_results:
        if g.get("country"): geo_signals.append(g["country"])
    for b in behavioral.get("behavioral_summary",[]):
        if "likely" in b.lower() or "india" in b.lower() or "europe" in b.lower():
            geo_signals.append(b)
    probable_region = geo_signals[0] if geo_signals else "Undetermined"

    # ── Evidence table ─────────────────────────────────────────────────────
    evidence_table = [
        {"factor": "PGP key with verified email",   "weight": "30%", "present": pgp_identity,   "detail": pgp_emails[0] if pgp_emails else ""},
        {"factor": "Email address in page",          "weight": "25%", "present": direct_email,   "detail": next((p["value"] for p in pii if p.get("type")=="Email Address"), "")},
        {"factor": "Username on clearnet platforms", "weight": "20%", "present": username_reuse, "detail": (github_with_pii[0].get("profile_url","") if github_with_pii else "Reddit match" if reddit_match else "")},
        {"factor": "Analytics ID / favicon reuse",   "weight": "12%", "present": infra_match,    "detail": "Cross-site fingerprint linkage"},
        {"factor": "Residential ISP IP",             "weight": "8%",  "present": residential_ip, "detail": f"{residential_ips[0]['ip']} / {residential_ips[0].get('isp','')}" if residential_ips else ""},
        {"factor": "Exchange-tagged crypto wallet",  "weight": "5%",  "present": crypto_link,    "detail": f"{exchange_wallets[0].get('label','')} KYC process" if exchange_wallets else ""},
    ]

    # ── Top 5 actionable leads ─────────────────────────────────────────────
    top_leads = []
    priority_order = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}

    if pgp_identity:
        for em in pgp_emails[:2]:
            top_leads.append({"rank":1,"priority":"CRITICAL","lead_type":"PGP → Email Identity",
                "action":f"Legal process to {em.split('@')[-1]} for {em}",
                "expected_outcome":"Full subscriber identity, registration IP, account history"})
    if direct_email:
        emails = [p["value"] for p in pii if p.get("type")=="Email Address"][:2]
        for em in emails:
            top_leads.append({"rank":2,"priority":"CRITICAL","lead_type":"Direct Email Exposure",
                "action":f"Legal process to {em.split('@')[-1]} for account {em}",
                "expected_outcome":"Name, registration IP, recovery email, device IDs"})
    if residential_ips:
        for g in residential_ips[:2]:
            top_leads.append({"rank":1,"priority":"CRITICAL","lead_type":"Residential IP Exposed",
                "action":f"Legal process to {g.get('isp')} ({g.get('country')}) for IP {g['ip']}",
                "expected_outcome":"Subscriber name, address, account creation date"})
    if telegram:
        top_leads.append({"rank":2,"priority":"CRITICAL","lead_type":"Telegram Handle",
            "action":f"Legal process to Telegram for phone number linked to {telegram[0]['value']}",
            "expected_outcome":"Phone number → SIM registration → national identity"})
    if has_analytics:
        for cat, items in infra.get("analytics_ids",{}).items():
            for item in items[:1]:
                top_leads.append({"rank":3,"priority":"HIGH","lead_type":"Analytics ID Cross-Site",
                    "action":f"Search all internet for {cat}: {item.get('id')} — find operator clearnet identity",
                    "expected_outcome":"Clearnet domain → WHOIS/registrar → real identity"})
    if github_with_pii:
        gh = github_with_pii[0]
        top_leads.append({"rank":3,"priority":"HIGH","lead_type":"GitHub Identity Match",
            "action":f"Legal process to GitHub/Microsoft for {gh.get('profile_url','')}",
            "expected_outcome":f"Account email, registration IP, payment details. PII already visible: {gh.get('pii_found','')}"})
    if exchange_wallets:
        w = exchange_wallets[0]
        top_leads.append({"rank":3,"priority":"HIGH","lead_type":"Exchange Wallet",
            "action":f"Legal process to {w.get('label','')} for KYC records on wallet",
            "expected_outcome":"Verified name, government ID, bank account, login IP logs"})
    if active_ips:
        g = active_ips[0]
        top_leads.append({"rank":4,"priority":"HIGH","lead_type":"Clearnet Domain IP",
            "action":f"Legal/abuse request to {g.get('isp','hosting provider')} for {g.get('ip','')} via domain {g.get('source_domain','')}",
            "expected_outcome":"Server account details, payment method, KYC if available"})

    top_leads = sorted(top_leads, key=lambda x: (priority_order.get(x["priority"],3), x["rank"]))[:5]

    return {
        "attribution_confidence_pct": confidence_pct,
        "primary_score_pct":          round(primary_score * 100),
        "corroboration_score_pct":    round(corroboration * 100),
        "attribution_strength":       strength,
        "attribution_strength_note":  strength_note,
        "threat_level":               threat_level,
        "threat_note":                threat_note,
        "operator_sophistication":    sophistication,
        "opsec_score":                opsec_score,
        "probable_region":            probable_region,
        "evidence_table":             evidence_table,
        "corroboration_notes":        corroboration_notes,
        "top_5_leads":                top_leads,
        "geo_signals":                list(set(geo_signals))[:6],
        # Legacy field kept for backwards compat
        "priority_actions": [
            {"priority": l["priority"], "action": l["lead_type"], "detail": l["action"]}
            for l in top_leads
        ],
        "evidence_breakdown": [
            {"name": e["factor"], "weight": int(e["weight"].replace("%","")),
             "found": e["present"], "contribution": int(e["weight"].replace("%","")) if e["present"] else 0,
             "detail": e["detail"]}
            for e in evidence_table
        ],
        "evidence_found_count": sum(1 for e in evidence_table if e["present"]),
        "evidence_total": len(evidence_table),
    }

    # Direct identity evidence (highest weight)
    pgp_with_email = any(k.get("email_in_key") for pgp in correlation.get("pgp_keyserver",[])
                         for k in pgp.get("keys",[]))
    evidence("PGP key with real email",   30, pgp_with_email,
             "Email from PGP key → direct legal process path")

    has_email = any(p.get("type")=="Email Address" for p in pii)
    evidence("Email address in page",     25, has_email,
             "Traceable email exposed in page content")

    github_pii = any(g.get("email") or g.get("location") for g in correlation.get("github",[]))
    evidence("GitHub profile with PII",   22, github_pii,
             "GitHub account with name/email/location linked to operator")

    # IP intelligence (high weight when residential)
    residential_ips = [g for g in ip_results if g.get("success") and
                       not g.get("is_proxy") and not g.get("is_hosting")]
    evidence("Residential IP identified", 28, bool(residential_ips),
             f"Direct ISP legal process: {residential_ips[0]['ip'] if residential_ips else ''}")

    hosting_ips = [g for g in ip_results if g.get("success") and g.get("is_hosting")]
    evidence("Hosting provider IP",       15, bool(hosting_ips) and not bool(residential_ips),
             "VPS/cloud IP — abuse team request required")

    # Analytics / tracking (critical cross-link)
    has_analytics = bool(infra.get("analytics_ids"))
    evidence("Analytics tracker ID",      20, has_analytics,
             "Same tracker on clearnet site links both identities")

    # BTC wallet
    btc = [p for p in pii if "Bitcoin" in p.get("type","")]
    evidence("Cryptocurrency addresses",  12, bool(btc),
             f"{len(btc)} address(es) for blockchain forensics")

    # PGP key (even without email)
    has_pgp = any(p.get("type") in ("PGP Key Block","PGP Key ID") for p in pii)
    evidence("PGP key present",           10, has_pgp and not pgp_with_email,
             "Keyserver search may yield identity")

    # Clearnet domains
    clearnet = page_intel.get("clearnet_links", [])
    evidence("Clearnet domain links",     8, bool(clearnet),
             f"{len(clearnet)} clearnet domain(s) — DNS + CT log resolution")

    # Telegram
    telegram = [p for p in pii if p.get("type")=="Telegram Handle"]
    evidence("Telegram handle",           10, bool(telegram),
             "Phone number linkage via legal process")

    # Behavioral signals
    lang_signal = behavioral.get("language_profile", {}).get("likely_language","")
    evidence("Language/behavioral signal", 5, bool(lang_signal and lang_signal!="Unknown"),
             f"Language: {lang_signal}")

    # Favicon hash
    evidence("Favicon hash (Shodan match)", 8,
             bool(infra.get("favicon",{}).get("hash")),
             "Cross-site server fingerprint")

    # ── Calculate attribution confidence ──────────────────────────────────
    total_possible = sum(e["weight"] for e in evidence_scores)
    total_found    = sum(e["contribution"] for e in evidence_scores)
    confidence_pct = round((total_found / total_possible) * 100) if total_possible else 0

    # ── Attribution strength label ─────────────────────────────────────────
    if confidence_pct >= 75:
        strength = "STRONG"
        strength_note = "Multiple independent evidence chains converge. Sufficient for legal action."
    elif confidence_pct >= 50:
        strength = "MODERATE"
        strength_note = "Significant evidence. Additional corroboration recommended before legal action."
    elif confidence_pct >= 25:
        strength = "WEAK"
        strength_note = "Early-stage intelligence. Continue investigation to strengthen attribution."
    else:
        strength = "INSUFFICIENT"
        strength_note = "Insufficient evidence for attribution. Use Shodan/urlscan queries to develop leads."

    # ── Threat level ──────────────────────────────────────────────────────
    categories = page_intel.get("category_signals", [])
    threat_map = {
        "Narcotics Market":        ("HIGH",   "Active narcotics distribution"),
        "Weapons Market":          ("CRITICAL","Illegal weapons trade"),
        "Financial Fraud / Carding":("HIGH",  "Financial crime enabling"),
        "Counterfeit Documents":   ("HIGH",   "Document forgery"),
        "Data Leaks / Breaches":   ("HIGH",   "Data trafficking"),
        "Violence for Hire":       ("CRITICAL","Threat to life"),
        "Cybercrime / Malware":    ("HIGH",   "Cybercrime infrastructure"),
        "Human Trafficking / Smuggling":("CRITICAL","Serious organized crime"),
    }
    threat_level, threat_note = "MEDIUM", "Category not determined"
    for cat in categories:
        if cat in threat_map:
            lvl, note = threat_map[cat]
            if ["LOW","MEDIUM","HIGH","CRITICAL"].index(lvl) > \
               ["LOW","MEDIUM","HIGH","CRITICAL"].index(threat_level):
                threat_level, threat_note = lvl, note

    # ── Operator sophistication ────────────────────────────────────────────
    opsec_score = opsec.get("opsec_score", 50)
    if opsec_score >= 80:
        sophistication = "ADVANCED"
    elif opsec_score >= 55:
        sophistication = "INTERMEDIATE"
    elif opsec_score >= 30:
        sophistication = "NOVICE"
    else:
        sophistication = "CARELESS"

    # ── Geographic assessment ─────────────────────────────────────────────
    geo_signals = []
    for g in ip_results:
        if g.get("country"):
            geo_signals.append(g["country"])
    behavior_summary = behavioral.get("behavioral_summary", [])
    for b in behavior_summary:
        if "likely" in b.lower():
            geo_signals.append(b)
    probable_region = geo_signals[0] if geo_signals else "Undetermined"

    # ── Priority actions ──────────────────────────────────────────────────
    priority_actions = []
    for e in sorted(evidence_scores, key=lambda x: -x["contribution"]):
        if e["found"] and e["detail"]:
            priority_actions.append({
                "priority": "CRITICAL" if e["weight"] >= 20 else "HIGH" if e["weight"] >= 10 else "MEDIUM",
                "action":   e["name"],
                "detail":   e["detail"],
            })

    return {
        "attribution_confidence_pct": confidence_pct,
        "attribution_strength":       strength,
        "attribution_strength_note":  strength_note,
        "threat_level":               threat_level,
        "threat_note":                threat_note,
        "operator_sophistication":    sophistication,
        "opsec_score":                opsec_score,
        "probable_region":            probable_region,
        "evidence_breakdown":         evidence_scores,
        "evidence_found_count":       sum(1 for e in evidence_scores if e["found"]),
        "evidence_total":             len(evidence_scores),
        "priority_actions":           priority_actions[:8],
        "geo_signals":                list(set(geo_signals))[:6],
    }


# ══════════════════════════════════════════════
# API ENDPOINTS
# ══════════════════════════════════════════════
@app.get("/")
def root():
    return {"service": "UMBRA V3", "status": "online", "version": "3.2.0",
            "endpoints": ["/api/tor/check", "/api/analyze", "/api/geo/{ip}", "/api/ct/{domain}", "/api/btc/{address}"]}

@app.get("/api/tor/check")
def tor_check():
    return check_tor()

@app.get("/api/tor/newcircuit")
def new_circuit():
    try:
        from stem import Signal
        from stem.control import Controller
        with Controller.from_port(port=9051) as c:
            c.authenticate()
            c.signal(Signal.NEWNYM)
            return {"success": True, "message": "New Tor circuit requested"}
    except Exception as e:
        return {"success": False, "error": str(e)}

@app.post("/api/analyze")
def analyze(req: AnalyzeRequest):
    log.info(f"[UMBRA V3] Analysis: {req.onion_url}")
    report = {
        "target_url": req.onion_url,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "fetch": None, "page_intel": None, "pii": [],
        "headers": [], "stylometry": None,
        "ip_intelligence": [], "active_ip_discovery": None,
        "cert_transparency": None, "blockchain": [], "correlation": None,
        "infra_fingerprint": None, "attribution_graph": None,
        "opsec_analysis": None, "behavioral": None, "intelligence": None,
        "ai_brief": "", "errors": [],
    }

    # 1. Fetch via Tor
    log.info("[1/12] Fetching via Tor SOCKS5h...")
    fr = fetch_onion(req.onion_url)
    report["fetch"] = {
        "success": fr.get("success"), "status_code": fr.get("status_code"),
        "url": fr.get("url"), "content_length": fr.get("content_length"),
        "elapsed_seconds": fr.get("elapsed_seconds"),
        "redirect_chain": fr.get("redirect_chain", []),
        "server": fr.get("server_fingerprint"),
    }
    if not fr.get("success"):
        report["errors"].append(f"Fetch failed: {fr.get('error')}")
        return report

    html        = fr["page_source"]
    headers_raw = fr["headers"]   # preserve raw dict for IP extraction

    # 2. Page Intelligence
    log.info("[2/12] Extracting page intelligence...")
    pi = extract_page_intel(html, req.onion_url)
    report["page_intel"] = {k: v for k, v in pi.items() if k != "all_text_for_analysis"}

    # 3. PII Extraction (now includes IPv6)
    log.info("[3/12] Running PII extraction (30 patterns incl. IPv6)...")
    report["pii"] = extract_pii(html + " " + json.dumps(headers_raw))

    # 4. Header Analysis
    log.info("[4/12] Analyzing HTTP headers (RFC 7239, X-Real-IP, CF-Connecting-IP)...")
    report["headers"] = analyze_headers(headers_raw)

    # 5. IP Geolocation + VPN Detection (full proxy chain)
    log.info("[5/12] Geolocating IPs — proxy chain + page source (IPv4 + IPv6)...")
    report["ip_intelligence"] = geolocate_all_ips(
        report["pii"], report["headers"], headers_raw=headers_raw
    )

    # 6. Stylometry
    log.info("[6/12] Computing stylometric fingerprint...")
    report["stylometry"] = analyze_stylometry(pi["all_text_for_analysis"])

    # 7. Certificate Transparency
    log.info("[7/12] Querying Certificate Transparency logs...")
    clearnet_domains = list(set(
        re.sub(r"https?://", "", l["href"]).split("/")[0]
        for l in pi.get("clearnet_links", [])[:4]
        if l.get("href", "").startswith("http")
    ))
    if clearnet_domains:
        report["cert_transparency"] = [{"domain": d, "result": query_ct(d)} for d in clearnet_domains[:2]]

    # 8. Blockchain Forensics
    log.info("[8/12] Blockchain forensics...")
    btc_list = [p["value"] for p in report["pii"] if "Bitcoin" in p["type"]][:3]
    report["blockchain"] = [{"address": a, "result": query_btc(a)} for a in btc_list]

    # 9. Identity Correlation
    log.info("[9/12] Cross-platform identity correlation (GitHub, Reddit, PGP)...")
    report["correlation"] = correlate_identities(report["pii"])

    # 10. Infrastructure Fingerprinting
    log.info("[10/12] Infrastructure fingerprinting (favicon, analytics, CDN)...")
    report["infra_fingerprint"] = fingerprint_infra(
        html, headers_raw, req.onion_url, pi.get("favicon_url", "")
    )

    # 10b. Active IP Discovery (correlation attack — resolves clearnet domains)
    log.info("[10b] Active IP Discovery — DNS resolution + Shodan queries...")
    report["active_ip_discovery"] = active_ip_discovery(
        html, headers_raw, report["pii"], pi, report["infra_fingerprint"]
    )
    # Merge discovered IPs into ip_intelligence so graph and brief see them
    for entry in report["active_ip_discovery"].get("discovered_ips", []):
        if entry.get("success") and entry.get("ip"):
            entry.setdefault("priority", "HIGH")
            report["ip_intelligence"].append(entry)

    # 11. Attribution Graph
    log.info("[11/14] Building attribution graph...")
    report["attribution_graph"] = build_graph(
        req.onion_url, report["pii"], report["correlation"],
        report["infra_fingerprint"], report["headers"], report["ip_intelligence"],
        active_disc=report["active_ip_discovery"]
    )

    # 12. OPSEC Failure Detector
    log.info("[12/14] OPSEC failure analysis...")
    report["opsec_analysis"] = detect_opsec_failures(
        report["pii"], report["headers"], pi,
        report["stylometry"], report["ip_intelligence"],
        report["active_ip_discovery"] or {}, report["infra_fingerprint"]
    )

    # 13. Behavioral Timeline
    log.info("[13/14] Behavioral timeline + timezone analysis...")
    report["behavioral"] = behavioral_analysis(
        html, headers_raw, pi, report["stylometry"]
    )

    # 14. Intelligence Scoring Core
    log.info("[14/14] Intelligence scoring — attribution confidence...")
    report["intelligence"] = intelligence_scoring(
        report["pii"], report["headers"], report["ip_intelligence"],
        report["correlation"], report["infra_fingerprint"],
        report["stylometry"] or {}, report["active_ip_discovery"] or {},
        report["opsec_analysis"], report["behavioral"], pi
    )

    # 15. Rule-based OSINT Brief (now enriched with scoring)
    log.info("[15] Generating OSINT brief...")
    report["ai_brief"] = osint_brief_engine(
        req.onion_url, pi, report["pii"], report["headers"],
        report["stylometry"], report["correlation"], report["ip_intelligence"],
        infra=report["infra_fingerprint"], active_disc=report["active_ip_discovery"]
    )

    stats = report["attribution_graph"]["stats"]
    disc_count = len(report["active_ip_discovery"].get("discovered_ips", []))
    log.info(f"[DONE] PII:{len(report['pii'])} IPs:{len(report['ip_intelligence'])} "
             f"ActiveDisc:{disc_count} "
             f"Leads:{len(report['correlation'].get('high_confidence_leads',[]))} "
             f"Graph:{stats['total_nodes']} nodes/{stats['total_edges']} edges")

    # Record scan for cross-case correlation
    _record_scan(req.onion_url, report.get("intelligence", {}), report["pii"])

    return report


@app.get("/api/cases")
def list_cases():
    """List all scans performed in this session for cross-case correlation."""
    return {
        "total_scans": len(_SCAN_HISTORY),
        "scans": _SCAN_HISTORY,
        "cross_case_hits": _find_cross_case_links(),
    }

def _find_cross_case_links() -> list:
    """Find artifacts reused across multiple scanned sites."""
    from collections import defaultdict
    artifact_to_urls = defaultdict(list)
    for scan in _SCAN_HISTORY:
        for h in scan.get("artifact_hashes", []):
            artifact_to_urls[h].append(scan["url"])
    return [
        {"artifact_hash": h, "seen_in": urls, "count": len(urls)}
        for h, urls in artifact_to_urls.items()
        if len(urls) > 1
    ]

@app.get("/api/cases/export")
def export_case_json():
    """Export all session scans as a structured case file (JSON)."""
    return {
        "case_export": {
            "generated": datetime.utcnow().isoformat() + "Z",
            "classification": "LEA / NIA — RESTRICTED",
            "tool": "UMBRA V3.2",
            "total_targets": len(_SCAN_HISTORY),
            "cross_case_links": _find_cross_case_links(),
            "scans": _SCAN_HISTORY,
        }
    }


@app.get("/api/geo/{ip}")
def geo_lookup(ip: str):
    return geolocate_ip(ip)

@app.get("/api/dns/{domain:path}")
def dns_lookup(domain: str):
    """Resolve a clearnet domain to IPs. Useful for manual investigation."""
    res = dns_resolve_domain(domain)
    if res.get("ips"):
        geos = []
        for ip in res["ips"]:
            geo = geolocate_ip(ip)
            geo["domain"] = domain
            geos.append(geo)
        return {"domain": domain, "ips": res["ips"], "geolocation": geos}
    ht = hackertarget_dns(domain)
    return {"domain": domain, "dns_result": res, "hackertarget_result": ht}

@app.get("/api/reverseip/{ip}")
def reverseip_lookup(ip: str):
    """Find all domains hosted on an IP — useful after discovering an operator IP."""
    return hackertarget_reverseip(ip)

@app.get("/api/ct/{domain}")
def ct_lookup(domain: str):
    return query_ct(domain)

@app.get("/api/btc/{address}")
def btc_lookup(address: str):
    return query_btc(address)

@app.post("/api/export")
def export_case(report: dict):
    """
    Generate a structured JSON case file from a completed scan report.
    Suitable for submission to agency case management systems.
    """
    intel = report.get("intelligence", {})
    opsec = report.get("opsec_analysis", {})
    beh   = report.get("behavioral", {})
    ts    = datetime.utcnow().isoformat() + "Z"
    return {
        "case_metadata": {
            "generated_at":   ts,
            "tool":           "UMBRA v3.2",
            "classification": "RESTRICTED — NIA / LEA Use Only",
            "target_url":     report.get("target_url",""),
            "scan_timestamp": report.get("timestamp",""),
        },
        "executive_summary": {
            "attribution_confidence":  f"{intel.get('attribution_confidence_pct',0)}%",
            "attribution_strength":    intel.get("attribution_strength",""),
            "threat_level":            intel.get("threat_level",""),
            "threat_category":         intel.get("threat_note",""),
            "operator_sophistication": intel.get("operator_sophistication",""),
            "opsec_score":             f"{opsec.get('opsec_score',0)}/100",
            "probable_region":         intel.get("probable_region",""),
            "pii_artifacts_found":     len(report.get("pii",[])),
            "ips_geolocated":          len([g for g in report.get("ip_intelligence",[]) if g.get("success")]),
        },
        "top_5_leads":         intel.get("top_5_leads",[]),
        "evidence_table":      intel.get("evidence_table",[]),
        "opsec_failures":      opsec.get("failures",[]),
        "critical_actions":    opsec.get("critical_actions",[]),
        "behavioral_signals":  beh.get("behavioral_summary",[]),
        "pii_artifacts":       report.get("pii",[]),
        "ip_intelligence":     report.get("ip_intelligence",[]),
        "identity_correlation": report.get("correlation",{}),
        "infrastructure": {
            "shodan_queries":   report.get("active_ip_discovery",{}).get("shodan_queries",[]),
            "clearnet_domains": report.get("active_ip_discovery",{}).get("all_candidate_domains",[]),
            "analytics_ids":    report.get("infra_fingerprint",{}).get("analytics_ids",{}),
            "favicon_hash":     report.get("infra_fingerprint",{}).get("favicon",{}),
        },
        "legal_process_matrix": _build_legal_matrix(report),
    }

def _build_legal_matrix(report: dict) -> list:
    matrix = []
    for g in report.get("ip_intelligence", []):
        if not g.get("success"): continue
        if not g.get("is_proxy") and not g.get("is_hosting"):
            matrix.append({"type":"ISP_SUBSCRIBER_QUERY","provider":g.get("isp",""),
                "country":g.get("country",""),"target":g.get("ip",""),
                "request":"Subscriber name, billing address, account creation date, device MAC",
                "mechanism":"Section 91 CrPC (domestic) or MLAT (foreign)","urgency":"HIGH"})
        elif g.get("is_hosting"):
            matrix.append({"type":"HOSTING_ABUSE_REQUEST","provider":g.get("isp",""),
                "country":g.get("country",""),"target":g.get("ip",""),
                "request":"VPS account holder, payment records, KYC documents",
                "mechanism":"Abuse team + MLAT if foreign","urgency":"MEDIUM"})
    for pgp in report.get("correlation",{}).get("pgp_keyserver",[]):
        for k in pgp.get("keys",[]):
            if k.get("email_in_key"):
                em = k["email_in_key"]
                matrix.append({"type":"EMAIL_PROVIDER_QUERY",
                    "provider":em.split("@")[-1] if "@" in em else "",
                    "target":em,"request":"Registration IP, name, recovery email, login history, device IDs",
                    "mechanism":"Legal process; ProtonMail via Swiss channels","urgency":"HIGH"})
    for tg in [p for p in report.get("pii",[]) if p.get("type")=="Telegram Handle"]:
        matrix.append({"type":"TELEGRAM_SUBPOENA","provider":"Telegram","target":tg["value"],
            "request":"Phone number, registration IP, device identifiers",
            "mechanism":"Interpol NCB channel to Telegram","urgency":"HIGH"})
    return matrix


@app.get("/api/proxy-test")
def proxy_test_headers(
    x_forwarded_for: Optional[str] = None,
    forwarded: Optional[str] = None,
    x_real_ip: Optional[str] = None,
):
    """
    Dev endpoint — simulate header extraction.
    Pass ?x_forwarded_for=1.2.3.4,5.6.7.8 to test chain parsing.
    """
    fake = {}
    if x_forwarded_for: fake["X-Forwarded-For"] = x_forwarded_for
    if forwarded:        fake["Forwarded"] = forwarded
    if x_real_ip:        fake["X-Real-IP"] = x_real_ip
    return {
        "extracted": extract_proxy_ips_from_headers(fake),
        "rfc7239_parse": _parse_rfc7239_forwarded(forwarded or ""),
    }

if __name__ == "__main__":
    import uvicorn
    print("\n" + "="*60)
    print("  UMBRA V3.1 — Dark Web Intelligence Platform")
    print("  NIA / Law Enforcement Use Only")
    print("="*60)
    print("\n  Changes in v3.1:")
    print("  ✓ IPv6 address extraction (PII + geolocation)")
    print("  ✓ RFC 7239 Forwarded header parser")
    print("  ✓ Full X-Forwarded-For proxy chain reconstruction")
    print("  ✓ X-Real-IP, CF-Connecting-IP, True-Client-IP, Via")
    print("  ✓ Rule-based OSINT brief (no Claude API required)")
    print("\n  Requirements:")
    print("  1. Tor daemon at 127.0.0.1:9050")
    print("  2. pip install fastapi uvicorn requests[socks] PySocks stem")
    print("     beautifulsoup4 lxml pydantic mmh3")
    print("\n  API: http://localhost:8000")
    print("  Docs: http://localhost:8000/docs\n")
    uvicorn.run("umbra_v3_backend:app", host="0.0.0.0", port=8000, reload=False)
