#!/usr/bin/env python3
"""
UMBRA V3 — Dark Web Intelligence Platform
NIA / Law Enforcement Use Only

Fixes in this revision:
  • IPv4 + IPv6 extraction (PII patterns + geolocation)
  • RFC 7239 Forwarded header parsing (for=, by=, host=)
  • Full X-Forwarded-For proxy chain reconstruction
  • X-Real-IP, CF-Connecting-IP, True-Client-IP, Via headers
  • Rule-based OSINT Intelligence Brief (no LLM API required)
  • Proxy/VPN chain labeling (position-aware)

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
import ipaddress
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
    Returns country, city, ISP, ASN, lat/lon, timezone, VPN/proxy/hosting flags.
    """
    clean = ip.strip().strip("[]")   # remove IPv6 brackets if present
    try:
        fields = ("status,message,country,countryCode,region,regionName,city,"
                  "zip,lat,lon,timezone,isp,org,as,asname,proxy,hosting,query")
        r = requests.get(
            f"http://ip-api.com/json/{clean}?fields={fields}",
            timeout=10, headers={"User-Agent": UA}
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

        return {
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
def build_graph(target_url, pii, correlation, infra, headers_findings, ip_results):
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


def osint_brief_engine(url, page_intel, pii, headers, stylo, correlation, ip_results, infra=None) -> str:
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

    # ── 3. TOP DE-ANONYMIZATION LEADS ───────────────────────────────────────
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


# ══════════════════════════════════════════════
# API ENDPOINTS
# ══════════════════════════════════════════════
@app.get("/")
def root():
    return {"service": "UMBRA V3", "status": "online", "version": "3.1.0",
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
        "ip_intelligence": [], "cert_transparency": None,
        "blockchain": [], "correlation": None,
        "infra_fingerprint": None, "attribution_graph": None,
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

    # 11. Attribution Graph
    log.info("[11/12] Building attribution graph...")
    report["attribution_graph"] = build_graph(
        req.onion_url, report["pii"], report["correlation"],
        report["infra_fingerprint"], report["headers"], report["ip_intelligence"]
    )

    # 12. Rule-based OSINT Intelligence Brief (no API key required)
    log.info("[12/12] Generating rule-based OSINT intelligence brief...")
    report["ai_brief"] = osint_brief_engine(
        req.onion_url, pi, report["pii"], report["headers"],
        report["stylometry"], report["correlation"], report["ip_intelligence"],
        infra=report["infra_fingerprint"]
    )

    stats = report["attribution_graph"]["stats"]
    log.info(f"[DONE] PII:{len(report['pii'])} IPs:{len(report['ip_intelligence'])} "
             f"Leads:{len(report['correlation'].get('high_confidence_leads',[]))} "
             f"Graph:{stats['total_nodes']} nodes/{stats['total_edges']} edges")
    return report


@app.get("/api/geo/{ip}")
def geo_lookup(ip: str):
    return geolocate_ip(ip)

@app.get("/api/ct/{domain}")
def ct_lookup(domain: str):
    return query_ct(domain)

@app.get("/api/btc/{address}")
def btc_lookup(address: str):
    return query_btc(address)

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
