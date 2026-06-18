#!/usr/bin/env python3
"""
UMBRA V3 — Complete Dark Web Intelligence Platform
NIA / Law Enforcement Use Only

Install:
    pip install fastapi uvicorn "requests[socks]" PySocks stem anthropic \
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
from collections import Counter
from typing import Optional
from datetime import datetime
from urllib.parse import quote

import requests
from bs4 import BeautifulSoup
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import anthropic

# ══════════════════════════════════════════════
# CONFIGURATION
# ══════════════════════════════════════════════
TOR_PROXY = "socks5h://127.0.0.1:9050"
TIMEOUT   = 35
UA        = "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("umbra")

app = FastAPI(title="UMBRA V3", version="3.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

class AnalyzeRequest(BaseModel):
    onion_url: str
    anthropic_api_key: Optional[str] = ""

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
# ENGINE 2: PII EXTRACTION (28 patterns)
# ══════════════════════════════════════════════
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
    ("IPv4 Address",          r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b", "CRITICAL"),
    ("Phone (Indian)",        r"(?:\+91[\-\s]?)?[6-9]\d{9}\b",                                       "HIGH"),
    ("Phone (International)", r"\+[1-9]\d{7,14}\b",                                                  "HIGH"),
    ("Clearnet URL",          r"https?://(?!.*\.onion)[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+",       "CRITICAL"),
    ("PGP Key Block",         r"-----BEGIN PGP PUBLIC KEY BLOCK-----[\s\S]+?-----END PGP PUBLIC KEY BLOCK-----", "HIGH"),
    ("PGP Key ID",            r"\b(?:0x)?[A-F0-9]{8,16}\b",                                          "MEDIUM"),
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

def extract_pii(text: str) -> list:
    findings, seen = [], set()
    PRIVATE_IPS = ("127.", "0.0.", "255.", "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.")
    for ptype, pattern, risk in PII_PATTERNS:
        for m in re.finditer(pattern, text, re.IGNORECASE | re.MULTILINE):
            val = m.group(0).strip()
            key = (ptype, val)
            if key in seen or len(val) < 4:
                continue
            if ptype == "IPv4 Address" and val.startswith(PRIVATE_IPS):
                continue
            seen.add(key)
            findings.append({
                "type": ptype, "value": val, "risk": risk,
                "context": text[max(0, m.start()-50):m.end()+50].strip()
            })
    return findings

# ══════════════════════════════════════════════
# ENGINE 3: IP GEOLOCATION + VPN DETECTION
# ══════════════════════════════════════════════
def geolocate_ip(ip: str) -> dict:
    """
    Real geolocation via ip-api.com (free, no key).
    Returns country, city, ISP, ASN, lat/lon, timezone, VPN/proxy/hosting flags.
    """
    try:
        fields = "status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,proxy,hosting,query"
        r = requests.get(
            f"http://ip-api.com/json/{ip}?fields={fields}",
            timeout=10, headers={"User-Agent": UA}
        )
        d = r.json()
        if d.get("status") == "fail":
            return {"success": False, "ip": ip, "error": d.get("message", "Lookup failed")}

        # Build investigation note
        notes = []
        if d.get("proxy"):
            notes.append("VPN/PROXY DETECTED — known proxy or VPN exit node")
        if d.get("hosting"):
            notes.append(f"HOSTING/DATACENTER — likely VPS/cloud, not residential")
        isp_lower = (d.get("isp") or "").lower()
        hosting_providers = ["digitalocean", "linode", "vultr", "amazon", "google", "ovh", "hetzner", "cloudflare", "contabo", "serverius", "frantech", "leaseweb"]
        if any(x in isp_lower for x in hosting_providers):
            notes.append(f"Cloud hosting provider: {d.get('isp')} — submit abuse/legal request to hosting provider")
        elif not d.get("proxy") and not d.get("hosting"):
            notes.append(f"Residential ISP: {d.get('isp')} — submit legal process for subscriber identity")

        return {
            "success": True, "ip": ip,
            "country": d.get("country"), "country_code": d.get("countryCode"),
            "region": d.get("regionName"), "city": d.get("city"), "postal": d.get("zip"),
            "lat": d.get("lat"), "lon": d.get("lon"),
            "timezone": d.get("timezone"),
            "isp": d.get("isp"), "org": d.get("org"),
            "asn": d.get("as"), "asn_name": d.get("asname"),
            "is_proxy": d.get("proxy", False),
            "is_hosting": d.get("hosting", False),
            "google_maps_url": f"https://www.google.com/maps?q={d.get('lat')},{d.get('lon')}",
            "google_maps_embed": f"https://maps.google.com/maps?q={d.get('lat')},{d.get('lon')}&z=12&output=embed",
            "investigation_notes": notes,
            "legal_action": "Legal process → " + d.get("isp", "ISP") + " for subscriber identity records",
        }
    except Exception as e:
        return {"success": False, "ip": ip, "error": str(e)}

def geolocate_all_ips(pii_findings: list, header_findings: list) -> list:
    """Geolocate all public IPs from PII extraction and header leaks."""
    to_check = []
    seen = set()

    # X-Forwarded-For = MOST CRITICAL (real IP leak from misconfigured hidden service)
    for h in header_findings:
        if h.get("field") == "X-Forwarded-For":
            for ip in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", h.get("value", "")):
                if ip not in seen and not ip.startswith(("127.", "10.", "192.168.", "172.")):
                    seen.add(ip)
                    to_check.append({"ip": ip, "source": "X-Forwarded-For HEADER LEAK — CRITICAL", "priority": "CRITICAL"})

    # IPs from page source
    for p in pii_findings:
        if p["type"] == "IPv4 Address":
            ip = p["value"]
            if ip not in seen:
                seen.add(ip)
                to_check.append({"ip": ip, "source": "Page source", "priority": "HIGH"})

    results = []
    for entry in to_check[:8]:
        geo = geolocate_ip(entry["ip"])
        geo["source"] = entry["source"]
        geo["priority"] = entry["priority"]
        results.append(geo)
        time.sleep(0.4)  # Rate limit: ip-api.com allows 45 req/min free
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
            "note": "Server clock → timezone fingerprint. Compare post times across days to map operator schedule"})

    if "x-forwarded-for" in h:
        findings.append({"field": "X-Forwarded-For", "value": h["x-forwarded-for"], "risk": "CRITICAL",
            "note": "REAL IP LEAK — hidden service running as reverse proxy. Leftmost IP is operator real IP",
            "action": f"IMMEDIATELY geolocate and request ISP records: {h['x-forwarded-for']}"})

    if "forwarded" in h:
        findings.append({"field": "Forwarded", "value": h["forwarded"], "risk": "CRITICAL",
            "note": "Proxy chain exposed — extract IP addresses for geolocation"})

    if "via" in h:
        findings.append({"field": "Via", "value": h["via"], "risk": "HIGH",
            "note": "Proxy/CDN infrastructure revealed — may expose upstream server or cloud provider"})

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
            "note": "Low technical sophistication — default config, likely self-hosted on residential connection"})

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
    hindi = bool(re.search(r"\b(?:bhai|yaar|kya|aur|nahi|hai|kar|karo|matlab|sahi|thik|wala|mera|tera|hoga|karna|chahiye|abhi|bahut|iska)\b", clean, re.I))
    russian = bool(re.search(r"\b(?:tovar|nakrutka|obnal|mule|drop|klad|zakupit|prodayom|kupit|prodat|tovar)\b", clean, re.I))
    spanish = bool(re.search(r"\b(?:que|como|para|esto|precio|comprar|vender|también|servicio|también)\b", clean, re.I))
    brit = bool(re.search(r"\b(?:colour|favour|honour|behaviour|realise|organisation|catalogue|centre|cheque|defence)\b", clean, re.I))
    amer = bool(re.search(r"\b(?:color|favor|honor|behavior|realize|organization|catalog|center|check|defense)\b", clean, re.I))
    if hindi:     lang = "Hindi/Hinglish — Indian subcontinent"
    elif russian: lang = "Russian — Eastern European"
    elif spanish: lang = "Spanish — Latin America / Spain"
    elif brit:    lang = "British English"
    elif amer:    lang = "American English"
    else:         lang = "Inconclusive"
    richness = "Very high — academic/professional" if ttr > 0.80 else "High — educated writer" if ttr > 0.65 else "Moderate — average writer" if ttr > 0.50 else "Low — limited vocabulary / translated"
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
    onion_links = [l for l in all_links if ".onion" in l["href"]]
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
            exchanges = ["binance", "kraken", "coinbase", "localbitcoin", "paxful", "okx", "huobi", "bybit", "gate", "bitfinex", "kucoin"]
            is_exchange = any(x in label.lower() for x in exchanges) if label else False
            return {
                "found": bool(label),
                "label": label,
                "wallet_id": d.get("wallet_id"),
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
                         headers={"User-Agent": "UMBRA-LEA/3.0"}, timeout=10)
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
        val = art.get("value", "").strip()

        if atype == "Telegram Handle":
            user = val.lstrip("@").split("/")[-1].strip()
            if user and len(user) >= 3 and user not in seen_users:
                seen_users.add(user)
                gh = search_github(user)
                if gh.get("found"):
                    gh["source_artifact"] = val
                    results["github"].append(gh)
                    if gh.get("pii_found"):
                        results["high_confidence_leads"].append({"type": "Username→GitHub PII", "artifact": val, "finding": f"GitHub: PII found: {gh['pii_found']}", "url": gh.get("profile_url"), "confidence": "HIGH"})
                rd = search_reddit(user)
                if rd.get("found"):
                    rd["source_artifact"] = val
                    results["reddit"].append(rd)
                    results["high_confidence_leads"].append({"type": "Username→Reddit Account", "artifact": val, "finding": f"Reddit: {rd['karma']} karma, since {str(rd.get('created_at',''))[:10]}", "url": rd.get("profile_url"), "confidence": "MEDIUM"})
                results["google_dorks"].append({"artifact": val, "type": "username", "queries": generate_dorks(user, "username")})
                time.sleep(0.5)

        elif atype == "Email Address" and val not in seen_emails:
            seen_emails.add(val)
            eu = val.split("@")[0]
            if len(eu) >= 3 and eu not in seen_users:
                seen_users.add(eu)
                gh = search_github(eu)
                if gh.get("found"):
                    gh["source_artifact"] = val
                    results["github"].append(gh)
                rd = search_reddit(eu)
                if rd.get("found"):
                    rd["source_artifact"] = val
                    results["reddit"].append(rd)
            pgp = search_pgp(val)
            if pgp.get("found"):
                pgp["source_artifact"] = val
                results["pgp_keyserver"].append(pgp)
                for k in pgp.get("keys", []):
                    if k.get("email_in_key"):
                        results["high_confidence_leads"].append({"type": "Email→PGP Real Identity", "artifact": val, "finding": f"PGP key contains email: {k['email_in_key']}", "confidence": "CRITICAL"})
            results["google_dorks"].append({"artifact": val, "type": "email", "queries": generate_dorks(val, "email")})
            time.sleep(0.4)

        elif atype == "PGP Key ID":
            pgp = search_pgp(val)
            if pgp.get("found"):
                pgp["source_artifact"] = val
                results["pgp_keyserver"].append(pgp)
                for k in pgp.get("keys", []):
                    if k.get("email_in_key"):
                        results["high_confidence_leads"].append({"type": "PGP Key→Real Email", "artifact": val, "finding": f"Key registered to: {k['email_in_key']}", "confidence": "CRITICAL"})
            time.sleep(0.3)

        elif "Bitcoin" in atype and val not in seen_btc:
            seen_btc.add(val)
            wl = query_wallet_label(val)
            results["wallet_labels"].append({"address": val, **wl})
            if wl.get("is_exchange"):
                results["high_confidence_leads"].append({"type": "BTC→Exchange Wallet", "artifact": val, "finding": f"Address is {wl.get('label')} — submit legal process for KYC identity", "confidence": "CRITICAL"})
            results["google_dorks"].append({"artifact": val, "type": "btc", "queries": generate_dorks(val, "btc")})
            time.sleep(0.4)

    return results

# ══════════════════════════════════════════════
# ENGINE 10: INFRASTRUCTURE FINGERPRINTING
# ══════════════════════════════════════════════
def fingerprint_infra(html: str, headers: dict, base_url: str = "", favicon_url: str = "") -> dict:
    analytics = {}
    ga_ua = list(set(re.findall(r"UA-\d{4,10}-\d{1,4}", html)))
    ga4 = list(set(re.findall(r"G-[A-Z0-9]{8,12}", html)))
    fb = list(set(re.findall(r"fbq\s*\(\s*[\"']init[\"']\s*,\s*[\"']?(\d{10,20})", html)))
    stripe = list(set(re.findall(r"pk_(?:live|test)_[a-zA-Z0-9]{20,60}", html)))
    s3 = list(set(re.findall(r"([a-z0-9.\-]+)\.s3(?:[\.-][a-z0-9-]+)?\.amazonaws\.com", html)))

    if ga_ua: analytics["google_analytics_ua"] = [{"id": x, "shodan": f'http.html:"{x}"', "dork": f'"{x}"', "note": "Search internet for same GA ID — links to operator clearnet site"} for x in ga_ua]
    if ga4:   analytics["google_analytics_4"]  = [{"id": x, "dork": f'"{x}"', "note": "GA4 property — search for sites using same property"} for x in ga4]
    if fb:    analytics["facebook_pixel"]       = [{"id": x, "fb_ads": f"https://www.facebook.com/ads/library/?q={x}", "note": "Facebook Pixel ID — may expose ad account"} for x in fb]
    if stripe:analytics["stripe_keys"]          = [{"key": k[:24]+"...", "type": "live" if "pk_live" in k else "test", "note": "Legal process to Stripe for merchant identity"} for k in stripe]
    if s3:    analytics["aws_s3_buckets"]        = [{"bucket": b, "url": f"https://{b}.s3.amazonaws.com/", "note": "Check for public file listing"} for b in s3]

    # Favicon hash
    favicon_result = {"found": False}
    if favicon_url:
        try:
            import mmh3
            import base64
            domain_match = re.match(r"(https?://[^/]+)", base_url)
            if favicon_url.startswith("http"):
                full_fav = favicon_url
            elif favicon_url.startswith("/") and domain_match:
                full_fav = domain_match.group(1) + favicon_url
            else:
                full_fav = base_url.rstrip("/") + "/" + favicon_url.lstrip("/")
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

    # JS fingerprinting
    scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I)
    ext_scripts = [s for s in scripts if s.startswith("http") and ".onion" not in s]
    libs = []
    for lib, pat in [("jQuery", r"jquery[/-]([\d.]+)"), ("Bootstrap", r"bootstrap[/-]([\d.]+)"), ("React", r"react[/-]([\d.]+)"), ("Vue.js", r"vue[/-]([\d.]+)")]:
        m = re.search(pat, html, re.I)
        if m:
            libs.append({"library": lib, "version": m.group(1)})
    script_fp = hashlib.sha256("|".join(sorted(scripts)).encode()).hexdigest()[:16]

    # CDN
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
        elif "IPv4" in t:           edge(root, node(v, "ip_address", {"source": "Page source"}, "CRITICAL"), "hosted_at", "CRITICAL")
        elif "Analytics" in t:      edge(root, node(v, "analytics_id", {}, "CRITICAL"), "tracked_by", "CRITICAL")
        elif "Clearnet" in t:
            d = re.sub(r"https?://", "", v).split("/")[0]
            if d and len(d) > 3:
                edge(root, node(d, "domain", {"url": v}, r), "links_to", "HIGH")
        elif "PGP" in t and "Block" not in t:
            edge(root, node(v, "pgp_key", {}, r), "signed_with", "MEDIUM")

    for h in headers_findings:
        if h.get("field") == "X-Forwarded-For":
            for ip in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", h.get("value", "")):
                n = node(ip, "ip_address", {"source": "X-Forwarded-For LEAK"}, "CRITICAL")
                edge(root, n, "real_ip_leak", "CRITICAL")
        elif h.get("field") == "Server":
            edge(root, node(h["value"], "server_software", {}, "HIGH"), "runs_on", "HIGH")

    for geo in ip_results:
        if geo.get("success"):
            ip_key = f"ip_address:{geo['ip']}"
            ip_n_id = nodes.get(ip_key, {}).get("id") or node(geo["ip"], "ip_address", {"source": geo.get("source", "")}, "CRITICAL")
            if geo.get("city") or geo.get("country"):
                loc = f"{geo.get('city', '?')}, {geo.get('region', '')}, {geo.get('country', '')}"
                loc_id = node(loc, "location", {"lat": geo.get("lat"), "lon": geo.get("lon"), "isp": geo.get("isp"), "maps": geo.get("google_maps_url")}, "HIGH")
                edge(ip_n_id, loc_id, "located_in", "HIGH")
            if geo.get("isp"):
                isp_id = node(geo["isp"], "isp", {"asn": geo.get("asn"), "is_vpn": geo.get("is_proxy"), "is_hosting": geo.get("is_hosting")}, "HIGH")
                edge(ip_n_id, isp_id, "belongs_to", "HIGH")

    for gh in correlation.get("github", []):
        if gh.get("found"):
            u = gh.get("username") or (gh.get("matches", [{}])[0].get("login") if gh.get("matches") else "")
            if u:
                gn = node(u, "github_profile", {"url": gh.get("profile_url", ""), "display_name": gh.get("display_name", ""), "location": gh.get("location", ""), "email": gh.get("email", "")}, "HIGH")
                src = gh.get("source_artifact", "")
                matched = False
                for k, nd in nodes.items():
                    if nd["label"] in src or src.lstrip("@") in nd["label"]:
                        edge(nd["id"], gn, "same_identity", "HIGH")
                        matched = True
                        break
                if not matched:
                    edge(root, gn, "same_identity", "HIGH")
                if gh.get("email"):
                    edge(gn, node(gh["email"], "email", {"source": "GitHub profile"}, "CRITICAL"), "registered_with", "CRITICAL")
                if gh.get("location"):
                    edge(gn, node(gh["location"], "location", {}, "HIGH"), "located_in", "HIGH")

    for rd in correlation.get("reddit", []):
        if rd.get("found"):
            rn = node(rd.get("username", ""), "reddit_profile", {"url": rd.get("profile_url", ""), "karma": rd.get("karma", 0), "created": rd.get("created_at", "")}, "MEDIUM")
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
                    edge(nd["id"], ln, "deposited_to", "CRITICAL")
                    break

    for cat, items in infra.get("analytics_ids", {}).items():
        for item in items:
            an = node(item.get("id", ""), "analytics_id", {"type": cat, "note": item.get("note", "")}, "CRITICAL")
            edge(root, an, "tracked_by", "CRITICAL")

    nlist = list(nodes.values())
    high_val = [e for e in edges if e.get("relation") in ("real_ip_leak", "registered_with", "same_identity", "deposited_to", "located_in")]

    return {
        "nodes": nlist, "edges": edges,
        "stats": {
            "total_nodes": len(nlist), "total_edges": len(edges),
            "critical_nodes": sum(1 for n in nlist if n["risk"] == "CRITICAL"),
            "node_types": list(set(n["type"] for n in nlist)),
        },
        "high_value_paths": high_val,
    }

# ══════════════════════════════════════════════
# ENGINE 12: CLAUDE OSINT BRIEF
# ══════════════════════════════════════════════
def claude_brief(url, page_intel, pii, headers, stylo, correlation, ip_results, api_key):
    if not api_key:
        return "No API key provided. Set ANTHROPIC_API_KEY env var or enter in UI."
    try:
        client = anthropic.Anthropic(api_key=api_key)
        geo_block = "\n".join(
            f"  IP: {g['ip']} → {g.get('city')}, {g.get('region')}, {g.get('country')} | "
            f"ISP: {g.get('isp')} | ASN: {g.get('asn')} | "
            f"VPN/Proxy: {g.get('is_proxy')} | Hosting/DC: {g.get('is_hosting')} | "
            f"Coords: {g.get('lat')},{g.get('lon')} | Source: {g.get('source')}"
            for g in ip_results if g.get("success")
        ) or "  No public IPs extracted"

        leads_block = json.dumps(correlation.get("high_confidence_leads", []), indent=2)
        stylo_block = json.dumps({k: v for k, v in (stylo or {}).items() if k not in ("top_function_words", "top_trigrams", "all_text_for_analysis")}, indent=2) if stylo else "Insufficient text"

        prompt = f"""You are a senior intelligence analyst for India's NIA (National Investigation Agency) and CERT-In. Analyze this dark web target comprehensively.

TARGET URL: {url}
TIMESTAMP: {datetime.utcnow().isoformat()} UTC

SITE INTELLIGENCE:
  Title: {page_intel.get('title', '')[:100]}
  Market Categories: {page_intel.get('category_signals', [])}
  Platform Detected: {page_intel.get('platform_signals', [])}
  Clearnet Links Found: {len(page_intel.get('clearnet_links', []))}

PII ARTIFACTS ({len(pii)} found):
{json.dumps(pii[:20], indent=2)}

HTTP HEADER INTELLIGENCE:
{json.dumps(headers, indent=2)}

IP GEOLOCATION INTELLIGENCE:
{geo_block}

IDENTITY CORRELATION LEADS:
{leads_block}

STYLOMETRIC ANALYSIS:
{stylo_block}

PAGE TEXT SAMPLE:
{page_intel.get('plain_text', '')[:1500]}

Provide a comprehensive NIA intelligence brief covering:

## 1. OPERATOR PROFILE
Estimated geographic location and ISP, technical skill level (1-10), language background with evidence, probable operating timezone and daily schedule from server timestamps, likely real-world occupation or background.

## 2. TOP 5 DE-ANONYMIZATION LEADS (Priority Order)
For each lead: exact step to take, which tool or service to use, expected intelligence outcome. Reference specific artifacts from the data above.

## 3. CRITICAL OPSEC FAILURES DETECTED
Every operational security mistake found. For each: what went wrong, exploitation method, severity rating.

## 4. SPECIFIC QUERIES TO RUN NOW (Copy-Paste Ready)
- Exact Shodan search queries with syntax
- WHOIS lookups with specific domains
- Blockchain explorer URLs
- Google dork queries
- Any crt.sh / CT log queries

## 5. IP & INFRASTRUCTURE ASSESSMENT
For each IP found: assess whether residential (direct ISP legal process) or hosting provider (abuse team request). VPN assessment. Hosting company identification.

## 6. LEGAL ACTION RECOMMENDATIONS (India LEA Framework)
Which platform/service to send legal process to. What specific records to request. Any mutual legal assistance treaty (MLAT) considerations for foreign providers.

## 7. THREAT CATEGORY ASSESSMENT
Nature and scale of illegal operation. Estimated operational capacity. Network connections.

## 8. OPSEC SOPHISTICATION RATING: X/10
Evidence-based justification for the rating.

Be precise, technical, and reference actual artifacts from the data. Every recommendation must be immediately actionable by an NIA analyst."""

        msg = client.messages.create(
            model="claude-opus-4-5",
            max_tokens=2500,
            messages=[{"role": "user", "content": prompt}]
        )
        return msg.content[0].text
    except Exception as e:
        return f"Claude API error: {e}"

# ══════════════════════════════════════════════
# API ENDPOINTS
# ══════════════════════════════════════════════
@app.get("/")
def root():
    return {"service": "UMBRA V3", "status": "online", "version": "3.0.0",
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

    html = fr["page_source"]
    headers_dict = fr["headers"]

    # 2. Page Intelligence
    log.info("[2/12] Extracting page intelligence...")
    pi = extract_page_intel(html, req.onion_url)
    report["page_intel"] = {k: v for k, v in pi.items() if k != "all_text_for_analysis"}

    # 3. PII Extraction
    log.info("[3/12] Running PII extraction (28 patterns)...")
    report["pii"] = extract_pii(html + " " + json.dumps(headers_dict))

    # 4. Header Analysis
    log.info("[4/12] Analyzing HTTP headers...")
    report["headers"] = analyze_headers(headers_dict)

    # 5. IP Geolocation + VPN Detection
    log.info("[5/12] Geolocating IPs + VPN detection...")
    report["ip_intelligence"] = geolocate_all_ips(report["pii"], report["headers"])

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
        html, headers_dict, req.onion_url, pi.get("favicon_url", "")
    )

    # 11. Attribution Graph
    log.info("[11/12] Building attribution graph...")
    report["attribution_graph"] = build_graph(
        req.onion_url, report["pii"], report["correlation"],
        report["infra_fingerprint"], report["headers"], report["ip_intelligence"]
    )

    # 12. Claude AI OSINT Brief
    log.info("[12/12] Generating Claude AI OSINT brief...")
    api_key = req.anthropic_api_key or os.environ.get("ANTHROPIC_API_KEY", "")
    report["ai_brief"] = claude_brief(
        req.onion_url, pi, report["pii"], report["headers"],
        report["stylometry"], report["correlation"], report["ip_intelligence"], api_key
    )

    stats = report["attribution_graph"]["stats"]
    log.info(f"[DONE] PII:{len(report['pii'])} IPs:{len(report['ip_intelligence'])} Leads:{len(report['correlation'].get('high_confidence_leads',[]))} Graph:{stats['total_nodes']} nodes/{stats['total_edges']} edges")
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

if __name__ == "__main__":
    import uvicorn
    print("\n" + "="*60)
    print("  UMBRA V3 — Dark Web Intelligence Platform")
    print("  NIA / Law Enforcement Use Only")
    print("="*60)
    print("\n  Requirements:")
    print("  1. Tor daemon at 127.0.0.1:9050")
    print("  2. ANTHROPIC_API_KEY environment variable")
    print("  3. All Python packages installed")
    print("\n  API: http://localhost:8000")
    print("  Docs: http://localhost:8000/docs\n")
    uvicorn.run("umbra_v3_backend:app", host="0.0.0.0", port=8000, reload=False)
