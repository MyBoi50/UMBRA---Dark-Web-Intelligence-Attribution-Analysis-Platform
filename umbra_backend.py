"""
UMBRA - Dark Web Intelligence Platform
Python FastAPI Backend — Law Enforcement Use Only

Requirements:
    pip install fastapi uvicorn requests[socks] stem anthropic httpx beautifulsoup4 lxml

Usage:
    1. Start Tor daemon (or Tor Browser — keep it open)
    2. python umbra_backend.py
    3. Open umbra_frontend in browser
    4. Paste any .onion URL and hit Analyze
"""

import re
import json
import time
import socket
import logging
import asyncio
import hashlib
from collections import Counter
from typing import Optional
from datetime import datetime

import requests
import httpx
from bs4 import BeautifulSoup
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
import anthropic

# ─────────────────────────────────────────────
#  CONFIG
# ─────────────────────────────────────────────
TOR_SOCKS5_PROXY  = "socks5h://127.0.0.1:9050"   # socks5h = resolve hostname through Tor (needed for .onion)
TOR_CONTROL_PORT  = 9051
ANTHROPIC_API_KEY = ""                             # Set via env var: export ANTHROPIC_API_KEY=sk-ant-...
REQUEST_TIMEOUT   = 30
USER_AGENT        = "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0"  # Tor Browser UA

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("umbra")

app = FastAPI(title="UMBRA Intelligence Platform", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─────────────────────────────────────────────
#  REQUEST MODELS
# ─────────────────────────────────────────────
class AnalyzeRequest(BaseModel):
    onion_url: str
    anthropic_api_key: Optional[str] = ""
    analyze_subpages: bool = False
    max_subpages: int = 3

class TextAnalyzeRequest(BaseModel):
    page_source: str
    raw_headers: str = ""
    clearnet_domain: str = ""
    btc_address: str = ""
    anthropic_api_key: Optional[str] = ""

# ─────────────────────────────────────────────
#  TOR FETCH ENGINE
# ─────────────────────────────────────────────
def tor_session() -> requests.Session:
    """Create a requests session routed through Tor SOCKS5."""
    s = requests.Session()
    s.proxies = {"http": TOR_SOCKS5_PROXY, "https": TOR_SOCKS5_PROXY}
    s.headers.update({"User-Agent": USER_AGENT})
    return s

def check_tor_running() -> dict:
    """Verify Tor SOCKS5 is reachable."""
    try:
        s = tor_session()
        r = s.get("http://check.torproject.org/api/ip", timeout=15)
        data = r.json()
        return {"running": True, "tor_ip": data.get("IP", "unknown"), "is_tor": data.get("IsTor", False)}
    except Exception as e:
        return {"running": False, "error": str(e)}

def fetch_onion(url: str) -> dict:
    """
    Fetch a .onion URL through Tor.
    Returns page source, headers, status code, redirect chain, timing.
    """
    if not url.startswith("http"):
        url = "http://" + url
    
    session = tor_session()
    start = time.time()
    
    try:
        log.info(f"Fetching via Tor: {url}")
        response = session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        elapsed = round(time.time() - start, 2)
        
        # Raw headers as dict and string
        headers_dict = dict(response.headers)
        headers_str = "\n".join(f"{k}: {v}" for k, v in response.headers.items())
        
        # Try to decode content
        content = ""
        try:
            content = response.text
        except Exception:
            content = response.content.decode("utf-8", errors="replace")
        
        # Follow redirect chain
        redirect_chain = [r.url for r in response.history] + [response.url]
        
        return {
            "success": True,
            "url": str(response.url),
            "status_code": response.status_code,
            "page_source": content,
            "headers": headers_dict,
            "headers_str": headers_str,
            "content_length": len(content),
            "redirect_chain": [str(u) for u in redirect_chain],
            "elapsed_seconds": elapsed,
            "server_fingerprint": headers_dict.get("Server", ""),
        }
    except requests.exceptions.ConnectTimeout:
        return {"success": False, "error": "Connection timed out. Site may be offline or Tor circuit is slow."}
    except requests.exceptions.ConnectionError as e:
        return {"success": False, "error": f"Connection failed: {str(e)}. Is Tor running? Check 127.0.0.1:9050"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def fetch_subpages(base_url: str, page_source: str, max_pages: int = 3) -> list:
    """Extract and fetch internal links to gather more intelligence."""
    soup = BeautifulSoup(page_source, "lxml")
    links = set()
    base_onion = re.match(r"(https?://[a-z2-7]{16,56}\.onion)", base_url)
    base = base_onion.group(1) if base_onion else ""
    
    for a in soup.find_all("a", href=True):
        href = a["href"]
        if href.startswith("/") and base:
            links.add(base + href)
        elif ".onion" in href:
            links.add(href if href.startswith("http") else "http://" + href)
    
    results = []
    for url in list(links)[:max_pages]:
        fetched = fetch_onion(url)
        if fetched["success"]:
            results.append({"url": url, "content": fetched["page_source"][:5000]})
        time.sleep(1)  # Be slow — avoid detection
    return results

# ─────────────────────────────────────────────
#  PII EXTRACTION ENGINE
# ─────────────────────────────────────────────
PII_PATTERNS = [
    ("Email Address",           r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b",                  "CRITICAL"),
    ("Bitcoin (Legacy P2PKH)",  r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b",                                    "CRITICAL"),
    ("Bitcoin (Bech32 SegWit)", r"\bbc1[a-z0-9]{39,59}\b",                                                  "CRITICAL"),
    ("Ethereum Address",        r"\b0x[a-fA-F0-9]{40}\b",                                                   "CRITICAL"),
    ("Monero Address",          r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b",                                    "CRITICAL"),
    ("Litecoin Address",        r"\b[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}\b",                                    "HIGH"),
    ("Zcash Address",           r"\bt1[a-zA-Z0-9]{33}\b",                                                   "HIGH"),
    ("Telegram Handle",         r"(?:t\.me/|telegram\.me/|@)([a-zA-Z][a-zA-Z0-9_]{4,31})\b",               "HIGH"),
    ("Telegram Group Link",     r"t\.me/[a-zA-Z0-9_+]+",                                                    "HIGH"),
    ("Onion v3 Address",        r"\b[a-z2-7]{56}\.onion\b",                                                 "HIGH"),
    ("Onion v2 Address",        r"\b[a-z2-7]{16}\.onion\b",                                                 "MEDIUM"),
    ("IPv4 Address",            r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b", "CRITICAL"),
    ("IPv6 Address",            r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b",                          "CRITICAL"),
    ("Phone (Indian)",          r"(?:\+91[-\s]?)?[6-9]\d{9}\b",                                            "HIGH"),
    ("Phone (International)",   r"\+[1-9]\d{7,14}\b",                                                      "HIGH"),
    ("Clearnet URL",            r"https?://(?!.*\.onion)[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+",          "CRITICAL"),
    ("PGP Key Block",           r"-----BEGIN PGP PUBLIC KEY BLOCK-----[\s\S]+?-----END PGP PUBLIC KEY BLOCK-----", "HIGH"),
    ("PGP Key ID",              r"\b(?:0x)?[A-F0-9]{8,16}\b",                                              "MEDIUM"),
    ("Wickr ID",                r"(?:wickr)[:\s#@]+([a-zA-Z0-9._\-]{3,40})\b",                             "HIGH"),
    ("Signal / Session ID",     r"(?:signal|session)[:\s#@]+([a-zA-Z0-9._\-]{3,60})\b",                    "HIGH"),
    ("Jabber / XMPP JID",       r"\b[a-z0-9._%+\-]+@(?:jabber|xmpp|conversations)\.[a-z]{2,}\b",          "HIGH"),
    ("SimpleX Link",            r"simplex\.chat/[a-zA-Z0-9/\-_#]+",                                        "HIGH"),
    ("I2P Address",             r"\b[a-zA-Z0-9\-]+\.i2p\b",                                                "MEDIUM"),
    ("Google Analytics ID",     r"\bUA-\d{4,10}-\d{1,4}\b|\bG-[A-Z0-9]{10}\b",                            "CRITICAL"),
    ("Facebook Pixel ID",       r"\bfbq\s*\(\s*['\"]init['\"],\s*['\"](\d{10,20})['\"]",                   "CRITICAL"),
    ("AWS S3 Bucket",           r"\b[a-z0-9.-]+\.s3(?:[\.-][a-z0-9-]+)?\.amazonaws\.com\b",               "CRITICAL"),
    ("Cloudflare Ray ID",       r"\bRay ID:\s*([a-f0-9]{16})\b",                                           "HIGH"),
]

def extract_pii(text: str) -> list:
    """Run all PII regex patterns over text. Returns deduplicated findings."""
    findings = []
    seen = set()
    for ptype, pattern, risk in PII_PATTERNS:
        for match in re.finditer(pattern, text, re.IGNORECASE | re.MULTILINE):
            value = match.group(0).strip()
            key = (ptype, value)
            if key not in seen and len(value) > 3:
                seen.add(key)
                # Filter out common false positives
                if ptype == "IPv4 Address" and value.startswith(("127.", "0.0.", "255.")):
                    continue
                findings.append({
                    "type": ptype,
                    "value": value,
                    "risk": risk,
                    "context": text[max(0, match.start()-40):match.end()+40].strip(),
                })
    return findings

# ─────────────────────────────────────────────
#  HEADER ANALYSIS ENGINE
# ─────────────────────────────────────────────
def analyze_headers(headers: dict) -> list:
    """Analyze HTTP headers for OPSEC failures and intelligence value."""
    findings = []
    h = {k.lower(): v for k, v in headers.items()}
    
    if "server" in h:
        findings.append({"field": "Server", "value": h["server"], "risk": "HIGH",
            "note": f"Software fingerprint. Search CVE database for '{h['server']}' vulnerabilities.",
            "action": f"shodan.io query: http.server:\"{h['server']}\""})
    
    if "x-powered-by" in h:
        findings.append({"field": "X-Powered-By", "value": h["x-powered-by"], "risk": "HIGH",
            "note": "Backend language/framework exposed. Reveals tech stack for exploit research."})
    
    if "date" in h:
        try:
            from email.utils import parsedate_to_datetime
            dt = parsedate_to_datetime(h["date"])
            findings.append({"field": "Date", "value": h["date"], "risk": "MEDIUM",
                "note": f"Server clock UTC offset detectable. Operator timezone narrowed. Day of week/time of posting patterns can identify work schedule.",
                "parsed_utc": dt.isoformat()})
        except Exception:
            findings.append({"field": "Date", "value": h["date"], "risk": "MEDIUM", "note": "Server timestamp"})
    
    if "x-forwarded-for" in h:
        ips = h["x-forwarded-for"]
        findings.append({"field": "X-Forwarded-For", "value": ips, "risk": "CRITICAL",
            "note": "REAL IP LEAK: Hidden service misconfigured as reverse proxy. The leftmost IP may be the operator's actual IP address.",
            "action": f"Immediately geolocate and query ISP for: {ips}"})
    
    if "via" in h:
        findings.append({"field": "Via", "value": h["via"], "risk": "CRITICAL",
            "note": "Proxy/CDN infrastructure revealed. May expose upstream IP or cloud provider."})
    
    if "x-generator" in h:
        findings.append({"field": "X-Generator", "value": h["x-generator"], "risk": "MEDIUM",
            "note": "CMS/framework fingerprint — search for known vulnerabilities in this version."})
    
    if "content-language" in h:
        findings.append({"field": "Content-Language", "value": h["content-language"], "risk": "MEDIUM",
            "note": f"Server configured with locale '{h['content-language']}' — corroborates operator geographic origin."})
    
    if "strict-transport-security" not in h and "x-frame-options" not in h and "content-security-policy" not in h:
        findings.append({"field": "Missing Security Headers", "value": "No HSTS/XFO/CSP", "risk": "LOW",
            "note": "No security hardening. Suggests low technical sophistication or default server config."})
    
    if "set-cookie" in h:
        cookie = h["set-cookie"]
        findings.append({"field": "Set-Cookie", "value": cookie[:200], "risk": "MEDIUM",
            "note": "Check for clearnet domain attributes, HttpOnly/Secure flags absent, or session token patterns."})
    
    if "x-runtime" in h:
        findings.append({"field": "X-Runtime", "value": h["x-runtime"], "risk": "LOW",
            "note": "Server processing time — can fingerprint backend load and framework."})
    
    if "last-modified" in h:
        findings.append({"field": "Last-Modified", "value": h["last-modified"], "risk": "MEDIUM",
            "note": "File modification timestamp — may reveal when site was last updated / operator's active hours."})
    
    if "etag" in h:
        findings.append({"field": "ETag", "value": h["etag"], "risk": "LOW",
            "note": "ETag may leak inode number (Apache) revealing filesystem structure on some old configs."})
    
    return findings

# ─────────────────────────────────────────────
#  STYLOMETRY ENGINE — real statistics
# ─────────────────────────────────────────────
FUNCTION_WORDS = [
    "the","be","to","of","and","a","in","that","have","it","for","not","on","with",
    "he","as","you","do","at","this","but","his","by","from","they","we","say","her",
    "she","or","an","will","my","one","all","would","there","their","what","so","if",
    "about","who","which","go","me","when","make","can","time","no","just","know","take",
    "into","your","some","could","them","see","than","then","now","look","only","come",
    "over","think","also","back","after","use","how","our","work","first","well","even",
    "new","want","because","any","these","give","most","us",
]

def analyze_stylometry(text: str) -> Optional[dict]:
    """
    Real stylometric analysis. Computes features used in academic authorship attribution.
    Based on Burrows' Delta, JGAAP, and stylo (R package) methodologies.
    """
    # Strip HTML
    clean = re.sub(r"<[^>]+>", " ", text)
    clean = re.sub(r"\s+", " ", clean).strip()
    
    if len(clean) < 100:
        return None
    
    sentences = re.split(r"[.!?]+", clean)
    sentences = [s.strip() for s in sentences if len(s.strip()) > 10]
    words_raw = re.findall(r"\b[a-z']{2,}\b", clean.lower())
    chars_alpha = re.sub(r"[^a-zA-Z]", "", clean)
    
    if not words_raw:
        return None
    
    word_freq = Counter(words_raw)
    unique_words = set(words_raw)
    
    # === Core metrics ===
    ttr = len(unique_words) / len(words_raw)  # Type-Token Ratio
    avg_sent_len = len(words_raw) / max(len(sentences), 1)
    avg_word_len = sum(len(w) for w in words_raw) / len(words_raw)
    
    # Hapax Legomena — words appearing exactly once
    hapax = sum(1 for f in word_freq.values() if f == 1)
    hapax_ratio = hapax / len(unique_words) if unique_words else 0
    
    # Dis Legomena — words appearing exactly twice
    dis_legomena = sum(1 for f in word_freq.values() if f == 2)
    
    # Yule's K (vocabulary richness, independent of text length)
    m1 = len(words_raw)
    m2 = sum(f * f for f in word_freq.values())
    yules_k = 10000 * (m2 - m1) / (m1 * m1) if m1 > 0 else 0
    
    # Honore's R statistic
    v1 = hapax
    v = len(unique_words)
    n = len(words_raw)
    honores_r = (100 * (v1 / (1 - v1/v))) / n if (v > 0 and v1 != v and n > 0) else 0
    
    # === Function word frequency (Burrows' Delta basis) ===
    func_word_profile = {}
    for w in FUNCTION_WORDS:
        func_word_profile[w] = round(word_freq.get(w, 0) / len(words_raw) * 1000, 3)
    top_func = sorted(func_word_profile.items(), key=lambda x: x[1], reverse=True)[:15]
    
    # === Character n-grams ===
    trigrams = Counter()
    for i in range(len(chars_alpha) - 2):
        tg = chars_alpha[i:i+3].lower()
        if re.match(r"^[a-z]{3}$", tg):
            trigrams[tg] += 1
    top_trigrams = trigrams.most_common(10)
    
    # === Punctuation profile ===
    punct = {
        "commas":          len(re.findall(r",", clean)),
        "exclamations":    len(re.findall(r"!", clean)),
        "questions":       len(re.findall(r"\?", clean)),
        "ellipsis":        len(re.findall(r"\.\.\.", clean)),
        "semicolons":      len(re.findall(r";", clean)),
        "dashes":          len(re.findall(r"--|-—", clean)),
        "all_caps_words":  len(re.findall(r"\b[A-Z]{3,}\b", clean)),
    }
    
    # === Language pattern detection ===
    hindi_romanized  = bool(re.search(r"\b(?:bhai|yaar|kya|aur|nahi|hai|kar|karo|matlab|sahi|thik|wala|mera|tera|unka|hoga|karna|chahiye)\b", clean, re.I))
    russian_patterns = bool(re.search(r"\b(?:tovar|nakrutka|obnal|mule|drop|otmyvanie|klad|zakupit|prodayom|tovar)\b", clean, re.I))
    brit_spelling    = bool(re.search(r"\b(?:colour|favour|honour|behaviour|realise|organisation|catalogue|centre|cheque|defence|practise)\b", clean, re.I))
    amer_spelling    = bool(re.search(r"\b(?:color|favor|honor|behavior|realize|organization|catalog|center|check|defense|practice)\b", clean, re.I))
    spanish_patterns = bool(re.search(r"\b(?:que|como|para|esto|también|también|precio|comprar|vender)\b", clean, re.I))
    
    # Native speaker confidence
    if hindi_romanized:   likely_lang = "Hindi/Hinglish (Indian subcontinent)"
    elif russian_patterns:  likely_lang = "Russian (Eastern European)"
    elif spanish_patterns:  likely_lang = "Spanish (Latin America / Spain)"
    elif brit_spelling:     likely_lang = "British English"
    elif amer_spelling:     likely_lang = "American English"
    else:                   likely_lang = "Inconclusive"
    
    # === Vocabulary richness interpretation ===
    if ttr > 0.80:      richness = "Very high — academic/professional writer"
    elif ttr > 0.65:    richness = "High — educated writer"
    elif ttr > 0.50:    richness = "Moderate — average writer"
    else:               richness = "Low — limited vocabulary / translated text"
    
    return {
        "word_count": len(words_raw),
        "unique_words": len(unique_words),
        "sentence_count": len(sentences),
        "char_count": len(chars_alpha),
        "ttr": round(ttr, 4),
        "avg_sentence_length": round(avg_sent_len, 2),
        "avg_word_length": round(avg_word_len, 2),
        "hapax_legomena": hapax,
        "hapax_ratio": round(hapax_ratio, 4),
        "dis_legomena": dis_legomena,
        "yules_k": round(yules_k, 2),
        "honores_r": round(honores_r, 2),
        "vocabulary_richness": richness,
        "top_function_words": top_func,
        "top_trigrams": top_trigrams,
        "punctuation": punct,
        "language": {
            "hindi_romanized": hindi_romanized,
            "russian_patterns": russian_patterns,
            "british_spelling": brit_spelling,
            "american_spelling": amer_spelling,
            "spanish_patterns": spanish_patterns,
            "likely_native_language": likely_lang,
        },
        "cross_match_note": "Export top_function_words + top_trigrams into JGAAP or stylo (R package) to compare against clearnet writing samples from forums, Reddit, Dread.",
    }

# ─────────────────────────────────────────────
#  PAGE INTELLIGENCE EXTRACTION
# ─────────────────────────────────────────────
def extract_page_intel(html: str, url: str) -> dict:
    """Extract structured intelligence from HTML page source."""
    soup = BeautifulSoup(html, "lxml")
    
    # Remove script/style for text analysis
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()
    
    plain_text = soup.get_text(separator=" ", strip=True)
    
    # All scripts (JS analysis)
    scripts = [s.string for s in soup.find_all("script") if s.string]
    all_scripts = " ".join(scripts)
    
    # All external links
    all_links = []
    for a in soup.find_all("a", href=True):
        href = a.get("href", "")
        text = a.get_text(strip=True)[:100]
        all_links.append({"href": href, "text": text})
    
    clearnet_links = [l for l in all_links if "http" in l["href"] and ".onion" not in l["href"]]
    onion_links = [l for l in all_links if ".onion" in l["href"]]
    
    # Meta tags
    meta = {}
    for m in soup.find_all("meta"):
        name = m.get("name") or m.get("property") or m.get("http-equiv", "")
        content = m.get("content", "")
        if name and content:
            meta[name] = content
    
    # Title
    title = soup.find("title")
    title_text = title.get_text(strip=True) if title else ""
    
    # Favicon hash (for Shodan favicon search)
    favicon_url = ""
    for link in soup.find_all("link"):
        rel = link.get("rel", [])
        if "icon" in rel or "shortcut" in rel:
            favicon_url = link.get("href", "")
            break
    
    # Detect common platforms
    platform_signals = []
    html_lower = html.lower()
    if "wordpress" in html_lower or "wp-content" in html_lower:
        platform_signals.append("WordPress")
    if "drupal" in html_lower:
        platform_signals.append("Drupal")
    if "joomla" in html_lower:
        platform_signals.append("Joomla")
    if "flask" in html_lower or "werkzeug" in html_lower:
        platform_signals.append("Flask (Python)")
    if "django" in html_lower:
        platform_signals.append("Django (Python)")
    if "laravel" in html_lower or "php artisan" in html_lower:
        platform_signals.append("Laravel (PHP)")
    if "express" in html_lower and "node" in html_lower:
        platform_signals.append("Express.js (Node)")
    if "opencart" in html_lower:
        platform_signals.append("OpenCart")
    if "woocommerce" in html_lower:
        platform_signals.append("WooCommerce")
    
    # Detect market category signals
    category_signals = []
    if re.search(r"\b(?:drug|narcotic|cocaine|heroin|meth|fentanyl|mdma|weed|cannabis|pills)\b", html_lower):
        category_signals.append("Narcotics Market")
    if re.search(r"\b(?:weapon|gun|rifle|pistol|ammo|firearm|explosive)\b", html_lower):
        category_signals.append("Weapons Market")
    if re.search(r"\b(?:carding|cvv|dumps|fullz|credit card|bank log|cc)\b", html_lower):
        category_signals.append("Financial Fraud / Carding")
    if re.search(r"\b(?:passport|id card|driver.?s license|fake id|counterfeit)\b", html_lower):
        category_signals.append("Counterfeit Documents")
    if re.search(r"\b(?:data breach|database leak|hacked|dox|credentials|combo list)\b", html_lower):
        category_signals.append("Data Leaks / Breaches")
    if re.search(r"\b(?:hitman|assassination|murder for hire)\b", html_lower):
        category_signals.append("Violence for Hire")
    if re.search(r"\b(?:ransomware|malware|rat|exploit|0day|botnet)\b", html_lower):
        category_signals.append("Cybercrime / Malware")
    
    # JS analytics / tracking IDs in scripts
    analytics_ids = re.findall(r"UA-\d{4,10}-\d{1,4}|G-[A-Z0-9]{10}", all_scripts)
    
    return {
        "title": title_text,
        "plain_text": plain_text[:5000],
        "all_text_for_analysis": plain_text,
        "clearnet_links": clearnet_links[:20],
        "onion_links": onion_links[:20],
        "all_links_count": len(all_links),
        "meta_tags": meta,
        "platform_signals": platform_signals,
        "category_signals": category_signals,
        "analytics_ids": analytics_ids,
        "favicon_url": favicon_url,
        "has_js": len(scripts) > 0,
        "js_external_srcs": [s.get("src", "") for s in soup.find_all("script") if s.get("src") and ".onion" not in s.get("src", "")],
    }

# ─────────────────────────────────────────────
#  CERTIFICATE TRANSPARENCY — live crt.sh
# ─────────────────────────────────────────────
def query_cert_transparency(domain: str) -> dict:
    """Query crt.sh for SSL certificate history — via clearnet (not Tor)."""
    clean = re.sub(r"^https?://", "", domain).split("/")[0].strip()
    if not clean or ".onion" in clean:
        return {"error": ".onion addresses are not in CT logs. Provide a clearnet domain from the page source."}
    try:
        r = requests.get(f"https://crt.sh/?q={clean}&output=json", timeout=15)
        if r.status_code != 200:
            return {"error": f"crt.sh returned HTTP {r.status_code}"}
        data = r.json()
        seen = set()
        unique = []
        for cert in data:
            key = f"{cert.get('common_name')}_{cert.get('issuer_name')}"
            if key not in seen:
                seen.add(key)
                unique.append({
                    "id": cert.get("id"),
                    "common_name": cert.get("common_name"),
                    "issuer": cert.get("issuer_name"),
                    "not_before": cert.get("not_before"),
                    "not_after": cert.get("not_after"),
                    "san_domains": cert.get("name_value", "").split("\n"),
                })
        # Extract unique domains from SANs
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
            "first_seen": min((c.get("not_before","") for c in data), default=""),
            "investigation_note": f"Query Shodan for: ssl.cert.subject.cn:{clean} to find hosting IPs. Query WHOIS for all SAN domains.",
        }
    except Exception as e:
        return {"error": str(e)}

# ─────────────────────────────────────────────
#  BLOCKCHAIN FORENSICS — live Blockchair
# ─────────────────────────────────────────────
def query_bitcoin_address(address: str) -> dict:
    """Query Blockchair for real Bitcoin address data."""
    if not address or len(address) < 25:
        return {"error": "Invalid Bitcoin address"}
    try:
        r = requests.get(f"https://blockchair.com/bitcoin/dashboards/address/{address}", timeout=15)
        if r.status_code != 200:
            return {"error": f"Blockchair HTTP {r.status_code} — may be rate limited. Try: https://www.blockchain.com/explorer/addresses/btc/{address}"}
        data = r.json()
        addr = data.get("data", {}).get(address, {}).get("address", {})
        if not addr:
            return {"error": "Address data unavailable. Try manually: https://oxt.me/address/" + address}
        txs = data.get("data", {}).get(address, {}).get("transactions", [])
        return {
            "address": address,
            "balance_btc": addr.get("balance", 0) / 1e8,
            "total_received_btc": addr.get("received", 0) / 1e8,
            "total_spent_btc": addr.get("spent", 0) / 1e8,
            "transaction_count": addr.get("transaction_count", 0),
            "first_seen": addr.get("first_seen_receiving"),
            "last_seen": addr.get("last_seen_spending"),
            "unspent_outputs": addr.get("unspent_output_count", 0),
            "recent_txids": txs[:5],
            "investigation_links": {
                "oxt_cluster": f"https://oxt.me/address/{address}",
                "blockchair": f"https://blockchair.com/bitcoin/address/{address}",
                "blockchain_com": f"https://www.blockchain.com/explorer/addresses/btc/{address}",
            },
            "investigation_note": "Submit to Chainalysis Reactor or Elliptic for full cluster analysis. Check OXT.me for UTXO clustering and exchange deposit identification.",
        }
    except Exception as e:
        return {"error": str(e)}

# ─────────────────────────────────────────────
#  CLAUDE AI OSINT ANALYSIS
# ─────────────────────────────────────────────
def run_claude_osint(
    url: str,
    page_intel: dict,
    pii_findings: list,
    header_findings: list,
    stylo: Optional[dict],
    api_key: str,
) -> str:
    """Send all extracted intelligence to Claude for actionable OSINT brief."""
    if not api_key:
        return "No Anthropic API key provided. Set it in the frontend or via ANTHROPIC_API_KEY env var."
    
    try:
        client = anthropic.Anthropic(api_key=api_key)
        
        prompt = f"""You are a senior dark web intelligence analyst for a Law Enforcement Agency (LEA). 
You have just completed automated analysis of a TOR hidden service (.onion site). 
Produce a structured, actionable intelligence brief.

TARGET: {url}
MARKET CATEGORIES DETECTED: {page_intel.get('category_signals', [])}
PLATFORM DETECTED: {page_intel.get('platform_signals', [])}
SITE TITLE: {page_intel.get('title', '')}

--- EXTRACTED PII ARTIFACTS ({len(pii_findings)} found) ---
{json.dumps(pii_findings[:25], indent=2)}

--- HTTP HEADER INTELLIGENCE ---
{json.dumps(header_findings, indent=2)}

--- STYLOMETRIC PROFILE ---
{json.dumps(stylo, indent=2) if stylo else "Insufficient text for analysis"}

--- CLEARNET LINKS FOUND IN SOURCE ---
{json.dumps(page_intel.get('clearnet_links', [])[:10], indent=2)}

--- EXTERNAL JS SOURCES ---
{json.dumps(page_intel.get('js_external_srcs', [])[:5], indent=2)}

--- PAGE TEXT SAMPLE ---
{page_intel.get('plain_text', '')[:1500]}

Provide the following in your brief:

## 1. OPERATOR PROFILE
Based on all signals: estimated location, technical skill level (1-10), language background, probable operating hours (from server timestamps), likely real-world occupation or background.

## 2. TOP 5 DE-ANONYMIZATION LEADS
List the 5 most actionable paths to identifying the real operator. For each: what to do, which tool/service to use, expected outcome. Reference specific artifacts from the data above.

## 3. CRITICAL OPSEC FAILURES
List every operational security mistake detected. For each: what they did wrong, how to exploit it, severity.

## 4. SPECIFIC INVESTIGATIVE QUERIES TO RUN NOW
Provide exact, copy-paste ready queries for:
- Shodan search queries
- WHOIS lookups
- Blockchain explorer searches  
- Google/forum searches
- Any other specific database queries

## 5. INFRASTRUCTURE ASSESSMENT
Real hosting IP likelihood, ISP/ASN identification path, VPN/hosting provider identification.

## 6. OPSEC SOPHISTICATION RATING
Rate 1-10. Justify with specific evidence from the data.

Be specific, technical, and reference actual artifacts from the extracted data. Every recommendation must be directly actionable."""

        message = client.messages.create(
            model="claude-opus-4-5",
            max_tokens=2000,
            messages=[{"role": "user", "content": prompt}]
        )
        return message.content[0].text
    except Exception as e:
        return f"Claude API error: {str(e)}"

# ─────────────────────────────────────────────
#  API ENDPOINTS
# ─────────────────────────────────────────────

@app.get("/")
def root():
    return {"service": "UMBRA Intelligence Platform", "status": "online", "endpoints": ["/api/tor/check", "/api/analyze", "/api/analyze/text", "/api/pii", "/api/ct/{domain}", "/api/btc/{address}"]}

@app.get("/api/tor/check")
def tor_check():
    """Check if Tor is running and connected."""
    result = check_tor_running()
    return result

@app.post("/api/analyze")
def analyze_onion(req: AnalyzeRequest):
    """
    MAIN ENDPOINT: Fetch .onion URL via Tor, run all analysis, return full intelligence report.
    """
    log.info(f"New analysis request: {req.onion_url}")
    report = {
        "target_url": req.onion_url,
        "timestamp": datetime.utcnow().isoformat(),
        "fetch": None,
        "page_intel": None,
        "pii": [],
        "headers": [],
        "stylometry": None,
        "cert_transparency": None,
        "blockchain": [],
        "ai_brief": "",
        "subpages": [],
        "errors": [],
    }
    
    # STEP 1: Fetch via Tor
    log.info("Step 1: Fetching via Tor...")
    fetch_result = fetch_onion(req.onion_url)
    report["fetch"] = {
        "success": fetch_result.get("success"),
        "status_code": fetch_result.get("status_code"),
        "url": fetch_result.get("url"),
        "content_length": fetch_result.get("content_length"),
        "elapsed_seconds": fetch_result.get("elapsed_seconds"),
        "redirect_chain": fetch_result.get("redirect_chain", []),
        "server": fetch_result.get("server_fingerprint"),
    }
    
    if not fetch_result.get("success"):
        report["errors"].append(f"Fetch failed: {fetch_result.get('error')}")
        return report
    
    html = fetch_result["page_source"]
    headers_dict = fetch_result["headers"]
    
    # STEP 2: Extract page intelligence
    log.info("Step 2: Extracting page intelligence...")
    page_intel = extract_page_intel(html, req.onion_url)
    report["page_intel"] = {k: v for k, v in page_intel.items() if k != "all_text_for_analysis"}
    
    # STEP 3: PII extraction
    log.info("Step 3: Running PII extraction...")
    all_text = html + " " + json.dumps(headers_dict)
    report["pii"] = extract_pii(all_text)
    
    # STEP 4: Header analysis
    log.info("Step 4: Analyzing headers...")
    report["headers"] = analyze_headers(headers_dict)
    
    # STEP 5: Stylometry
    log.info("Step 5: Running stylometric analysis...")
    report["stylometry"] = analyze_stylometry(page_intel["all_text_for_analysis"])
    
    # STEP 6: Cert Transparency (for any clearnet domains found)
    log.info("Step 6: Certificate Transparency lookup...")
    clearnet_domains = []
    for link in page_intel.get("clearnet_links", []):
        m = re.search(r"https?://([a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})", link.get("href", ""))
        if m:
            clearnet_domains.append(m.group(1))
    clearnet_domains = list(set(clearnet_domains))[:3]
    
    if clearnet_domains:
        ct_results = []
        for domain in clearnet_domains:
            ct = query_cert_transparency(domain)
            ct_results.append({"domain": domain, "result": ct})
        report["cert_transparency"] = ct_results
    
    # STEP 7: Blockchain (for all BTC addresses found)
    log.info("Step 7: Blockchain forensics...")
    btc_addresses = [p["value"] for p in report["pii"] if "Bitcoin" in p["type"]][:3]
    blockchain_results = []
    for addr in btc_addresses:
        btc_data = query_bitcoin_address(addr)
        blockchain_results.append({"address": addr, "result": btc_data})
        time.sleep(0.5)
    report["blockchain"] = blockchain_results
    
    # STEP 8: Subpages (optional)
    if req.analyze_subpages:
        log.info("Step 8: Fetching subpages...")
        report["subpages"] = fetch_subpages(req.onion_url, html, req.max_subpages)
    
    # STEP 9: Claude AI OSINT brief
    log.info("Step 9: Running Claude OSINT analysis...")
    api_key = req.anthropic_api_key or ANTHROPIC_API_KEY
    report["ai_brief"] = run_claude_osint(
        req.onion_url, page_intel,
        report["pii"], report["headers"],
        report["stylometry"], api_key
    )
    
    log.info(f"Analysis complete. PII: {len(report['pii'])} artifacts. Headers: {len(report['headers'])} findings.")
    return report

@app.post("/api/analyze/text")
def analyze_text(req: TextAnalyzeRequest):
    """Analyze already-fetched text (paste mode — for offline/manual use)."""
    page_intel = extract_page_intel(req.page_source, "")
    pii = extract_pii(req.page_source + " " + req.raw_headers)
    
    headers_dict = {}
    header_findings = []
    if req.raw_headers.strip():
        for line in req.raw_headers.split("\n"):
            idx = line.find(":")
            if idx > 0:
                headers_dict[line[:idx].strip().lower()] = line[idx+1:].strip()
        header_findings = analyze_headers(headers_dict)
    
    stylo = analyze_stylometry(page_intel["all_text_for_analysis"])
    ct = query_cert_transparency(req.clearnet_domain) if req.clearnet_domain else None
    
    btc_addresses = [p["value"] for p in pii if "Bitcoin" in p["type"]][:2]
    btc_target = req.btc_address.strip() or (btc_addresses[0] if btc_addresses else None)
    btc_result = query_bitcoin_address(btc_target) if btc_target else None
    
    api_key = req.anthropic_api_key or ANTHROPIC_API_KEY
    ai_brief = run_claude_osint("manual-input", page_intel, pii, header_findings, stylo, api_key)
    
    return {
        "page_intel": {k: v for k, v in page_intel.items() if k != "all_text_for_analysis"},
        "pii": pii,
        "headers": header_findings,
        "stylometry": stylo,
        "cert_transparency": ct,
        "blockchain": [{"address": btc_target, "result": btc_result}] if btc_result else [],
        "ai_brief": ai_brief,
    }

@app.get("/api/pii")
def pii_quick(text: str):
    """Quick PII extraction — GET endpoint for testing."""
    return {"findings": extract_pii(text)}

@app.get("/api/ct/{domain}")
def cert_transparency(domain: str):
    """Certificate Transparency lookup for a domain."""
    return query_cert_transparency(domain)

@app.get("/api/btc/{address}")
def btc_lookup(address: str):
    """Bitcoin address blockchain lookup."""
    return query_bitcoin_address(address)

@app.get("/api/tor/newcircuit")
def new_tor_circuit():
    """Request a new Tor circuit (requires Tor control port access)."""
    try:
        from stem import Signal
        from stem.control import Controller
        with Controller.from_port(port=TOR_CONTROL_PORT) as controller:
            controller.authenticate()
            controller.signal(Signal.NEWNYM)
            return {"success": True, "message": "New Tor circuit requested"}
    except ImportError:
        return {"success": False, "error": "stem library not installed: pip install stem"}
    except Exception as e:
        return {"success": False, "error": str(e), "note": "Ensure Tor ControlPort 9051 is enabled in torrc and HashedControlPassword is set"}

if __name__ == "__main__":
    import uvicorn
    print("\n" + "="*60)
    print("  UMBRA Dark Web Intelligence Platform")
    print("  Backend API — Law Enforcement Use Only")
    print("="*60)
    print("\n  Prerequisites:")
    print("  1. Tor must be running (Tor Browser OR 'tor' daemon)")
    print("  2. SOCKS5 proxy at 127.0.0.1:9050")
    print("  3. Set ANTHROPIC_API_KEY env var for AI briefs")
    print("\n  Starting server at http://localhost:8000")
    print("  API docs at http://localhost:8000/docs\n")
    uvicorn.run("umbra_backend:app", host="0.0.0.0", port=8000, reload=False)
