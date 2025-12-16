import os
import re
import json
import time
import hashlib
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


WAYBACK_CDX = "https://web.archive.org/cdx/search/cdx"
WAYBACK_WEB = "https://web.archive.org/web"

SUSPICIOUS_PATTERNS = {
    "emails": re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"),
    "php_mail_call": re.compile(r"\bmail\s*\(", re.IGNORECASE),
    "form_action": re.compile(r"<form[^>]+action\s*=\s*['\"]([^'\"]+)['\"]", re.IGNORECASE),
    "hidden_input": re.compile(r"<input[^>]+type\s*=\s*['\"]hidden['\"][^>]*>", re.IGNORECASE),
    "external_http": re.compile(r"https?://[A-Za-z0-9\.\-]+(?:\:[0-9]+)?/[^\s\"']*", re.IGNORECASE),
    "js_redirect": re.compile(r"(location\.href|window\.location|document\.location)\s*=", re.IGNORECASE),
    "paypal_branding": re.compile(r"paypal", re.IGNORECASE),
    "credential_fields": re.compile(r"(password|passcode|card\s*number|cvv|ssn)", re.IGNORECASE),
}

DEFAULT_CONFIG = {

    "url_pattern": "ebay-verification.com/*",

    # Диапазон дат для поиска в архиве
    "year_from": 2003,
    "year_to": 2012,

    # Лимит строк CDX (увеличивай при необходимости)
    "cdx_limit": 2000,

    # Задержка между скачиваниями (важно, чтобы не словить ограничения)
    "sleep_seconds": 1.2,

    # Куда сохранять
    "out_dir": "wayback_dump",
}


def make_session() -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "User-Agent": "Mozilla/5.0 (OSINT-research; Wayback analysis script)"
    })
    retries = Retry(
        total=8,
        backoff_factor=1.5,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "HEAD"]
    )
    adapter = HTTPAdapter(max_retries=retries, pool_connections=10, pool_maxsize=10)
    s.mount("https://", adapter)
    return s


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safe_filename(url: str, ts: str) -> str:
    parsed = urlparse(url)
    host = parsed.netloc.replace(":", "_")
    path = parsed.path.strip("/").replace("/", "_") or "root"
    if parsed.query:
        q = re.sub(r"[^A-Za-z0-9._-]+", "_", parsed.query)[:80]
        path = f"{path}__q_{q}"
    return f"{ts}__{host}__{path}.html"


def cdx_query(session: requests.Session,
              url_pattern: str,
              year_from: int,
              year_to: int,
              limit: int) -> list[dict]:
    params = {
        "url": url_pattern,
        "from": f"{year_from}0101",
        "to": f"{year_to}1231",
        "output": "json",
        "fl": "timestamp,original,mimetype,statuscode,digest,length",
        "collapse": "urlkey",
        "filter": "statuscode:200",
        "limit": str(limit),
    }

    r = session.get(WAYBACK_CDX, params=params, timeout=30)
    r.raise_for_status()
    data = r.json()
    if not data or len(data) < 2:
        return []

    header = data[0]
    rows = data[1:]
    return [dict(zip(header, row)) for row in rows]


def is_probably_php_url(url: str) -> bool:
    return urlparse(url).path.lower().endswith((".php", ".phtml", ".asp", ".aspx", ".cgi"))


def is_html_like(mimetype: str) -> bool:
    mt = (mimetype or "").lower()
    return ("text/html" in mt) or ("application/xhtml" in mt) or (mt == "")


def download_capture(session: requests.Session, ts: str, url: str) -> tuple[int, bytes]:
    capture_url = f"{WAYBACK_WEB}/{ts}id_/{url}"
    r = session.get(capture_url, timeout=60)
    return r.status_code, r.content


def analyze_content(url: str, ts: str, content: bytes) -> dict:
    try:
        text = content.decode("utf-8", errors="replace")
    except Exception:
        text = str(content[:2000])

    findings: dict = {}

    emails = sorted(set(SUSPICIOUS_PATTERNS["emails"].findall(text)))
    if emails:
        findings["emails"] = emails[:50]

    if SUSPICIOUS_PATTERNS["php_mail_call"].search(text):
        findings["php_mail_call"] = True

    actions = SUSPICIOUS_PATTERNS["form_action"].findall(text)
    if actions:
        findings["form_actions"] = actions[:30]

    hidden_count = len(SUSPICIOUS_PATTERNS["hidden_input"].findall(text))
    if hidden_count:
        findings["hidden_inputs_count"] = hidden_count

    ext_urls = sorted(set(SUSPICIOUS_PATTERNS["external_http"].findall(text)))
    if ext_urls:
        findings["external_urls"] = ext_urls[:50]

    if SUSPICIOUS_PATTERNS["js_redirect"].search(text):
        findings["js_redirect_like"] = True

    if SUSPICIOUS_PATTERNS["credential_fields"].search(text):
        findings["credential_like_fields"] = True

    if SUSPICIOUS_PATTERNS["paypal_branding"].search(text):
        findings["mentions_paypal"] = True

    findings["sha256"] = sha256_bytes(content)
    findings["bytes"] = len(content)
    findings["timestamp"] = ts
    findings["url"] = url
    return findings


def score_findings(f: dict) -> int:
    score = 0
    score += 2 if f.get("mentions_paypal") else 0
    score += 2 if f.get("credential_like_fields") else 0
    score += 2 if f.get("php_mail_call") else 0
    score += 1 if f.get("emails") else 0
    score += 1 if f.get("form_actions") else 0
    score += 1 if f.get("external_urls") else 0
    score += 1 if f.get("hidden_inputs_count", 0) >= 3 else 0
    score += 1 if f.get("js_redirect_like") else 0
    return score


def load_config() -> dict:
    """
    Если рядом с запуском есть config.json — берём его, иначе DEFAULT_CONFIG.
    """
    cfg_path = os.path.join(os.getcwd(), "config.json")
    if os.path.exists(cfg_path):
        with open(cfg_path, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        merged = DEFAULT_CONFIG.copy()
        merged.update(cfg)
        return merged
    return DEFAULT_CONFIG.copy()


def main():
    cfg = load_config()

    url_pattern = cfg["url_pattern"]
    year_from = int(cfg["year_from"])
    year_to = int(cfg["year_to"])
    limit = int(cfg["cdx_limit"])
    sleep_seconds = float(cfg["sleep_seconds"])
    out_dir = cfg["out_dir"]

    os.makedirs(out_dir, exist_ok=True)

    session = make_session()

    print(f"[+] CDX query: {url_pattern}")
    records = cdx_query(session, url_pattern, year_from, year_to, limit)

    if not records:
        print("[-] No records found. Try changing url_pattern or year range.")
        return

    filtered = []
    for rec in records:
        url = rec["original"]
        mt = rec.get("mimetype", "")
        if is_html_like(mt) or is_probably_php_url(url):
            filtered.append(rec)

    print(f"[+] Total records: {len(records)} | HTML/PHP-like: {len(filtered)}")

    findings_all = []
    downloaded = 0

    for rec in filtered:
        ts = rec["timestamp"]
        url = rec["original"]

        time.sleep(sleep_seconds)

        try:
            status, content = download_capture(session, ts, url)
        except requests.RequestException as e:
            print(f"[!] Download failed ts={ts} url={url} err={e}")
            continue

        if status != 200 or not content:
            continue

        fn = safe_filename(url, ts)
        path = os.path.join(out_dir, fn)
        with open(path, "wb") as f:
            f.write(content)

        findings = analyze_content(url, ts, content)
        findings["saved_as"] = fn
        findings["cdx_mimetype"] = rec.get("mimetype")
        findings["cdx_digest"] = rec.get("digest")
        findings["cdx_length"] = rec.get("length")
        findings["cdx_statuscode"] = rec.get("statuscode")
        findings["suspicion_score"] = score_findings(findings)

        findings_all.append(findings)
        downloaded += 1

    findings_all.sort(key=lambda x: x.get("suspicion_score", 0), reverse=True)

    report_path = os.path.join(out_dir, "findings.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(findings_all, f, ensure_ascii=False, indent=2)

    print(f"[+] Downloaded: {downloaded}")
    print(f"[+] Report: {report_path}")

    print("\n=== Top suspicious captures ===")
    for item in findings_all[:10]:
        print(f"- score={item['suspicion_score']} ts={item['timestamp']} url={item['url']}")
        if "emails" in item:
            print(f"  emails: {item['emails'][:5]}")
        if "form_actions" in item:
            print(f"  form_actions: {item['form_actions'][:3]}")
