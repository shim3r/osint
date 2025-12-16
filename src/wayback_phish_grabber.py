
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


RE_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
RE_PHP_MAIL = re.compile(r"\bmail\s*\(", re.IGNORECASE)
RE_FORM_ACTION = re.compile(r"<form[^>]+action\s*=\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)
RE_HIDDEN = re.compile(r"<input[^>]+type\s*=\s*['\"]hidden['\"][^>]*>", re.IGNORECASE)
RE_URLS = re.compile(r"https?://[A-Za-z0-9\.\-]+(?:\:[0-9]+)?/[^\s\"']*", re.IGNORECASE)
RE_JS_REDIRECT = re.compile(r"(location\.href|window\.location|document\.location)\s*=", re.IGNORECASE)


RE_BRANDS = re.compile(r"\b(paypal|ebay|aol|citibank|bank|visa|mastercard)\b", re.IGNORECASE)
RE_CREDS = re.compile(
    r"\b(password|passwd|passcode|pin|cvv|cvc|card\s*number|ccnum|ssn|routing|account\s*number)\b",
    re.IGNORECASE
)

DEFAULT_CONFIG = {

    "url_pattern": "ebay-verification.com/*",

    "year_from": 2003,
    "year_to": 2008,

    "cdx_limit": 2000,
    "sleep_seconds": 1.2,

    "out_dir": "wayback_dump",
    "save_cdx_dump": True,

    # 0 = без лимита
    "max_downloads": 0,

    # Если True — сохраняем только страницы с score >= min_score_to_save
    "save_only_suspicious": False,
    "min_score_to_save": 6
}


# ---------------- HTTP ----------------
def make_session() -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "User-Agent": "Mozilla/5.0 (OSINT-research; Wayback Analyzer)"
    })
    retries = Retry(
        total=8,
        backoff_factor=1.5,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "HEAD"],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retries, pool_connections=10, pool_maxsize=10)
    s.mount("https://", adapter)
    return s


# ---------------- helpers ----------------
def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def guess_ext(mimetype: str) -> str:
    mt = (mimetype or "").lower()
    if "javascript" in mt:
        return ".js"
    if "text/plain" in mt:
        return ".txt"
    return ".html"


def safe_filename(url: str, ts: str, ext: str = ".html") -> str:
    parsed = urlparse(url)
    host = parsed.netloc.replace(":", "_")
    path = parsed.path.strip("/").replace("/", "_") or "root"
    if parsed.query:
        q = re.sub(r"[^A-Za-z0-9._-]+", "_", parsed.query)[:80]
        path = f"{path}__q_{q}"
    return f"{ts}__{host}__{path}{ext}"


def is_probably_php_url(url: str) -> bool:
    return urlparse(url).path.lower().endswith((".php", ".phtml", ".cgi", ".asp", ".aspx"))


def is_html_like(mimetype: str) -> bool:
    mt = (mimetype or "").lower()
    return ("text/html" in mt) or ("application/xhtml" in mt) or (mt == "")


def load_config() -> dict:
    """
    Если рядом лежит config.json — подхватит его.
    Иначе использует DEFAULT_CONFIG.
    """
    cfg_path = os.path.join(os.getcwd(), "config.json")
    if os.path.exists(cfg_path):
        with open(cfg_path, "r", encoding="utf-8") as f:
            user_cfg = json.load(f)
        merged = DEFAULT_CONFIG.copy()
        merged.update(user_cfg)
        return merged
    return DEFAULT_CONFIG.copy()


# ---------------- CDX ----------------
def cdx_query(session: requests.Session, url_pattern: str, year_from: int, year_to: int, limit: int) -> list[dict]:
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
    return [dict(zip(header, row)) for row in data[1:]]


# ---------------- Download ----------------
def download_capture(session: requests.Session, ts: str, url: str) -> requests.Response:
    capture_url = f"{WAYBACK_WEB}/{ts}id_/{url}"
    return session.get(capture_url, timeout=60)


# ---------------- Analysis ----------------
def analyze_content(text: str) -> dict:
    """
    Возвращает находки. 
    - email
    - mail(
    - form action
    - hidden inputs
    - внешние URL
    - js redirect
    - бренды
    - чувствительные поля (password/cvv/ssn/...)
    """
    f: dict = {}

    lt = text.lower()
    has_at = "@" in text
    has_form = "<form" in lt
    has_http = "http://" in lt or "https://" in lt

    if has_at:
        emails = sorted(set(RE_EMAIL.findall(text)))
        if emails:
            f["emails"] = emails[:50]

    if "mail(" in lt and RE_PHP_MAIL.search(text):
        f["php_mail_call"] = True

    if has_form:
        actions = RE_FORM_ACTION.findall(text)
        if actions:
            f["form_actions"] = actions[:30]
        hidden_count = len(RE_HIDDEN.findall(text))
        if hidden_count:
            f["hidden_inputs_count"] = hidden_count

    if has_http:
        ext_urls = sorted(set(RE_URLS.findall(text)))
        if ext_urls:
            f["external_urls"] = ext_urls[:50]

    if "location" in lt and RE_JS_REDIRECT.search(text):
        f["js_redirect_like"] = True

    if RE_BRANDS.search(text):
        f["mentions_brand"] = True

    if RE_CREDS.search(text):
        f["credential_like_fields"] = True

    return f


# ---------------- Realistic scoring ----------------
def _is_script_endpoint(action: str) -> bool:
    a = (action or "").strip().lower()
    return any(a.endswith(ext) for ext in (".php", ".phtml", ".cgi", ".asp", ".aspx")) or \
           a in {"post.php", "send.php", "login.php", "verify.php", "flee.php"}

def _is_external_action(page_url: str, action: str) -> bool:
    if not action:
        return False
    action = action.strip()
    if action.startswith(("http://", "https://")):
        pu = urlparse(page_url)
        au = urlparse(action)
        return pu.netloc.lower() != au.netloc.lower()
    return False

def score_findings(f: dict) -> int:
    """
    Реалистичная шкала для фишинга :
    - максимум: 25
    - ключ: форма + креды + эксфильтрация
    """
    score = 0

    has_form = bool(f.get("form_actions"))
    has_creds = bool(f.get("credential_like_fields"))
    has_mail = bool(f.get("php_mail_call"))
    has_emails = bool(f.get("emails"))
    hidden = int(f.get("hidden_inputs_count", 0))
    has_redirect = bool(f.get("js_redirect_like"))
    mentions_brand = bool(f.get("mentions_brand"))

    # 1) Центральный признак: сбор чувствительных данных через форму
    if has_form and has_creds:
        score += 8
    elif has_form:
        score += 3
    elif has_creds:
        score += 2

    # 2) Обработчик формы
    if has_form:
        actions = f.get("form_actions", [])
        script_actions = [a for a in actions if _is_script_endpoint(a)]
        if script_actions:
            score += 4
        page_url = f.get("url", "")
        if any(_is_external_action(page_url, a) for a in actions):
            score += 6

    # 3) Экcфильтрация через mail()
    if has_mail:
        score += 6

    # 4) Email — сильнее, если есть механизм кражи
    if has_emails and (has_form or has_mail or has_creds):
        score += 4
    elif has_emails:
        score += 1

    # 5) Hidden inputs (киты)
    if hidden >= 8:
        score += 3
    elif hidden >= 3:
        score += 2
    elif hidden >= 1:
        score += 1

    # 6) JS-редирект
    if has_redirect and has_form:
        score += 2
    elif has_redirect:
        score += 1

    # 7) Бренд — слабый сам по себе, сильнее вместе с механикой
    if mentions_brand and (has_form or has_creds or has_mail):
        score += 2

    return min(score, 25)


# ---------------- main pipeline ----------------
def main():
    cfg = load_config()

    url_pattern = cfg["url_pattern"]
    year_from = int(cfg["year_from"])
    year_to = int(cfg["year_to"])
    limit = int(cfg["cdx_limit"])
    sleep_seconds = float(cfg["sleep_seconds"])
    out_dir = cfg["out_dir"]
    save_cdx_dump = bool(cfg.get("save_cdx_dump", True))
    max_downloads = int(cfg.get("max_downloads", 0))
    save_only_suspicious = bool(cfg.get("save_only_suspicious", False))
    min_score_to_save = int(cfg.get("min_score_to_save", 6))

    os.makedirs(out_dir, exist_ok=True)

    session = make_session()

    print(f"[+] CDX query: {url_pattern}")
    records = cdx_query(session, url_pattern, year_from, year_to, limit)
    if not records:
        print("[-] No records found. Try changing url_pattern or year range.")
        return

    if save_cdx_dump:
        with open(os.path.join(out_dir, "cdx_records.json"), "w", encoding="utf-8") as f:
            json.dump(records, f, ensure_ascii=False, indent=2)

    # фильтр + дедуп
    filtered = []
    seen = set()
    for rec in records:
        url = rec["original"]
        mt = rec.get("mimetype", "")
        if not (is_html_like(mt) or is_probably_php_url(url)):
            continue

        key = (rec.get("timestamp"), url)
        if key in seen:
            continue
        seen.add(key)
        filtered.append(rec)

    print(f"[+] Total records: {len(records)} | HTML/PHP-like unique: {len(filtered)}")

    findings_all = []
    downloaded = 0

    for rec in filtered:
        if max_downloads and downloaded >= max_downloads:
            break

        ts = rec["timestamp"]
        url = rec["original"]
        mimetype = rec.get("mimetype", "")
        ext = guess_ext(mimetype)

        time.sleep(sleep_seconds)

        try:
            resp = download_capture(session, ts, url)
        except requests.RequestException as e:
            print(f"[!] Download failed ts={ts} url={url} err={e}")
            continue

        if resp.status_code != 200 or not resp.content:
            continue

        text = resp.content.decode("utf-8", errors="replace")
        findings = analyze_content(text)

        
        findings.update({
            "timestamp": ts,
            "url": url,
            "bytes": len(resp.content),
            "sha256": sha256_bytes(resp.content),
            "cdx_mimetype": mimetype,
            "cdx_digest": rec.get("digest"),
            "cdx_length": rec.get("length"),
            "cdx_statuscode": rec.get("statuscode"),
            "response_content_type": resp.headers.get("Content-Type"),
            "final_url": resp.url,
        })

        score = score_findings(findings)
        findings["suspicion_score"] = score

        # сохраняем файл (либо всё, либо только подозрительное)
        if (not save_only_suspicious) or (score >= min_score_to_save):
            fn = safe_filename(url, ts, ext=ext)
            with open(os.path.join(out_dir, fn), "wb") as f:
                f.write(resp.content)
            findings["saved_as"] = fn

        findings_all.append(findings)
        downloaded += 1

    findings_all.sort(key=lambda x: x.get("suspicion_score", 0), reverse=True)

    report_path = os.path.join(out_dir, "findings.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(findings_all, f, ensure_ascii=False, indent=2)

    print(f"[+] Processed captures: {downloaded}")
    print(f"[+] Report: {report_path}")

    print("\n=== Top suspicious captures ===")
    for item in findings_all[:10]:
        print(f"- score={item['suspicion_score']} ts={item['timestamp']} url={item['url']}")
        if "emails" in item:
            print(f"  emails: {item['emails'][:5]}")
        if "form_actions" in item:
            print(f"  form_actions: {item['form_actions'][:3]}")


