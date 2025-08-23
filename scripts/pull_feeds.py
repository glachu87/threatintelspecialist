# scripts/pull_feeds.py
# requirements: requests, feedparser, python-dotenv
import os, re, json, time, datetime as dt
import requests, feedparser

# ---- CONFIG ----
OUT_ROOT = "feeds"
WEEK = dt.date.today().isocalendar().week
YEAR = dt.date.today().year
ARCHIVE_DIR = f"{OUT_ROOT}/archive/{YEAR}-{WEEK:02d}"
os.makedirs(OUT_ROOT, exist_ok=True)
os.makedirs(ARCHIVE_DIR, exist_ok=True)

VT_API_KEY = os.getenv("VT_API_KEY", "")
NVD_API_KEY = os.getenv("NVD_API_KEY", "")
VT_LOOKUPS = int(os.getenv("VT_LOOKUPS", "40"))  # cap VT lookups per run

VENDOR_RSS = [
    # Mandiant (official)
    "https://www.mandiant.com/resources/blog/rss.xml",
    # Unit 42 (commonly mirrored via FeedBurner)
    "http://feeds.feedburner.com/Unit42",
    # Talos (if RSS is unavailable, we’ll just skip gracefully)
    "https://sec.cloudapps.cisco.com/security/center/eventResponses_20.xml"
]

# ---- HELPERS ----
def write_lines(path, rows):
    with open(path, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

def save_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

# ---- 1) CISA KEV ----
def pull_kev():
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    r = requests.get(url, timeout=30)
    r.raise_for_status()
    data = r.json()
    rows = []
    for v in data.get("vulnerabilities", []):
        rows.append({
            "source": "CISA-KEV",
            "cve": v.get("cveID"),
            "vendor": v.get("vendorProject"),
            "product": v.get("product"),
            "date_added": v.get("dateAdded"),
            "due_date": v.get("dueDate"),
            "required_action": v.get("requiredAction"),
            "notes": v.get("notes"),
        })
    save_json(f"{OUT_ROOT}/kev.json", rows)
    save_json(f"{ARCHIVE_DIR}/kev.json", rows)
    return rows

# ---- 2) NVD (last 7 days) ----
def pull_nvd(days_back=7):
    end = dt.datetime.utcnow()
    start = end - dt.timedelta(days=days_back)
    base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "lastModStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "lastModEndDate":   end.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "resultsPerPage": 2000,
        "startIndex": 0,
    }
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    out = []
    while True:
        r = requests.get(base, params=params, headers=headers, timeout=60)
        r.raise_for_status()
        j = r.json()
        for item in j.get("vulnerabilities", []):
            cve = item.get("cve", {})
            metrics = cve.get("metrics", {})
            cvss = None
            for key in ("cvssMetricV31","cvssMetricV30","cvssMetricV2"):
                if metrics.get(key):
                    cvss = metrics[key][0]["cvssData"].get("baseScore")
                    break
            out.append({
                "source": "NVD",
                "cve": cve.get("id"),
                "published": cve.get("published"),
                "lastModified": cve.get("lastModified"),
                "cvss": cvss,
                "descriptions": cve.get("descriptions", []),
            })
        params["startIndex"] += j.get("resultsPerPage", 0)
        if params["startIndex"] >= j.get("totalResults", 0): break
        time.sleep(1)
    save_json(f"{OUT_ROOT}/nvd_last7d.json", out)
    save_json(f"{ARCHIVE_DIR}/nvd_last7d.json", out)
    return out

# ---- 3) Vendor RSS (Mandiant, Unit42, Talos) ----
def pull_vendor_rss():
    rows = []
    for feed in VENDOR_RSS:
        try:
            d = feedparser.parse(feed)
            for e in d.entries:
                rows.append({
                    "source": d.feed.get("title", feed),
                    "title": e.get("title"),
                    "link": e.get("link"),
                    "published": e.get("published", e.get("updated")),
                    "summary": e.get("summary", ""),
                })
        except Exception:
            continue
    write_lines(f"{OUT_ROOT}/vendor.ndjson", rows)
    write_lines(f"{ARCHIVE_DIR}/vendor.ndjson", rows)
    return rows

# ---- IOC extraction + VT enrichment ----
IOC_RE = {
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "ipv4":   re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
    "domain": re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"),
    "url":    re.compile(r"\bhttps?://[^\s)]+", re.I),
}
def extract_iocs(text):
    if not text: return []
    found = []
    for t, rx in IOC_RE.items():
        for m in rx.findall(text):
            found.append({"type": t, "value": m})
    seen, uniq = set(), []
    for i in found:
        k = (i["type"], i["value"].lower())
        if k not in seen:
            seen.add(k); uniq.append(i)
    return uniq

def vt_lookup(obj_type, value):
    if not VT_API_KEY: return None
    headers = {"x-apikey": VT_API_KEY}
    # VT v3 /search accepts hash/url/domain/ip directly
    q = f'{obj_type}:"{value}"' if obj_type in ("domain","ip","url") else value
    r = requests.get("https://www.virustotal.com/api/v3/search",
                     params={"query": q}, headers=headers, timeout=30)
    if r.status_code == 429:
        time.sleep(20); return vt_lookup(obj_type, value)
    if not r.ok: return None
    data = (r.json().get("data") or [])
    return data[0] if data else None

def enrich_vendor_iocs(vendor_rows):
    # extract IOCs from titles + summaries
    raw = []
    for v in vendor_rows:
        raw += extract_iocs((v.get("title") or "") + " " + (v.get("summary") or ""))
    # de-dup
    seen, iocs = set(), []
    for i in raw:
        k = (i["type"], i["value"].lower())
        if k not in seen:
            seen.add(k); iocs.append(i)
    # VT (capped)
    enriched = []
    looked = 0
    for i in iocs:
        vt_type = {"sha256":"file","domain":"domain","ipv4":"ip","url":"url"}[i["type"]]
        vt = vt_lookup(vt_type, i["value"]) if looked < VT_LOOKUPS else None
        looked += 1 if vt is not None else 0
        rec = {**i, "vt": {"found": False}}
        if vt and "attributes" in vt:
            a = vt["attributes"]
            rec["vt"] = {
                "found": True,
                "reputation": a.get("reputation"),
                "malicious": a.get("last_analysis_stats", {}).get("malicious"),
                "suspicious": a.get("last_analysis_stats", {}).get("suspicious"),
                "undetected": a.get("last_analysis_stats", {}).get("undetected"),
                "last_analysis_date": a.get("last_analysis_date"),
            }
        enriched.append(rec)
        if looked >= VT_LOOKUPS: break
        time.sleep(1)
    write_lines(f"{OUT_ROOT}/ioc_enriched.ndjson", enriched)
    write_lines(f"{ARCHIVE_DIR}/ioc_enriched.ndjson", enriched)
    return enriched

def write_manifest(kev, nvd, vendor, enriched):
    manifest = {
        "generated_utc": dt.datetime.utcnow().isoformat() + "Z",
        "week": f"{YEAR}-{WEEK:02d}",
        "files": {
            "kev": "feeds/kev.json",
            "nvd_last7d": "feeds/nvd_last7d.json",
            "vendor_ndjson": "feeds/vendor.ndjson",
            "ioc_enriched": "feeds/ioc_enriched.ndjson"
        },
        "counts": {
            "kev": len(kev), "nvd": len(nvd),
            "vendor_posts": len(vendor), "iocs_enriched": len(enriched)
        }
    }
    save_json(f"{OUT_ROOT}/manifest.json", manifest)
    save_json(f"{ARCHIVE_DIR}/manifest.json", manifest)

if __name__ == "__main__":
    kev = pull_kev()
    nvd = pull_nvd(days_back=7)
    vendor = pull_vendor_rss()
    enriched = enrich_vendor_iocs(vendor)
    write_manifest(kev, nvd, vendor, enriched)
    print("Done. Files written to:", OUT_ROOT, "and", ARCHIVE_DIR)
