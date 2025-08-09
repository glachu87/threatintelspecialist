import csv, io, json, re, time
from datetime import datetime, timezone
from urllib.request import urlopen, Request

import feedparser
from dateutil import parser as dtp

# --- Sources (stable, official) ---
KEV_JSON_URL = "https://www.cisa.gov/feeds/kev/current.json"  # linked from KEV Catalog page
KEV_CSV_URL  = "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"
RSS_ALL      = "https://www.cisa.gov/cybersecurity-advisories/all.xml"
RSS_ICS      = "https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml"
RSS_ICS_MED  = "https://www.cisa.gov/cybersecurity-advisories/ics-medical-advisories.xml"

# --- Helpers ---
def fetch(url, binary=False):
    req = Request(url, headers={"User-Agent": "Mozilla/5.0 (ThreatIntelSpecialist Indexer)"})
    with urlopen(req, timeout=60) as r:
        data = r.read()
        return data if binary else data.decode("utf-8", errors="replace")

def parse_kev():
    out = []

    # Prefer JSON; fall back to CSV if needed
    try:
        kev = json.loads(fetch(KEV_JSON_URL))
        items = kev.get("vulnerabilities", [])
        for v in items:
            cve = v.get("cveID") or v.get("cve_id")
            vendor = v.get("vendorProject") or ""
            product = v.get("product") or ""
            name = f"{vendor} {product}".strip()
            desc = v.get("shortDescription") or v.get("vulnerabilityName") or ""
            link = f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search={cve}"
            date_added = v.get("dateAdded") or v.get("date_added")
            due = v.get("dueDate") or v.get("due_date")
            out.append({
                "source": "CISA KEV",
                "type": "kev",
                "cve": cve,
                "vendor": vendor,
                "product": product,
                "title": f"{cve} — {name}".strip(" —"),
                "summary": desc,
                "published": date_added,
                "link": link,
                "extra": {"dueDate": due},
            })
        return out
    except Exception:
        pass

    # Fallback CSV
    try:
        csv_text = fetch(KEV_CSV_URL)
        reader = csv.DictReader(io.StringIO(csv_text))
        for row in reader:
            cve = row.get("cveID")
            vendor = row.get("vendorProject", "")
            product = row.get("product", "")
            name = f"{vendor} {product}".strip()
            out.append({
                "source": "CISA KEV",
                "type": "kev",
                "cve": cve,
                "vendor": vendor,
                "product": product,
                "title": f"{cve} — {name}".strip(" —"),
                "summary": row.get("shortDescription", "") or row.get("vulnerabilityName", ""),
                "published": row.get("dateAdded"),
                "link": f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search={cve}",
                "extra": {"dueDate": row.get("dueDate")},
            })
    except Exception:
        pass

    return out

def parse_rss(url, label):
    feed = feedparser.parse(fetch(url, binary=True))
    items = []
    for e in feed.entries:
        title = e.get("title", "")
        link = e.get("link", "")
        summary = re.sub("<[^>]+>", " ", e.get("summary", "")).strip()
        pub = e.get("published") or e.get("updated") or ""
        try:
            pub_iso = dtp.parse(pub).astimezone(timezone.utc).strftime("%Y-%m-%d")
        except Exception:
            pub_iso = ""
        # Heuristic vendor/product extraction (optional; still searchable by text)
        m = re.findall(r"(?:Vendor|Company|Manufacturer)\s*:\s*([A-Za-z0-9 ._-]+)", summary, flags=re.I)
        vendor = m[0].strip() if m else ""
        m2 = re.findall(r"(?:Product|Product Name|Affected Product\(s\))\s*:\s*([A-Za-z0-9 ._/\-\(\)]+)", summary, flags=re.I)
        product = m2[0].strip() if m2 else ""
        items.append({
            "source": label,
            "type": "advisory",
            "cve": None,  # CVEs usually appear in body; still text-searchable
            "vendor": vendor,
            "product": product,
            "title": title,
            "summary": summary[:1200],
            "published": pub_iso,
            "link": link,
        })
    return items

def main():
    idx = []
    idx.extend(parse_kev())
    idx.extend(parse_rss(RSS_ALL, "CISA Advisories (All)"))
    # Optional: include ICS feeds for OT visitors
    idx.extend(parse_rss(RSS_ICS, "CISA ICS Advisories"))
    idx.extend(parse_rss(RSS_ICS_MED, "CISA ICS Medical Advisories"))

    # Write compact JSON
    out = {
        "built_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "records": idx
    }
    # Ensure target dir exists
    import os, pathlib
    target = pathlib.Path("public/data")
    target.mkdir(parents=True, exist_ok=True)
    with open(target / "index.json", "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False)

if __name__ == "__main__":
    main()
