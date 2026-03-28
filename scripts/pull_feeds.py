#!/usr/bin/env python3
"""
pull_feeds.py
Fetches threat intelligence feeds from authoritative sources.

Sources:
  - CISA KEV (Known Exploited Vulnerabilities) JSON API  → feeds/cisa/advisories.json
  - UK NCSC RSS feed                                     → feeds/ncsc/advisories.json
  - VirusTotal blog RSS                                  → feeds/vt/advisories.json
  - Google TAG / Mandiant RSS                            → feeds/google/advisories.json

Previously this script fetched the CISA RSS (all.xml) which only had titles
and produced N/A for every field. This version uses the KEV JSON API directly
which contains full details: CVE ID, vendor, product, description,
required action, due date, and ransomware flag.
"""

import os
import json
import requests
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

# ── OUTPUT PATHS ───────────────────────────────────────────────────────────
os.makedirs("feeds/cisa",   exist_ok=True)
os.makedirs("feeds/ncsc",   exist_ok=True)
os.makedirs("feeds/vt",     exist_ok=True)
os.makedirs("feeds/google", exist_ok=True)

TIMESTAMP = datetime.now(timezone.utc).isoformat()

# ── HELPER ─────────────────────────────────────────────────────────────────
def save(path: str, data: dict):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"  Saved {len(data.get('items', []))} items → {path}")


def fetch_rss(url: str, source_name: str, max_items: int = 30) -> list[dict]:
    """Parse an RSS/Atom feed and return a list of normalised items."""
    try:
        r = requests.get(url, timeout=20, headers={"User-Agent": "ThreatIntelSpecialist/1.0"})
        r.raise_for_status()
        root = ET.fromstring(r.content)

        # Handle both RSS 2.0 and Atom
        ns = {"atom": "http://www.w3.org/2005/Atom"}
        items = []

        # RSS 2.0
        for item in root.findall(".//item")[:max_items]:
            title   = (item.findtext("title") or "").strip()
            link    = (item.findtext("link")  or "").strip()
            pubdate = (item.findtext("pubDate") or item.findtext("published") or "").strip()
            summary = (item.findtext("description") or item.findtext("summary") or "").strip()
            # Strip HTML tags from summary
            import re
            summary = re.sub(r"<[^>]+>", " ", summary).strip()
            summary = re.sub(r"\s+", " ", summary)

            items.append({
                "title":             title,
                "link":              link,
                "published":         pubdate[:10] if pubdate else "",
                "summary":           summary[:500] if summary else "",
                "executive_summary": summary[:500] if summary else "",
                "vendor":            "",
                "affected_products": "",
                "source":            source_name,
            })

        # Atom feed fallback
        if not items:
            for entry in root.findall("atom:entry", ns)[:max_items]:
                title   = (entry.findtext("atom:title", namespaces=ns) or "").strip()
                link_el = entry.find("atom:link", ns)
                link    = link_el.get("href", "") if link_el is not None else ""
                pubdate = (entry.findtext("atom:published", namespaces=ns) or "").strip()
                summary = (entry.findtext("atom:summary", namespaces=ns) or
                           entry.findtext("atom:content", namespaces=ns) or "").strip()
                import re
                summary = re.sub(r"<[^>]+>", " ", summary).strip()

                items.append({
                    "title":             title,
                    "link":              link,
                    "published":         pubdate[:10] if pubdate else "",
                    "summary":           summary[:500] if summary else "",
                    "executive_summary": summary[:500] if summary else "",
                    "vendor":            "",
                    "affected_products": "",
                    "source":            source_name,
                })

        return items

    except Exception as e:
        print(f"  WARNING: Could not fetch {source_name} RSS: {e}")
        return []


# ══════════════════════════════════════════════════════════════════════════
# 1. CISA KEV — uses the official JSON API (NOT the RSS feed)
# ══════════════════════════════════════════════════════════════════════════
def fetch_cisa_kev(max_items: int = 50) -> list[dict]:
    KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    print(f"\nFetching CISA KEV from JSON API...")
    try:
        r = requests.get(KEV_URL, timeout=30, headers={"User-Agent": "ThreatIntelSpecialist/1.0"})
        r.raise_for_status()
        data   = r.json()
        vulns  = data.get("vulnerabilities", [])

        # Sort by dateAdded descending — most recent first
        vulns.sort(key=lambda x: x.get("dateAdded", ""), reverse=True)
        recent = vulns[:max_items]

        items = []
        for v in recent:
            cve_id  = v.get("cveID", "")
            vendor  = v.get("vendorProject", "")
            product = v.get("product", "")
            title   = v.get("vulnerabilityName", "") or f"{vendor} {product} Vulnerability".strip()
            summary = v.get("shortDescription", "")
            action  = v.get("requiredAction", "")
            notes   = v.get("notes", "")

            items.append({
                # Identity
                "cveID":                      cve_id,
                "title":                      title,
                "link":                       f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id else "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",

                # Vendor / product
                "vendor":                     vendor,
                "affected_products":          product,

                # Dates
                "dateAdded":                  v.get("dateAdded", ""),
                "dueDate":                    v.get("dueDate", ""),
                "published":                  v.get("dateAdded", ""),
                "release_date":               v.get("dateAdded", ""),

                # Description — multiple aliases so any renderer can find it
                "shortDescription":           summary,
                "executive_summary":          summary,
                "summary":                    summary,
                "vulnerability_overview":     summary,

                # Required action — multiple aliases
                "requiredAction":             action,
                "mitigations":                action,

                # Ransomware flag
                "knownRansomwareCampaignUse": v.get("knownRansomwareCampaignUse", "Unknown"),

                # References (semicolon-separated URLs)
                "notes":                      notes,

                # CVSS — KEV doesn't include scores; leave blank rather than N/A
                "cvss_v4":                    "",
                "cvss_v3":                    "",
                "risk_evaluation":            "",

                "source": "CISA KEV",
            })

        print(f"  Fetched {len(items)} KEV entries (total in catalog: {len(vulns)})")
        return items

    except Exception as e:
        print(f"  ERROR fetching CISA KEV: {e}")
        return []


# ══════════════════════════════════════════════════════════════════════════
# 2. UK NCSC
# ══════════════════════════════════════════════════════════════════════════
def fetch_ncsc() -> list[dict]:
    print("\nFetching UK NCSC feed...")
    items = fetch_rss(
        "https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml",
        source_name="UK NCSC",
        max_items=30,
    )
    # Fallback URL
    if not items:
        items = fetch_rss(
            "https://www.ncsc.gov.uk/feeds/alerts.xml",
            source_name="UK NCSC",
            max_items=30,
        )
    return items


# ══════════════════════════════════════════════════════════════════════════
# 3. VirusTotal Blog
# ══════════════════════════════════════════════════════════════════════════
def fetch_virustotal() -> list[dict]:
    print("\nFetching VirusTotal feed...")
    return fetch_rss(
        "https://blog.virustotal.com/feeds/posts/default",
        source_name="VirusTotal",
        max_items=20,
    )


# ══════════════════════════════════════════════════════════════════════════
# 4. Google Threat Intelligence / TAG
# ══════════════════════════════════════════════════════════════════════════
def fetch_google_threat_intel() -> list[dict]:
    print("\nFetching Google Threat Intelligence feed...")
    items = fetch_rss(
        "https://blog.google/threat-analysis-group/rss/",
        source_name="Google Threat Intel",
        max_items=20,
    )
    # Fallback to Mandiant blog
    if not items:
        items = fetch_rss(
            "https://www.mandiant.com/resources/blog/rss.xml",
            source_name="Google Threat Intel",
            max_items=20,
        )
    return items


# ══════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════
def main():
    print("=" * 60)
    print("ThreatIntelSpecialist — Feed Fetcher")
    print(f"Started: {TIMESTAMP}")
    print("=" * 60)

    # 1. CISA KEV (JSON API — full data, no N/A)
    cisa_items = fetch_cisa_kev(max_items=50)
    save("feeds/cisa/advisories.json", {
        "source":     "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "fetched_at": TIMESTAMP,
        "total":      len(cisa_items),
        "items":      cisa_items,
    })

    # 2. UK NCSC
    ncsc_items = fetch_ncsc()
    save("feeds/ncsc/advisories.json", {
        "source":     "https://www.ncsc.gov.uk",
        "fetched_at": TIMESTAMP,
        "total":      len(ncsc_items),
        "items":      ncsc_items,
    })

    # 3. VirusTotal
    vt_items = fetch_virustotal()
    save("feeds/vt/advisories.json", {
        "source":     "https://blog.virustotal.com",
        "fetched_at": TIMESTAMP,
        "total":      len(vt_items),
        "items":      vt_items,
    })

    # 4. Google Threat Intel
    google_items = fetch_google_threat_intel()
    save("feeds/google/advisories.json", {
        "source":     "https://blog.google/threat-analysis-group",
        "fetched_at": TIMESTAMP,
        "total":      len(google_items),
        "items":      google_items,
    })

    print("\n" + "=" * 60)
    print("All feeds updated successfully.")
    print("=" * 60)


if __name__ == "__main__":
    main()
