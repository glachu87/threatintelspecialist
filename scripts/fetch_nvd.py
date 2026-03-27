#!/usr/bin/env python3
"""Fetch recent CVEs from NVD API and save to public/data/vulnerabilities.json"""

import os, json, requests
from datetime import datetime, timedelta, timezone

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OUTPUT  = "public/data/vulnerabilities.json"
DAYS    = 30  # Fetch last 30 days of CVEs

def fetch_cves(days: int = DAYS) -> list[dict]:
    end   = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    fmt   = lambda d: d.strftime("%Y-%m-%dT%H:%M:%S.000")

    headers = {}
    api_key = os.environ.get("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key

    params = {
        "pubStartDate": fmt(start),
        "pubEndDate":   fmt(end),
        "resultsPerPage": 2000,
    }

    print(f"Fetching CVEs from {fmt(start)} to {fmt(end)}")
    r = requests.get(NVD_API, params=params, headers=headers, timeout=60)
    r.raise_for_status()
    data = r.json()

    vulns = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cid = cve.get("id", "")
        desc = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "")

        metrics = cve.get("metrics", {})
        m = (metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or [None])[0]
        m2 = (metrics.get("cvssMetricV2") or [None])[0]

        score    = m["cvssData"]["baseScore"] if m else (m2["cvssData"]["baseScore"] if m2 else None)
        severity = m["cvssData"]["baseSeverity"] if m else (m2["baseSeverity"] if m2 else "N/A")
        av       = m["cvssData"]["attackVector"] if m else "N/A"

        vulns.append({
            "id": cid,
            "description": desc[:500],
            "score": score,
            "severity": severity.upper() if severity else "N/A",
            "attackVector": av.upper() if av else "N/A",
            "published": cve.get("published", ""),
            "references": [r["url"] for r in cve.get("references", [])[:3]],
            "cwes": list(set(
                d["value"] for w in cve.get("weaknesses", [])
                for d in w.get("description", [])
                if d["value"].startswith("CWE-")
            ))[:2],
        })

    vulns.sort(key=lambda v: v["score"] or 0, reverse=True)
    print(f"Fetched {len(vulns)} CVEs")
    return vulns


def main():
    os.makedirs("public/data", exist_ok=True)

    # Load existing data
    existing = []
    if os.path.exists(OUTPUT):
        with open(OUTPUT) as f:
            existing = json.load(f).get("vulnerabilities", [])

    existing_ids = {v["id"] for v in existing}
    new_vulns = fetch_cves()

    # Merge: keep existing, add new ones
    merged = {v["id"]: v for v in existing}
    added = 0
    for v in new_vulns:
        if v["id"] not in merged:
            merged[v["id"]] = v
            added += 1
        else:
            merged[v["id"]] = v  # Update with latest data

    all_vulns = sorted(merged.values(), key=lambda v: v["published"], reverse=True)

    output = {
        "lastUpdated": datetime.now(timezone.utc).isoformat(),
        "totalCount":  len(all_vulns),
        "vulnerabilities": all_vulns
    }

    with open(OUTPUT, "w") as f:
        json.dump(output, f, indent=2)

    print(f"Saved {len(all_vulns)} total CVEs to {OUTPUT} ({added} new)")


if __name__ == "__main__":
    main()
