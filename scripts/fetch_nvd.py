#!/usr/bin/env python3
"""
fetch_nvd.py — Fetches CRITICAL CVEs from NVD API v2.0
Saves to feeds/nvd/vulnerabilities.json
"""
import os, sys, json, time, requests
from datetime import datetime, timezone

OUTPUT = "feeds/nvd/vulnerabilities.json"
os.makedirs("feeds/nvd", exist_ok=True)
print(f"Output path: {os.path.abspath(OUTPUT)}")

api_key = os.environ.get("NVD_API_KEY", "")
headers = {"apiKey": api_key} if api_key else {}
print(f"API key present: {bool(api_key)}")

url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Fetch CRITICAL CVEs
all_vulns = []
for severity in ["CRITICAL", "HIGH"]:
    params = {"cvssV3Severity": severity, "resultsPerPage": 200, "startIndex": 0}
    print(f"\nFetching {severity} CVEs...")
    for attempt in range(3):
        try:
            r = requests.get(url, params=params, headers=headers, timeout=60)
            print(f"  Attempt {attempt+1}: status {r.status_code}")
            if r.status_code == 200:
                data = r.json()
                vulns = data.get("vulnerabilities", [])
                print(f"  Got {len(vulns)} CVEs (total available: {data.get('totalResults','?')})")
                all_vulns.extend(vulns)
                break
            time.sleep(6)
        except Exception as e:
            print(f"  Error: {e}")
            time.sleep(6)

print(f"\nTotal raw CVEs: {len(all_vulns)}")

def parse(entry):
    c = entry.get("cve", {})
    if not c: return None
    cid = c.get("id", "")
    if not cid: return None
    desc = next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
    metrics = c.get("metrics", {})
    m31 = (metrics.get("cvssMetricV31") or [None])[0]
    m30 = (metrics.get("cvssMetricV30") or [None])[0]
    m2  = (metrics.get("cvssMetricV2")  or [None])[0]
    cvss = m31 or m30
    score = severity = av = ui = priv = None
    if cvss:
        cd       = cvss.get("cvssData", {})
        score    = cd.get("baseScore")
        severity = cd.get("baseSeverity", "N/A")
        av       = cd.get("attackVector", "N/A")
        ui       = cd.get("userInteraction")
        priv     = cd.get("privilegesRequired")
    elif m2:
        cd       = m2.get("cvssData", {})
        score    = cd.get("baseScore")
        severity = m2.get("baseSeverity", "N/A")
        av       = cd.get("accessVector", "N/A")
    if score is None: return None
    cwes = list(set(
        d["value"] for w in c.get("weaknesses", [])
        for d in w.get("description", [])
        if d.get("value", "").startswith("CWE-")
    ))[:3]
    refs = [r["url"] for r in c.get("references", [])[:5]]
    return {
        "id":                  cid,
        "description":         desc[:600],
        "score":               score,
        "severity":            severity.upper() if severity else "N/A",
        "attackVector":        av.upper() if av else "N/A",
        "userInteraction":     ui,
        "privilegesRequired":  priv,
        "published":           c.get("published", ""),
        "lastModified":        c.get("lastModified", ""),
        "cwes":                cwes,
        "references":          refs,
    }

parsed = [parse(v) for v in all_vulns]
good   = [v for v in parsed if v is not None]

# Deduplicate by ID
seen = {}
for v in good:
    seen[v["id"]] = v
unique = sorted(seen.values(), key=lambda v: v.get("published", ""), reverse=True)

print(f"CVEs with scores: {len(unique)}")

# Load existing to merge
existing = {}
if os.path.exists(OUTPUT):
    try:
        with open(OUTPUT) as f:
            old = json.load(f)
        for v in old.get("vulnerabilities", []):
            existing[v["id"]] = v
        print(f"Existing records: {len(existing)}")
    except Exception as e:
        print(f"Could not read existing: {e}")

# Merge new into existing
existing.update(seen)
final = sorted(existing.values(), key=lambda v: v.get("published", ""), reverse=True)

output = {
    "lastUpdated":     datetime.now(timezone.utc).isoformat(),
    "totalCount":      len(final),
    "vulnerabilities": final,
}

with open(OUTPUT, "w") as f:
    json.dump(output, f, indent=2)

# Verify file was written
size = os.path.getsize(OUTPUT)
print(f"\n✅ Saved {len(final)} CVEs to {OUTPUT} ({size:,} bytes)")
print(f"Top 5 CVEs:")
for v in final[:5]:
    print(f"  {v['id']} | {v['severity']} | Score: {v['score']} | {v['published'][:10]}")

if len(final) == 0:
    print("ERROR: No CVEs saved!", file=sys.stderr)
    sys.exit(1)
