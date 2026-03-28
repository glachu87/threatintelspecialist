import os, json, requests, time
from datetime import datetime, timezone

os.makedirs("public/data", exist_ok=True)

# NVD API v2.0 - fetch without date filter first to test connectivity
api_key = os.environ.get("NVD_API_KEY", "")
headers = {"apiKey": api_key} if api_key else {}
print(f"API key present: {bool(api_key)}")

# Use keyword search instead of date range - more reliable
url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
params = {
    "resultsPerPage": 100,
    "startIndex": 0,
    "cvssV3Severity": "CRITICAL",
}

print(f"Fetching CRITICAL CVEs from NVD...")
success = False

for attempt in range(3):
    try:
        r = requests.get(url, params=params, headers=headers, timeout=60)
        print(f"Attempt {attempt+1} status: {r.status_code}")
        if r.status_code == 200:
            success = True
            break
        time.sleep(6)
    except Exception as e:
        print(f"Attempt {attempt+1} error: {e}")
        time.sleep(6)

if not success:
    # Fallback: fetch HIGH severity
    print("Trying HIGH severity as fallback...")
    params["cvssV3Severity"] = "HIGH"
    for attempt in range(3):
        try:
            r = requests.get(url, params=params, headers=headers, timeout=60)
            print(f"Fallback attempt {attempt+1} status: {r.status_code}")
            if r.status_code == 200:
                success = True
                break
            time.sleep(6)
        except Exception as e:
            print(f"Fallback error: {e}")
            time.sleep(6)

if not success:
    print("NVD API unavailable. Keeping existing data.")
    exit(0)  # Exit cleanly - don't fail the workflow

raw = r.json().get("vulnerabilities", [])
print(f"CVEs returned: {len(raw)}")

def parse(entry):
    c = entry.get("cve", {})
    if not c: return None
    cid  = c.get("id", "")
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
    refs = [ref["url"] for ref in c.get("references", [])[:5]]
    cwes = list(set(d["value"] for w in c.get("weaknesses", []) for d in w.get("description", []) if d.get("value","").startswith("CWE-")))[:2]
    return {"id":cid,"description":desc[:500],"score":score,"severity":severity.upper() if severity else "N/A","attackVector":av.upper() if av else "N/A","userInteraction":ui,"privilegesRequired":priv,"published":c.get("published",""),"references":refs,"cwes":cwes}

vulns = [v for v in (parse(e) for e in raw) if v]
vulns.sort(key=lambda v: v.get("score") or 0, reverse=True)
print(f"CVEs with scores: {len(vulns)}")

existing = []
if os.path.exists("public/data/vulnerabilities.json"):
    try:
        with open("public/data/vulnerabilities.json") as f:
            existing = json.load(f).get("vulnerabilities", [])
        print(f"Existing CVEs: {len(existing)}")
    except: pass

merged = {v["id"]: v for v in existing}
for v in vulns:
    merged[v["id"]] = v
all_vulns = sorted(merged.values(), key=lambda v: v.get("published",""), reverse=True)

with open("public/data/vulnerabilities.json", "w") as f:
    json.dump({
        "lastUpdated": datetime.now(timezone.utc).isoformat(),
        "totalCount": len(all_vulns),
        "vulnerabilities": all_vulns
    }, f, indent=2)

print(f"Saved {len(all_vulns)} CVEs to public/data/vulnerabilities.json")
