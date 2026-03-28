import os, json, time, requests
from datetime import datetime, timedelta, timezone

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OUTPUT  = "public/data/vulnerabilities.json"
os.makedirs("public/data", exist_ok=True)

api_key = os.environ.get("NVD_API_KEY", "")
headers = {"apiKey": api_key} if api_key else {}

end   = datetime.now(timezone.utc)
start = end - timedelta(days=30)
fmt   = lambda d: d.strftime("%Y-%m-%dT%H:%M:%S.000")

print(f"Fetching CVEs from {fmt(start)} to {fmt(end)}")

params = {
    "pubStartDate":   fmt(start),
    "pubEndDate":     fmt(end),
    "resultsPerPage": 2000,
}

for attempt in range(3):
    try:
        r = requests.get(NVD_API, params=params, headers=headers, timeout=60)
        if r.status_code == 403:
            print("Rate limited — waiting 30s...")
            time.sleep(30)
            continue
        r.raise_for_status()
        data = r.json()
        break
    except requests.RequestException as e:
        print(f"Attempt {attempt+1} failed: {e}")
        if attempt < 2:
            time.sleep(10)
        else:
            raise

raw = data.get("vulnerabilities", [])
print(f"Raw CVEs returned: {len(raw)}")

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
        cd = cvss.get("cvssData", {})
        score    = cd.get("baseScore")
        severity = cd.get("baseSeverity", "N/A")
        av       = cd.get("attackVector", "N/A")
        ui       = cd.get("userInteraction")
        priv     = cd.get("privilegesRequired")
    elif m2:
        cd = m2.get("cvssData", {})
        score    = cd.get("baseScore")
        severity = m2.get("baseSeverity", "N/A")
        av       = cd.get("accessVector", "N/A")
    if score is None: return None
    refs = [ref["url"] for ref in c.get("references", [])[:5]]
    cwes = list(set(d["value"] for w in c.get("weaknesses", []) for d in w.get("description", []) if d.get("value","").startswith("CWE-")))[:2]
    return {"id":cid,"description":desc[:500],"score":score,"severity":severity.upper(),"attackVector":av.upper(),"userInteraction":ui,"privilegesRequired":priv,"published":c.get("published",""),"references":refs,"cwes":cwes}

vulns = [v for v in (parse(e) for e in raw) if v]
vulns.sort(key=lambda v: v.get("score") or 0, reverse=True)
print(f"CVEs with scores: {len(vulns)}")

existing = []
if os.path.exists(OUTPUT):
    try:
        with open(OUTPUT) as f:
            existing = json.load(f).get("vulnerabilities", [])
    except: pass

merged = {v["id"]: v for v in existing}
for v in vulns:
    merged[v["id"]] = v
all_vulns = sorted(merged.values(), key=lambda v: v.get("published",""), reverse=True)

with open(OUTPUT, "w") as f:
    json.dump({"lastUpdated": datetime.now(timezone.utc).isoformat(), "totalCount": len(all_vulns), "vulnerabilities": all_vulns}, f, indent=2)

print(f"Saved {len(all_vulns)} CVEs to {OUTPUT}")
