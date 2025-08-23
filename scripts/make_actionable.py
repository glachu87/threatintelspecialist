import os, json, csv
from datetime import datetime
from dateutil import parser as dtp
import pandas as pd
from pathlib import Path

FEEDS_DIR = Path("feeds")
OUT_DIR = Path("actionable")
OUT_DIR.mkdir(parents=True, exist_ok=True)
OUT_MD = OUT_DIR / "actionable_intelligence.md"

# Collect rows from CSV/JSON/TXT (simple heuristic)
records = []

def normalize_indicator(x):
    x = x.strip()
    return x.lower() if any(k in x for k in (".", ":")) else x

def as_dt(v):
    try:
        return dtp.parse(str(v)).isoformat()
    except Exception:
        return None

for root, _, files in os.walk(FEEDS_DIR):
    for f in files:
        p = Path(root) / f
        if f.lower().endswith(".csv"):
            with open(p, newline='', encoding="utf-8") as fh:
                for row in csv.DictReader(fh):
                    records.append({
                        "indicator": normalize_indicator(row.get("indicator") or row.get("value") or row.get("ioc","")),
                        "type": (row.get("type") or "").lower(),
                        "first_seen": as_dt(row.get("first_seen")),
                        "last_seen": as_dt(row.get("last_seen")),
                        "source": str(p),
                        "confidence": row.get("confidence") or "",
                        "tags": row.get("tags") or "",
                        "references": row.get("reference") or row.get("references") or ""
                    })
        elif f.lower().endswith(".json"):
            try:
                data = json.loads(Path(p).read_text(encoding="utf-8"))
                items = data if isinstance(data, list) else data.get("objects") or data.get("data") or []
                for it in items:
                    records.append({
                        "indicator": normalize_indicator(it.get("indicator") or it.get("value") or it.get("id","")),
                        "type": (it.get("type") or it.get("indicator_type") or "").lower(),
                        "first_seen": as_dt(it.get("first_seen") or it.get("created")),
                        "last_seen": as_dt(it.get("last_seen") or it.get("modified")),
                        "source": str(p),
                        "confidence": it.get("confidence") or "",
                        "tags": ",".join(it.get("labels", [])) if isinstance(it.get("labels"), list) else (it.get("labels") or ""),
                        "references": ", ".join(it.get("external_references", [])) if isinstance(it.get("external_references"), list) else (it.get("reference") or "")
                    })
            except Exception:
                pass
        elif f.lower().endswith(".txt"):
            for line in Path(p).read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    records.append({
                        "indicator": normalize_indicator(line),
                        "type": "",
                        "first_seen": None,
                        "last_seen": None,
                        "source": str(p),
                        "confidence": "",
                        "tags": "",
                        "references": ""
                    })

# Build DataFrame and dedupe
df = pd.DataFrame(records)
if df.empty:
    OUT_MD.write_text("# Actionable Intelligence\n\n_No indicators found in `feeds/`._\n", encoding="utf-8")
    raise SystemExit(0)

df["indicator"] = df["indicator"].fillna("").astype(str)
df = df[df["indicator"] != ""]
df["type"] = df["type"].fillna("")
df["last_seen_sort"] = pd.to_datetime(df["last_seen"], errors="coerce")
df = df.sort_values(["last_seen_sort"], ascending=[False])

# Dedupe on indicator
df = df.drop_duplicates(subset=["indicator"])

# Simple priority heuristic
def priority(row):
    t = row["type"]
    if any(k in row["indicator"] for k in (".exe", ".dll", ".bin")) or t in ("sha256","sha1","md5","file"):
        return "High"
    if t in ("domain","url"):
        return "Medium"
    return "Low"

df["priority"] = df.apply(priority, axis=1)

# Generate Markdown
lines = []
lines.append("# Actionable Intelligence")
lines.append(f"_Generated: {datetime.utcnow().isoformat()}Z_\n")

top = df.head(50)  # keep it concise
for i, row in top.iterrows():
    ind = row["indicator"]
    t = row["type"] or "indicator"
    prio = row["priority"]
    src = row["source"]
    last_seen = row["last_seen"] or "unknown"
    conf = row["confidence"] or "unknown"

    lines.append(f"## {ind}")
    lines.append(f"- **Type:** {t}  \n- **Priority:** {prio}  \n- **Confidence:** {conf}  \n- **Last seen:** {last_seen}  \n- **Source:** `{src}`")
    lines.append("**Detections (examples):**")
    lines.append("```splunk\nindex=* (url=\"{ind}\" OR domain=\"{ind}\" OR file_hash=\"{ind}\")\n| stats count by host, sourcetype, _time\n```".format(ind=ind))
    lines.append("```kusto\nDeviceNetworkEvents\n| where RemoteUrl == \"{ind}\" or RemoteIP == \"{ind}\"\n```".format(ind=ind))
    lines.append("```yaml\n# Sigma (placeholder)\ndetection:\n  selection:\n    Indicator: \"{ind}\"\n  condition: selection\n```".format(ind=ind))
    lines.append("**Mitigations:** block at egress/web proxy, add to safe-blocklist, hunt for historical hits, ticket to IR if any hits found.\n")

OUT_MD.write_text("\n".join(lines) + "\n", encoding="utf-8")
print(f"Wrote {OUT_MD}")
