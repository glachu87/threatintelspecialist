from pathlib import Path
import json

SRC = Path("feeds/cisa/advisories.json")
OUT = Path("feeds/cisa/advisories_filtered.json")

# fields that must all be N/A to exclude
FIELDS = [
    "Vendor",
    "Affected Products",
    "Release Date",
    "CVSS v4",
    "Summary",
    "Risk",
    "Overview",
    "Mitigations",
]

def is_na(val: object) -> bool:
    """Treat N/A-like values as NA (case-insensitive), including empty and None."""
    if val is None:
        return True
    s = str(val).strip().lower()
    return s in {"n/a", "na", "none", ""}

def all_fields_na(item: dict) -> bool:
    return all(is_na(item.get(f)) for f in FIELDS)

data = json.loads(SRC.read_text(encoding="utf-8"))

# Support both a list of advisories or an object with 'advisories' inside
advisories = data.get("advisories", data) if isinstance(data, dict) else data
if not isinstance(advisories, list):
    raise SystemExit("Expected a JSON array of advisories or an object with 'advisories'.")

kept = [a for a in advisories if not all_fields_na(a)]

# Write out in the same shape you read
if isinstance(data, dict) and "advisories" in data:
    data["advisories"] = kept
    OUT.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
else:
    OUT.write_text(json.dumps(kept, indent=2, ensure_ascii=False), encoding="utf-8")

print(f"Filtered {len(advisories) - len(kept)} advisories. Kept {len(kept)} -> {OUT}")
