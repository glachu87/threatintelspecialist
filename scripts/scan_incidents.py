#!/usr/bin/env python3
"""
AI-powered incident scanner.
Sources: NewsAPI, CISA advisories, RSS feeds.
Uses Google Gemini (free tier) to classify, summarise, and deduplicate incidents.
"""

import os, json, hashlib, requests
from datetime import datetime, timezone

INCIDENT_FILE = "public/data/incidents.json"
GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent"

NEWS_SOURCES = [
    "https://feeds.feedburner.com/TheHackersNews",
    "https://www.bleepingcomputer.com/feed/",
    "https://krebsonsecurity.com/feed/",
    "https://www.darkreading.com/rss.xml",
    "https://www.securityweek.com/feed",
]


def fetch_news_articles() -> list[dict]:
    """Fetch recent cybersecurity news from RSS feeds and NewsAPI."""
    articles = []

    # NewsAPI (requires free API key)
    newsapi_key = os.environ.get("NEWSAPI_KEY")
    if newsapi_key:
        try:
            r = requests.get(
                "https://newsapi.org/v2/everything",
                params={
                    "q": "cybersecurity incident ransomware breach hack data leak",
                    "sortBy": "publishedAt",
                    "pageSize": 50,
                    "language": "en",
                    "apiKey": newsapi_key,
                },
                timeout=15
            )
            for art in r.json().get("articles", []):
                articles.append({
                    "title": art.get("title", ""),
                    "description": art.get("description", ""),
                    "url": art.get("url", ""),
                    "publishedAt": art.get("publishedAt", ""),
                    "source": art.get("source", {}).get("name", ""),
                })
        except Exception as e:
            print(f"NewsAPI error: {e}")

    # CISA advisories
    try:
        r = requests.get(
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            timeout=15
        )
        for vuln in r.json().get("vulnerabilities", [])[:10]:
            articles.append({
                "title": f"CISA KEV: {vuln.get('vulnerabilityName', '')}",
                "description": vuln.get("shortDescription", ""),
                "url": f"https://nvd.nist.gov/vuln/detail/{vuln.get('cveID', '')}",
                "publishedAt": vuln.get("dateAdded", "") + "T00:00:00Z",
                "source": "CISA KEV",
            })
    except Exception as e:
        print(f"CISA error: {e}")

    print(f"Collected {len(articles)} articles")
    return articles


def call_gemini(prompt: str) -> str:
    """Send a prompt to Gemini and return the response text."""
    gemini_key = os.environ.get("GEMINI_API_KEY")
    if not gemini_key:
        raise ValueError("GEMINI_API_KEY environment variable is not set")

    response = requests.post(
        f"{GEMINI_API_URL}?key={gemini_key}",
        json={
            "contents": [
                {
                    "parts": [{"text": prompt}]
                }
            ],
            "generationConfig": {
                "temperature": 0.1,       # Low temperature = more consistent/predictable JSON output
                "maxOutputTokens": 2000,
            }
        },
        timeout=30
    )

    if response.status_code != 200:
        raise Exception(f"Gemini API error {response.status_code}: {response.text}")

    candidates = response.json().get("candidates", [])
    if not candidates:
        raise Exception("Gemini returned no candidates")

    return candidates[0]["content"]["parts"][0]["text"]


def classify_incidents_with_ai(articles: list[dict]) -> list[dict]:
    """Use Gemini to classify articles as cybersecurity incidents."""
    batch_size = 10
    incidents = []

    for i in range(0, len(articles), batch_size):
        batch = articles[i:i + batch_size]
        articles_text = "\n\n".join([
            f"Article {j+1}:\nTitle: {a['title']}\nDescription: {a['description']}\nSource: {a['source']}\nDate: {a['publishedAt']}"
            for j, a in enumerate(batch)
        ])

        prompt = f"""Analyse these cybersecurity news articles and extract any real cybersecurity incidents (not general news or opinion pieces).

For each incident found, return a JSON array with objects containing:
- title: brief incident title
- organisation: affected organisation name
- sector: one of [Healthcare, Finance, Government, Energy, Education, Retail, Technology, Critical Infrastructure, Other]
- type: one of [Ransomware, Data Breach, DDoS, Supply Chain, APT, Phishing, Zero-day, Credential Theft, Other]
- severity: one of [Critical, High, Medium]
- summary: 2-sentence technical summary
- cves: array of CVE IDs mentioned (empty array if none)
- threatActor: threat actor name if identified (null if unknown)
- date: incident date in YYYY-MM-DD format

Only include actual security incidents (not commentary, analysis, or general news).
Return ONLY the JSON array with no markdown formatting, no code fences, no extra text.

Articles:
{articles_text}"""

        try:
            raw = call_gemini(prompt)

            # Strip markdown code fences if Gemini wraps the JSON in them
            # e.g. ```json ... ``` or ``` ... ```
            cleaned = raw.strip()
            if cleaned.startswith("```"):
                cleaned = cleaned.split("```")[1]          # remove opening fence
                if cleaned.startswith("json"):
                    cleaned = cleaned[4:]                  # strip the word "json"
                cleaned = cleaned.rsplit("```", 1)[0]      # remove closing fence
                cleaned = cleaned.strip()

            result = json.loads(cleaned)
            if isinstance(result, list):
                incidents.extend(result)
                print(f"  Batch {i//batch_size + 1}: extracted {len(result)} incidents")
            else:
                print(f"  Batch {i//batch_size + 1}: unexpected response format, skipping")

        except json.JSONDecodeError as e:
            print(f"  Batch {i//batch_size + 1}: JSON parse error — {e}")
        except Exception as e:
            print(f"  Batch {i//batch_size + 1}: Gemini error — {e}")

    return incidents


def deduplicate(new_incidents: list[dict], existing: list[dict]) -> list[dict]:
    """Remove incidents already in history using title similarity."""
    existing_titles = {inc.get("title", "").lower()[:60] for inc in existing}

    fresh = []
    for inc in new_incidents:
        key = inc.get("title", "").lower()[:60]
        if key not in existing_titles:
            inc["id"] = "INC-" + hashlib.md5(inc["title"].encode()).hexdigest()[:8].upper()
            inc["discoveredAt"] = datetime.now(timezone.utc).isoformat()
            fresh.append(inc)
            existing_titles.add(key)

    return fresh


def main():
    os.makedirs("public/data", exist_ok=True)

    # Load existing incidents
    existing = []
    if os.path.exists(INCIDENT_FILE):
        with open(INCIDENT_FILE) as f:
            existing = json.load(f).get("incidents", [])

    print(f"Loaded {len(existing)} existing incidents from history")

    # Fetch and classify new incidents
    articles = fetch_news_articles()
    print(f"Classifying {len(articles)} articles with Gemini...")
    new_incidents = classify_incidents_with_ai(articles)
    print(f"Gemini extracted {len(new_incidents)} incidents total")

    fresh = deduplicate(new_incidents, existing)
    print(f"{len(fresh)} are new (not seen before)")

    # Merge and save
    all_incidents = fresh + existing
    all_incidents = all_incidents[:5000]  # Cap at 5000 records

    output = {
        "lastUpdated": datetime.now(timezone.utc).isoformat(),
        "totalCount": len(all_incidents),
        "newInLastScan": len(fresh),
        "incidents": all_incidents
    }

    with open(INCIDENT_FILE, "w") as f:
        json.dump(output, f, indent=2)

    print(f"Done. Saved {len(all_incidents)} total incidents ({len(fresh)} new) to {INCIDENT_FILE}")


if __name__ == "__main__":
    main()
