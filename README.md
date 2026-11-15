# Threat Intel Specialist

Source for [www.threatintelspecialist.com](https://www.threatintelspecialist.com/): a free cybersecurity briefing with news, vulnerabilities, an incident tracker and a blog. It is a static site on GitHub Pages. There is no server and no build tool; a GitHub Actions workflow refreshes the data every 30 minutes.

## What is where

| Path | What it is |
| --- | --- |
| `index.html`, `news/`, `vulnerabilities/`, `incidents/`, `blog/`, `learn/`, `about/`, `search/` | The pages. Plain HTML. |
| `assets/` | One stylesheet (`site.css`) and small scripts, one per page. `site.js` draws the header and footer. |
| `data/` | JSON/CSV the pages read or expose for download. Written by the workflow; do not edit by hand, except `incidents_curated.json`. |
| `content/posts/` | Blog posts in Markdown. |
| `scripts/build_data.py` | Fetches news, vulnerabilities and incidents. |
| `scripts/build_posts.py` | Turns Markdown posts into pages. |
| `scripts/sources.json` | The list of news feeds. |
| `pages/` | Redirects from the old page addresses. |

## Common jobs

**Publish a blog post.** Add a file such as `content/posts/my-post.md`:

```
---
title: My post title
date: 2026-11-15
summary: One or two sentences for lists and search results.
tags: Ransomware, Guide
---

Write the post here in Markdown.
```

Commit it to `main`. The workflow builds the page within a couple of minutes. Add `draft: true` to keep a post unpublished.

**Add or correct an incident.** Edit `data/incidents_curated.json`. Entries there override the automatic tracker. To correct an automatic entry, reuse its `id`.

**Add or remove a feed source.** Edit `scripts/sources.json`. Use `"kind": "news"` for established press, `"research"` for vendor/researcher reporting and `"official"` for government/CERT sources. Ransomware.live is ingested separately through its JSON API so reported cyberattacks and leak-site claims remain distinct.

**Refresh now.** Actions tab, "Update site data", "Run workflow".

## AI labelling and optional secrets

Incidents are labelled by an AI model when one is reachable, and by keyword rules when none is. The services are tried in this order:

1. **GitHub Models**, using the workflow's built-in token. No key or setup. Free, with daily usage limits.
2. **Google Gemini**, if the `GEMINI_API_KEY` secret is set.
3. **Keyword rules** in `scripts/build_data.py`.

Recent entries that were labelled by rules are re-checked once an AI service answers again.

Exploited vulnerabilities combine CISA's KEV catalogue with ENISA's EU list. Their publication dates come from the CVE Project and are cached in `data/vuln_cache.json`, as are the weekly publication totals used on the Trends tab.

New vulnerabilities come from NVD's "recent" download file. If that fails, the NVD search API is used; the optional `NVD_API_KEY` secret makes that fallback faster.

Optional repository variables (Settings, Secrets and variables, Actions, Variables): `GITHUB_MODELS_MODEL` to pin a GitHub model (for example `openai/gpt-4.1`), `GEMINI_MODEL` to pin a Gemini model.

## How incidents are verified

The tracker uses five evidence states:

- **Confirmed** — acknowledged by the affected organisation or a competent authority.
- **Corroborated** — at least two independent reputable sources report the same incident.
- **Reported** — one reputable source reports the incident, without official acknowledgement yet.
- **Claimed** — a threat actor or leak site claims the incident; this is an early-warning signal, not proof.
- **Disputed** — the affected organisation denies or directly challenges the allegation.

Every source stored against an incident has its own evidence state. The incident-level state is derived from those sources, so verification can strengthen as new reporting appears. The incident corpus is cumulative: rule changes do not erase old records. The workflow also imports the repository’s 2025 ransomware archive as **Claimed** evidence and ingests Ransomware.live’s JSON cyberattack/victim data. `data/incidents.csv` is the full cumulative export.

## Run it locally

```
python -m unittest discover tests     # tests, no network needed
python scripts/build_posts.py         # rebuild blog pages
python scripts/build_data.py          # fetch live data
python -m http.server 8000            # then open http://localhost:8000
```

Python 3.10 or newer. No packages to install.


## Incident coverage

The CSV is designed to contain **all incidents discovered by the configured public sources**, retained over time. It is not possible to guarantee every cyber incident worldwide because many incidents are never disclosed and no single authoritative global registry exists.

Coverage currently combines:

- Monitored security-news, research and official/CERT feeds
- Ransomware.live reported-cyberattack JSON data
- Ransomware.live leak-site victim claims, always marked **Claimed**
- The repository's 2025 ransomware archive, imported as **Claimed**
- Manual corrections in `data/incidents_curated.json`

Ransomware.live aggregate records do not count as an independent second source for **Corroborated**, preventing a syndicated article from being counted twice.
