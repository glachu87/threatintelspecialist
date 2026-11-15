# Threat Intel Specialist

Source for [www.threatintelspecialist.com](https://www.threatintelspecialist.com/): a free cybersecurity briefing with news, vulnerabilities, an incident tracker and a blog. It is a static site on GitHub Pages. There is no server and no build tool; a GitHub Actions workflow refreshes the data every hour.

## What is where

| Path | What it is |
| --- | --- |
| `index.html`, `news/`, `vulnerabilities/`, `incidents/`, `blog/`, `learn/`, `about/`, `search/` | The pages. Plain HTML. |
| `assets/` | One stylesheet (`site.css`) and small scripts, one per page. `site.js` draws the header and footer. |
| `data/` | JSON the pages read. Written by the workflow; do not edit by hand, except `incidents_curated.json`. |
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

**Add or remove a news source.** Edit `scripts/sources.json`. Use `"kind": "news"` for press (these are also scanned for incidents), `"research"` for vendor and researcher blogs, `"official"` for government bodies.

**Refresh now.** Actions tab, "Update site data", "Run workflow".

## AI labelling and optional secrets

Incidents are labelled by an AI model when one is reachable, and by keyword rules when none is. The services are tried in this order:

1. **GitHub Models**, using the workflow's built-in token. No key or setup. Free, with daily usage limits.
2. **Google Gemini**, if the `GEMINI_API_KEY` secret is set.
3. **Keyword rules** in `scripts/build_data.py`.

Recent entries that were labelled by rules are re-checked once an AI service answers again.

New vulnerabilities come from NVD's "recent" download file. If that fails, the NVD search API is used; the optional `NVD_API_KEY` secret makes that fallback faster.

Optional repository variables (Settings, Secrets and variables, Actions, Variables): `GITHUB_MODELS_MODEL` to pin a GitHub model (for example `openai/gpt-4.1`), `GEMINI_MODEL` to pin a Gemini model.

## How incidents are labelled

An incident is **confirmed** only when a report says the affected organisation, a regulator, a court or a government body has acknowledged it. Everything else is **unconfirmed**. A label can move from unconfirmed to confirmed automatically, never the other way. The rules are in `scripts/build_data.py` under "incidents".

## Run it locally

```
python -m unittest discover tests     # tests, no network needed
python scripts/build_posts.py         # rebuild blog pages
python scripts/build_data.py          # fetch live data
python -m http.server 8000            # then open http://localhost:8000
```

Python 3.10 or newer. No packages to install.
