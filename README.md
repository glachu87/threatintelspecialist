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

## Optional secrets

Set under Settings, Secrets and variables, Actions. The site works without them.

| Secret | Effect |
| --- | --- |
| `NVD_API_KEY` | Faster, more reliable requests to the National Vulnerability Database. |
| `GEMINI_API_KEY` | Uses Google Gemini to extract the organisation, write a one-line summary and judge confirmed/unconfirmed for each incident. Without it, simpler keyword rules are used. |

The model defaults to `gemini-flash-latest`. To pin another, add a repository variable named `GEMINI_MODEL`.

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
