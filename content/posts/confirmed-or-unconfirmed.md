---
title: Unverified, corroborated or organisation-confirmed? How to read an incident
date: 2026-11-15
summary: Evidence labels, source health, incident dates and the limits of public-source monitoring.
tags: Guide, Incidents, Threat Intelligence
---

The tracker distinguishes what a source claims from what reviewed evidence supports. A leak-site listing, several articles repeating that listing, and an organisation's own statement are different kinds of evidence.

## Three public evidence labels

**Unverified claim** is the default. It includes attacker allegations, single-source reports and records awaiting evidence review. A headline containing “confirmed” does not itself qualify an incident for a stronger label.

**Corroborated report** requires reviewed reports with at least two independent evidence origins. Two publishers repeating one attacker statement do not count as independent corroboration.

**Organisation-confirmed incident** requires a reviewed statement or filing from the affected organisation acknowledging the incident. That does not automatically verify the attacker, incident date, financial loss or every detail of the report.

Disputes and denials remain visible separately. Labels can change when evidence is reviewed or corrected. Older automatic labels are not treated as proof.

## What runs automatically

The existing collector is scheduled every 30 minutes. It reads configured public news, research and official feeds plus public ransomware-intelligence APIs. GitHub can delay scheduled jobs.

RansomLook's group directory discovers relevant profiles and records their first and last observation. RansomLook and Ransomware.live provide indirect access to publicly reported leak-site disclosures. They are not independent confirmation when they repeat the same actor claim.

The cumulative incident database retains older records. New reports are matched using organisation, dates, actor and source links. Conflicting known actors or attack dates prevent an automatic merge. Clearly different victims in older claim-only clusters have been separated while preserving their evidence. Ambiguous cases can still need correction.

AI can assist with organisation, actor, incident type, headline, summary and explicit date extraction when the configured model is available. Deterministic processing continues without it. AI does not independently certify public evidence labels.

## Which date is shown?

**First reported** means a publication or aggregator-discovery date. **Claimed incident date** is only populated when the source explicitly supplies an attack date. Missing dates remain unknown; conflicting dates are flagged. The first time a collector saw a post is not necessarily the date an attack happened.

## Source health and monitoring gaps

The monitoring panel shows source links, latest check, last successful check, empty responses and failures. Status becomes stale when no check is recorded for more than two hours. A successful HTTP request is not proof that an aggregator captured every disclosure.

Feed last-checked means the feed was requested. It does not mean every linked article was re-opened. Last-observed timestamps identify records actually returned by a source, not merely carried forward from history.

This collector does not directly crawl onion sites, access private communities or discover undisclosed addresses. Recent API and RSS windows can leave gaps after downtime. The charts describe this monitored corpus, not all cyber incidents worldwide.

## Evidence review

Reviewed evidence appears with its source URL, short supporting excerpt, review date and reviewer. Records awaiting review stay unverified. A review queue and version-controlled evidence records support corrections; old records are not automatically certified simply because they have several source links.

Always consult the original evidence before making a decision based on an incident. Automated extraction and deduplication can make mistakes.
