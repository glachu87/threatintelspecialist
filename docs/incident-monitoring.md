# Incident monitoring and evidence

The existing GitHub Actions data workflow runs at minutes 7 and 37 each hour. Schedules can be delayed by GitHub. All existing feeds remain configured in `scripts/sources.json`. Ransomware.live and RansomLook public APIs supply additional incident metadata. RansomLook's public group directory discovers relevant actor profiles automatically. Group profiles are indirect coverage, not direct onion uptime checks.

## Outputs

- `data/incidents.json` and `incidents.csv`: cumulative records, claimed incident dates when explicitly provided, report dates, per-source links/excerpts, observation timestamps and reviewed evidence.
- `data/source_registry.json`: configured incident sources, latest attempts, last successful checks, consecutive failures, empty responses and coverage limits. Vulnerability-only APIs are excluded.
- `data/source_discovery.json`: cumulative public group profiles, provenance, first seen and last seen. An absent profile is retained with its previous last-seen time.
- `data/incident_review_queue.json`: latest 200 pending evidence reviews; not the entire backlog.

The page flags checks older than two hours. Feed last-checked means the feed was requested, not that every linked article was re-opened. Failed fetches preserve cumulative incidents. Empty responses are shown separately. An aggregator can have its own collection gaps even when its API responds successfully.

## Evidence policy

The public `evidence_state` and `evidence_label` are authoritative. The legacy `status` remains an extraction hint for backwards-compatible ingestion and must not be presented as verified evidence. All public views and CSV exports use the stricter policy.

1. **Unverified claim:** default, including single-source reporting and headlines saying “confirmed”.
2. **Corroborated report:** reviewed reports with at least two different original evidence origins. Two publishers repeating one attacker claim do not count.
3. **Organisation-confirmed incident:** a reviewed statement or filing from the affected organisation acknowledges the incident. An official government statement is not automatically an organisation statement.

Disputes are recorded separately. Confirmation of an incident does not automatically confirm its reported attacker, date, loss amount or every other allegation. Initial source reviews cover the M&S notice and UnitedHealth's filing; the rest of the archive is not retrospectively certified.

AI extracts candidate fields when the existing GitHub Models/Gemini configuration works. Deterministic extraction continues without AI. AI does not promote public evidence labels. Unknown incident dates stay null; API `attackdate` is explicitly a claimed date. AI dates require the ISO date and its verbatim support in supplied text. Publication/discovery dates are never copied into the incident-date field. Conflicting source dates are retained and surfaced.

## Review an entry

Find its ID in the page/JSON or review queue. Read the original source and add a review to `data/incident_evidence_reviews.json`. The URL must already appear in that incident's source list. To add an organisation statement, use `data/incidents_curated.json` with the same ID and preserve the existing evidence plus the new source. Commit the changes; the existing workflow regenerates the labels.

Example structure (illustrative only, not a real incident):

```json
{
  "reviews": {
    "INC-EXAMPLE": [{
      "url": "https://example.org/security-notice",
      "type": "organisation_statement",
      "reviewer": "Reviewer name",
      "reviewed_at": "2026-11-15",
      "excerpt": "Short exact passage acknowledging the incident"
    }]
  }
}
```

For `independent_report`, add `independent_origin` identifying the original evidence (such as a distinct investigation), not simply the newspaper. Use `denial` for an organisation's denial. The repository review is the trust boundary: the program validates structure and linked provenance, not the truth of a reviewer's assertions. Removing a review can downgrade a label on the next run.

## Deduplication and limitations

Canonical links discard tracking query parameters. Matching uses organisation, report window, actor and explicit incident dates; conflicting known actors/dates prevent automatic merging. A 30-day window is anchored to first report so an active cluster cannot grow indefinitely. Unicode organisation names are preserved. Clearly different victims in legacy claim-only clusters are split without deleting source evidence; original IDs are preserved for the original victim. Ambiguous matches and repeat incidents can still need editorial correction. No claim of perfect deduplication is made.

Public APIs and feed windows are finite. Private, undisclosed and login-protected services remain outside coverage. No direct Tor crawler, stolen-file collection or automatic publication of new onion addresses is included. Adding such a collector requires a separate runtime and source-specific collection policies.

## Validate and run

```sh
python -m unittest discover tests
node --check assets/incidents.js
python scripts/build_data.py --incidents-only
```

The incidents-only option refreshes news and incident monitoring without refreshing vulnerabilities; the normal workflow still runs the complete build. Fetches use bounded concurrency for feeds and retain failures explicitly.
