"""Evidence policy and source monitoring. No Tor access or private-content collection.

Public labels require reviewable evidence; model/rule classifications alone are
never sufficient to confirm an incident or prove source independence.
"""
import hashlib
import json
import re
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode, quote

RECENT_URL = 'https://www.ransomlook.io/api/recent'
GROUPS_URL = 'https://www.ransomlook.io/api/groups'
LABELS = {'unverified': 'Unverified claim', 'corroborated': 'Corroborated report',
          'confirmed': 'Organisation-confirmed incident'}
GAPS = [
    'Coverage is limited to configured public feeds and APIs; it is not a census of cyber incidents.',
    'Onion disclosures are monitored indirectly through public aggregators. No direct Tor collector is running.',
    'Private, undisclosed and login-protected sources are not monitored.',
    'Recent feeds have finite windows. Downtime can leave historical gaps even after recovery.',
    'Missing incident dates remain unknown. Disclosure and discovery dates are not attack dates.',
    'Independent corroboration and organisation confirmation require reviewed evidence; AI labels alone do not qualify.',
]


def canonical_url(value):
    try:
        p = urlsplit(value or '')
        if p.scheme not in ('http', 'https') or not p.hostname or p.username or p.password:
            return ''
        query = [(k, v) for k, v in parse_qsl(p.query, keep_blank_values=True)
                 if not k.lower().startswith('utm_') and k.lower() not in ('fbclid', 'gclid')]
        return urlunsplit((p.scheme.lower(), p.netloc.lower(), p.path or '/', urlencode(sorted(query)), p.fragment))
    except ValueError:
        return ''


def stamp():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def date_only(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace('Z', '+00:00')).date().isoformat()
    except ValueError:
        return None


def collect_ransomlook(status, fetch, previous=None):
    """Consume only public post metadata; never fetch stolen files or screenshots."""
    now = stamp()
    items = []
    directory = {g['name']: dict(g) for g in (previous or {}).get('groups', [])}
    for name, url in [('RansomLook victim claims', RECENT_URL), ('RansomLook group discovery', GROUPS_URL)]:
        entry = {'name': name, 'url': url, 'checked': now, 'scope': 'incident'}
        try:
            payload = json.loads(fetch(url, timeout=25, retries=1))
            if not isinstance(payload, list):
                raise ValueError('Unexpected API schema: expected a list')
            if url == GROUPS_URL:
                if any(not isinstance(g, str) for g in payload):
                    raise ValueError('Unexpected group schema')
                for group in payload:
                    record = directory.setdefault(group, {'name': group, 'first_seen': now})
                    record.update(last_seen=now, provenance=url,
                                  url='https://www.ransomlook.io/group/' + quote(group, safe=''),
                                  monitoring='Indirect public-aggregator coverage; direct site not checked')
            else:
                for row in payload:
                    if not isinstance(row, dict) or not row.get('post_title') or not row.get('group_name') or not date_only(row.get('discovered')):
                        raise ValueError('Unexpected post schema: missing title, group or discovery date')
                for row in payload:
                    if row.get('private'):
                        continue
                    victim, actor = str(row['post_title']), str(row['group_name'])
                    discovered = str(row['discovered']).replace(' ', 'T')
                    if not re.search(r'(Z|[+-]\d\d:\d\d)$', discovered):
                        discovered += 'Z'
                    link = 'https://www.ransomlook.io/group/' + quote(actor, safe='')
                    key = str(row.get('misp_uuid') or (victim + '|' + actor + '|' + discovered))
                    items.append({'id': 'rlook-' + hashlib.sha256(key.encode()).hexdigest()[:20],
                                  'title': victim + ' by ' + actor, 'organisation': victim,
                                  'threat_actor': actor, 'kind': 'claim', 'source': name,
                                  'link': link, 'published': discovered,
                                  'published_basis': 'Aggregator first observed the post',
                                  'observed_at': now, 'claimed_incident_date': None,
                                  'summary': 'Public leak-site listing attributed to ' + actor + '; allegation not independently verified.',
                                  'topics': ['Ransomware'], 'origin_id': key})
            entry.update(ok=True, items=len(payload))
        except Exception as exc:
            entry.update(ok=False, error=str(exc)[:160])
        status['apis'].append(entry)
    return items, {'updated': now, 'groups': sorted(directory.values(), key=lambda g: g['name'].lower())}


def source_registry(config, status, previous=None):
    """Persist successes and outages across runs; zero-item responses are visible."""
    previous = previous or {}
    old = {s['name']: s for s in previous.get('sources', [])}
    definitions = {s['name']: s for s in config.get('feeds', [])}
    api_urls = {'Ransomware.live cyberattacks': 'https://api.ransomware.live/v2/allcyberattacks',
                'Ransomware.live victim claims': 'https://api.ransomware.live/v2/recentvictims'}
    current = status.get('feeds', []) + [s for s in status.get('apis', []) if s.get('name', '').startswith(('Ransomware.live', 'RansomLook'))]
    records = []
    for result in current:
        name = result['name']
        before = old.get(name, {})
        definition = definitions.get(name, {})
        checked = result.get('checked')
        healthy = result.get('ok') is True
        empty = healthy and result.get('items') == 0
        records.append({
            'name': name, 'url': result.get('url') or definition.get('url') or before.get('url') or api_urls.get(name, ''),
            'kind': definition.get('kind', 'discovery' if 'discovery' in name else 'aggregate'),
            'mode': 'Public RSS/Atom' if name in definitions else 'Public API',
            'checked': checked, 'last_success': checked if healthy else before.get('last_success'),
            'status': 'empty' if empty else 'ok' if healthy else 'error',
            'consecutive_failures': 0 if healthy else before.get('consecutive_failures', 0) + 1,
            'failure_since': None if healthy else before.get('failure_since') or checked,
            'items': result.get('items'), 'error': result.get('error', ''),
            'cadence_minutes': 30,
        })
    names = {r['name'] for r in records}
    for name, definition in definitions.items():
        if name not in names:
            records.append({**old.get(name, {}), 'name': name, 'url': definition['url'],
                            'status': 'not_checked', 'mode': 'Public RSS/Atom'})
    return {'updated': status.get('updated'), 'sources': records, 'gaps': GAPS}


def apply_evidence_policy(incidents, reviews=None, checked_sources=None):
    """Legacy labels are retained as extraction hints, not verification evidence.

    Reviews are repository-maintained records keyed by incident ID, containing
    source URL, reviewer, date, evidence excerpt, type and independent origin.
    """
    reviews = reviews or {}
    checked_sources = checked_sources or {}
    for incident in incidents:
        sources = incident.get('sources', [])
        unique = {}
        for src in sources:
            url = canonical_url(src.get('link'))
            key = (url, src.get('origin_id') or src.get('title') if src.get('kind') in ('claim', 'aggregate') else '')
            if not url:
                continue
            if key in unique:
                continue
            src['link'] = url
            # A feed check is not a check of every linked article.
            src['feed_last_checked'] = checked_sources.get(src.get('name'))
            unique[key] = src
        incident['sources'] = list(unique.values())
        allowed = {canonical_url(s.get('link')) for s in incident['sources']}
        accepted = []
        for review in reviews.get(incident['id'], []):
            if (canonical_url(review.get('url')) in allowed and review.get('reviewer')
                    and date_only(review.get('reviewed_at')) and review.get('excerpt')
                    and review.get('type') in ('organisation_statement', 'independent_report', 'denial')):
                accepted.append(review)
        confirmed = any(r['type'] == 'organisation_statement' for r in accepted)
        origins = {r['independent_origin'] for r in accepted
                   if r['type'] == 'independent_report' and r.get('independent_origin')}
        state = 'confirmed' if confirmed else 'corroborated' if len(origins) >= 2 else 'unverified'
        previous_state = incident.get('evidence_state')
        if previous_state != state:
            incident.setdefault('evidence_history', []).append({'date': stamp(), 'status': state,
                'note': 'Evidence policy applied' if previous_state is None else 'Reviewed evidence changed'})
        incident['evidence_state'] = state
        incident['evidence_label'] = LABELS[state]
        incident['evidence_reviews'] = accepted
        incident['disputed'] = any(r['type'] == 'denial' for r in accepted) or incident.get('status') == 'disputed'
        incident['evidence_basis'] = (
            'Reviewed acknowledgement by the affected organisation; see cited evidence.' if confirmed else
            'Reviewed reports with at least two independent evidence origins.' if state == 'corroborated' else
            'No reviewed organisation acknowledgement or independent corroboration recorded. This includes single-source reports.')
        dates = sorted({d for s in incident['sources'] if (d := date_only(s.get('claimed_incident_date')))})
        incident['claimed_incident_dates'] = dates
        incident['claimed_incident_date'] = dates[0] if len(dates) == 1 else None
        incident['incident_date_conflict'] = len(dates) > 1
        observed = [s['observed_at'] for s in incident['sources'] if s.get('observed_at')]
        incident['last_observed'] = max(observed) if observed else None
    return incidents


def repair_claim_clusters(incidents):
    """Split legacy clusters that incorrectly combined different named victims.

    Only deterministic 'victim by actor' claim-only records are repaired. Mixed
    reporting and ambiguous titles are retained for review, never silently split.
    """
    import copy
    output = []
    for incident in incidents:
        sources = incident.get('sources', [])
        if incident.get('curated') or not sources or not all(s.get('kind') == 'claim' and ' by ' in s.get('title', '') for s in sources):
            output.append(incident)
            continue
        groups = {}
        for source in sources:
            victim, actor = source['title'].rsplit(' by ', 1)
            key = (victim.casefold().strip(), actor.casefold().strip())
            groups.setdefault(key, []).append(source)
        if len(groups) < 2:
            output.append(incident)
            continue
        primary = (str(incident.get('organisation', '')).casefold().strip(),
                   str(incident.get('threat_actor', '')).casefold().strip())
        if primary not in groups:
            primary = next(iter(groups))
        for key, evidence in groups.items():
            entry = copy.deepcopy(incident)
            victim, actor = evidence[0]['title'].rsplit(' by ', 1)
            if key != primary:
                entry['id'] = 'INC-SPLIT-' + hashlib.sha256((incident['id'] + '|'.join(key)).encode()).hexdigest()[:12].upper()
            entry.update(organisation=victim, threat_actor=actor, title=victim + ' by ' + actor,
                         summary='Public leak-site claim attributed to ' + actor + '; not independently verified.',
                         sources=evidence, ai=False, status='claimed', sector='Other', country='',
                         why_it_matters='', split_from=incident['id'])
            dates = [s['published'] for s in evidence if s.get('published')]
            if dates:
                entry['first_reported'], entry['last_reported'] = min(dates), max(dates)
            entry['history'] = [{'date': stamp(), 'status': 'claimed', 'note': 'Separated different victims from a legacy claim cluster'}]
            output.append(entry)
    return output
