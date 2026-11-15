import copy
import json
import os
import sys
import unittest
from datetime import datetime, timezone
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), 'scripts'))
import incident_monitor as m
import build_data as b

class EvidencePolicy(unittest.TestCase):
    def incident(self):
        return {'id': 'INC-X', 'status': 'confirmed', 'organisation': 'Example', 'sources': [
            {'name': 'A', 'link': 'https://example.com/statement', 'verification': 'confirmed', 'kind': 'news'},
            {'name': 'B', 'link': 'https://another.example/report', 'verification': 'reported', 'kind': 'news'}]}

    def review(self, url='https://example.com/statement', kind='independent_report', origin='original interview'):
        return {'url': url, 'type': kind, 'reviewer': 'Test reviewer', 'reviewed_at': '2026-11-15',
                'excerpt': 'Evidence excerpt', 'independent_origin': origin}

    def test_headline_confirmation_does_not_confirm(self):
        incident = self.incident()
        m.apply_evidence_policy([incident])
        self.assertEqual(incident['evidence_state'], 'unverified')
        self.assertIsNone(incident['claimed_incident_date'])

    def test_repeat_claim_is_not_corroboration(self):
        i = self.incident()
        r = [self.review(), self.review('https://another.example/report')]
        m.apply_evidence_policy([i], {'INC-X': r})
        self.assertEqual(i['evidence_state'], 'unverified')
        r[1]['independent_origin'] = 'independent technical investigation'
        m.apply_evidence_policy([i], {'INC-X': r})
        self.assertEqual(i['evidence_state'], 'corroborated')

    def test_confirmation_requires_review_and_cited_statement(self):
        i = self.incident()
        r = self.review(kind='organisation_statement')
        r['url'] = 'https://unrelated.example/nope'
        m.apply_evidence_policy([i], {'INC-X': [r]})
        self.assertEqual(i['evidence_state'], 'unverified')
        r['url'] = i['sources'][0]['link']
        m.apply_evidence_policy([i], {'INC-X': [r]})
        self.assertEqual(i['evidence_state'], 'confirmed')
        m.apply_evidence_policy([i], {'INC-X': [r]})
        self.assertEqual(len(i['evidence_history']), 2)

    def test_conflicting_dates_preserved(self):
        i = self.incident()
        for source, date in zip(i['sources'], ['2026-11-01', '2026-11-02']):
            source['claimed_incident_date'] = date
        m.apply_evidence_policy([i])
        self.assertTrue(i['incident_date_conflict'])
        self.assertIsNone(i['claimed_incident_date'])
        self.assertEqual(len(i['claimed_incident_dates']), 2)

    def test_canonical_dedupe_and_unsafe_links(self):
        i = self.incident()
        i['sources'] += [dict(i['sources'][0], link='https://example.com/statement?utm_source=repeat'),
                         {'link': 'javascript:alert(1)'}, {'link': 'http://user:pass@example.com/'}]
        m.apply_evidence_policy([i])
        self.assertEqual(len(i['sources']), 2)

    def test_same_organisation_different_attack_not_merged(self):
        i = {'organisation': 'Example', 'title': 'Example attack', 'first_reported': '2026-11-01',
             'last_reported': '2026-11-15', 'threat_actor': 'Actor A',
             'sources': [{'claimed_incident_date': '2026-11-01'}]}
        now = datetime(2026, 11, 15, tzinfo=timezone.utc)
        self.assertFalse(b.same_incident(i, i['title'], 'Example', now, 'Actor B'))
        self.assertFalse(b.same_incident(i, i['title'], 'Example', now, 'Actor A', '2026-11-02'))
        self.assertFalse(b.same_incident(i, i['title'], 'Other Example', now))

class LegacyRepair(unittest.TestCase):
    def test_distinct_claim_victims_split_once_without_losing_evidence(self):
        old = {'id': 'INC-OLD', 'organisation': 'One', 'threat_actor': 'Actor', 'sources': [
            {'kind': 'claim', 'title': 'One by Actor', 'link': 'https://example.com/1', 'published': '2026-11-01'},
            {'kind': 'claim', 'title': 'Two by Actor', 'link': 'https://example.com/2', 'published': '2026-11-02'}]}
        split = m.repair_claim_clusters([old])
        self.assertEqual({i['organisation'] for i in split}, {'One', 'Two'})
        self.assertEqual(sum(len(i['sources']) for i in split), 2)
        self.assertEqual(split, m.repair_claim_clusters(split))
        self.assertEqual(split[0]['id'], 'INC-OLD')

class Monitoring(unittest.TestCase):
    def test_failure_keeps_success_and_empty_is_visible(self):
        config = {'feeds': [{'name': 'Feed', 'url': 'https://example.com/feed'}]}
        success = {'feeds': [{'name': 'Feed', 'checked': '2026-11-01', 'ok': True, 'items': 1}]}
        old = m.source_registry(config, success)
        failure = {'feeds': [{'name': 'Feed', 'checked': '2026-11-02', 'ok': False, 'error': 'timeout'}]}
        failed = m.source_registry(config, failure, old)['sources'][0]
        self.assertEqual(failed['last_success'], '2026-11-01')
        self.assertEqual(failed['status'], 'error')
        self.assertEqual(failed['consecutive_failures'], 1)
        success['feeds'][0]['items'] = 0
        self.assertEqual(m.source_registry(config, success)['sources'][0]['status'], 'empty')

    def test_public_metadata_only_and_no_discovery_as_attack_date(self):
        def fetch(url, **kwargs):
            if url == m.GROUPS_URL:
                return json.dumps(['Example Group']).encode()
            return json.dumps([{'post_title': 'Example', 'group_name': 'Example Group',
                                'discovered': '2026-11-15 09:00:00', 'description': 'Secret data',
                                'screen': '/screenshot', 'magnet': 'magnet:payload'}]).encode()
        status = {'apis': []}
        items, groups = m.collect_ransomlook(status, fetch)
        self.assertIsNone(items[0]['claimed_incident_date'])
        self.assertEqual(items[0]['kind'], 'claim')
        self.assertNotIn('Secret data', json.dumps(items))
        self.assertNotIn('magnet:', json.dumps(items))
        self.assertEqual(len(groups['groups']), 1)
        self.assertTrue(all(s['ok'] for s in status['apis']))

    def test_schema_failure_retains_directory(self):
        previous = {'groups': [{'name': 'Known', 'first_seen': '2026-11-01'}]}
        status = {'apis': []}
        items, groups = m.collect_ransomlook(status, lambda *a, **k: b'{}', previous)
        self.assertFalse(any(s['ok'] for s in status['apis']))
        self.assertEqual(items, [])
        self.assertEqual(groups['groups'], previous['groups'])

    def test_no_private_posts(self):
        payload = [{'post_title': 'Private', 'group_name': 'Group', 'discovered': '2026-11-15', 'private': True}]
        items, _ = m.collect_ransomlook({'apis': []}, lambda u, **k: json.dumps([] if u == m.GROUPS_URL else payload).encode())
        self.assertEqual(items, [])
