"""Offline tests for scripts/build_data.py.  Run:  python -m unittest discover tests"""
import json
import os
import sys
import unittest
from datetime import timedelta

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))
import build_data as bd  # noqa: E402

NOW = bd.now_utc()


def rfc822(dt):
    return dt.strftime("%a, %d %b %Y %H:%M:%S +0000")


RSS = f"""<?xml version="1.0"?><rss version="2.0" xmlns:content="http://purl.org/rss/1.0/modules/content/"><channel>
<item><title>Acme Corp confirms ransomware attack disrupted orders</title><link>https://news.example/acme</link>
<pubDate>{rfc822(NOW - timedelta(hours=5))}</pubDate>
<description><![CDATA[<p>Acme said <b>systems</b> were taken offline.</p><script>alert(1)</script>]]></description></item>
<item><title>&lt;img src=x onerror=alert(1)&gt; Patch Tuesday fixes 80 flaws</title><link>javascript:alert(1)</link></item>
<item><title>Patch Tuesday fixes 80 flaws</title><link>https://news.example/patch</link>
<pubDate>{rfc822(NOW - timedelta(hours=6))}</pubDate><description>Monthly updates.</description></item>
</channel></rss>""".encode()

ATOM = f"""<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom">
<entry><title>Hackers claim breach of Globex, company investigating claims</title>
<link rel="alternate" href="https://other.example/globex"/><link rel="replies" href="https://other.example/c"/>
<published>{bd.iso(NOW - timedelta(hours=2))}</published><summary>A post on a leak site lists Globex.</summary></entry>
</feed>""".encode()


class FeedParsing(unittest.TestCase):
    def test_rss_is_cleaned_and_unsafe_links_dropped(self):
        items = bd.parse_feed(RSS)
        self.assertEqual([i["link"] for i in items], ["https://news.example/acme", "https://news.example/patch"])
        self.assertEqual(items[0]["summary"], "Acme said systems were taken offline.")
        self.assertNotIn("<", items[0]["summary"])

    def test_atom_prefers_alternate_link(self):
        items = bd.parse_feed(ATOM)
        self.assertEqual(items[0]["link"], "https://other.example/globex")
        self.assertIsNotNone(items[0]["published"])

    def test_dates(self):
        self.assertEqual(bd.iso(bd.parse_date("Mon, 02 Nov 2026 14:00:00 +0000")), "2026-11-02T14:00:00Z")
        self.assertEqual(bd.iso(bd.parse_date("2026-11-02T14:00:00+01:00")), "2026-11-02T13:00:00Z")
        self.assertIsNone(bd.parse_date("not a date"))


class Classification(unittest.TestCase):
    def label(self, title, summary=""):
        return bd.classify_rules({"title": title, "summary": summary})

    def test_confirmed(self):
        r = self.label("Acme Corp confirms ransomware attack disrupted orders")
        self.assertEqual((r["status"], r["type"], r["organisation"]), ("confirmed", "Ransomware", "Acme Corp"))

    def test_attacker_claim_is_unconfirmed(self):
        r = self.label("Hackers claim breach of Globex, company investigating claims")
        self.assertEqual(r["status"], "unconfirmed")
        self.assertEqual(r["basis"], bd.BASIS["claim"])

    def test_doubt_in_title_beats_confirmation_in_summary(self):
        r = self.label("Initech allegedly breached, 2M records for sale", "The company confirmed it is looking into it.")
        self.assertEqual(r["status"], "unconfirmed")

    def test_denial(self):
        self.assertEqual(self.label("Umbrella denies data breach after hacker post")["basis"], bd.BASIS["denied"])

    def test_no_signal_defaults_to_unconfirmed(self):
        r = self.label("City of Springfield hit by cyberattack")
        self.assertEqual((r["status"], r["basis"], r["sector"]), ("unconfirmed", bd.BASIS["press"], "Government"))

    def test_non_incidents_rejected(self):
        for title in ["Patch Tuesday fixes 80 flaws", "How to respond to a data breach",
                      "Critical flaw in FooVPN exploited in the wild", "Week in review: breaches and patches",
                      "New infostealer spreads through fake installers"]:
            self.assertIsNone(self.label(title), title)

    def test_realistic_headlines(self):
        cases = {"Jaguar Land Rover says cyberattack severely disrupted production": "confirmed",
                 "Qilin ransomware gang claims attack on Nissan design studio": "unconfirmed",
                 "Police arrest suspect linked to airport check-in system ransomware attack": "confirmed",
                 "Asahi brewery restarts production after ransomware attack": "confirmed",
                 "Alleged breach of telecom giant: hacker puts 6M records up for sale": "unconfirmed",
                 "Hackers steal $40 million from crypto exchange in hot wallet hack": "unconfirmed"}
        for title, status in cases.items():
            self.assertEqual(self.label(title)["status"], status, title)
        self.assertIsNone(self.label("New Android malware steals banking credentials via accessibility abuse"))

    def test_org_extraction_ignores_generic_subjects(self):
        self.assertIsNone(bd.extract_org("Hackers breach 20 banks in a week"))
        self.assertEqual(bd.extract_org("Ransomware attack on Wayne Enterprises halts production"), "Wayne Enterprises")


class Incidents(unittest.TestCase):
    def news(self, n, title, hours_ago, summary="", kind="news", source="Feed A"):
        return {"id": f"n{n}", "title": title, "link": f"https://x.example/{n}", "source": source, "kind": kind,
                "published": bd.iso(NOW - timedelta(hours=hours_ago)), "summary": summary}

    def test_cluster_and_upgrade(self):
        first = [self.news(1, "Hackers claim breach of Globex, 3M records for sale", 30)]
        out = bd.merge_incidents({}, first, [], ai=lambda items: {})
        self.assertEqual(len(out["incidents"]), 1)
        self.assertEqual(out["incidents"][0]["status"], "unconfirmed")

        second = first + [self.news(2, "Globex confirms data breach affecting 3M customers", 2, source="Feed B"),
                          self.news(3, "Vendor blog: tips for breach response", 1, kind="research")]
        out = bd.merge_incidents(out, second, [], ai=lambda items: {})
        self.assertEqual(len(out["incidents"]), 1)
        inc = out["incidents"][0]
        self.assertEqual(inc["status"], "confirmed")
        self.assertEqual(len(inc["sources"]), 2)
        self.assertEqual([h["status"] for h in inc["history"]], ["unconfirmed", "confirmed"])
        self.assertEqual(out["upgraded_in_last_scan"], 1)

        again = bd.merge_incidents(out, second, [], ai=lambda items: {})
        self.assertEqual(len(again["incidents"][0]["sources"]), 2, "re-running must not duplicate sources")

    def test_confirmed_never_downgrades(self):
        items = [self.news(1, "Globex confirms data breach affecting 3M customers", 20),
                 self.news(2, "Globex breach: hackers claim far more data stolen", 1)]
        out = bd.merge_incidents({}, items, [], ai=lambda items: {})
        self.assertEqual(out["incidents"][0]["status"], "confirmed")

    def test_ai_verdict_overrides_rules(self):
        items = [self.news(1, "Hooli hit by cyberattack", 3), self.news(2, "Pied Piper suffers outage", 2)]
        def fake_ai(cands):
            return {"n1": {"is_incident": True, "organisation": "Hooli", "type": "Ransomware", "sector": "Technology",
                           "status": "confirmed", "basis": bd.BASIS["official"], "summary": "Hooli said so.",
                           "threat_actor": None, "ai": True},
                    "n2": {"is_incident": False}}
        out = bd.merge_incidents({}, items, [], ai=fake_ai)
        self.assertEqual([(i["organisation"], i["status"], i["ai"]) for i in out["incidents"]], [("Hooli", "confirmed", True)])

    def test_ai_response_parsing(self):
        item = self.news(1, "Hooli hit by cyberattack", 3)
        reply = json.dumps([{"n": 1, "is_incident": True, "organisation": "Hooli", "type": "Nonsense",
                             "sector": "Technology", "status": "maybe", "summary": "<b>x</b>"}])
        v = bd.classify_ai([item], fetch_json=lambda prompt: "```json\n" + reply + "\n```")
        self.assertEqual((v["n1"]["status"], v["n1"]["type"], v["n1"]["summary"]), ("unconfirmed", "Cyberattack", "x"))
        self.assertEqual(bd.classify_ai([item], fetch_json=lambda prompt: "not json"), {})

    def test_curated_entries_win(self):
        curated = [{"id": "INC-CUR1", "title": "Curated", "status": "confirmed", "first_reported": "2021-05-08T00:00:00Z",
                    "sources": [{"name": "x", "link": "javascript:alert(1)"}, {"name": "y", "link": "https://ok.example"}]}]
        out = bd.merge_incidents({}, [], curated, ai=lambda items: {})
        self.assertEqual(len(out["incidents"][0]["sources"]), 1)
        self.assertTrue(out["incidents"][0]["curated"])


class NewsAndVulns(unittest.TestCase):
    def test_collect_news_survives_a_dead_feed(self):
        def fetch(url, **kw):
            if "dead" in url:
                raise RuntimeError("boom")
            return RSS if "rss" in url else ATOM
        status = {"feeds": [], "apis": []}
        srcs = [{"name": "A", "url": "https://a/rss", "kind": "news"}, {"name": "B", "url": "https://b/atom", "kind": "news"},
                {"name": "C", "url": "https://c/dead", "kind": "news"}]
        news = bd.collect_news(srcs, {}, status, fetch=fetch)
        self.assertEqual(len(news["items"]), 3)
        self.assertEqual([f["ok"] for f in status["feeds"]], [True, True, False])
        self.assertIn("Ransomware", news["items"][-2]["topics"] + news["items"][-1]["topics"] + news["items"][0]["topics"])
        again = bd.collect_news(srcs, news, {"feeds": [], "apis": []}, fetch=fetch)
        self.assertEqual(len(again["items"]), 3)

    def test_vulnerabilities(self):
        kev = {"catalogVersion": "1", "vulnerabilities": [
            {"cveID": "CVE-2026-0001", "vendorProject": "Foo", "product": "Bar", "vulnerabilityName": "Foo Bar RCE",
             "dateAdded": "2026-11-10", "dueDate": "2026-12-01", "shortDescription": "Bad.",
             "requiredAction": "Apply mitigations per vendor instructions or discontinue.", "knownRansomwareCampaignUse": "Known"},
            {"cveID": "bogus"}]}
        nvd = {"resultsPerPage": 2, "totalResults": 2, "vulnerabilities": [
            {"cve": {"id": "CVE-2026-0001", "published": "2026-11-09T10:00:00.000", "descriptions": [{"lang": "en", "value": "RCE"}],
                     "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL", "attackVector": "NETWORK"}}]}}},
            {"cve": {"id": "CVE-2026-0002", "published": "2026-11-09T10:00:00.000", "descriptions": [],
                     "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 5.0, "baseSeverity": "MEDIUM"}}]}}}]}
        def fetch(url, **kw):
            if "known_exploited" in url:
                return json.dumps(kev).encode()
            if "nvd.nist" in url:
                return json.dumps(nvd).encode()
            return json.dumps({"data": [{"cve": "CVE-2026-0001", "epss": "0.91234"}]}).encode()
        bd.time.sleep = lambda s: None
        status = {"feeds": [], "apis": []}
        v = bd.collect_vulnerabilities({}, status, fetch=fetch)
        self.assertEqual(v["kev"]["total"], 1)
        self.assertTrue(v["kev"]["items"][0]["ransomware"])
        self.assertNotIn("action", v["kev"]["items"][0])
        self.assertEqual([i["cve"] for i in v["recent"]["items"]], ["CVE-2026-0001"])
        self.assertTrue(v["recent"]["items"][0]["kev"])
        self.assertEqual(v["recent"]["items"][0]["epss"], 0.9123)
        self.assertTrue(all(a["ok"] for a in status["apis"]))

        def broken(url, **kw):
            raise RuntimeError("offline")
        kept = bd.collect_vulnerabilities(v, {"feeds": [], "apis": []}, fetch=broken)
        self.assertEqual(kept["kev"]["total"], 1, "old data is kept when sources fail")


if __name__ == "__main__":
    unittest.main()
