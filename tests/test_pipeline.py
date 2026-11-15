"""Offline tests for scripts/build_data.py.  Run:  python -m unittest discover tests"""
import json
import os
import sys
import tempfile
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

    def test_attacker_claim_is_claimed(self):
        r = self.label("Hackers claim breach of Globex, company investigating claims")
        self.assertEqual(r["status"], "claimed")
        self.assertEqual(r["basis"], bd.BASIS["claimed"])

    def test_doubt_in_title_beats_confirmation_in_summary(self):
        r = self.label("Initech allegedly breached, 2M records for sale", "The company confirmed it is looking into it.")
        self.assertEqual(r["status"], "claimed")

    def test_denial(self):
        r = self.label("Umbrella denies data breach after hacker post")
        self.assertEqual((r["status"], r["basis"]), ("disputed", bd.BASIS["disputed"]))

    def test_no_signal_defaults_to_reported(self):
        r = self.label("City of Springfield hit by cyberattack")
        self.assertEqual((r["status"], r["basis"], r["sector"]), ("reported", bd.BASIS["reported"], "Government"))

    def test_non_incidents_rejected(self):
        for title in ["Patch Tuesday fixes 80 flaws", "How to respond to a data breach",
                      "Critical flaw in FooVPN exploited in the wild", "Week in review: breaches and patches",
                      "New infostealer spreads through fake installers"]:
            self.assertIsNone(self.label(title), title)

    def test_realistic_headlines(self):
        cases = {"Jaguar Land Rover says cyberattack severely disrupted production": "confirmed",
                 "Qilin ransomware gang claims attack on Nissan design studio": "claimed",
                 "Police arrest suspect linked to airport check-in system ransomware attack": "confirmed",
                 "Asahi brewery restarts production after ransomware attack": "confirmed",
                 "Alleged breach of telecom giant: hacker puts 6M records up for sale": "claimed",
                 "Hackers steal $40 million from crypto exchange in hot wallet hack": "reported"}
        for title, status in cases.items():
            self.assertEqual(self.label(title)["status"], status, title)
        self.assertIsNone(self.label("New Android malware steals banking credentials via accessibility abuse"))

    def test_live_run_regressions(self):
        for title in ["White House AI Task Force Urges Leniency on Cyberattack Penalties",
                      "In Other News: New CISA Director Nominee, Connected Car Hacking, Baker Tilly Data Breach",
                      "Microsoft Cloud Outage Hits Outlook, Teams, Copilot and AI Services",
                      "Who Runs the Ransomware Group Qilin?",
                      "Operation Endgame Takes Down Gootloader Servers, Seizes 6.4M Stolen Logins",
                      "New Model Beats Rival in Multi-Stage Cyberattack Benchmark"]:
            self.assertIsNone(self.label(title), title)
        for title in ["City of Osaka warns of data breach impacting 1 million",
                      "Railway Says Stolen Customer AI Keys Led to $740,000 in Unauthorized Charges",
                      "Shipping giant Maersk probes 'IT security incident,' data theft"]:
            self.assertEqual(self.label(title)["status"], "confirmed", title)
        self.assertEqual(bd.extract_org("Uber Data Breach: Driver Licenses Stolen via Fireworks AI"), "Uber")

    def test_org_extraction_ignores_generic_subjects(self):
        self.assertIsNone(bd.extract_org("Hackers breach 20 banks in a week"))
        self.assertEqual(bd.extract_org("Ransomware attack on Wayne Enterprises halts production"), "Wayne Enterprises")
        self.assertEqual(bd.extract_org("Cyberattack at Acme disrupts services"), "Acme")

    def test_incident_signal_in_summary_is_not_lost(self):
        r = self.label("Acme issues customer update", "The company was hit by a ransomware attack and systems were taken offline.")
        self.assertIsNotNone(r)
        self.assertEqual(r["type"], "Ransomware")


class Incidents(unittest.TestCase):
    def news(self, n, title, hours_ago, summary="", kind="news", source="Feed A"):
        return {"id": f"n{n}", "title": title, "link": f"https://x.example/{n}", "source": source, "kind": kind,
                "published": bd.iso(NOW - timedelta(hours=hours_ago)), "summary": summary}

    def test_cluster_and_upgrade(self):
        first = [self.news(1, "Hackers claim breach of Globex, 3M records for sale", 30)]
        out = bd.merge_incidents({}, first, [], ai=lambda items: {})
        self.assertEqual(len(out["incidents"]), 1)
        self.assertEqual(out["incidents"][0]["status"], "claimed")

        second = first + [self.news(2, "Globex confirms data breach affecting 3M customers", 2, source="Feed B"),
                          self.news(3, "Vendor blog: tips for breach response", 1, kind="research")]
        out = bd.merge_incidents(out, second, [], ai=lambda items: {})
        self.assertEqual(len(out["incidents"]), 1)
        inc = out["incidents"][0]
        self.assertEqual(inc["status"], "confirmed")
        self.assertEqual(len(inc["sources"]), 2)
        self.assertEqual([h["status"] for h in inc["history"]], ["claimed", "confirmed"])
        self.assertEqual(out["upgraded_in_last_scan"], 1)

        again = bd.merge_incidents(out, second, [], ai=lambda items: {})
        self.assertEqual(len(again["incidents"][0]["sources"]), 2, "re-running must not duplicate sources")

    def test_related_headlines_group(self):
        items = [self.news(1, "Vanderbilt University reels following ransomware attack claimed by BYOD group", 9),
                 self.news(2, "Ransomware threat blares from Vanderbilt University computers during cyberattack", 3)]
        out = bd.merge_incidents({}, items, [], ai=lambda items: {})
        self.assertEqual(len(out["incidents"]), 1)

    def test_two_independent_reports_become_corroborated(self):
        items = [self.news(1, "Globex hit by cyberattack disrupting customer portal", 8, source="Feed A"),
                 self.news(2, "Cyberattack at Globex disrupts customer portal", 2, source="Feed B")]
        out = bd.merge_incidents({}, items, [], ai=lambda items: {})
        self.assertEqual(len(out["incidents"]), 1)
        self.assertEqual(out["incidents"][0]["status"], "corroborated")
        self.assertEqual(out["incidents"][0]["basis"], bd.BASIS["corroborated"])

    def test_claim_feed_is_early_warning_not_confirmation(self):
        item = self.news(9, "Acme Manufacturing by DarkCrew", 1, "Listed on the group's leak site.",
                         kind="claim", source="Ransomware.live")
        out = bd.merge_incidents({}, [item], [], ai=lambda items: {})
        self.assertEqual(len(out["incidents"]), 1)
        inc = out["incidents"][0]
        self.assertEqual((inc["status"], inc["type"], inc["organisation"], inc["threat_actor"]),
                         ("claimed", "Ransomware", "Acme Manufacturing", "DarkCrew"))

    def test_research_and_official_sources_can_contribute_incident_evidence(self):
        items = [self.news(1, "Acme hit by cyberattack disrupting services", 8, kind="research", source="Research Lab"),
                 self.news(2, "Cyberattack at Acme disrupts services", 2, kind="official", source="National CERT")]
        out = bd.merge_incidents({}, items, [], ai=lambda items: {})
        self.assertEqual(len(out["incidents"]), 1)
        self.assertEqual(out["incidents"][0]["status"], "corroborated")

    def test_articles_wait_for_ai_when_it_is_down(self):
        import os
        os.environ["GEMINI_API_KEY"] = "x"
        real = bd.classify_ai
        try:
            bd.classify_ai = lambda items: {}
            items = [self.news(1, "Hooli confirms data breach", 1), self.news(2, "Initech confirms data breach", 9)]
            out = bd.merge_incidents({}, items, [], ai=bd.classify_ai)
            self.assertEqual([i["organisation"] for i in out["incidents"]], ["Initech"], "only the old article falls back to rules")
            self.assertNotIn("n1", out["scanned"])
        finally:
            bd.classify_ai = real
            del os.environ["GEMINI_API_KEY"]

    def test_rule_entries_are_rechecked_when_ai_returns(self):
        import os
        items = [self.news(1, "Hooli confirms data breach", 20), self.news(2, "Globex hit by cyberattack", 19)]
        out = bd.merge_incidents({}, items, [], ai=lambda items: {})
        self.assertEqual(len(out["incidents"]), 2)
        ids = {i["organisation"]: i["id"] for i in out["incidents"]}
        os.environ["GEMINI_API_KEY"] = "x"
        real = bd.classify_ai
        try:
            bd.classify_ai = lambda cands: {
                ids["Hooli"]: {"is_incident": True, "organisation": "Hooli Inc", "type": "Ransomware", "sector": "Technology",
                               "status": "confirmed", "basis": bd.BASIS["official"], "summary": "AI summary.", "threat_actor": None, "ai": True},
                ids["Globex"]: {"is_incident": False}}
            out = bd.merge_incidents(out, items, [], ai=bd.classify_ai)
        finally:
            bd.classify_ai = real
            del os.environ["GEMINI_API_KEY"]
        self.assertEqual([(i["organisation"], i["type"], i["ai"], i["summary"]) for i in out["incidents"]],
                         [("Hooli Inc", "Ransomware", True, "AI summary.")])

    def test_rule_change_preserves_historical_entries(self):
        old = {"rules_version": 2, "scanned": [], "incidents": [{
            "id": "INC-OLD", "title": "Historical incident", "organisation": "Legacy Co",
            "status": "reported", "basis": "", "sources": [], "last_reported": "2024-01-01T00:00:00Z"
        }]}
        out = bd.merge_incidents(old, [self.news(1, "Hooli confirms data breach", 2)], [], ai=lambda items: {})
        self.assertEqual({i.get("organisation") for i in out["incidents"]}, {"Legacy Co", "Hooli"})
        self.assertEqual(out["rules_version"], bd.RULES_VERSION)

    def test_archive_backfill_is_cumulative_and_claim_only(self):
        csv_text = (
            "year,month,victim,threat_actor,date_discovered,description\n"
            "2025,january,Archive Victim,DarkCrew,\"Jan 31, 2025\",Archive description\n"
        )
        with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False, encoding="utf-8") as fh:
            fh.write(csv_text)
            path = fh.name
        try:
            out = bd.merge_incidents({}, [], [], ai=lambda items: {}, archive_path=path)
            self.assertEqual(out["archive_added_in_last_scan"], 1)
            self.assertEqual(len(out["incidents"]), 1)
            inc = out["incidents"][0]
            self.assertEqual((inc["organisation"], inc["status"], inc["type"], inc["threat_actor"]),
                             ("Archive Victim", "claimed", "Ransomware", "DarkCrew"))
            again = bd.merge_incidents(out, [], [], ai=lambda items: {}, archive_path=path)
            self.assertEqual(again["archive_added_in_last_scan"], 0)
            self.assertEqual(len(again["incidents"]), 1)
        finally:
            os.unlink(path)

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
        self.assertEqual((v["n1"]["status"], v["n1"]["type"], v["n1"]["summary"]), ("reported", "Cyberattack", "x"))
        self.assertEqual(bd.classify_ai([item], fetch_json=lambda prompt: "not json"), {})

    def test_ai_lessons_are_cleaned_and_stored(self):
        item = self.news(1, "Hooli hit by cyberattack", 3)
        reply = json.dumps([{"n": 1, "is_incident": True, "organisation": "Hooli", "type": "Ransomware", "sector": "Technology",
                             "status": "reported", "summary": "s", "lessons": ["Patch VPNs.", "", 7, "Second.", "Third."]}])
        v = bd.classify_ai([item], fetch_json=lambda prompt: reply)
        self.assertEqual(v["n1"]["lessons"], ["Patch VPNs.", "Second."])
        out = bd.merge_incidents({}, [item], [], ai=lambda items: v)
        self.assertEqual(out["incidents"][0]["lessons"], ["Patch VPNs.", "Second."])
        plain = bd.merge_incidents({}, [self.news(2, "Globex confirms data breach", 3)], [], ai=lambda items: {})
        self.assertNotIn("lessons", plain["incidents"][0], "no placeholder lessons are stored; the page supplies general advice")

    def test_ai_falls_through_providers(self):
        item = self.news(1, "Hooli hit by cyberattack", 3)
        reply = json.dumps([{"n": 1, "is_incident": True, "organisation": "Hooli", "type": "Ransomware",
                             "sector": "Technology", "status": "confirmed", "summary": "ok"}])
        tried = []
        def request(provider, prompt):
            tried.append(provider["name"])
            if provider["name"] == "first":
                raise RuntimeError("503")
            return reply
        provs = [{"name": "first", "kind": "github", "model": "m", "key": "k"}, {"name": "second", "kind": "gemini", "model": "m", "key": "k"}]
        v = bd.classify_ai([item, self.news(2, "Globex hit by cyberattack", 2)] * 6, providers=provs, request=request)
        self.assertEqual(v["n1"]["status"], "confirmed")
        self.assertEqual(tried.count("first"), 1, "a failing service is dropped for the rest of the run")
        self.assertEqual(bd.classify_ai([item], providers=[provs[0]], request=request), {})

    def test_provider_order(self):
        import os
        old = {k: os.environ.pop(k, None) for k in ("GITHUB_TOKEN", "GEMINI_API_KEY", "GITHUB_MODELS", "GITHUB_MODELS_MODEL", "GEMINI_MODEL")}
        try:
            self.assertEqual(bd.ai_providers(), [])
            os.environ["GITHUB_TOKEN"] = "t"; os.environ["GEMINI_API_KEY"] = "g"
            kinds = [p["kind"] for p in bd.ai_providers()]
            self.assertEqual(kinds[0], "github"); self.assertEqual(kinds[-1], "gemini")
            os.environ["GITHUB_MODELS"] = "off"
            self.assertEqual({p["kind"] for p in bd.ai_providers()}, {"gemini"})
        finally:
            for k, v in old.items():
                os.environ.pop(k, None)
                if v is not None:
                    os.environ[k] = v

    def test_curated_entries_win(self):
        curated = [{"id": "INC-CUR1", "title": "Curated", "status": "confirmed", "first_reported": "2021-05-08T00:00:00Z",
                    "sources": [{"name": "x", "link": "javascript:alert(1)"}, {"name": "y", "link": "https://ok.example"}]}]
        out = bd.merge_incidents({}, [], curated, ai=lambda items: {})
        self.assertEqual(len(out["incidents"][0]["sources"]), 1)
        self.assertTrue(out["incidents"][0]["curated"])


class NewsAndVulns(unittest.TestCase):
    def test_ransomware_live_json_sources(self):
        attacks = [{"date": "2026-11-01", "victim": "Acme", "country": "GB",
                    "summary": "Acme suffered a cyberattack.", "title": "Cyberattack at Acme disrupts services",
                    "url": "https://news.example/acme"}]
        victims = [{"victim": "Globex", "group": "DarkCrew", "country": "US",
                    "activity": "Technology", "discovered": "2026-11-02T10:00:00Z",
                    "description": "Listed on the leak site."}]
        def fetch(url, **kw):
            if "allcyberattacks" in url:
                return json.dumps(attacks).encode()
            if "recentvictims" in url:
                return json.dumps({"victims": victims}).encode()
            raise RuntimeError(url)
        status = {"feeds": [], "apis": []}
        rows = bd.collect_ransomware_live(status, fetch=fetch)
        self.assertEqual(len(rows), 2)
        self.assertEqual({r["kind"] for r in rows}, {"aggregate", "claim"})
        claim = next(r for r in rows if r["kind"] == "claim")
        self.assertEqual((claim["title"], claim["country"], claim["source_sector"]),
                         ("Globex by DarkCrew", "US", "Technology"))
        self.assertTrue(all(a["ok"] for a in status["apis"]))

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
        eukev = [{"cveID": "CVE-2026-0001", "vendorProject": "Foo", "product": "Bar", "dateReported": "2026/11/08", "patchedSince": "2026/11/05"},
                 {"cveID": "CVE-2026-0777", "vendorProject": "Acme", "product": "Router", "dateReported": "2026/10/01", "shortDescription": "EU only."},
                 {"cveID": "not-a-cve"}]
        def fetch(url, **kw):
            if "known_exploited" in url:
                return json.dumps(kev).encode()
            if "eukev" in url:
                return json.dumps(eukev).encode()
            if "cvelistV5" in url:
                if "CVE-2026-0777" in url:
                    raise RuntimeError("HTTP Error 404: Not Found")
                return json.dumps({"cveMetadata": {"datePublished": "2026-11-09T10:00:00.000Z"}}).encode()
            if "resultsPerPage=1&" in url:
                return json.dumps({"totalResults": 1234}).encode()
            if "feeds/json" in url:
                raise RuntimeError("feed down")
            if "nvd.nist" in url:
                return json.dumps(nvd).encode()
            return json.dumps({"data": [{"cve": "CVE-2026-0001", "epss": "0.91234"}]}).encode()
        bd.time.sleep = lambda s: None
        status = {"feeds": [], "apis": []}
        v = bd.collect_vulnerabilities({}, status, fetch=fetch)
        self.assertEqual(v["kev"]["total"], 2, "the EU-only entry is added")
        both = next(i for i in v["kev"]["items"] if i["cve"] == "CVE-2026-0001")
        self.assertEqual((both["catalogs"], both["eu_reported"], both["eu_patched"], both["added"], both["published"]),
                         (["CISA", "ENISA"], "2026-11-08", "2026-11-05", "2026-11-08", "2026-11-09"), "earliest listing wins")
        eu_only = next(i for i in v["kev"]["items"] if i["cve"] == "CVE-2026-0777")
        self.assertEqual((eu_only["catalogs"], eu_only["added"], "published" in eu_only), (["ENISA"], "2026-10-01", False))
        self.assertEqual(len(v["trend"]), bd.TREND_WEEKS)
        self.assertEqual(sum(w["exploited"] for w in v["trend"]), 2)
        self.assertEqual(sum(1 for w in v["trend"] if w["published"] == 1234), bd.WEEK_COUNTS_PER_RUN, "weekly totals are filled a few per run")
        self.assertTrue(bd.cve_record_url("CVE-2021-44228").endswith("/2021/44xxx/CVE-2021-44228.json"))
        self.assertTrue(bd.cve_record_url("CVE-2026-123039").endswith("/2026/123xxx/CVE-2026-123039.json"))
        self.assertTrue(bd.cve_record_url("CVE-2019-0708").endswith("/2019/0xxx/CVE-2019-0708.json"))
        self.assertTrue(v["kev"]["items"][0]["ransomware"])
        self.assertNotIn("action", v["kev"]["items"][0])
        self.assertEqual([i["cve"] for i in v["recent"]["items"]], ["CVE-2026-0001"])
        self.assertTrue(v["recent"]["items"][0]["kev"])
        self.assertEqual(v["recent"]["items"][0]["epss"], 0.9123)
        self.assertTrue(all(a["ok"] for a in status["apis"]))

        seen = []
        def picky(url, headers=None, **kw):
            if "feeds/json" in url:
                raise RuntimeError("feed down")
            if "nvd.nist" in url:
                seen.append(url)
                if headers:
                    raise RuntimeError(url + ": HTTP Error 404: Not Found")
                return json.dumps(nvd).encode()
            return fetch(url)
        os.environ["NVD_API_KEY"] = "expired"
        try:
            again = bd.collect_vulnerabilities({}, {"feeds": [], "apis": []}, fetch=picky)
        finally:
            del os.environ["NVD_API_KEY"]
        self.assertEqual(len(again["recent"]["items"]), 1, "falls back to keyless NVD requests")
        self.assertNotIn("Z&", seen[0])
        self.assertRegex(seen[0], r"pubStartDate=\d{4}-\d\d-\d\dT\d\d%3A\d\d%3A\d\d\.000&")

        recent = (bd.now_utc() - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%S.000")
        old = (bd.now_utc() - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%S.000")
        feed = {"vulnerabilities": [dict(nvd["vulnerabilities"][0], cve=dict(nvd["vulnerabilities"][0]["cve"], published=recent)),
                                    dict(nvd["vulnerabilities"][0], cve=dict(nvd["vulnerabilities"][0]["cve"], id="CVE-2026-0009", published=old))]}
        calls = []
        def feed_only(url, **kw):
            calls.append(url)
            if "feeds/json" in url:
                return json.dumps(feed).encode()
            raise RuntimeError("API must not be called when the feed works")
        self.assertEqual([i["cve"] for i in bd.fetch_nvd(feed_only)], ["CVE-2026-0001"], "feed is used and filtered to the last week")
        self.assertEqual(len(calls), 1)

        def broken(url, **kw):
            raise RuntimeError("offline")
        kept = bd.collect_vulnerabilities(v, {"feeds": [], "apis": []}, fetch=broken)
        self.assertEqual(kept["kev"]["total"], 2, "old data is kept when sources fail")
        self.assertEqual(sorted(i["catalogs"] for i in kept["kev"]["items"]), [["CISA", "ENISA"], ["ENISA"]])


if __name__ == "__main__":
    unittest.main()
