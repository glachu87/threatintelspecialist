// Today page: a short briefing built from the three data files.
(function () {
  "use strict";
  var T = window.TIS, h = T.h;
  var $ = function (id) { return document.getElementById(id); };
  $("today-date").textContent = T.date(new Date().toISOString());

  function get(name) { return T.data(name).catch(function () { return null; }); }

  Promise.all([get("news"), get("vulnerabilities"), get("incidents"), get("posts")]).then(function (r) {
    var news = r[0], vulns = r[1], inc = r[2], posts = r[3];
    var headlines = news ? news.items : [];
    var kev = vulns ? vulns.kev.items : [];
    var incidents = inc ? inc.incidents : [];

    /* the one-paragraph briefing */
    var brief = $("brief");
    var day = headlines.filter(function (n) { return T.daysSince(n.published) <= 1; }).length;
    var kevWeek = kev.filter(function (v) { return T.daysSince(v.added) <= 7; }).length;
    var incWeek = incidents.filter(function (i) { return T.daysSince(i.first_reported) <= 7; });
    var conf = incWeek.filter(function (i) { return i.evidence_state === "confirmed"; }).length;
    if (!news && !vulns && !inc) {
      brief.textContent = "Today's data could not be loaded. Reload the page to try again.";
    } else {
      brief.replaceChildren(
        h("b", { text: T.plural(day, "new headline") }), " in the last 24 hours. ",
        h("b", { text: T.plural(kevWeek, "vulnerability", "vulnerabilities") }),
        " added to the list of flaws attackers are actively using this week. ",
        h("b", { text: T.plural(incWeek.length, "incident") }), " reported this week",
        incWeek.length ? ", " + conf + " organisation-confirmed; the remaining records have other evidence states." : ".");
      var updated = (news && news.updated) || (vulns && vulns.updated);
      if (updated) $("fresh").textContent = "Data refreshed " + T.ago(updated) + ".";
    }

    /* incidents */
    var il = $("home-incidents");
    il.replaceChildren();
    incidents.slice(0, 6).forEach(function (i) {
      il.append(h("li", { class: "incident" },
        T.status(i.evidence_state || "unverified"),
        h("div", null,
          h("p", { class: "row-title" }, h("a", { href: "/incidents/?q=" + encodeURIComponent(i.id), text: i.title })),
          h("p", { class: "meta" },
            h("span", { text: i.type }),
            h("span", { text: T.ago(i.last_reported) }),
            h("span", { text: T.plural(i.sources.length, "source") })))));
    });
    if (!incidents.length) il.append(h("li", { class: "empty", text: inc ? "No incidents recorded yet. The tracker scans the news every hour." : "Incidents could not be loaded." }));

    /* exploited vulnerabilities */
    var kl = $("home-kev");
    kl.replaceChildren();
    kev.slice(0, 6).forEach(function (v) {
      kl.append(h("li", null,
        h("p", { class: "row-title" }, h("a", { href: "/vulnerabilities/?q=" + encodeURIComponent(v.cve), text: v.name || (v.vendor + " " + v.product) })),
        h("p", { class: "meta" },
          h("span", { class: "cve", text: v.cve }),
          h("span", { text: "added " + T.ago(v.added) }),
          v.ransomware ? h("span", { class: "flag danger", text: "Used by ransomware" }) : null)));
    });
    if (!kev.length) kl.append(h("li", { class: "empty", text: "The exploited-vulnerability list could not be loaded." }));

    /* headlines */
    var nl = $("home-news");
    nl.replaceChildren();
    headlines.slice(0, 10).forEach(function (n) {
      nl.append(h("li", null,
        h("p", { class: "row-title" }, T.ext(n.link, n.title)),
        h("p", { class: "meta" }, h("span", { text: n.source }), h("span", { text: T.ago(n.published) }))));
    });
    if (!headlines.length) nl.append(h("li", { class: "empty", text: "Headlines could not be loaded." }));

    /* writeups */
    var pl = $("home-posts");
    pl.replaceChildren();
    (posts ? posts.posts : []).slice(0, 3).forEach(function (p) {
      pl.append(h("li", null,
        h("p", { class: "row-title" }, h("a", { href: T.local(p.url), text: p.title })),
        h("p", { class: "meta" }, h("span", { text: T.date(p.date, true) }))));
    });
  });
})();
