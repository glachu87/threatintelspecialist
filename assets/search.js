(function () {
  "use strict";
  var T = window.TIS, h = T.h;
  var out = document.getElementById("results"), q = T.param("q").trim();
  var box = document.getElementById("q");
  box.value = q;
  if (!q) { out.replaceChildren(h("p", { class: "empty", text: "Type a company, product, CVE number or topic above." })); return; }
  document.title = "“" + q + "” — search — Threat Intel Specialist";

  function get(name) { return T.data(name).catch(function () { return null; }); }
  function section(title, href, items, render) {
    if (!items.length) return null;
    return h("section", { class: "lane" },
      h("div", { class: "lane-head" }, h("h2", { text: title + " (" + items.length + ")" }), h("a", { href: href, text: "Open in " + title })),
      h("ul", { class: "rows" }, items.slice(0, 8).map(render)));
  }

  Promise.all([get("incidents"), get("vulnerabilities"), get("news"), get("posts")]).then(function (r) {
    var e = encodeURIComponent(q);
    var inc = (r[0] ? r[0].incidents : []).filter(function (i) { return T.matches([i.title, i.organisation, i.summary, i.type, i.threat_actor].join(" "), q); });
    var kev = (r[1] ? r[1].kev.items : []).filter(function (v) { return T.matches([v.cve, v.name, v.vendor, v.product, v.description].join(" "), q); });
    var recent = (r[1] ? r[1].recent.items : []).filter(function (v) { return T.matches(v.cve + " " + v.description, q); });
    var news = (r[2] ? r[2].items : []).filter(function (n) { return T.matches(n.title + " " + n.summary, q); });
    var posts = (r[3] ? r[3].posts : []).filter(function (p) { return T.matches(p.title + " " + p.summary + " " + (p.tags || []).join(" "), q); });
    var total = inc.length + kev.length + recent.length + news.length + posts.length;
    out.replaceChildren(
      h("p", { class: "count", text: total ? T.plural(total, "result") + " for “" + q + "”" : "" }),
      section("Incidents", "/incidents/?q=" + e, inc, function (i) {
        return h("li", { class: "incident" }, T.status(i.evidence_state || "unverified"), h("div", null,
          h("p", { class: "row-title" }, h("a", { href: "/incidents/?q=" + encodeURIComponent(i.id), text: i.title })),
          h("p", { class: "meta" }, h("span", { text: i.type }), h("span", { text: T.date(i.first_reported, true) }))));
      }),
      section("Vulnerabilities", "/vulnerabilities/?q=" + e, kev.concat(recent), function (v) {
        return h("li", null,
          h("p", { class: "row-title" }, h("a", { href: "/vulnerabilities/?q=" + encodeURIComponent(v.cve), text: v.name || v.description.slice(0, 110) })),
          h("p", { class: "meta" }, h("span", { class: "cve", text: v.cve }), v.added ? h("span", { class: "flag danger", text: "Being exploited" }) : h("span", { text: v.severity + " " + v.score })));
      }),
      section("News", "/news/?q=" + e, news, function (n) {
        return h("li", null, h("p", { class: "row-title" }, T.ext(n.link, n.title)),
          h("p", { class: "meta" }, h("span", { text: n.source }), h("span", { text: T.ago(n.published) })));
      }),
      section("Blog", "/blog/", posts, function (p) {
        return h("li", null, h("p", { class: "row-title" }, h("a", { href: T.local(p.url), text: p.title })), h("p", { class: "meta" }, h("span", { text: T.date(p.date, true) })));
      }),
      total ? null : h("p", { class: "empty" }, "Nothing found for “" + q + "”. Check the spelling, or try a shorter term such as a company or product name. News is kept for 45 days; incidents and exploited vulnerabilities are kept indefinitely."));
  });
})();
