(function () {
  "use strict";
  var T = window.TIS, h = T.h;
  var $ = function (id) { return document.getElementById(id); };
  var q = $("q"), list = $("list"), more = $("more"), count = $("count");
  var tabKev = $("tab-kev"), tabNew = $("tab-new"), tabTrends = $("tab-trends"), ransom = $("ransom"), ransomWrap = $("ransom-wrap"), sev = $("sev"), sevWrap = $("sev-wrap");
  var zero = $("zero"), zeroWrap = $("zero-wrap"), first = $("first"), firstWrap = $("first-wrap");
  var data = null, tab = "kev", SVG = "http://www.w3.org/2000/svg";
  var MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

  function num(n) { return Number(n).toLocaleString("en-GB"); }
  function dayNumber(d) { return Math.round(Date.parse(d.slice(0, 10) + "T00:00:00Z") / 864e5); }
  /* Days from the CVE record's publication to the first exploited listing; null if unknown. */
  function lag(v) { return v.published && v.added ? dayNumber(v.added) - dayNumber(v.published) : null; }
  function byDisclosure(v) { var d = lag(v); return d !== null && d <= 0; }
  /* This site's own priority rating for newly published flaws. */
  function priority(v) {
    if (v.kev) return "Urgent";
    if ((v.epss_pct != null && v.epss_pct >= 0.95) || (v.severity === "Critical" && v.vector === "Network")) return "High";
    return "";
  }
  function catalogs(v) { return v.catalogs && v.catalogs.length ? v.catalogs : ["CISA"]; }
  function lagText(v) {
    var d = lag(v);
    if (d === null) return "";
    if (d === 0) return " (the day the CVE record was published)";
    return d > 0 ? " (" + num(d) + (d === 1 ? " day" : " days") + " after the CVE record was published)"
                 : " (" + num(-d) + (d === -1 ? " day" : " days") + " before the CVE record was published)";
  }

  function pct(x) { return x >= 0.1 ? Math.round(x * 100) + "%" : (x * 100).toFixed(1) + "%"; }
  function links(cve) {
    return h("p", null,
      T.ext("https://nvd.nist.gov/vuln/detail/" + cve, "NVD entry"), " · ",
      T.ext("https://www.cve.org/CVERecord?id=" + cve, "CVE record"));
  }
  function epss(v) {
    return v.epss == null ? null : [h("dt", { text: "Chance of attack" }), h("dd", { text: pct(v.epss) + " likelihood of exploitation in the next 30 days (EPSS)" })];
  }

  function kevRow(v) {
    return h("details", { class: "vuln" },
      h("summary", null,
        h("span", null, h("span", { class: "cve", text: v.cve }), h("span", { class: "when", text: "Listed " + T.date(v.added, true) })),
        h("span", null,
          h("span", { class: "row-title", text: v.name || v.vendor + " " + v.product }),
          h("span", { class: "meta" }, h("span", { text: v.vendor + " · " + v.product }),
            v.ransomware ? h("span", { class: "flag danger", text: "Used by ransomware" }) : null,
            byDisclosure(v) ? h("span", { class: "flag danger", text: "Exploited by disclosure day" }) : null,
            catalogs(v).length > 1 ? h("span", { class: "flag plain", text: "Listed by " + catalogs(v).join(" and ") }) : null,
            catalogs(v).join() === "ENISA" ? h("span", { class: "flag plain", text: "Listed by ENISA only" }) : null))),
      h("div", { class: "vuln-body" },
        v.description ? h("p", { text: v.description }) : null,
        h("dl", null,
          v.published ? [h("dt", { text: "Published" }), h("dd", { text: T.date(v.published, true) })] : null,
          h("dt", { text: "Listed as exploited" }), h("dd", { text: T.date(v.added, true) + lagText(v) + ", by " + catalogs(v).join(" and ") }),
          v.eu_patched ? [h("dt", { text: "Fix available since" }), h("dd", { text: T.date(v.eu_patched, true) + " (per ENISA)" })] : null,
          h("dt", { text: "What to do" }), h("dd", { text: v.action || "Apply the vendor's update or mitigation. If none exists, stop using the product." }),
          v.due ? [h("dt", { text: "US agency deadline" }), h("dd", { text: T.date(v.due, true) })] : null,
          epss(v)),
        links(v.cve)));
  }

  function newRow(v) {
    return h("details", { class: "vuln" },
      h("summary", null,
        h("span", null, h("span", { class: "cve", text: v.cve }), h("span", { class: "when", text: "Published " + T.date(v.published, true) })),
        h("span", null,
          h("span", { class: "row-title", text: v.description.length > 140 ? v.description.slice(0, 140).replace(/\s+\S*$/, "") + "…" : v.description }),
          h("span", { class: "meta" },
            h("span", { class: "flag " + (v.severity === "Critical" ? "danger" : "plain"), text: v.severity + " " + v.score }),
            priority(v) ? h("span", { class: "flag " + (priority(v) === "Urgent" ? "danger" : "warn"), text: priority(v) + " priority" }) : null,
            v.kev ? h("span", { class: "flag danger", text: "Being exploited" }) : null,
            v.vector ? h("span", { text: "Attack route: " + v.vector.toLowerCase() }) : null))),
      h("div", { class: "vuln-body" },
        h("p", { text: v.description }),
        h("dl", null,
          h("dt", { text: "Severity" }), h("dd", { text: v.severity + ", " + v.score + " out of 10 (CVSS " + v.cvss_version + ")" }),
          epss(v),
          v.epss_pct != null ? [h("dt", { text: "Compared with others" }), h("dd", { text: "More likely to be attacked than " + Math.floor(v.epss_pct * 100) + "% of all known flaws" })] : null),
        links(v.cve)));
  }

  /* ── insights: this site's own analysis of the exploited lists ── */
  function el(tag, attrs) {
    var node = document.createElementNS(SVG, tag);
    for (var k in attrs) node.setAttribute(k, attrs[k]);
    return node;
  }
  function hbars(host, rows, wide) {
    var max = Math.max.apply(null, rows.map(function (r) { return r[1]; }).concat([1]));
    host.replaceChildren();
    rows.forEach(function (r) {
      var fill = h("span", { class: "hbar-fill" });
      fill.style.width = Math.max(1.5, (r[1] / max) * 100) + "%";
      host.append(h("li", { title: r[0] + ": " + (r[2] || r[1]) },
        h("span", { class: "hbar-label" + (wide ? " wide" : ""), text: r[0] }), h("span", { class: "hbar-track" }, fill), h("span", { class: "hbar-value", text: r[2] || num(r[1]) })));
    });
    if (!rows.length) host.append(h("li", { class: "empty", text: "Nothing to show for this period." }));
  }
  function median(list) {
    var a = list.slice().sort(function (x, y) { return x - y; }), m = Math.floor(a.length / 2);
    return a.length ? (a.length % 2 ? a[m] : Math.round((a[m - 1] + a[m]) / 2)) : null;
  }

  function months(all) {
    var host = $("ins-months"), tip = $("ins-tip"), now = new Date(), rows = [], index = {};
    for (var n = 23; n >= 0; n--) {
      var d = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - n, 1)), key = d.toISOString().slice(0, 7);
      index[key] = { key: key, label: MONTHS[d.getUTCMonth()] + " " + d.getUTCFullYear(), short: MONTHS[d.getUTCMonth()] + " " + String(d.getUTCFullYear()).slice(2), ransom: 0, other: 0 };
      rows.push(index[key]);
    }
    all.forEach(function (v) { var r = index[(v.added || "").slice(0, 7)]; if (r) r[v.ransomware ? "ransom" : "other"]++; });
    host.replaceChildren();
    var W = Math.max(300, Math.round(host.clientWidth || 720)), H = W < 480 ? 200 : 220, L = 34, R = 6, Tp = 10, B = 24, plotW = W - L - R, plotH = H - Tp - B;
    var max = Math.max.apply(null, rows.map(function (r) { return r.ransom + r.other; }).concat([1])), step = 1;
    for (var m = 1; max / step > 5; m *= 10) { [1, 2, 5, 10].some(function (k) { step = k * m; return max / step <= 5; }); }
    var top = Math.ceil(max / step) * step;
    var svg = el("svg", { viewBox: "0 0 " + W + " " + H, role: "img", "aria-label": "Stacked bar chart of flaws added to the exploited lists per month for the last 24 months, split by known ransomware use. The same figures are in the table below." });
    for (var v = 0; v <= top; v += step) {
      var y = Tp + plotH - (v / top) * plotH;
      svg.append(el("line", { x1: L, x2: W - R, y1: y, y2: y, class: v ? "grid" : "axis" }));
      var t = el("text", { x: L - 6, y: y + 4, "text-anchor": "end", class: "tick" }); t.textContent = v; svg.append(t);
    }
    var slot = plotW / rows.length, bw = Math.max(3, Math.min(30, slot - 3)), every = W < 480 ? 6 : 3;
    rows.forEach(function (r, n) {
      var x = L + n * slot + (slot - bw) / 2, base = Tp + plotH, g = el("g", { class: "col", tabindex: "0" });
      var hr = (r.ransom / top) * plotH, ho = (r.other / top) * plotH, gap = r.ransom && r.other ? 2 : 0;
      if (r.ransom) g.append(el("rect", { x: x, y: base - hr, width: bw, height: hr, rx: r.other ? 0 : Math.min(4, bw / 2), class: "bar-ransom" }));
      if (r.other) g.append(el("rect", { x: x, y: base - hr - ho, width: bw, height: Math.max(1, ho - gap), rx: Math.min(4, bw / 2), class: "bar-other" }));
      g.append(el("rect", { x: L + n * slot, y: Tp, width: slot, height: plotH, class: "hit" }));
      var text = r.label + ": " + (r.ransom + r.other) + " added, " + r.ransom + " used by ransomware groups";
      g.setAttribute("aria-label", text);
      function show() {
        tip.textContent = text; tip.hidden = false;
        var box = host.getBoundingClientRect(), px = ((L + n * slot + slot / 2) / W) * box.width, half = Math.min(165, box.width / 2 - 4);
        tip.style.left = Math.max(half, Math.min(box.width - half, px)) + "px";
      }
      g.addEventListener("mouseenter", show); g.addEventListener("focus", show);
      g.addEventListener("mouseleave", function () { tip.hidden = true; }); g.addEventListener("blur", function () { tip.hidden = true; });
      svg.append(g);
      if (n % every === 0) { var lx = el("text", { x: L + n * slot + slot / 2, y: H - 7, "text-anchor": "middle", class: "tick" }); lx.textContent = r.short; svg.append(lx); }
    });
    host.append(svg);
    var body = h("tbody");
    rows.slice().reverse().forEach(function (r) {
      body.append(h("tr", null, h("td", { text: r.label }), h("td", { text: r.ransom + r.other }), h("td", { text: r.ransom })));
    });
    $("ins-months-table").replaceChildren(h("thead", null, h("tr", null, h("th", { text: "Month" }), h("th", { text: "Added" }), h("th", { text: "Of which used by ransomware" }))), body);
  }

  function trends() {
    var all = data.kev.items, days = +$("ins-period").value || 0;
    var set = days ? all.filter(function (v) { return T.daysSince(v.added) <= days; }) : all;
    var scope = days ? "in the last 12 months" : "since the lists began";

    /* headline figures */
    var month = all.filter(function (v) { return T.daysSince(v.added) <= 30; }).length;
    var ransom = set.filter(function (v) { return v.ransomware; }).length;
    var today = Math.floor(Date.now() / 864e5);
    var due = all.filter(function (v) { return v.due && dayNumber(v.due) >= today && dayNumber(v.due) <= today + 14; })
      .sort(function (a, b) { return a.due.localeCompare(b.due) || a.cve.localeCompare(b.cve); });
    function tile(value, label, note) { return h("div", { class: "tile" }, h("strong", { text: value }), h("span", { text: label }), h("small", { text: note })); }
    $("ins-tiles").replaceChildren(
      tile(num(all.length), "exploited flaws tracked", "on the US or EU lists"),
      tile(num(month), "added in the last 30 days", "newly listed as exploited"),
      tile(set.length ? Math.round((ransom / set.length) * 100) + "%" : "0%", "used by ransomware groups", num(ransom) + " of " + num(set.length) + " listed " + scope),
      tile(num(due.length), "fix deadlines in 14 days", "set by CISA for US agencies"));

    /* deadlines */
    var dl = $("ins-due");
    dl.replaceChildren();
    due.slice(0, 12).forEach(function (v) {
      var left = dayNumber(v.due) - today;
      dl.append(h("li", null,
        h("p", { class: "row-title" }, h("a", { href: "/vulnerabilities/?q=" + encodeURIComponent(v.cve), text: v.name || v.vendor + " " + v.product })),
        h("p", { class: "meta" }, h("span", { class: "cve", text: v.cve }),
          h("span", { text: "Due " + T.date(v.due, true) + (left === 0 ? " (today)" : left === 1 ? " (tomorrow)" : " (in " + left + " days)") }),
          v.ransomware ? h("span", { class: "flag danger", text: "Used by ransomware" }) : null)));
    });
    if (!due.length) dl.append(h("li", { class: "empty", text: "No CISA deadlines fall in the next 14 days." }));
    if (due.length > 12) dl.append(h("li", { class: "empty", text: "And " + (due.length - 12) + " more." }));

    months(all);

    /* vendors */
    var counts = {};
    set.forEach(function (v) { if (v.vendor) counts[v.vendor] = (counts[v.vendor] || 0) + 1; });
    hbars($("ins-vendors"), Object.keys(counts).map(function (k) { return [k, counts[k]]; })
      .sort(function (a, b) { return b[1] - a[1] || a[0].localeCompare(b[0]); }).slice(0, 10));

    /* warning time */
    var timed = set.filter(function (v) { return lag(v) !== null; });
    var bands = [["None: listed by the day it was published", function (d) { return d <= 0; }], ["Up to a week", function (d) { return d >= 1 && d <= 7; }],
      ["Up to a month", function (d) { return d >= 8 && d <= 30; }], ["Up to a year", function (d) { return d >= 31 && d <= 365; }],
      ["More than a year", function (d) { return d > 365; }]];
    hbars($("ins-warning"), bands.map(function (b) {
      var n = timed.filter(function (v) { return b[1](lag(v)); }).length;
      return [b[0], n, n + " · " + (timed.length ? Math.round((n / timed.length) * 100) : 0) + "%"];
    }), true);
    var positive = timed.map(lag).filter(function (d) { return d > 0; });
    $("ins-warning-note").textContent = timed.length
      ? "For the " + num(timed.length) + " flaws listed " + scope + ". Where there was any warning, the typical (median) gap was " + num(median(positive)) + " days."
      : "Publication dates are still being collected.";

    /* US and EU lists */
    var both = all.filter(function (v) { return catalogs(v).length > 1 && v.cisa_added && v.eu_reported; });
    var euOnly = all.filter(function (v) { return catalogs(v).join() === "ENISA"; }).length;
    var gaps = both.map(function (v) { return dayNumber(v.eu_reported) - dayNumber(v.cisa_added); });
    var us = gaps.filter(function (g) { return g > 0; }), eu = gaps.filter(function (g) { return g < 0; }).map(Math.abs), same = gaps.length - us.length - eu.length;
    hbars($("ins-agree"), both.length ? [["CISA listed it first", us.length], ["ENISA listed it first", eu.length], ["Both on the same day", same]] : [], true);
    $("ins-agree-note").textContent = both.length
      ? num(both.length) + " flaws are on both lists and " + euOnly + " are on the EU list only. When CISA was first, ENISA typically followed " + num(median(us) || 0)
        + " days later; when ENISA was first, CISA followed " + num(median(eu) || 0) + " days later. The EU list started years after the US one and is still short, which explains most of that gap, so treat this as an early picture."
      : "The EU list has not been loaded yet.";
  }

  function render() {
    var kev = tab === "kev", tr = tab === "trends";
    tabKev.setAttribute("aria-pressed", kev); tabNew.setAttribute("aria-pressed", tab === "new"); tabTrends.setAttribute("aria-pressed", tr);
    $("trends").hidden = !tr; $("filters").hidden = tr; $("list-wrap").hidden = tr; count.hidden = tr;
    $("priority-note").hidden = tab !== "new";
    if (tr) { more.hidden = true; T.setParams({ tab: "insights", period: $("ins-period").value ? "" : "all" }); trends(); return; }
    ransomWrap.hidden = !kev; zeroWrap.hidden = !kev; sevWrap.hidden = kev; firstWrap.hidden = kev;
    var src = kev ? data.kev.items : data.recent.items;
    var out = src.filter(function (v) {
      if (kev && ransom.checked && !v.ransomware) return false;
      if (kev && zero.checked && !byDisclosure(v)) return false;
      if (!kev && sev.value && v.severity !== sev.value) return false;
      if (!kev && first.value === "urgent" && priority(v) !== "Urgent") return false;
      if (!kev && first.value === "high" && !priority(v)) return false;
      return !q.value || T.matches([v.cve, v.name, v.vendor, v.product, v.description].join(" "), q.value);
    });
    count.textContent = (kev ? T.plural(out.length, "exploited vulnerability", "exploited vulnerabilities") : T.plural(out.length, "new vulnerability", "new vulnerabilities"))
      + (out.length === src.length ? "" : " of " + num(src.length));
    T.setParams({ q: q.value, tab: kev ? "" : "new", ransomware: kev && ransom.checked ? "1" : "", disclosure: kev && zero.checked ? "1" : "",
      severity: kev ? "" : sev.value, priority: kev ? "" : first.value });
    var empty = src.length ? "Nothing matches. Clear the search or a filter."
      : kev ? "The exploited list is empty right now. It refreshes every 30 minutes."
            : "No new high or critical vulnerabilities have been loaded yet. This list fills on the next refresh.";
    T.paged(list, more, out, kev ? kevRow : newRow, 60, empty);
    if (out.length === 1) { var d = list.querySelector("details"); if (d) d.open = true; }
  }

  T.data("vulnerabilities").then(function (d) {
    data = d;
    q.value = T.param("q");
    tab = T.param("tab") === "new" ? "new" : T.param("tab") === "insights" ? "trends" : "kev";
    $("ins-period").value = T.param("period") === "all" ? "" : "365";
    $("ins-period").addEventListener("change", render);
    ransom.checked = T.param("ransomware") === "1";
    zero.checked = T.param("disclosure") === "1";
    first.value = T.param("priority") === "urgent" || T.param("priority") === "high" ? T.param("priority") : "";
    sev.value = T.param("severity");
    /* a CVE searched from elsewhere may only be in the other list */
    if (q.value && tab === "kev" && !d.kev.items.some(function (v) { return T.matches(v.cve + " " + v.name, q.value); })
        && d.recent.items.some(function (v) { return T.matches(v.cve, q.value); })) tab = "new";
    $("updated").textContent = "Exploited list refreshed " + T.ago(d.kev.updated) + "."
      + (d.recent.updated ? " New-this-week list refreshed " + T.ago(d.recent.updated) + "." : "");
    tabKev.addEventListener("click", function () { tab = "kev"; render(); });
    tabNew.addEventListener("click", function () { tab = "new"; render(); });
    tabTrends.addEventListener("click", function () { tab = "trends"; render(); });
    [ransom, sev, zero, first].forEach(function (c) { c.addEventListener("change", render); });
    window.addEventListener("resize", T.debounce(function () { if (tab === "trends") trends(); }, 200));
    q.addEventListener("input", T.debounce(render));
    render();
  }).catch(function () { T.failed(list, "vulnerability data"); more.hidden = true; });
})();
