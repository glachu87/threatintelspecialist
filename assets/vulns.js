(function () {
  "use strict";
  var T = window.TIS, h = T.h;
  var $ = function (id) { return document.getElementById(id); };
  var q = $("q"), list = $("list"), more = $("more"), count = $("count");
  var tabKev = $("tab-kev"), tabNew = $("tab-new"), tabTrends = $("tab-trends"), ransom = $("ransom"), ransomWrap = $("ransom-wrap"), sev = $("sev"), sevWrap = $("sev-wrap");
  var zero = $("zero"), zeroWrap = $("zero-wrap"), first = $("first"), firstWrap = $("first-wrap");
  var data = null, tab = "kev", SVG = "http://www.w3.org/2000/svg";
  var MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  var PATCH_FIRST_EPSS = 0.03;

  function num(n) { return Number(n).toLocaleString("en-GB"); }
  function dayNumber(d) { return Math.round(Date.parse(d.slice(0, 10) + "T00:00:00Z") / 864e5); }
  /* Days from the CVE record's publication to the first exploited listing; null if unknown. */
  function lag(v) { return v.published && v.added ? dayNumber(v.added) - dayNumber(v.published) : null; }
  function byDisclosure(v) { var d = lag(v); return d !== null && d <= 0; }
  function patchFirst(v) { return !!v.kev || (v.epss != null && v.epss >= PATCH_FIRST_EPSS); }
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
            patchFirst(v) ? h("span", { class: "flag danger", text: "Patch first" }) : null,
            v.kev ? h("span", { class: "flag danger", text: "Being exploited" }) : null,
            v.vector ? h("span", { text: "Attack route: " + v.vector.toLowerCase() }) : null))),
      h("div", { class: "vuln-body" },
        h("p", { text: v.description }),
        h("dl", null,
          h("dt", { text: "Severity" }), h("dd", { text: v.severity + ", " + v.score + " out of 10 (CVSS " + v.cvss_version + ")" }),
          epss(v)),
        links(v.cve)));
  }

  /* ── trends ── */
  function el(tag, attrs) {
    var node = document.createElementNS(SVG, tag);
    for (var k in attrs) node.setAttribute(k, attrs[k]);
    return node;
  }
  function weekLabel(w) { return +w.slice(8, 10) + " " + MONTHS[+w.slice(5, 7) - 1]; }

  function weekly(hostId, tipId, rows, key, cls, noun) {
    var host = $(hostId), tip = $(tipId), have = rows.filter(function (r) { return r[key] != null; });
    host.replaceChildren();
    if (!have.length) {
      host.append(h("p", { class: "empty", text: "These counts are still being collected. They fill in over the next few refreshes." }));
      return;
    }
    var W = Math.max(300, Math.round(host.clientWidth || 720)), H = 170, L = 44, R = 6, Tp = 10, B = 24, plotW = W - L - R, plotH = H - Tp - B;
    var max = Math.max.apply(null, have.map(function (r) { return r[key]; }).concat([1])), step = 1;
    for (var m = 1; max / step > 4; m *= 10) { [1, 2, 5, 10].some(function (k) { step = k * m; return max / step <= 4; }); }
    var top = Math.ceil(max / step) * step;
    var svg = el("svg", { viewBox: "0 0 " + W + " " + H, role: "img", "aria-label": "Bar chart: " + noun + " per week. The same figures are in the table below." });
    for (var v = 0; v <= top; v += step) {
      var y = Tp + plotH - (v / top) * plotH;
      svg.append(el("line", { x1: L, x2: W - R, y1: y, y2: y, class: v ? "grid" : "axis" }));
      var t = el("text", { x: L - 6, y: y + 4, "text-anchor": "end", class: "tick" }); t.textContent = num(v); svg.append(t);
    }
    var slot = plotW / rows.length, bw = Math.max(2, Math.min(26, slot - 2)), every = Math.ceil(rows.length / (W < 480 ? 4 : 9));
    rows.forEach(function (r, n) {
      var g = el("g", { class: "col", tabindex: "0" }), val = r[key];
      if (val != null) {
        var hgt = val ? Math.max(2, (val / top) * plotH) : 0;
        if (hgt) g.append(el("rect", { x: L + n * slot + (slot - bw) / 2, y: Tp + plotH - hgt, width: bw, height: hgt, rx: Math.min(4, bw / 2), class: cls }));
      }
      g.append(el("rect", { x: L + n * slot, y: Tp, width: slot, height: plotH, class: "hit" }));
      var text = "Week of " + weekLabel(r.week) + ": " + (val == null ? "not collected yet" : num(val) + " " + noun);
      g.setAttribute("aria-label", text);
      function show() {
        tip.textContent = text; tip.hidden = false;
        var box = host.getBoundingClientRect(), px = ((L + n * slot + slot / 2) / W) * box.width, half = Math.min(150, box.width / 2 - 4);
        tip.style.left = Math.max(half, Math.min(box.width - half, px)) + "px";
      }
      g.addEventListener("mouseenter", show); g.addEventListener("focus", show);
      g.addEventListener("mouseleave", function () { tip.hidden = true; }); g.addEventListener("blur", function () { tip.hidden = true; });
      svg.append(g);
      if (n % every === 0) { var lx = el("text", { x: L + n * slot + slot / 2, y: H - 7, "text-anchor": "middle", class: "tick" }); lx.textContent = weekLabel(r.week); svg.append(lx); }
    });
    host.append(svg);
  }

  function trends() {
    var rows = data.trend || [];
    weekly("chart-pub", "tip-pub", rows, "published", "bar-reported", "published");
    weekly("chart-exp", "tip-exp", rows, "exploited", "bar-claimed", "first listed as exploited");
    var body = h("tbody");
    rows.slice().reverse().forEach(function (r) {
      body.append(h("tr", null, h("td", { text: weekLabel(r.week) + " " + r.week.slice(0, 4) }), h("td", { text: r.published == null ? "–" : num(r.published) }), h("td", { text: num(r.exploited) })));
    });
    $("trend-table").replaceChildren(h("thead", null, h("tr", null, h("th", { text: "Week starting" }), h("th", { text: "Published" }), h("th", { text: "First listed as exploited" }))), body);

    var year = data.kev.items.filter(function (v) { return lag(v) !== null && T.daysSince(v.added) <= 365; });
    var bands = [["On or before publication day", function (d) { return d <= 0; }], ["Within a week", function (d) { return d >= 1 && d <= 7; }],
      ["Within a month", function (d) { return d >= 8 && d <= 30; }], ["Within a year", function (d) { return d >= 31 && d <= 365; }],
      ["More than a year old", function (d) { return d > 365; }]];
    var counts = bands.map(function (b) { return year.filter(function (v) { return b[1](lag(v)); }).length; });
    var max = Math.max.apply(null, counts.concat([1])), bars = $("age-bars");
    bars.replaceChildren();
    bands.forEach(function (b, n) {
      var fill = h("span", { class: "hbar-fill" }), share = year.length ? Math.round((counts[n] / year.length) * 100) : 0;
      fill.style.width = Math.max(1.5, (counts[n] / max) * 100) + "%";
      bars.append(h("li", { title: b[0] + ": " + counts[n] + " (" + share + "%)" },
        h("span", { class: "hbar-label wide", text: b[0] }), h("span", { class: "hbar-track" }, fill), h("span", { class: "hbar-value", text: counts[n] + " · " + share + "%" })));
    });
    $("age-note").textContent = year.length
      ? "Of the " + num(year.length) + " vulnerabilities first listed as exploited in the last 12 months, measured from the day the CVE record was published."
      : "Publication dates are still being collected.";
  }

  function render() {
    var kev = tab === "kev", tr = tab === "trends";
    tabKev.setAttribute("aria-pressed", kev); tabNew.setAttribute("aria-pressed", tab === "new"); tabTrends.setAttribute("aria-pressed", tr);
    $("trends").hidden = !tr; $("filters").hidden = tr; $("list-wrap").hidden = tr; count.hidden = tr;
    if (tr) { more.hidden = true; T.setParams({ tab: "trends" }); trends(); return; }
    ransomWrap.hidden = !kev; zeroWrap.hidden = !kev; sevWrap.hidden = kev; firstWrap.hidden = kev;
    var src = kev ? data.kev.items : data.recent.items;
    var out = src.filter(function (v) {
      if (kev && ransom.checked && !v.ransomware) return false;
      if (kev && zero.checked && !byDisclosure(v)) return false;
      if (!kev && sev.value && v.severity !== sev.value) return false;
      if (!kev && first.checked && !patchFirst(v)) return false;
      return !q.value || T.matches([v.cve, v.name, v.vendor, v.product, v.description].join(" "), q.value);
    });
    count.textContent = (kev ? T.plural(out.length, "exploited vulnerability", "exploited vulnerabilities") : T.plural(out.length, "new vulnerability", "new vulnerabilities"))
      + (out.length === src.length ? "" : " of " + num(src.length));
    T.setParams({ q: q.value, tab: kev ? "" : "new", ransomware: kev && ransom.checked ? "1" : "", disclosure: kev && zero.checked ? "1" : "",
      severity: kev ? "" : sev.value, first: !kev && first.checked ? "1" : "" });
    var empty = src.length ? "Nothing matches. Clear the search or a filter."
      : kev ? "The exploited list is empty right now. It refreshes every 30 minutes."
            : "No new high or critical vulnerabilities have been loaded yet. This list fills on the next refresh.";
    T.paged(list, more, out, kev ? kevRow : newRow, 60, empty);
    if (out.length === 1) { var d = list.querySelector("details"); if (d) d.open = true; }
  }

  T.data("vulnerabilities").then(function (d) {
    data = d;
    q.value = T.param("q");
    tab = T.param("tab") === "new" ? "new" : T.param("tab") === "trends" ? "trends" : "kev";
    ransom.checked = T.param("ransomware") === "1";
    zero.checked = T.param("disclosure") === "1";
    first.checked = T.param("first") === "1";
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
