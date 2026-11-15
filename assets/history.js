// Incident history: every tracked incident, with a few charts on top.
(function () {
  "use strict";
  var T = window.TIS, h = T.h, SVG = "http://www.w3.org/2000/svg";
  var $ = function (id) { return document.getElementById(id); };
  var q = $("q"), period = $("period"), sector = $("sector"), type = $("type"), statusSel = $("status"), list = $("list"), more = $("more"), count = $("count");
  var items = [], shown = [];
  var GROUPS = ["confirmed", "reported", "claimed"];
  var GROUP_LABEL = { confirmed: "confirmed", reported: "reported", claimed: "claimed" };
  var STATUS_LABEL = { confirmed: "Confirmed", corroborated: "Corroborated", reported: "Reported", claimed: "Claimed", disputed: "Disputed" };
  /* General advice shown when an entry has no lessons of its own. */
  var GENERAL = {
    "Ransomware": ["Keep offline or immutable backups and rehearse restoring from them.", "Require multi-factor sign-in on all remote access and admin accounts."],
    "Data breach": ["Collect and keep only the personal data you need, and encrypt what you hold.", "Watch for unusual bulk access or export of records, and have a notification plan ready."],
    "Supply chain": ["Know which suppliers hold your data or can reach your systems, and limit that access.", "Be ready to rotate credentials and tokens quickly when a supplier is compromised."],
    "DDoS": ["Put public services behind a DDoS mitigation provider and test the failover.", "Agree in advance how to keep customers informed during an outage."],
    "Crypto theft": ["Keep most funds in offline storage and require several approvers for large transfers.", "Treat unexpected job offers, video calls and software downloads as likely attack routes."],
    "Espionage": ["Patch internet-facing devices fast and replace those that no longer get updates.", "Log and review sign-ins and remote-access activity so long-running intrusions are noticed."],
    "Phishing": ["Use phishing-resistant sign-in such as passkeys or security keys.", "Verify payment changes and password resets through a second, known channel."],
    "Cyberattack": ["Have a tested incident response plan, including how to run key services by hand.", "Patch internet-facing systems promptly and require multi-factor sign-in."]
  };
  function num(n) { return Number(n).toLocaleString("en-GB"); }
  function group(i) { return i.status === "confirmed" ? "confirmed" : (i.status === "claimed" || i.status === "disputed") ? "claimed" : "reported"; }
  function lessonsFor(i) {
    if ((i.lessons || []).length) return { items: i.lessons, note: i.curated ? "" : "Suggested with AI assistance from the reports." };
    return { items: GENERAL[i.type] || GENERAL.Cyberattack, note: "General advice for this type of incident, not findings about this case." };
  }
  var MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

  function s(tag, attrs) {
    var el = document.createElementNS(SVG, tag);
    for (var k in attrs) el.setAttribute(k, attrs[k]);
    return el;
  }
  function confirmedOn(i) {
    if (i.status !== "confirmed") return null;
    var dates = (i.history || []).filter(function (x) { return x.status === "confirmed" && x.date; }).map(function (x) { return x.date; }).sort();
    return dates[0] || i.first_reported;
  }

  /* ── charts ── */
  function buckets(data) {
    var times = data.map(function (i) { return Date.parse(i.first_reported); }).filter(function (t) { return !isNaN(t); });
    if (!times.length) return { unit: "", rows: [] };
    var p = period.value, now = Date.now(), from = Math.min.apply(null, times), unit, start;
    if (p === "30") { unit = "day"; start = now - 29 * 864e5; }
    else if (p === "90") { unit = "week"; start = now - 12 * 7 * 864e5; }
    else if (p === "365") { unit = "month"; start = now - 334 * 864e5; }
    else if (/^\d{4}$/.test(p)) { unit = "month"; start = Date.UTC(+p, 0, 1); now = Math.min(now, Date.UTC(+p, 11, 31)); }
    else {
      var span = (now - from) / 864e5;
      unit = span <= 45 ? "day" : span <= 730 ? "month" : "year";
      start = unit === "day" ? Math.min(from, now - 13 * 864e5) : from;
    }
    function key(t) {
      var d = new Date(t);
      if (unit === "year") return String(d.getUTCFullYear());
      if (unit === "month") return d.getUTCFullYear() + "-" + ("0" + (d.getUTCMonth() + 1)).slice(-2);
      if (unit === "week") { var day = (d.getUTCDay() + 6) % 7; d = new Date(t - day * 864e5); }
      return d.toISOString().slice(0, 10);
    }
    function label(k) {
      if (unit === "year") return k;
      if (unit === "month") return MONTHS[+k.slice(5, 7) - 1] + " " + k.slice(0, 4);
      return +k.slice(8, 10) + " " + MONTHS[+k.slice(5, 7) - 1];
    }
    var rows = [], seen = {}, t = start;
    while (t <= now + 864e5 && rows.length < 400) {
      var k = key(t);
      if (!seen[k] && Date.parse(k.length === 4 ? k + "-01-01" : k.length === 7 ? k + "-01" : k) <= now) {
        seen[k] = { key: k, label: (unit === "week" ? "Week of " : "") + label(k), short: label(k), confirmed: 0, reported: 0, claimed: 0 };
        rows.push(seen[k]);
      }
      t += 864e5;
    }
    data.forEach(function (i) {
      var row = seen[key(Date.parse(i.first_reported))];
      if (row) row[group(i)]++;
    });
    return { unit: unit, rows: rows };
  }

  function timeline(data) {
    var host = $("timeline"), tip = $("tip"), b = buckets(data), rows = b.rows;
    $("timeline-title").textContent = "Incidents first reported, by " + (b.unit || "date");
    host.replaceChildren();
    if (!rows.length) { host.append(h("p", { class: "empty", text: "No incidents in this selection." })); $("timeline-table").replaceChildren(); return; }
    var W = Math.max(300, Math.round(host.clientWidth || 720)), H = W < 480 ? 210 : 230, L = 40, R = 6, Tp = 10, B = 26, plotW = W - L - R, plotH = H - Tp - B;
    function total(r) { return r.confirmed + r.reported + r.claimed; }
    var max = Math.max.apply(null, rows.map(total).concat([1]));
    var step = 1;
    for (var m = 1; max / step > 5; m *= 10) { [1, 2, 5, 10].some(function (k) { step = k * m; return max / step <= 5; }); }
    var top = Math.ceil(max / step) * step;
    var svg = s("svg", { viewBox: "0 0 " + W + " " + H, role: "img", "aria-label": "Stacked bar chart of incidents first reported by " + b.unit + ", split into confirmed, reported and claimed. The same figures are in the table below." });
    for (var v = 0; v <= top; v += step) {
      var y = Tp + plotH - (v / top) * plotH;
      svg.append(s("line", { x1: L, x2: W - R, y1: y, y2: y, class: v ? "grid" : "axis" }));
      var tx = s("text", { x: L - 6, y: y + 4, "text-anchor": "end", class: "tick" }); tx.textContent = v >= 1000 ? (v / 1000) + "k" : v; svg.append(tx);
    }
    var slot = plotW / rows.length, bw = Math.max(2, Math.min(40, slot - 2)), every = Math.ceil(rows.length / (W < 480 ? 4 : 8));
    rows.forEach(function (r, n) {
      var x = L + n * slot + (slot - bw) / 2, y = Tp + plotH, g = s("g", { class: "col", tabindex: "0" });
      var present = GROUPS.filter(function (k) { return r[k]; });
      present.forEach(function (k, idx) {
        var hgt = Math.max(2, (r[k] / top) * plotH), last = idx === present.length - 1, gap = last ? 0 : 2;
        y -= hgt;
        g.append(s("rect", { x: x, y: y + (last ? 0 : gap), width: bw, height: Math.max(1, hgt - gap), rx: last ? Math.min(4, bw / 2) : 0, class: "bar-" + k }));
      });
      g.append(s("rect", { x: L + n * slot, y: Tp, width: slot, height: plotH, class: "hit" }));
      var text = r.label + ": " + GROUPS.map(function (k) { return num(r[k]) + " " + GROUP_LABEL[k]; }).join(", ");
      g.setAttribute("aria-label", text);
      function show() {
        tip.textContent = text; tip.hidden = false;
        var box = host.getBoundingClientRect(), px = ((L + n * slot + slot / 2) / W) * box.width, half = Math.min(170, box.width / 2 - 4);
        tip.style.left = Math.max(half, Math.min(box.width - half, px)) + "px";
      }
      g.addEventListener("mouseenter", show); g.addEventListener("focus", show);
      g.addEventListener("mouseleave", function () { tip.hidden = true; }); g.addEventListener("blur", function () { tip.hidden = true; });
      svg.append(g);
      if (n % every === 0) { var lx = s("text", { x: L + n * slot + slot / 2, y: H - 8, "text-anchor": "middle", class: "tick" }); lx.textContent = r.short; svg.append(lx); }
    });
    host.append(svg);
    var body = h("tbody");
    rows.filter(total).forEach(function (r) {
      body.append(h("tr", null, h("td", { text: r.label }), h("td", { text: num(r.confirmed) }), h("td", { text: num(r.reported) }), h("td", { text: num(r.claimed) })));
    });
    $("timeline-table").replaceChildren(h("thead", null, h("tr", null, h("th", { text: b.unit ? b.unit.charAt(0).toUpperCase() + b.unit.slice(1) : "" }), h("th", { text: "Confirmed" }), h("th", { text: "Reported" }), h("th", { text: "Claimed" }))), body);
  }

  function ranked(host, note, data, field, limit, missing, what) {
    var counts = {}, blank = 0;
    data.forEach(function (i) {
      var k = i[field];
      if (!k || missing.indexOf(k) !== -1) { blank++; return; }
      counts[k] = (counts[k] || 0) + 1;
    });
    var rows = Object.keys(counts).map(function (k) { return [k, counts[k]]; }).sort(function (a, b) { return b[1] - a[1] || a[0].localeCompare(b[0]); });
    var known = data.length - blank, max = rows.length ? rows[0][1] : 1;
    rows = rows.slice(0, limit);
    host.replaceChildren();
    rows.forEach(function (r) {
      var fill = h("span", { class: "hbar-fill" });
      fill.style.width = Math.max(1.5, (r[1] / max) * 100) + "%";
      host.append(h("li", { title: r[0] + ": " + num(r[1]) + " (" + Math.round((r[1] / (known || 1)) * 100) + "% of those recorded)" },
        h("span", { class: "hbar-label", text: r[0] }), h("span", { class: "hbar-track" }, fill), h("span", { class: "hbar-value", text: num(r[1]) })));
    });
    if (!rows.length) host.append(h("li", { class: "empty", text: "Nothing recorded in this selection." }));
    note.textContent = blank ? num(blank) + " of " + num(data.length) + " entries have no " + what + " recorded and are left out." : "";
  }

  function tiles(data) {
    var n = { confirmed: 0, reported: 0, claimed: 0 };
    data.forEach(function (i) { n[group(i)]++; });
    function pct(v) { return data.length ? Math.round((v / data.length) * 100) : 0; }
    function tile(value, label, note) { return h("div", { class: "tile" }, h("strong", { text: num(value) }), h("span", { text: label }), note ? h("small", { text: note }) : null); }
    $("tiles").replaceChildren(
      tile(data.length, data.length === 1 ? "incident tracked" : "incidents tracked", "in this selection"),
      tile(n.confirmed, "confirmed", "acknowledged by the organisation or an authority"),
      tile(n.reported, "reported", "in the press, not officially confirmed"),
      tile(n.claimed, "claimed", "by attackers or leak sites, unverified"));
    var split = $("split");
    split.replaceChildren();
    GROUPS.forEach(function (k) {
      if (!n[k]) return;
      var seg = h("span", { class: "split-" + k });
      seg.style.flexGrow = n[k];
      split.append(seg);
    });
    split.setAttribute("aria-label", GROUPS.map(function (k) { return pct(n[k]) + "% " + k; }).join(", "));
  }

  /* ── the list ── */
  function row(i) {
    var conf = confirmedOn(i), lessons = lessonsFor(i), summary = i.summary && i.summary !== "N/A" ? i.summary : "";
    var industry = i.sector && i.sector !== "Other" ? i.sector : "Industry not recorded";
    return h("details", { class: "vuln hist", id: i.id },
      h("summary", null,
        h("span", null, h("span", { class: "cve", text: T.date(i.first_reported, true) }), T.status(i.status)),
        h("span", null,
          h("span", { class: "row-title", text: i.organisation || i.title || "Organisation not named" }),
          h("span", { class: "meta" }, h("span", { text: industry }), h("span", { text: i.type }),
            h("span", { text: conf ? "Confirmed " + T.date(conf, true) : "Not confirmed" })))),
      h("div", { class: "vuln-body" },
        i.organisation && i.title ? h("h3", { text: i.title }) : null,
        summary ? h("p", { text: summary }) : h("p", { class: "basis", text: "No summary is available for this entry. See the source for details." }),
        i.why_it_matters ? h("p", { text: i.why_it_matters }) : null,
        h("dl", null,
          h("dt", { text: "First reported" }), h("dd", { text: T.date(i.first_reported, true) }),
          h("dt", { text: "Confirmed" }), h("dd", { text: conf ? T.date(conf, true) : "Not confirmed" }),
          h("dt", { text: "Evidence" }), h("dd", { text: (STATUS_LABEL[i.status] || "Reported") + ". " + (i.basis || "") }),
          h("dt", { text: "Industry" }), h("dd", { text: industry }),
          i.threat_actor ? [h("dt", { text: "Attacker" }), h("dd", { text: i.threat_actor + " (claimed or attributed)" })] : null),
        h("h4", { text: "Lessons" }), h("ul", null, lessons.items.map(function (l) { return h("li", { text: l }); })),
        lessons.note ? h("p", { class: "basis", text: lessons.note }) : null,
        h("h4", { text: (i.sources || []).length === 1 ? "Source" : "Sources" }),
        h("ul", { class: "sources" }, (i.sources || []).slice(0, 8).map(function (src) {
          return h("li", null, T.ext(src.link, src.title || src.name), " ", h("span", { class: "basis", text: "— " + src.name + (src.published ? ", " + T.date(src.published, true) : "") }));
        }))));
  }

  function inPeriod(i) {
    var p = period.value;
    if (!p) return true;
    if (/^\d{4}$/.test(p)) return (i.first_reported || "").slice(0, 4) === p;
    return T.daysSince(i.first_reported) <= +p;
  }

  function render() {
    var st = statusSel.value;
    shown = items.filter(function (i) {
      if (st && i.status !== st) return false;
      if (type.value && i.type !== type.value) return false;
      if (sector.value && i.sector !== sector.value) return false;
      if (!inPeriod(i)) return false;
      return !q.value || T.matches([i.id, i.title, i.organisation, i.summary, i.type, i.sector, i.threat_actor].join(" "), q.value);
    }).sort(function (a, b) { return (b.first_reported || "").localeCompare(a.first_reported || ""); });
    T.setParams({ q: q.value, status: st, type: type.value, industry: sector.value, period: period.value });
    count.textContent = num(shown.length) + (shown.length === 1 ? " incident" : " incidents") + (shown.length === items.length ? "" : " of " + num(items.length)) + ", newest first";
    tiles(shown); timeline(shown);
    ranked($("by-type"), $("by-type-note"), shown, "type", 8, [], "type");
    ranked($("by-sector"), $("by-sector-note"), shown, "sector", 8, ["Other"], "industry");
    ranked($("by-actor"), $("by-actor-note"), shown, "threat_actor", 10, [], "attacker");
    T.paged(list, more, shown, row, 50, items.length ? "No incidents match. Widen the period or clear a filter." : "No incidents recorded yet.");
    if (shown.length === 1) { var d = list.querySelector("details"); if (d) d.open = true; }
  }

  function csv() {
    function cell(v) {
      v = v == null ? "" : String(v);
      if (/^[=+\-@\t\r]/.test(v)) v = "'" + v;  // stop spreadsheets treating text as a formula
      return '"' + v.replace(/"/g, '""') + '"';
    }
    var lines = [["Organisation", "Incident", "Evidence", "First reported", "Confirmed", "Industry", "Type", "Attacker (claimed or attributed)", "Summary", "Lessons", "Lessons basis", "Sources"].map(cell).join(",")];
    shown.forEach(function (i) {
      lines.push([i.organisation, i.title, i.status, (i.first_reported || "").slice(0, 10), (confirmedOn(i) || "").slice(0, 10), i.sector, i.type, i.threat_actor,
        i.summary === "N/A" ? "" : i.summary, lessonsFor(i).items.join(" "), (i.lessons || []).length ? (i.curated ? "specific" : "AI-assisted") : "general advice for the type",
        (i.sources || []).map(function (x) { return T.safeUrl(x.link) || ""; }).join(" ")].map(cell).join(","));
    });
    var a = h("a", { href: URL.createObjectURL(new Blob(["﻿" + lines.join("\r\n")], { type: "text/csv" })), download: "incident-history.csv" });
    document.body.append(a); a.click(); a.remove();
  }

  T.data("incidents").then(function (d) {
    items = d.incidents;
    T.fill(type, T.unique(items.map(function (i) { return i.type; })), "All types");
    T.fill(sector, T.unique(items.map(function (i) { return i.sector; })), "All industries");
    period.replaceChildren(h("option", { value: "", text: "All time" }), h("option", { value: "30", text: "Last 30 days" }),
      h("option", { value: "90", text: "Last 90 days" }), h("option", { value: "365", text: "Last 12 months" }));
    T.unique(items.map(function (i) { return (i.first_reported || "").slice(0, 4); })).reverse().forEach(function (y) { period.append(h("option", { value: y, text: y })); });
    q.value = T.param("q"); type.value = T.param("type"); sector.value = T.param("industry"); period.value = T.param("period");
    statusSel.value = STATUS_LABEL[T.param("status")] ? T.param("status") : "";
    $("updated").textContent = "Last updated " + T.ago(d.updated) + ".";
    [type, sector, period, statusSel].forEach(function (el) { el.addEventListener("change", render); });
    q.addEventListener("input", T.debounce(render));
    $("csv").addEventListener("click", csv);
    window.addEventListener("resize", T.debounce(function () { timeline(shown); }, 200));
    render();
  }).catch(function () { T.failed(list, "incident history"); more.hidden = true; });
})();
