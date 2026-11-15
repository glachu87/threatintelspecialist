(function () {
  "use strict";

  var T = window.TIS, h = T.h;
  var $ = function (id) { return document.getElementById(id); };
  var q = $("q"), type = $("type"), sector = $("sector"), country = $("country"), period = $("period");
  var list = $("list"), more = $("more"), count = $("count"), reset = $("reset-filters"), exportFiltered = $("export-filtered");
  var seg = Array.prototype.slice.call(document.querySelectorAll("#status button"));
  var analyticsSeg = Array.prototype.slice.call(document.querySelectorAll("#analytics-window button"));
  var states = ["confirmed", "corroborated", "reported", "claimed", "disputed"];
  var labels = {
    confirmed: "Confirmed",
    corroborated: "Corroborated",
    reported: "Reported",
    claimed: "Claimed",
    disputed: "Disputed"
  };
  var strength = { claimed: 1, reported: 2, corroborated: 3, confirmed: 4 };
  var status = "", items = [], filteredItems = [], statusData = null, analyticsDays = 30;
  var DAY = 86400000;
  var SVG_NS = "http://www.w3.org/2000/svg";

  function number(n) {
    return new Intl.NumberFormat("en-GB").format(n || 0);
  }

  function percentage(n, total) {
    return total ? Math.round((n / total) * 1000) / 10 : 0;
  }

  function timestamp(i) {
    var d = new Date(i.first_reported || i.last_reported || "");
    return isNaN(d) ? NaN : d.getTime();
  }

  function windowRows(days, offset) {
    if (!days) return items.slice();
    var now = Date.now();
    var newest = now - (offset || 0) * days * DAY;
    var oldest = now - ((offset || 0) + 1) * days * DAY;
    return items.filter(function (i) {
      var t = timestamp(i);
      return !isNaN(t) && t > oldest && t <= newest;
    });
  }

  function sourceCount(i) {
    return (i.sources || []).length;
  }

  function row(i) {
    var history = i.history || [];
    var changed = history.length > 1;
    var lastChange = changed ? history[history.length - 1] : null;
    var sources = i.sources || [];
    return h("li", { class: "incident", id: i.id },
      T.status(i.status),
      h("div", null,
        h("h2", { class: "row-title", text: i.title }),
        h("p", { class: "meta" },
          i.organisation ? h("span", { text: i.organisation }) : null,
          h("span", { text: i.type }),
          i.sector && i.sector !== "Other" ? h("span", { text: i.sector }) : null,
          i.country ? h("span", { text: i.country }) : null,
          h("span", { text: "First reported " + T.date(i.first_reported, true) }),
          h("span", { text: T.plural(sources.length, "source") }),
          i.threat_actor ? h("span", { text: "Attributed to or claimed by: " + i.threat_actor }) : null),
        i.summary ? h("p", { class: "excerpt", text: i.summary }) : null,
        i.why_it_matters ? h("p", { class: "impact" }, h("strong", { text: "Why it matters: " }), i.why_it_matters) : null,
        h("p", { class: "basis" },
          i.basis || "",
          changed && lastChange ? " Latest verification change: " + T.date(lastChange.date, true) + " — " + lastChange.note + "." : "",
          i.ai ? " Headline/summary prepared with AI assistance from the cited source text." : ""),
        h("ul", { class: "sources" }, sources.slice(0, 8).map(function (src) {
          var evidence = src.verification && labels[src.verification] ? " · " + labels[src.verification] : "";
          return h("li", null,
            T.ext(src.link, src.title || src.name),
            " ",
            h("span", { class: "basis", text: "— " + src.name + (src.published ? ", " + T.date(src.published, true) : "") + evidence }));
        }))));
  }

  function inPeriod(i) {
    var p = period.value;
    if (!p) return true;
    if (/^\d+d$/.test(p)) return T.daysSince(i.first_reported) <= parseInt(p, 10);
    return (i.first_reported || "").slice(0, 4) === p;
  }

  function render() {
    seg.forEach(function (b) { b.setAttribute("aria-pressed", b.value === status); });
    var out = items.filter(function (i) {
      if (status && i.status !== status) return false;
      if (type.value && i.type !== type.value) return false;
      if (sector.value && i.sector !== sector.value) return false;
      if (country.value && i.country !== country.value) return false;
      if (!inPeriod(i)) return false;
      return !q.value || T.matches([
        i.id, i.title, i.organisation, i.summary, i.why_it_matters, i.type,
        i.sector, i.country, i.threat_actor
      ].join(" "), q.value);
    });
    filteredItems = out;
    var bits = states.map(function (state) {
      var n = out.filter(function (i) { return i.status === state; }).length;
      return n ? number(n) + " " + labels[state].toLowerCase() : "";
    }).filter(Boolean);
    count.textContent = number(out.length) + " " + (out.length === 1 ? "incident" : "incidents")
      + (bits.length ? ": " + bits.join(" · ") : "");
    T.setParams({
      q: q.value,
      status: status,
      type: type.value,
      sector: sector.value,
      country: country.value,
      period: period.value
    });
    T.paged(list, more, out, row, 40, items.length
      ? "No incidents match. Widen the period or clear a filter."
      : "No incidents recorded yet. The agent scans public sources every 30 minutes and lists what it finds here.");
  }

  function csvCell(value) {
    var s = String(value == null ? "" : value);
    return /[",\n\r]/.test(s) ? "\"" + s.replace(/"/g, "\"\"") + "\"" : s;
  }

  function downloadFilteredCsv() {
    var columns = [
      ["id", "ID"], ["title", "Headline"], ["organisation", "Organisation"], ["type", "Type"],
      ["sector", "Sector"], ["country", "Country"], ["status", "Verification"],
      ["threat_actor", "Threat actor"], ["first_reported", "First reported"], ["last_reported", "Last reported"],
      ["summary", "Summary"], ["why_it_matters", "Why it matters"]
    ];
    var lines = [columns.map(function (c) { return csvCell(c[1]); }).join(",")];
    filteredItems.forEach(function (i) {
      lines.push(columns.map(function (c) { return csvCell(i[c[0]]); }).join(","));
    });
    var blob = new Blob([lines.join("\r\n") + "\r\n"], { type: "text/csv;charset=utf-8" });
    var url = URL.createObjectURL(blob);
    var a = document.createElement("a");
    a.href = url;
    a.download = "threat-intel-incidents-filtered-" + new Date().toISOString().slice(0, 10) + ".csv";
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  }

  function setListPeriodFromAnalytics() {
    period.value = analyticsDays ? analyticsDays + "d" : "";
  }

  function applyChartFilter(kind, value) {
    setListPeriodFromAnalytics();
    if (kind === "status") status = value;
    if (kind === "sector") sector.value = value;
    if (kind === "country") country.value = value;
    if (kind === "actor") q.value = value;
    render();
    $("filters").scrollIntoView({ behavior: "smooth", block: "start" });
  }

  function metric(label, value, detail) {
    return h("div", { class: "analytics-kpi" },
      h("span", { class: "kpi-label", text: label }),
      h("strong", { class: "kpi-value", text: value }),
      h("span", { class: "kpi-detail", text: detail }));
  }

  function renderKpis(rows) {
    var total = rows.length;
    var strong = rows.filter(function (i) { return i.status === "confirmed" || i.status === "corroborated"; }).length;
    var claims = rows.filter(function (i) { return i.status === "claimed"; }).length;
    var multi = rows.filter(function (i) { return sourceCount(i) >= 2; }).length;
    var located = rows.filter(function (i) { return !!i.country; }).length;
    var healthRows = statusData ? (statusData.feeds || []).concat(statusData.apis || []) : [];
    var healthy = healthRows.filter(function (x) { return x.ok; }).length;
    var overall = statusData && statusData.incident_agent && statusData.incident_agent.total_incidents
      ? statusData.incident_agent.total_incidents : items.length;

    $("analytics-kpis").replaceChildren(
      metric("Incidents in window", number(total), number(overall) + " retained in the corpus"),
      metric("Confirmed / corroborated", number(strong), percentage(strong, total) + "% of this window"),
      metric("Claimed", number(claims), percentage(claims, total) + "% early-warning records"),
      metric("Multi-source evidence", number(multi), percentage(multi, total) + "% cite 2+ sources"),
      metric("Location coverage", percentage(located, total) + "%", number(located) + " incidents have country data"),
      metric("Source health", healthRows.length ? healthy + "/" + healthRows.length : "—",
        healthRows.length ? "feeds and APIs responding" : "source status unavailable")
    );
  }

  function countMap(rows, getter) {
    var m = {};
    rows.forEach(function (i) {
      var key = getter(i);
      if (!key) return;
      m[key] = (m[key] || 0) + 1;
    });
    return m;
  }

  function topCounts(rows, getter, limit) {
    var m = countMap(rows, getter);
    return Object.keys(m).map(function (key) {
      return { label: key, count: m[key] };
    }).sort(function (a, b) {
      return b.count - a.count || a.label.localeCompare(b.label);
    }).slice(0, limit || 7);
  }

  function renderRanks(id, data, totalKnown, kind) {
    var box = $(id);
    box.replaceChildren();
    if (!data.length) {
      box.append(h("p", { class: "analytics-empty", text: "Not enough structured data in this window." }));
      return;
    }
    var max = data[0].count || 1;
    data.forEach(function (d) {
      var btn = h("button", {
        class: "rank-row",
        type: "button",
        title: "Filter incidents by " + d.label
      });
      btn.append(
        h("span", { class: "rank-label", text: d.label }),
        h("span", { class: "rank-count", text: number(d.count) }),
        h("span", { class: "rank-track" }, h("span", { class: "rank-fill" }))
      );
      btn.querySelector(".rank-fill").style.width = Math.max(3, (d.count / max) * 100) + "%";
      btn.addEventListener("click", function () { applyChartFilter(kind, d.label); });
      box.append(btn);
    });
    box.append(h("p", {
      class: "rank-note",
      text: number(totalKnown) + " incidents in this window have usable " +
        (kind === "actor" ? "threat-actor" : kind) + " data."
    }));
  }

  function renderVerification(rows) {
    var box = $("verification-chart");
    box.replaceChildren();
    if (!rows.length) {
      box.append(h("p", { class: "analytics-empty", text: "No incidents in this window." }));
      return;
    }
    var counts = {};
    states.forEach(function (state) { counts[state] = 0; });
    rows.forEach(function (i) { if (counts[i.status] !== undefined) counts[i.status] += 1; });

    var stack = h("div", { class: "verify-stack", role: "img", "aria-label": "Verification mix" });
    states.forEach(function (state) {
      if (!counts[state]) return;
      var btn = h("button", {
        class: "verify-segment " + state,
        type: "button",
        title: labels[state] + ": " + number(counts[state]) + " (" + percentage(counts[state], rows.length) + "%)"
      });
      btn.style.width = percentage(counts[state], rows.length) + "%";
      btn.addEventListener("click", function () { applyChartFilter("status", state); });
      stack.append(btn);
    });

    var legend = h("div", { class: "verify-legend" });
    states.forEach(function (state) {
      if (!counts[state]) return;
      var btn = h("button", { type: "button" },
        T.status(state),
        h("span", { class: "verify-count", text: number(counts[state]) + " · " + percentage(counts[state], rows.length) + "%" }));
      btn.addEventListener("click", function () { applyChartFilter("status", state); });
      legend.append(btn);
    });
    box.append(stack, legend);
  }

  function svgEl(name, attrs, text) {
    var el = document.createElementNS(SVG_NS, name);
    Object.keys(attrs || {}).forEach(function (key) { el.setAttribute(key, attrs[key]); });
    if (text != null) el.textContent = text;
    return el;
  }

  function midnightUtc(ms) {
    var d = new Date(ms);
    return Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate());
  }

  function trendBuckets(rows, days) {
    var now = Date.now(), out = [], i, d, key, map = {};
    rows.forEach(function (item) {
      var t = timestamp(item);
      if (isNaN(t)) return;
      d = new Date(t);
      if (!days) key = String(d.getUTCFullYear());
      else if (days <= 30) key = d.toISOString().slice(0, 10);
      else if (days <= 90) {
        var diff = Math.floor((midnightUtc(now) - midnightUtc(t)) / DAY);
        key = "w" + Math.floor(diff / 7);
      } else {
        key = d.getUTCFullYear() + "-" + String(d.getUTCMonth() + 1).padStart(2, "0");
      }
      map[key] = (map[key] || 0) + 1;
    });

    if (!days) {
      var years = Object.keys(map).map(Number).sort(function (a, b) { return a - b; });
      if (!years.length) return [];
      for (i = years[0]; i <= years[years.length - 1]; i += 1) {
        out.push({ label: String(i), count: map[String(i)] || 0 });
      }
      return out;
    }

    if (days <= 30) {
      var start = midnightUtc(now) - (days - 1) * DAY;
      for (i = 0; i < days; i += 1) {
        d = new Date(start + i * DAY);
        key = d.toISOString().slice(0, 10);
        out.push({
          label: d.toLocaleDateString("en-GB", { day: "numeric", month: "short", timeZone: "UTC" }),
          count: map[key] || 0
        });
      }
      return out;
    }

    if (days <= 90) {
      var weeks = Math.ceil(days / 7);
      for (i = weeks - 1; i >= 0; i -= 1) {
        d = new Date(midnightUtc(now) - i * 7 * DAY);
        out.push({
          label: d.toLocaleDateString("en-GB", { day: "numeric", month: "short", timeZone: "UTC" }),
          count: map["w" + i] || 0
        });
      }
      return out;
    }

    var months = 12;
    var current = new Date(now);
    for (i = months - 1; i >= 0; i -= 1) {
      d = new Date(Date.UTC(current.getUTCFullYear(), current.getUTCMonth() - i, 1));
      key = d.getUTCFullYear() + "-" + String(d.getUTCMonth() + 1).padStart(2, "0");
      out.push({
        label: d.toLocaleDateString("en-GB", { month: "short", year: "2-digit", timeZone: "UTC" }),
        count: map[key] || 0
      });
    }
    return out;
  }

  function renderTrend(rows) {
    var box = $("trend-chart");
    box.replaceChildren();
    var data = trendBuckets(rows, analyticsDays);
    if (!data.length) {
      box.append(h("p", { class: "analytics-empty", text: "No incidents in this window." }));
      return;
    }

    var width = 760, height = 220, left = 44, right = 12, top = 14, bottom = 34;
    var plotW = width - left - right, plotH = height - top - bottom;
    var max = Math.max.apply(null, data.map(function (d) { return d.count; }).concat([1]));
    var svg = svgEl("svg", {
      class: "trend-svg", viewBox: "0 0 " + width + " " + height,
      role: "img", "aria-label": "Incident volume over time"
    });

    for (var g = 0; g <= 4; g += 1) {
      var y = top + (plotH * g / 4);
      svg.append(
        svgEl("line", { x1: left, y1: y, x2: width - right, y2: y, class: "trend-grid" }),
        svgEl("text", { x: left - 8, y: y + 4, "text-anchor": "end", class: "trend-axis-text" },
          String(Math.round(max * (4 - g) / 4)))
      );
    }

    var points = data.map(function (d, idx) {
      var x = data.length === 1 ? left + plotW / 2 : left + (idx / (data.length - 1)) * plotW;
      var y = top + plotH - (d.count / max) * plotH;
      return { x: x, y: y, label: d.label, count: d.count };
    });
    var lineD = points.map(function (p, idx) { return (idx ? "L" : "M") + p.x.toFixed(1) + " " + p.y.toFixed(1); }).join(" ");
    var areaD = lineD + " L " + points[points.length - 1].x.toFixed(1) + " " + (top + plotH)
      + " L " + points[0].x.toFixed(1) + " " + (top + plotH) + " Z";
    svg.append(svgEl("path", { d: areaD, class: "trend-area" }));
    svg.append(svgEl("path", { d: lineD, class: "trend-line" }));

    var pointStep = Math.max(1, Math.ceil(points.length / 14));
    points.forEach(function (p, idx) {
      if (idx % pointStep === 0 || idx === points.length - 1) {
        var c = svgEl("circle", { cx: p.x, cy: p.y, r: 3.5, class: "trend-point" });
        c.append(svgEl("title", {}, p.label + ": " + number(p.count)));
        svg.append(c);
      }
    });

    var labelIndexes = [0, Math.floor((data.length - 1) / 2), data.length - 1].filter(function (v, idx, a) {
      return a.indexOf(v) === idx;
    });
    labelIndexes.forEach(function (idx) {
      var p = points[idx];
      var anchor = idx === 0 ? "start" : (idx === data.length - 1 ? "end" : "middle");
      svg.append(svgEl("text", {
        x: p.x, y: height - 8, "text-anchor": anchor, class: "trend-axis-text"
      }, p.label));
    });

    var peak = data.reduce(function (a, b) { return b.count > a.count ? b : a; }, data[0]);
    box.append(svg, h("p", {
      class: "chart-summary",
      text: "Peak " + number(peak.count) + " in " + peak.label + " · " + number(rows.length) + " incidents in the selected window."
    }));

    $("trend-note").textContent = !analyticsDays ? "Yearly · all time"
      : analyticsDays <= 30 ? "Daily · last " + analyticsDays + " days"
      : analyticsDays <= 90 ? "Weekly · last 90 days"
      : "Monthly · last 12 months";
  }

  function topRiser(currentRows, previousRows, getter) {
    var cur = countMap(currentRows, getter), prev = countMap(previousRows, getter);
    return Object.keys(cur).map(function (key) {
      return { label: key, current: cur[key] || 0, previous: prev[key] || 0, delta: (cur[key] || 0) - (prev[key] || 0) };
    }).filter(function (x) {
      return x.label && x.current >= 2 && x.delta > 0;
    }).sort(function (a, b) {
      return b.delta - a.delta || b.current - a.current;
    })[0] || null;
  }

  function changeDetail(current, previous) {
    var delta = current - previous;
    if (!previous) return current ? "new activity in this period" : "no change";
    var pct = Math.round((delta / previous) * 100);
    return (delta >= 0 ? "+" : "") + number(delta) + " · " + (pct >= 0 ? "+" : "") + pct + "% vs previous";
  }

  function signal(label, value, detail) {
    return h("div", { class: "signal" },
      h("span", { class: "signal-label", text: label }),
      h("strong", { text: value }),
      h("small", { text: detail }));
  }

  function renderRising(currentRows) {
    var box = $("rising-signals");
    box.replaceChildren();
    if (!analyticsDays) {
      box.append(h("p", { class: "analytics-empty", text: "Choose 7d, 30d, 90d or 1y to compare with the previous equivalent period." }));
      return;
    }
    var previousRows = windowRows(analyticsDays, 1);
    var sectorRise = topRiser(currentRows, previousRows, function (i) {
      return i.sector && i.sector !== "Other" ? i.sector : "";
    });
    var actorRise = topRiser(currentRows, previousRows, function (i) { return i.threat_actor || ""; });
    var confirmedNow = currentRows.filter(function (i) { return i.status === "confirmed"; }).length;
    var confirmedPrev = previousRows.filter(function (i) { return i.status === "confirmed"; }).length;

    box.append(
      signal("Overall volume", number(currentRows.length), changeDetail(currentRows.length, previousRows.length)),
      signal("Rising sector", sectorRise ? sectorRise.label : "No clear riser",
        sectorRise ? "+" + number(sectorRise.delta) + " incidents (" + sectorRise.previous + " → " + sectorRise.current + ")" : "structured sector data is limited"),
      signal("Rising threat actor", actorRise ? actorRise.label : "No clear riser",
        actorRise ? "+" + number(actorRise.delta) + " incidents (" + actorRise.previous + " → " + actorRise.current + ")" : "no actor has a clear increase"),
      signal("Confirmed incidents", number(confirmedNow), changeDetail(confirmedNow, confirmedPrev))
    );
  }

  function verificationUpgrades(days) {
    var now = Date.now();
    var oldest = days ? now - days * DAY : -Infinity;
    var upgrades = [];
    items.forEach(function (inc) {
      var history = (inc.history || []).slice().sort(function (a, b) {
        return String(a.date).localeCompare(String(b.date));
      });
      if (history.length < 2) return;
      var previous = history[0].status;
      for (var i = 1; i < history.length; i += 1) {
        var current = history[i].status;
        var t = new Date(history[i].date || "").getTime();
        if (strength[current] && strength[previous] && strength[current] > strength[previous] && t >= oldest && t <= now) {
          upgrades.push({ incident: inc, from: previous, to: current, date: history[i].date });
        }
        previous = current;
      }
    });
    return upgrades.sort(function (a, b) { return String(b.date).localeCompare(String(a.date)); });
  }

  function renderMovement() {
    var box = $("verification-movement");
    box.replaceChildren();
    var upgrades = verificationUpgrades(analyticsDays);
    box.append(
      h("strong", { class: "movement-total", text: number(upgrades.length) }),
      h("p", { class: "chart-summary", text: "evidence-strength upgrades in this window" })
    );
    if (!upgrades.length) {
      box.append(h("p", { class: "analytics-empty", text: "No recorded verification upgrades in this period." }));
      return;
    }
    var ul = h("ul", { class: "movement-list" });
    upgrades.slice(0, 4).forEach(function (u) {
      ul.append(h("li", null,
        h("strong", { text: u.incident.organisation || u.incident.title }),
        h("span", { text: labels[u.from] + " → " + labels[u.to] + " · " + T.date(u.date, true) })
      ));
    });
    box.append(ul);
  }

  function renderAnalytics() {
    analyticsSeg.forEach(function (b) {
      b.setAttribute("aria-pressed", parseInt(b.value, 10) === analyticsDays);
    });
    var rows = windowRows(analyticsDays, 0);
    renderKpis(rows);
    renderTrend(rows);
    renderVerification(rows);

    var knownSector = rows.filter(function (i) { return i.sector && i.sector !== "Other"; });
    var knownCountry = rows.filter(function (i) { return !!i.country; });
    var knownActor = rows.filter(function (i) { return !!i.threat_actor; });

    renderRanks("sector-chart", topCounts(knownSector, function (i) { return i.sector; }, 7), knownSector.length, "sector");
    renderRanks("country-chart", topCounts(knownCountry, function (i) { return i.country; }, 7), knownCountry.length, "country");
    renderRanks("actor-chart", topCounts(knownActor, function (i) { return i.threat_actor; }, 7), knownActor.length, "actor");
    renderRising(rows);
    renderMovement();
  }

  Promise.all([
    T.data("incidents"),
    T.data("status").catch(function () { return null; })
  ]).then(function (result) {
    var d = result[0];
    statusData = result[1];
    items = d.incidents || [];

    T.fill(type, T.unique(items.map(function (i) { return i.type; })), "All types");
    T.fill(sector, T.unique(items.map(function (i) { return i.sector; }).filter(function (v) { return v && v !== "Other"; })), "All sectors");
    T.fill(country, T.unique(items.map(function (i) { return i.country; }).filter(Boolean)), "All countries");

    var years = T.unique(items.map(function (i) { return (i.first_reported || "").slice(0, 4); }).filter(Boolean)).reverse();
    period.replaceChildren(
      h("option", { value: "", text: "All time" }),
      h("option", { value: "7d", text: "Last 7 days" }),
      h("option", { value: "30d", text: "Last 30 days" }),
      h("option", { value: "90d", text: "Last 90 days" }),
      h("option", { value: "365d", text: "Last 12 months" })
    );
    years.forEach(function (y) { period.append(h("option", { value: y, text: y })); });

    q.value = T.param("q");
    type.value = T.param("type");
    sector.value = T.param("sector");
    country.value = T.param("country");
    period.value = T.param("period");
    status = states.indexOf(T.param("status")) !== -1 ? T.param("status") : "";
    $("updated").textContent = "Last scan " + T.ago(d.updated) + ".";

    seg.forEach(function (b) {
      b.addEventListener("click", function () { status = b.value; render(); });
    });
    analyticsSeg.forEach(function (b) {
      b.addEventListener("click", function () {
        analyticsDays = parseInt(b.value, 10);
        renderAnalytics();
      });
    });
    [type, sector, country, period].forEach(function (el) { el.addEventListener("change", render); });
    q.addEventListener("input", T.debounce(render));
    exportFiltered.addEventListener("click", downloadFilteredCsv);
    reset.addEventListener("click", function () {
      q.value = "";
      type.value = "";
      sector.value = "";
      country.value = "";
      period.value = "";
      status = "";
      render();
    });

    renderAnalytics();
    render();
  }).catch(function () {
    T.failed(list, "incident tracker");
    more.hidden = true;
    $("analytics-kpis").replaceChildren(h("p", { class: "analytics-empty", text: "Analytics could not be loaded." }));
  });
})();
