(function () {
  "use strict";
  var T = window.TIS, h = T.h;
  var $ = function (id) { return document.getElementById(id); };
  var q = $("q"), type = $("type"), sector = $("sector"), period = $("period"), list = $("list"), more = $("more"), count = $("count");
  var seg = Array.prototype.slice.call(document.querySelectorAll("#status button"));
  var states = ["confirmed", "corroborated", "reported", "claimed", "disputed"];
  var labels = {
    confirmed: "confirmed",
    corroborated: "corroborated",
    reported: "reported",
    claimed: "claimed",
    disputed: "disputed"
  };
  var status = "", items = [];

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
    if (p === "30") return T.daysSince(i.last_reported) <= 30;
    return (i.first_reported || "").slice(0, 4) === p;
  }

  function render() {
    seg.forEach(function (b) { b.setAttribute("aria-pressed", b.value === status); });
    var out = items.filter(function (i) {
      if (status && i.status !== status) return false;
      if (type.value && i.type !== type.value) return false;
      if (sector.value && i.sector !== sector.value) return false;
      if (!inPeriod(i)) return false;
      return !q.value || T.matches([i.id, i.title, i.organisation, i.summary, i.why_it_matters, i.type, i.sector, i.threat_actor].join(" "), q.value);
    });
    var bits = states.map(function (state) {
      var n = out.filter(function (i) { return i.status === state; }).length;
      return n ? n + " " + labels[state] : "";
    }).filter(Boolean);
    count.textContent = T.plural(out.length, "incident") + (bits.length ? ": " + bits.join(" · ") : "");
    T.setParams({ q: q.value, status: status, type: type.value, sector: sector.value, period: period.value });
    T.paged(list, more, out, row, 40, items.length
      ? "No incidents match. Widen the period or clear a filter."
      : "No incidents recorded yet. The agent scans public sources every 30 minutes and lists what it finds here.");
  }

  T.data("incidents").then(function (d) {
    items = d.incidents || [];
    T.fill(type, T.unique(items.map(function (i) { return i.type; })), "All types");
    T.fill(sector, T.unique(items.map(function (i) { return i.sector; })), "All sectors");
    var years = T.unique(items.map(function (i) { return (i.first_reported || "").slice(0, 4); })).reverse();
    period.replaceChildren(h("option", { value: "", text: "All time" }), h("option", { value: "30", text: "Last 30 days" }));
    years.forEach(function (y) { period.append(h("option", { value: y, text: y })); });
    q.value = T.param("q");
    type.value = T.param("type");
    sector.value = T.param("sector");
    period.value = T.param("period");
    status = states.indexOf(T.param("status")) !== -1 ? T.param("status") : "";
    $("updated").textContent = "Last scan " + T.ago(d.updated) + ".";
    seg.forEach(function (b) { b.addEventListener("click", function () { status = b.value; render(); }); });
    [type, sector, period].forEach(function (el) { el.addEventListener("change", render); });
    q.addEventListener("input", T.debounce(render));
    render();
  }).catch(function () {
    T.failed(list, "incident tracker");
    more.hidden = true;
  });
})();
