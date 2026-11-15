// Shared helpers, header and footer. Everything from the data files is treated as
// untrusted text: it is only ever inserted with textContent, never as HTML.
(function () {
  "use strict";
  var T = (window.TIS = {});
  var SVG = "http://www.w3.org/2000/svg";

  T.h = function (tag, attrs) {
    var el = document.createElement(tag);
    for (var k in attrs || {}) {
      var v = attrs[k];
      if (v == null || v === false) continue;
      if (k === "class") el.className = v;
      else if (k === "text") el.textContent = v;
      else if (k.slice(0, 2) === "on") el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v === true ? "" : v);
    }
    for (var i = 2; i < arguments.length; i++) {
      var kid = arguments[i];
      if (kid == null || kid === false) continue;
      if (Array.isArray(kid)) kid.forEach(function (c) { if (c != null && c !== false) el.append(c); });
      else el.append(kid);
    }
    return el;
  };
  var h = T.h;

  T.safeUrl = function (u) { return typeof u === "string" && /^https?:\/\//i.test(u) ? u : null; };

  /* Only same-site paths, e.g. "/blog/post/". */
  T.local = function (u) { return typeof u === "string" && /^\/(?!\/)/.test(u) ? u : "/blog/"; };

  T.ext = function (url, text, cls) {
    var safe = T.safeUrl(url);
    if (!safe) return h("span", { class: cls, text: text });
    return h("a", { href: safe, class: cls, rel: "noopener noreferrer", target: "_blank", text: text });
  };

  T.data = function (name) {
    return fetch("/data/" + name + ".json", { cache: "no-cache" }).then(function (r) {
      if (!r.ok) throw new Error(name + " " + r.status);
      return r.json();
    });
  };

  T.date = function (iso, short) {
    var d = new Date(iso && iso.length === 10 ? iso + "T00:00:00Z" : iso);
    if (isNaN(d)) return "";
    return d.toLocaleDateString("en-GB", short
      ? { day: "numeric", month: "short", year: "numeric", timeZone: "UTC" }
      : { weekday: "long", day: "numeric", month: "long", year: "numeric" });
  };

  T.ago = function (iso) {
    var d = new Date(iso && iso.length === 10 ? iso + "T00:00:00Z" : iso);
    if (isNaN(d)) return "";
    var mins = Math.round((Date.now() - d.getTime()) / 60000);
    if (mins < 1) return "just now";
    if (mins < 60) return mins + " min ago";
    var hrs = Math.round(mins / 60);
    if (hrs < 24) return hrs + (hrs === 1 ? " hour ago" : " hours ago");
    var days = Math.round(hrs / 24);
    if (days < 31) return days + (days === 1 ? " day ago" : " days ago");
    return T.date(iso, true);
  };

  T.daysSince = function (iso) {
    var d = new Date(iso && iso.length === 10 ? iso + "T00:00:00Z" : iso);
    return isNaN(d) ? Infinity : (Date.now() - d.getTime()) / 86400000;
  };

  T.plural = function (n, one, many) { return n + " " + (n === 1 ? one : many || one + "s"); };
  T.param = function (name) { return new URLSearchParams(location.search).get(name) || ""; };
  T.setParams = function (obj) {
    var p = new URLSearchParams();
    for (var k in obj) if (obj[k]) p.set(k, obj[k]);
    var qs = p.toString();
    history.replaceState(null, "", location.pathname + (qs ? "?" + qs : ""));
  };
  T.matches = function (haystack, query) {
    var words = query.toLowerCase().split(/\s+/).filter(Boolean);
    var text = haystack.toLowerCase();
    return words.every(function (w) { return text.indexOf(w) !== -1; });
  };
  T.debounce = function (fn, ms) {
    var t;
    return function () { clearTimeout(t); t = setTimeout(fn, ms || 150); };
  };
  T.fill = function (select, values, allLabel) {
    select.replaceChildren(h("option", { value: "", text: allLabel }));
    values.forEach(function (v) { select.append(h("option", { value: v, text: v })); });
  };
  T.unique = function (list) {
    return Array.from(new Set(list.filter(Boolean))).sort(function (a, b) { return a.localeCompare(b); });
  };

  T.status = function (status) {
    var labels = {
      confirmed: "Confirmed",
      corroborated: "Corroborated",
      reported: "Reported",
      claimed: "Claimed",
      disputed: "Disputed"
    };
    var key = labels[status] ? status : "reported";
    return h("span", { class: "status " + key, text: labels[key] });
  };

  T.failed = function (container, what) {
    container.replaceChildren(h("p", { class: "empty" },
      "The " + what + " could not be loaded. Check your connection and reload the page. ",
      "If it keeps happening, the data may be mid-update: try again in a minute."));
  };

  /* Renders a list in pages so long lists stay fast. */
  T.paged = function (container, moreBtn, items, renderItem, pageSize, emptyText) {
    var shown = 0;
    container.replaceChildren();
    function more() {
      items.slice(shown, shown + pageSize).forEach(function (it) { container.append(renderItem(it)); });
      shown = Math.min(items.length, shown + pageSize);
      moreBtn.hidden = shown >= items.length;
    }
    moreBtn.onclick = more;
    if (!items.length) { container.append(h("li", { class: "empty", text: emptyText })); moreBtn.hidden = true; }
    else more();
  };

  /* ── header and footer ── */
  function icon(paths, attrs) {
    var s = document.createElementNS(SVG, "svg");
    s.setAttribute("viewBox", "0 0 24 24");
    s.setAttribute("fill", "none");
    s.setAttribute("stroke", "currentColor");
    s.setAttribute("stroke-width", "2");
    s.setAttribute("stroke-linecap", "round");
    s.setAttribute("stroke-linejoin", "round");
    s.setAttribute("aria-hidden", "true");
    paths.forEach(function (d) {
      var p = document.createElementNS(SVG, "path");
      p.setAttribute("d", d);
      for (var k in attrs || {}) p.setAttribute(k, attrs[k]);
      s.append(p);
    });
    return s;
  }
  var MARK = ["M12 2.5 4 5.5v6c0 4.9 3.3 8.6 8 10 4.7-1.4 8-5.1 8-10v-6l-8-3Z", "M12 10.2v4.3", "M12 9.2h.01"];
  var SUN = ["M12 3v2M12 19v2M3 12h2M19 12h2M5.6 5.6 7 7M17 17l1.4 1.4M5.6 18.4 7 17M17 7l1.4-1.4", "M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8Z"];
  var MOON = ["M20 14.5A8 8 0 0 1 9.5 4a8 8 0 1 0 10.5 10.5Z"];

  var NAV = [
    ["/", "Today", "home"],
    ["/news/", "News", "news"],
    ["/vulnerabilities/", "Vulnerabilities", "vulnerabilities"],
    ["/incidents/", "Incidents", "incidents"],
    ["/blog/", "Blog", "blog"],
    ["/learn/", "Learn", "learn"],
    ["/about/", "About", "about"],
  ];

  function renderHeader() {
    var host = document.getElementById("site-header");
    if (!host) return;
    var page = document.body.getAttribute("data-page");
    var themeBtn = h("button", { class: "icon-btn", type: "button" });
    function paint() {
      var dark = document.documentElement.getAttribute("data-theme") === "dark";
      themeBtn.replaceChildren(icon(dark ? SUN : MOON));
      themeBtn.setAttribute("aria-label", dark ? "Switch to light theme" : "Switch to dark theme");
    }
    themeBtn.addEventListener("click", function () {
      var next = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
      document.documentElement.setAttribute("data-theme", next);
      try { localStorage.setItem("tis-theme", next); } catch (e) { /* stays for this page only */ }
      paint();
    });
    paint();
    host.replaceChildren(h("div", { class: "wrap bar" },
      h("a", { class: "brand", href: "/" }, icon(MARK), "Threat Intel Specialist"),
      h("nav", { "aria-label": "Main" }, h("ul", { class: "nav" }, NAV.map(function (n) {
        return h("li", null, h("a", { href: n[0], "aria-current": n[2] === page ? "page" : null, text: n[1] }));
      }))),
      h("div", { class: "tools" },
        h("form", { class: "site-search", action: "/search/", method: "get", role: "search" },
          h("label", { class: "sr", for: "site-q", text: "Search the site" }),
          h("input", { id: "site-q", type: "search", name: "q", placeholder: "Search", value: page === "search" ? T.param("q") : null })),
        themeBtn)));
  }

  function renderFooter() {
    var host = document.getElementById("site-footer");
    if (!host) return;
    host.replaceChildren(h("div", { class: "wrap" },
      h("p", null, "Threat Intel Specialist gathers public cybersecurity reporting in one place. Headlines link to their original publishers. ",
        h("a", { href: "/about/", text: "How this site works" }), "."),
      h("ul", null, NAV.slice(1).map(function (n) { return h("li", null, h("a", { href: n[0], text: n[1] })); }))));
  }

  /* Google Analytics (same property the site used before). */
  function analytics() {
    var id = "G-NYCC5SQJNN";
    var s = document.createElement("script");
    s.async = true;
    s.src = "https://www.googletagmanager.com/gtag/js?id=" + id;
    document.head.append(s);
    window.dataLayer = window.dataLayer || [];
    window.gtag = function () { window.dataLayer.push(arguments); };
    window.gtag("js", new Date());
    window.gtag("config", id);
  }

  renderHeader();
  renderFooter();
  if (location.hostname.indexOf("threatintelspecialist.com") !== -1) analytics();
})();
