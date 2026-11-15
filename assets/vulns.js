(function () {
  "use strict";
  var T = window.TIS, h = T.h;
  var $ = function (id) { return document.getElementById(id); };
  var q = $("q"), list = $("list"), more = $("more"), count = $("count");
  var tabKev = $("tab-kev"), tabNew = $("tab-new"), ransom = $("ransom"), ransomWrap = $("ransom-wrap"), sev = $("sev"), sevWrap = $("sev-wrap");
  var data = null, tab = "kev";

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
        h("span", null, h("span", { class: "cve", text: v.cve }), h("span", { class: "when", text: "Added " + T.date(v.added, true) })),
        h("span", null,
          h("span", { class: "row-title", text: v.name || v.vendor + " " + v.product }),
          h("span", { class: "meta" }, h("span", { text: v.vendor + " · " + v.product }),
            v.ransomware ? h("span", { class: "flag danger", text: "Used by ransomware" }) : null))),
      h("div", { class: "vuln-body" },
        h("p", { text: v.description }),
        h("dl", null,
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
            v.kev ? h("span", { class: "flag danger", text: "Being exploited" }) : null,
            v.vector ? h("span", { text: "Attack route: " + v.vector.toLowerCase() }) : null))),
      h("div", { class: "vuln-body" },
        h("p", { text: v.description }),
        h("dl", null,
          h("dt", { text: "Severity" }), h("dd", { text: v.severity + ", " + v.score + " out of 10 (CVSS " + v.cvss_version + ")" }),
          epss(v)),
        links(v.cve)));
  }

  function render() {
    var kev = tab === "kev";
    tabKev.setAttribute("aria-pressed", kev); tabNew.setAttribute("aria-pressed", !kev);
    ransomWrap.hidden = !kev; sevWrap.hidden = kev;
    var src = kev ? data.kev.items : data.recent.items;
    var out = src.filter(function (v) {
      if (kev && ransom.checked && !v.ransomware) return false;
      if (!kev && sev.value && v.severity !== sev.value) return false;
      return !q.value || T.matches([v.cve, v.name, v.vendor, v.product, v.description].join(" "), q.value);
    });
    count.textContent = (kev ? T.plural(out.length, "exploited vulnerability", "exploited vulnerabilities") : T.plural(out.length, "new vulnerability", "new vulnerabilities"))
      + (out.length === src.length ? "" : " of " + src.length);
    T.setParams({ q: q.value, tab: kev ? "" : "new", ransomware: kev && ransom.checked ? "1" : "", severity: kev ? "" : sev.value });
    var empty = src.length ? "Nothing matches. Clear the search or a filter."
      : kev ? "The exploited list is empty right now. It refreshes every hour."
            : "No new high or critical vulnerabilities have been loaded yet. This list fills on the next hourly refresh.";
    T.paged(list, more, out, kev ? kevRow : newRow, 60, empty);
    if (out.length === 1) { var d = list.querySelector("details"); if (d) d.open = true; }
  }

  T.data("vulnerabilities").then(function (d) {
    data = d;
    q.value = T.param("q");
    tab = T.param("tab") === "new" ? "new" : "kev";
    ransom.checked = T.param("ransomware") === "1";
    sev.value = T.param("severity");
    /* a CVE searched from elsewhere may only be in the other list */
    if (q.value && tab === "kev" && !d.kev.items.some(function (v) { return T.matches(v.cve + " " + v.name, q.value); })
        && d.recent.items.some(function (v) { return T.matches(v.cve, q.value); })) tab = "new";
    $("updated").textContent = "Exploited list refreshed " + T.ago(d.kev.updated) + "."
      + (d.recent.updated ? " New-this-week list refreshed " + T.ago(d.recent.updated) + "." : "");
    tabKev.addEventListener("click", function () { tab = "kev"; render(); });
    tabNew.addEventListener("click", function () { tab = "new"; render(); });
    ransom.addEventListener("change", render); sev.addEventListener("change", render);
    q.addEventListener("input", T.debounce(render));
    render();
  }).catch(function () { T.failed(list, "vulnerability data"); more.hidden = true; });
})();
