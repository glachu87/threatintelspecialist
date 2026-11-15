(function () {
  "use strict";
  var T = window.TIS, h = T.h;
  var $ = function (id) { return document.getElementById(id); };
  var q = $("q"), topic = $("topic"), source = $("source"), kind = $("kind"), list = $("list"), more = $("more"), count = $("count");
  var KINDS = { news: "Press", research: "Research", official: "Official" };
  var items = [];

  function row(n) {
    return h("li", null,
      h("p", { class: "row-title" }, T.ext(n.link, n.title)),
      n.summary ? h("p", { class: "excerpt", text: n.summary }) : null,
      h("p", { class: "meta" },
        h("span", { text: n.source }),
        h("span", { text: T.ago(n.published) }),
        (n.topics || []).map(function (t) { return h("span", { text: t }); })));
  }

  function render() {
    var out = items.filter(function (n) {
      if (topic.value && (n.topics || []).indexOf(topic.value) === -1) return false;
      if (source.value && n.source !== source.value) return false;
      if (kind.value && n.kind !== kind.value) return false;
      return !q.value || T.matches(n.title + " " + n.summary + " " + n.source, q.value);
    });
    count.textContent = T.plural(out.length, "headline") + (out.length === items.length ? "" : " of " + items.length);
    T.setParams({ q: q.value, topic: topic.value, source: source.value, kind: kind.value });
    var lastDay = "";
    T.paged(list, more, out, function (n) {
      var day = n.published.slice(0, 10), node = row(n);
      if (day === lastDay) return node;
      lastDay = day;
      var frag = document.createDocumentFragment();
      frag.append(h("li", { class: "day-row" }, h("h2", { class: "day", text: T.date(n.published) })), node);
      return frag;
    }, 60, "No headlines match. Clear a filter or try a different word.");
  }

  T.data("news").then(function (d) {
    items = d.items;
    T.fill(topic, T.unique([].concat.apply([], items.map(function (n) { return n.topics || []; }))), "All topics");
    T.fill(source, T.unique(items.map(function (n) { return n.source; })), "All sources");
    kind.replaceChildren(h("option", { value: "", text: "All types" }));
    Object.keys(KINDS).forEach(function (k) { kind.append(h("option", { value: k, text: KINDS[k] })); });
    q.value = T.param("q"); topic.value = T.param("topic"); source.value = T.param("source"); kind.value = T.param("kind");
    $("updated").textContent = "Refreshed " + T.ago(d.updated) + ".";
    [topic, source, kind].forEach(function (el) { el.addEventListener("change", render); });
    q.addEventListener("input", T.debounce(render));
    render();
  }).catch(function () { T.failed(list, "headlines"); more.hidden = true; });
})();
