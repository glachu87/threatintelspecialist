(function () {
  "use strict";
  var T = window.TIS, h = T.h, list = document.getElementById("list");
  T.data("posts").then(function (d) {
    list.replaceChildren();
    d.posts.forEach(function (p) {
      list.append(h("li", null,
        h("h2", { class: "row-title" }, h("a", { href: T.local(p.url), text: p.title })),
        h("p", { class: "excerpt", text: p.summary }),
        h("p", { class: "meta" }, h("span", { text: T.date(p.date, true) }), h("span", { text: p.minutes + " min read" }),
          (p.tags || []).map(function (t) { return h("span", { text: t }); }))));
    });
    if (!d.posts.length) list.append(h("li", { class: "empty", text: "No writeups published yet." }));
  }).catch(function () { T.failed(list, "writeups"); });
})();
