// Shows whether each source was read successfully on the last refresh.
(function () {
  "use strict";
  var T = window.TIS, h = T.h, list = document.getElementById("health"), note = document.getElementById("health-note");
  T.data("status").then(function (s) {
    var all = (s.apis || []).concat(s.feeds || []);
    list.replaceChildren();
    all.forEach(function (f) {
      list.append(h("li", null, h("span", { class: f.ok ? "ok" : "bad", text: f.ok ? "OK" : "Failed" }), " ", f.name));
    });
    var bad = all.filter(function (f) { return !f.ok; }).length;
    note.textContent = "Last refresh " + T.ago(s.updated) + ". " + (bad ? T.plural(bad, "source") + " could not be read; earlier data from " + (bad === 1 ? "it is" : "them is") + " still shown." : "Every source was read.")
      + (s.ai_enabled ? " AI-assisted incident labelling is on." : " Incident labelling is rule-based (no AI).");
  }).catch(function () { note.textContent = "Source status is not available yet. It appears after the first data refresh."; });
})();
