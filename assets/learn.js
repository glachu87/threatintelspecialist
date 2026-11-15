(function () {
  "use strict";
  var box = document.getElementById("term"), terms = Array.prototype.slice.call(document.querySelectorAll(".glossary > div")), none = document.getElementById("no-term");
  box.addEventListener("input", function () {
    var q = box.value.trim().toLowerCase(), shown = 0;
    terms.forEach(function (t) { var hit = !q || t.textContent.toLowerCase().indexOf(q) !== -1; t.hidden = !hit; if (hit) shown++; });
    none.hidden = shown > 0;
  });
})();
