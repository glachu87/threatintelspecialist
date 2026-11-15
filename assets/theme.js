// Runs before the page paints so the chosen theme never flashes.
(function () {
  var theme = null;
  try { theme = localStorage.getItem("tis-theme"); } catch (e) { /* storage unavailable */ }
  if (theme !== "light" && theme !== "dark") {
    theme = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }
  document.documentElement.setAttribute("data-theme", theme);
})();
