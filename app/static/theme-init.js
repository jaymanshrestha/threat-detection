// Apply the saved theme before first paint (external file: the CSP forbids inline scripts).
// Default is the dark SOC theme; the toggle in the top bar stores the choice.
(function () {
  var t = "dark";
  try { t = localStorage.getItem("td-theme") || "dark"; } catch (e) { /* storage blocked */ }
  document.documentElement.setAttribute("data-theme", t === "light" ? "light" : "dark");
})();
