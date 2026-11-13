/* Threat map: Leaflet (vendored) + offline Natural Earth basemap (app/static/world.geojson);
   data from /api/geo; refreshes on the shared SSE stream (app.js) or every 30 s. */
(() => {
  const el = document.getElementById("map");
  if (!el) return;
  const SEV = {Low: "#3b82f6", Medium: "#f5b31c", High: "#fb6a1d", Critical: "#ff3355"};
  const map = L.map(el, {worldCopyJump: true, zoomControl: true}).setView([20, 10], 2);
  // Offline basemap: Natural Earth country outlines (public domain) shipped with the app,
  // so the map needs no API key, no external tile server and works without internet.
  map.attributionControl.addAttribution('Basemap: <a href="https://www.naturalearthdata.com">Natural Earth</a> &middot; IP Geolocation by <a href="https://db-ip.com">DB-IP</a>');
  const isDark = () => document.documentElement.getAttribute("data-theme") !== "light";
  const landStyle = () => isDark()
    ? {color: "#3b4a6b", weight: 0.8, fillColor: "#1a2340", fillOpacity: 1}
    : {color: "#94a3b8", weight: 0.8, fillColor: "#e2e8f0", fillOpacity: 1};
  const paintSea = () => { el.style.background = isDark() ? "#0b1020" : "#f8fafc"; };
  paintSea();
  let land = null;
  fetch(el.dataset.world || "/static/world.geojson").then(r => r.json()).then(g => {
    land = L.geoJSON(g, {style: landStyle, interactive: false}).addTo(map);
    land.bringToBack();
  }).catch(() => {});
  new MutationObserver(() => { paintSea(); if (land) land.setStyle(landStyle()); })
    .observe(document.documentElement, {attributes: true, attributeFilter: ["data-theme"]});
  const layer = L.layerGroup().addTo(map);
  const esc = s => String(s).replace(/[&<>"']/g, c => ({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[c]));
  let fitted = false;

  async function load() {
    const sev = document.getElementById("sev").value;
    const r = await fetch("/api/geo" + (sev ? "?severity=" + encodeURIComponent(sev) : ""), {credentials: "same-origin"});
    if (!r.ok) return;
    const d = await r.json();
    layer.clearLayers();
    const bounds = [];
    d.lines.forEach(l => {
      L.polyline([l.from, l.to], {color: SEV[l.severity] || "#94a3b8", weight: 1.5 + Math.min(4, Math.log10(1 + l.count)), opacity: .7,
        className: `glow-${l.severity} flow-${l.severity}`})
        .bindPopup(`<b>Alert #${l.id}</b> ${esc(l.severity)}<br>${esc(l.category)}<br>${esc(l.label)}<br>${l.count} flows<br><a href="/alerts/${l.id}">Open alert</a>`)
        .addTo(layer);
    });
    d.points.forEach(p => {
      const m = L.circleMarker([p.lat, p.lon], {radius: 5 + Math.min(10, Math.sqrt(p.alerts)), color: p.internal ? "#e6ecff" : SEV[p.severity],
        weight: p.internal ? 3 : 1.5, fillColor: SEV[p.severity] || "#94a3b8", fillOpacity: .8, className: `glow-${p.severity}`});
      m.bindPopup(`<b>${esc(p.ip)}</b>${p.internal ? " (internal)" : ""}<br>${esc(p.place || "unknown place")}<br>role: ${esc(p.roles.join(", "))}<br>${p.alerts} alert(s), highest ${esc(p.severity)}`);
      m.addTo(layer);
      bounds.push([p.lat, p.lon]);
    });
    document.getElementById("map-stats").textContent =
      `${d.points.length} locations, ${d.lines.length} alert lines, ${d.unknown_locations} address(es) without a known location`;
    if (!fitted && bounds.length) { map.fitBounds(bounds, {padding: [30, 30], maxZoom: 5}); fitted = true; }
  }
  document.getElementById("sev").addEventListener("change", load);
  load();
  let t = 0;
  window.addEventListener("td:tick", () => { if (Date.now() - t > 5000) { t = Date.now(); load(); } });
  setInterval(load, 30000);
})();
