/* Overview dashboard: live updates pushed via Server-Sent Events (shared /api/stream connection opened
   by app.js); falls back to polling /api/summary every 5 s if SSE is unavailable or the connection drops.
   Styling only reads theme colours from CSS variables; every number shown comes from /api/summary. */
const SEV_COLORS = {Low: "#3b82f6", Medium: "#f5b31c", High: "#fb6a1d", Critical: "#ff3355"};
const CAT_COLORS = ["#8b5cf6", "#ff3355", "#22d3ee", "#22e39a", "#f5b31c", "#d946ef", "#3b82f6"];
const charts = {};
const css = (v) => getComputedStyle(document.documentElement).getPropertyValue(v).trim();

function applyTheme() {
  Chart.defaults.color = css("--chart-text");
  Chart.defaults.borderColor = css("--chart-grid");
  Chart.defaults.font.family = '"Inter", system-ui, sans-serif';
  const tt = Chart.defaults.plugins.tooltip;
  Object.assign(tt, {backgroundColor: css("--panel-solid"), titleColor: css("--text"), bodyColor: css("--text"),
    borderColor: css("--border-strong"), borderWidth: 1, padding: 10, cornerRadius: 10, boxPadding: 4, usePointStyle: true});
  Object.values(charts).forEach(c => {
    Object.values(c.options.scales || {}).forEach(s => { if (s.grid) s.grid.color = css("--chart-grid"); if (s.ticks) s.ticks.color = css("--chart-text"); });
    c.options.plugins.tooltip = Object.assign(c.options.plugins.tooltip || {}, tt);
    if (c.options.plugins.legend && c.options.plugins.legend.labels) c.options.plugins.legend.labels.color = css("--chart-text");
    c.data.datasets.forEach(ds => { if (c.config.type === "doughnut") ds.borderColor = css("--panel-solid"); });
    c.update("none");
  });
}

// vertical gradient fill for area charts (recomputed when the chart area changes)
function areaGradient(rgb) {
  return (ctx) => {
    const {chart} = ctx, a = chart.chartArea;
    if (!a) return `rgba(${rgb},.2)`;
    const g = chart.ctx.createLinearGradient(0, a.top, 0, a.bottom);
    g.addColorStop(0, `rgba(${rgb},.45)`); g.addColorStop(.6, `rgba(${rgb},.10)`); g.addColorStop(1, `rgba(${rgb},0)`);
    return g;
  };
}
function barGradient(c1, c2) {
  return (ctx) => {
    const {chart} = ctx, a = chart.chartArea;
    if (!a) return c1;
    const g = chart.ctx.createLinearGradient(a.left, 0, a.right, 0);
    g.addColorStop(0, c1); g.addColorStop(1, c2);
    return g;
  };
}
// draws the total in the middle of a doughnut
const centreText = {
  id: "centreText",
  afterDraw(chart, _args, opts) {
    if (chart.config.type !== "doughnut" || !opts || !opts.label) return;
    const total = chart.data.datasets[0].data.reduce((s, v) => s + (+v || 0), 0);
    const m = chart.getDatasetMeta(0); if (!m.data.length) return;
    const {x, y} = m.data[0];
    const c = chart.ctx; c.save(); c.textAlign = "center"; c.textBaseline = "middle";
    c.fillStyle = css("--text"); c.font = '800 24px "Inter", system-ui, sans-serif'; c.fillText(total.toLocaleString(), x, y - 8);
    c.fillStyle = css("--muted"); c.font = '600 11px "Inter", system-ui, sans-serif'; c.fillText(opts.label, x, y + 14);
    c.restore();
  },
};
Chart.register(centreText);

function mk(id, type, data, opts = {}) {
  const base = {responsive: true, maintainAspectRatio: false, animation: {duration: 700, easing: "easeOutQuart"},
    interaction: {mode: "index", intersect: false},
    plugins: {legend: {display: type !== "bar", position: type === "doughnut" ? "right" : "top",
      labels: {usePointStyle: true, pointStyle: "circle", padding: 14, color: css("--chart-text")}}}};
  if (opts.plugins) { Object.assign(base.plugins, opts.plugins); delete opts.plugins; }
  const el = document.getElementById(id);
  if (!el) return;  // widget hidden by the administrator's layout (UC-03 A2)
  charts[id] = new Chart(el, {type, data, options: Object.assign(base, opts)});
}

const lineScales = () => ({x: {grid: {display: false}, ticks: {maxTicksLimit: 10}},
  y: {beginAtZero: true, grid: {color: css("--chart-grid")}, border: {display: false}}});
const barScales = () => ({x: {beginAtZero: true, grid: {color: css("--chart-grid")}, border: {display: false}},
  y: {grid: {display: false}, border: {display: false}}});

function init() {
  applyTheme();
  mk("c-events", "line", {labels: [], datasets: [
    {label: "Events / min", data: [], borderColor: "#22d3ee", backgroundColor: areaGradient("34,211,238"), fill: true,
     pointRadius: 0, pointHoverRadius: 5, borderWidth: 2.5, tension: .35},
  ]}, {scales: lineScales()});
  mk("c-flagged", "line", {labels: [], datasets: [
    {label: "Flagged / min", data: [], borderColor: "#d946ef", backgroundColor: areaGradient("217,70,239"), fill: true,
     pointRadius: 0, pointHoverRadius: 5, borderWidth: 2.5, tension: .35},
  ]}, {scales: lineScales()});
  mk("c-sev", "doughnut", {labels: Object.keys(SEV_COLORS), datasets: [{data: [], backgroundColor: Object.values(SEV_COLORS),
    borderColor: css("--panel-solid"), borderWidth: 3, hoverOffset: 10, borderRadius: 6}]},
    {cutout: "70%", plugins: {centreText: {label: "flagged"}}});
  mk("c-cat", "doughnut", {labels: [], datasets: [{data: [], backgroundColor: CAT_COLORS,
    borderColor: css("--panel-solid"), borderWidth: 3, hoverOffset: 10, borderRadius: 6}]},
    {cutout: "70%", plugins: {centreText: {label: "alerts"}}});
  mk("c-ports", "bar", {labels: [], datasets: [{label: "Flagged flows", data: [], backgroundColor: barGradient("#06b6d4", "#8b5cf6"),
    borderRadius: 8, borderSkipped: false, barPercentage: .72}]}, {indexAxis: "y", scales: barScales()});
  mk("c-srcs", "bar", {labels: [], datasets: [{label: "Flagged flows", data: [], backgroundColor: barGradient("#fb6a1d", "#ff3355"),
    borderRadius: 8, borderSkipped: false, barPercentage: .72}]}, {indexAxis: "y", scales: barScales()});
}

function setText(id, v) { const el = document.getElementById(id); if (el) el.textContent = v; }
function setNum(id, n) { window.tdCountUp ? window.tdCountUp(document.getElementById(id), n) : setText(id, n.toLocaleString()); }

function esc(s) { return String(s).replace(/[&<>"']/g, c => ({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[c])); }

// trend chip: up/down arrow with the difference; "higherIsBad" colours rises amber/red
function setTrend(id, cur, prev, suffix) {
  const el = document.getElementById(id);
  if (!el) return;
  if (prev === null || prev === undefined || cur === null || cur === undefined) { el.classList.add("hidden"); return; }
  const diff = cur - prev;
  el.classList.remove("hidden", "up", "down", "flat");
  el.classList.add(diff > 0 ? "up" : diff < 0 ? "down" : "flat");
  el.textContent = `${diff > 0 ? "▲" : diff < 0 ? "▼" : "■"} ${diff > 0 ? "+" : ""}${diff.toLocaleString()} ${suffix}`;
}
let prevAlerts = null, lastGoodQuery = "range=all";

function setChart(id, labels, data) {
  const c = charts[id]; if (!c) return;
  if (labels) c.data.labels = labels;
  c.data.datasets[0].data = data;
}
let appliedQuery = "range=all";
function rangeQuery() {
  const range = document.getElementById("range").value;
  if (range !== "custom") return `range=${encodeURIComponent(range)}`;
  const f = document.getElementById("custom-from").value, t = document.getElementById("custom-to").value;
  return `range=custom&from=${encodeURIComponent(f)}&to=${encodeURIComponent(t)}`;
}

async function refresh() {
  const banner = document.getElementById("conn-banner"), rerr = document.getElementById("range-error");
  try {
    const r = await fetch(`/api/summary?${appliedQuery}`, {credentials: "same-origin"});
    if (r.status === 401) { banner.textContent = "Session expired - please sign in again."; banner.classList.remove("hidden"); return; }
    if (r.status === 400) {  // UC-03 E1: keep the previous view and explain why
      const e = await r.json().catch(() => ({}));
      rerr.textContent = (e.error || "That time range is not valid.") + " The previous view is still shown.";
      rerr.classList.remove("hidden"); appliedQuery = lastGoodQuery; return;
    }
    if (!r.ok) throw new Error(r.status);
    const d = await r.json();
    lastGoodQuery = appliedQuery; rerr.classList.add("hidden");
    banner.classList.add("hidden");
    const t = d.tiles;
    setNum("t-events", t.events); setNum("t-flagged", t.flagged);
    setText("t-rate", t.flag_rate + "%"); setNum("t-alerts", t.alerts);
    setText("t-grouped", `${t.grouped_detections.toLocaleString()} → ${t.alerts.toLocaleString()}`);
    setNum("t-crit", t.critical_open); setText("t-status", t.ingest_status);
    const st = document.getElementById("t-status");
    if (st) st.classList.toggle("ok", t.ingest_status === "Receiving");
    setText("t-last", t.last_received || "-"); setText("t-latest", d.latest_event || "-");
    setText("t-replay", d.replay ? `#${d.replay.id} ${d.replay.status} · ${d.replay.events.toLocaleString()} events · ${d.replay.alerts} alerts` : "none");
    const ev = d.series.events, fl = d.series.flagged, n = ev.length;
    setTrend("tr-events", n > 1 ? ev[n - 1] : null, n > 1 ? ev[n - 2] : null, "/min");
    setTrend("tr-flagged", n > 1 ? fl[n - 1] : null, n > 1 ? fl[n - 2] : null, "/min");
    setTrend("tr-alerts", t.alerts, prevAlerts, "new");
    prevAlerts = t.alerts;
    const lbl = d.series.labels.map(s => s.slice(11));
    setChart("c-events", lbl, ev); setChart("c-flagged", lbl, fl);
    setChart("c-sev", null, Object.keys(SEV_COLORS).map(k => d.severity[k] || 0));
    setChart("c-cat", Object.keys(d.categories), Object.values(d.categories));
    setChart("c-ports", d.top_ports.map(p => p[0]), d.top_ports.map(p => p[1]));
    setChart("c-srcs", d.top_sources.map(p => p[0]), d.top_sources.map(p => p[1]));
    Object.values(charts).forEach(c => c.update());
    const tl = document.getElementById("inc-timeline");
    const SC = {Critical: "crit", High: "high", Medium: "med", Low: "low"};
    if (tl) tl.innerHTML = (d.incidents || []).map(i =>
      `<li style="--sc:var(--${SC[i.severity] || "cyan"})"><a href="/incidents/${i.id}"><b>#${i.id} ${esc(i.title)}</b></a>
       <span class="badge sev-${esc(i.severity)}">${esc(i.severity)}</span> <span class="pill">${esc(i.status)}</span>
       ${i.simulated ? '<span class="sim">SIMULATED</span>' : ""}<div class="when">${esc(i.created)}</div></li>`).join("")
      || '<li class="muted">No incidents yet.</li>';
    const recent = document.getElementById("recent");
    if (recent) recent.innerHTML = d.recent_alerts.map(a =>
      `<tr><td><span class="badge sev-${esc(a.severity)}">${esc(a.severity)}</span></td>
       <td><a href="/alerts/${a.id}">${esc(a.category)}</a> ${a.simulated ? '<span class="sim">SIMULATED</span>' : ""}</td>
       <td>${esc(a.src)} → ${esc(a.dst)}</td><td>${a.count.toLocaleString()}</td><td>${esc(a.last_seen)}</td></tr>`).join("")
      || '<tr><td colspan="5" class="muted">No alerts yet - start the replay simulator.</td></tr>';
  } catch (e) {
    banner.textContent = "Live updates are paused - connection lost. Showing the last data received; retrying automatically.";
    banner.classList.remove("hidden");
  }
}

let pollTimer = null, busy = false, again = false;
async function refreshOnce() {
  if (busy) { again = true; return; }
  busy = true;
  try { await refresh(); } finally { busy = false; if (again) { again = false; refreshOnce(); } }
}
function startPolling() {
  if (!pollTimer) { pollTimer = setInterval(refreshOnce, 5000); setText("t-live", "polling every 5 s"); }
}
function stopPolling() { if (pollTimer) { clearInterval(pollTimer); pollTimer = null; } }
function startStream() {
  const s = window.tdStream;
  if (!s || !s.es) { startPolling(); return; }
  const onOpen = () => { stopPolling(); setText("t-live", "live (server push)"); };
  if (s.state === "open") onOpen();
  window.addEventListener("td:open", onOpen);
  window.addEventListener("td:tick", refreshOnce);
  // the browser reconnects automatically; poll meanwhile so the page never goes stale
  window.addEventListener("td:error", startPolling);
}

init(); refreshOnce();
(() => {
  const sel = document.getElementById("range"), custom = ["custom-from-f", "custom-to-f", "custom-apply"].map(i => document.getElementById(i));
  sel.addEventListener("change", () => {
    const isCustom = sel.value === "custom";
    custom.forEach(el => el.classList.toggle("hidden", !isCustom));
    if (!isCustom) { appliedQuery = rangeQuery(); refreshOnce(); }
  });
  document.getElementById("custom-apply").addEventListener("click", () => { appliedQuery = rangeQuery(); refreshOnce(); });
})();
window.addEventListener("td:theme", applyTheme);
startStream();
