// confirm dialogs for destructive admin actions (no inline JS, CSP-friendly)
document.addEventListener("submit", (e) => {
  const msg = e.target.getAttribute("data-confirm");
  if (msg && !window.confirm(msg)) e.preventDefault();
});
// client-side email format hint + disable sign-in until both fields are filled
(() => {
  const f = document.getElementById("login-form");
  if (!f) return;
  const em = f.querySelector("[name=email]"), pw = f.querySelector("[name=password]"),
    btn = f.querySelector("button"), hint = document.getElementById("email-hint");
  const upd = () => {
    const okEmail = /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(em.value);
    hint.classList.toggle("hidden", !em.value || okEmail);
    btn.disabled = !(okEmail && pw.value);
  };
  em.addEventListener("input", upd); pw.addEventListener("input", upd); upd();
})();
// periodic page refresh for tables that opt in (data-autorefresh="seconds")
(() => {
  const el = document.querySelector("[data-autorefresh]");
  if (el) setTimeout(() => location.reload(), 1000 * parseInt(el.dataset.autorefresh, 10));
})();

// ---------- UI shell: theme toggle, mobile sidebar, one shared live stream per tab ----------
(() => {
  const root = document.documentElement;
  const themeBtn = document.getElementById("theme-btn");
  if (themeBtn) themeBtn.addEventListener("click", () => {
    const next = root.getAttribute("data-theme") === "light" ? "dark" : "light";
    root.setAttribute("data-theme", next);
    try { localStorage.setItem("td-theme", next); } catch (e) { /* ignore */ }
    window.dispatchEvent(new CustomEvent("td:theme", {detail: next}));
  });
  const menuBtn = document.getElementById("menu-btn");
  if (menuBtn) {
    menuBtn.addEventListener("click", () => {
      const open = document.body.classList.toggle("nav-open");
      menuBtn.setAttribute("aria-expanded", String(open));
    });
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && document.body.classList.contains("nav-open")) {
        document.body.classList.remove("nav-open"); menuBtn.setAttribute("aria-expanded", "false"); menuBtn.focus();
      }
    });
  }

  // Live indicator + shared Server-Sent Events connection (/api/stream). Pages listen for
  // window events "td:open", "td:tick" and "td:error" instead of opening their own stream.
  const live = document.getElementById("live"), liveText = document.getElementById("live-text");
  const stream = window.tdStream = {state: "none", es: null};
  if (!live || !document.body.classList.contains("app")) return;
  const setLive = (cls, text) => {
    live.classList.remove("on", "poll", "off"); if (cls) live.classList.add(cls);
    liveText.textContent = text;
  };
  if (!window.EventSource) { stream.state = "unsupported"; setLive("poll", "Polling"); return; }
  const es = stream.es = new EventSource("/api/stream");
  stream.state = "connecting";
  let tickTimer = null;
  es.addEventListener("open", () => {
    stream.state = "open"; setLive("on", "Live · streaming");
    window.dispatchEvent(new Event("td:open"));
  });
  es.addEventListener("tick", () => {
    live.classList.add("tick"); clearTimeout(tickTimer);
    tickTimer = setTimeout(() => live.classList.remove("tick"), 450);
    window.dispatchEvent(new Event("td:tick"));
  });
  es.addEventListener("error", () => {
    // the browser reconnects automatically; pages fall back to polling meanwhile
    stream.state = "error"; setLive("off", "Reconnecting…");
    window.dispatchEvent(new Event("td:error"));
  });
  window.addEventListener("pagehide", () => es.close());
})();

// ---------- animated count-up for numeric text (respects reduced motion) ----------
window.tdCountUp = (el, target, fmt = (n) => Math.round(n).toLocaleString()) => {
  if (!el) return;
  const reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const from = parseFloat(el.dataset.n || "0");
  el.dataset.n = String(target);
  if (reduce || from === target || !isFinite(target)) { el.textContent = fmt(target); return; }
  const t0 = performance.now(), dur = 900;
  const step = (t) => {
    const p = Math.min(1, (t - t0) / dur), e = 1 - Math.pow(1 - p, 3);
    el.textContent = p < 1 ? fmt(from + (target - from) * e) : fmt(target);
    if (p < 1 && el.dataset.n === String(target)) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
};

// ---------- threshold slider <-> number field (models page) ----------
(() => {
  const slider = document.getElementById("threshold-slider"), num = document.getElementById("threshold");
  if (!slider || !num) return;
  slider.addEventListener("input", () => { num.value = parseFloat(slider.value).toFixed(2); });
  num.addEventListener("input", () => { const v = parseFloat(num.value); if (isFinite(v)) slider.value = String(v); });
})();

// ---------- sensitivity presets + preview before applying (UC-06 A2) ----------
(() => {
  const num = document.getElementById("threshold"), slider = document.getElementById("threshold-slider");
  const out = document.getElementById("threshold-preview"), preset = document.getElementById("preset");
  if (!num || !out) return;
  const preview = () => {
    const v = parseFloat(num.value);
    document.querySelectorAll("table.sweep tr.preview").forEach(r => r.classList.remove("preview"));
    if (!isFinite(v)) { out.textContent = "Enter a threshold between 0 and 1."; return; }
    const key = v.toFixed(2), parts = [];
    document.querySelectorAll("table.sweep").forEach(t => {
      const row = t.querySelector(`tr[data-t="${key}"]`);
      if (!row) return;
      row.classList.add("preview");
      parts.push(`${t.dataset.model}${t.dataset.active ? " (active)" : ""}: precision ${row.dataset.p}, recall ${row.dataset.r}, ~${row.dataset.fph} false-positive flows/hour`);
    });
    out.textContent = parts.length ? `Preview at ${key} - ` + parts.join(" · ") : `No test-day preview for ${key}: use 0.50-0.95 in steps of 0.05.`;
  };
  document.querySelectorAll("[data-preset]").forEach(b => b.addEventListener("click", () => {
    num.value = b.dataset.preset; if (slider) slider.value = b.dataset.preset;
    if (preset) preset.value = b.dataset.name; preview();
  }));
  num.addEventListener("input", () => { if (preset) preset.value = ""; preview(); });
  if (slider) slider.addEventListener("input", () => { if (preset) preset.value = ""; preview(); });
})();

// ---------- replay progress (UC-02 step 6) ----------
(() => {
  const box = document.getElementById("sim-progress");
  if (!box) return;
  const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
  const tick = async () => {
    try {
      const r = await fetch(box.dataset.statusUrl, {credentials: "same-origin"});
      if (!r.ok) return;
      const d = await r.json();
      set("sim-status", d.status); set("sim-events", d.events_sent.toLocaleString()); set("sim-alerts", d.alerts_raised);
      const pct = d.events_planned ? Math.min(100, 100 * d.events_sent / d.events_planned) : 0;
      const bar = document.getElementById("sim-bar");
      if (bar) { bar.setAttribute("aria-valuenow", String(Math.round(pct))); bar.firstElementChild.style.width = pct.toFixed(1) + "%"; }
      if (!["Running", "Paused", "Stopping"].includes(d.status)) { window.location.href = box.dataset.doneUrl; return; }
    } catch (e) { /* keep last values; retry */ }
    setTimeout(tick, 2000);
  };
  setTimeout(tick, 1500);
})();
