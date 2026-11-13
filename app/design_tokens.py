"""Design tokens for the SentinelSMB UI and a WCAG 2.1 contrast audit.

These hex values mirror the CSS custom properties in app/static/style.css
(tests/test_accessibility.py checks they stay in sync). Translucent CSS surfaces
(--panel) are listed here as their composited solid colour over --bg, which is
what the eye actually sees and what contrast must be measured against.

Used by the in-app style guide (/style-guide) and docs/design (accessibility report).
"""

# Human-readable groups for the style guide palette.
PALETTE_GROUPS = [
    ("Surfaces", ["bg", "surface", "input", "input_border"]),
    ("Text", ["text", "muted", "faint", "link", "th"]),
    ("Accents", ["cyan", "violet", "magenta", "green"]),
    ("Severity (fills, dots, charts)", ["low", "med", "high", "crit"]),
    ("Severity (text on badges)", ["low_fg", "med_fg", "high_fg", "crit_fg"]),
    ("Primary button gradient", ["btn_1", "btn_2", "btn_3"]),
]

TOKEN_CSS = {  # token -> CSS custom property (None = derived / not a variable)
    "bg": "--bg", "surface": None, "input": "--input", "input_border": "--input-border",
    "text": "--text", "muted": "--muted", "faint": "--faint", "link": "--cyan", "th": "--th",
    "cyan": "--cyan", "violet": "--violet", "magenta": "--magenta", "green": "--green",
    "low": "--low", "med": "--med", "high": "--high", "crit": "--crit",
    "low_fg": "--low-fg", "med_fg": "--med-fg", "high_fg": "--high-fg", "crit_fg": "--crit-fg",
    "btn_1": "--btn-1", "btn_2": "--btn-2", "btn_3": "--btn-3",
}

THEMES = {
    "dark": {
        "bg": "#060914", "surface": "#0d1225", "input": "#0a1129", "input_border": "#636f97",
        "text": "#e6ecff", "muted": "#93a1c4", "faint": "#8592b8", "link": "#22d3ee", "th": "#a9b6dc",
        "cyan": "#22d3ee", "violet": "#8b5cf6", "magenta": "#d946ef", "green": "#22e39a",
        "low": "#3b82f6", "med": "#f5b31c", "high": "#fb6a1d", "crit": "#ff3355",
        "low_fg": "#7aaaff", "med_fg": "#f5b31c", "high_fg": "#fb7a35", "crit_fg": "#ff6b82",
        "btn_1": "#0e7490", "btn_2": "#7c3aed", "btn_3": "#a21caf", "white": "#ffffff",
    },
    "light": {
        "bg": "#eef2fb", "surface": "#fbfcfe", "input": "#ffffff", "input_border": "#7d88a6",
        "text": "#0d1430", "muted": "#4b5878", "faint": "#5f6b8a", "link": "#0e7490", "th": "#3b4766",
        "cyan": "#0e7490", "violet": "#7c3aed", "magenta": "#a21caf", "green": "#047857",
        "low": "#2563eb", "med": "#d97706", "high": "#ea580c", "crit": "#e11d48",
        "low_fg": "#1d4ed8", "med_fg": "#92400e", "high_fg": "#9a3412", "crit_fg": "#9f1239",
        "btn_1": "#0e7490", "btn_2": "#7c3aed", "btn_3": "#a21caf", "white": "#ffffff",
    },
}

# (description, foreground, background, kind, where it is used)
# kind: "text" needs 4.5:1, "large" (>=18.66px bold / 24px) and "ui" (borders, focus rings, icons) need 3:1.
# A background written "tint:<token>" is that colour at 14 % over the surface (the badge fill).
PAIRS = [
    ("Body text on page", "text", "bg", "text", "all pages"),
    ("Body text on card", "text", "surface", "text", "cards, tables"),
    ("Secondary text on card", "muted", "surface", "text", "help text, captions, labels"),
    ("Secondary text on page", "muted", "bg", "text", "page subtitles"),
    ("Tertiary text (nav headings)", "faint", "surface", "text", "sidebar section headings"),
    ("Table header text", "th", "surface", "text", "table headers"),
    ("Link text on card", "link", "surface", "text", "links, report headings"),
    ("Link text on page", "link", "bg", "text", "links outside cards"),
    ("Hover link (accent)", "magenta", "surface", "text", "link hover"),
    ("Success text", "green", "surface", "text", "ingest status, live indicator"),
    ("Input text", "text", "input", "text", "form fields"),
    ("Input border vs card", "input_border", "surface", "ui", "form field outline (WCAG 1.4.11)"),
    ("Focus ring vs page", "cyan", "bg", "ui", "keyboard focus outline"),
    ("Focus ring vs card", "cyan", "surface", "ui", "keyboard focus outline"),
    ("Button text on gradient start", "white", "btn_1", "text", "primary buttons, active tabs"),
    ("Button text on gradient middle", "white", "btn_2", "text", "primary buttons, active tabs"),
    ("Button text on gradient end", "white", "btn_3", "text", "primary buttons, active tabs"),
    ("Low badge text", "low_fg", "tint:low", "text", "severity badge"),
    ("Medium badge text", "med_fg", "tint:med", "text", "severity badge"),
    ("High badge text", "high_fg", "tint:high", "text", "severity badge"),
    ("Critical badge text", "crit_fg", "tint:crit", "text", "severity badge"),
    ("Critical KPI number", "crit", "surface", "large", "Open critical alerts tile (32px bold)"),
    ("Severity dot / chart colour Low", "low", "surface", "ui", "badge dot, charts, map"),
    ("Severity dot / chart colour Medium", "med", "surface", "ui", "badge dot, charts, map"),
    ("Severity dot / chart colour High", "high", "surface", "ui", "badge dot, charts, map"),
    ("Severity dot / chart colour Critical", "crit", "surface", "ui", "badge dot, charts, map"),
]

REQUIRED = {"text": 4.5, "large": 3.0, "ui": 3.0}

TYPE_SCALE = [  # (name, css size, weight, sample usage)
    ("H1 - page title", "26px", 800, "Network overview"),
    ("H2 - section title", "15px", 700, "Traffic over time"),
    ("H3 - sub-section", "13.5px", 700, "What happened"),
    ("KPI value", "32px", 800, "239,855"),
    ("Body", "14px", 400, "Security operations view of ingested flows."),
    ("Small / caption", "12.5px", 400, "Auto-refreshes every 15 s."),
    ("Overline / label", "11.5px", 700, "EVENTS"),
]


def _rgb(h):
    h = h.lstrip("#")
    return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))


def _hex(c):
    return "#%02x%02x%02x" % c


def blend(fg, alpha, bg):
    f, b = _rgb(fg), _rgb(bg)
    return _hex(tuple(round(x * alpha + y * (1 - alpha)) for x, y in zip(f, b)))


def luminance(h):
    def ch(v):
        v /= 255
        return v / 12.92 if v <= 0.03928 else ((v + 0.055) / 1.055) ** 2.4
    r, g, b = (ch(v) for v in _rgb(h))
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast(a, b):
    la, lb = sorted((luminance(a), luminance(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


def _resolve(theme, name):
    t = THEMES[theme]
    if name.startswith("tint:"):
        return blend(t[name[5:]], 0.14, t["surface"])
    return t[name]


def audit(theme):
    rows = []
    for desc, fg, bg, kind, where in PAIRS:
        f, b = _resolve(theme, fg), _resolve(theme, bg)
        ratio = contrast(f, b)
        need = REQUIRED[kind]
        rows.append({"pair": desc, "fg": f, "bg": b, "kind": kind, "where": where, "ratio": round(ratio, 2),
                     "required": need, "pass": ratio >= need,
                     "aaa": ratio >= (7.0 if kind == "text" else 4.5)})
    return rows


def palette(theme):
    t = THEMES[theme]
    out = []
    for group, names in PALETTE_GROUPS:
        items = []
        for n in names:
            items.append({"name": n, "css": TOKEN_CSS.get(n), "hex": t[n],
                          "on_surface": round(contrast(t[n], t["surface"]), 2),
                          "white_on": round(contrast("#ffffff", t[n]), 2)})
        out.append((group, items))
    return out


# Values before the accessibility pass (Nov 2026), kept so the design report can show before -> after.
BEFORE_OVERRIDES = {
    "dark": {"faint": "#5d6a8c", "low_fg": "#3b82f6", "high_fg": "#fb6a1d", "crit_fg": "#ff3355",
             "input_border": blend("#94a3ff", 0.14, "#0a1129"),
             "btn_1": "#22d3ee", "btn_2": "#8b5cf6", "btn_3": "#d946ef"},
    "light": {"link": "#0891b2", "cyan": "#0891b2", "magenta": "#c026d3", "green": "#059669", "faint": "#7c88a8",
              "low_fg": "#2563eb", "med_fg": "#b7791f", "high_fg": "#d9480f", "crit_fg": "#e11d48",
              "med": "#b7791f", "high": "#d9480f", "input_border": blend("#1e295a", 0.12, "#ffffff"),
              "btn_1": "#0891b2", "btn_2": "#7c3aed", "btn_3": "#c026d3"},
}


def audit_before_after(theme):
    saved = dict(THEMES[theme])
    try:
        THEMES[theme].update(BEFORE_OVERRIDES[theme])
        before = audit(theme)
    finally:
        THEMES[theme].clear()
        THEMES[theme].update(saved)
    after = audit(theme)
    return [dict(a, before=b["ratio"], before_pass=b["pass"], before_fg=b["fg"], before_bg=b["bg"])
            for a, b in zip(after, before)]
