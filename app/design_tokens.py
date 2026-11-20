"""Design tokens for the SentinelSMB UI and a WCAG 2.1 contrast audit.

These hex values mirror the CSS custom properties in app/static/style.css
(tests/test_accessibility.py checks they stay in sync). All surfaces are opaque, so
each token is exactly the colour contrast is measured against.

Used by the in-app style guide (/style-guide) and docs/design (accessibility report).
"""

# Human-readable groups for the style guide palette.
PALETTE_GROUPS = [
    ("Surfaces", ["bg", "surface", "raised", "input", "input_border"]),
    ("Text", ["text", "muted", "faint", "th", "link"]),
    ("Accent (one colour) and status", ["accent", "accent_hover", "focus", "green"]),
    ("Severity (fills, dots, charts, map)", ["low", "med", "high", "crit"]),
    ("Severity (text on badges)", ["low_fg", "med_fg", "high_fg", "crit_fg"]),
]

TOKEN_CSS = {  # token -> CSS custom property
    "bg": "--bg", "surface": "--panel", "raised": "--panel-2", "input": "--input", "input_border": "--input-border",
    "text": "--text", "muted": "--muted", "faint": "--faint", "th": "--th", "link": "--link",
    "accent": "--accent", "accent_hover": "--accent-hover", "focus": "--focus", "green": "--green",
    "low": "--low", "med": "--med", "high": "--high", "crit": "--crit",
    "low_fg": "--low-fg", "med_fg": "--med-fg", "high_fg": "--high-fg", "crit_fg": "--crit-fg",
}

# v2 (Nov 2026 redesign): neutral slate surfaces, a single indigo accent and four severity colours.
# Cards are opaque, so "surface" is exactly the --panel colour the eye sees.
THEMES = {
    "dark": {
        "bg": "#0d1117", "surface": "#151b24", "raised": "#1c2430", "input": "#0f141b", "input_border": "#6b7588",
        "text": "#e6e9ef", "muted": "#a1abb9", "faint": "#8f99a8", "th": "#b3bcc8", "link": "#9db4ff",
        "accent": "#3b5bdb", "accent_hover": "#364fc7", "focus": "#7c9cff", "green": "#3fd68f",
        "low": "#3b82f6", "med": "#eab308", "high": "#f97316", "crit": "#ef4444",
        "low_fg": "#8ab4ff", "med_fg": "#facc15", "high_fg": "#fb923c", "crit_fg": "#fc8181", "white": "#ffffff",
    },
    "light": {
        "bg": "#f4f6f9", "surface": "#ffffff", "raised": "#f8fafc", "input": "#ffffff", "input_border": "#7a8496",
        "text": "#111827", "muted": "#4b5563", "faint": "#5b6472", "th": "#374151", "link": "#3b5bdb",
        "accent": "#3b5bdb", "accent_hover": "#364fc7", "focus": "#3b5bdb", "green": "#047857",
        "low": "#2563eb", "med": "#a16207", "high": "#c2410c", "crit": "#dc2626",
        "low_fg": "#1d4ed8", "med_fg": "#854d0e", "high_fg": "#9a3412", "crit_fg": "#991b1b", "white": "#ffffff",
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
    ("Table header text", "th", "raised", "text", "table headers"),
    ("Link text on card", "link", "surface", "text", "links"),
    ("Link text on page", "link", "bg", "text", "links outside cards"),
    ("Success text", "green", "surface", "text", "ingest status, live indicator"),
    ("Input text", "text", "input", "text", "form fields"),
    ("Input border vs card", "input_border", "surface", "ui", "form field outline (WCAG 1.4.11)"),
    ("Focus ring vs page", "focus", "bg", "ui", "keyboard focus outline"),
    ("Focus ring vs card", "focus", "surface", "ui", "keyboard focus outline"),
    ("Button text on accent", "white", "accent", "text", "primary buttons, active tabs"),
    ("Button text on accent (hover)", "white", "accent_hover", "text", "primary button hover"),
    ("Low badge text", "low_fg", "tint:low", "text", "severity badge"),
    ("Medium badge text", "med_fg", "tint:med", "text", "severity badge"),
    ("High badge text", "high_fg", "tint:high", "text", "severity badge"),
    ("Critical badge text", "crit_fg", "tint:crit", "text", "severity badge"),
    ("Critical KPI number", "crit_fg", "surface", "large", "Open critical alerts tile (30px bold)"),
    ("Severity dot / chart colour Low", "low", "surface", "ui", "badge dot, charts, map"),
    ("Severity dot / chart colour Medium", "med", "surface", "ui", "badge dot, charts, map"),
    ("Severity dot / chart colour High", "high", "surface", "ui", "badge dot, charts, map"),
    ("Severity dot / chart colour Critical", "crit", "surface", "ui", "badge dot, charts, map"),
]

REQUIRED = {"text": 4.5, "large": 3.0, "ui": 3.0}

FONT_STACK = 'system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif'
MONO_STACK = 'ui-monospace, "Cascadia Mono", "Cascadia Code", Consolas, "SFMono-Regular", Menlo, monospace'
SPACING = [("--sp-1", "4px"), ("--sp-2", "8px"), ("--sp-3", "12px"), ("--sp-4", "16px"), ("--sp-5", "24px"), ("--sp-6", "32px")]

TYPE_SCALE = [  # (name, css size, weight, sample usage)
    ("H1 - page title", "22px", 650, "Network overview"),
    ("H2 - section title", "15px", 600, "Traffic over time"),
    ("H3 - sub-section", "13.5px", 600, "What happened"),
    ("KPI value", "30px", 700, "239,855"),
    ("Body", "14px", 400, "Security operations view of ingested flows."),
    ("Small / caption", "12.5px", 400, "Auto-refreshes every 15 s."),
    ("Overline / label", "11.5px", 600, "EVENTS"),
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


# "Before" = the v1 gradient theme (before the Nov 2026 accessibility pass), mapped onto the v2 token names,
# so the design report can show before -> after for the same roles.
BEFORE_OVERRIDES = {
    "dark": {"bg": "#060914", "surface": "#0d1225", "raised": "#0f1730", "input": "#0a1129",
             "input_border": blend("#94a3ff", 0.14, "#0a1129"), "text": "#e6ecff", "muted": "#93a1c4",
             "faint": "#5d6a8c", "th": "#a9b6dc", "link": "#22d3ee", "accent": "#22d3ee", "accent_hover": "#8b5cf6",
             "focus": "#22d3ee", "green": "#22e39a", "low": "#3b82f6", "med": "#f5b31c", "high": "#fb6a1d",
             "crit": "#ff3355", "low_fg": "#3b82f6", "med_fg": "#f5b31c", "high_fg": "#fb6a1d", "crit_fg": "#ff3355"},
    "light": {"bg": "#eef2fb", "surface": "#fbfcfe", "raised": "#ffffff", "input": "#ffffff",
              "input_border": blend("#1e295a", 0.12, "#ffffff"), "text": "#0d1430", "muted": "#4b5878",
              "faint": "#7c88a8", "th": "#3b4766", "link": "#0891b2", "accent": "#0891b2", "accent_hover": "#c026d3",
              "focus": "#0891b2", "green": "#059669", "low": "#2563eb", "med": "#b7791f", "high": "#d9480f",
              "crit": "#e11d48", "low_fg": "#2563eb", "med_fg": "#b7791f", "high_fg": "#d9480f", "crit_fg": "#e11d48"},
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
