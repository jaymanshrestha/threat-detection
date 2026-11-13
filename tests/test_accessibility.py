"""Accessibility and design-consistency checks.

* the palette in app/design_tokens.py matches the CSS variables in style.css;
* every text/background pair meets WCAG 2.1 AA in both themes;
* every rendered page gives each form control and button an accessible name.
"""
import re
from html.parser import HTMLParser
from pathlib import Path

from app import design_tokens as dt
from tests.test_pages import _login

CSS = (Path(__file__).resolve().parent.parent / "app" / "static" / "style.css").read_text()


def _theme_block(theme):
    sel = ':root,[data-theme="dark"]{' if theme == "dark" else '[data-theme="light"]{'
    start = CSS.index(sel) + len(sel)
    return CSS[start:CSS.index("}", start)]


def test_tokens_match_stylesheet():
    for theme, tokens in dt.THEMES.items():
        block = _theme_block(theme)
        for name, var in dt.TOKEN_CSS.items():
            if var is None:
                continue
            m = re.search(re.escape(var) + r":\s*(#[0-9a-fA-F]{6})", block)
            assert m, f"{var} missing in {theme} theme"
            assert m.group(1).lower() == tokens[name].lower(), f"{theme} {var}: css {m.group(1)} != tokens {tokens[name]}"


def test_surface_is_composited_panel():
    assert dt.blend("#111830", 0.62, dt.THEMES["dark"]["bg"]) == dt.THEMES["dark"]["surface"]
    assert dt.blend("#ffffff", 0.78, dt.THEMES["light"]["bg"]) == dt.THEMES["light"]["surface"]


def test_contrast_wcag_aa_both_themes():
    assert abs(dt.contrast("#000000", "#ffffff") - 21) < 1e-6
    for theme in dt.THEMES:
        bad = [(r["pair"], r["ratio"]) for r in dt.audit(theme) if not r["pass"]]
        assert not bad, f"{theme}: {bad}"


class _Controls(HTMLParser):
    def __init__(self):
        super().__init__()
        self.labels_for, self.controls, self.buttons = set(), [], []
        self._label_depth = 0
        self._btn = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "label":
            self._label_depth += 1
            if a.get("for"):
                self.labels_for.add(a["for"])
        elif tag in ("input", "select", "textarea") and a.get("type") not in ("hidden", "submit"):
            self.controls.append((tag, a, self._label_depth > 0))
        elif tag == "button":
            self._btn = {"attrs": a, "text": ""}
        elif tag == "svg" and self._btn is not None:
            pass

    def handle_endtag(self, tag):
        if tag == "label":
            self._label_depth -= 1
        elif tag == "button" and self._btn is not None:
            self.buttons.append(self._btn)
            self._btn = None

    def handle_data(self, data):
        if self._btn is not None:
            self._btn["text"] += data


def _check_page(html, path):
    p = _Controls()
    p.feed(html)
    for tag, a, wrapped in p.controls:
        named = wrapped or a.get("aria-label") or a.get("aria-labelledby") or (a.get("id") in p.labels_for)
        assert named, f"{path}: unlabeled <{tag} {a}>"
    for b in p.buttons:
        assert b["text"].strip() or b["attrs"].get("aria-label"), f"{path}: button without a name {b['attrs']}"


def test_every_control_has_a_label(client):
    for path in ["/login"]:
        _check_page(client.get(path).get_data(as_text=True), path)
    _login(client)
    for path in ["/", "/events", "/alerts", "/models", "/sources", "/datasets", "/notifications", "/users",
                 "/incidents", "/simulator",
                 "/audit", "/map", "/style-guide", "/sources/upload/syslog", "/sources/upload/pcap"]:
        r = client.get(path)
        assert r.status_code == 200, path
        _check_page(r.get_data(as_text=True), path)


def test_style_guide_page(client):
    _login(client)
    html = client.get("/style-guide").get_data(as_text=True)
    assert "Contrast audit" in html and "#0e7490" in html and "Typography" in html
    assert 'href="/style-guide"' in client.get("/").get_data(as_text=True)
