"""
Regression guard for the platform-wide "buttons/tabs stop responding" bug:
web/static/css/inline-extracted.css classes carry !important on every
declaration (to reproduce the old inline style="" cascade precedence -- see
that file's header comment). That's correct for genuinely static values, but
an element whose display/background/width/etc. is later toggled by JS via
element.style.<prop> or .style.setProperty() would have that assignment
permanently defeated by the !important class -- the element freezes on
whichever state the class encodes. This silently broke every showTab()-style
tab switcher, several modals, and a couple of progress bars/toggle switches
across 17 templates before being fixed (see README's CSP section).

This test statically re-derives, from the templates and their <script>
blocks plus main.js, every element that both (a) carries an inline-extracted
class with an !important declaration on some property, and (b) is targeted
by a JS assignment to that same property via element.style -- and fails if
any such pair exists. It does not need a browser: this is a pure text/regex
cross-reference, same technique used to find the original bug.

Deliberately conservative: only element ids resolvable from the JS source
(literal strings, `prefix-${var}` template literals, and 'prefix-'+var
concatenation where `var` loops over a literal array via .forEach) are
checked. Anything the resolver can't pin down is skipped rather than
guessed -- false negatives here are the same trade-off the browser-based
Playwright test in test_red_team_and_platform_tabs.py exists to catch;
false positives would make this test impossible to keep green.
"""
import glob
import os
import re

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATE_FILES = sorted(glob.glob(os.path.join(REPO_ROOT, "web/templates/*.html")))
MAIN_JS_PATH = os.path.join(REPO_ROOT, "web/static/js/main.js")
EXTRACTED_CSS = os.path.join(REPO_ROOT, "web/static/css/inline-extracted.css")

CAMEL_TO_KEBAB = re.compile(r"(?<!^)(?=[A-Z])")


def _camel_to_kebab(prop):
    return CAMEL_TO_KEBAB.sub("-", prop).lower()


def _parse_ie_important_props():
    """.ie<hash> -> set of CSS property names declared with !important."""
    css = open(EXTRACTED_CSS).read()
    result = {}
    for cls, body in re.findall(r"\.(ie[0-9a-f]{8})\s*\{([^}]*)\}", css):
        props = set()
        for decl in body.split(";"):
            decl = decl.strip()
            if not decl or ":" not in decl:
                continue
            prop, val = decl.split(":", 1)
            if "!important" in val:
                props.add(prop.strip().lower())
        if props:
            result[cls] = props
    return result


TAG_RE = re.compile(r"<[a-zA-Z][a-zA-Z0-9]*\b[^>]*>", re.DOTALL)
ID_RE = re.compile(r'\bid=["\']([^"\']+)["\']')
CLASS_RE = re.compile(r'\bclass=["\']([^"\']*)["\']')


def _parse_elements_by_id(template_src):
    """id -> set(classes), for every statically-id'd tag in the template."""
    out = {}
    for m in TAG_RE.finditer(template_src):
        tag = m.group(0)
        idm = ID_RE.search(tag)
        if not idm:
            continue
        el_id = idm.group(1)
        if "{{" in el_id or "{%" in el_id or "${" in el_id:
            continue  # Jinja/JS-templated id, not statically resolvable here
        clsm = CLASS_RE.search(tag)
        classes = clsm.group(1).split() if clsm else []
        out.setdefault(el_id, set()).update(classes)
    return out


def _get_inline_scripts(html_src):
    return re.findall(r"<script\b[^>]*>(.*?)</script>", html_src, re.DOTALL)


# getElementById(...) with the id expressed as: a plain literal, a template
# literal `a${x}b`, or string concatenation 'a'+x (both directions). Two
# shapes are checked: the direct chain (getElementById(X).style.P = ...)
# and the much more common "bind to a variable, use it a few lines later"
# shape (const el = document.getElementById(X); ... el.style.P = ...).
GETBYID_STYLE_PROP_RE = re.compile(
    r"getElementById\(\s*(.+?)\s*\)\s*\.style\.([a-zA-Z]+)\s*="
)
GETBYID_SETPROPERTY_RE = re.compile(
    r"getElementById\(\s*(.+?)\s*\)\s*\.style\.setProperty\(\s*['\"]([a-zA-Z-]+)['\"]"
)
VAR_BINDING_RE = re.compile(
    r"(?:const|let|var)\s+(\w+)\s*=\s*(?:document\.)?getElementById\(\s*(.+?)\s*\)"
)
VAR_STYLE_PROP_RE = re.compile(r"\b(\w+)\.style\.([a-zA-Z]+)\s*=")
VAR_STYLE_SETPROPERTY_RE = re.compile(
    r"\b(\w+)\.style\.setProperty\(\s*['\"]([a-zA-Z-]+)['\"]"
)


def _literal_string(expr):
    expr = expr.strip()
    if len(expr) >= 2 and expr[0] == expr[-1] and expr[0] in "'\"":
        return expr[1:-1]
    if expr.startswith("`") and expr.endswith("`") and "${" not in expr:
        return expr[1:-1]
    return None


def _resolve_dynamic_ids(expr, src, pos):
    """Resolve `prefix${var}suffix` or 'prefix'+var (either operand order)
    where `var` is the loop variable of a .forEach over a literal array
    declared within ~800 chars before this expression. Returns a list of
    concrete ids, or None if unresolvable."""
    m = re.match(r"`([a-zA-Z0-9_-]*)\$\{(\w+)\}([a-zA-Z0-9_-]*)`", expr)
    if not m:
        m = re.match(r"'([a-zA-Z0-9_-]*)'\s*\+\s*(\w+)$", expr)
    if not m:
        m = re.match(r"(\w+)\s*\+\s*'([a-zA-Z0-9_-]*)'$", expr)
        if m:
            var, suffix = m.groups()
            prefix = ""
        else:
            return None
    else:
        prefix, var, *rest = m.groups()
        suffix = rest[0] if rest else ""
    window = src[max(0, pos - 800):pos]
    arr_match = None
    for am in re.finditer(r"\[([^\[\]]*)\]\.forEach\(\s*\(?\s*" + re.escape(var) + r"\b", window):
        arr_match = am
    if not arr_match:
        return None
    items = re.findall(r"['\"]([a-zA-Z0-9_-]+)['\"]", arr_match.group(1))
    return [f"{prefix}{it}{suffix}" for it in items] if items else None


def _resolve_ids(expr, src, pos):
    lit = _literal_string(expr)
    if lit is not None:
        return [lit]
    return _resolve_dynamic_ids(expr, src, pos)


def _find_var_binding(varname, js_src, before_pos):
    """Last `const/let/var VARNAME = document.getElementById(EXPR)` binding
    in js_src before before_pos, i.e. the binding in scope at the use site
    (approximated -- this is a flat text search, not real scope analysis,
    which is fine for the small, mostly-flat handler functions these
    templates use)."""
    last = None
    for m in VAR_BINDING_RE.finditer(js_src, 0, before_pos):
        if m.group(1) == varname:
            last = m
    if not last:
        return None
    return _resolve_ids(last.group(2), js_src, last.start())


def _scan_style_mutations(js_src):
    """Yields (resolved_id, css_prop) for every element.style.X assignment
    or .style.setProperty() call this scanner can trace back to a concrete
    element id -- whether chained directly onto getElementById(...) or via
    an intermediate `const el = document.getElementById(...)` binding."""
    for pattern, is_setproperty in (
        (GETBYID_STYLE_PROP_RE, False),
        (GETBYID_SETPROPERTY_RE, True),
    ):
        for m in pattern.finditer(js_src):
            expr, prop = m.groups()
            ids = _resolve_ids(expr, js_src, m.start())
            if not ids:
                continue
            css_prop = prop if is_setproperty else _camel_to_kebab(prop)
            for el_id in ids:
                yield el_id, css_prop

    for pattern, is_setproperty in (
        (VAR_STYLE_PROP_RE, False),
        (VAR_STYLE_SETPROPERTY_RE, True),
    ):
        for m in pattern.finditer(js_src):
            varname, prop = m.groups()
            if varname in ("this", "document", "window"):
                continue
            ids = _find_var_binding(varname, js_src, m.start())
            if not ids:
                continue
            css_prop = prop if is_setproperty else _camel_to_kebab(prop)
            for el_id in ids:
                yield el_id, css_prop


def test_no_js_toggled_element_carries_a_conflicting_important_class():
    ie_important = _parse_ie_important_props()
    main_js_src = open(MAIN_JS_PATH).read()
    main_js_mutations = list(_scan_style_mutations(main_js_src))

    violations = []
    for tpl_path in TEMPLATE_FILES:
        tpl_name = os.path.basename(tpl_path)
        tpl_src = open(tpl_path).read()
        elements_by_id = _parse_elements_by_id(tpl_src)

        mutations = list(main_js_mutations)
        for script in _get_inline_scripts(tpl_src):
            mutations.extend(_scan_style_mutations(script))

        for el_id, css_prop in mutations:
            classes = elements_by_id.get(el_id)
            if not classes:
                continue
            for cls in classes:
                if css_prop in ie_important.get(cls, ()):
                    violations.append(
                        f"{tpl_name}: #{el_id}.{cls} sets `{css_prop}` with "
                        f"!important, but JS also assigns element.style.{css_prop} "
                        f"on #{el_id} -- the !important class permanently wins "
                        f"and the element will never visually respond to that "
                        f"JS assignment. Use class=\"is-hidden\" + "
                        f"window.optisecSetVisible() for display, or drop "
                        f"!important from just that declaration for any other "
                        f"property (see README's CSP section)."
                    )

    assert not violations, "JS-toggle vs. !important conflict(s) found:\n" + "\n".join(violations)


def test_is_hidden_class_exists_and_is_important():
    style_css = open(os.path.join(REPO_ROOT, "web/static/css/style.css")).read()
    m = re.search(r"\.is-hidden\s*\{([^}]*)\}", style_css)
    assert m, "style.css is missing the central .is-hidden class"
    assert "display" in m.group(1) and "none" in m.group(1) and "!important" in m.group(1), (
        ".is-hidden must be `display: none !important;` -- it's the only "
        "sanctioned way to give a JS-toggled element an !important-strength "
        "initial hidden state without fighting element.style later"
    )


def test_main_js_defines_optisecSetVisible():
    js = open(MAIN_JS_PATH).read()
    assert "window.optisecSetVisible" in js
    assert "classList.toggle('is-hidden'" in js
