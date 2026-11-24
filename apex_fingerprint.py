"""Bounded passive CMS and frontend fingerprinting for ApexRecon."""
from __future__ import annotations

import re
from typing import Any


def _header(headers: Any, name: str) -> str | None:
    value = headers.get(name) if hasattr(headers, "get") else None
    return str(value).strip() if value is not None else None


def fingerprint(headers: Any, body: bytes) -> list[dict]:
    """Identify common CMS/frontend markers without retaining raw page content.

    The caller must cap body to MAX_RESPONSE_BYTES. No paths are requested and
    no version is inferred unless an explicit CMS generator meta tag supplies it.
    """
    import codecs

    content_type = _header(headers, "Content-Type") or ""
    if content_type and "text/html" not in content_type.lower() and "application/xhtml+xml" not in content_type.lower():
        return []
    charset = re.search(r"charset\s*=\s*['\"]?([a-zA-Z0-9._-]+)", content_type, re.I)
    encoding = "utf-8"
    if charset:
        try:
            encoding = codecs.lookup(charset.group(1)).name
        except LookupError:
            pass
    html = (body or b"").decode(encoding, errors="replace").lower()
    results: list[dict] = []

    def add(name: str, category: str, markers: list[str], confidence: str,
            version: str | None = None) -> None:
        results.append({
            "name": name, "category": category, "confidence": confidence,
            "evidence": markers, "version": version,
            "source": "response headers and bounded HTML sample",
        })

    cms_rules = {
        "WordPress": [
            ("wp-content asset path", "/wp-content/" in html),
            ("wp-includes asset path", "/wp-includes/" in html),
            ("WordPress REST marker", "wp-json" in html),
            ("X-Pingback header", bool(_header(headers, "X-Pingback"))),
        ],
        "Joomla": [
            ("Joomla media asset path", "/media/system/" in html),
            ("Joomla component marker", "com_content" in html),
        ],
        "Drupal": [
            ("Drupal settings marker", "drupalsettings" in html),
            ("Drupal core asset path", "/core/misc/drupal.js" in html),
            ("Drupal files path", "/sites/default/files/" in html),
        ],
        "Shopify": [
            ("Shopify CDN asset", "cdn.shopify.com" in html),
            ("Shopify storefront marker", "shopify.theme" in html or "shopify-section" in html),
            ("Shopify response header", bool(_header(headers, "X-ShopId"))),
        ],
        "Wix": [
            ("Wix static asset", "wixstatic.com" in html),
            ("Wix runtime marker", "wix.com" in html and "wix" in html),
        ],
        "Squarespace": [
            ("Squarespace static asset", "static1.squarespace.com" in html),
            ("Squarespace runtime marker", "squarespace-context" in html),
        ],
    }
    for cms, checks in cms_rules.items():
        markers = [label for label, present in checks if present]
        # HTML attribute order is not significant. Parse quoted name/content
        # attributes independently instead of assuming name precedes content.
        generator_content = None
        for tag in re.findall(r"<meta\b[^>]*>", html, re.I):
            attributes = {
                name.lower(): value
                for name, _quote, value in re.findall(
                    r"""([a-zA-Z_:][a-zA-Z0-9_.:-]*)\s*=\s*(["'])(.*?)\2""",
                    tag,
                    re.I,
                )
            }
            if attributes.get("name", "").strip().lower() == "generator":
                content = attributes.get("content", "").strip()
                if content.lower() == cms.lower() or content.lower().startswith(cms.lower() + " "):
                    generator_content = content
                    break
        if generator_content:
            markers.append("CMS generator meta tag")
        if markers:
            # A self-declared generator tag is easy to spoof. Require at least
            # two independent markers for HIGH confidence.
            confidence = "high" if len(markers) >= 2 else ("medium" if generator_content else "low")
            version = None
            if generator_content:
                candidate = generator_content[len(cms):].strip()
                if re.fullmatch(r"v?\d+(?:\.\d+){0,3}(?:[-+][a-z0-9.-]+)?", candidate, re.I):
                    version = candidate
            add(cms, "CMS", markers, confidence, version)

    tech_rules = {
        "React": [
            ("React root attribute", "data-reactroot" in html, "high"),
            ("React runtime marker", "react-dom" in html or "__react" in html, "medium"),
        ],
        "Vue.js": [
            ("Vue runtime marker", "__vue__" in html or "vue.runtime" in html, "medium"),
            ("Vue component attribute", bool(re.search(r"\sdata-v-[a-f0-9]+", html)), "high"),
        ],
        "Angular": [
            ("Angular version attribute", bool(re.search(r"ng-version\s*=", html)), "high"),
            ("Angular app marker", "ng-app" in html or "angular.min.js" in html, "medium"),
        ],
        "jQuery": [
            ("jQuery script reference", bool(re.search(r"jquery(?:[-.]\d|\.min)", html)), "medium"),
        ],
        "Bootstrap": [
            ("Bootstrap asset reference", bool(re.search(r"bootstrap(?:\.min)?\.(?:css|js)", html)), "medium"),
        ],
    }
    for name, checks in tech_rules.items():
        markers = [label for label, present, _ in checks if present]
        if markers:
            confidence = "high" if any(level == "high" and present for _, present, level in checks) else "medium"
            add(name, "Frontend technology", markers, confidence)

    server = _header(headers, "Server")
    powered = _header(headers, "X-Powered-By")
    if server:
        add(server[:120], "Server header", ["Server response header"], "low")
    if powered:
        add(powered[:120], "Application header", ["X-Powered-By response header"], "low")
    return results
