"""ApexRecon Phase 2: conservative HTTP security-header assessment.

This module performs two bounded, read-only GET requests (HTTP and HTTPS) for
one operator-supplied origin/path. It does not crawl, fuzz, submit forms, or
attempt exploitation. The caller is responsible for the written-authorization
gate before invoking assess_url().
"""
from __future__ import annotations

import re
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

from apex_fingerprint import fingerprint
from apex_findings import normalize_finding


USER_AGENT = "ApexRecon/2.1-dev (+authorized security assessment)"
DEFAULT_TIMEOUT = 8.0
MAX_TIMEOUT = 20.0
MAX_RESPONSE_BYTES = 8192  # Per-response cap; at most two responses are read.


class AssessmentInputError(ValueError):
    """Raised when a target URL is malformed or outside the supported scope."""


class RedirectScopeError(urllib.error.URLError):
    """Raised when a redirect attempts to leave the supplied hostname."""


@dataclass
class FetchResult:
    status: int
    headers: Any
    final_url: str
    body: bytes = b""


class SameHostRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Allow only one same-host, same-path HTTP->HTTPS upgrade redirect."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        try:
            old = urllib.parse.urlsplit(req.full_url)
            new = urllib.parse.urlsplit(urllib.parse.urljoin(req.full_url, newurl))
            old_port = old.port
            new_port = new.port
        except ValueError as exc:
            raise RedirectScopeError("redirect URL or port is malformed") from exc

        if (old.username is not None or old.password is not None
                or new.username is not None or new.password is not None):
            raise RedirectScopeError("redirect with embedded credentials blocked")
        if new.fragment:
            raise RedirectScopeError("redirect URL fragments are blocked")
        if not old.hostname or not new.hostname:
            raise RedirectScopeError("redirect must contain a hostname")

        def normalized_host(host):
            try:
                return host.encode("idna").decode("ascii").lower().rstrip(".")
            except UnicodeError as exc:
                raise RedirectScopeError("redirect hostname is invalid") from exc

        if normalized_host(new.hostname) != normalized_host(old.hostname):
            raise RedirectScopeError("cross-host redirect blocked")

        # Permit only one exact-path HTTP -> HTTPS upgrade. Once HTTPS is
        # reached, further redirects are blocked, bounding the assessment to
        # at most two network requests and preventing path/query scope drift.
        if old.scheme.lower() != "http" or new.scheme.lower() != "https":
            raise RedirectScopeError("only HTTP-to-HTTPS upgrade redirects are permitted")
        if old_port not in (None, 80):
            raise RedirectScopeError("redirect source uses a non-standard HTTP port")
        if new_port not in (None, 443):
            raise RedirectScopeError("redirect to non-standard HTTPS port blocked")
        if new.path != old.path or new.query:
            raise RedirectScopeError("redirect path/query scope change blocked")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def normalize_target_url(value: str) -> urllib.parse.SplitResult:
    """Validate one HTTP(S) URL and return its parsed, query-free origin/path."""
    if not isinstance(value, str):
        raise AssessmentInputError("target must be text")
    raw = value.strip()
    if not raw or any(ord(ch) < 32 for ch in raw):
        raise AssessmentInputError("target is empty or contains control characters")
    if "://" not in raw:
        raw = "https://" + raw
    try:
        parsed = urllib.parse.urlsplit(raw)
        port = parsed.port  # Access validates malformed/out-of-range ports.
    except ValueError as exc:
        raise AssessmentInputError("target URL or port is malformed") from exc
    if parsed.scheme.lower() not in ("http", "https"):
        raise AssessmentInputError("only http:// and https:// targets are supported")
    if not parsed.hostname or parsed.username is not None or parsed.password is not None:
        raise AssessmentInputError("target must contain a hostname and no embedded credentials")
    if parsed.fragment:
        raise AssessmentInputError("URL fragments are not sent to web servers")
    if port not in (None, 80, 443):
        raise AssessmentInputError("only standard HTTP (80) and HTTPS (443) ports are supported in this phase")
    if (parsed.scheme.lower() == "http" and port not in (None, 80)) or (parsed.scheme.lower() == "https" and port not in (None, 443)):
        raise AssessmentInputError("explicit port must match the URL scheme")
    try:
        hostname = parsed.hostname.encode("idna").decode("ascii")
    except (UnicodeError, AttributeError) as exc:
        raise AssessmentInputError("hostname is invalid") from exc
    path = parsed.path or "/"
    # Query strings are deliberately omitted to avoid sending URL tokens/secrets.
    authority = f"[{hostname}]" if ":" in hostname else hostname
    return urllib.parse.SplitResult(parsed.scheme.lower(), authority, path, "", "")


def _fetch(url: str, timeout: float = DEFAULT_TIMEOUT) -> FetchResult:
    """Perform one bounded GET; follow same-host redirects only."""
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.1",
            "Range": f"bytes=0-{MAX_RESPONSE_BYTES - 1}",
            "Connection": "close",
            "Accept-Encoding": "identity",
        },
        method="GET",
    )
    opener = urllib.request.build_opener(SameHostRedirectHandler())
    try:
        response = opener.open(request, timeout=timeout)
    except urllib.error.HTTPError as exc:
        # HTTP 4xx/5xx is still a valid HTTP response whose headers can be assessed.
        response = exc
    with response:
        content_type = str(response.headers.get("Content-Type", "")).lower()
        body = b""
        if "text/html" in content_type or "application/xhtml+xml" in content_type:
            try:
                body = response.read(MAX_RESPONSE_BYTES)
            except (TimeoutError, socket.timeout, OSError):
                body = b""
        return FetchResult(
            status=int(response.getcode()),
            headers=response.headers,
            final_url=response.geturl(),
            body=body,
        )


def _header(headers: Any, name: str) -> str | None:
    value = headers.get(name) if hasattr(headers, "get") else None
    if value is None and hasattr(headers, "items"):
        for key, candidate in headers.items():
            if str(key).lower() == name.lower():
                value = candidate
                break
    return str(value).strip() if value is not None else None


def _header_values(headers: Any, name: str) -> list[str]:
    if hasattr(headers, "get_all"):
        values = headers.get_all(name)
        if values:
            return [str(item) for item in values]
    value = _header(headers, name)
    return [value] if value else []


def _finding(check: str, severity: str, status: str, evidence: str, recommendation: str) -> dict:
    """Create a common-schema finding from a direct HTTP response observation."""
    return normalize_finding(
        {
            "check": check,
            "severity": severity,
            "status": status,
            "evidence": evidence,
            "recommendation": recommendation,
        },
        "HTTP Security Assessment",
        default_confidence="HIGH",
        default_evidence_type="OBSERVATION",
    )


def _inspect_csp_policy(csp: str) -> list[dict]:
    """Report conservative CSP hardening indicators from one enforced policy.

    This is a static header review, not a browser-policy simulator. It does not
    determine whether a directive is effective for a particular application.
    """
    directives: dict[str, list[str]] = {}
    for part in csp.split(";"):
        tokens = part.strip().split()
        if not tokens:
            continue
        name = tokens[0].lower()
        # Browsers ignore later duplicate directives; retain the first instance.
        directives.setdefault(name, tokens[1:])

    findings = []
    script_sources = directives.get("script-src", directives.get("default-src", []))
    style_sources = directives.get("style-src", directives.get("default-src", []))
    object_sources = directives.get("object-src", directives.get("default-src", []))

    if "'unsafe-eval'" in {item.lower() for item in script_sources}:
        findings.append(_finding(
            "CSP_UNSAFE_EVAL", "MEDIUM", "REVIEW",
            "The effective script source list contains 'unsafe-eval'.",
            "Remove 'unsafe-eval' where possible and replace eval-like behavior with safer application code."
        ))
    if "'unsafe-inline'" in {item.lower() for item in script_sources}:
        findings.append(_finding(
            "CSP_UNSAFE_INLINE_SCRIPT", "LOW", "REVIEW",
            "The effective script source list contains 'unsafe-inline'.",
            "Prefer nonces or hashes for required inline scripts; validate compatibility before tightening the policy."
        ))
    if "'unsafe-inline'" in {item.lower() for item in style_sources}:
        findings.append(_finding(
            "CSP_UNSAFE_INLINE_STYLE", "LOW", "REVIEW",
            "The effective style source list contains 'unsafe-inline'.",
            "Consider nonces or hashes for required inline styles after testing application compatibility."
        ))

    source_lists = (
        ("default-src", directives.get("default-src", [])),
        ("script-src", script_sources),
        ("style-src", style_sources),
        ("img-src", directives.get("img-src", directives.get("default-src", []))),
        ("connect-src", directives.get("connect-src", directives.get("default-src", []))),
    )
    wildcard_directives = [name for name, sources in source_lists if "*" in sources]
    if wildcard_directives:
        findings.append(_finding(
            "CSP_WILDCARD_SOURCE", "LOW", "REVIEW",
            "Wildcard source (*) observed in: " + ", ".join(sorted(set(wildcard_directives))) + ".",
            "Replace broad wildcard sources with the smallest set of required trusted origins."
        ))

    if not object_sources or "'none'" not in {item.lower() for item in object_sources}:
        findings.append(_finding(
            "CSP_OBJECT_SRC", "LOW", "REVIEW",
            "The effective object-src directive does not explicitly restrict plugin content to 'none'.",
            "Consider object-src 'none' unless the application has a documented requirement for embedded plugin content."
        ))
    if "base-uri" not in directives:
        findings.append(_finding(
            "CSP_BASE_URI", "LOW", "REVIEW",
            "The CSP does not define base-uri.",
            "Consider base-uri 'self' or 'none' to restrict document base URL changes."
        ))
    return findings

def _cookie_evidence_summary(value: str) -> str:
    """Describe cookie security attributes without exporting cookie values."""
    parts = [part.strip() for part in str(value).split(";")]
    name = parts[0].split("=", 1)[0][:80] if parts else "unknown"
    attributes = []
    for part in parts[1:]:
        if not part:
            continue
        key, separator, raw = part.partition("=")
        key = key.strip().lower()
        if key in {"secure", "httponly"}:
            attributes.append(key)
        elif key in {"samesite", "path", "domain"}:
            attributes.append(f"{key}={raw.strip()[:100]}" if separator else key)
        else:
            attributes.append(key)
    return f"cookie-name={name}; attributes={', '.join(attributes) or 'none'}"


def _attach_response_evidence(
    findings: list[dict], headers: Any, status: int, final_url: str
) -> None:
    """Attach bounded response provenance and observed header values to findings.

    Set-Cookie values and CSP nonce/hash tokens are deliberately redacted.
    """
    source_headers = {
        "HSTS": ("Strict-Transport-Security",),
        "CSP": ("Content-Security-Policy",),
        "CSP_REPORT_ONLY": ("Content-Security-Policy-Report-Only",),
        "CSP_UNSAFE_EVAL": ("Content-Security-Policy",),
        "CSP_UNSAFE_INLINE_SCRIPT": ("Content-Security-Policy",),
        "CSP_UNSAFE_INLINE_STYLE": ("Content-Security-Policy",),
        "CSP_WILDCARD_SOURCE": ("Content-Security-Policy",),
        "CSP_OBJECT_SRC": ("Content-Security-Policy",),
        "CSP_BASE_URI": ("Content-Security-Policy",),
        "MIME_SNIFFING": ("X-Content-Type-Options",),
        "REFERRER_POLICY": ("Referrer-Policy",),
        "PERMISSIONS_POLICY": ("Permissions-Policy",),
        "CLICKJACKING_PROTECTION": ("Content-Security-Policy", "X-Frame-Options"),
        "COOKIE_FLAGS": ("Set-Cookie",),
        "SERVER_HEADER": ("Server",),
        "X_POWERED_BY": ("X-Powered-By",),
    }
    safe_url = _safe_url(final_url)
    for finding in findings:
        observations = []
        for name in source_headers.get(finding.get("check"), ()):
            values = _header_values(headers, name)
            if not values:
                observations.append(f"{name}: absent")
                continue
            if name.lower() == "set-cookie":
                rendered = [_cookie_evidence_summary(value) for value in values]
            else:
                rendered = values
                if name.lower() == "content-security-policy":
                    rendered = [
                        re.sub(
                            r"(?i)(?:'nonce-[^']*'|'sha(?:256|384|512)-[^']*')",
                            "'[REDACTED_TOKEN]'",
                            value,
                        )
                        for value in rendered
                    ]
            observations.append(
                f"{name}: " + " | ".join(repr(value[:350]) for value in rendered[:4])
            )
        response_scheme = urllib.parse.urlsplit(final_url).scheme.upper() or "UNKNOWN"
        context = f"Response provenance: {response_scheme} status {int(status)} at {safe_url}."
        if observations:
            context += " Observed: " + "; ".join(observations) + "."
        updated = normalize_finding(
            {
                **finding,
                "evidence": (str(finding.get("evidence", "")) + " " + context)[:4000],
            },
            "HTTP Security Assessment",
            default_confidence=finding.get("confidence", "UNKNOWN"),
            default_evidence_type=finding.get("evidence_type", "UNKNOWN"),
        )
        finding.clear()
        finding.update(updated)


def _status_class(status: int) -> str:
    """Classify an HTTP status code without treating the class as a vulnerability verdict."""
    try:
        code = int(status)
    except (TypeError, ValueError):
        return "UNKNOWN"
    if 100 <= code <= 199:
        return "INFORMATIONAL"
    if 200 <= code <= 299:
        return "SUCCESS"
    if 300 <= code <= 399:
        return "REDIRECTION"
    if 400 <= code <= 499:
        return "CLIENT_ERROR"
    if 500 <= code <= 599:
        return "SERVER_ERROR"
    return "UNKNOWN"


def _inspect_hsts(headers: Any) -> dict:
    """Validate the HSTS max-age directive without assuming policy intent."""
    values = _header_values(headers, "Strict-Transport-Security")
    if not values:
        return _finding(
            "HSTS", "MEDIUM", "MISSING",
            "Strict-Transport-Security response header was not present.",
            "Configure HSTS on HTTPS responses after confirming all required subdomains support HTTPS.",
        )
    if len(values) != 1:
        return _finding(
            "HSTS", "MEDIUM", "AMBIGUOUS",
            f"{len(values)} Strict-Transport-Security header values were observed.",
            "Send one unambiguous HSTS policy and review it against the organisation's deployment needs.",
        )

    directives = {}
    duplicates = []
    for part in values[0].split(";"):
        token = part.strip()
        if not token:
            continue
        name, separator, raw_value = token.partition("=")
        name = name.strip().lower()
        if not name:
            continue
        if name in directives:
            duplicates.append(name)
            continue
        directives[name] = raw_value.strip().strip('"') if separator else None

    max_age = directives.get("max-age")
    if duplicates:
        return _finding(
            "HSTS", "MEDIUM", "AMBIGUOUS",
            "Duplicate HSTS directive(s): " + ", ".join(sorted(set(duplicates))) + ".",
            "Remove duplicate HSTS directives and retain one explicit max-age value.",
        )
    if max_age is None or not max_age.isascii() or not max_age.isdigit() or len(max_age) > 20:
        return _finding(
            "HSTS", "MEDIUM", "INVALID",
            "HSTS did not contain one valid non-negative integer max-age directive.",
            "Set a valid decimal max-age value; confirm the intended duration before enabling HSTS.",
        )
    if int(max_age) == 0:
        return _finding(
            "HSTS", "MEDIUM", "DISABLED",
            "HSTS max-age is 0, which instructs browsers to clear the stored HSTS policy.",
            "Use a positive max-age only after confirming HTTPS is reliable across the affected host scope.",
        )
    return _finding(
        "HSTS", "INFO", "PRESENT",
        f"HSTS max-age is {max_age} seconds; includeSubDomains={'present' if 'includesubdomains' in directives else 'absent'}; preload={'present' if 'preload' in directives else 'absent'}.",
        "Review max-age and includeSubDomains/preload policy against the organisation's deployment needs.",
    )


def _inspect_headers(headers: Any, scheme: str) -> list[dict]:
    findings = []
    if scheme == "https":
        findings.append(_inspect_hsts(headers))
    else:
        findings.append(_finding("HSTS", "INFO", "NOT_APPLICABLE",
                                 "HSTS is evaluated on HTTPS responses.",
                                 "Serve HSTS from the HTTPS origin."))

    # CSP is handled separately because a response may carry multiple enforced
    # policies. A report-only policy is reported as advisory, never as enforced.
    csp_values = _header_values(headers, "Content-Security-Policy")
    if csp_values:
        findings.append(_finding(
            "CSP", "INFO", "PRESENT",
            f"{len(csp_values)} enforced Content-Security-Policy value(s) observed.",
            "Review each enforced policy in the context of the application and supported browsers.",
        ))
        seen = set()
        for policy in csp_values:
            for finding in _inspect_csp_policy(policy):
                if finding["finding_id"] not in seen:
                    seen.add(finding["finding_id"])
                    findings.append(finding)
    else:
        findings.append(_finding(
            "CSP", "MEDIUM", "MISSING",
            "Content-Security-Policy response header was not present.",
            "Define a restrictive Content-Security-Policy appropriate to the application; avoid unsafe-inline/unsafe-eval where possible.",
        ))

    report_only = _header_values(headers, "Content-Security-Policy-Report-Only")
    if report_only:
        findings.append(_finding(
            "CSP_REPORT_ONLY", "INFO", "REPORT_ONLY_NOT_ENFORCED",
            f"{len(report_only)} Content-Security-Policy-Report-Only value(s) observed; report-only policies do not enforce restrictions.",
            "Use report-only mode to test policy changes, then deploy an enforced Content-Security-Policy when ready.",
        ))

    xcto_values = _header_values(headers, "X-Content-Type-Options")
    if not xcto_values:
        findings.append(_finding("MIME_SNIFFING", "MEDIUM", "MISSING",
                                 "X-Content-Type-Options response header was not present.",
                                 "Set X-Content-Type-Options: nosniff."))
    elif len(xcto_values) > 1:
        findings.append(_finding("MIME_SNIFFING", "MEDIUM", "AMBIGUOUS",
                                 f"{len(xcto_values)} X-Content-Type-Options values were observed.",
                                 "Send one unambiguous X-Content-Type-Options: nosniff header."))
    elif xcto_values[0].strip().lower() == "nosniff":
        findings.append(_finding("MIME_SNIFFING", "INFO", "PRESENT", xcto_values[0][:200],
                                 "Keep X-Content-Type-Options set to nosniff."))
    else:
        findings.append(_finding("MIME_SNIFFING", "MEDIUM", "INVALID",
                                 f"Unrecognized X-Content-Type-Options value: {xcto_values[0][:200]!r}.",
                                 "Use the supported value X-Content-Type-Options: nosniff."))

    referrer_values = _header_values(headers, "Referrer-Policy")
    valid_referrer = {
        "no-referrer", "no-referrer-when-downgrade", "origin",
        "origin-when-cross-origin", "same-origin", "strict-origin",
        "strict-origin-when-cross-origin", "unsafe-url",
    }
    tokens = [token.strip().lower() for value in referrer_values for token in value.split(",")]
    recognized = [token for token in tokens if token in valid_referrer]
    if not referrer_values:
        findings.append(_finding("REFERRER_POLICY", "LOW", "MISSING",
                                 "Referrer-Policy response header was not present.",
                                 "Set a deliberate Referrer-Policy, commonly strict-origin-when-cross-origin or stricter."))
    elif recognized:
        effective = recognized[-1]
        findings.append(_finding("REFERRER_POLICY", "INFO", "PRESENT",
                                 f"Last recognized Referrer-Policy token: {effective}.",
                                 "Review the effective policy against application privacy and navigation requirements."))
    else:
        findings.append(_finding("REFERRER_POLICY", "LOW", "INVALID",
                                 "No recognized Referrer-Policy token was present.",
                                 "Use a recognized Referrer-Policy value such as strict-origin-when-cross-origin."))

    permissions = _header_values(headers, "Permissions-Policy")
    if permissions:
        findings.append(_finding(
            "PERMISSIONS_POLICY", "INFO", "PRESENT_UNVALIDATED",
            "Permissions-Policy header is present; its full directive grammar and browser support are not evaluated.",
            "Review directive syntax, allowlists and browser support against the application's feature requirements.",
        ))
    else:
        findings.append(_finding(
            "PERMISSIONS_POLICY", "LOW", "MISSING",
            "Permissions-Policy response header was not present.",
            "Set a Permissions-Policy that disables browser capabilities the application does not need.",
        ))

    xfo_values = _header_values(headers, "X-Frame-Options")
    has_frame_ancestors = any(
        any((part.strip().split()[:1] and part.strip().split()[0].lower() == "frame-ancestors") for part in policy.split(";"))
        for policy in csp_values
    )
    if has_frame_ancestors:
        findings.append(_finding("CLICKJACKING_PROTECTION", "INFO", "PRESENT",
                                 "An enforced Content-Security-Policy contains frame-ancestors.",
                                 "Keep frame-ancestors aligned with approved embedding requirements."))
    elif not xfo_values:
        findings.append(_finding("CLICKJACKING_PROTECTION", "MEDIUM", "MISSING",
                                 "Neither enforced CSP frame-ancestors nor X-Frame-Options was present.",
                                 "Set CSP frame-ancestors 'none' or an explicit trusted-origin list; consider X-Frame-Options for legacy clients."))
    elif len(xfo_values) != 1:
        findings.append(_finding("CLICKJACKING_PROTECTION", "MEDIUM", "AMBIGUOUS",
                                 f"{len(xfo_values)} X-Frame-Options values were observed.",
                                 "Send one unambiguous X-Frame-Options value or use an enforced CSP frame-ancestors directive."))
    else:
        xfo = xfo_values[0].strip().upper()
        if xfo in {"DENY", "SAMEORIGIN"}:
            findings.append(_finding("CLICKJACKING_PROTECTION", "INFO", "PRESENT", xfo,
                                     "Prefer CSP frame-ancestors for modern browser policy; retain X-Frame-Options where legacy support is required."))
        elif xfo == "ALLOW-FROM" or xfo.startswith("ALLOW-FROM "):
            findings.append(_finding("CLICKJACKING_PROTECTION", "LOW", "LEGACY_UNSUPPORTED",
                                     xfo[:200],
                                     "Replace obsolete X-Frame-Options ALLOW-FROM with an enforced CSP frame-ancestors policy."))
        else:
            findings.append(_finding("CLICKJACKING_PROTECTION", "MEDIUM", "INVALID",
                                     f"Unrecognized X-Frame-Options value: {xfo[:200]!r}.",
                                     "Use DENY or SAMEORIGIN, or define an enforced CSP frame-ancestors directive."))
    return findings

def _inspect_cookies(headers: Any, secure_transport: bool) -> list[dict]:
    findings = []
    cookies = _header_values(headers, "Set-Cookie")
    if not cookies:
        return [_finding("COOKIE_FLAGS", "INFO", "NO_COOKIES_OBSERVED",
                         "No Set-Cookie response header was observed on this response.",
                         "Review authenticated and state-changing application flows; this response alone cannot establish cookie policy.")]
    for index, cookie in enumerate(cookies, 1):
        parts = [part.strip() for part in cookie.split(";")]
        name = parts[0].split("=", 1)[0][:80] if parts else f"cookie-{index}"
        attributes = []
        for part in parts[1:]:
            if not part:
                continue
            key, separator, raw_value = part.partition("=")
            attributes.append((key.strip().lower(), raw_value.strip().strip('"') if separator else None))

        names = {key for key, _ in attributes}
        missing = []
        invalid = []
        if secure_transport and "secure" not in names:
            missing.append("Secure")
        if "httponly" not in names:
            missing.append("HttpOnly")
        if any(value is not None for key, value in attributes if key in {"secure", "httponly"}):
            invalid.append("Secure/HttpOnly flag syntax")

        same_site = [value for key, value in attributes if key == "samesite"]
        if not same_site:
            missing.append("SameSite")
        elif len(same_site) != 1 or same_site[0] is None or same_site[0].lower() not in {"strict", "lax", "none"}:
            invalid.append("SameSite")
        elif same_site[0].lower() == "none" and "secure" not in names:
            invalid.append("SameSite=None without Secure")

        if invalid:
            findings.append(_finding(
                "COOKIE_FLAGS", "MEDIUM", "INVALID_ATTRIBUTES",
                f"Cookie {name!r} has invalid or conflicting attribute(s): {', '.join(invalid)}."
                + (f" Also missing: {', '.join(missing)}." if missing else ""),
                "Use one valid SameSite value (Strict, Lax or None); SameSite=None requires Secure. Set HttpOnly where JavaScript access is unnecessary.",
            ))
        elif missing:
            findings.append(_finding("COOKIE_FLAGS", "MEDIUM", "MISSING_ATTRIBUTES",
                                     f"Cookie {name!r} is missing: {', '.join(missing)}.",
                                     "Set Secure on HTTPS cookies, HttpOnly where JavaScript access is unnecessary, and an intentional SameSite policy."))
        else:
            findings.append(_finding("COOKIE_FLAGS", "INFO", "PRESENT",
                                     f"Cookie {name!r} includes Secure/HttpOnly and one recognized SameSite value.",
                                     "Confirm cookie scope, lifetime, and SameSite mode match the application's authentication design."))
    return findings

def assess_url(target: str, timeout: float = DEFAULT_TIMEOUT) -> dict:
    """Assess HTTP->HTTPS behavior and common response headers for one URL.

    This performs at most two read-only GET requests. A same-host, same-path
    HTTP-to-HTTPS redirect counts as the HTTPS request; other redirects are
    blocked. It does not crawl links, submit forms, probe common paths, or exploit.
    A caller must enforce written authorization before calling this function.
    """
    parsed = normalize_target_url(target)
    try:
        timeout = float(timeout)
    except (TypeError, ValueError) as exc:
        raise AssessmentInputError("timeout must be numeric") from exc
    if timeout <= 0 or timeout > MAX_TIMEOUT:
        raise AssessmentInputError(f"timeout must be greater than 0 and no more than {MAX_TIMEOUT:g} seconds")

    host = parsed.hostname
    path = parsed.path
    authority = f"[{host}]" if ":" in host else host
    http_url = urllib.parse.urlunsplit(("http", authority, path, "", ""))
    https_url = urllib.parse.urlunsplit(("https", authority, path, "", ""))
    try:
        http_result = _fetch(http_url, timeout=timeout)
    except (urllib.error.URLError, TimeoutError, socket.timeout, ssl.SSLError, OSError) as exc:
        http_result = exc

    # A permitted HTTP->HTTPS upgrade already supplies the HTTPS response.
    # Otherwise make one direct HTTPS request. The redirect handler blocks
    # further redirects, so the total request count cannot exceed two.
    if isinstance(http_result, FetchResult) and urllib.parse.urlsplit(http_result.final_url).scheme.lower() == "https":
        https_result = http_result
    else:
        try:
            https_result = _fetch(https_url, timeout=timeout)
        except (urllib.error.URLError, TimeoutError, socket.timeout, ssl.SSLError, OSError) as exc:
            https_result = exc

    fingerprints = fingerprint(https_result.headers, https_result.body) if isinstance(https_result, FetchResult) else []
    findings = []
    if isinstance(http_result, FetchResult):
        final_scheme = urllib.parse.urlsplit(http_result.final_url).scheme.lower()
        if final_scheme == "https":
            findings.append(_finding("HTTPS_ENFORCEMENT", "INFO", "REDIRECTED",
                                     f"HTTP request upgraded to HTTPS; final HTTPS response status {http_result.status}.",
                                     "Keep HTTP-to-HTTPS redirection enabled and avoid mixed-content resources."))
        else:
            findings.append(_finding("HTTPS_ENFORCEMENT", "MEDIUM", "NOT_ENFORCED",
                                     f"HTTP request ended on {final_scheme.upper()} (HTTP status {http_result.status}).",
                                     "Redirect all HTTP requests to the equivalent HTTPS URL and avoid serving sensitive content over HTTP."))
    else:
        findings.append(_finding("HTTP_ENDPOINT", "INFO", "UNAVAILABLE",
                                 f"HTTP endpoint could not be assessed: {type(http_result).__name__}.",
                                 "Confirm whether HTTP is intentionally disabled; verify HTTPS is available independently."))

    if isinstance(https_result, FetchResult):
        status_class = _status_class(https_result.status)
        findings.append(_finding("HTTPS_ENDPOINT", "INFO", "RESPONDED",
                                 f"HTTPS endpoint returned HTTP status {https_result.status} ({status_class}).",
                                 "Review the application response and its authentication/access controls. HTTP status classes are descriptive observations, not vulnerability verdicts."))
        https_finding_start = len(findings) - 1
        findings.extend(_inspect_headers(https_result.headers, "https"))
        findings.extend(_inspect_cookies(https_result.headers, True))
        server = _header(https_result.headers, "Server")
        powered = _header(https_result.headers, "X-Powered-By")
        for name, value in (("SERVER_HEADER", server), ("X_POWERED_BY", powered)):
            if value:
                findings.append(_finding(name, "LOW", "DISCLOSED", value[:200],
                                         "Consider minimising version/product disclosure where it is not operationally required."))
        _attach_response_evidence(
            findings[https_finding_start:],
            https_result.headers,
            https_result.status,
            https_result.final_url,
        )
    else:
        findings.append(_finding("HTTPS_ENDPOINT", "MEDIUM", "UNAVAILABLE",
                                 f"HTTPS endpoint could not be assessed: {type(https_result).__name__}.",
                                 "Verify DNS, network reachability, certificate validity, and HTTPS listener configuration. TLS details are assessed in a separate phase."))

    if isinstance(http_result, FetchResult):
        enforcement = next(
            (item for item in findings if item.get("check") == "HTTPS_ENFORCEMENT"),
            None,
        )
        if enforcement is not None:
            _attach_response_evidence(
                [enforcement], http_result.headers, http_result.status, http_result.final_url
            )

    http_final_scheme = urllib.parse.urlsplit(http_result.final_url).scheme.lower() if isinstance(http_result, FetchResult) else None
    http_redirected_to_https = http_final_scheme == "https"

    return {
        "schema_version": "1.0",
        "module": "HTTP Security Assessment",
        "target": host,
        "path": path,
        "http_status": http_result.status if isinstance(http_result, FetchResult) and not http_redirected_to_https else None,
        "http_final_scheme": http_final_scheme,
        "http_redirected_to_https": http_redirected_to_https,
        "https_status": https_result.status if isinstance(https_result, FetchResult) else None,
        "http_status_class": _status_class(http_result.status) if isinstance(http_result, FetchResult) and not http_redirected_to_https else None,
        "https_status_class": _status_class(https_result.status) if isinstance(https_result, FetchResult) else None,
        "http_final_url": _safe_url(http_result.final_url) if isinstance(http_result, FetchResult) else None,
        "https_final_url": _safe_url(https_result.final_url) if isinstance(https_result, FetchResult) else None,
        "findings": findings,
        "fingerprints": fingerprints,
        "limitations": [
            "One URL path only; no crawling or common-path discovery.",
            f"At most two read-only GET requests; at most {MAX_RESPONSE_BYTES} HTML bytes per response (16 KiB total) are read for passive fingerprinting.",
            "CMS and technology fingerprints are heuristic observations, not proof of installed components or versions.",
            "Header presence is not proof that a policy is correctly configured or effective.",
            "No vulnerability exploitation or authenticated workflow testing is performed.",
            "TLS certificate and protocol analysis is outside this HTTP milestone.",
        ],
    }


def _safe_url(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))



def generate_html_report(result: dict, duration_seconds: float) -> str:
    """Write a self-contained, escaped HTML report for one HTTP assessment."""
    import os
    from datetime import datetime
    from html import escape

    if not isinstance(result, dict) or result.get("module") != "HTTP Security Assessment":
        raise ValueError("result is not an ApexRecon HTTP assessment")
    try:
        duration = float(duration_seconds)
    except (TypeError, ValueError) as exc:
        raise ValueError("duration must be numeric") from exc
    if duration < 0:
        raise ValueError("duration cannot be negative")

    findings = result.get("findings")
    limitations = result.get("limitations")
    if not isinstance(findings, list) or not isinstance(limitations, list):
        raise ValueError("assessment result is missing findings or limitations")

    now = datetime.now().astimezone()
    filename = "apex_http_report_" + now.strftime("%Y%m%d_%H%M%S_%f") + ".html"
    target = escape(str(result.get("target", "Unknown")))
    path = escape(str(result.get("path", "/")))
    timestamp = escape(now.isoformat(timespec="seconds"))
    assessment_id = escape(str(result.get("assessment_id", "Not assigned")))
    counts = {level: sum(1 for item in findings if str(item.get("severity", "INFO")).upper() == level)
              for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}

    rows = []
    for item in findings:
        severity = str(item.get("severity", "INFO")).upper()
        if severity not in counts:
            severity = "INFO"
        rows.append(
            "<tr>"
            f"<td><span class='severity {severity.lower()}'>{escape(severity)}</span><br>Review: {escape(str(item.get('review_priority', 'UNRANKED')))}</td>"
            f"<td>{escape(str(item.get('check', 'UNKNOWN')))}</td>"
            f"<td>{escape(str(item.get('status', 'UNKNOWN')))}</td>"
            f"<td>{escape(str(item.get('evidence', '')))}</td>"
            f"<td>{escape(str(item.get('recommendation_status', 'MISSING')))}</td>"
            f"<td>{escape(str(item.get('recommendation', '')))}</td>"
            "</tr>"
        )
    if not rows:
        rows.append("<tr><td colspan='6'>No findings were returned. This is not proof of security.</td></tr>")

    limit_items = "".join(f"<li>{escape(str(item))}</li>" for item in limitations)
    fingerprints = result.get("fingerprints", [])
    fingerprint_rows = []
    for item in fingerprints if isinstance(fingerprints, list) else []:
        if not isinstance(item, dict):
            continue
        markers = ", ".join(str(marker) for marker in item.get("evidence", [])[:8])
        version = f" {item.get('version')}" if item.get("version") else ""
        fingerprint_rows.append(
            "<tr>"
            f"<td>{escape(str(item.get('category', 'Technology')))}</td>"
            f"<td>{escape(str(item.get('name', 'Unknown')))}{escape(version)}</td>"
            f"<td>{escape(str(item.get('confidence', 'unknown')).upper())}</td>"
            f"<td>{escape(markers)}</td>"
            f"<td>{escape(str(item.get('source', '')))}</td>"
            "</tr>"
        )
    if not fingerprint_rows:
        fingerprint_rows.append("<tr><td colspan='5'>No fingerprints observed in the bounded response sample. This does not establish absence.</td></tr>")
    fingerprint_html = "".join(fingerprint_rows)
    summary_cards = "".join(
        f"<div class='stat'><strong>{counts[level]}</strong><span>{level.title()}</span></div>"
        for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
    )
    html = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ApexRecon HTTP Assessment</title>
<style>
:root{{color-scheme:dark;--bg:#0b1018;--panel:#121c29;--line:#263648;--text:#e8eef5;--muted:#a5b4c4;--cyan:#48d7e8;--red:#ff647c;--orange:#ffad5c;--gold:#f1d16b;--green:#65d69a}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--text);font:14px/1.55 system-ui,sans-serif}}
main{{max-width:1180px;margin:0 auto;padding:28px 18px 48px}}header,.panel{{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:22px;margin-bottom:18px}}
.brand{{color:var(--cyan);font-weight:800;letter-spacing:2px;font-size:22px}}h1{{font-size:23px;margin:8px 0}}h2{{font-size:17px;margin:0 0 14px}}
.meta{{color:var(--muted);overflow-wrap:anywhere}}.stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:10px;margin:18px 0}}
.stat{{background:var(--panel);border:1px solid var(--line);padding:14px;border-radius:9px}}.stat strong{{display:block;font-size:25px}}.stat span{{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:1px}}
.notice{{border-left:4px solid var(--gold);padding:10px 14px;background:#292516;color:#f6e8b2;border-radius:4px}}
.table-wrap{{overflow-x:auto}}table{{width:100%;border-collapse:collapse;min-width:850px}}th,td{{text-align:left;vertical-align:top;padding:11px;border-bottom:1px solid var(--line);overflow-wrap:anywhere}}th{{color:var(--cyan);font-size:11px;text-transform:uppercase;letter-spacing:1px}}
.severity{{font-weight:800;font-size:11px}}.critical,.high{{color:var(--red)}}.medium{{color:var(--orange)}}.low{{color:var(--gold)}}.info{{color:var(--cyan)}}
li{{margin:6px 0;color:var(--muted)}}footer{{color:var(--muted);font-size:12px;margin-top:24px}}
@media print{{body{{background:#fff;color:#111}}header,.panel,.stat{{background:#fff;color:#111;border-color:#ccc}}.meta,li,footer{{color:#333}}.notice{{background:#fff8dc;color:#222}}}}
</style>
</head>
<body><main>
<header>
<div class="brand">APEXRECON | TRINTECH DIGITAL DEFENSE</div>
<h1>HTTP Security Assessment Report</h1>
<div class="meta">Assessment ID: {assessment_id}<br>Target: {target} &nbsp;|&nbsp; Path: {path}<br>Generated: {timestamp} &nbsp;|&nbsp; Duration: {duration:.2f}s</div>
</header>
<div class="notice"><strong>Scope and interpretation:</strong> This is a bounded HTTP response-configuration assessment, not a comprehensive vulnerability scan or penetration test. Observed missing headers and disclosures are not proof of exploitable vulnerabilities. Review findings in application context.</div>
<section class="stats">{summary_cards}</section>
<section class="panel">
<h2>Observed Findings</h2>
<div class="table-wrap"><table><thead><tr><th>Severity / review priority</th><th>Check</th><th>Status</th><th>Evidence</th><th>Recommendation status</th><th>Recommended action</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table></div>
</section>
<section class="panel"><h2>CMS and Technology Fingerprints</h2><p class="meta">Passive fingerprints from response headers and a capped HTML sample. Confidence describes fingerprint strength, not certainty that a component is installed.</p><div class="table-wrap"><table><thead><tr><th>Category</th><th>Observed</th><th>Confidence</th><th>Evidence markers</th><th>Source</th></tr></thead><tbody>{fingerprint_html}</tbody></table></div></section>
<section class="panel"><h2>Assessment Limitations</h2><ul>{limit_items}</ul></section>
<footer>CONFIDENTIAL — Intended only for personnel authorized to receive this assessment.<br>TrinTech Digital Defense · ApexRecon · Operator-initiated assessment</footer>
</main></body></html>"""

    fd = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            fd = -1
            handle.write(html)
    finally:
        if fd >= 0:
            os.close(fd)
    return filename
