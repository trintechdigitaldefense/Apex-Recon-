"""ApexRecon Phase 2: conservative HTTP security-header assessment.

This module performs two bounded, read-only GET requests (HTTP and HTTPS) for
one operator-supplied origin/path. It does not crawl, fuzz, submit forms, or
attempt exploitation. The caller is responsible for the written-authorization
gate before invoking assess_url().
"""
from __future__ import annotations

import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

from apex_fingerprint import fingerprint


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
        old = urllib.parse.urlsplit(req.full_url)
        new = urllib.parse.urlsplit(urllib.parse.urljoin(req.full_url, newurl))
        if (new.hostname or "").lower().rstrip(".") != (old.hostname or "").lower().rstrip("."):
            raise RedirectScopeError("cross-host redirect blocked")
        # Permit only one exact-path HTTP -> HTTPS upgrade. Once HTTPS is
        # reached, further redirects are blocked, bounding the assessment to
        # at most two network requests and preventing path/query scope drift.
        if old.scheme != "http" or new.scheme != "https":
            raise RedirectScopeError("only HTTP-to-HTTPS upgrade redirects are permitted")
        if new.port not in (None, 443):
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
    return {
        "check": check,
        "severity": severity,
        "status": status,
        "evidence": evidence,
        "recommendation": recommendation,
    }


def _inspect_headers(headers: Any, scheme: str) -> list[dict]:
    findings = []
    if scheme == "https":
        hsts = _header(headers, "Strict-Transport-Security")
        if hsts:
            findings.append(_finding("HSTS", "INFO", "PRESENT", hsts[:300],
                                     "Review max-age and includeSubDomains/preload policy against the organisation's deployment needs."))
        else:
            findings.append(_finding("HSTS", "MEDIUM", "MISSING", "Strict-Transport-Security response header was not present.",
                                     "Configure HSTS on HTTPS responses after confirming all required subdomains support HTTPS."))
    else:
        findings.append(_finding("HSTS", "INFO", "NOT_APPLICABLE", "HSTS is evaluated on HTTPS responses.",
                                 "Serve HSTS from the HTTPS origin."))

    checks = (
        ("Content-Security-Policy", "CSP", "MEDIUM",
         "Define a restrictive Content-Security-Policy appropriate to the application; avoid unsafe-inline/unsafe-eval where possible."),
        ("X-Content-Type-Options", "MIME_SNIFFING", "MEDIUM",
         "Set X-Content-Type-Options: nosniff."),
        ("Referrer-Policy", "REFERRER_POLICY", "LOW",
         "Set a deliberate Referrer-Policy, commonly strict-origin-when-cross-origin or stricter."),
        ("Permissions-Policy", "PERMISSIONS_POLICY", "LOW",
         "Set a Permissions-Policy that disables browser capabilities the application does not need."),
    )
    for header_name, check_name, severity, recommendation in checks:
        value = _header(headers, header_name)
        if value:
            findings.append(_finding(check_name, "INFO", "PRESENT", value[:300], recommendation))
        else:
            findings.append(_finding(check_name, severity, "MISSING",
                                     f"{header_name} response header was not present.", recommendation))

    csp = _header(headers, "Content-Security-Policy") or ""
    xfo = _header(headers, "X-Frame-Options")
    if "frame-ancestors" in csp.lower():
        findings.append(_finding("CLICKJACKING_PROTECTION", "INFO", "PRESENT",
                                 "Content-Security-Policy includes frame-ancestors.",
                                 "Keep frame-ancestors aligned with approved embedding requirements."))
    elif xfo:
        findings.append(_finding("CLICKJACKING_PROTECTION", "INFO", "PRESENT", xfo[:200],
                                 "Prefer CSP frame-ancestors for modern browser policy; retain X-Frame-Options where legacy support is required."))
    else:
        findings.append(_finding("CLICKJACKING_PROTECTION", "MEDIUM", "MISSING",
                                 "Neither CSP frame-ancestors nor X-Frame-Options was present.",
                                 "Set CSP frame-ancestors 'none' or an explicit trusted-origin list; consider X-Frame-Options for legacy clients."))
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
        attributes = {part.split("=", 1)[0].strip().lower() for part in parts[1:] if part}
        missing = []
        if secure_transport and "secure" not in attributes:
            missing.append("Secure")
        if "httponly" not in attributes:
            missing.append("HttpOnly")
        if not any(attr.startswith("samesite") for attr in attributes):
            missing.append("SameSite")
        if missing:
            findings.append(_finding("COOKIE_FLAGS", "MEDIUM", "MISSING_ATTRIBUTES",
                                     f"Cookie {name!r} is missing: {', '.join(missing)}.",
                                     "Set Secure on HTTPS cookies, HttpOnly where JavaScript access is unnecessary, and an intentional SameSite policy."))
        else:
            findings.append(_finding("COOKIE_FLAGS", "INFO", "PRESENT",
                                     f"Cookie {name!r} includes Secure/HttpOnly/SameSite attributes.",
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
        findings.append(_finding("HTTPS_ENDPOINT", "INFO", "RESPONDED",
                                 f"HTTPS endpoint returned HTTP status {https_result.status}.",
                                 "Review the application response and its authentication/access controls."))
        findings.extend(_inspect_headers(https_result.headers, "https"))
        findings.extend(_inspect_cookies(https_result.headers, True))
        server = _header(https_result.headers, "Server")
        powered = _header(https_result.headers, "X-Powered-By")
        for name, value in (("SERVER_HEADER", server), ("X_POWERED_BY", powered)):
            if value:
                findings.append(_finding(name, "LOW", "DISCLOSED", value[:200],
                                         "Consider minimising version/product disclosure where it is not operationally required."))
    else:
        findings.append(_finding("HTTPS_ENDPOINT", "MEDIUM", "UNAVAILABLE",
                                 f"HTTPS endpoint could not be assessed: {type(https_result).__name__}.",
                                 "Verify DNS, network reachability, certificate validity, and HTTPS listener configuration. TLS details are assessed in a separate phase."))

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
    counts = {level: sum(1 for item in findings if str(item.get("severity", "INFO")).upper() == level)
              for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}

    rows = []
    for item in findings:
        severity = str(item.get("severity", "INFO")).upper()
        if severity not in counts:
            severity = "INFO"
        rows.append(
            "<tr>"
            f"<td><span class='severity {severity.lower()}'>{escape(severity)}</span></td>"
            f"<td>{escape(str(item.get('check', 'UNKNOWN')))}</td>"
            f"<td>{escape(str(item.get('status', 'UNKNOWN')))}</td>"
            f"<td>{escape(str(item.get('evidence', '')))}</td>"
            f"<td>{escape(str(item.get('recommendation', '')))}</td>"
            "</tr>"
        )
    if not rows:
        rows.append("<tr><td colspan='5'>No findings were returned. This is not proof of security.</td></tr>")

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
<div class="meta">Target: {target} &nbsp;|&nbsp; Path: {path}<br>Generated: {timestamp} &nbsp;|&nbsp; Duration: {duration:.2f}s</div>
</header>
<div class="notice"><strong>Scope and interpretation:</strong> This is a bounded HTTP response-configuration assessment, not a comprehensive vulnerability scan or penetration test. Observed missing headers and disclosures are not proof of exploitable vulnerabilities. Review findings in application context.</div>
<section class="stats">{summary_cards}</section>
<section class="panel">
<h2>Observed Findings</h2>
<div class="table-wrap"><table><thead><tr><th>Severity</th><th>Check</th><th>Status</th><th>Evidence</th><th>Recommended action</th></tr></thead>
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
