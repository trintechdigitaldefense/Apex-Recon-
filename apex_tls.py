"""ApexRecon Phase 2C: one-connection, verified TLS configuration assessment.

This module performs one TCP connection and one TLS handshake to the target's
standard HTTPS port (443). Certificate and hostname verification remain enabled.
It does not downgrade, enumerate protocol versions, enumerate ciphers, or scan ports.
The caller must enforce written authorization before invoking assess_tls().
"""
from __future__ import annotations

import os
import socket
import ssl
import urllib.parse
from datetime import datetime, timezone
from html import escape
from typing import Any


DEFAULT_TIMEOUT = 8.0
MAX_TIMEOUT = 20.0


class TLSAssessmentInputError(ValueError):
    """Raised when a TLS target or timeout is outside the supported scope."""


def normalize_tls_target(value: str) -> str:
    """Return one validated DNS hostname or IP literal for TLS SNI/verification."""
    if not isinstance(value, str):
        raise TLSAssessmentInputError("target must be text")
    raw = value.strip()
    if not raw or any(ord(ch) < 32 for ch in raw):
        raise TLSAssessmentInputError("target is empty or contains control characters")
    try:
        from apex_web import normalize_target_url, AssessmentInputError
        parsed = normalize_target_url(raw)
    except (ValueError, AssessmentInputError) as exc:
        raise TLSAssessmentInputError(str(exc)) from exc
    host = parsed.hostname
    if not host:
        raise TLSAssessmentInputError("target must contain a hostname")
    return host


def _name_parts(value: Any) -> str:
    """Format certificate subject/issuer tuples without trusting them as HTML."""
    if not value:
        return "Not supplied"
    parts = []
    try:
        for rdn in value:
            for key, item in rdn:
                parts.append(f"{key}={item}")
    except (TypeError, ValueError):
        return "Certificate field unavailable"
    return ", ".join(parts)[:1000] if parts else "Not supplied"


def _finding(check: str, severity: str, status: str, evidence: str, recommendation: str) -> dict:
    return {
        "check": check,
        "severity": severity,
        "status": status,
        "evidence": evidence,
        "recommendation": recommendation,
    }


def assess_tls(target: str, timeout: float = DEFAULT_TIMEOUT) -> dict:
    """Perform one verified TLS handshake to target:443 and report negotiated data."""
    host = normalize_tls_target(target)
    try:
        timeout = float(timeout)
    except (TypeError, ValueError) as exc:
        raise TLSAssessmentInputError("timeout must be numeric") from exc
    if not 0 < timeout <= MAX_TIMEOUT:
        raise TLSAssessmentInputError(
            f"timeout must be greater than 0 and no more than {MAX_TIMEOUT:g} seconds"
        )

    context = ssl.create_default_context()
    # Fail closed if a platform/customization unexpectedly weakens verification.
    if context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname:
        raise TLSAssessmentInputError("platform TLS context does not enforce certificate and hostname verification")

    try:
        with socket.create_connection((host, 443), timeout=timeout) as raw_socket:
            with context.wrap_socket(raw_socket, server_hostname=host) as tls_socket:
                protocol = tls_socket.version()
                cipher_info = tls_socket.cipher()
                certificate = tls_socket.getpeercert()
    except ssl.SSLCertVerificationError as exc:
        reason = getattr(exc, "verify_message", None) or str(exc) or "certificate verification failed"
        return {
            "schema_version": "1.0",
            "module": "TLS Security Assessment",
            "target": host,
            "port": 443,
            "status": "VERIFICATION_FAILED",
            "verified": False,
            "protocol": None,
            "cipher": None,
            "certificate": None,
            "findings": [
                _finding(
                    "CERTIFICATE_VERIFICATION",
                    "HIGH",
                    "FAILED",
                    str(reason)[:500],
                    "Install a valid certificate whose trust chain and subject alternative names match this hostname. Do not disable client-side verification.",
                )
            ],
            "limitations": [
                "The verified handshake did not complete, so certificate details and negotiated protocol/cipher were not collected.",
                "No unverified fallback handshake was attempted.",
                "Only the protocol and cipher negotiated by this client are observed; server-wide support is not enumerated.",
            ],
            "error_type": type(exc).__name__,
        }
    except (ssl.SSLError, socket.timeout, TimeoutError, OSError) as exc:
        return {
            "schema_version": "1.0",
            "module": "TLS Security Assessment",
            "target": host,
            "port": 443,
            "status": "UNAVAILABLE",
            "verified": False,
            "protocol": None,
            "cipher": None,
            "certificate": None,
            "findings": [
                _finding(
                    "TLS_HANDSHAKE",
                    "MEDIUM",
                    "UNAVAILABLE",
                    f"{type(exc).__name__}: {str(exc)[:400]}",
                    "Confirm that the authorized host is reachable on TCP/443 and review its TLS listener and network path.",
                )
            ],
            "limitations": [
                "No verified TLS session was established; certificate and negotiated protocol/cipher details are unavailable.",
                "No unverified fallback handshake, downgrade probing, protocol enumeration, or port scanning was attempted.",
            ],
            "error_type": type(exc).__name__,
        }

    now = datetime.now(timezone.utc)
    certificate_data = {
        "subject": _name_parts(certificate.get("subject")),
        "issuer": _name_parts(certificate.get("issuer")),
        "not_before": certificate.get("notBefore"),
        "not_after": certificate.get("notAfter"),
        "subject_alt_names": [
            f"{kind}:{name}" for kind, name in (certificate.get("subjectAltName") or [])[:30]
        ],
    }
    findings = [
        _finding(
            "CERTIFICATE_VERIFICATION",
            "INFO",
            "VERIFIED",
            "The operating system trust store accepted the certificate chain and hostname verification succeeded.",
            "Keep certificate renewal and trust-chain monitoring in the organisation's normal maintenance process.",
        )
    ]

    expiry_text = certificate.get("notAfter")
    if expiry_text:
        try:
            expiry_epoch = ssl.cert_time_to_seconds(expiry_text)
            expiry = datetime.fromtimestamp(expiry_epoch, timezone.utc)
            remaining_seconds = (expiry - now).total_seconds()
            days_remaining = int(remaining_seconds // 86400)
            certificate_data["days_remaining"] = days_remaining
            certificate_data["expires_at_utc"] = expiry.isoformat()
            if remaining_seconds <= 0:
                findings.append(_finding(
                    "CERTIFICATE_EXPIRY", "HIGH", "EXPIRED",
                    f"Certificate notAfter is {expiry.isoformat()}.",
                    "Renew and deploy a valid certificate immediately.",
                ))
            elif remaining_seconds <= 7 * 86400:
                findings.append(_finding(
                    "CERTIFICATE_EXPIRY", "HIGH", "EXPIRING_WITHIN_7_DAYS",
                    f"Certificate expires in approximately {days_remaining} day(s), at {expiry.isoformat()}.",
                    "Renew and deploy the certificate before expiry; verify the full chain after deployment.",
                ))
            elif remaining_seconds <= 30 * 86400:
                findings.append(_finding(
                    "CERTIFICATE_EXPIRY", "MEDIUM", "EXPIRING_WITHIN_30_DAYS",
                    f"Certificate expires in approximately {days_remaining} day(s), at {expiry.isoformat()}.",
                    "Schedule certificate renewal and verify automated renewal is functioning.",
                ))
            else:
                findings.append(_finding(
                    "CERTIFICATE_EXPIRY", "INFO", "VALID",
                    f"Certificate expires at {expiry.isoformat()} ({days_remaining} days remaining).",
                    "Maintain routine certificate renewal and expiry monitoring.",
                ))
        except (OverflowError, OSError, TypeError, ValueError):
            certificate_data["days_remaining"] = None
            findings.append(_finding(
                "CERTIFICATE_EXPIRY", "INFO", "NOT_INTERPRETED",
                "The certificate expiry field could not be parsed.",
                "Review the certificate validity dates with a trusted certificate inspection tool.",
            ))
    else:
        findings.append(_finding(
            "CERTIFICATE_EXPIRY", "INFO", "NOT_REPORTED",
            "The peer certificate did not expose a notAfter value.",
            "Review the certificate validity period with a trusted certificate inspection tool.",
        ))

    if not certificate_data["subject_alt_names"]:
        findings.append(_finding(
            "CERTIFICATE_SAN", "LOW", "NO_SAN_REPORTED",
            "No subject alternative names were returned by the verified TLS session.",
            "Confirm that the certificate includes subject alternative names for every intended service hostname.",
        ))
    else:
        findings.append(_finding(
            "CERTIFICATE_SAN", "INFO", "PRESENT",
            "; ".join(certificate_data["subject_alt_names"])[:1000],
            "Confirm the listed names are limited to the intended service scope.",
        ))

    cipher_name = cipher_info[0] if cipher_info else None
    cipher_protocol = cipher_info[1] if cipher_info and len(cipher_info) > 1 else None
    cipher_bits = cipher_info[2] if cipher_info and len(cipher_info) > 2 else None
    findings.append(_finding(
        "NEGOTIATED_TLS",
        "INFO",
        "NEGOTIATED",
        f"Protocol: {protocol or 'Unknown'}; cipher: {cipher_name or 'Unknown'}; cipher protocol: {cipher_protocol or 'Unknown'}; strength: {cipher_bits if cipher_bits is not None else 'Unknown'} bits.",
        "Review the negotiated protocol and cipher against the organisation's current cryptographic baseline. This single result does not enumerate other server-supported options.",
    ))

    return {
        "schema_version": "1.0",
        "module": "TLS Security Assessment",
        "target": host,
        "port": 443,
        "status": "VERIFIED",
        "verified": True,
        "protocol": protocol,
        "cipher": {
            "name": cipher_name,
            "protocol": cipher_protocol,
            "bits": cipher_bits,
        },
        "certificate": certificate_data,
        "findings": findings,
        "limitations": [
            "One TCP connection and one verified TLS handshake to standard port 443 only.",
            "Certificate-chain trust and hostname verification remain enabled; no insecure fallback is used.",
            "Only the protocol and cipher negotiated by this client are observed; server-wide protocol/cipher support is not enumerated.",
            "No downgrade probing, protocol enumeration, cipher enumeration, port scanning, HTTP request, crawling, or exploitation is performed.",
            "A failed handshake does not establish which other TLS versions or ciphers the server may support.",
        ],
    }


def generate_html_report(result: dict, duration_seconds: float) -> str:
    """Write a self-contained TLS report with escaped evidence and private permissions."""
    if not isinstance(result, dict) or result.get("module") != "TLS Security Assessment":
        raise ValueError("result is not an ApexRecon TLS assessment")
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
    filename = "apex_tls_report_" + now.strftime("%Y%m%d_%H%M%S_%f") + ".html"
    rows = []
    for item in findings:
        rows.append(
            "<tr>"
            f"<td>{escape(str(item.get('severity', 'INFO')))}</td>"
            f"<td>{escape(str(item.get('check', 'UNKNOWN')))}</td>"
            f"<td>{escape(str(item.get('status', 'UNKNOWN')))}</td>"
            f"<td>{escape(str(item.get('evidence', '')))}</td>"
            f"<td>{escape(str(item.get('recommendation', '')))}</td>"
            "</tr>"
        )
    cert = result.get("certificate") or {}
    metadata = [
        ("Target", f"{result.get('target', 'Unknown')}:443"),
        ("Assessment", result.get("status", "UNKNOWN")),
        ("Verified", result.get("verified", False)),
        ("Negotiated protocol", result.get("protocol") or "Not available"),
        ("Cipher", (result.get("cipher") or {}).get("name") or "Not available"),
        ("Certificate subject", cert.get("subject", "Not available")),
        ("Certificate issuer", cert.get("issuer", "Not available")),
        ("Certificate expiry", cert.get("expires_at_utc") or cert.get("not_after") or "Not available"),
        ("Duration", f"{duration:.2f} seconds"),
        ("Generated", now.isoformat(timespec="seconds")),
    ]
    meta_html = "".join(
        f"<tr><th>{escape(str(key))}</th><td>{escape(str(value))}</td></tr>"
        for key, value in metadata
    )
    limit_html = "".join(f"<li>{escape(str(item))}</li>" for item in limitations)
    html = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ApexRecon TLS Assessment</title>
<style>
body{{margin:0;padding:20px;background:#0b1018;color:#e8eef5;font:14px/1.55 system-ui,sans-serif}}
main{{max-width:1100px;margin:auto}}header,section{{background:#121c29;border:1px solid #263648;border-radius:10px;padding:20px;margin-bottom:16px}}
h1{{margin:0;color:#48d7e8}}h2{{font-size:17px}}table{{width:100%;border-collapse:collapse;overflow-wrap:anywhere}}
th,td{{padding:9px;text-align:left;vertical-align:top;border-bottom:1px solid #263648}}
th{{color:#48d7e8}}p,li{{color:#c3ceda}}.notice{{color:#ffbf69}}
@media(max-width:700px){{body{{padding:10px}}table{{font-size:12px}}th,td{{padding:6px}}}}
@media print{{body{{background:#fff;color:#111}}header,section{{background:#fff;color:#111;border:1px solid #bbb}}th{{color:#111}}p,li{{color:#222}}}}
</style></head><body><main>
<header><h1>APEXRECON — TLS SECURITY ASSESSMENT</h1>
<p>TrinTech Digital Defense · Confidential · One-time authorized assessment</p>
<p class="notice">A verified handshake is an observation of this client/server negotiation, not a complete inventory of server TLS capabilities.</p></header>
<section><h2>Assessment details</h2><table>{meta_html}</table></section>
<section><h2>Findings</h2><table><thead><tr><th>Severity</th><th>Check</th><th>Status</th><th>Evidence</th><th>Recommendation</th></tr></thead>
<tbody>{''.join(rows) if rows else '<tr><td colspan="5">No findings returned; this is not proof of security.</td></tr>'}</tbody></table></section>
<section><h2>Scope and limitations</h2><ul>{limit_html}</ul></section>
</main></body></html>"""
    fd = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(html)
    return filename
