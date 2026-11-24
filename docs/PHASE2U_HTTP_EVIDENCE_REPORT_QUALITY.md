# Phase 2U — HTTP evidence quality and report consistency

## Purpose

Make HTTP assessment findings easier to verify by tying each header-related finding to bounded response provenance and the exact observed header values, while preventing sensitive response material from leaking into reports.

## Changes

- Add response status and sanitized final URL context to HTTP response findings.
- Attach the observed response header values relevant to each header finding, including missing-header observations.
- Redact Set-Cookie values while retaining cookie names and security-attribute observations.
- Redact CSP nonce and hash tokens from exported finding evidence.
- Re-normalize findings after evidence enrichment so stable finding identifiers match the final evidence text.
- Keep the same finding evidence available to HTML and JSON/PDF export paths.
- Add regression coverage for conflicting and duplicate header combinations, sensitive-value redaction, response provenance and report generation.

## Scope and safety

- No new network requests, HTTP methods, paths, ports, redirect behavior, probes or target expansion.
- Existing at-most-two bounded read-only GET request behavior is unchanged.
- Existing written-authorization gates are unchanged.
- No crawling, fuzzing, authentication, form submission, exploitation, recurring scans, background agents or monitoring.
- Tests use synthetic response headers and mocked requests only. No live targets are contacted.

## Evidence handling

- Cookie values are never copied into finding evidence. Cookie names and selected attributes are retained for traceability.
- CSP nonce and SHA-based source tokens are redacted because they may contain request-specific or deployment-sensitive material.
- Header evidence is bounded and remains subject to the existing finding text limits.
- The SHA-256 evidence checksum detects later record changes; it is not a digital signature, immutable storage or proof that an observation is true.

## Interpretation limits

- Captured headers describe one response at one URL path and one assessment time.
- Header values do not prove application exploitability or policy effectiveness in every browser.
- Recommendations remain review guidance and must be checked against application requirements before implementation.
- Successful unit tests and report generation do not establish live-target accuracy or client readiness.

## Validation

- Run the full unit suite and compile checks on Python 3.10, 3.11 and 3.12.
- Run the full suite in the user's Termux/Ubuntu environment before merge.
- Verify HTML, JSON and optional PDF output using synthetic fixtures.
- No live target validation is included.
