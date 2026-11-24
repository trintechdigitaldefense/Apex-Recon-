# Phase 2S — Content Security Policy quality observations

## Purpose

Phase 2S improves the existing HTTP header assessment by reviewing selected hardening characteristics of an observed enforced Content-Security-Policy header. It uses only the header already collected by the existing bounded HTTP request.

## Observations

- `unsafe-eval` in the effective script source list is reported as a medium-severity review indicator.
- `unsafe-inline` in effective script or style source lists is reported as a low-severity review indicator.
- Literal wildcard source expressions in selected source lists are reported for review.
- The effective `object-src` policy is reviewed for an explicit `none` restriction.
- The presence of `base-uri` is reviewed.
- Duplicate directives are parsed using the first occurrence.

## Interpretation limits

These are conservative static indicators, not a browser-policy simulator. Nonces, hashes, browser versions, application behavior, report-only policies, and compatibility requirements can affect the practical meaning of a policy. A finding is not proof of exploitability. Operators must review the complete policy and application requirements before remediation.

## Scope and safety

- No new network requests or HTTP methods.
- No new paths, crawling, fuzzing, authentication, form submission or exploitation.
- Existing maximum of two read-only GET requests and response-byte limits remain unchanged.
- Existing authorization gates remain unchanged.

## Validation

Run the focused and full suites:

    python3 -m unittest discover -s tests -p 'test_web_assessment.py' -v
    python3 -m unittest discover -s tests -v
    python3 -m compileall -q apex_recon_v2.py apex_web.py tests

Unit tests and CI do not establish live-world accuracy or client readiness.
