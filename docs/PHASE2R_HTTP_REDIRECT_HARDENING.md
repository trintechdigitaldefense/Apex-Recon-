# Phase 2R — HTTP redirect scope hardening

## Purpose

This milestone hardens the existing HTTP assessment redirect policy. It does not add assessment checks or change the bounded request model.

## Redirect rules

A redirect is accepted only when it:

- stays on the same normalized hostname;
- upgrades from standard HTTP to standard HTTPS;
- preserves the exact request path;
- does not add a query string;
- contains no embedded username or password;
- contains no URL fragment;
- has a valid, standard port (HTTP 80 or HTTPS 443, including implicit defaults).

Malformed URL/port values, missing or invalid hostnames, cross-host redirects, unsupported schemes, path changes, query strings, fragments and embedded credentials are rejected as redirect-scope errors.

## Scope and safety

- The assessment remains limited to one operator-supplied hostname and path.
- The engine still performs at most two bounded, read-only GET requests.
- A same-host HTTP-to-HTTPS upgrade can still count as the HTTPS response, avoiding an extra request.
- No crawling, fuzzing, form submission, authentication, exploit attempts, port scanning, or target expansion is introduced.
- The caller remains responsible for enforcing written authorization for the exact target.

## Validation

The added regression tests use synthetic request objects and do not contact live targets. Run:

    python3 -m unittest discover -s tests -p 'test_web_assessment.py' -v
    python3 -m compileall -q apex_web.py tests

Passing unit tests and CI do not establish live-world accuracy or client readiness.
