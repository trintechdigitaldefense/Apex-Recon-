# Phase 2 — HTTP Security Assessment (Milestone 2A)

## Scope

The first Phase 2 milestone adds a standalone, standard-library HTTP assessment engine in `apex_web.py`. It performs no more than two read-only GET requests against one operator-supplied hostname and path:

1. HTTP endpoint: determine whether the request remains on HTTP or redirects to HTTPS.
2. HTTPS endpoint: inspect response security headers and observed Set-Cookie attributes.

It does not crawl links, discover common paths, submit forms, authenticate, fuzz, exploit, or scan port ranges. Response bodies are not analysed. The module is deliberately separate from the legacy CLI until its evidence model and tests are reviewed.

## Checks

- HTTP-to-HTTPS redirect behavior.
- HSTS on HTTPS responses.
- Content-Security-Policy.
- X-Content-Type-Options.
- X-Frame-Options or CSP frame-ancestors.
- Referrer-Policy and Permissions-Policy.
- Secure, HttpOnly, and SameSite attributes on observed cookies.
- Server and X-Powered-By disclosure (informational/low).

Missing headers are findings, not proof of an exploitable vulnerability. Header presence does not prove that a policy is correct or effective. No response cookie does not prove that the application never uses cookies.

## Safety controls

- The caller must obtain written authorization for the exact target before invoking the assessment.
- Supports only HTTP/HTTPS and standard ports 80/443.
- Embedded credentials and URL fragments are rejected.
- Query strings are stripped before requests and excluded from evidence to reduce accidental transmission or disclosure of URL tokens.
- At most two requests are made, with a bounded timeout and a small Range request.
- Redirects must remain on the original hostname; HTTPS downgrade and cross-host redirects are blocked.
- No shell commands, external scanning dependencies, crawling, or exploit payloads are used.
- No background activity or scheduled scans are introduced.

## Validation

Run the isolated regression tests:

```bash
python3 -m unittest discover -s tests -p 'test_web_assessment.py' -v
python3 -m compileall -q apex_web.py tests
```

The tests use synthetic headers and mocked network calls. They do not contact real targets and do not establish live-world accuracy or client readiness.

## Known limitations / next work

- TLS certificate, hostname, expiry, protocol and cipher inspection is not included in this milestone.
- CMS and technology fingerprinting are not included.
- The engine is not yet wired into the interactive ApexRecon menu or HTML client report.
- Header policy quality requires application-specific review; the engine reports observed evidence only.
- Redirect checks are hostname-bound, not a complete multi-origin application scope model.
- No live target validation has been performed.
