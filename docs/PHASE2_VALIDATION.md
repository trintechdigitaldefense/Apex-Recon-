# Phase 2A Validation Procedure

Run these checks from the repository root in the Android/Ubuntu proot or Linux environment.

## Offline checks (no target traffic)

```bash
python3 -m compileall -q apex_recon_v2.py apex_web.py tests
python3 -m unittest discover -s tests -v
```

The Phase 2A tests use synthetic response headers and mocked fetch calls. They must not contact real hosts.

## Review points

- A bare hostname defaults to HTTPS.
- Query strings are stripped before either request and are not copied into assessment output.
- Only standard HTTP/HTTPS ports are accepted, and an explicitly supplied port must match the URL scheme.
- IPv6 literal authorities remain bracketed when request URLs are constructed.
- IPv6 literals remain bracketed when constructing request URLs.
- Only a same-host, same-path HTTP-to-HTTPS redirect is followed; cross-host, same-scheme, path/query-changing, HTTPS-downgrade, and non-standard-port redirects are blocked.
- The assessment makes at most two GET requests with a bounded timeout.
- Missing evidence is reported as missing/unavailable, not as a clean security result.
- Cookie findings apply only to Set-Cookie headers observed in the single response.
- The engine is not integrated into the interactive CLI; invoke only after a future explicit written-authorization gate is added.

## Live validation

Do not perform live validation until the operator has confirmed written authorization for the exact hostname/path and the test window. Live validation is not required for the unit-test workflow and is not part of this milestone's current CI evidence.

## Acceptance gates

- All Python 3.10, 3.11, and 3.12 test jobs pass on the same commit.
- Linux dependency smoke test passes.
- Source review confirms scope and redirect restrictions.
- Phone-only validation is recorded separately from hosted CI.
- No merge or release until separately reviewed and explicitly approved.
