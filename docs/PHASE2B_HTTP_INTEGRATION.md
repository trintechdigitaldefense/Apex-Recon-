# Phase 2B — HTTP CLI and HTML report integration

## What this milestone adds

- Interactive menu option 3: HTTP Security Assessment.
- URL validation and normalization before authorization is requested.
- The existing exact-scope written-authorization attestation before any HTTP request.
- Integration with the Phase 2A bounded assessment engine.
- A dedicated responsive HTML report containing severity counts, observed status, evidence, recommendations and limitations.
- HTML escaping for target and finding data.
- Owner-only report permissions (0600) on supported POSIX filesystems.
- Logging of a minimal assessment summary, not full response headers or URL query strings.

## Operator workflow

1. Start ApexRecon with `python3 apex_recon_v2.py`.
2. Select menu option `3`.
3. Enter one authorized hostname or HTTP/HTTPS URL.
4. Review the normalized target and path.
5. Confirm written authorization for that exact scope by typing `YES`.
6. Review the findings and open the generated `apex_http_report_*.html` file.

If authorization is declined, no HTTP assessment request is made. URL query strings are removed by the underlying engine before requests and report output.

## Scope and limitations

- One operator-supplied URL path only.
- At most two read-only GET requests.
- No crawling, path enumeration, fuzzing, authentication, form submission, exploitation or background monitoring.
- Header absence is a configuration observation, not proof of exploitability.
- Header presence does not prove policy quality or effectiveness.
- TLS certificate/protocol/cipher assessment and CMS identification are not included in this milestone.
- The report is HTML; native PDF generation remains a separate milestone (browser print is a convenience only).

## Offline validation

Run:

```bash
python3 -m compileall -q apex_recon_v2.py apex_web.py tests
python3 -m unittest discover -s tests -v
```

The new tests mock the HTTP engine and do not contact a live target. A passing suite does not replace Android/Ubuntu phone validation or controlled live testing against explicitly authorized assets.

## Development status

This milestone is a draft development change. It does not authorize merge, release, client deployment or live scanning.
