# Phase 2T — HTTP header accuracy and response classification

## Purpose

Improve the accuracy of ApexRecon's existing bounded HTTP assessment by validating selected security-header values instead of treating every non-empty value as correctly configured.

## Changes

- Validate HSTS `max-age` as one non-negative decimal value. Report missing, malformed, duplicate/ambiguous and `max-age=0` states separately.
- Recognize only `nosniff` for `X-Content-Type-Options`.
- Validate Referrer-Policy tokens and report the last recognized policy token.
- Accept `DENY` and `SAMEORIGIN` as X-Frame-Options protections; distinguish invalid values, ambiguous multiple values and obsolete `ALLOW-FROM`.
- Parse cookie attributes by exact attribute name. Validate SameSite values and flag `SameSite=None` without Secure.
- Distinguish enforced Content-Security-Policy headers from Content-Security-Policy-Report-Only. Observe multiple enforced policy values without claiming to simulate browser behavior.
- Label Permissions-Policy presence as unvalidated because full directive grammar and browser support are outside this phase.
- Expose HTTP response status classes as descriptive metadata, not vulnerability severity.

## Scope and safety

- No new HTTP requests, methods, URL paths, ports, redirects, probes or target expansion.
- Existing at-most-two bounded read-only GET request behavior is unchanged.
- Existing written-authorization gates remain unchanged.
- No crawling, fuzzing, authentication, form submission, exploitation, live scans, recurring scans or background monitoring.
- Regression tests use synthetic headers and mocked responses; no live targets are contacted.

## Interpretation limits

- Header validation is deliberately narrow and is not a full browser-policy parser.
- CSP observations do not model nonces, hashes, browser versions, application behavior or policy interactions.
- A response status class is not a vulnerability verdict; 4xx and 5xx responses can be intentional or transient.
- A present header does not establish that the policy is appropriate for the application.
- Operator review remains necessary before remediation.

## Validation

- Python 3.10, 3.11 and 3.12 CI matrix and Linux dependency/import smoke test.
- Termux/Ubuntu compile and unit-test validation required before merge.
- No live target validation is included.
