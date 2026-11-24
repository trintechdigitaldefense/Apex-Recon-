# Phase 2W — Assessment accuracy and false-positive reduction

## Purpose

Improve the reliability and interpretation of passive technology fingerprints without expanding target interaction.

## Changes

- Treat a CMS generator meta tag as a self-declared indicator, not high-confidence identification by itself.
- Require at least two detected markers before assigning HIGH CMS fingerprint confidence.
- Assign MEDIUM confidence when the only CMS marker is a matching generator meta tag.
- Retain LOW confidence for a single non-generator CMS marker.
- Parse quoted HTML meta attributes independently of their order, since HTML does not require the name attribute to precede content.
- Label Server and X-Powered-By banner attribution as LOW confidence because response headers can be changed or spoofed.
- Add offline regression tests for reordered attributes, confidence calibration, and banner attribution.

## Interpretation limits

- Fingerprints are passive indicators from response headers and a bounded HTML sample, not a complete software inventory.
- A matching generator tag is self-reported and may be stale, intentionally altered, or spoofed.
- Two markers improve confidence but do not prove that a component is active, current, or exploitable.
- Server and X-Powered-By values describe response banners, not independently verified server-side software.
- Version values are reported only when explicitly present in a matching CMS generator tag and syntactically numeric.
- Confidence describes the strength of the observed fingerprint evidence, not vulnerability severity or exploitability.

## Scope and safety

- No new HTTP requests, methods, paths, ports, probes, redirects, or target expansion.
- Existing response-size and request-count limits remain unchanged.
- No crawling, fuzzing, authentication, form submission, exploitation, recurring scans, background agents, or monitoring.
- Changes are limited to passive parsing, confidence classification, documentation, and offline tests.
- No live targets are contacted by these changes.

## Validation

Run the full unit test suite and compile checks on Python 3.10, 3.11, and 3.12 through CI, plus local Termux/Ubuntu validation. Synthetic fixtures and mocked requests only. Passing tests do not establish live fingerprint accuracy or client readiness.
