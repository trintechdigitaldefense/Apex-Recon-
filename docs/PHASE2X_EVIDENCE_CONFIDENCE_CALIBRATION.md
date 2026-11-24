# Phase 2X — Evidence confidence and unavailable-result classification

## Purpose

Prevent failed or incomplete network observations from being presented as security findings with a ranked severity when the relevant control could not be assessed.

## Changes

- HTTP and HTTPS endpoint results with status `UNAVAILABLE` use severity `UNKNOWN`.
- TLS handshake results with status `UNAVAILABLE` use severity `UNKNOWN`.
- The shared finding schema consequently assigns `UNRANKED` review priority to these records.
- HTTP reports include an explicit UNKNOWN count and display UNKNOWN rather than silently folding it into INFO.
- Regression tests cover endpoint failures, transport errors, TLS timeouts, and report rendering.

## Interpretation

- `UNAVAILABLE` means the assessment did not obtain a usable response or complete the handshake.
- It does not mean the endpoint is vulnerable, secure, or absent.
- A timeout, connection refusal, DNS issue, or TLS transport error may have several causes and may be transient.
- A separate confirmed observation, such as a certificate verification failure after a completed TLS connection, retains its own classification.
- Operators should resolve reachability or repeat the assessment before drawing conclusions about the unassessed control.

## Scope and safety

- Classification, report presentation, documentation, and offline tests only.
- No new requests, methods, paths, ports, probes, redirects, or target expansion.
- Existing bounded HTTP GET behavior and one-connection TLS behavior are unchanged.
- No crawling, fuzzing, authentication, form submission, exploitation, recurring scans, background agents, or monitoring.
- No live targets contacted.

## Validation

- GitHub Actions Python 3.10, 3.11, and 3.12 test/compile matrix and Linux dependency/import smoke test.
- Synthetic fixtures and mocked network interactions only.
- Local Termux/Ubuntu validation required before merge.
- Passing CI does not establish live-network accuracy or client readiness.
