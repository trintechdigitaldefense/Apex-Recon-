# Phase 2Y — Assessment report consistency

## Purpose

Ensure individual assessment summaries do not omit findings that the shared finding schema classifies as UNKNOWN.

## Changes

- Individual HTTP/TLS evidence PDF summaries now count CRITICAL, HIGH, MEDIUM, LOW, INFO, and UNKNOWN.
- Unrecognized severity values are conservatively counted as UNKNOWN in the PDF summary instead of silently disappearing from the totals.
- Add a regression test that renders the PDF flowables and confirms an UNAVAILABLE finding appears in the UNKNOWN count.
- Update the README and CI branch triggers for this milestone.

## Interpretation

- UNKNOWN means the relevant control was not assessed or the source severity was not recognized; it is not a negative security result.
- UNAVAILABLE endpoint or handshake results remain UNKNOWN and UNRANKED.
- Severity counts are descriptive totals, not a composite risk score or proof of exploitability.
- The individual assessment PDF, HTTP HTML report, and unified engagement summary retain their own existing report structures.

## Scope and safety

- Report generation, severity-count normalization, documentation, and offline tests only.
- No new requests, methods, paths, ports, probes, redirects, or target expansion.
- Existing bounded HTTP GET behavior and one-connection TLS behavior are unchanged.
- No crawling, fuzzing, authentication, form submission, exploitation, recurring scans, background agents, or monitoring.
- No live targets contacted.

## Validation

- Synthetic finding records and mocked report rendering only.
- GitHub Actions runs Python 3.10, 3.11, and 3.12 test/compile jobs plus Linux dependency/import smoke test.
- Local Termux/Ubuntu validation is required before merge.
- Passing CI does not establish live-network accuracy or client readiness.
