# Phase 2V — Finding quality and remediation triage

## Purpose

Make finding severity provenance and review ordering visible without inventing risk, exploitability, or remediation advice.

## Changes

- Add `severity_basis` to distinguish module-assigned severity from an unassessed/unknown result.
- Add `review_priority`, derived only from the existing normalized severity:
  - P1: CRITICAL or HIGH
  - P2: MEDIUM
  - P3: LOW
  - INFO: INFO
  - UNRANKED: UNKNOWN
- Add an explicit note that review priority is triage ordering, not a composite risk score or proof of exploitability.
- Add `recommendation_status` so reports distinguish supplied remediation text from missing guidance.
- Expose review priority and recommendation status in HTTP HTML, HTTP/TLS PDF, and unified engagement PDF reports.
- Add regression tests for priority mapping, unknown severity handling, and missing recommendations.

## Interpretation limits

- Severity remains assigned by the originating assessment module; Phase 2V does not independently validate or change it.
- Priority is a simple ordering aid based on severity alone. It does not account for asset criticality, exposure, compensating controls, business impact, confidence, or exploitability.
- P1 does not mean a vulnerability is confirmed or must be remediated without human review.
- Recommendation status checks only whether text was supplied. It does not grade technical completeness or suitability.
- UNKNOWN remains UNRANKED and is never silently converted into a low-risk result.
- Findings remain observations or indicators according to their evidence type.

## Scope and safety

- No new network requests, HTTP methods, paths, ports, probes, redirects or target expansion.
- No changes to written-authorization gates or command execution.
- No crawling, fuzzing, authentication, form submission, exploitation, recurring scans, background agents or monitoring.
- Changes are limited to finding normalization, reporting, documentation and offline tests.

## Validation

Run the complete unit suite and compile checks on Python 3.10, 3.11 and 3.12, plus the user's Termux/Ubuntu environment. Tests use synthetic data and do not contact live targets.
