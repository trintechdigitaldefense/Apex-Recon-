# Phase 2G — Cross-Module Finding Consistency

## Objective

Introduce one conservative, machine-readable finding structure for assessment modules that already emit structured findings. This milestone is a data-contract improvement, not a change to scan behavior or a new vulnerability-detection capability.

## Common finding record

The shared normalizer in `apex_findings.py` emits:

- `schema_version`: finding schema version (`1.0`).
- `finding_id`: deterministic identifier derived from module, check, status and evidence.
- `module`: source assessment module.
- `check`: stable check name.
- `severity`: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO` or `UNKNOWN`.
- `status`: module-defined observation status.
- `confidence`: `HIGH`, `MEDIUM`, `LOW` or `UNKNOWN`.
- `evidence_type`: `OBSERVATION`, `INDICATOR`, `INFERENCE` or `UNKNOWN`.
- `evidence`: bounded evidence text.
- `recommendation`: bounded remediation guidance.

Unknown or unsupported classifications are retained as `UNKNOWN`; they are not silently converted to a higher severity. The shared schema does not calculate CVSS, assign business impact, or prove exploitability.

## Current integration

- HTTP: each finding is normalized from the bounded HTTP response/header observation. Confidence describes confidence in the recorded observation, not confidence that a vulnerability can be exploited.
- TLS: each finding is normalized from the single verified TLS session or its explicit failure result. It does not imply server-wide protocol/cipher enumeration.
- Evidence JSON: normalized finding metadata is preserved in exported records and included in the existing assessment checksum.

## Known migration gaps

- SMB currently stores parser findings as free-text strings on each host. It has not been converted to structured records in this milestone. Existing SMB severity/risk presentation remains unchanged.
- OSINT currently collects DNS, WHOIS, geolocation and quick port-scan output as raw collection data; it does not yet emit a structured findings list. This milestone does not invent findings from incomplete collection data.
- HTML report layouts remain module-specific. This phase standardizes the underlying HTTP/TLS finding data and evidence export, not every report presentation.
- Partial-module orchestration and engagement-level combined reporting are outside this initial slice.

## Safety and compatibility

- No additional requests or scans are introduced.
- Existing HTTP/TLS severity decisions are preserved.
- The normalizer rejects malformed finding objects rather than silently dropping them.
- Evidence export remains backward-tolerant of legacy finding dictionaries by marking absent confidence/evidence-type metadata as `UNKNOWN`.
- The SHA-256 evidence checksum remains a tamper-detection aid, not a digital signature or proof of origin.
- Tests use synthetic data and mocks; no live target is contacted.

## Validation

Run on Ubuntu/Termux:

```bash
python3 -m compileall -q apex_recon_v2.py apex_web.py apex_tls.py apex_fingerprint.py apex_evidence.py apex_findings.py tests
python3 -m unittest discover -s tests -q
```

The expected test count will be recorded after GitHub Actions and operator validation complete. No client-readiness claim is made by this milestone.
