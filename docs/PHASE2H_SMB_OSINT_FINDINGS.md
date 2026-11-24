# Phase 2H — SMB and OSINT Finding Integration

## Objective

Extend the Phase 2G common finding schema to the legacy SMB parser and the OSINT collection workflow. This is a representation and evidence-quality change only. It does not add scans, probes, requests, or vulnerability detection.

## SMB integration

- Existing SMB parser output remains compatible: legacy free-text `findings`, host risk labels, signing state, share list, and Nmap vulnerability-script status fields remain available.
- `apex_finding_adapters.py` converts those existing fields into the Phase 2G finding schema.
- SMB signing-disabled and non-hidden-share observations retain MEDIUM severity, matching the existing parser's risk treatment.
- Nmap NSE positive indicators retain HIGH severity; potential indicators retain MEDIUM; explicit NOT VULNERABLE script results are INFO observations only.
- Missing or unrecognized required checks produce an UNKNOWN / UNASSESSED completeness record. No incomplete host is promoted to LOW.
- Nmap script output is an indicator, not proof of exploitation or independent vulnerability confirmation.

## OSINT integration

- Existing DNS, selected WHOIS metadata, geolocation-provider response metadata, and top-20 TCP port output are converted into structured observations.
- Collected DNS values and open-port lines are retained as bounded evidence. WHOIS values are not duplicated into finding evidence; only returned metadata field names are recorded. Geolocation values are not duplicated; only returned field names are recorded.
- OSINT records use INFO severity and OBSERVATION evidence type. They are collection results, not vulnerability findings.
- Empty/missing datasets do not create synthetic findings or imply that a record/service does not exist.
- The existing geolocation behavior still sends the resolved target IP to ipinfo.io; this phase does not change that privacy boundary.

## Compatibility and safety

- Existing Nmap commands, target validation, written-authorization prompts, timeouts, and scan limits are unchanged.
- No live target is contacted by unit tests.
- The shared normalizer still bounds text and maps unsupported classifications to UNKNOWN.
- Structured records are attached to the in-memory SMB host and OSINT result objects. No new engagement-level report, OSINT PDF/JSON export, auto-risk scoring, or continuous monitoring is introduced.

## Validation

Run on Ubuntu/Termux:

```bash
python3 -m compileall -q apex_recon_v2.py apex_web.py apex_tls.py apex_fingerprint.py apex_evidence.py apex_findings.py apex_finding_adapters.py tests
python3 -m unittest discover -s tests -q
```

CI and local unit tests do not establish live scan accuracy, client readiness, or production suitability. Draft PR only; no merge, release, or deployment.
