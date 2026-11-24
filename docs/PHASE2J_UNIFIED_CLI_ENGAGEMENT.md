# Phase 2J — Unified CLI Engagement Integration

## Purpose

Phase 2J connects the Phase 2I engagement record builder to the existing interactive ApexRecon CLI. Operators can start one engagement, choose which existing assessment modules to run, and export a consolidated JSON report plus an optional PDF.

## Operator workflow

1. Select **Unified Engagement** from the main menu.
2. Enter an engagement name or reference.
3. Select ALL modules or a comma-separated selection:
   - External Footprinting (OSINT)
   - SMB Network Auditor
   - HTTP Security Assessment
   - TLS Security Assessment
4. Each selected module runs through its existing target validation and exact-scope written-authorization prompt.
5. ApexRecon records each module as COMPLETED, PARTIAL, FAILED or NOT_RUN and generates one combined engagement record.
6. JSON is the primary export. PDF is attempted when ReportLab is installed and available.

Individual assessment menu options remain available and retain their existing behavior. The workflow runs selected modules sequentially in the current terminal session; it does not schedule or resume work in the background.

## Coverage and interpretation

- Unselected modules are explicitly NOT_RUN with a NOT_SELECTED marker.
- Selected modules that do not proceed, including invalid target or declined authorization, are explicitly NOT_RUN with a SELECTED_BUT_NOT_RUN marker.
- Operational failures are recorded as FAILED where the module can identify them.
- A module whose standalone HTML report cannot be written after its assessment is recorded as PARTIAL, while its collected findings remain in the engagement.
- OSINT, SMB, HTTP and TLS findings are passed through the existing common finding normalizer.
- Module-specific target scopes and limitations are preserved.
- No composite risk score is calculated. Missing or NOT_RUN coverage is not a clean result.

## Safety boundaries

- Every selected module retains its own target validation and written-authorization gate.
- No new scan commands, probes, paths, ports, network requests or target expansion are introduced by the orchestrator.
- Existing module scan behavior is reused without increasing its scope.
- The existing OSINT GeoIP behavior still sends the resolved target IP to ipinfo.io.
- The SMB checks remain limited to the configured Nmap scripts and ports. NSE positive output is an indicator, not proof of exploitation.
- HTTP checks remain bounded and read-only. TLS remains one certificate-verified handshake on TCP/443.
- The workflow is operator-initiated and sequential. It is not a daemon, scheduler, recurring scanner or 24-hour monitoring service.
- Engagement checksums are SHA-256 integrity checks, not digital signatures or immutable storage.

## Validation

Run:

```bash
python3 -m compileall -q apex_recon_v2.py apex_web.py apex_tls.py apex_fingerprint.py apex_evidence.py apex_findings.py apex_finding_adapters.py apex_engagement.py apex_engagement_cli.py tests
python3 -m unittest discover -s tests -v
```

All new tests use synthetic inputs. No live target scan is needed to validate selection and report assembly.

## Release boundaries

Phase 2J is a draft development milestone. CI and offline tests do not establish live accuracy, platform compatibility, client readiness or production readiness. No merge, release, deployment or live scan is authorized by this work.
