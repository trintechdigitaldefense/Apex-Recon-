# Phase 2AA — Capability-aware startup

## Purpose

Make ApexRecon's startup menu accurately reflect which modules can run with the tools installed on the local system. Missing unrelated tools must not block the standard-library HTTP/TLS assessment modules.

## Runtime behavior

- Startup performs local executable-path checks for `nmap`, `whois`, `dig`, `curl`, and `ip`; it does not execute those tools during the check.
- OSINT is labelled PARTIAL when one or more collection dependencies are missing. Missing `dig`, `whois`, `curl`, or `nmap` checks are explicitly reported as NOT ASSESSED and are not presented as empty/negative results. Available collection steps can still run.
- SMB assessment is blocked before target input when Nmap is unavailable.
- Unified engagements record a selected SMB module as UNAVAILABLE when Nmap is missing, rather than treating it as a clean result.
- HTTP and TLS remain available independently of external OSINT/SMB tools.
- Ed25519 signing is labelled and guarded as unavailable when the Python `cryptography` package is absent.
- Missing `ip` disables automatic subnet discovery only; manual target entry remains available.

## Validation

```bash
python3 -m compileall -q apex_recon_v2.py tests
python3 -m unittest discover -s tests -v
```

Tests mock executable and Python-package availability. They do not invoke scanners, contact targets, or install packages.

## Boundaries

No assessment requests, methods, paths, ports, probes, redirects, target expansion, crawling, fuzzing, authentication, exploitation, or authorization gates change. No live targets are contacted. Missing dependencies are represented as unavailable or partial capability states, not as negative security findings. CI and unit tests do not establish live-network accuracy or client readiness.
