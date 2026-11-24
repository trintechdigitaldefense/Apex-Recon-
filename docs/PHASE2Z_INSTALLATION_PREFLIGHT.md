# Phase 2Z — Installation preflight and environment diagnostics

## Purpose

Make first-run setup easier to understand on Termux/Ubuntu and Linux without changing assessment behavior or automatically installing software.

## New local diagnostic

Run:

```bash
python3 apex_doctor.py
```

The diagnostic reports:
- Python version support (3.10 or newer).
- Availability of `dig`, `whois`, `curl`, `nmap`, and `ip`.
- Availability of optional ReportLab and cryptography packages.
- Which ApexRecon capabilities those dependencies enable.
- Platform-appropriate package installation guidance for Termux or Linux.

Machine-readable output:

```bash
python3 apex_doctor.py --json
```

Strict completeness check:

```bash
python3 apex_doctor.py --strict
```

The normal diagnostic exits successfully when Python is supported, even if optional features or individual external tools are unavailable. This is intentional: HTTP/TLS assessment uses the Python standard library and should remain usable when unrelated OSINT/SMB dependencies are missing. Strict mode returns a non-zero status if any listed external or optional dependency is absent.

## Installation

### Existing Termux with Ubuntu proot

Install system packages inside the Ubuntu environment:

```bash
apt-get update
apt-get install -y git python3 nmap whois dnsutils curl iproute2
```

From the repository root, install optional report and signing features only when needed:

```bash
python3 -m pip install -r requirements-pdf.txt
python3 -m pip install -r requirements-crypto.txt
```

Some Ubuntu/proot images restrict global pip installation. If pip reports an externally-managed-environment error, use a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements-pdf.txt -r requirements-crypto.txt
```

The core HTTP/TLS engines and JSON evidence generation do not require either optional package.

### Termux native environment

For native Termux (not Ubuntu proot), install system tools with:

```bash
pkg update
pkg install python git nmap whois dnsutils curl iproute2
```

Use the Termux Python interpreter to run the diagnostic and application. Do not mix packages installed by native Termux Python with the separate Ubuntu proot Python environment.

## Validation

Run the following from the repository root:

```bash
python3 apex_doctor.py
python3 -m compileall -q apex_doctor.py apex_recon_v2.py apex_web.py apex_tls.py apex_fingerprint.py apex_evidence.py apex_findings.py apex_finding_adapters.py apex_engagement.py apex_engagement_cli.py apex_signing.py apex_audit.py apex_audit_backup.py apex_audit_backup_signing.py tests
python3 -m unittest discover -s tests -v
```

The diagnostic only checks local executable paths and Python module availability. It does not run Nmap, WHOIS, DNS, curl, or any assessment operation and does not contact targets.

## Interpretation and boundaries

- A missing external tool disables or limits only the capability that uses it; it does not mean ApexRecon itself cannot start.
- ReportLab is optional for native PDF output. JSON evidence remains available without it.
- cryptography is optional for Ed25519 signing and verification.
- GeoIP lookup uses curl to send the resolved target IP to ipinfo.io; obtain client approval or avoid that lookup where third-party disclosure is prohibited.
- The diagnostic does not install, upgrade, remove, or configure packages.
- No assessment requests, methods, paths, ports, probes, redirects, target scope, or authorization gates change.
- No live targets are contacted by this phase.
- Passing the diagnostic or CI does not establish live-network accuracy, universal platform compatibility, client readiness, or release approval.
