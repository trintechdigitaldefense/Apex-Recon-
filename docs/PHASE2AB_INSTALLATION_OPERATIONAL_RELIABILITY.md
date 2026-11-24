# Phase 2AB — Installation and operational reliability

## Purpose

Make setup failures visible before an assessment starts, especially on Android Termux with an Ubuntu proot environment. This phase improves local diagnostics and recovery guidance only. It does not change assessment scope or run any target checks.

## Expanded offline preflight

From the repository directory, run:

```bash
python3 apex_doctor.py
python3 apex_doctor.py --json
```

The diagnostic now checks:

- Python 3.10 or newer.
- The active interpreter path, whether a virtual environment is active, and availability of `pip` and `venv`.
- Required ApexRecon source files.
- Actual ability to create and remove a temporary file in the project directory, which checks whether reports and other local artifacts can be written there.
- External tools and optional ReportLab/cryptography packages, with platform-appropriate installation guidance.

The write check is local and temporary. It does not overwrite an existing file. If it fails, inspect directory ownership and permissions before changing them. Do not solve a permissions problem by running ApexRecon as root unless that is an intentional, understood operational choice.

## Recommended isolated setup

From the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements-pdf.txt -r requirements-crypto.txt
python apex_doctor.py
```

The PDF and signing requirements are optional. HTTP/TLS assessment and JSON evidence generation do not require either package.

Use the same interpreter for installation, diagnostics, tests, and application startup. After activating the environment, prefer `python` rather than switching between unrelated `python` and `python3` executables.

## Termux and Ubuntu proot separation

For Ubuntu inside proot, install system tools inside Ubuntu:

```bash
apt-get update
apt-get install -y git python3 nmap whois dnsutils curl iproute2 python3-venv
```

For native Termux, use Termux packages and the native Termux Python interpreter:

```bash
pkg update
pkg install python git nmap whois dnsutils curl iproute2
```

Do not install packages with native Termux Python and expect Ubuntu proot Python to see them, or the reverse. They are separate environments.

## Recovery guidance

### Virtual environment is missing or damaged

From the repository root, recreate it:

```bash
deactivate 2>/dev/null || true
rm -rf .venv
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements-pdf.txt -r requirements-crypto.txt
```

This removes only the local `.venv` directory. Confirm that it contains no user data before removing it.

### pip reports an externally managed environment

Do not force a global installation. Create and activate the project virtual environment as shown above, then install optional Python requirements inside it.

### The project write test fails

Check the project directory path, available storage, and ownership/permissions. Keep generated evidence in a directory accessible only to the intended operator. The diagnostic reports the exception type but does not alter permissions or delete existing artifacts.

### Optional package installation fails

ApexRecon's HTTP/TLS engines and JSON evidence export use the Python standard library. PDF export requires ReportLab; Ed25519 signing requires cryptography. Install only the optional feature you intend to use, then rerun the diagnostic with the same interpreter.

## Validation

```bash
python3 apex_doctor.py
python3 -m compileall -q apex_doctor.py apex_recon_v2.py apex_web.py apex_tls.py apex_fingerprint.py apex_evidence.py apex_findings.py apex_finding_adapters.py apex_engagement.py apex_engagement_cli.py apex_signing.py apex_audit.py apex_audit_backup.py apex_audit_backup_signing.py tests
python3 -m unittest discover -s tests -v
```

Unit tests use temporary directories and mocked failures. They do not install packages, run assessment tools, or contact targets.

## Boundaries and limitations

- The diagnostic checks local files and write access only; it does not prove that a filesystem will remain writable during a later assessment.
- It does not verify every optional dependency's runtime behavior or every supported Android/Linux distribution.
- It does not repair permissions, install packages, alter Python environments, or remove existing files.
- No scan requests, methods, paths, ports, probes, redirects, target expansion, crawling, fuzzing, authentication, or exploitation are added or changed.
- No live targets are contacted. No recurring scans, background agents, or monitoring are introduced.
- Passing the diagnostic, CI, or unit tests does not establish client readiness or production approval.
