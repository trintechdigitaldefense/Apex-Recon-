# Phase 2AN — Cross-platform validation

## Purpose

Establish a repeatable compatibility baseline for the supported Linux operating environments used by ApexRecon. This phase validates source compilation, the offline unit suite, dependency detection, startup imports, and local evidence-storage capabilities without contacting assessment targets.

## Supported environments

ApexRecon's current implementation depends on POSIX/Linux behavior, including `fcntl`-based file locking. The supported platform family is therefore Linux:

- Native Termux on Android.
- Ubuntu running inside Termux/proot.
- Desktop/server Ubuntu Linux.

Windows and macOS are not supported by this phase. The diagnostic must report those systems as unsupported rather than allowing a misleading green readiness result. A Linux kernel profile alone does not prove that every Android, proot, mount, or filesystem combination behaves identically.

## Automated CI matrix

GitHub Actions runs the compile and complete unit-test suite on:

- Ubuntu 22.04 and Ubuntu 24.04.
- Python 3.10, 3.11 and 3.12.

The Linux dependency/startup smoke test runs on both Ubuntu releases. These jobs validate the hosted Ubuntu environments only; they do not emulate native Android Termux or a proot filesystem.

## Manual environment validation

Run these commands separately in each environment. Do not reuse a Python virtual environment between native Termux and Ubuntu/proot.

### Native Termux

Install the system dependencies using Termux's package manager:

```bash
pkg update
pkg install python nmap whois dnsutils curl
```

From the ApexRecon checkout:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements-pdf.txt -r requirements-crypto.txt
python3 -m compileall -q apex_storage.py apex_execution.py apex_doctor.py apex_recon_v2.py apex_web.py apex_tls.py apex_fingerprint.py apex_evidence.py apex_findings.py apex_finding_adapters.py apex_engagement.py apex_engagement_cli.py apex_signing.py apex_audit.py apex_audit_backup.py apex_audit_backup_signing.py tests
python3 -m unittest discover -s tests -v
python3 apex_doctor.py
python3 tools/apex_storage_probe.py --parent "$HOME"
python3 tools/apex_storage_probe.py --parent "$PWD"
```

### Ubuntu inside Termux/proot

Inside the Ubuntu environment, install dependencies with Ubuntu's package manager:

```bash
apt-get update
apt-get install -y python3 python3-venv python3-pip nmap whois dnsutils curl iproute2
```

Then run the same venv, compile, test, doctor and storage-probe commands shown above. Run the probe against both `$HOME` and `$PWD`; those may reside on different mounts.

### Desktop Ubuntu

Use the Ubuntu/proot procedure on the desktop Ubuntu installation. Record the exact Ubuntu release and Python version reported by `python3 --version` and `lsb_release -ds`.

## Required evidence

For every manually tested environment, record:

- Environment type: native Termux, Ubuntu/proot, or desktop Ubuntu.
- Android/host OS version where applicable, Linux kernel, CPU architecture, Ubuntu release, and Python version.
- Exact Git commit SHA tested.
- Compile result and complete unit-test count/result.
- `apex_doctor.py` output, including missing optional dependencies.
- Storage probe output for each selected parent directory.
- Any warnings, failures, filesystem-specific behavior, or cleanup residue.

A test is PASS only when the command completes successfully and its output is retained. A skipped environment is NOT RUN, not PASS. Do not infer native Termux or proot compatibility from GitHub Actions.

## Safety and boundaries

- No network target scans or external network requests are part of this phase.
- No package manager command is run automatically by ApexRecon.
- Do not probe a directory containing client evidence if a disposable writable test directory is available.
- The storage probe creates and removes only its own small temporary test tree.
- Do not mix Termux and Ubuntu/proot virtual environments or Python package installations.
- This phase does not perform the controlled power-loss drills required by Phase 2AM and does not establish client readiness.

## Completion criteria

Phase 2AN requires all six Ubuntu/Python CI combinations and both Ubuntu dependency-smoke jobs to pass, plus retained manual evidence from native Termux, Ubuntu/proot and desktop Ubuntu. Any unavailable manual environment remains explicitly NOT RUN and is carried into the final readiness assessment.
