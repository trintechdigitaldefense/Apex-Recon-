# ApexRecon — R1 Source Recovery and Stabilization

**TrinTech Digital Defense** · Authorized network and OSINT assessment framework

![Python](https://img.shields.io/badge/Python-3.9%2B-blue)

## Current branch status

This branch restores the last complete executable implementation found in Git history (the v2.0 source at commit `086eb48`) and applies initial R1 stabilization changes.

**Important recovery finding:** the v2.1.0 source committed to `main` is incomplete. Its Python entry point ends after the SMB parser and prints a loader-placeholder message. The repository history inspected for R1 did not contain the complete v2.1.0 implementation. This branch therefore does not claim that the v2.1 web scanner, SMTP report delivery, or v2.1 configuration system are operational. Those features must be reconstructed and tested in a later, separate change.

## Available modules in this recovered baseline

### 1. External OSINT
- DNS lookups using `dig`
- WHOIS collection
- IP geolocation via ipinfo.io
- Quick external port and banner scan using `nmap`

### 2. Local network SMB auditor
- Local subnet discovery using actual route/interface prefix information
- SMB host and share enumeration using Nmap scripts
- SMB signing and selected legacy SMB vulnerability checks
- Structured host findings and HTML reporting

## R1 stabilization changes

- Restore the complete executable v2.0 baseline rather than retain the truncated loader.
- Add input validation for hostnames, IP addresses, and bounded IP/CIDR ranges.
- Require explicit confirmation of written authorization for each scan scope.
- Keep subprocess execution argument-list based, disable shell execution, close stdin, and enforce timeouts.
- Replace guessed `/24` subnet construction with actual route/interface prefix parsing.
- Escape untrusted scan data before inserting it into HTML reports.
- Reduce the default Nmap timing template from `-T4` to `-T3`.
- Add automated unit tests and GitHub Actions validation.

## Requirements

- Python 3.9 or newer
- Linux or Termux environment
- `nmap`, `whois`, `dig` (dnsutils), and `curl`

On Debian/Ubuntu/Termux Ubuntu:

```bash
apt-get update
apt-get install -y python3 nmap whois dnsutils curl
```

## Run

```bash
git clone https://github.com/trintechdigitaldefense/Apex-Recon-.git
cd Apex-Recon-
python3 apex_recon_v2.py
```

## Test without scanning

The automated test suite uses mocked command execution and synthetic Nmap output. It does not scan external hosts.

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q apex_recon_v2.py tests
```

## Authorization and safe use

ApexRecon is for assets you own or are explicitly authorized to assess. Before either module starts network activity, the operator must confirm written authorization for the exact target or range. SMB targets must be IP addresses or CIDR ranges containing no more than 4,096 addresses. Do not use this tool against third-party systems without permission.

## Known limitations — not client-release ready

- The recovered branch is a stabilization baseline, not a completed v2.1 replacement.
- The v2.1 Web Application Scanner is not included in this recovered source.
- The current report is HTML; PDF export is not implemented in this baseline.
- The legacy SMB vulnerability scripts are indicators and require independent verification before client reporting.
- No continuous monitoring, multi-client tenancy, scheduling, or unattended 24-hour operation is provided.
- CI and unit tests validate local logic only; they do not establish safe operation across every Linux/Termux device or prove scan accuracy.

## Next R1 gates

1. Pass syntax and unit-test workflows on the same commit.
2. Review the complete diff for scope enforcement, command execution, report escaping, and data handling.
3. Validate installation and interactive use in controlled Linux and Termux environments.
4. Submit the pull request for maintainer review.

No merge, production release, or client deployment is authorized by this branch.
