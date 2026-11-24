#!/usr/bin/env python3
"""Offline ApexRecon environment and optional-feature diagnostic.

This command only inspects the local Python environment and executable paths.
It does not install packages, invoke assessment tools, or contact any target.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import platform
import shutil
import sys
from typing import Callable

MIN_PYTHON = (3, 10)

TOOL_CHECKS = (
    ("dig", "DNS lookups", "dnsutils"),
    ("whois", "WHOIS collection", "whois"),
    ("curl", "GeoIP lookup via ipinfo.io", "curl"),
    ("nmap", "External port scan and SMB assessment", "nmap"),
    ("ip", "Automatic local subnet discovery", "iproute2"),
)

PYTHON_CHECKS = (
    ("reportlab", "PDF report export", "requirements-pdf.txt"),
    ("cryptography", "Ed25519 evidence signing", "requirements-crypto.txt"),
)


def collect_diagnostics(
    python_version=None,
    executable_lookup: Callable[[str], str | None] | None = None,
    module_lookup: Callable[[str], bool] | None = None,
    system: str | None = None,
    prefix: str | None = None,
) -> dict:
    """Return deterministic environment diagnostics without running subprocesses."""
    version = tuple(python_version if python_version is not None else sys.version_info[:3])
    executable_lookup = executable_lookup or shutil.which
    module_lookup = module_lookup or (
        lambda name: importlib.util.find_spec(name) is not None
    )
    system = system or platform.system()
    prefix = os.environ.get("PREFIX", "") if prefix is None else prefix
    is_termux = "com.termux" in prefix.lower() or "termux" in prefix.lower()

    tools = {
        name: executable_lookup(name) is not None
        for name, _label, _package in TOOL_CHECKS
    }
    python_packages = {
        name: bool(module_lookup(name))
        for name, _label, _requirements in PYTHON_CHECKS
    }

    return {
        "python": {
            "version": ".".join(str(part) for part in version),
            "supported": version >= MIN_PYTHON,
            "minimum": "3.10",
        },
        "platform": {
            "system": system,
            "termux": is_termux,
        },
        "tools": tools,
        "python_packages": python_packages,
        "capabilities": {
            "http_tls_assessment": True,
            "dns_lookup": tools["dig"],
            "whois_collection": tools["whois"],
            "geoip_lookup": tools["curl"],
            "external_port_scan": tools["nmap"],
            "smb_assessment": tools["nmap"],
            "automatic_subnet_discovery": tools["ip"],
            "pdf_export": python_packages["reportlab"],
            "evidence_signing": python_packages["cryptography"],
        },
    }


def _install_command(report: dict, package: str) -> str:
    if report["platform"]["termux"]:
        return f"pkg install {package}"
    if report["platform"]["system"] == "Linux":
        return f"apt-get install -y {package}"
    return f"Install the {package} system package using your operating system's package manager."


def render_report(report: dict) -> str:
    """Render a concise human-readable diagnostic report."""
    lines = [
        "ApexRecon environment check",
        "===========================",
        f"Python: {report['python']['version']} "
        + ("[SUPPORTED]" if report["python"]["supported"] else "[UNSUPPORTED: requires 3.10+]"),
        f"Platform: {report['platform']['system']}"
        + (" (Termux)" if report["platform"]["termux"] else ""),
        "",
        "Assessment capabilities:",
        "  HTTP/TLS assessment:       AVAILABLE (Python standard library)",
    ]

    for name, label, package in TOOL_CHECKS:
        present = report["tools"][name]
        status = "AVAILABLE" if present else "MISSING"
        lines.append(f"  {label + ':':34} {status}")
        if not present:
            lines.append(f"    Install: {_install_command(report, package)}")

    for name, label, requirements_file in PYTHON_CHECKS:
        present = report["python_packages"][name]
        status = "AVAILABLE" if present else "OPTIONAL / NOT INSTALLED"
        lines.append(f"  {label + ':':34} {status}")
        if not present:
            lines.append(f"    Install: python3 -m pip install -r {requirements_file}")

    lines.extend([
        "",
        "Notes:",
        "- Missing tools affect only the capabilities listed above; HTTP/TLS checks use Python's standard library.",
        "- PDF export and Ed25519 signing are optional features.",
        "- GeoIP lookup sends the resolved target IP to ipinfo.io.",
        "- This check is local-only. It does not install software or contact assessment targets.",
    ])
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Check ApexRecon's local runtime and optional feature dependencies."
    )
    parser.add_argument(
        "--json", action="store_true", help="print machine-readable diagnostic JSON"
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="return status 1 if any external or optional dependency is missing",
    )
    args = parser.parse_args(argv)

    report = collect_diagnostics()
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(render_report(report))

    if not report["python"]["supported"]:
        return 1
    if args.strict:
        if not all(report["tools"].values()) or not all(report["python_packages"].values()):
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
