#!/usr/bin/env python3
"""Offline ApexRecon environment and operational-readiness diagnostic.

This command inspects the local Python environment, required project files,
and the ability to create a temporary file in the project directory. It does
not install packages, invoke assessment tools, or contact any target.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import platform
import shutil
import sys
import tempfile
from pathlib import Path
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

REQUIRED_PROJECT_FILES = (
    "apex_recon_v2.py",
    "apex_web.py",
    "apex_tls.py",
    "apex_doctor.py",
)


def inspect_project(
    project_root: str | os.PathLike[str] | None = None,
    artifact_directory: str | os.PathLike[str] | None = None,
    write_probe: bool = True,
) -> dict:
    """Check required source files and actual artifact-directory write access."""
    root = Path(project_root).resolve() if project_root is not None else Path(__file__).resolve().parent
    output_dir = Path(artifact_directory).resolve() if artifact_directory is not None else Path.cwd().resolve()
    files = {name: (root / name).is_file() for name in REQUIRED_PROJECT_FILES}
    writable = False
    write_error = None
    if write_probe and output_dir.is_dir():
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb",
                prefix=".apexrecon-write-check-",
                dir=str(output_dir),
                delete=True,
            ):
                pass
            writable = True
        except OSError as exc:
            write_error = type(exc).__name__
    return {
        "root": str(root),
        "artifact_directory": str(output_dir),
        "required_files": files,
        "complete": all(files.values()),
        "writable": writable,
        "write_error": write_error,
    }


def collect_diagnostics(
    python_version=None,
    executable_lookup: Callable[[str], str | None] | None = None,
    module_lookup: Callable[[str], bool] | None = None,
    system: str | None = None,
    prefix: str | None = None,
    project_root: str | os.PathLike[str] | None = None,
    artifact_directory: str | os.PathLike[str] | None = None,
    write_probe: bool = True,
    python_prefix: str | None = None,
    python_base_prefix: str | None = None,
) -> dict:
    """Return local diagnostics without running subprocesses or network calls."""
    version = tuple(python_version if python_version is not None else sys.version_info[:3])
    executable_lookup = executable_lookup or shutil.which
    module_lookup = module_lookup or (
        lambda name: importlib.util.find_spec(name) is not None
    )
    system = system or platform.system()
    prefix = os.environ.get("PREFIX", "") if prefix is None else prefix
    is_termux = "com.termux" in prefix.lower() or "termux" in prefix.lower()
    active_prefix = sys.prefix if python_prefix is None else python_prefix
    base_prefix = sys.base_prefix if python_base_prefix is None else python_base_prefix

    tools = {
        name: executable_lookup(name) is not None
        for name, _label, _package in TOOL_CHECKS
    }
    python_packages = {
        name: bool(module_lookup(name))
        for name, _label, _requirements in PYTHON_CHECKS
    }
    environment = {
        "executable": sys.executable,
        "virtual_environment": active_prefix != base_prefix,
        "pip_available": bool(module_lookup("pip")),
        "venv_available": bool(module_lookup("venv")),
    }
    project = inspect_project(project_root, artifact_directory, write_probe)

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
        "environment": environment,
        "project": project,
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
            "project_layout": project["complete"],
            "artifact_directory_writable": project["writable"],
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
    project = report.get("project", {})
    environment = report.get("environment", {})
    lines = [
        "ApexRecon environment and readiness check",
        "=========================================",
        f"Python: {report['python']['version']} "
        + ("[SUPPORTED]" if report["python"]["supported"] else "[UNSUPPORTED: requires 3.10+]"),
        f"Platform: {report['platform']['system']}"
        + (" (Termux)" if report["platform"]["termux"] else ""),
        "",
        "Python environment:",
        f"  Interpreter: {environment.get('executable', sys.executable)}",
        "  Virtual environment: "
        + ("ACTIVE" if environment.get("virtual_environment") else "NOT ACTIVE"),
        "  pip: " + ("AVAILABLE" if environment.get("pip_available") else "MISSING"),
        "  venv module: " + ("AVAILABLE" if environment.get("venv_available") else "MISSING"),
        "",
        "Project and report storage:",
        f"  Project directory: {project.get('root', '[not checked]')}",
        "  Required core files: " + ("PRESENT" if project.get("complete") else "MISSING"),
        f"  Artifact output directory: {project.get('artifact_directory', '[not checked]')}",
        "  Artifact directory write test: " + ("WRITABLE" if project.get("writable") else "FAILED"),
    ]
    if not project.get("complete"):
        missing = [name for name, present in project.get("required_files", {}).items() if not present]
        lines.append("    Missing: " + (", ".join(missing) if missing else "project layout could not be verified"))
    if not project.get("writable") and project.get("write_error"):
        lines.append(f"    Write test error: {project['write_error']}")

    lines.extend(["", "Assessment capabilities:",
                  "  HTTP/TLS assessment:       AVAILABLE (Python standard library)"])
    for name, label, package in TOOL_CHECKS:
        present = report["tools"][name]
        lines.append(f"  {label + ':':34} {'AVAILABLE' if present else 'MISSING'}")
        if not present:
            lines.append(f"    Install: {_install_command(report, package)}")

    for name, label, requirements_file in PYTHON_CHECKS:
        present = report["python_packages"][name]
        lines.append(f"  {label + ':':34} {'AVAILABLE' if present else 'OPTIONAL / NOT INSTALLED'}")
        if not present:
            lines.append(f"    Install: python3 -m pip install -r {requirements_file}")

    if not environment.get("virtual_environment"):
        lines.extend([
            "",
            "Recommended isolated Python setup (from the project directory):",
            "  python3 -m venv .venv",
            "  source .venv/bin/activate",
            "  python -m pip install --upgrade pip",
            "  python -m pip install -r requirements-pdf.txt -r requirements-crypto.txt",
        ])
    if not environment.get("pip_available"):
        lines.append("  pip is unavailable in this interpreter; repair/install pip for this same Python environment before installing optional packages.")

    lines.extend([
        "",
        "Notes:",
        "- Missing tools affect only the capabilities listed above; HTTP/TLS checks use Python's standard library.",
        "- PDF export and Ed25519 signing are optional features.",
        "- GeoIP lookup sends the resolved target IP to ipinfo.io.",
        "- Run the application with the same Python interpreter used for dependency installation.",
        "- Keep native Termux and Ubuntu-proot Python packages separate; do not mix their environments.",
        "- This check creates and removes one temporary file to verify local write access. It does not install software or contact assessment targets.",
    ])
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Check ApexRecon's local runtime, project files, and report-directory readiness."
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
    project = report.get("project", {})
    if project and (not project.get("complete") or not project.get("writable")):
        return 1
    if args.strict:
        if not all(report["tools"].values()) or not all(report["python_packages"].values()):
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
