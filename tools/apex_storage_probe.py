#!/usr/bin/env python3
"""Safely probe local filesystem capabilities used by ApexRecon evidence storage.

All test artifacts are created inside a temporary directory beneath the chosen
parent and removed automatically. This tool does not scan networks, install
packages, change permissions on existing files, or consume significant space.
"""
from __future__ import annotations

import argparse
import errno
import json
import os
import platform
import stat
import sys
import tempfile
from pathlib import Path

from apex_storage import write_exclusive_atomic


def _error(exc: BaseException) -> str:
    return f"{type(exc).__name__}: {exc}"


def probe(parent: Path) -> dict:
    parent = parent.expanduser().resolve()
    if not parent.exists() or not parent.is_dir():
        raise ValueError("probe parent must be an existing directory")

    result = {
        "schema_version": "1.0",
        "platform": platform.platform(),
        "python": platform.python_version(),
        "os_name": os.name,
        "parent_directory_name": parent.name or str(parent),
        "hard_links": {"supported": None, "error": None},
        "directory_fsync": {"supported": None, "error": None},
        "private_file_mode_0600": {"supported": None, "observed_mode": None, "error": None},
        "atomic_publication": {"supported": None, "content_verified": False, "error": None},
        "free_bytes_before": None,
        "free_bytes_after": None,
        "network_access": False,
        "existing_files_modified": False,
        "temporary_artifacts_removed": False,
    }

    try:
        result["free_bytes_before"] = (
            os.statvfs(parent).f_bavail * os.statvfs(parent).f_frsize
            if hasattr(os, "statvfs") else None
        )
    except OSError as exc:
        result["free_space_error"] = _error(exc)

    with tempfile.TemporaryDirectory(prefix=".apexrecon-fs-probe-", dir=str(parent)) as temp:
        root = Path(temp)

        source = root / "hardlink-source"
        linked = root / "hardlink-destination"
        try:
            source.write_bytes(b"apexrecon filesystem probe")
            os.link(source, linked)
            result["hard_links"]["supported"] = linked.read_bytes() == source.read_bytes()
        except OSError as exc:
            result["hard_links"]["supported"] = False
            result["hard_links"]["error"] = _error(exc)

        try:
            flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            directory_fd = os.open(str(root), flags)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
            result["directory_fsync"]["supported"] = True
        except OSError as exc:
            result["directory_fsync"]["supported"] = False
            result["directory_fsync"]["error"] = _error(exc)

        artifact = root / "atomic-probe.bin"
        payload = b"ApexRecon local filesystem capability probe\n"
        try:
            write_exclusive_atomic(artifact, payload, mode=0o600)
            result["atomic_publication"]["supported"] = True
            result["atomic_publication"]["content_verified"] = artifact.read_bytes() == payload
            if os.name == "posix":
                observed = stat.S_IMODE(artifact.stat().st_mode)
                result["private_file_mode_0600"]["observed_mode"] = oct(observed)
                result["private_file_mode_0600"]["supported"] = observed == 0o600
            else:
                result["private_file_mode_0600"]["supported"] = None
                result["private_file_mode_0600"]["error"] = "POSIX permission bits are not evaluated on this platform"
        except (OSError, TypeError, ValueError) as exc:
            result["atomic_publication"]["supported"] = False
            result["atomic_publication"]["error"] = _error(exc)
            result["private_file_mode_0600"]["supported"] = False
            result["private_file_mode_0600"]["error"] = "Atomic publisher did not complete"

        # Confirm this probe created only its own temporary directory. The
        # TemporaryDirectory context removes it on normal completion.
        result["temporary_artifacts_removed"] = not root.exists()

    try:
        result["free_bytes_after"] = (
            os.statvfs(parent).f_bavail * os.statvfs(parent).f_frsize
            if hasattr(os, "statvfs") else None
        )
    except OSError as exc:
        result["free_space_after_error"] = _error(exc)

    result["overall_atomic_storage_compatible"] = (
        result["hard_links"]["supported"] is True
        and result["directory_fsync"]["supported"] is True
        and result["atomic_publication"]["supported"] is True
        and result["atomic_publication"]["content_verified"] is True
        and result["temporary_artifacts_removed"] is True
    )
    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Probe ApexRecon local storage capabilities using disposable temporary files."
    )
    parser.add_argument(
        "--parent",
        default=tempfile.gettempdir(),
        help="existing directory on the filesystem to probe (default: system temp directory)",
    )
    args = parser.parse_args()
    try:
        report = probe(Path(args.parent))
    except (OSError, ValueError) as exc:
        print(json.dumps({"probe_error": _error(exc)}, indent=2))
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["overall_atomic_storage_compatible"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
