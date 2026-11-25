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
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# Running this file by path puts tools/ rather than the repository root on sys.path.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from apex_storage import write_exclusive_atomic


def _error(exc: BaseException) -> str:
    return f"{type(exc).__name__}: {exc}"


def _remove_probe_tree(root: Path, max_passes: int = 8) -> tuple[bool, str | None]:
    """Remove only our private probe tree, retrying transient sidecar creation.

    Some compatibility filesystems create hidden helper entries during link or
    unlink operations. A bounded retry lets us clean those entries without
    allowing TemporaryDirectory cleanup to mask the capability report.
    """
    last_error = None
    for _ in range(max_passes):
        try:
            with os.scandir(root) as entries:
                for entry in entries:
                    path = Path(entry.path)
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            child_ok, child_error = _remove_probe_tree(path, max_passes)
                            if not child_ok:
                                last_error = child_error
                        else:
                            path.unlink()
                    except FileNotFoundError:
                        pass
                    except OSError as exc:
                        last_error = _error(exc)
            root.rmdir()
            return True, None
        except FileNotFoundError:
            return True, None
        except OSError as exc:
            last_error = _error(exc)
            if exc.errno not in (errno.ENOTEMPTY, errno.EEXIST):
                break
    return False, last_error or "probe directory remained non-empty after bounded cleanup"




def _probe_advisory_file_locking(lock_path: Path, workspace: Path) -> dict:
    """Verify that an exclusive flock blocks and then releases across processes."""
    result = {
        "supported": False,
        "exclusive_lock_blocks_other_process": False,
        "lock_released_for_waiting_process": False,
        "error": None,
    }
    try:
        import fcntl
    except ImportError as exc:
        result["error"] = _error(exc)
        return result

    blocked_marker = workspace / "lock-blocked"
    release_marker = workspace / "lock-release"
    acquired_marker = workspace / "lock-acquired"
    lock_fd = -1
    child = None
    child_code = r"""
import errno
import fcntl
import os
import sys
import time
from pathlib import Path

lock_path, blocked_path, release_path, acquired_path = sys.argv[1:]
fd = os.open(lock_path, os.O_RDWR)
try:
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        if exc.errno not in (errno.EACCES, errno.EAGAIN):
            raise
        Path(blocked_path).write_text("blocked", encoding="ascii")
    else:
        Path(blocked_path).write_text("unexpectedly-acquired", encoding="ascii")
        fcntl.flock(fd, fcntl.LOCK_UN)
        raise SystemExit(4)

    deadline = time.monotonic() + 8
    while not Path(release_path).exists():
        if time.monotonic() >= deadline:
            raise SystemExit(5)
        time.sleep(0.01)

    fcntl.flock(fd, fcntl.LOCK_EX)
    Path(acquired_path).write_text("acquired", encoding="ascii")
    fcntl.flock(fd, fcntl.LOCK_UN)
finally:
    os.close(fd)
"""
    try:
        lock_fd = os.open(str(lock_path), os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        child = subprocess.Popen(
            [
                sys.executable, "-c", child_code, str(lock_path),
                str(blocked_marker), str(release_marker), str(acquired_marker),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        deadline = time.monotonic() + 8
        while not blocked_marker.exists() and child.poll() is None:
            if time.monotonic() >= deadline:
                raise TimeoutError("child process did not test the held lock")
            time.sleep(0.01)

        if not blocked_marker.exists() or blocked_marker.read_text(encoding="ascii") != "blocked":
            raise RuntimeError("exclusive lock did not block a competing process")
        result["exclusive_lock_blocks_other_process"] = True

        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        release_marker.write_text("release", encoding="ascii")
        stdout, stderr = child.communicate(timeout=8)
        if child.returncode != 0:
            raise RuntimeError(
                f"lock probe child exited {child.returncode}: {(stderr or stdout).strip()[:240]}"
            )
        result["lock_released_for_waiting_process"] = (
            acquired_marker.exists()
            and acquired_marker.read_text(encoding="ascii") == "acquired"
        )
        result["supported"] = (
            result["exclusive_lock_blocks_other_process"]
            and result["lock_released_for_waiting_process"]
        )
        if not result["supported"]:
            result["error"] = "waiting process did not acquire the lock after release"
    except Exception as exc:
        result["error"] = _error(exc)
    finally:
        if child is not None and child.poll() is None:
            child.kill()
            try:
                child.communicate(timeout=3)
            except Exception:
                pass
        if lock_fd >= 0:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            except OSError:
                pass
            os.close(lock_fd)
    return result


def probe(parent: Path) -> dict:
    parent = parent.expanduser().resolve()
    if not parent.exists() or not parent.is_dir():
        raise ValueError("probe parent must be an existing directory")

    result = {
        "schema_version": "1.1",
        "platform": platform.platform(),
        "python": platform.python_version(),
        "os_name": os.name,
        "parent_directory_name": parent.name or str(parent),
        "hard_links": {"supported": None, "cleanup_supported": None, "error": None},
        "directory_fsync": {"supported": None, "error": None},
        "advisory_file_locking": {
            "supported": False,
            "exclusive_lock_blocks_other_process": False,
            "lock_released_for_waiting_process": False,
            "error": None,
        },
        "private_file_mode_0600": {"supported": None, "observed_mode": None, "error": None},
        "atomic_publication": {
            "supported": None, "content_verified": False,
            "cleanup_supported": None, "error": None,
        },
        "free_bytes_before": None,
        "free_bytes_after": None,
        "network_access": False,
        "existing_files_modified": False,
        "temporary_artifacts_removed": False,
    }

    try:
        if hasattr(os, "statvfs"):
            stats = os.statvfs(parent)
            result["free_bytes_before"] = stats.f_bavail * stats.f_frsize
    except OSError as exc:
        result["free_space_error"] = _error(exc)

    root = Path(tempfile.mkdtemp(prefix=".apexrecon-fs-probe-", dir=str(parent)))
    try:
        hardlink_dir = root / "hardlink-check"
        hardlink_dir.mkdir()
        source = hardlink_dir / "source"
        linked = hardlink_dir / "linked"
        try:
            source.write_bytes(b"apexrecon filesystem probe")
            os.link(source, linked)
            result["hard_links"]["supported"] = (
                linked.read_bytes() == source.read_bytes()
            )
            linked.unlink()
            source.unlink()
            leftovers = sorted(item.name for item in hardlink_dir.iterdir())
            result["hard_links"]["cleanup_supported"] = not leftovers
            if leftovers:
                result["hard_links"]["error"] = (
                    "link/unlink left unexpected entries: " + ", ".join(leftovers[:8])
                )
        except (OSError, AttributeError) as exc:
            result["hard_links"]["supported"] = False
            result["hard_links"]["cleanup_supported"] = False
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

        lock_dir = root / "lock-check"
        lock_dir.mkdir()
        result["advisory_file_locking"] = _probe_advisory_file_locking(
            lock_dir / "journal.lock", lock_dir
        )

        atomic_dir = root / "atomic-check"
        atomic_dir.mkdir()
        artifact = atomic_dir / "atomic-probe.bin"
        payload = b"ApexRecon local filesystem capability probe\\n"
        try:
            write_exclusive_atomic(artifact, payload, mode=0o600)
            result["atomic_publication"]["supported"] = True
            result["atomic_publication"]["content_verified"] = (
                artifact.read_bytes() == payload
            )
            if os.name == "posix":
                observed = stat.S_IMODE(artifact.stat().st_mode)
                result["private_file_mode_0600"]["observed_mode"] = oct(observed)
                result["private_file_mode_0600"]["supported"] = observed == 0o600
            else:
                result["private_file_mode_0600"]["supported"] = None
                result["private_file_mode_0600"]["error"] = (
                    "POSIX permission bits are not evaluated on this platform"
                )

            # Some compatibility filesystems expose helper sidecars while a
            # hard-linked inode is still published. They disappear with the
            # final link, so judge cleanup only after removing our own artifact.
            artifact.unlink()
            leftovers = sorted(item.name for item in atomic_dir.iterdir())
            result["atomic_publication"]["cleanup_supported"] = not leftovers
            if leftovers:
                result["atomic_publication"]["error"] = (
                    "entries remained after published artifact removal: "
                    + ", ".join(leftovers[:8])[:300]
                )
        except (OSError, TypeError, ValueError, AttributeError) as exc:
            result["atomic_publication"]["supported"] = False
            result["atomic_publication"]["cleanup_supported"] = False
            result["atomic_publication"]["error"] = _error(exc)
            result["private_file_mode_0600"]["supported"] = False
            result["private_file_mode_0600"]["error"] = (
                "Atomic publisher did not complete"
            )
    finally:
        removed, cleanup_error = _remove_probe_tree(root)
        result["temporary_artifacts_removed"] = removed
        if cleanup_error:
            result["temporary_cleanup_error"] = cleanup_error

    try:
        if hasattr(os, "statvfs"):
            stats = os.statvfs(parent)
            result["free_bytes_after"] = stats.f_bavail * stats.f_frsize
    except OSError as exc:
        result["free_space_after_error"] = _error(exc)

    result["overall_atomic_storage_compatible"] = (
        result["hard_links"]["supported"] is True
        and result["hard_links"]["cleanup_supported"] is True
        and result["directory_fsync"]["supported"] is True
        and result["atomic_publication"]["supported"] is True
        and result["atomic_publication"]["content_verified"] is True
        and result["atomic_publication"]["cleanup_supported"] is True
        and (
            os.name != "posix"
            or result["private_file_mode_0600"]["supported"] is True
        )
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
