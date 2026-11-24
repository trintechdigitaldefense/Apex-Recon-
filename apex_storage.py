"""Crash-safe, create-only publication of local evidence artifacts.

Files are staged in the destination directory, flushed, then published with
an atomic hard link. The final path is never visible with partially written
contents and an existing destination is never replaced.
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path


def write_exclusive_atomic(
    path: str | os.PathLike[str],
    data: bytes,
    mode: int = 0o600,
) -> str:
    """Publish complete bytes at path without overwriting an existing file.

    A temporary file is created in the destination directory so publication
    stays on one filesystem. os.link provides atomic create-only publication:
    it fails if the destination already exists. The temporary file is removed
    after publication. A process interruption before the link can leave a
    hidden staging file, but cannot leave a partial final artifact.
    """
    if not isinstance(data, bytes):
        raise TypeError("artifact data must be bytes")
    if isinstance(mode, bool) or not isinstance(mode, int) or mode < 0 or mode > 0o777:
        raise ValueError("artifact mode must be an integer permission mode")

    destination = Path(path)
    parent = destination.parent
    if not parent.is_dir():
        raise FileNotFoundError(f"artifact directory does not exist: {parent}")

    fd, temporary_name = tempfile.mkstemp(
        prefix=".apexrecon-tmp-",
        dir=str(parent),
    )
    temporary_path = Path(temporary_name)
    published_info = None
    try:
        if os.name == "posix":
            os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as handle:
            fd = -1
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())

        # Same-directory hard-link publication is atomic and create-only.
        # An existing file or symlink is never overwritten.
        os.link(temporary_path, destination)
        published_info = temporary_path.stat()
        temporary_path.unlink()

        # Persist the directory entry where the platform supports directory
        # fsync. File contents have already been fsynced before publication.
        if os.name == "posix":
            directory_fd = os.open(
                str(parent),
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
            )
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        return str(destination)
    except Exception:
        if fd >= 0:
            os.close(fd)
        # If publication succeeded but directory sync failed, remove only the
        # exact inode we published; never unlink a path another process swapped.
        if published_info is not None:
            try:
                destination_info = destination.stat()
                if (published_info.st_dev, published_info.st_ino) == (
                    destination_info.st_dev, destination_info.st_ino
                ):
                    destination.unlink()
            except OSError:
                pass
        raise
    finally:
        try:
            temporary_path.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            pass
