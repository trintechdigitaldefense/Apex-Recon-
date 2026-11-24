import errno
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from apex_storage import write_exclusive_atomic


class AtomicArtifactStorageTests(unittest.TestCase):
    def test_publishes_complete_private_file_and_cleans_staging_file(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "assessment.json"
            returned = write_exclusive_atomic(destination, b'{"complete":true}\\n')

            self.assertEqual(returned, str(destination))
            self.assertEqual(destination.read_bytes(), b'{"complete":true}\\n')
            self.assertEqual(list(Path(directory).glob(".apexrecon-tmp-*")), [])
            if os.name == "posix":
                self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)

    def test_existing_destination_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "assessment.json"
            destination.write_bytes(b"original")

            with self.assertRaises(FileExistsError):
                write_exclusive_atomic(destination, b"replacement")

            self.assertEqual(destination.read_bytes(), b"original")
            self.assertEqual(list(Path(directory).glob(".apexrecon-tmp-*")), [])

    def test_staging_fsync_failure_does_not_publish_final_file(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "assessment.json"
            with patch("apex_storage.os.fsync", side_effect=OSError("simulated storage failure")):
                with self.assertRaisesRegex(OSError, "simulated storage failure"):
                    write_exclusive_atomic(destination, b"must-not-appear")

            self.assertFalse(destination.exists())
            self.assertEqual(list(Path(directory).glob(".apexrecon-tmp-*")), [])

    def test_atomic_publish_failure_cleans_staging_file(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "assessment.json"
            with patch("apex_storage.os.link", side_effect=OSError("simulated publish failure")):
                with self.assertRaisesRegex(OSError, "simulated publish failure"):
                    write_exclusive_atomic(destination, b"must-not-appear")

            self.assertFalse(destination.exists())
            self.assertEqual(list(Path(directory).glob(".apexrecon-tmp-*")), [])

    def test_unsupported_hard_links_fail_closed_without_direct_write_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "assessment.json"
            unsupported = OSError(errno.EOPNOTSUPP, "hard links unsupported")
            with patch("apex_storage.os.link", side_effect=unsupported):
                with self.assertRaises(OSError):
                    write_exclusive_atomic(destination, b"must-not-appear")

            self.assertFalse(destination.exists())
            self.assertEqual(list(Path(directory).glob(".apexrecon-tmp-*")), [])

    def test_symlink_destination_is_not_followed_or_overwritten(self):
        if not hasattr(os, "symlink"):
            self.skipTest("symlinks are unavailable on this platform")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            protected = root / "protected.txt"
            destination = root / "assessment.json"
            protected.write_bytes(b"protected")
            try:
                destination.symlink_to(protected)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"cannot create symlink in this environment: {exc}")

            with self.assertRaises(FileExistsError):
                write_exclusive_atomic(destination, b"replacement")

            self.assertTrue(destination.is_symlink())
            self.assertEqual(protected.read_bytes(), b"protected")
            self.assertEqual(list(root.glob(".apexrecon-tmp-*")), [])

    def test_directory_fsync_failure_removes_our_published_inode(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "assessment.json"
            with patch("apex_storage.os.fsync", side_effect=[None, OSError("directory sync failure")]):
                with self.assertRaisesRegex(OSError, "directory sync failure"):
                    write_exclusive_atomic(destination, b"must-not-remain")

            self.assertFalse(destination.exists())
            self.assertEqual(list(Path(directory).glob(".apexrecon-tmp-*")), [])

    def test_directory_fsync_failure_does_not_remove_replacement_inode(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "assessment.json"
            real_fsync = os.fsync
            calls = {"count": 0}

            def replace_then_fail(fd):
                calls["count"] += 1
                if calls["count"] == 1:
                    return real_fsync(fd)
                destination.unlink()
                destination.write_bytes(b"replacement from another process")
                raise OSError("directory sync failure")

            with patch("apex_storage.os.fsync", side_effect=replace_then_fail):
                with self.assertRaisesRegex(OSError, "directory sync failure"):
                    write_exclusive_atomic(destination, b"our original publication")

            self.assertEqual(destination.read_bytes(), b"replacement from another process")
            self.assertEqual(list(Path(directory).glob(".apexrecon-tmp-*")), [])

    def test_rejects_non_bytes_and_invalid_permission_modes(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "assessment.json"
            with self.assertRaises(TypeError):
                write_exclusive_atomic(destination, "not bytes")
            for mode in (True, -1, 0o1000):
                with self.subTest(mode=mode):
                    with self.assertRaises(ValueError):
                        write_exclusive_atomic(destination, b"data", mode=mode)
            self.assertFalse(destination.exists())


if __name__ == "__main__":
    unittest.main()
