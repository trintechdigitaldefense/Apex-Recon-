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
            returned = write_exclusive_atomic(destination, b'{"complete":true}\n')

            self.assertEqual(returned, str(destination))
            self.assertEqual(destination.read_bytes(), b'{"complete":true}\n')
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

    def test_rejects_non_bytes_and_invalid_permission_modes(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "assessment.json"
            with self.assertRaises(TypeError):
                write_exclusive_atomic(destination, "not bytes")
            with self.assertRaises(ValueError):
                write_exclusive_atomic(destination, b"data", mode=0o1000)
            self.assertFalse(destination.exists())


if __name__ == "__main__":
    unittest.main()
