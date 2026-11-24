"""Subprocess-level crash recovery tests using disposable synthetic artifacts.

These tests terminate child interpreters with os._exit so Python cleanup handlers
cannot run. They do not interrupt the host, exhaust storage, or access networks.
"""
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from apex_audit import append_audit_event
from apex_audit_backup import (
    AuditBackupError,
    create_audit_backup,
    verify_audit_backup,
)


REPO_ROOT = Path(__file__).resolve().parents[1]


class ProcessCrashRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="apexrecon-crash-drill-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.audit = self.root / "synthetic-audit.jsonl"
        self.backup = self.root / "synthetic-backup.json"
        self.checkpoint = self.root / "synthetic-checkpoint.json"
        self.engagement = "12345678-1234-5678-1234-567812345678"
        append_audit_event(
            self.audit, "ENGAGEMENT_SIGNED", self.engagement, "SUCCESS", "a" * 64
        )
        append_audit_event(
            self.audit, "SIGNATURE_VERIFIED", self.engagement, "SUCCESS", "a" * 64
        )

    def _run_child(self, source, *args):
        return subprocess.run(
            [sys.executable, "-c", source, *(str(arg) for arg in args)],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )

    def test_process_exit_during_staging_leaves_no_partial_final_artifact(self):
        destination = self.root / "crashed-publication.json"
        child = """
import os
import sys
import apex_storage

def terminate_during_fsync(_fd):
    os._exit(71)

apex_storage.os.fsync = terminate_during_fsync
apex_storage.write_exclusive_atomic(sys.argv[1], b"complete staged bytes")
"""
        result = self._run_child(child, destination)
        self.assertEqual(result.returncode, 71, result.stderr)
        self.assertFalse(destination.exists())
        staging = list(self.root.glob(".apexrecon-tmp-*"))
        self.assertEqual(len(staging), 1)
        self.assertEqual(staging[0].read_bytes(), b"complete staged bytes")

    def test_process_exit_between_backup_and_checkpoint_fails_closed(self):
        child = """
import os
import sys
import apex_audit_backup

real_publish = apex_audit_backup.write_exclusive_atomic
calls = 0

def terminate_before_second_publication(path, data, mode=0o600):
    global calls
    calls += 1
    if calls == 2:
        os._exit(72)
    return real_publish(path, data, mode)

apex_audit_backup.write_exclusive_atomic = terminate_before_second_publication
apex_audit_backup.create_audit_backup(sys.argv[1], sys.argv[2], sys.argv[3])
"""
        result = self._run_child(child, self.audit, self.backup, self.checkpoint)
        self.assertEqual(result.returncode, 72, result.stderr)
        self.assertTrue(self.backup.is_file())
        self.assertFalse(self.checkpoint.exists())
        with self.assertRaises(AuditBackupError):
            verify_audit_backup(self.backup, self.checkpoint)

    def test_process_exit_during_restore_preserves_sources_and_no_final_restore(self):
        create_audit_backup(self.audit, self.backup, self.checkpoint)
        backup_before = hashlib.sha256(self.backup.read_bytes()).hexdigest()
        checkpoint_before = hashlib.sha256(self.checkpoint.read_bytes()).hexdigest()
        destination = self.root / "crashed-restore.jsonl"
        child = """
import os
import sys
import apex_storage
from apex_audit_backup import restore_audit_backup

def terminate_during_staging_fsync(_fd):
    os._exit(73)

apex_storage.os.fsync = terminate_during_staging_fsync
restore_audit_backup(sys.argv[1], sys.argv[2], sys.argv[3])
"""
        result = self._run_child(child, self.backup, self.checkpoint, destination)
        self.assertEqual(result.returncode, 73, result.stderr)
        self.assertFalse(destination.exists())
        self.assertEqual(hashlib.sha256(self.backup.read_bytes()).hexdigest(), backup_before)
        self.assertEqual(
            hashlib.sha256(self.checkpoint.read_bytes()).hexdigest(), checkpoint_before
        )
        self.assertTrue(verify_audit_backup(self.backup, self.checkpoint)["valid"])
        staging = list(self.root.glob(".apexrecon-tmp-*"))
        self.assertEqual(len(staging), 1)


if __name__ == "__main__":
    unittest.main()
