"""Offline tests for Phase 2P audit backup and recovery."""
import base64
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import apex_audit_backup
from apex_audit import append_audit_event
from apex_audit_backup import AuditBackupError, create_audit_backup, verify_audit_backup, restore_audit_backup

class AuditBackupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.audit, self.backup, self.checkpoint = root / "audit.jsonl", root / "backup.json", root / "checkpoint.json"
        self.engagement = "12345678-1234-5678-1234-567812345678"
        append_audit_event(self.audit, "ENGAGEMENT_SIGNED", self.engagement, "SUCCESS", "a" * 64)
        append_audit_event(self.audit, "SIGNATURE_VERIFIED", self.engagement, "SUCCESS", "a" * 64)

    def test_create_and_verify(self):
        created = create_audit_backup(self.audit, self.backup, self.checkpoint)
        result = verify_audit_backup(self.backup, self.checkpoint)
        self.assertTrue(result["valid"])
        self.assertEqual(result["entries"], 2)
        self.assertEqual(created["head_hash"], result["head_hash"])

    def test_restore_exact_bytes(self):
        create_audit_backup(self.audit, self.backup, self.checkpoint)
        target = Path(self.temp.name) / "restored.jsonl"
        result = restore_audit_backup(self.backup, self.checkpoint, target)
        self.assertEqual(target.read_bytes(), self.audit.read_bytes())
        self.assertEqual(result["head_hash"], verify_audit_backup(self.backup, self.checkpoint)["head_hash"])

    def test_restore_uses_one_verified_source_snapshot(self):
        create_audit_backup(self.audit, self.backup, self.checkpoint)
        target = Path(self.temp.name) / "snapshot-restored.jsonl"
        original_read = apex_audit_backup._read_regular
        reads = {"backup": 0, "checkpoint": 0}

        def mutate_after_read(path, limit):
            data = original_read(path, limit)
            if Path(path) == self.backup:
                reads["backup"] += 1
                # Change the on-disk file after the verified bytes have been captured.
                self.backup.write_bytes(b'{"replacement":true}\\n')
            elif Path(path) == self.checkpoint:
                reads["checkpoint"] += 1
            return data

        with patch.object(apex_audit_backup, "_read_regular", side_effect=mutate_after_read):
            result = restore_audit_backup(self.backup, self.checkpoint, target)

        self.assertEqual(reads, {"backup": 1, "checkpoint": 1})
        self.assertEqual(target.read_bytes(), self.audit.read_bytes())
        self.assertEqual(result["audit_sha256"], hashlib.sha256(self.audit.read_bytes()).hexdigest())
        self.assertEqual(result["restored_bytes"], len(self.audit.read_bytes()))

    def test_restore_refuses_mismatched_source_snapshot(self):
        create_audit_backup(self.audit, self.backup, self.checkpoint)
        target = Path(self.temp.name) / "snapshot-mismatch.jsonl"
        original_read = apex_audit_backup._read_regular

        def mutate_after_backup_read(path, limit):
            data = original_read(path, limit)
            if Path(path) == self.backup:
                self.backup.write_bytes(b'{"replacement":true}\\n')
            return data

        with patch.object(apex_audit_backup, "_read_regular", side_effect=mutate_after_backup_read):
            result = restore_audit_backup(self.backup, self.checkpoint, target)

        # Restore uses the already verified snapshot, never the changed path contents.
        self.assertEqual(target.read_bytes(), self.audit.read_bytes())
        self.assertNotEqual(target.read_bytes(), self.backup.read_bytes())
        self.assertEqual(result["audit_sha256"], hashlib.sha256(target.read_bytes()).hexdigest())

    def test_tampered_backup_detected(self):
        create_audit_backup(self.audit, self.backup, self.checkpoint)
        data = json.loads(self.backup.read_text())
        raw = base64.b64decode(data["audit_jsonl_base64"]).replace(b"ENGAGEMENT_SIGNED", b"SIGNATURE_REJECTED")
        data["audit_jsonl_base64"] = base64.b64encode(raw).decode("ascii")
        self.backup.write_text(json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n")
        with self.assertRaises(AuditBackupError):
            verify_audit_backup(self.backup, self.checkpoint)

    def test_tampered_checkpoint_detected(self):
        create_audit_backup(self.audit, self.backup, self.checkpoint)
        data = json.loads(self.checkpoint.read_text())
        data["audit_entries"] = 99
        self.checkpoint.write_text(json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n")
        with self.assertRaises(AuditBackupError):
            verify_audit_backup(self.backup, self.checkpoint)

    def test_embedded_chain_corruption_detected_even_with_recomputed_payload_digest(self):
        create_audit_backup(self.audit, self.backup, self.checkpoint)
        data = json.loads(self.backup.read_text())
        raw = base64.b64decode(data["audit_jsonl_base64"]).replace(b"SUCCESS", b"INVALID")
        data["audit_jsonl_base64"] = base64.b64encode(raw).decode("ascii")
        data["audit_sha256"] = hashlib.sha256(raw).hexdigest()
        backup_bytes = json.dumps(data, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        self.backup.write_bytes(backup_bytes)
        checkpoint = json.loads(self.checkpoint.read_text())
        checkpoint["backup_sha256"] = hashlib.sha256(backup_bytes).hexdigest()
        self.checkpoint.write_text(json.dumps(checkpoint, sort_keys=True, separators=(",", ":")) + "\n")
        with self.assertRaises(AuditBackupError):
            verify_audit_backup(self.backup, self.checkpoint)

    def test_restore_refuses_overwrite(self):
        create_audit_backup(self.audit, self.backup, self.checkpoint)
        target = Path(self.temp.name) / "existing.jsonl"
        target.write_text("preserve")
        with self.assertRaises(AuditBackupError):
            restore_audit_backup(self.backup, self.checkpoint, target)
        self.assertEqual(target.read_text(), "preserve")

    def test_backup_creation_refuses_overwrite(self):
        create_audit_backup(self.audit, self.backup, self.checkpoint)
        with self.assertRaises(AuditBackupError):
            create_audit_backup(self.audit, self.backup, Path(self.temp.name) / "second.json")

    def test_posix_permissions(self):
        create_audit_backup(self.audit, self.backup, self.checkpoint)
        if os.name == "posix":
            self.assertEqual(self.backup.stat().st_mode & 0o777, 0o600)
            self.assertEqual(self.checkpoint.stat().st_mode & 0o777, 0o600)

    def test_missing_checkpoint_fails_closed(self):
        create_audit_backup(self.audit, self.backup, self.checkpoint)
        self.checkpoint.unlink()
        with self.assertRaises(AuditBackupError):
            verify_audit_backup(self.backup, self.checkpoint)

    def test_empty_audit_trail_backup_and_restore(self):
        self.audit.unlink()
        create_audit_backup(self.audit, self.backup, self.checkpoint)
        verified = verify_audit_backup(self.backup, self.checkpoint)
        self.assertTrue(verified["valid"])
        self.assertEqual(verified["entries"], 0)
        target = Path(self.temp.name) / "empty-restored.jsonl"
        restored = restore_audit_backup(self.backup, self.checkpoint, target)
        self.assertEqual(target.read_bytes(), b"")
        self.assertEqual(restored["entries"], 0)

    def test_backup_and_checkpoint_paths_must_be_distinct(self):
        with self.assertRaises(AuditBackupError):
            create_audit_backup(self.audit, self.backup, self.backup)
        self.assertFalse(self.backup.exists())

    def test_non_finite_json_metadata_fails_with_backup_error(self):
        create_audit_backup(self.audit, self.backup, self.checkpoint)
        self.backup.write_text('{"invalid":NaN}\n', encoding="utf-8")
        with self.assertRaises(AuditBackupError):
            verify_audit_backup(self.backup, self.checkpoint)

if __name__ == "__main__":
    unittest.main()
