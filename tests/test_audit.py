"""Offline tests for Phase 2O local evidence audit trail."""
import json
import os
import tempfile
import unittest
from pathlib import Path

from apex_audit import (
    AuditTrailError, append_audit_event, verify_audit_trail,
)


class AuditTrailTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "audit.jsonl"
        self.engagement_id = "12345678-1234-5678-1234-567812345678"
        self.fingerprint = "a" * 64

    def test_empty_trail_is_valid(self):
        result = verify_audit_trail(self.path)
        self.assertTrue(result["valid"])
        self.assertEqual(result["entries"], 0)

    def test_append_and_verify_hash_chain(self):
        first = append_audit_event(
            self.path, "ENGAGEMENT_SIGNED", self.engagement_id,
            "SUCCESS", self.fingerprint,
        )
        second = append_audit_event(
            self.path, "SIGNATURE_VERIFIED", self.engagement_id,
            "SUCCESS", self.fingerprint,
        )
        result = verify_audit_trail(self.path)
        self.assertTrue(result["valid"])
        self.assertEqual(result["entries"], 2)
        self.assertEqual(second["previous_hash"], first["entry_hash"])
        self.assertEqual(result["head_hash"], second["entry_hash"])

    def test_tampering_is_detected(self):
        append_audit_event(
            self.path, "SIGNATURE_VERIFIED", self.engagement_id,
            "SUCCESS", self.fingerprint,
        )
        data = self.path.read_text(encoding="utf-8").replace("SUCCESS", "INVALID")
        self.path.write_text(data, encoding="utf-8")
        result = verify_audit_trail(self.path)
        self.assertFalse(result["valid"])
        with self.assertRaises(AuditTrailError):
            append_audit_event(
                self.path, "SIGNATURE_VERIFIED", self.engagement_id,
                "SUCCESS", self.fingerprint,
            )

    def test_reordered_or_missing_sequence_is_rejected(self):
        append_audit_event(
            self.path, "SIGNATURE_VERIFIED", self.engagement_id,
            "SUCCESS", self.fingerprint,
        )
        entry = json.loads(self.path.read_text().strip())
        entry["sequence"] = 9
        unsigned = dict(entry)
        unsigned.pop("entry_hash")
        import hashlib
        entry["entry_hash"] = hashlib.sha256(json.dumps(
            unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            allow_nan=False,
        ).encode()).hexdigest()
        self.path.write_text(json.dumps(
            entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ) + "\n", encoding="utf-8")
        self.assertFalse(verify_audit_trail(self.path)["valid"])

    def test_incomplete_final_event_is_rejected(self):
        append_audit_event(
            self.path, "SIGNATURE_VERIFIED", self.engagement_id,
            "SUCCESS", self.fingerprint,
        )
        self.path.write_bytes(self.path.read_bytes().rstrip(b"\\n"))
        self.assertFalse(verify_audit_trail(self.path)["valid"])

    def test_invalid_event_inputs_rejected(self):
        with self.assertRaises(AuditTrailError):
            append_audit_event(self.path, "UNKNOWN", self.engagement_id, "SUCCESS")
        with self.assertRaises(AuditTrailError):
            append_audit_event(self.path, "SIGNATURE_VERIFIED", "not-a-uuid", "SUCCESS")
        with self.assertRaises(AuditTrailError):
            append_audit_event(self.path, "SIGNATURE_VERIFIED", self.engagement_id, "SUCCESS", "bad")

    def test_file_permissions_are_owner_only(self):
        append_audit_event(
            self.path, "KEYPAIR_CREATED", None, "SUCCESS", self.fingerprint,
        )
        if os.name == "posix":
            self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_symlink_is_rejected(self):
        target = Path(self.temp.name) / "target.jsonl"
        target.write_text("", encoding="utf-8")
        link = Path(self.temp.name) / "link.jsonl"
        link.symlink_to(target)
        with self.assertRaises(AuditTrailError):
            append_audit_event(link, "KEYPAIR_CREATED", None, "SUCCESS")


if __name__ == "__main__":
    unittest.main()
