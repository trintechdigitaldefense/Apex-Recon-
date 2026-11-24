"""Offline tests for Phase 2O local evidence audit trail."""
import hashlib
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
        self.path.write_bytes(self.path.read_bytes().rstrip(b"\n"))
        self.assertFalse(verify_audit_trail(self.path)["valid"])

    def test_duplicate_record_is_reported_explicitly(self):
        append_audit_event(
            self.path, "SIGNATURE_VERIFIED", self.engagement_id,
            "SUCCESS", self.fingerprint,
        )
        original_record = self.path.read_bytes()
        self.path.write_bytes(original_record + original_record)
        result = verify_audit_trail(self.path)
        self.assertFalse(result["valid"])
        self.assertEqual(result["failure_code"], "duplicate_event")
        self.assertEqual(result["entries"], 1)
        self.assertEqual(result["failure_sequence"], 2)
        self.assertEqual(result["verified_bytes"], len(original_record))
        with self.assertRaises(AuditTrailError):
            append_audit_event(
                self.path, "SIGNATURE_VERIFIED", self.engagement_id,
                "SUCCESS", self.fingerprint,
            )

    def test_incomplete_tail_reports_verified_prefix_without_modifying_source(self):
        append_audit_event(
            self.path, "ENGAGEMENT_SIGNED", self.engagement_id,
            "SUCCESS", self.fingerprint,
        )
        verified_prefix = self.path.read_bytes()
        original = verified_prefix + b'{"schema_version":"1.0","sequence":2'
        self.path.write_bytes(original)
        result = verify_audit_trail(self.path)
        self.assertFalse(result["valid"])
        self.assertEqual(result["failure_code"], "incomplete_final_event")
        self.assertEqual(result["entries"], 1)
        self.assertEqual(result["failure_sequence"], 2)
        self.assertEqual(result["verified_bytes"], len(verified_prefix))
        self.assertEqual(
            result["verified_prefix_sha256"],
            hashlib.sha256(verified_prefix).hexdigest(),
        )
        self.assertEqual(result["original_sha256"], hashlib.sha256(original).hexdigest())
        self.assertEqual(self.path.read_bytes(), original)

    def test_corrupt_second_event_reports_first_verified_prefix(self):
        append_audit_event(
            self.path, "ENGAGEMENT_SIGNED", self.engagement_id,
            "SUCCESS", self.fingerprint,
        )
        append_audit_event(
            self.path, "SIGNATURE_VERIFIED", self.engagement_id,
            "SUCCESS", self.fingerprint,
        )
        records = self.path.read_bytes().splitlines(keepends=True)
        records[1] = records[1].replace(b'"SUCCESS"', b'"INVALID"')
        self.path.write_bytes(b"".join(records))
        result = verify_audit_trail(self.path)
        self.assertFalse(result["valid"])
        self.assertEqual(result["failure_code"], "event_hash_mismatch")
        self.assertEqual(result["entries"], 1)
        self.assertEqual(result["failure_sequence"], 2)
        self.assertEqual(result["verified_bytes"], len(records[0]))

    def test_valid_report_includes_original_and_verified_prefix_digests(self):
        append_audit_event(
            self.path, "KEYPAIR_CREATED", None, "SUCCESS", self.fingerprint,
        )
        data = self.path.read_bytes()
        result = verify_audit_trail(self.path)
        self.assertTrue(result["valid"])
        self.assertEqual(result["verified_bytes"], len(data))
        self.assertEqual(result["verified_prefix_sha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual(result["original_sha256"], hashlib.sha256(data).hexdigest())

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
