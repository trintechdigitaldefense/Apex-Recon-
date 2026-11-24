"""Offline tests for Phase 2Q signed audit backup checkpoints."""
import json
import os
import tempfile
import unittest
from pathlib import Path

from apex_audit import append_audit_event
from apex_audit_backup import create_audit_backup
from apex_audit_backup_signing import (
    AuditBackupSignatureError,
    sign_audit_backup_checkpoint,
    verify_signed_audit_backup,
)
from apex_signing import generate_ed25519_keypair


class AuditBackupSigningTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.audit = root / "audit.jsonl"
        self.backup = root / "backup.json"
        self.checkpoint = root / "checkpoint.json"
        self.signature = root / "checkpoint.sig.json"
        self.private = root / "private.pem"
        self.public = root / "public.pem"
        self.wrong_public = root / "wrong-public.pem"
        append_audit_event(
            self.audit, "ENGAGEMENT_SIGNED",
            "12345678-1234-5678-1234-567812345678", "SUCCESS", "a" * 64,
        )
        create_audit_backup(self.audit, self.backup, self.checkpoint)
        self.keys = generate_ed25519_keypair(
            self.private, self.public, "correct horse battery"
        )

    def _sign(self):
        return sign_audit_backup_checkpoint(
            self.backup, self.checkpoint, self.private,
            "correct horse battery", self.signature,
        )

    def _verify(self, fingerprint=None, public=None):
        return verify_signed_audit_backup(
            self.backup, self.checkpoint, self.signature,
            public or self.public, fingerprint or self.keys["public_key_sha256"],
        )

    def test_sign_and_verify_checkpoint(self):
        result = self._sign()
        verified = self._verify()
        self.assertTrue(verified["valid"])
        self.assertEqual(verified["entries"], 1)
        self.assertEqual(result["public_key_sha256"], verified["public_key_sha256"])

    def test_signature_file_is_owner_only_and_exclusive(self):
        self._sign()
        if os.name == "posix":
            self.assertEqual(self.signature.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(AuditBackupSignatureError):
            self._sign()

    def test_wrong_trusted_fingerprint_rejected(self):
        self._sign()
        with self.assertRaises(AuditBackupSignatureError):
            self._verify(fingerprint="b" * 64)

    def test_wrong_public_key_rejected(self):
        self._sign()
        generate_ed25519_keypair(
            self.temp.name + "/wrong-private.pem",
            self.wrong_public,
            "another correct battery",
        )
        with self.assertRaises(AuditBackupSignatureError):
            self._verify(public=self.wrong_public)

    def test_checkpoint_tampering_rejected(self):
        self._sign()
        checkpoint = json.loads(self.checkpoint.read_text(encoding="utf-8"))
        checkpoint["audit_entries"] = 900
        self.checkpoint.write_text(
            json.dumps(checkpoint, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        with self.assertRaises(AuditBackupSignatureError):
            self._verify()

    def test_signature_envelope_tampering_rejected(self):
        self._sign()
        envelope = json.loads(self.signature.read_text(encoding="utf-8"))
        envelope["signed_at"] = "2026-01-01T00:00:00Z"
        self.signature.write_text(
            json.dumps(envelope, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        with self.assertRaises(AuditBackupSignatureError):
            self._verify()

    def test_incorrect_private_key_passphrase_rejected(self):
        with self.assertRaises(AuditBackupSignatureError):
            sign_audit_backup_checkpoint(
                self.backup, self.checkpoint, self.private,
                "incorrect passphrase", self.signature,
            )
        self.assertFalse(self.signature.exists())

    def test_private_key_with_permissive_permissions_rejected(self):
        if os.name != "posix":
            self.skipTest("POSIX permission semantics required")
        self.private.chmod(0o644)
        with self.assertRaises(AuditBackupSignatureError):
            self._sign()
        self.assertFalse(self.signature.exists())


if __name__ == "__main__":
    unittest.main()
