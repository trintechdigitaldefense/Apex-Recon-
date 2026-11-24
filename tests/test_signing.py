"""Offline tests for Phase 2N detached Ed25519 evidence signatures."""
import json
import os
import tempfile
import unittest
from pathlib import Path

from apex_engagement import MODULES, EngagementError, build_engagement_record
from apex_signing import (
    export_signature_envelope,
    generate_ed25519_keypair,
    sign_engagement_record,
    verify_engagement_signature,
)

PASSPHRASE = "correct horse battery staple"


def sample_record():
    modules = [{
        "module": name,
        "status": "NOT_RUN",
        "target_scope": {"target": "example.test"},
        "findings": [],
        "duration_seconds": 0,
        "limitations": ["Synthetic test fixture; no scan was run."],
    } for name in sorted(MODULES)]
    return build_engagement_record({"target": "example.test"}, modules)


class EvidenceSigningTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.private_path = self.root / "private.pem"
        self.public_path = self.root / "public.pem"
        self.keys = generate_ed25519_keypair(
            self.private_path, self.public_path, PASSPHRASE
        )
        self.record = sample_record()

    def test_round_trip_signature_verifies(self):
        envelope = sign_engagement_record(
            self.record, self.private_path, PASSPHRASE
        )
        self.assertTrue(verify_engagement_signature(
            self.record, envelope, self.public_path
        ))
        self.assertEqual(envelope["algorithm"], "Ed25519")
        self.assertEqual(
            envelope["engagement_id"], self.record["engagement"]["id"]
        )

    def test_signature_rejects_tampered_record(self):
        envelope = sign_engagement_record(
            self.record, self.private_path, PASSPHRASE
        )
        tampered = json.loads(json.dumps(self.record))
        tampered["engagement"]["target_scope"]["target"] = "changed.example"
        self.assertFalse(verify_engagement_signature(
            tampered, envelope, self.public_path
        ))

    def test_signature_rejects_wrong_public_key(self):
        other_private = self.root / "other-private.pem"
        other_public = self.root / "other-public.pem"
        generate_ed25519_keypair(other_private, other_public, PASSPHRASE)
        envelope = sign_engagement_record(
            self.record, self.private_path, PASSPHRASE
        )
        self.assertFalse(verify_engagement_signature(
            self.record, envelope, other_public
        ))

    def test_signature_rejects_modified_envelope(self):
        envelope = sign_engagement_record(
            self.record, self.private_path, PASSPHRASE
        )
        envelope["signature"] = "not-base64!"
        self.assertFalse(verify_engagement_signature(
            self.record, envelope, self.public_path
        ))

    def test_signing_rejects_invalid_record(self):
        tampered = json.loads(json.dumps(self.record))
        tampered["engagement"]["target_scope"]["target"] = "changed.example"
        with self.assertRaises(EngagementError):
            sign_engagement_record(tampered, self.private_path, PASSPHRASE)

    def test_wrong_passphrase_is_rejected(self):
        with self.assertRaises(EngagementError):
            sign_engagement_record(self.record, self.private_path, "wrong passphrase")

    def test_key_generation_requires_strong_passphrase(self):
        with self.assertRaises(EngagementError):
            generate_ed25519_keypair(
                self.root / "short-private.pem",
                self.root / "short-public.pem",
                "short",
            )

    def test_key_files_are_not_overwritten_and_private_key_is_owner_only(self):
        with self.assertRaises(FileExistsError):
            generate_ed25519_keypair(
                self.private_path, self.root / "new-public.pem", PASSPHRASE
            )
        if os.name == "posix":
            self.assertEqual(self.private_path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(self.public_path.stat().st_mode & 0o777, 0o600)

    def test_signature_export_is_exclusive_and_owner_only(self):
        envelope = sign_engagement_record(
            self.record, self.private_path, PASSPHRASE
        )
        output = self.root / "record.sig.json"
        export_signature_envelope(envelope, output)
        self.assertEqual(json.loads(output.read_text())["algorithm"], "Ed25519")
        with self.assertRaises(FileExistsError):
            export_signature_envelope(envelope, output)
        if os.name == "posix":
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
