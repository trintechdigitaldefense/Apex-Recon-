"""Synthetic offline edge-case tests for recovery integrity inspection."""
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from apex_execution import (
    ExecutionJournal,
    MODULES,
    _canonical,
    _hash_event,
    _new_event,
    inspect_execution_journal,
    inspect_execution_recovery,
)


class RecoveryIntegrityEdgeCaseTests(unittest.TestCase):
    def _journal(self, directory, *, with_artifact=True):
        path = Path(directory) / "execution.jsonl"
        execution_id = "phase2av-synthetic"
        journal = ExecutionJournal.create(path, execution_id, [MODULES[0]])
        journal.start_module(MODULES[0])
        if with_artifact:
            journal.finish_module(MODULES[0], "COMPLETED", {
                "status": "COMPLETED",
                "target_scope": {"scope": "synthetic"},
                "findings": [],
                "duration_seconds": 0.01,
            })
        else:
            journal.finish_module(MODULES[0], "COMPLETED")
        return path, journal, execution_id

    def _rewrite_last_event(self, path, **changes):
        events = [json.loads(line) for line in path.read_bytes().splitlines()]
        events[-1].update(changes)
        unsigned = dict(events[-1])
        unsigned.pop("event_hash", None)
        events[-1]["event_hash"] = _hash_event(unsigned)
        path.write_bytes(b"".join(_canonical(item) + b"\n" for item in events))

    def test_duplicate_module_start_with_valid_hash_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path, _journal, execution_id = self._journal(directory, with_artifact=False)
            events = [json.loads(line) for line in path.read_bytes().splitlines()]
            duplicate = _new_event(
                len(events) + 1, execution_id, "MODULE_STARTED",
                events[-1]["event_hash"], module=MODULES[0],
            )
            path.write_bytes(path.read_bytes() + _canonical(duplicate) + b"\n")
            before = path.read_bytes()

            report = inspect_execution_journal(path)

            self.assertFalse(report["valid"])
            self.assertEqual(report["failure_sequence"], 4)
            self.assertEqual(path.read_bytes(), before)

    def test_conflicting_duplicate_module_finish_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path, _journal, execution_id = self._journal(directory, with_artifact=False)
            events = [json.loads(line) for line in path.read_bytes().splitlines()]
            duplicate = _new_event(
                len(events) + 1, execution_id, "MODULE_FINISHED",
                events[-1]["event_hash"], module=MODULES[0], status="FAILED",
            )
            path.write_bytes(path.read_bytes() + _canonical(duplicate) + b"\n")

            report = inspect_execution_journal(path)

            self.assertFalse(report["valid"])
            self.assertEqual(report["failure_sequence"], 4)
            self.assertIn("invalid module finish transition", report["error"])

    def test_parent_traversal_artifact_reference_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path, _journal, _execution_id = self._journal(directory, with_artifact=False)
            self._rewrite_last_event(
                path, artifact_file="../outside.json", artifact_sha256="a" * 64,
            )
            before = path.read_bytes()

            report = inspect_execution_recovery(path)

            self.assertFalse(report["valid"])
            self.assertEqual(report["recovery_status"], "JOURNAL_INVALID")
            self.assertEqual(path.read_bytes(), before)

    def test_windows_separator_artifact_reference_is_rejected_on_posix(self):
        with tempfile.TemporaryDirectory() as directory:
            path, _journal, _execution_id = self._journal(directory, with_artifact=False)
            self._rewrite_last_event(
                path, artifact_file="..\\outside.json", artifact_sha256="a" * 64,
            )
            before = path.read_bytes()

            report = inspect_execution_journal(path)

            self.assertFalse(report["valid"])
            self.assertIn("invalid module artifact reference", report["error"])
            self.assertEqual(path.read_bytes(), before)

    def test_permission_denied_sidecar_is_review_required_and_read_only(self):
        with tempfile.TemporaryDirectory() as directory:
            path, _journal, _execution_id = self._journal(directory)
            artifact = next(Path(directory).glob("*_module_1.json"))
            journal_before = path.read_bytes()
            artifact_before = artifact.read_bytes()
            real_open = os.open

            def guarded_open(candidate, flags, *args, **kwargs):
                if os.fspath(candidate) == str(artifact):
                    raise PermissionError("synthetic permission denial")
                return real_open(candidate, flags, *args, **kwargs)

            with mock.patch("apex_execution.os.open", side_effect=guarded_open):
                report = inspect_execution_recovery(path)

            self.assertEqual(report["recovery_status"], "REVIEW_REQUIRED")
            self.assertEqual(report["modules"][0]["artifact_status"], "INVALID")
            self.assertIn("PermissionError", report["modules"][0]["error"])
            self.assertEqual(path.read_bytes(), journal_before)
            self.assertEqual(artifact.read_bytes(), artifact_before)

    @unittest.skipUnless(hasattr(os, "O_NOFOLLOW"), "O_NOFOLLOW is unavailable")
    def test_symlink_sidecar_is_rejected_without_touching_target(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence_dir = root / "evidence"
            evidence_dir.mkdir()
            path = evidence_dir / "execution.jsonl"
            execution_id = "phase2av-symlink"
            journal = ExecutionJournal.create(path, execution_id, [MODULES[0]])
            journal.start_module(MODULES[0])
            journal.finish_module(MODULES[0], "COMPLETED", {
                "status": "COMPLETED", "target_scope": {"scope": "synthetic"},
                "findings": [], "duration_seconds": 0.01,
            })
            artifact = evidence_dir / "execution_module_1.json"
            target = root / "outside.json"
            target.write_bytes(artifact.read_bytes())
            artifact.unlink()
            artifact.symlink_to(target)
            journal_before = path.read_bytes()
            target_before = target.read_bytes()

            report = inspect_execution_recovery(path)

            self.assertEqual(report["recovery_status"], "REVIEW_REQUIRED")
            self.assertEqual(report["modules"][0]["artifact_status"], "INVALID")
            self.assertTrue(artifact.is_symlink())
            self.assertEqual(path.read_bytes(), journal_before)
            self.assertEqual(target.read_bytes(), target_before)


if __name__ == "__main__":
    unittest.main()
