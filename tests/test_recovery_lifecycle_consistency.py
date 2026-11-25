"""Recovery lifecycle consistency tests using synthetic offline artifacts only."""
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from apex_execution import (
    ExecutionJournal,
    ExecutionJournalError,
    MODULES,
    inspect_execution_journal,
    inspect_execution_recovery,
)


class RecoveryLifecycleConsistencyTests(unittest.TestCase):
    def _journal(self, directory):
        path = Path(directory) / "execution.jsonl"
        journal = ExecutionJournal.create(path, "phase2ay-synthetic", [MODULES[0]])
        return path, journal

    def _make_outcome(self):
        return {
            "status": "COMPLETED",
            "target_scope": {"scope": "synthetic"},
            "findings": [],
            "duration_seconds": 0.01,
        }

    def test_lifecycle_status_progression_is_consistent(self):
        with tempfile.TemporaryDirectory() as directory:
            path, journal = self._journal(directory)
            self.assertEqual(inspect_execution_journal(path)["execution_status"], "READY")

            journal.start_module(MODULES[0])
            self.assertEqual(inspect_execution_journal(path)["execution_status"], "INCOMPLETE")

            journal.finish_module(MODULES[0], "COMPLETED", self._make_outcome())
            self.assertEqual(
                inspect_execution_journal(path)["execution_status"],
                "AWAITING_FINALIZATION",
            )

            journal.finalize()
            report = inspect_execution_journal(path)
            self.assertTrue(report["valid"])
            self.assertEqual(report["execution_status"], "FINALIZED")
            self.assertEqual(report["module_states"], {MODULES[0]: "COMPLETED"})

    def test_finalization_is_rejected_while_module_is_unresolved(self):
        with tempfile.TemporaryDirectory() as directory:
            _path, journal = self._journal(directory)
            journal.start_module(MODULES[0])
            with self.assertRaises(ExecutionJournalError):
                journal.finalize()

    def test_module_finish_is_rejected_without_a_start_event(self):
        with tempfile.TemporaryDirectory() as directory:
            _path, journal = self._journal(directory)
            with self.assertRaises(ExecutionJournalError):
                journal.finish_module(MODULES[0], "COMPLETED", self._make_outcome())

    def test_crash_window_after_sidecar_publication_remains_untrusted(self):
        with tempfile.TemporaryDirectory() as directory:
            path, journal = self._journal(directory)
            journal.start_module(MODULES[0])
            journal_before = path.read_bytes()

            # Simulate interruption after atomic sidecar publication but before
            # the MODULE_FINISHED journal event can be appended.
            with mock.patch.object(
                journal, "_append",
                side_effect=ExecutionJournalError("synthetic append interruption"),
            ):
                with self.assertRaises(ExecutionJournalError):
                    journal.finish_module(MODULES[0], "COMPLETED", self._make_outcome())

            orphan = Path(directory) / "execution_module_1.json"
            self.assertTrue(orphan.is_file())
            orphan_before = orphan.read_bytes()

            first = inspect_execution_recovery(path)
            second = inspect_execution_recovery(path)

            self.assertEqual(first, second)
            self.assertEqual(first["recovery_status"], "REVIEW_REQUIRED")
            module = first["modules"][0]
            self.assertEqual(module["journal_state"], "STARTED")
            self.assertEqual(module["artifact_status"], "INTERRUPTED")
            self.assertEqual(module["unreferenced_artifact"], {
                "status": "PRESENT",
                "file": orphan.name,
                "kind": "REGULAR_FILE",
            })
            self.assertEqual(path.read_bytes(), journal_before)
            self.assertEqual(orphan.read_bytes(), orphan_before)

    def test_repeated_recovery_inspection_is_deterministic_and_read_only(self):
        with tempfile.TemporaryDirectory() as directory:
            path, journal = self._journal(directory)
            journal.start_module(MODULES[0])
            orphan = Path(directory) / "execution_module_1.json"
            orphan.write_bytes(b"synthetic bytes; never trusted evidence")
            journal_before = path.read_bytes()
            orphan_before = orphan.read_bytes()

            first = inspect_execution_recovery(path)
            second = inspect_execution_recovery(path)

            self.assertEqual(first, second)
            self.assertEqual(first["recovery_status"], "REVIEW_REQUIRED")
            self.assertEqual(path.read_bytes(), journal_before)
            self.assertEqual(orphan.read_bytes(), orphan_before)


if __name__ == "__main__":
    unittest.main()
