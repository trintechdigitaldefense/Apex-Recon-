import json
import tempfile
import unittest
import uuid
from pathlib import Path

from apex_execution import (
    ExecutionJournal,
    ExecutionJournalError,
    MODULES,
    inspect_execution_journal,
)


class ExecutionJournalTests(unittest.TestCase):
    def _create(self, directory, selected=None):
        execution_id = str(uuid.uuid4())
        path = Path(directory) / f"apex_execution_{execution_id}.jsonl"
        journal = ExecutionJournal.create(path, execution_id, selected or [MODULES[0], MODULES[2]])
        return path, journal, execution_id

    def test_new_journal_records_selected_modules_without_target_data(self):
        with tempfile.TemporaryDirectory() as directory:
            path, _journal, execution_id = self._create(directory)
            report = inspect_execution_journal(path)

            self.assertTrue(report["valid"])
            self.assertEqual(report["execution_id"], execution_id)
            self.assertEqual(report["execution_status"], "IN_PROGRESS")
            self.assertEqual(report["module_states"], {
                MODULES[0]: "NOT_STARTED",
                MODULES[2]: "NOT_STARTED",
            })
            raw = path.read_text(encoding="utf-8")
            self.assertNotIn("target", raw.lower())
            self.assertNotIn("findings", raw.lower())

    def test_start_and_finish_transitions_are_durable_and_finalizable(self):
        with tempfile.TemporaryDirectory() as directory:
            path, journal, _ = self._create(directory)
            journal.start_module(MODULES[0])
            journal.finish_module(MODULES[0], "COMPLETED")
            journal.start_module(MODULES[2])
            journal.finish_module(MODULES[2], "PARTIAL")

            before_finalize = inspect_execution_journal(path)
            self.assertEqual(before_finalize["execution_status"], "AWAITING_FINALIZATION")
            self.assertEqual(before_finalize["module_states"][MODULES[0]], "COMPLETED")
            self.assertEqual(before_finalize["module_states"][MODULES[2]], "PARTIAL")

            journal.finalize()
            final = inspect_execution_journal(path)
            self.assertTrue(final["valid"])
            self.assertEqual(final["execution_status"], "FINALIZED")

    def test_unfinished_module_is_reported_incomplete_and_never_auto_resumed(self):
        with tempfile.TemporaryDirectory() as directory:
            path, journal, _ = self._create(directory)
            journal.start_module(MODULES[0])

            recovered = inspect_execution_journal(path)
            self.assertTrue(recovered["valid"])
            self.assertEqual(recovered["execution_status"], "INCOMPLETE")
            self.assertEqual(recovered["module_states"][MODULES[0]], "STARTED")
            with self.assertRaises(ExecutionJournalError):
                journal.start_module(MODULES[0])
            self.assertEqual(inspect_execution_journal(path)["events"], 2)

    def test_declined_module_can_be_recorded_not_run(self):
        with tempfile.TemporaryDirectory() as directory:
            path, journal, _ = self._create(directory, [MODULES[0]])
            journal.start_module(MODULES[0])
            journal.finish_module(MODULES[0], "NOT_RUN")
            journal.finalize()
            report = inspect_execution_journal(path)
            self.assertEqual(report["module_states"][MODULES[0]], "NOT_RUN")
            self.assertEqual(report["execution_status"], "FINALIZED")

    def test_rejects_invalid_transitions_and_unresolved_finalization(self):
        with tempfile.TemporaryDirectory() as directory:
            path, journal, _ = self._create(directory)
            with self.assertRaises(ExecutionJournalError):
                journal.finish_module(MODULES[0], "COMPLETED")
            with self.assertRaises(ExecutionJournalError):
                journal.finalize()
            journal.start_module(MODULES[0])
            with self.assertRaises(ExecutionJournalError):
                journal.finish_module(MODULES[0], "UNKNOWN")
            with self.assertRaises(ExecutionJournalError):
                journal.start_module(MODULES[0])

    def test_torn_final_event_is_invalid_and_append_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path, journal, _ = self._create(directory)
            journal.start_module(MODULES[0])
            with path.open("ab") as handle:
                handle.write(b'{"incomplete":')
            report = inspect_execution_journal(path)
            self.assertFalse(report["valid"])
            self.assertIn("incomplete final event", report["error"])
            with self.assertRaises(ExecutionJournalError):
                journal.finish_module(MODULES[0], "FAILED")

    def test_tampered_event_hash_is_detected(self):
        with tempfile.TemporaryDirectory() as directory:
            path, journal, _ = self._create(directory, [MODULES[0]])
            journal.start_module(MODULES[0])
            events = [json.loads(line) for line in path.read_text().splitlines()]
            events[1]["status"] = "COMPLETED"
            path.write_text("".join(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n"
                                    for event in events), encoding="utf-8")
            report = inspect_execution_journal(path)
            self.assertFalse(report["valid"])
            self.assertIn("hash mismatch", report["error"])

    def test_finalization_failure_is_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            path, journal, _ = self._create(directory, [MODULES[0]])
            journal.start_module(MODULES[0])
            journal.finish_module(MODULES[0], "FAILED")
            journal.fail_finalization()
            report = inspect_execution_journal(path)
            self.assertTrue(report["valid"])
            self.assertEqual(report["execution_status"], "FINALIZATION_FAILED")

    def test_existing_journal_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            path, _journal, _ = self._create(directory, [MODULES[0]])
            original = path.read_bytes()
            with self.assertRaises(ExecutionJournalError):
                ExecutionJournal.create(path, str(uuid.uuid4()), [MODULES[0]])
            self.assertEqual(path.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
