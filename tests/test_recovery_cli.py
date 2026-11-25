"""Tests for the read-only operator recovery inspection CLI."""
import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from apex_execution import ExecutionJournal, MODULES, main


class RecoveryCLITests(unittest.TestCase):
    def _journal(self, directory, *, completed=True):
        path = Path(directory) / "execution.jsonl"
        journal = ExecutionJournal.create(str(path), "test-execution", [MODULES[0]])
        if completed:
            journal.start_module(MODULES[0])
            journal.finish_module(MODULES[0], "COMPLETED", {
                "status": "COMPLETED",
                "target_scope": {"scope": "synthetic fixture"},
                "findings": [],
                "duration_seconds": 0.01,
            })
            journal.finalize()
        else:
            journal.start_module(MODULES[0])
        return path

    def _run(self, path):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main([str(path), "--recovery"])
        return code, output.getvalue()

    def test_cli_reports_verified_artifact_and_does_not_modify_files(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._journal(directory)
            artifact = next(Path(directory).glob("*_module_1.json"))
            journal_before = path.read_bytes()
            artifact_before = artifact.read_bytes()

            code, output = self._run(path)

            self.assertEqual(code, 0)
            self.assertIn("Recovery status: EVIDENCE_VERIFIED", output)
            self.assertIn("artifact=VERIFIED", output)
            self.assertEqual(path.read_bytes(), journal_before)
            self.assertEqual(artifact.read_bytes(), artifact_before)

    def test_cli_returns_review_required_for_interrupted_module(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._journal(directory, completed=False)

            code, output = self._run(path)

            self.assertEqual(code, 2)
            self.assertIn("Recovery status: REVIEW_REQUIRED", output)
            self.assertIn("artifact=INTERRUPTED", output)

    def test_cli_returns_review_required_for_missing_sidecar(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._journal(directory)
            next(Path(directory).glob("*_module_1.json")).unlink()

            code, output = self._run(path)

            self.assertEqual(code, 2)
            self.assertIn("artifact=INVALID", output)
            self.assertIn("FileNotFoundError", output)

    def test_cli_rejects_invalid_journal_without_trusting_prefix(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._journal(directory, completed=False)
            with path.open("ab") as handle:
                handle.write(b'{"incomplete":')
            before = path.read_bytes()

            code, output = self._run(path)

            self.assertEqual(code, 1)
            self.assertIn("Recovery status: JOURNAL_INVALID", output)
            self.assertEqual(path.read_bytes(), before)

    def test_cli_does_not_print_assessment_outcomes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._journal(directory)

            code, output = self._run(path)

            self.assertEqual(code, 0)
            self.assertNotIn("findings", output.lower())
            self.assertNotIn("target_scope", output.lower())


if __name__ == "__main__":
    unittest.main()
