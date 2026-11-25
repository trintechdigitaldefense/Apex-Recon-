"""Cross-process concurrency tests for the append-only execution journal."""
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from apex_execution import (
    ExecutionJournal,
    MODULES,
    inspect_execution_journal,
    inspect_execution_recovery,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
EXECUTION_ID = "phase2az-concurrent-synthetic"

_CHILD = r"""
import sys
import time
from pathlib import Path
from apex_execution import ExecutionJournal, ExecutionJournalError

journal_path, execution_id, module, ready_path, release_path, operation = sys.argv[1:]
Path(ready_path).write_text("ready", encoding="ascii")
deadline = time.monotonic() + 10
while not Path(release_path).exists():
    if time.monotonic() >= deadline:
        raise SystemExit(3)
    time.sleep(0.005)

journal = ExecutionJournal(journal_path, execution_id)
try:
    if operation == "start":
        journal.start_module(module)
    elif operation == "finish":
        journal.finish_module(module, "COMPLETED", {
            "status": "COMPLETED",
            "target_scope": {"scope": "synthetic-concurrency-test"},
            "findings": [],
            "duration_seconds": 0.01,
        })
    else:
        raise SystemExit("unsupported operation")
except ExecutionJournalError:
    print("REJECTED")
else:
    print("SUCCESS")
"""


class ExecutionJournalConcurrencyTests(unittest.TestCase):
    def _journal(self, directory, modules=None):
        path = Path(directory) / "execution.jsonl"
        selected = modules or [MODULES[0], MODULES[1]]
        journal = ExecutionJournal.create(path, EXECUTION_ID, selected)
        return path, journal

    def _race(self, path, modules, operation):
        release = path.parent / "release"
        ready_paths = [
            path.parent / f"ready-{index}" for index in range(len(modules))
        ]
        processes = [
            subprocess.Popen(
                [
                    sys.executable, "-c", _CHILD, str(path), EXECUTION_ID,
                    module, str(ready_paths[index]), str(release), operation,
                ],
                cwd=str(REPOSITORY_ROOT),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            for index, module in enumerate(modules)
        ]
        deadline = time.monotonic() + 15
        try:
            while not all(item.exists() for item in ready_paths):
                if time.monotonic() >= deadline:
                    self.fail("concurrent journal workers did not reach the start barrier")
                if any(process.poll() is not None for process in processes):
                    self.fail("a concurrent journal worker exited before the start barrier")
                time.sleep(0.005)
            release.write_text("go", encoding="ascii")
            results = [process.communicate(timeout=15) for process in processes]
        finally:
            for process in processes:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)

        outcomes = []
        for process, (stdout, stderr) in zip(processes, results):
            self.assertEqual(process.returncode, 0, stdout + stderr)
            self.assertEqual(stderr, "")
            outcomes.append(stdout.strip())
        return outcomes

    def test_competing_processes_cannot_start_the_same_module_twice(self):
        with tempfile.TemporaryDirectory() as directory:
            path, _journal = self._journal(directory)
            outcomes = self._race(path, [MODULES[0], MODULES[0]], "start")

            self.assertCountEqual(outcomes, ["SUCCESS", "REJECTED"])
            report = inspect_execution_journal(path)
            self.assertTrue(report["valid"])
            self.assertEqual(report["events"], 2)
            self.assertEqual(report["module_states"][MODULES[0]], "STARTED")

    def test_concurrent_starts_for_distinct_modules_preserve_both_events(self):
        with tempfile.TemporaryDirectory() as directory:
            path, _journal = self._journal(directory)
            outcomes = self._race(path, [MODULES[0], MODULES[1]], "start")

            self.assertEqual(outcomes.count("SUCCESS"), 2)
            report = inspect_execution_journal(path)
            self.assertTrue(report["valid"])
            self.assertEqual(report["events"], 3)
            self.assertEqual(report["module_states"][MODULES[0]], "STARTED")
            self.assertEqual(report["module_states"][MODULES[1]], "STARTED")

    def test_competing_processes_cannot_finish_one_module_twice(self):
        with tempfile.TemporaryDirectory() as directory:
            path, journal = self._journal(directory, modules=[MODULES[0]])
            journal.start_module(MODULES[0])

            outcomes = self._race(path, [MODULES[0], MODULES[0]], "finish")

            self.assertCountEqual(outcomes, ["SUCCESS", "REJECTED"])
            report = inspect_execution_journal(path)
            self.assertTrue(report["valid"])
            self.assertEqual(report["module_states"][MODULES[0]], "COMPLETED")
            self.assertEqual(len(report["artifact_refs"]), 0)

            recovery = inspect_execution_recovery(path)
            self.assertEqual(recovery["recovery_status"], "REVIEW_REQUIRED")
            self.assertEqual(recovery["modules"][0]["artifact_status"], "NO_ARTIFACT_RECORDED")


if __name__ == "__main__":
    unittest.main()
