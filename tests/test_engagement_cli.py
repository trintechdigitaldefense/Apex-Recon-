"""Offline tests for Phase 2J unified engagement CLI helpers."""
import unittest

from apex_engagement_cli import (MODULE_NAMES, assemble_module_results, parse_module_selection,
                                 run_selected_modules)
from apex_engagement import build_engagement_record, verify_engagement_record


class ModuleSelectionTests(unittest.TestCase):
    def test_all_selects_every_module(self):
        self.assertEqual(parse_module_selection("ALL"), set(MODULE_NAMES))
        self.assertEqual(parse_module_selection("all"), set(MODULE_NAMES))

    def test_comma_selection_is_order_independent(self):
        self.assertEqual(parse_module_selection("4, 2"), {MODULE_NAMES[1], MODULE_NAMES[3]})

    def test_rejects_empty_invalid_out_of_range_and_duplicates(self):
        for value in ("", "0", "5", "1,x", "1,1"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_module_selection(value)


class ModuleAssemblyTests(unittest.TestCase):
    def test_unselected_and_declined_modules_are_explicit_not_run(self):
        selected = {MODULE_NAMES[0], MODULE_NAMES[2]}
        entries = assemble_module_results(selected, {MODULE_NAMES[0]: None, MODULE_NAMES[2]: {
            "status": "COMPLETED", "target_scope": {"url": "https://example.com"},
            "findings": [], "duration_seconds": 1.5,
        }})
        by_name = {entry["module"]: entry for entry in entries}
        self.assertEqual(len(entries), 4)
        self.assertEqual(by_name[MODULE_NAMES[0]]["status"], "NOT_RUN")
        self.assertEqual(by_name[MODULE_NAMES[0]]["target_scope"]["selection"], "SELECTED_BUT_NOT_RUN")
        self.assertEqual(by_name[MODULE_NAMES[1]]["status"], "NOT_RUN")
        self.assertEqual(by_name[MODULE_NAMES[1]]["target_scope"]["selection"], "NOT_SELECTED")
        self.assertEqual(by_name[MODULE_NAMES[2]]["status"], "COMPLETED")

    def test_preserves_failed_and_partial_outcomes(self):
        selected = {MODULE_NAMES[1], MODULE_NAMES[3]}
        entries = assemble_module_results(selected, {
            MODULE_NAMES[1]: {"status": "FAILED", "target_scope": {"cidr": "192.0.2.0/24"}, "findings": []},
            MODULE_NAMES[3]: {"status": "PARTIAL", "target_scope": {"host": "example.com"}, "findings": []},
        })
        states = {entry["module"]: entry["status"] for entry in entries}
        self.assertEqual(states[MODULE_NAMES[1]], "FAILED")
        self.assertEqual(states[MODULE_NAMES[3]], "PARTIAL")

    def test_assembled_results_build_a_verified_four_module_engagement(self):
        selected = {MODULE_NAMES[0], MODULE_NAMES[2]}
        outcomes = {
            MODULE_NAMES[0]: {
                "status": "COMPLETED", "target_scope": {"target": "example.com"},
                "findings": [{
                    "check": "DNS_A", "severity": "INFO", "status": "OBSERVED",
                    "evidence": "192.0.2.10", "confidence": "HIGH",
                    "evidence_type": "OBSERVATION",
                }], "duration_seconds": 1.25,
            },
            MODULE_NAMES[2]: {
                "status": "PARTIAL", "target_scope": {"url": "https://example.com"},
                "findings": [], "duration_seconds": 0.5,
            },
        }
        record = build_engagement_record(
            {"engagement_name": "synthetic test"},
            assemble_module_results(selected, outcomes),
        )
        self.assertEqual(record["engagement"]["module_count"], 4)
        self.assertEqual(record["summary"]["total_findings"], 1)
        self.assertTrue(verify_engagement_record(record))

    def test_invalid_outcomes_and_not_run_findings_become_failed(self):
        invalid_outcomes = (
            {"status": "UNKNOWN", "target_scope": {"target": "example.com"}, "findings": []},
            {"status": "NOT_RUN", "target_scope": {"target": "example.com"},
             "findings": [{"check": "x"}]},
            {"status": "COMPLETED", "target_scope": {}, "findings": []},
        )
        for outcome in invalid_outcomes:
            with self.subTest(outcome=outcome):
                entries = assemble_module_results(
                    {MODULE_NAMES[0]}, {MODULE_NAMES[0]: outcome}
                )
                self.assertEqual(entries[0]["status"], "FAILED")
                self.assertEqual(entries[0]["findings"], [])

    def test_invalid_module_output_isolated_and_engagement_remains_verifiable(self):
        selected = {MODULE_NAMES[0], MODULE_NAMES[2]}
        outcomes = {
            MODULE_NAMES[0]: {
                "status": "COMPLETED", "target_scope": {"target": "example.com"},
                "findings": [{"check": "DNS_A", "severity": "INFO", "status": "OBSERVED"}],
            },
            MODULE_NAMES[2]: {
                "status": "COMPLETED", "target_scope": {"url": "https://example.com"},
                "findings": ["malformed finding"],
            },
        }
        entries = assemble_module_results(selected, outcomes)
        by_name = {entry["module"]: entry for entry in entries}
        self.assertEqual(by_name[MODULE_NAMES[0]]["status"], "COMPLETED")
        self.assertEqual(by_name[MODULE_NAMES[2]]["status"], "FAILED")
        self.assertEqual(by_name[MODULE_NAMES[2]]["findings"], [])
        self.assertEqual(by_name[MODULE_NAMES[1]]["status"], "NOT_RUN")
        record = build_engagement_record({"engagement_name": "failure isolation"}, entries)
        self.assertEqual(record["engagement"]["status"], "PARTIAL")
        self.assertTrue(verify_engagement_record(record))

    def test_combined_finding_limit_is_enforced_per_module(self):
        selected = {MODULE_NAMES[0], MODULE_NAMES[1]}
        outcomes = {
            MODULE_NAMES[0]: {
                "status": "COMPLETED", "target_scope": {"target": "example.com"},
                "findings": [{"check": "A", "status": "OBSERVED"} for _ in range(1500)],
            },
            MODULE_NAMES[1]: {
                "status": "COMPLETED", "target_scope": {"network": "192.0.2.0/24"},
                "findings": [{"check": "B", "status": "OBSERVED"} for _ in range(600)],
            },
        }
        entries = assemble_module_results(selected, outcomes)
        self.assertEqual(entries[0]["status"], "COMPLETED")
        self.assertEqual(entries[1]["status"], "FAILED")
        self.assertEqual(len(entries[0]["findings"]), 1500)
        self.assertEqual(entries[1]["findings"], [])

    def test_invalid_duration_and_timestamp_fail_only_the_affected_module(self):
        selected = {MODULE_NAMES[0], MODULE_NAMES[1]}
        outcomes = {
            MODULE_NAMES[0]: {
                "status": "COMPLETED", "target_scope": {"target": "example.com"},
                "findings": [], "duration_seconds": float("nan"),
            },
            MODULE_NAMES[1]: {
                "status": "COMPLETED", "target_scope": {"network": "192.0.2.0/24"},
                "findings": [], "started_at": "not-a-timestamp",
            },
        }
        entries = assemble_module_results(selected, outcomes)
        self.assertTrue(all(entry["status"] == "FAILED" for entry in entries[:2]))

    def test_before_run_checkpoint_failure_prevents_module_execution(self):
        selected = {MODULE_NAMES[0]}
        calls = []

        def runner():
            calls.append("ran")
            return {"status": "COMPLETED", "target_scope": {"target": "example.com"}, "findings": []}

        def checkpoint(_name):
            raise OSError("journal unavailable")

        outcomes = run_selected_modules(
            selected, {MODULE_NAMES[0]: runner}, before_run=checkpoint
        )
        self.assertEqual(calls, [])
        self.assertEqual(outcomes[MODULE_NAMES[0]]["status"], "FAILED")

    def test_finish_checkpoint_failure_downgrades_result_to_failed(self):
        selected = {MODULE_NAMES[0]}
        outcomes = run_selected_modules(
            selected,
            {MODULE_NAMES[0]: lambda: {
                "status": "COMPLETED", "target_scope": {"target": "example.com"},
                "findings": [],
            }},
            on_finish=lambda _name, _outcome: (_ for _ in ()).throw(OSError("journal failure")),
        )
        self.assertEqual(outcomes[MODULE_NAMES[0]]["status"], "FAILED")
        self.assertIn("checkpointed", outcomes[MODULE_NAMES[0]]["limitations"][0])

    def test_runner_exception_does_not_prevent_later_selected_modules(self):
        selected = {MODULE_NAMES[0], MODULE_NAMES[2]}
        calls = []
        errors = []

        def broken():
            calls.append("broken")
            raise RuntimeError("synthetic failure")

        def healthy():
            calls.append("healthy")
            return {
                "status": "COMPLETED", "target_scope": {"url": "https://example.com"},
                "findings": [], "duration_seconds": 0.1,
            }

        outcomes = run_selected_modules(
            selected, {MODULE_NAMES[0]: broken, MODULE_NAMES[2]: healthy},
            on_error=lambda name, exc: errors.append((name, type(exc).__name__)),
        )
        entries = assemble_module_results(selected, outcomes)
        by_name = {entry["module"]: entry for entry in entries}
        self.assertEqual(calls, ["broken", "healthy"])
        self.assertEqual(errors, [(MODULE_NAMES[0], "RuntimeError")])
        self.assertEqual(by_name[MODULE_NAMES[0]]["status"], "FAILED")
        self.assertEqual(by_name[MODULE_NAMES[2]]["status"], "COMPLETED")

    def test_callback_exceptions_do_not_interrupt_module_execution(self):
        selected = {MODULE_NAMES[0], MODULE_NAMES[2]}
        calls = []

        def healthy(label):
            def run():
                calls.append(label)
                return {
                    "status": "COMPLETED", "target_scope": {"target": "example.com"},
                    "findings": [], "duration_seconds": 0.1,
                }
            return run

        def broken_start(_name):
            raise RuntimeError("synthetic output failure")

        def broken_error(_name, _exc):
            raise RuntimeError("synthetic logging failure")

        def broken_runner():
            calls.append("broken")
            raise RuntimeError("synthetic module failure")

        outcomes = run_selected_modules(
            selected,
            {MODULE_NAMES[0]: broken_runner, MODULE_NAMES[2]: healthy("healthy")},
            on_start=broken_start,
            on_error=broken_error,
        )
        entries = assemble_module_results(selected, outcomes)
        by_name = {entry["module"]: entry for entry in entries}
        self.assertEqual(calls, ["broken", "healthy"])
        self.assertEqual(by_name[MODULE_NAMES[0]]["status"], "FAILED")
        self.assertEqual(by_name[MODULE_NAMES[2]]["status"], "COMPLETED")

    def test_runner_missing_or_returns_none_is_recorded_without_abort(self):
        selected = {MODULE_NAMES[0], MODULE_NAMES[1]}
        outcomes = run_selected_modules(selected, {MODULE_NAMES[0]: lambda: None})
        entries = assemble_module_results(selected, outcomes)
        by_name = {entry["module"]: entry for entry in entries}
        self.assertEqual(by_name[MODULE_NAMES[0]]["status"], "NOT_RUN")
        self.assertEqual(by_name[MODULE_NAMES[1]]["status"], "FAILED")


if __name__ == "__main__":
    unittest.main()
