"""Offline tests for Phase 2J unified engagement CLI helpers."""
import unittest

from apex_engagement_cli import MODULE_NAMES, assemble_module_results, parse_module_selection
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

    def test_rejects_invalid_outcomes_and_not_run_findings(self):
        with self.assertRaises(ValueError):
            assemble_module_results({MODULE_NAMES[0]}, {MODULE_NAMES[0]: {"status": "UNKNOWN"}})
        with self.assertRaises(ValueError):
            assemble_module_results({MODULE_NAMES[0]}, {MODULE_NAMES[0]: {
                "status": "NOT_RUN", "target_scope": {"target": "example.com"},
                "findings": [{"check": "x"}],
            }})
        with self.assertRaises(ValueError):
            assemble_module_results({MODULE_NAMES[0]}, {MODULE_NAMES[0]: {
                "status": "COMPLETED", "target_scope": {}, "findings": [],
            }})


if __name__ == "__main__":
    unittest.main()
