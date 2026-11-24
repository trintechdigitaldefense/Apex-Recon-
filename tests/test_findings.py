import unittest

from apex_findings import (
    FINDING_SCHEMA_VERSION,
    FindingSchemaError,
    normalize_finding,
    normalize_findings,
)


class FindingNormalizationTests(unittest.TestCase):
    def sample(self):
        return {
            "check": "CSP",
            "severity": "MED",
            "status": "MISSING",
            "evidence": "Content-Security-Policy response header was not present.",
            "recommendation": "Configure a restrictive policy.",
        }

    def test_normalizes_aliases_and_adds_common_fields(self):
        finding = normalize_finding(
            self.sample(),
            "HTTP Security Assessment",
            default_confidence="HIGH",
            default_evidence_type="OBSERVATION",
        )
        self.assertEqual(finding["schema_version"], FINDING_SCHEMA_VERSION)
        self.assertEqual(finding["severity"], "MEDIUM")
        self.assertEqual(finding["confidence"], "HIGH")
        self.assertEqual(finding["evidence_type"], "OBSERVATION")
        self.assertEqual(finding["module"], "HTTP Security Assessment")
        self.assertTrue(finding["finding_id"].startswith("ARF-"))

    def test_finding_id_is_stable_for_same_observation(self):
        first = normalize_finding(self.sample(), "HTTP Security Assessment")
        second = normalize_finding(self.sample(), "HTTP Security Assessment")
        self.assertEqual(first["finding_id"], second["finding_id"])

    def test_identity_changes_when_evidence_or_module_changes(self):
        original = normalize_finding(self.sample(), "HTTP Security Assessment")
        changed = self.sample()
        changed["evidence"] = "A different observation."
        self.assertNotEqual(
            original["finding_id"],
            normalize_finding(changed, "HTTP Security Assessment")["finding_id"],
        )
        self.assertNotEqual(
            original["finding_id"],
            normalize_finding(self.sample(), "TLS Security Assessment")["finding_id"],
        )

    def test_unknown_values_fail_closed_without_severity_promotion(self):
        raw = self.sample()
        raw["severity"] = "URGENT-AND-EXPLOSIVE"
        raw["confidence"] = "ABSOLUTE"
        finding = normalize_finding(raw, "Test Module")
        self.assertEqual(finding["severity"], "UNKNOWN")
        self.assertEqual(finding["confidence"], "UNKNOWN")

    def test_bounds_untrusted_text(self):
        raw = self.sample()
        raw["evidence"] = "x" * 9000
        finding = normalize_finding(raw, "Test Module")
        self.assertEqual(len(finding["evidence"]), 4000)

    def test_rejects_invalid_records_instead_of_dropping_them(self):
        with self.assertRaises(FindingSchemaError):
            normalize_findings([self.sample(), "not-an-object"], "HTTP Security Assessment")
        with self.assertRaises(FindingSchemaError):
            normalize_findings({}, "HTTP Security Assessment")
        raw = self.sample()
        raw["check"] = {"unexpected": "object"}
        with self.assertRaises(FindingSchemaError):
            normalize_finding(raw, "HTTP Security Assessment")


if __name__ == "__main__":
    unittest.main()
