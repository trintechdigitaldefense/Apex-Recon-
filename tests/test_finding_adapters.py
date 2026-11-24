import unittest

from apex_finding_adapters import osint_result_observations, smb_host_findings
from apex_findings import FINDING_SCHEMA_VERSION


class SMBFindingAdapterTests(unittest.TestCase):
    def test_maps_signing_share_and_vulnerability_indicators(self):
        host = {
            "signing": "DISABLED",
            "shares": ["PUBLIC", "C$", "IPC"],
            "vuln_ms17010_status": "INDICATOR",
            "vuln_ms10054_status": "POTENTIAL",
        }
        findings = smb_host_findings(host)
        by_check = {item["check"]: item for item in findings}
        self.assertEqual(by_check["SMB_MESSAGE_SIGNING"]["severity"], "MEDIUM")
        self.assertEqual(by_check["SMB_NON_HIDDEN_SHARE"]["status"], "OBSERVED")
        self.assertEqual(by_check["MS17-010"]["severity"], "HIGH")
        self.assertEqual(by_check["MS17-010"]["evidence_type"], "INDICATOR")
        self.assertEqual(by_check["MS10-054"]["severity"], "MEDIUM")
        self.assertNotIn("IPC", by_check["SMB_NON_HIDDEN_SHARE"]["evidence"])
        self.assertTrue(all(item["schema_version"] == FINDING_SCHEMA_VERSION for item in findings))

    def test_marks_incomplete_checks_unassessed(self):
        findings = smb_host_findings({
            "signing": "Unknown",
            "shares": [],
            "vuln_ms17010_status": "NOT_REPORTED",
            "vuln_ms10054_status": "NOT_REPORTED",
        })
        completeness = [item for item in findings if item["check"] == "SMB_ASSESSMENT_COMPLETENESS"]
        self.assertEqual(len(completeness), 1)
        self.assertEqual(completeness[0]["severity"], "UNKNOWN")
        self.assertEqual(completeness[0]["status"], "UNASSESSED")

    def test_not_vulnerable_is_limited_observation(self):
        findings = smb_host_findings({
            "signing": "Required",
            "shares": [],
            "vuln_ms17010_status": "NOT_VULNERABLE",
            "vuln_ms10054_status": "NOT_VULNERABLE",
        })
        ms17 = next(item for item in findings if item["check"] == "MS17-010")
        self.assertEqual(ms17["severity"], "INFO")
        self.assertIn("limited to that script result", ms17["evidence"])


class OSINTObservationAdapterTests(unittest.TestCase):
    def test_maps_only_collected_datasets_as_observations(self):
        observations = osint_result_observations({
            "DNS_A": ["192.0.2.10"],
            "WHOIS": ["Registrar: Example Registrar", "Creation Date: 2020-01-01"],
            "GEO": {"ip": "192.0.2.10", "city": "Example City"},
            "PORTS": "PORT STATE SERVICE\n443/tcp open https\n80/tcp closed http",
        })
        by_check = {item["check"]: item for item in observations}
        self.assertEqual(set(by_check), {
            "DNS_A", "WHOIS_METADATA", "IP_GEOLOCATION_METADATA", "TOP_20_TCP_PORTS"
        })
        self.assertTrue(all(item["severity"] == "INFO" for item in observations))
        self.assertTrue(all(item["evidence_type"] == "OBSERVATION" for item in observations))
        self.assertNotIn("Example City", by_check["IP_GEOLOCATION_METADATA"]["evidence"])
        self.assertIn("443/tcp open https", by_check["TOP_20_TCP_PORTS"]["evidence"])
        self.assertNotIn("80/tcp", by_check["TOP_20_TCP_PORTS"]["evidence"])

    def test_empty_or_missing_datasets_do_not_create_findings(self):
        self.assertEqual(osint_result_observations({}), [])
        self.assertEqual(osint_result_observations({"DNS_A": []}), [])


if __name__ == "__main__":
    unittest.main()
