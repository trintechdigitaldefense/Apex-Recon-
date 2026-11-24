import socket
import ssl
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import apex_tls


class TLSInputTests(unittest.TestCase):
    def test_normalizes_hostname_and_url(self):
        self.assertEqual(apex_tls.normalize_tls_target("example.com"), "example.com")
        self.assertEqual(apex_tls.normalize_tls_target("https://example.com/path?token=x"), "example.com")
        self.assertEqual(apex_tls.normalize_tls_target("https://[2001:db8::1]/"), "2001:db8::1")

    def test_rejects_credentials_bad_schemes_and_bad_ports(self):
        for target in ("", "ftp://example.com", "https://user:pass@example.com",
                       "https://example.com:8443", "example.com\nheader"):
            with self.subTest(target=target):
                with self.assertRaises(apex_tls.TLSAssessmentInputError):
                    apex_tls.normalize_tls_target(target)

    def test_timeout_is_bounded(self):
        for value in (0, -1, 20.1, "invalid"):
            with self.subTest(value=value):
                with self.assertRaises(apex_tls.TLSAssessmentInputError):
                    apex_tls.assess_tls("example.com", value)


class FakeTLSSocket:
    def __init__(self, cert=None):
        expiry = (datetime.now(timezone.utc) + timedelta(days=90)).strftime("%b %d %H:%M:%S %Y GMT")
        self.cert = cert or {
            "subject": ((("commonName", "example.com"),),),
            "issuer": ((("commonName", "Test CA"),),),
            "notBefore": "Jan 01 00:00:00 2026 GMT",
            "notAfter": expiry,
            "subjectAltName": (("DNS", "example.com"),),
        }

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def version(self):
        return "TLSv1.3"

    def cipher(self):
        return ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)

    def getpeercert(self):
        return self.cert


class TLSAssessmentTests(unittest.TestCase):
    def context(self, tls_socket=None):
        ctx = MagicMock()
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = True
        ctx.wrap_socket.return_value = tls_socket or FakeTLSSocket()
        return ctx

    @patch("apex_tls.socket.create_connection")
    @patch("apex_tls.ssl.create_default_context")
    def test_success_reports_verified_handshake_and_negotiated_values(self, make_context, connect):
        make_context.return_value = self.context()
        connect.return_value.__enter__.return_value = object()
        result = apex_tls.assess_tls("example.com")
        self.assertEqual(result["status"], "VERIFIED")
        self.assertTrue(result["verified"])
        self.assertEqual(result["protocol"], "TLSv1.3")
        self.assertEqual(result["cipher"]["bits"], 256)
        self.assertEqual(result["certificate"]["subject_alt_names"], ["DNS:example.com"])
        self.assertEqual(connect.call_args.args, (("example.com", 443),))
        self.assertTrue(make_context.return_value.check_hostname)
        self.assertEqual(make_context.return_value.verify_mode, ssl.CERT_REQUIRED)
        finding = result["findings"][0]
        self.assertEqual(finding["module"], "TLS Security Assessment")
        self.assertEqual(finding["confidence"], "HIGH")
        self.assertEqual(finding["evidence_type"], "OBSERVATION")
        self.assertTrue(finding["finding_id"].startswith("ARF-"))

    @patch("apex_tls.socket.create_connection")
    @patch("apex_tls.ssl.create_default_context")
    def test_certificate_verification_failure_is_not_bypassed(self, make_context, connect):
        ctx = self.context()
        ctx.wrap_socket.side_effect = ssl.SSLCertVerificationError("certificate verify failed")
        make_context.return_value = ctx
        connect.return_value.__enter__.return_value = object()
        result = apex_tls.assess_tls("example.com")
        self.assertEqual(result["status"], "VERIFICATION_FAILED")
        self.assertFalse(result["verified"])
        self.assertIsNone(result["certificate"])
        ctx.wrap_socket.assert_called_once()
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(ctx.check_hostname)

    @patch("apex_tls.socket.create_connection", side_effect=socket.timeout("timed out"))
    @patch("apex_tls.ssl.create_default_context")
    def test_timeout_is_reported_without_crashing(self, make_context, connect):
        make_context.return_value = self.context()
        result = apex_tls.assess_tls("example.com")
        self.assertEqual(result["status"], "UNAVAILABLE")
        self.assertIsNone(result["protocol"])
        finding = result["findings"][0]
        self.assertEqual(finding["severity"], "UNKNOWN")
        self.assertEqual(finding["review_priority"], "UNRANKED")

    @patch("apex_tls.socket.create_connection")
    @patch("apex_tls.ssl.create_default_context")
    def test_context_without_verification_is_rejected(self, make_context, connect):
        ctx = self.context()
        ctx.check_hostname = False
        make_context.return_value = ctx
        result = None
        with self.assertRaises(apex_tls.TLSAssessmentInputError):
            apex_tls.assess_tls("example.com")
        connect.assert_not_called()

    @patch("apex_tls.socket.create_connection")
    @patch("apex_tls.ssl.create_default_context")
    def test_expiry_threshold_is_reported(self, make_context, connect):
        expiry = (datetime.now(timezone.utc) + timedelta(days=4)).strftime("%b %d %H:%M:%S %Y GMT")
        cert = {
            "subject": ((("commonName", "example.com"),),),
            "issuer": ((("commonName", "Test CA"),),),
            "notAfter": expiry,
            "subjectAltName": (("DNS", "example.com"),),
        }
        make_context.return_value = self.context(FakeTLSSocket(cert))
        connect.return_value.__enter__.return_value = object()
        result = apex_tls.assess_tls("example.com")
        finding = next(item for item in result["findings"] if item["check"] == "CERTIFICATE_EXPIRY")
        self.assertEqual(finding["severity"], "HIGH")
        self.assertEqual(finding["status"], "EXPIRING_WITHIN_7_DAYS")

    def test_report_escapes_untrusted_fields_and_uses_private_file(self):
        import os
        import tempfile
        result = {
            "module": "TLS Security Assessment", "target": "<script>bad</script>",
            "assessment_id": "tls-assessment-456",
            "status": "VERIFIED", "verified": True, "protocol": "TLSv1.3",
            "cipher": {"name": "TEST"},
            "certificate": {"subject": "<img src=x>", "issuer": "Test CA"},
            "findings": [{"check": "TLS", "severity": "INFO", "status": "OK",
                          "evidence": "<script>alert(1)</script>", "recommendation": "Safe"}],
            "limitations": ["<svg onload=alert(1)>"],
        }
        with tempfile.TemporaryDirectory() as tmp:
            old = os.getcwd()
            try:
                os.chdir(tmp)
                path = apex_tls.generate_html_report(result, 0.2)
                content = open(path, encoding="utf-8").read()
                self.assertNotIn("<script>", content)
                self.assertNotIn("<img src=x>", content)
                self.assertNotIn("<svg onload", content)
                self.assertIn("tls-assessment-456", content)
                self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            finally:
                os.chdir(old)


if __name__ == "__main__":
    unittest.main()
