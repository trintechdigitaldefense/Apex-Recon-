import importlib.util
import socket
import sys
import ssl
import unittest
import urllib.error
from email.message import Message
from pathlib import Path
from unittest.mock import patch

MODULE_PATH = Path(__file__).resolve().parents[1] / "apex_web.py"
SPEC = importlib.util.spec_from_file_location("apex_web", MODULE_PATH)
web = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = web
SPEC.loader.exec_module(web)


class URLValidationTests(unittest.TestCase):
    def test_hostname_defaults_to_https_and_query_is_removed(self):
        parsed = web.normalize_target_url("example.com/private?token=secret")
        self.assertEqual(parsed.scheme, "https")
        self.assertEqual(parsed.netloc, "example.com")
        self.assertEqual(parsed.path, "/private")
        self.assertEqual(parsed.query, "")

    def test_accepts_standard_http_and_https_urls(self):
        self.assertEqual(web.normalize_target_url("http://example.com").scheme, "http")
        self.assertEqual(web.normalize_target_url("https://example.com:443").hostname, "example.com")

    def test_ipv6_literal_is_preserved(self):
        parsed = web.normalize_target_url("https://[2001:db8::1]/")
        self.assertEqual(parsed.hostname, "2001:db8::1")

    def test_rejects_unsupported_schemes_and_malformed_inputs(self):
        for target in ("", "ftp://example.com", "javascript:alert(1)",
                       "https://user:pass@example.com", "https://example.com:8443",
                       "http://example.com:443", "https://example.com:80",
                       "https://example.com/#fragment", "https://example.com:99999"):
            with self.subTest(target=target):
                with self.assertRaises(web.AssessmentInputError):
                    web.normalize_target_url(target)

    def test_rejects_control_characters_and_non_text(self):
        for target in ("example.com\nHeader: injected", None):
            with self.subTest(target=target):
                with self.assertRaises(web.AssessmentInputError):
                    web.normalize_target_url(target)

    def test_timeout_is_bounded(self):
        for timeout in (0, -1, 20.1, "not-a-number"):
            with self.subTest(timeout=timeout):
                with self.assertRaises(web.AssessmentInputError):
                    web.assess_url("example.com", timeout=timeout)


class RedirectPolicyTests(unittest.TestCase):
    def test_allows_same_host_http_to_https_upgrade(self):
        handler = web.SameHostRedirectHandler()
        request = __import__("urllib.request").request.Request("http://example.com/")
        result = handler.redirect_request(request, None, 301, "Moved", Message(), "https://example.com/")
        self.assertEqual(result.full_url, "https://example.com/")

    def test_blocks_cross_host_redirect(self):
        handler = web.SameHostRedirectHandler()
        request = __import__("urllib.request").request.Request("https://example.com/")
        with self.assertRaises(web.RedirectScopeError):
            handler.redirect_request(request, None, 302, "Found", Message(), "https://other.example/")

    def test_blocks_https_downgrade(self):
        handler = web.SameHostRedirectHandler()
        request = __import__("urllib.request").request.Request("https://example.com/")
        with self.assertRaises(web.RedirectScopeError):
            handler.redirect_request(request, None, 302, "Found", Message(), "http://example.com/")

    def test_blocks_redirect_to_non_standard_port(self):
        handler = web.SameHostRedirectHandler()
        request = __import__("urllib.request").request.Request("http://example.com/")
        with self.assertRaises(web.RedirectScopeError):
            handler.redirect_request(request, None, 302, "Found", Message(), "https://example.com:8443/")

    def test_blocks_same_scheme_redirect_and_path_scope_drift(self):
        handler = web.SameHostRedirectHandler()
        request = __import__("urllib.request").request.Request("http://example.com/app")
        with self.assertRaises(web.RedirectScopeError):
            handler.redirect_request(request, None, 302, "Found", Message(), "http://example.com/app/")
        with self.assertRaises(web.RedirectScopeError):
            handler.redirect_request(request, None, 302, "Found", Message(), "https://example.com/other")


class HeaderAssessmentTests(unittest.TestCase):
    def headers(self, values=None, cookies=None):
        result = Message()
        for key, value in (values or {}).items():
            result[key] = value
        for cookie in cookies or []:
            result.add_header("Set-Cookie", cookie)
        return result

    def test_all_present_security_headers_are_reported(self):
        headers = self.headers({
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "camera=(), microphone=()",
        })
        findings = web._inspect_headers(headers, "https")
        statuses = {item["check"]: item["status"] for item in findings}
        self.assertEqual(statuses["HSTS"], "PRESENT")
        self.assertEqual(statuses["CSP"], "PRESENT")
        self.assertEqual(statuses["MIME_SNIFFING"], "PRESENT")
        self.assertEqual(statuses["CLICKJACKING_PROTECTION"], "PRESENT")

    def test_missing_security_headers_are_not_marked_clean(self):
        findings = web._inspect_headers(self.headers(), "https")
        statuses = {item["check"]: item["status"] for item in findings}
        self.assertEqual(statuses["HSTS"], "MISSING")
        self.assertEqual(statuses["CSP"], "MISSING")
        self.assertEqual(statuses["CLICKJACKING_PROTECTION"], "MISSING")
        self.assertTrue(any(item["severity"] == "MEDIUM" for item in findings))

    def test_http_does_not_claim_hsts_is_missing(self):
        findings = web._inspect_headers(self.headers(), "http")
        hsts = next(item for item in findings if item["check"] == "HSTS")
        self.assertEqual(hsts["status"], "NOT_APPLICABLE")

    def test_x_frame_options_is_accepted_as_clickjacking_protection(self):
        findings = web._inspect_headers(self.headers({"X-Frame-Options": "DENY"}), "https")
        item = next(item for item in findings if item["check"] == "CLICKJACKING_PROTECTION")
        self.assertEqual(item["status"], "PRESENT")

    def test_cookie_flags_are_checked_individually(self):
        headers = self.headers(cookies=[
            "session=abc; Secure; HttpOnly; SameSite=Lax",
            "prefs=xyz; Path=/",
        ])
        findings = web._inspect_cookies(headers, True)
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0]["status"], "PRESENT")
        self.assertEqual(findings[1]["status"], "MISSING_ATTRIBUTES")
        self.assertIn("Secure", findings[1]["evidence"])
        self.assertIn("HttpOnly", findings[1]["evidence"])
        self.assertIn("SameSite", findings[1]["evidence"])

    def test_no_cookie_header_is_not_reported_as_secure(self):
        findings = web._inspect_cookies(self.headers(), True)
        self.assertEqual(findings[0]["status"], "NO_COOKIES_OBSERVED")


class AssessmentFlowTests(unittest.TestCase):
    def response(self, status, scheme, headers=None):
        return web.FetchResult(status, headers or Message(), f"{scheme}://example.com/login")

    @patch.object(web, "_fetch")
    def test_http_redirect_and_https_headers_are_assessed(self, mocked_fetch):
        mocked_fetch.side_effect = [
            self.response(200, "https", {
                "Strict-Transport-Security": "max-age=31536000",
                "Content-Security-Policy": "default-src 'self'",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
            }),
        ]
        result = web.assess_url("https://example.com/login?access_token=secret")
        self.assertEqual(mocked_fetch.call_count, 1)
        self.assertIsNone(result["http_status"])
        self.assertEqual(result["http_final_scheme"], "https")
        self.assertTrue(result["http_redirected_to_https"])
        self.assertEqual(result["https_status"], 200)
        self.assertNotIn("access_token", str(result))
        self.assertEqual(next(f for f in result["findings"] if f["check"] == "HTTPS_ENFORCEMENT")["status"], "REDIRECTED")

    @patch.object(web, "_fetch")
    def test_http_without_https_redirect_is_flagged(self, mocked_fetch):
        mocked_fetch.side_effect = [
            self.response(200, "http"),
            self.response(200, "https"),
        ]
        result = web.assess_url("example.com")
        finding = next(f for f in result["findings"] if f["check"] == "HTTPS_ENFORCEMENT")
        self.assertEqual(finding["status"], "NOT_ENFORCED")

    @patch.object(web, "_fetch")
    def test_unavailable_https_is_not_reported_as_secure(self, mocked_fetch):
        mocked_fetch.side_effect = [
            self.response(200, "http"),
            ssl.SSLError("certificate verify failed"),
        ]
        result = web.assess_url("example.com")
        finding = next(f for f in result["findings"] if f["check"] == "HTTPS_ENDPOINT")
        self.assertEqual(finding["status"], "UNAVAILABLE")
        self.assertEqual(result["https_status"], None)

    @patch.object(web, "_fetch")
    def test_http_and_https_fetch_targets_are_same_host_and_path(self, mocked_fetch):
        mocked_fetch.side_effect = [
            self.response(200, "http"),
            self.response(200, "https"),
        ]
        web.assess_url("https://example.com/app")
        self.assertEqual(mocked_fetch.call_args_list[0].args[0], "http://example.com/app")
        self.assertEqual(mocked_fetch.call_args_list[1].args[0], "https://example.com/app")

    @patch.object(web, "_fetch")
    def test_server_disclosure_is_low_severity(self, mocked_fetch):
        mocked_fetch.side_effect = [
            self.response(200, "http"),
            self.response(200, "https", {"Server": "Example/1.2", "X-Powered-By": "PHP/8.2"}),
        ]
        result = web.assess_url("example.com")
        disclosures = [f for f in result["findings"] if f["check"] in ("SERVER_HEADER", "X_POWERED_BY")]
        self.assertEqual(len(disclosures), 2)
        self.assertTrue(all(f["severity"] == "LOW" for f in disclosures))

    @patch.object(web, "_fetch")
    def test_network_errors_are_recorded_without_crashing(self, mocked_fetch):
        mocked_fetch.side_effect = [
            urllib.error.URLError("connection refused"),
            socket.timeout("timed out"),
        ]
        result = web.assess_url("example.com")
        self.assertIsNone(result["http_status"])
        self.assertIsNone(result["https_status"])
        self.assertTrue(any(f["status"] == "UNAVAILABLE" for f in result["findings"]))

    @patch.object(web, "_fetch")
    def test_only_two_requests_are_made(self, mocked_fetch):
        mocked_fetch.side_effect = [self.response(200, "http"), self.response(200, "https")]
        web.assess_url("example.com")
        self.assertEqual(mocked_fetch.call_count, 2)

    @patch.object(web, "_fetch")
    def test_result_has_explicit_scope_limitations(self, mocked_fetch):
        mocked_fetch.side_effect = [self.response(200, "http"), self.response(200, "https")]
        result = web.assess_url("example.com")
        self.assertEqual(result["schema_version"], "1.0")
        self.assertGreaterEqual(len(result["limitations"]), 4)


if __name__ == "__main__":
    unittest.main()
