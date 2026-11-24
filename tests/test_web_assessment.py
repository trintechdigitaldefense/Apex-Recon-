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

    def test_blocks_redirect_with_embedded_credentials(self):
        handler = web.SameHostRedirectHandler()
        request = __import__("urllib.request").request.Request("http://example.com/")
        for destination in (
            "https://user:pass@example.com/",
            "https://user@example.com/",
        ):
            with self.subTest(destination=destination):
                with self.assertRaises(web.RedirectScopeError):
                    handler.redirect_request(request, None, 301, "Moved", Message(), destination)

    def test_blocks_redirect_with_malformed_port(self):
        handler = web.SameHostRedirectHandler()
        request = __import__("urllib.request").request.Request("http://example.com/")
        with self.assertRaises(web.RedirectScopeError):
            handler.redirect_request(request, None, 301, "Moved", Message(), "https://example.com:notaport/")

    def test_blocks_redirect_fragments(self):
        handler = web.SameHostRedirectHandler()
        request = __import__("urllib.request").request.Request("http://example.com/")
        with self.assertRaises(web.RedirectScopeError):
            handler.redirect_request(request, None, 301, "Moved", Message(), "https://example.com/#fragment")
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

    def test_hsts_requires_a_valid_positive_max_age(self):
        valid = web._inspect_headers(self.headers({"Strict-Transport-Security": "max-age=31536000; includeSubDomains"}), "https")
        disabled = web._inspect_headers(self.headers({"Strict-Transport-Security": "max-age=0"}), "https")
        invalid = web._inspect_headers(self.headers({"Strict-Transport-Security": "max-age=soon"}), "https")
        self.assertEqual(next(f for f in valid if f["check"] == "HSTS")["status"], "PRESENT")
        self.assertEqual(next(f for f in disabled if f["check"] == "HSTS")["status"], "DISABLED")
        self.assertEqual(next(f for f in invalid if f["check"] == "HSTS")["status"], "INVALID")

    def test_duplicate_hsts_values_are_ambiguous(self):
        headers = Message()
        headers.add_header("Strict-Transport-Security", "max-age=31536000")
        headers.add_header("Strict-Transport-Security", "max-age=0")
        finding = next(f for f in web._inspect_headers(headers, "https") if f["check"] == "HSTS")
        self.assertEqual(finding["status"], "AMBIGUOUS")

    def test_mime_sniffing_header_requires_nosniff(self):
        findings = web._inspect_headers(self.headers({"X-Content-Type-Options": "enabled"}), "https")
        finding = next(f for f in findings if f["check"] == "MIME_SNIFFING")
        self.assertEqual(finding["status"], "INVALID")

    def test_duplicate_mime_header_values_are_ambiguous(self):
        headers = Message()
        headers.add_header("X-Content-Type-Options", "nosniff")
        headers.add_header("X-Content-Type-Options", "invalid")
        finding = next(f for f in web._inspect_headers(headers, "https") if f["check"] == "MIME_SNIFFING")
        self.assertEqual(finding["status"], "AMBIGUOUS")

    def test_referrer_policy_uses_last_recognized_token(self):
        findings = web._inspect_headers(
            self.headers({"Referrer-Policy": "unknown-policy, no-referrer, strict-origin"}),
            "https",
        )
        finding = next(f for f in findings if f["check"] == "REFERRER_POLICY")
        self.assertEqual(finding["status"], "PRESENT")
        self.assertIn("strict-origin", finding["evidence"])

    def test_invalid_referrer_policy_is_not_marked_present(self):
        findings = web._inspect_headers(self.headers({"Referrer-Policy": "unsafe-referrer"}), "https")
        finding = next(f for f in findings if f["check"] == "REFERRER_POLICY")
        self.assertEqual(finding["status"], "INVALID")

    def test_invalid_x_frame_options_is_not_counted_as_protection(self):
        findings = web._inspect_headers(self.headers({"X-Frame-Options": "ALLOWALL"}), "https")
        finding = next(f for f in findings if f["check"] == "CLICKJACKING_PROTECTION")
        self.assertEqual(finding["status"], "INVALID")

    def test_permissions_policy_presence_is_not_full_validation(self):
        findings = web._inspect_headers(self.headers({"Permissions-Policy": "camera=()"}), "https")
        finding = next(f for f in findings if f["check"] == "PERMISSIONS_POLICY")
        self.assertEqual(finding["status"], "PRESENT_UNVALIDATED")

    def test_report_only_csp_is_not_counted_as_enforced_csp(self):
        headers = self.headers({"Content-Security-Policy-Report-Only": "default-src 'none'"})
        findings = web._inspect_headers(headers, "https")
        csp = next(f for f in findings if f["check"] == "CSP")
        report_only = next(f for f in findings if f["check"] == "CSP_REPORT_ONLY")
        self.assertEqual(csp["status"], "MISSING")
        self.assertEqual(report_only["status"], "REPORT_ONLY_NOT_ENFORCED")

    def test_multiple_enforced_csp_values_are_observed(self):
        headers = Message()
        headers.add_header("Content-Security-Policy", "default-src 'self'")
        headers.add_header("Content-Security-Policy", "frame-ancestors 'none'")
        findings = web._inspect_headers(headers, "https")
        csp = next(f for f in findings if f["check"] == "CSP")
        clickjacking = next(f for f in findings if f["check"] == "CLICKJACKING_PROTECTION")
        self.assertIn("2 enforced", csp["evidence"])
        self.assertEqual(clickjacking["status"], "PRESENT")

    def test_samesite_attribute_name_must_match_exactly(self):
        findings = web._inspect_cookies(
            self.headers(cookies=["sid=value; Secure; HttpOnly; SameSiteBogus=Lax"]),
            True,
        )
        self.assertEqual(findings[0]["status"], "MISSING_ATTRIBUTES")
        self.assertIn("SameSite", findings[0]["evidence"])

    def test_samesite_none_requires_secure(self):
        findings = web._inspect_cookies(
            self.headers(cookies=["sid=value; HttpOnly; SameSite=None"]),
            False,
        )
        self.assertEqual(findings[0]["status"], "INVALID_ATTRIBUTES")
        self.assertIn("SameSite=None without Secure", findings[0]["evidence"])

    def test_csp_policy_quality_reports_unsafe_sources_and_missing_restrictions(self):
        headers = self.headers({
            "Content-Security-Policy": "default-src *; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'",
        })
        findings = web._inspect_headers(headers, "https")
        checks = {item["check"]: item for item in findings}
        self.assertIn("CSP_UNSAFE_EVAL", checks)
        self.assertIn("CSP_UNSAFE_INLINE_SCRIPT", checks)
        self.assertIn("CSP_UNSAFE_INLINE_STYLE", checks)
        self.assertIn("CSP_WILDCARD_SOURCE", checks)
        self.assertIn("CSP_OBJECT_SRC", checks)
        self.assertIn("CSP_BASE_URI", checks)
        self.assertEqual(checks["CSP_UNSAFE_EVAL"]["severity"], "MEDIUM")

    def test_csp_policy_quality_accepts_restricted_policy(self):
        findings = web._inspect_csp_policy(
            "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'self'"
        )
        self.assertEqual(findings, [])

    def test_csp_duplicate_directives_use_first_occurrence(self):
        findings = web._inspect_csp_policy(
            "default-src 'self'; default-src *; object-src 'none'; base-uri 'self'"
        )
        self.assertFalse(any(item["check"] == "CSP_WILDCARD_SOURCE" for item in findings))
    def test_findings_use_common_schema_with_observation_confidence(self):
        findings = web._inspect_headers(self.headers(), "https")
        finding = next(item for item in findings if item["check"] == "CSP")
        self.assertEqual(finding["module"], "HTTP Security Assessment")
        self.assertEqual(finding["severity"], "MEDIUM")
        self.assertEqual(finding["confidence"], "HIGH")
        self.assertEqual(finding["evidence_type"], "OBSERVATION")
        self.assertTrue(finding["finding_id"].startswith("ARF-"))

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
    def test_http_response_status_classes_are_descriptive(self, mocked_fetch):
        mocked_fetch.side_effect = [
            self.response(404, "http"),
            self.response(503, "https"),
        ]
        result = web.assess_url("example.com")
        self.assertEqual(result["http_status_class"], "CLIENT_ERROR")
        self.assertEqual(result["https_status_class"], "SERVER_ERROR")
        endpoint = next(f for f in result["findings"] if f["check"] == "HTTPS_ENDPOINT")
        self.assertIn("SERVER_ERROR", endpoint["evidence"])
        self.assertEqual(endpoint["severity"], "INFO")

    @patch.object(web, "_fetch")
    def test_result_has_explicit_scope_limitations(self, mocked_fetch):
        mocked_fetch.side_effect = [self.response(200, "http"), self.response(200, "https")]
        result = web.assess_url("example.com")
        self.assertEqual(result["schema_version"], "1.0")
        self.assertGreaterEqual(len(result["limitations"]), 4)


if __name__ == "__main__":
    unittest.main()
