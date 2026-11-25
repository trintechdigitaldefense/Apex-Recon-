import os
import tempfile
import unittest
from email.message import Message
from pathlib import Path
from unittest.mock import Mock, patch
from urllib.request import Request

import apex_evidence
import apex_web as web


class FakeResponse:
    def __init__(self, body=b"sample", content_type="text/html", content_length=None):
        self.headers = Message()
        self.headers["Content-Type"] = content_type
        if content_length is not None:
            self.headers["Content-Length"] = str(content_length)
        self.body = body
        self.read_limit = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self, limit):
        self.read_limit = limit
        return self.body[:limit]

    def getcode(self):
        return 200

    def geturl(self):
        return "https://example.test/app"


class HTTPHTTPSComparisonTests(unittest.TestCase):
    def response(self, url, body=b"sample", status=200, content_type="text/html",
                 content_length=None, redirects=(), limit_reached=False):
        headers = Message()
        headers["Content-Type"] = content_type
        return web.FetchResult(
            status=status,
            headers=headers,
            final_url=url,
            body=body,
            redirect_chain=tuple(redirects),
            content_type=content_type,
            content_length=content_length,
            body_bytes_read=len(body),
            body_sample_limit_reached=limit_reached,
        )

    @patch.object(web.urllib.request, "build_opener")
    def test_fetch_uses_client_side_body_cap_without_range_request(self, build_opener):
        response = FakeResponse(body=b"x" * web.MAX_RESPONSE_BYTES,
                                content_type="text/html",
                                content_length=web.MAX_RESPONSE_BYTES + 500)
        opener = Mock()
        opener.open.return_value = response
        build_opener.return_value = opener

        result = web._fetch("https://example.test/app")

        request = opener.open.call_args.args[0]
        self.assertIsInstance(request, Request)
        self.assertFalse(any(name.lower() == "range" for name, _ in request.header_items()))
        self.assertEqual(response.read_limit, web.MAX_RESPONSE_BYTES)
        self.assertEqual(result.body_bytes_read, web.MAX_RESPONSE_BYTES)
        self.assertTrue(result.body_sample_limit_reached)
        self.assertEqual(result.content_length, web.MAX_RESPONSE_BYTES + 500)

    def test_direct_http_and_https_responses_are_compared(self):
        http = self.response("http://example.test/app", body=b"http", content_length=4)
        https = self.response("https://example.test/app", body=b"https", content_length=5)

        result = web._build_http_https_comparison(
            "http://example.test/app", "https://example.test/app", http, https
        )

        self.assertEqual(result["outcome"], "HTTP_CONTENT_OBSERVED")
        self.assertTrue(result["http_content_observed"])
        self.assertTrue(result["same_hostname"])
        self.assertTrue(result["same_path"])
        self.assertEqual(result["request_count"], 2)
        self.assertEqual(result["direct_response_comparison"]["status_matches"], True)
        self.assertFalse(result["direct_response_comparison"]["body_samples_match"])

    def test_http_upgrade_records_redirect_status_and_reuses_https_response(self):
        handler = web.SameHostRedirectHandler()
        request = Request("http://example.test/app")
        redirect_headers = Message()
        redirect_headers["Content-Type"] = "text/html"
        redirect_headers["Content-Length"] = "0"
        handler.redirect_request(
            request, None, 301, "Moved Permanently", redirect_headers,
            "https://example.test/app"
        )
        https = self.response(
            "https://example.test/app", body=b"secure", content_length=6,
            redirects=handler.redirects
        )

        result = web._build_http_https_comparison(
            "http://example.test/app", "https://example.test/app", https, https
        )

        self.assertEqual(result["outcome"], "HTTP_REDIRECTED_TO_HTTPS")
        self.assertEqual(result["http_response"]["status"], 301)
        self.assertEqual(result["http_response"]["final_scheme"], "https")
        self.assertEqual(result["request_count"], 1)
        self.assertIsNone(result["direct_response_comparison"])

    def test_empty_http_response_is_not_described_as_serving_content(self):
        http = self.response("http://example.test/health", body=b"", content_length=0)
        https = self.response("https://example.test/health", body=b"", content_length=0)

        result = web._build_http_https_comparison(
            "http://example.test/health", "https://example.test/health", http, https
        )

        self.assertEqual(result["outcome"], "HTTP_RESPONSE_WITHOUT_BODY")
        self.assertFalse(result["http_content_observed"])


    def test_assessment_includes_comparison_and_report_exports_it(self):
        http = self.response(
            "http://example.test/", body=b"plain", content_type="text/html",
            content_length=5
        )
        https = self.response(
            "https://example.test/", body=b"secure", content_type="text/html",
            content_length=6
        )
        with patch.object(web, "_fetch", side_effect=[http, https]):
            result = web.assess_url("example.test")

        comparison = result["http_https_comparison"]
        self.assertEqual(comparison["outcome"], "HTTP_CONTENT_OBSERVED")
        self.assertFalse(comparison["direct_response_comparison"]["body_samples_match"])

        record = apex_evidence.build_evidence_record(result, 1.0)
        self.assertEqual(
            record["evidence"]["technical_details"]["http_https_comparison"]["outcome"],
            "HTTP_CONTENT_OBSERVED",
        )

        with tempfile.TemporaryDirectory() as tmp:
            original = os.getcwd()
            try:
                os.chdir(tmp)
                report_path = web.generate_html_report(result, 1.0)
                report = Path(report_path).read_text(encoding="utf-8")
            finally:
                os.chdir(original)
        self.assertIn("HTTP/HTTPS Response Comparison", report)
        self.assertIn("HTTP_CONTENT_OBSERVED", report)

    def test_body_comparison_is_unknown_when_samples_are_truncated(self):
        http = self.response("http://example.test/", body=b"abc", content_length=9000,
                             limit_reached=True)
        https = self.response("https://example.test/", body=b"abc", content_length=9000,
                              limit_reached=True)

        result = web._build_http_https_comparison(
            "http://example.test/", "https://example.test/", http, https
        )

        comparison = result["direct_response_comparison"]
        self.assertFalse(comparison["body_samples_comparable"])
        self.assertIsNone(comparison["body_samples_match"])


if __name__ == "__main__":
    unittest.main()
