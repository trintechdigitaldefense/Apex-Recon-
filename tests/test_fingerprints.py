import unittest
from email.message import Message

from apex_fingerprint import fingerprint


class FingerprintTests(unittest.TestCase):
    def headers(self, content_type="text/html; charset=utf-8", **values):
        result = Message()
        result["Content-Type"] = content_type
        for key, value in values.items():
            result[key.replace("_", "-")] = value
        return result

    def test_wordpress_detected_from_multiple_independent_markers(self):
        html = b'<html><script src="/wp-includes/js/wp-embed.min.js"></script><img src="/wp-content/logo.png"></html>'
        results = fingerprint(self.headers(), html)
        wordpress = next(item for item in results if item["name"] == "WordPress")
        self.assertEqual(wordpress["confidence"], "high")
        self.assertIn("wp-content asset path", wordpress["evidence"])
        self.assertIsNone(wordpress["version"])

    def test_version_only_reported_when_explicit_generator_meta_is_numeric(self):
        html = b'<meta name="generator" content="WordPress 6.5.2">'
        results = fingerprint(self.headers(), html)
        wordpress = next(item for item in results if item["name"] == "WordPress")
        self.assertEqual(wordpress["version"], "6.5.2")
        self.assertEqual(wordpress["confidence"], "medium")

    def test_generator_detection_accepts_attribute_order_and_does_not_overstate_confidence(self):
        html = b'<meta content="WordPress 6.5.2" name="generator">'
        results = fingerprint(self.headers(), html)
        wordpress = next(item for item in results if item["name"] == "WordPress")
        self.assertEqual(wordpress["confidence"], "medium")
        self.assertEqual(wordpress["version"], "6.5.2")

    def test_non_numeric_generator_does_not_become_a_version(self):
        html = b'<meta name="generator" content="WordPress custom-build">'
        results = fingerprint(self.headers(), html)
        wordpress = next(item for item in results if item["name"] == "WordPress")
        self.assertIsNone(wordpress["version"])

    def test_single_weak_cms_marker_is_low_confidence(self):
        results = fingerprint(self.headers(), b'<script src="/wp-content/theme.js"></script>')
        wordpress = next(item for item in results if item["name"] == "WordPress")
        self.assertEqual(wordpress["confidence"], "low")

    def test_drupal_and_shopify_fingerprints(self):
        html = b'<script>window.DrupalSettings={};</script><img src="https://cdn.shopify.com/s/files/a.png">'
        results = fingerprint(self.headers(), html)
        names = {item["name"] for item in results}
        self.assertIn("Drupal", names)
        self.assertIn("Shopify", names)

    def test_frontend_markers_are_reported_without_version_claims(self):
        html = b'<div data-reactroot></div><app-root ng-version="17.0.1"></app-root><script src="/jquery-3.7.1.min.js"></script>'
        results = fingerprint(self.headers(), html)
        by_name = {item["name"]: item for item in results}
        self.assertEqual(by_name["React"]["confidence"], "high")
        self.assertEqual(by_name["Angular"]["confidence"], "high")
        self.assertIsNone(by_name["Angular"]["version"])
        self.assertIn("jQuery", by_name)

    def test_response_header_technology_is_labelled_as_observed(self):
        results = fingerprint(self.headers(Server="nginx/1.24", X_Powered_By="PHP/8.2"), b"")
        by_name = {item["name"]: item for item in results}
        self.assertEqual(by_name["nginx/1.24"]["confidence"], "low")
        self.assertIn(by_name["nginx/1.24"]["confidence"], {"high", "medium", "low", "unknown"})
        self.assertEqual(by_name["PHP/8.2"]["category"], "Application header")

    def test_non_html_response_does_not_create_body_fingerprints(self):
        results = fingerprint(self.headers("application/json"), b'{"wp-content":true}')
        self.assertEqual(results, [])


if __name__ == "__main__":
    unittest.main()
