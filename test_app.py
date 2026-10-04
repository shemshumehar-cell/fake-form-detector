"""
test_app.py - Automated test suite for Fake Form Detector
Event: BUILD SECURE 2026
"""

import unittest
import scanner
from app import app

class TestFakeFormDetector(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()
        app.config["TESTING"] = True

    # 1. URL Validation Tests
    def test_url_validation_normal(self):
        norm, err = scanner.validate_and_normalize_url("example.com")
        self.assertIsNone(err)
        self.assertEqual(norm, "https://example.com")

    def test_url_validation_http(self):
        norm, err = scanner.validate_and_normalize_url("http://test.local/login")
        self.assertIsNone(err)
        self.assertEqual(norm, "http://test.local/login")

    def test_url_validation_dangerous_schemes(self):
        norm, err = scanner.validate_and_normalize_url("javascript:alert(1)")
        self.assertIsNotNone(err)
        self.assertIn("Unsupported or dangerous", err)

        norm, err = scanner.validate_and_normalize_url("file:///etc/passwd")
        self.assertIsNotNone(err)

    def test_url_validation_empty(self):
        norm, err = scanner.validate_and_normalize_url("   ")
        self.assertIsNotNone(err)

    # 2. Form & HTML Parsing Tests
    def test_form_parsing_insecure(self):
        html = """
        <html>
          <body>
            <form action="http://auth.local/login" method="GET">
              <input type="text" name="user">
              <input type="password" name="pass">
              <input type="file" name="doc">
            </form>
          </body>
        </html>
        """
        forms, findings, stats = scanner.analyze_forms_and_inputs(html, "http://auth.local")
        self.assertEqual(stats["total_forms"], 1)
        self.assertTrue(stats["has_password"])
        self.assertTrue(stats["has_file_upload"])
        self.assertTrue(stats["has_plaintext_password"])
        self.assertFalse(stats["has_csrf_indicator"])

        # Check for High Risk finding on plaintext password
        risk_findings = [f for f in findings if f["severity"] == "HIGH RISK"]
        self.assertGreaterEqual(len(risk_findings), 1)

    def test_form_parsing_secure(self):
        html = """
        <html>
          <body>
            <form action="/login" method="POST">
              <input type="hidden" name="csrf_token" value="abc123xyz">
              <input type="email" name="user_email">
              <input type="password" name="user_pwd">
            </form>
          </body>
        </html>
        """
        forms, findings, stats = scanner.analyze_forms_and_inputs(html, "https://secure.local")
        self.assertEqual(stats["total_forms"], 1)
        self.assertTrue(stats["has_password"])
        self.assertFalse(stats["has_plaintext_password"])
        self.assertTrue(stats["has_csrf_indicator"])

    # 3. Security Header Audit Tests
    def test_security_headers_audit(self):
        headers = {
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=31536000",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin",
            "Permissions-Policy": "camera=()"
        }
        findings = scanner.check_security_headers(headers, is_https=True)
        passes = [f for f in findings if f["status"] == "PASS"]
        self.assertGreaterEqual(len(passes), 5)

    def test_hsts_unverified_over_http(self):
        headers = {"Strict-Transport-Security": "max-age=31536000"}
        findings = scanner.check_security_headers(headers, is_https=False)
        hsts_finding = next(f for f in findings if "Strict-Transport-Security" in f["name"])
        self.assertEqual(hsts_finding["status"], "UNVERIFIED")

    # 4. Scoring Logic Tests
    def test_scoring_bounds(self):
        stats = {
            "total_forms": 1,
            "has_password": True,
            "has_file_upload": True,
            "has_plaintext_password": True,
            "has_insecure_action": True,
            "has_csrf_indicator": False
        }
        score_data = scanner.calculate_security_score(False, [], [], stats)
        self.assertGreaterEqual(score_data["score"], 0)
        self.assertLessEqual(score_data["score"], 100)
        self.assertEqual(score_data["risk_level"], "HIGH")

    # 5. Flask Web Application Route Tests
    def test_home_page(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"FAKE FORM DETECTOR", response.data)
        self.assertIn(b"Is This Website Safe?", response.data)

    def test_compare_page(self):
        response = self.client.get("/compare")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"BEFORE VS AFTER HARDENING", response.data)

    def test_methodology_page(self):
        response = self.client.get("/methodology")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"SCANNING METHODOLOGY", response.data)
        self.assertIn(b"OWASP", response.data)

    def test_demo_insecure_route(self):
        response = self.client.get("/demo/insecure")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Training demonstration only", response.data)
        self.assertNotIn("Content-Security-Policy", response.headers)

    def test_demo_secure_route(self):
        response = self.client.get("/demo/secure")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Training demonstration only", response.data)
        self.assertIn("Content-Security-Policy", response.headers)
        self.assertIn("X-Content-Type-Options", response.headers)

    def test_scan_invalid_url(self):
        response = self.client.post("/scan", data={"url": "javascript:alert(1)"})
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Target Analysis Failed", response.data)

if __name__ == "__main__":
    unittest.main()
