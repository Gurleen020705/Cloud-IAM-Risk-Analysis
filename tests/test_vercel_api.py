import os
import unittest
from unittest.mock import patch

from api.index import get_response, post_response, request_path


class VercelApiTests(unittest.TestCase):
    def test_request_path_uses_original_route_from_vercel_rewrite(self):
        self.assertEqual(
            request_path("/api/index.py?route=%2Fapi%2Fhealth"),
            "/api/health",
        )

    def test_request_path_supports_local_unrewritten_urls(self):
        self.assertEqual(request_path("/api/health"), "/api/health")

    def test_health_endpoint_reports_sample_mode(self):
        payload, status = get_response("/api/health")

        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["mode"], "sample-demo")

    def test_config_endpoint_defaults_to_sample_mode(self):
        with patch.dict(os.environ, {}, clear=True):
            payload, status = get_response("/api/config")

        self.assertEqual(status, 200)
        self.assertEqual(payload, {"mode": "sample-demo", "project_id": None})

    def test_dashboard_endpoint_returns_empty_initial_state(self):
        payload, status = get_response("/api/dashboard")

        self.assertEqual(status, 200)
        self.assertEqual(payload["identities"], [])
        self.assertEqual(payload["metrics"]["identity_count"], 0)

    def test_unknown_get_endpoint_returns_not_found(self):
        payload, status = get_response("/api/not-found")

        self.assertEqual(status, 404)
        self.assertEqual(payload["error"], "Endpoint not found.")

    @patch("api.index.scan_sample", return_value={"mode": "sample-demo"})
    def test_scan_endpoint_runs_sample_scan(self, scan_sample):
        payload, status = post_response("/api/scan")

        self.assertEqual(status, 200)
        self.assertEqual(payload["mode"], "sample-demo")
        scan_sample.assert_called_once_with()

    def test_review_endpoint_explains_serverless_storage_limit(self):
        payload, status = post_response("/api/findings/example:IAM-001/review")

        self.assertEqual(status, 409)
        self.assertIn("not stored by Vercel functions", payload["error"])

    def test_unknown_post_endpoint_returns_not_found(self):
        payload, status = post_response("/api/not-found")

        self.assertEqual(status, 404)
        self.assertEqual(payload["error"], "Endpoint not found.")


if __name__ == "__main__":
    unittest.main()
