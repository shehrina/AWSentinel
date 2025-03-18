import unittest
from unittest.mock import Mock, patch
from datetime import datetime
import json

from src.scanners.wiz_scanner import WizScanner
from src.storage.mongodb import MongoDBStorage
from src.alerts.alert_manager import AlertManager

class TestCloudSecurityScanner(unittest.TestCase):
    def setUp(self):
        self.wiz_scanner = WizScanner()
        self.storage = MongoDBStorage()
        self.alert_manager = AlertManager()

    @patch('src.scanners.wiz_scanner.requests.post')
    def test_wiz_authentication(self, mock_post):
        # Mock the authentication response
        mock_post.return_value.json.return_value = {
            "access_token": "test-token",
            "expires_in": 3600
        }
        mock_post.return_value.raise_for_status = Mock()

        token = self.wiz_scanner._get_auth_token()
        self.assertEqual(token, "test-token")

    @patch('src.scanners.wiz_scanner.requests.request')
    def test_scan_resources(self, mock_request):
        # Mock the scan response
        mock_request.return_value.json.return_value = {
            "data": {
                "securityIssues": {
                    "nodes": [
                        {
                            "id": "test-issue-1",
                            "severity": "HIGH",
                            "title": "Test Security Issue",
                            "description": "Test Description"
                        }
                    ]
                }
            }
        }
        mock_request.return_value.raise_for_status = Mock()

        results = self.wiz_scanner.scan_resources("AWS")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["severity"], "HIGH")

    @patch('pymongo.collection.Collection.insert_one')
    def test_store_scan_results(self, mock_insert):
        # Mock MongoDB insert
        mock_insert.return_value.inserted_id = "test-id"

        test_results = {
            "cloud_provider": "AWS",
            "results": [{"id": "test-issue"}],
            "timestamp": datetime.now().isoformat()
        }

        result_id = self.storage.store_scan_results(test_results)
        self.assertEqual(result_id, "test-id")

    @patch('requests.post')
    def test_slack_alert(self, mock_post):
        # Mock Slack API call
        mock_post.return_value.raise_for_status = Mock()

        test_message = "Test security alert"
        result = self.alert_manager.send_slack_alert(test_message, "high")
        self.assertTrue(result)

    def test_format_security_alert(self):
        test_issue = {
            "severity": "HIGH",
            "title": "Security Vulnerability",
            "description": "Test vulnerability",
            "resource": {
                "name": "test-resource",
                "type": "s3-bucket",
                "region": "us-west-2"
            }
        }

        formatted = self.alert_manager.format_security_alert(test_issue)
        self.assertIn("Security Issue Detected", formatted["slack_message"])
        self.assertIn("HIGH", formatted["email_subject"])

if __name__ == '__main__':
    unittest.main() 