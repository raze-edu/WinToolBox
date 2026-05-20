import unittest
from unittest.mock import patch, MagicMock
import os
import json
import csv
import sys
from pathlib import Path

# Add project root to path so we can import domain_exporter
sys.path.append(str(Path(__file__).parent.parent))

from domain_exporter import DomainExporter

class TestDomainExporter(unittest.TestCase):
    def setUp(self):
        self.exporter = DomainExporter()

    @patch('domain_exporter.DomainExporter._run_ps_script')
    def test_fetch_domain_data_users(self, mock_run):
        # Mocking PS output
        mock_run.return_value = json.dumps([
            {"Name": "User1", "Email": "user1@example.com"},
            {"Name": "User2", "Email": "user2@example.com"}
        ])
        
        data = self.exporter.fetch_domain_data("users")
        
        self.assertEqual(len(data), 2)
        self.assertEqual(data[0]["Name"], "User1")
        mock_run.assert_called_once_with(self.exporter.ad_data_script, "-Type", "users")

    def test_export_to_csv(self):
        data = [
            {"Name": "User1", "Email": "user1@example.com", "Title": "Manager"},
            {"Name": "User2", "Email": "user2@example.com"} # Missing Title
        ]
        
        filepath = self.exporter.export_to_csv(data, "test_export")
        
        self.assertTrue(os.path.exists(filepath))
        
        # Verify CSV content
        with open(filepath, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f, delimiter=';')
            rows = list(reader)
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[0]["Name"], "User1")
            self.assertEqual(rows[1]["Title"], "") # Check missing field handling
            
        # Cleanup
        os.remove(filepath)

if __name__ == "__main__":
    unittest.main()
