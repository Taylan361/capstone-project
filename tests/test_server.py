import unittest
from unittest.mock import patch

import server


class ScanApiTests(unittest.TestCase):
    def test_online_dependency_lookup_is_off_by_default(self):
        with patch.object(server, "check_dependencies") as check_dependencies:
            report = server.build_scan_report("sample", [
                {"path": "sample/requirements.txt", "content": "requests==2.28.0"},
            ])

        check_dependencies.assert_not_called()
        self.assertIn("inventory_only", report["dependency_check_status"])

    def test_online_dependency_lookup_runs_only_when_explicitly_enabled(self):
        files = [{"path": "sample/requirements.txt", "content": "requests==2.28.0"}]
        with patch.object(server, "check_dependencies", return_value=(
            [{"name": "requests", "registry_status": "found_public"}],
            {"status": "completed"},
        )) as check_dependencies:
            report = server.build_scan_report("sample", files, online_lookup=True)

        check_dependencies.assert_called_once()
        self.assertEqual("completed", report["dependency_check_status"])
        self.assertEqual("found_public", report["dependencies"][0]["registry_status"])


if __name__ == "__main__":
    unittest.main()
