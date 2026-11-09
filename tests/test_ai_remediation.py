import json
import os
import unittest
from unittest.mock import patch

from aicodeshield import ai_remediation


class AiRemediationTests(unittest.TestCase):
    def test_unconfigured_api_does_not_make_request(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(RuntimeError, "not configured"):
                ai_remediation.explain_findings([])

    def test_prompt_redacts_secrets_and_returns_validated_recommendation(self):
        api_response = {
            "choices": [{
                "message": {
                    "content": json.dumps({"reviews": [{
                        "item_type": "finding",
                        "item_index": 0,
                        "explanation": "The call may execute an unsafe shell command.",
                        "remediation": "Use argument arrays and validate input.",
                        "priority": "high",
                        "cwe": "CWE-78",
                    }, {
                        "item_type": "dependency",
                        "item_index": 0,
                        "explanation": "The pinned version has a known advisory.",
                        "remediation": "Upgrade to a version documented as fixed by the advisory.",
                        "priority": "high",
                        "cwe": "unknown",
                    }]})
                }
            }]
        }
        with patch.dict(os.environ, {"DEEPSEEK_API_KEY": "local-test-key"}, clear=True):
            with patch.object(ai_remediation, "_post_chat", return_value=api_response) as post_chat:
                result = ai_remediation.explain_findings(
                    [{"rule_id": "PY001", "evidence": "api_key='dont-send-this value' eval(x)"}],
                    [{"name": "demo", "advisory_count": 1, "pinned_version": "1.0.0", "advisories": [
                        {"id": "GHSA-demo", "severity": "high", "summary": "An advisory summary.", "fixed_versions": ["1.0.2"]}
                    ]}],
                )

        request_text = post_chat.call_args.args[0]["messages"][1]["content"]
        self.assertNotIn("dont-send-this value", request_text)
        self.assertIn("[REDACTED]", request_text)
        self.assertIn("1.0.2", request_text)
        self.assertEqual({"finding", "dependency"}, {item["item_type"] for item in result["reviews"]})
        self.assertEqual("high", result["reviews"][0]["priority"])


if __name__ == "__main__":
    unittest.main()
