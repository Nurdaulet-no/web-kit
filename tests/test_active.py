import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from auditkit.active import validate_plan, verify
from auditkit.cli import main
from auditkit.reports import merge_reports, write_report
from auditkit.scope import Scope
from tests.active_fixture import active_server, MATRIX, matrix_plan


def fixture_scope(base):
    return Scope.from_dict({"targets": [base], "allowed_origins": [base], "delay": 0.1, "max_bytes": 1024})


class ActiveValidationTests(unittest.TestCase):
    def setUp(self):
        self.scope = fixture_scope("https://example.com")

    def test_entire_plan_validated_before_network(self):
        checks = [{"type": "cors", "url": "https://example.com"}, {"type": "cors", "url": "https://other.test"}]
        with patch("auditkit.active.fetch") as fetch, self.assertRaises(ValueError):
            verify(self.scope, checks)
        fetch.assert_not_called()

    def test_missing_duplicate_and_excluded_parameters(self):
        for item in ({"type": "sqli-boolean", "url": "https://example.com/?q=x", "parameter": "id"},
                     {"type": "html-injection", "url": "https://example.com/?q=x&q=y", "parameter": "q"},
                     {"type": "cors", "url": "https://example.com/logout"},
                     {"type": "shell", "url": "https://example.com"},
                     {"type": "cors", "url": "https://example.com", "payload": "unknown"}):
            with self.subTest(item=item), self.assertRaises(ValueError):
                validate_plan({"checks": [item]}, self.scope)

    def test_budget_and_invalid_limits(self):
        checks = [{"type": "cors", "url": "https://example.com"}]
        with patch("auditkit.active.fetch") as fetch:
            data = verify(self.scope, checks, max_requests=2)
        fetch.assert_not_called()
        self.assertEqual(data["requests"], 0)
        self.assertEqual(data["active_results"][0]["status"], "skipped-budget")
        self.assertTrue(data["errors"])
        for number in (0, True, 5001):
            with self.assertRaises(ValueError):
                verify(self.scope, checks, max_requests=number)

    def test_network_error_and_interrupt_preserve_progress(self):
        checks = [{"type": "cors", "url": "https://example.com"}] * 2
        for exception, expected in ((TimeoutError(), "error"), (KeyboardInterrupt(), "interrupted")):
            with self.subTest(expected=expected), patch("auditkit.active.fetch", side_effect=exception):
                data = verify(self.scope, checks, max_requests=6)
            self.assertEqual(len(data["active_results"]), 2)
            self.assertTrue(all(x["status"] == expected for x in data["active_results"]))
            self.assertEqual(data["requests"], 1 if expected == "interrupted" else 2)


class ActiveNetworkTests(unittest.TestCase):
    def test_detection_matrix_real_sqlite_and_http(self):
        with active_server() as (server, base):
            data = verify(fixture_scope(base), matrix_plan(base), max_requests=100)
            self.assertEqual(len(data["active_results"]), len(MATRIX))
            for expected, actual in zip(MATRIX, data["active_results"]):
                with self.subTest(case=expected[4]):
                    self.assertEqual(actual["status"], expected[3])
            self.assertEqual(len(data["findings"]), sum(x[3] == "finding" for x in MATRIX))
            self.assertEqual(data["requests"], len(server.requests))
            self.assertTrue(all("outside" not in x["path"] for x in server.requests))
            serialized = json.dumps(data)
            self.assertNotIn("apple", serialized)  # DB row and original parameter not retained
            self.assertTrue(all(len(x["requests"]) <= 8 for x in data["active_results"]))

    def test_header_override_secret_redaction_and_report_merge(self):
        with active_server() as (server, base), tempfile.TemporaryDirectory() as tmp:
            checks = [{"type": "cors", "url": base + "/cors/open"}]
            data = verify(fixture_scope(base), checks, auth_headers={base: {"origin": "https://stale.invalid", "Authorization": "Bearer TOPSECRET"}})
            self.assertTrue(all(x["authorization"] == "Bearer TOPSECRET" for x in server.requests))
            self.assertNotEqual(server.requests[1]["origin"], "https://stale.invalid")
            write_report(data, tmp)
            merged = merge_reports([str(Path(tmp) / "report.json")])
            self.assertEqual(len(merged["active_results"]), 1)
            self.assertNotIn("TOPSECRET", (Path(tmp) / "report.json").read_text())

    def test_cli_complete_negative_and_incomplete_codes(self):
        with active_server() as (_, base), tempfile.TemporaryDirectory() as tmp:
            scope = Path(tmp) / "scope.json"
            scope.write_text(json.dumps({"targets": [base], "allowed_origins": [base], "delay": 0.1}))
            plan = Path(tmp) / "plan.json"
            for path, budget, fail_args, expected in (("/cors/open", 3, ["--fail-on", "medium"], 1),
                                                     ("/cors/strict", 3, [], 0), ("/cors/open", 2, [], 2)):
                plan.write_text(json.dumps({"checks": [{"type": "cors", "url": base + path}]}))
                with self.subTest(path=path, budget=budget), contextlib.redirect_stdout(io.StringIO()):
                    status = main(["verify", "--scope", str(scope), "--plan", str(plan), "--authorized", "--max-requests", str(budget), "--out", tmp] + fail_args)
                    self.assertEqual(status, expected)


if __name__ == "__main__":
    unittest.main()
