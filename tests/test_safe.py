import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from auditkit.cli import main
from auditkit.reports import write_report, merge_reports
from auditkit.safe import load_test, ports, review_code
from auditkit.scope import Scope
from auditkit.tui import TerminalUI


def scope():
    return Scope.from_dict({"targets": ["https://a.test/path?token=PRIVATE"],
                            "allowed_origins": ["https://a.test", "https://a.test:8443"], "delay": .1})


def response(status=200):
    return {"status": status, "elapsed": .05, "truncated": False}


class SafeTests(unittest.TestCase):
    def test_load_validates_all_inputs_without_network(self):
        for count, rps in ((11, 1), (True, 1), (1, float("nan")), (1, 11)):
            with self.subTest(count=count, rps=rps), patch("auditkit.safe.fetch") as fetch:
                with self.assertRaises(ValueError):
                    load_test(scope(), count, rps)
                fetch.assert_not_called()
        bad = scope()
        bad.targets.append("https://outside.test")
        with patch("auditkit.safe.fetch") as fetch, self.assertRaises(ValueError):
            load_test(bad)
        fetch.assert_not_called()

    def test_load_stops_on_backpressure_and_keeps_private_headers(self):
        with patch("auditkit.safe.fetch", side_effect=[response(), response(429)]) as fetch, patch("auditkit.safe.time.sleep"):
            events = []
            data = load_test(scope(), 10, 10, {"https://a.test": {"Authorization": "Bearer SECRET"}}, events.append)
        self.assertEqual(fetch.call_count, 2)
        self.assertEqual(fetch.call_args.args[2], {"Authorization": "Bearer SECRET"})
        self.assertEqual(data["errors"][0]["type"], "SafetyStop")
        self.assertEqual(data["load"]["p95_seconds"], .05)
        self.assertTrue(events[-1]["finished"])
        self.assertNotIn("PRIVATE", json.dumps(data))
        self.assertNotIn("SECRET", json.dumps(data))

    def test_load_three_errors_and_interrupt_save_partial_report(self):
        with patch("auditkit.safe.fetch", side_effect=TimeoutError), patch("auditkit.safe.time.sleep"):
            data = load_test(scope())
        self.assertEqual(data["requests"], 3)
        self.assertEqual(data["errors"][-1]["type"], "SafetyStop")
        with patch("auditkit.safe.fetch", side_effect=[response(), KeyboardInterrupt]), patch("auditkit.safe.time.sleep"):
            data = load_test(scope())
        self.assertEqual(len(data["samples"]), 1)
        self.assertEqual(data["errors"][-1]["type"], "Interrupted")

    def test_tcp_only_explicit_endpoints_and_unknown_errors(self):
        with patch("auditkit.safe.socket.create_connection", side_effect=[contextlib.nullcontext(), TimeoutError]) as connect, patch("auditkit.safe.time.sleep"):
            data = ports(scope())
        self.assertEqual([x.args[0] for x in connect.call_args_list], [("a.test", 443), ("a.test", 8443)])
        self.assertEqual([x["state"] for x in data["ports"]], ["open", "unknown"])
        self.assertEqual(len(data["errors"]), 1)

    def test_static_review_no_secret_source_or_symlink_following(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "config.py").write_text('DEBUG = True\nSECRET_KEY = "PRIVATE_SECRET_123"\neval(user_input)\n')
            (root / "alias.py").symlink_to(root / "config.py")
            data = review_code(root)
            self.assertEqual(data["files_reviewed"], 1)
            self.assertEqual({x["rule"] for x in data["findings"]}, {"code.debug", "code.secret", "code.dynamic_execution"})
            self.assertNotIn("PRIVATE_SECRET_123", json.dumps(data))
            write_report(data, root / "out")
            page = (root / "out" / "report.html").read_text()
            self.assertIn("Таймлайн", page)
            self.assertIn("@media print", page)
            self.assertNotIn("PRIVATE_SECRET_123", page)
            self.assertEqual(len(merge_reports([root / "out" / "report.json"])["timeline"]), len(data["timeline"]))

    def test_plain_terminal_strips_escape_sequences_and_cleans_up(self):
        stream = io.StringIO()
        with TerminalUI("on", stream) as ui:
            ui({"timestamp": "2026-11-11T00:00:00", "message": "test\x1b[2J", "completed": 1, "total": 1, "finished": True})
        self.assertNotIn("\x1b", stream.getvalue())
        self.assertIn("100%", stream.getvalue())
        tty = io.StringIO()
        tty.isatty = lambda: True
        with patch.dict("os.environ", {"TERM": "xterm"}):
            with self.assertRaises(RuntimeError), TerminalUI("on", tty):
                raise RuntimeError()
        self.assertTrue(tty.getvalue().endswith("\x1b[?25h\x1b[?1049l"))

    def test_code_cli_and_threshold(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text("DEBUG = True\n")
            with contextlib.redirect_stdout(io.StringIO()):
                status = main(["code", "--path", tmp, "--out", str(root / "out"), "--ui", "off", "--fail-on", "medium"])
            self.assertEqual(status, 1)
            self.assertTrue((root / "out" / "report.html").is_file())
