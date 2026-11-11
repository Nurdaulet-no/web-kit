import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from auditkit.cli import main
from auditkit.pipeline import run_pipeline
from auditkit.reports import empty_report
from auditkit.scope import Scope


class PipelineTests(unittest.TestCase):
    def scope(self):
        return Scope.from_dict({"targets": ["https://example.test/"], "allowed_origins": ["https://example.test"]})

    def test_cli_url_order_reports_and_shared_progress(self):
        order = []
        def stage(name):
            def execute(scope, *args, **kwargs):
                order.append(name)
                self.assertEqual(scope.targets, ["https://example.test/path?token=PRIVATE"])
                self.assertEqual(scope.allowed_origins, {"https://example.test"})
                callback = kwargs.get("on_event") or args[-1]
                callback({"timestamp": "2026-11-11T00:00:00+00:00", "message": "done", "completed": 1, "total": 1, "finished": True})
                return {**empty_report(), "mode": name, "requests": 1}
            return execute
        with tempfile.TemporaryDirectory() as tmp, patch("auditkit.pipeline.scan", side_effect=stage("scan")), patch("auditkit.pipeline.ports", side_effect=stage("ports")), patch("auditkit.pipeline.load_test", side_effect=stage("load")), contextlib.redirect_stdout(io.StringIO()):
            status = main(["run", "--profile", "basic", "--url", "https://example.test/path?token=PRIVATE", "--authorized", "--ui", "off", "--out", tmp])
            self.assertEqual(status, 0)
            self.assertEqual(order, ["scan", "ports", "load"])
            report_text = (Path(tmp) / "report.json").read_text()
            self.assertNotIn("PRIVATE", report_text)
            data = json.loads(report_text)
            self.assertEqual(data["requests"], 3)
            self.assertEqual([x["completed"] for x in data["timeline"]], [1, 2, 3, 3])
            for name in order:
                self.assertTrue((Path(tmp) / name / "report.html").is_file())

    def test_no_arguments_prompts_then_runs_with_validated_url(self):
        report = {**empty_report(), "summary": {"pages": 0, "findings": 0, "errors": 0}}
        with patch("builtins.input", side_effect=["", "ftp://example.test", " example.test/path "]) as prompt, patch("auditkit.cli.run_pipeline", return_value=report) as pipeline, patch("auditkit.cli.write_report", return_value=report), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(main([]), 0)
        self.assertEqual(prompt.call_count, 3)
        self.assertIn("Некорректный URL", output.getvalue())
        scope = pipeline.call_args.args[0]
        self.assertEqual(scope.targets, ["https://example.test/path"])
        self.assertEqual(scope.allowed_origins, {"https://example.test"})
        self.assertEqual(pipeline.call_args.args[2:4], (10, 1.0))
        self.assertEqual(pipeline.call_args.kwargs["profile"], "production")

    def test_prompt_cancellation_does_not_start_network(self):
        for error in (EOFError, KeyboardInterrupt):
            with self.subTest(error=error), patch("builtins.input", side_effect=error), patch("auditkit.cli.run_pipeline") as pipeline, contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main([]), 2)
                pipeline.assert_not_called()

    def test_preflight_and_partial_error_stop(self):
        with tempfile.TemporaryDirectory() as tmp, patch("auditkit.pipeline.scan") as scan, patch("auditkit.pipeline.ports") as ports:
            with self.assertRaises(ValueError):
                run_pipeline(self.scope(), tmp, count=11)
            scan.assert_not_called()
            with self.assertRaises(ValueError):
                run_pipeline(self.scope(), tmp, code_path=Path(tmp) / "missing")
            scan.assert_not_called()
            scan.return_value = {**empty_report(), "errors": [{"type": "Interrupted"}]}
            result = run_pipeline(self.scope(), tmp)
            ports.assert_not_called()
            self.assertEqual(result["skipped_stages"], ["ports", "load"])
            self.assertEqual(result["errors"][0]["type"], "Interrupted")
