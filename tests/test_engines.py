import contextlib
import io
import json
from pathlib import Path
import shutil
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from auditkit.engines import Captures, execute, k6_script, run_engine
from auditkit.events import Events
from auditkit.production import run_production
from auditkit.reports import write_report, merge_reports
from auditkit.scope import Scope


def scope(url="http://127.0.0.1:8080/"):
    from auditkit.scope import origin
    return Scope.from_dict({"targets": [url], "allowed_origins": [origin(url)], "delay": .1})


class EngineTests(unittest.TestCase):
    def test_process_timeout_log_redaction_and_failure(self):
        result = execute([sys.executable, "-c", "import time; print('Authorization: SECRET', flush=True); time.sleep(10)"], .2)
        self.assertEqual(result["status"], "timeout")
        self.assertNotIn("SECRET", result["log"])
        result = execute([sys.executable, "-c", "raise SystemExit(7)"], 5)
        self.assertEqual(result["exit_code"], 7)

    def test_missing_engine_never_counts_as_completed(self):
        with patch("auditkit.engines.inventory", return_value={"nmap": None}), tempfile.TemporaryDirectory() as tmp:
            record = run_engine("nmap", scope(), tmp, None, Events())
        self.assertEqual(record["status"], "unavailable")

    def test_interrupt_during_resolution_retains_status(self):
        with tempfile.TemporaryDirectory() as tmp, patch("auditkit.engines.inventory", return_value={"nmap": "nmap"}), patch("auditkit.engines.execute", return_value={"status": "completed", "log": "nmap test", "exit_code": 0}), patch("auditkit.engines.socket.getaddrinfo", side_effect=KeyboardInterrupt):
            result = run_engine("nmap", scope(), tmp, None, Events())
            self.assertEqual(result["status"], "interrupted")
            self.assertTrue((Path(tmp) / "nmap" / "engine.json").is_file())

    def test_k6_script_prevents_redirects_and_uses_exact_origin_headers(self):
        script = k6_script(scope(), 2, 1, {"http://other.test": {"Authorization": "NO_LEAK"}}, "/tmp/summary.json")
        self.assertNotIn("NO_LEAK", script)
        self.assertIn("maxRedirects:0", script)
        self.assertIn("insecureSkipTLSVerify:false", script)
        self.assertIn("exec.test.abort", script)

    def test_passive_commands_only_consume_captures(self):
        from auditkit.engines import nuclei_scan, zap_scan
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            captures = Captures(root)
            captures("https://example.test/", {"headers": [("Content-Type", "text/html")], "body": b"<h1>test</h1>", "status": 200, "elapsed": .1})
            def fake(command, *args, **kwargs):
                if command[0] == "nuclei":
                    (root / "nuclei.jsonl").write_text("")
                else:
                    plan = json.loads((root / "zap-plan.yaml").read_text())
                    self.assertFalse(plan["jobs"][0]["parameters"].get("sendRequests", False))
                    self.assertEqual([job["type"] for job in plan["jobs"]], ["import", "passiveScan-wait", "report"])
                    self.assertEqual(plan["env"]["contexts"][0]["urls"], ["https://example.test"])
                    (root / "zap.json").write_text('{"site":[]}')
                return {"status": "completed", "exit_code": 0}
            with patch("auditkit.engines.execute", side_effect=fake) as process, patch.dict("os.environ", {"AUDIT_NUCLEI_TEMPLATES": tmp}):
                self.assertEqual(nuclei_scan("nuclei", captures, root, None)["status"], "completed")
                args = process.call_args.args[0]
                self.assertIn("-passive", args)
                self.assertIn("-ni", args)
                self.assertNotIn("https://example.test/", args)
                self.assertEqual(zap_scan("zap", captures, root, None)["status"], "completed")

    def test_production_missing_tools_and_report_coverage(self):
        response = {"status": 200, "headers": [("Content-Type", "text/html")], "body": b"ok", "tls": None, "truncated": False, "elapsed": .1}
        with tempfile.TemporaryDirectory() as tmp, patch("auditkit.scanner.fetch", return_value=response), patch("auditkit.engines.inventory", return_value={x: None for x in ("nmap", "k6", "nuclei", "zap")}):
            data = run_production(scope(), tmp, 2, 1, {}, None, None, False)
            self.assertEqual(data["execution_status"], "incomplete")
            self.assertEqual(sum(x["status"] == "unavailable" for x in data["coverage"]), 4)
            self.assertEqual(len(data["errors"]), 4)
            write_report(data, tmp)
            self.assertIn("Пробелы".lower(), (Path(tmp) / "report.html").read_text().lower())
            self.assertTrue(data["coverage_gaps"])
            merged = merge_reports([Path(tmp) / "report.json"])
            self.assertEqual(merged["coverage"], data["coverage"])
            self.assertEqual(merged["execution_status"], "incomplete")


class LocalHandler(BaseHTTPRequestHandler):
    requests = []
    def do_GET(self):
        type(self).requests.append(self.path)
        self.send_response(429 if self.path == "/busy" else 302 if self.path == "/redirect" else 200)
        if self.path == "/redirect":
            self.send_header("Location", "/forbidden")
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")
    def handle(self):
        try:
            super().handle()
        except ConnectionResetError:
            pass
    def log_message(self, *args):
        pass


@unittest.skipUnless(shutil.which("k6") and shutil.which("nmap"), "Real k6 and nmap required")
class EngineIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), LocalHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f"http://127.0.0.1:{cls.server.server_port}"
    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()
    def setUp(self):
        LocalHandler.requests = []

    def test_real_nmap_and_k6(self):
        with tempfile.TemporaryDirectory() as tmp:
            s = scope(self.url + "/")
            nmap = run_engine("nmap", s, tmp, None, Events(), count=2, rps=10)
            self.assertEqual(nmap["status"], "completed", nmap)
            self.assertEqual(nmap["ports"][0]["state"], "open")
            self.assertEqual(nmap["ports"][0]["port"], self.server.server_port)
            k6 = run_engine("k6", s, tmp, None, Events(), count=2, rps=10)
            self.assertEqual(k6["status"], "completed", k6)
            self.assertEqual(k6["requests"], 2)
            self.assertEqual(LocalHandler.requests, ["/", "/"])
            self.assertIn("http_req_duration", k6["metrics"]["metrics"])
            # Keep actual local-engine evidence for review when requested by the harness.
            import os
            evidence = os.environ.get("AUDIT_ENGINE_EVIDENCE")
            if evidence:
                Path(evidence).mkdir(parents=True, exist_ok=True)
                (Path(evidence) / "real-engines.json").write_text(json.dumps({"nmap": nmap, "k6": k6}, ensure_ascii=False, indent=2))

    def test_real_production_cli_reports_incomplete_coverage(self):
        from auditkit.cli import main
        from auditkit.engines import inventory
        tools = inventory()
        tools.update(nuclei=None, zap=None)
        with tempfile.TemporaryDirectory() as tmp, patch("auditkit.engines.inventory", return_value=tools), contextlib.redirect_stdout(io.StringIO()):
            code = main(["run", "--url", self.url + "/", "--authorized", "--requests", "2", "--out", tmp, "--ui", "off"])
            self.assertEqual(code, 2)
            data = json.loads((Path(tmp) / "report.json").read_text())
            states = {x["engine"]: x["status"] for x in data["coverage"]}
            self.assertEqual(states["nmap"], "completed")
            self.assertEqual(states["k6"], "completed")
            self.assertEqual(states["nuclei"], "unavailable")
            self.assertEqual(data["execution_status"], "incomplete")
            self.assertEqual(data["requests"], 3)
            self.assertEqual(len(LocalHandler.requests), 3)
            self.assertTrue((Path(tmp) / "report.html").is_file())

    @unittest.skipUnless(shutil.which("openssl"), "OpenSSL required for local TLS fixture")
    def test_real_nmap_certificate_script(self):
        import ssl
        import subprocess
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cert, key = root / "cert.pem", root / "key.pem"
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(cert),
                            "-days", "1", "-subj", "/CN=localhost"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            server = ThreadingHTTPServer(("127.0.0.1", 0), LocalHandler)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert, key)
            server.socket = context.wrap_socket(server.socket, server_side=True)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                result = run_engine("nmap", scope(f"https://127.0.0.1:{server.server_port}/"), tmp, None, Events())
                self.assertEqual(result["status"], "completed", result)
                self.assertIn("ssl-cert", [x["id"] for x in result["ports"][0]["scripts"]])
            finally:
                server.shutdown()
                server.server_close()
                thread.join()

    def test_real_k6_stops_on_429_and_never_follows_redirects(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = run_engine("k6", scope(self.url + "/busy"), tmp, None, Events(), count=5, rps=10)
            self.assertEqual(result["status"], "error")
            self.assertEqual(LocalHandler.requests, ["/busy"])
            LocalHandler.requests = []
            result = run_engine("k6", scope(self.url + "/redirect"), tmp, None, Events(), count=2, rps=10)
            self.assertEqual(result["status"], "completed", result)
            self.assertEqual(LocalHandler.requests, ["/redirect", "/redirect"])
