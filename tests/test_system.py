import contextlib
import io
import json
from pathlib import Path
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from auditkit.cli import main, read_headers
from auditkit.reports import add_evidence, empty_report, import_report, merge_reports, sanitize, write_report
from auditkit.scanner import inspect_response, scan
from auditkit.scope import Scope, canonical_url


class Handler(BaseHTTPRequestHandler):
    requests = []

    def do_GET(self):
        type(self).requests.append((self.path, self.headers.get("Authorization")))
        if self.path == "/large":
            body = b"x" * 10000
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", self.server.external + "/forbidden")
            self.end_headers()
            return
        if self.path == "/inside-redirect":
            self.send_response(302)
            self.send_header("Location", "/next")
            self.end_headers()
            return
        body = b'''<title>Real audit fixture</title><a href="/next">next</a>
        <a href="/next#fragment">duplicate</a><a href="/logout">logout</a>
        <a href="/query?token=secret">query</a><a href="/redirect">external redirect</a>
        <form method="GET"><input type="password"></form>'''
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Set-Cookie", "session=DO_NOT_SAVE; Path=/")
        self.send_header("Set-Cookie", "pref=ANOTHER_SECRET; Secure; HttpOnly; SameSite=Lax")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class ScopeTests(unittest.TestCase):
    def test_normalization_and_strict_origins(self):
        self.assertEqual(canonical_url("https://EXAMPLE.com:443/a#x"), "https://example.com/a")
        scope = Scope.from_dict({"targets": ["https://example.com/"], "allowed_origins": ["https://example.com"]})
        self.assertFalse(scope.permits("https://sub.example.com/"))
        self.assertFalse(scope.permits("http://example.com/"))
        self.assertFalse(scope.permits("https://example.com:8443/"))
        self.assertFalse(scope.permits("https://example.com/%6cogout"))

    def test_invalid_scope(self):
        base = {"targets": ["https://example.com/"], "allowed_origins": ["https://example.com"]}
        for fields in ({"delay": 0}, {"timeout": float("nan")}, {"max_pages": 1.5}, {"targets": ["https://other.test/"]}, {"allowed_origins": ["https://example.com/path"]}, {"typo": True}):
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                Scope.from_dict({**base, **fields})
        for url in ("file:///etc/passwd", "https://user:password@example.com", "https://example.com:0", "https://example.com/\n"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                canonical_url(url)


class NetworkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.server.external = "http://127.0.0.1:1"
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def setUp(self):
        Handler.requests = []

    def scope(self, path="/", **options):
        return Scope.from_dict({"targets": [self.base + path], "allowed_origins": [self.base], "delay": 0.1, **options})

    def test_real_http_crawl_scope_duplicates_and_cookies(self):
        data = scan(self.scope(max_pages=10), crawl=True, auth_headers={self.base: {"Authorization": "Bearer secret"}})
        self.assertEqual({x[0] for x in Handler.requests}, {"/", "/next", "/redirect"})
        self.assertEqual(data["requests"], 3)
        self.assertTrue(all(x[1] == "Bearer secret" for x in Handler.requests))
        self.assertEqual(len(data["pages"][0]["cookies"]), 2)
        self.assertNotIn("DO_NOT_SAVE", json.dumps(data))
        self.assertNotIn("ANOTHER_SECRET", json.dumps(data))
        self.assertIn("form.password_get", {x["rule"] for x in data["findings"]})
        self.assertFalse(data["errors"])

    def test_no_implicit_redirect(self):
        data = scan(self.scope("/inside-redirect"))
        self.assertEqual([x[0] for x in Handler.requests], ["/inside-redirect"])
        self.assertEqual(data["pages"][0]["status"], 302)

    def test_allowed_redirect_and_budget(self):
        data = scan(self.scope("/inside-redirect", max_pages=2), crawl=True)
        self.assertEqual([x[0] for x in Handler.requests], ["/inside-redirect", "/next"])
        self.assertEqual(data["requests"], 2)

    def test_failure_recorded_and_other_targets_continue(self):
        scope = self.scope()
        scope.targets.insert(0, self.server.external + "/")
        scope.allowed_origins.add(self.server.external)
        data = scan(scope)
        self.assertEqual(len(data["errors"]), 1)
        self.assertEqual(len(data["pages"]), 1)

    def test_body_size_limit(self):
        data = scan(self.scope("/large", max_bytes=1024))
        self.assertEqual(data["pages"][0]["body_bytes"], 1024)
        self.assertTrue(data["pages"][0]["body_truncated"])

    def test_safe_commands_real_local_server(self):
        from auditkit.safe import load_test, ports
        data = load_test(self.scope(), count=3, rps=10)
        self.assertEqual(data["requests"], 3)
        self.assertEqual(len(Handler.requests), 3)
        self.assertFalse(data["errors"])
        self.assertTrue(all(x["status"] == 200 for x in data["samples"]))
        tcp = ports(self.scope())
        self.assertEqual(tcp["ports"], [{"host": "127.0.0.1", "port": self.server.server_port, "state": "open"}])
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scope.json"
            path.write_text(json.dumps({"targets": [self.base], "allowed_origins": [self.base], "delay": .1}))
            for command in ("load", "ports"):
                with contextlib.redirect_stdout(io.StringIO()):
                    status = main([command, "--scope", str(path), "--authorized", "--ui", "off", "--out", str(Path(tmp) / command)])
                self.assertEqual(status, 0)
                self.assertTrue((Path(tmp) / command / "report.html").is_file())

    def test_pipeline_real_local_server(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scope.json"
            path.write_text(json.dumps({"targets": [self.base], "allowed_origins": [self.base], "delay": .1}))
            output = Path(tmp) / "out"
            with contextlib.redirect_stdout(io.StringIO()):
                status = main(["run", "--profile", "basic", "--scope", str(path), "--authorized", "--requests", "2", "--rps", "10", "--ui", "off", "--out", str(output)])
            self.assertEqual(status, 0)
            self.assertEqual(len(Handler.requests), 3)
            data = json.loads((output / "report.json").read_text())
            self.assertEqual(data["requests"], 4)
            self.assertEqual([x["mode"] for x in data["runs"]], ["targets", "tcp-inventory", "load-test"])
            self.assertEqual(data["load"]["planned_requests"], 2)

    def test_cli_creates_three_reports(self):
        with tempfile.TemporaryDirectory() as tmp:
            scope_path = Path(tmp) / "scope.json"
            scope_path.write_text(json.dumps({"targets": [self.base], "allowed_origins": [self.base]}))
            output = Path(tmp) / "out"
            with contextlib.redirect_stdout(io.StringIO()):
                status = main(["scan", "--scope", str(scope_path), "--authorized", "--out", str(output), "--fail-on", "medium"])
            self.assertEqual(status, 1)
            self.assertEqual({p.name for p in output.iterdir()}, {"report.json", "report.md", "report.html"})


class ReportTests(unittest.TestCase):
    def test_headers_file_origin_and_injection(self):
        scope = Scope.from_dict({"targets": ["https://example.com"], "allowed_origins": ["https://example.com"]})
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "headers.json"
            for payload in ({"https://other.test": {"Authorization": "secret"}}, {"https://example.com": {"Host": "other.test"}}, {"https://example.com": {"X-Test": "a\r\nb"}}):
                path.write_text(json.dumps(payload))
                with self.assertRaises(ValueError):
                    read_headers(path, scope)

    def test_escaping_redaction_and_evidence(self):
        data = empty_report()
        data["findings"] = [{"title": "<script>alert(1)</script>", "severity": "info", "evidence": {"Authorization": "Bearer SECRET"}}]
        add_evidence(data, "test", "denied", "https://user:pass@example.com/a?token=SECRET")
        with tempfile.TemporaryDirectory() as tmp:
            write_report(data, tmp)
            text = (Path(tmp) / "report.html").read_text()
            self.assertNotIn("<script>", text)
            self.assertNotIn("SECRET", text)
            self.assertNotIn("user:pass", text)
            self.assertIn("&lt;script&gt;", text)

    def test_secret_text(self):
        text = sanitize('Cookie: TOPSECRET\nAuthorization: Bearer ABC\n{"password": "PASS"}\nhttps://example.com/?key=PRIVATE')
        for value in ("TOPSECRET", "ABC", "PASS", "PRIVATE"):
            self.assertNotIn(value, text)

    def test_import_nuclei_zap_and_dedup(self):
        with tempfile.TemporaryDirectory() as tmp:
            nuclei = Path(tmp) / "nuclei.jsonl"
            nuclei.write_text(json.dumps({"template-id": "test", "matched-at": "https://example.com/?token=secret", "info": {"name": "Test", "severity": "low"}}) + "\n")
            zap = Path(tmp) / "zap.json"
            zap.write_text(json.dumps({"site": [{"alerts": [{"pluginid": "42", "alert": "Header", "riskcode": "1", "instances": [{"uri": "https://example.com/", "evidence": "absent"}]}]}]}))
            data = merge_reports([nuclei, nuclei, zap])
            self.assertEqual(len(data["findings"]), 2)
            self.assertTrue(all(x["confidence"] == "unverified-tool-alert" for x in data["findings"]))
            self.assertNotIn("token=secret", json.dumps(data))
            unsupported = Path(tmp) / "unknown.json"
            unsupported.write_text('{"other": true}')
            with self.assertRaises(ValueError):
                import_report(unsupported)

    def test_partial_run_error_exit(self):
        with tempfile.TemporaryDirectory() as tmp, patch("auditkit.cli.scan", return_value={**empty_report(), "errors": [{"type": "SSLCertVerificationError"}]}):
            path = Path(tmp) / "scope.json"
            path.write_text('{"targets":["https://example.com"],"allowed_origins":["https://example.com"]}')
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["scan", "--scope", str(path), "--authorized", "--out", tmp]), 2)

    def test_https_mixed_content_and_base(self):
        response = {"status": 200, "headers": [("Content-Type", "text/html")],
                    "body": b'<base href="https://other.test/"><img src="http://cdn.test/a"><a href="page">p</a>',
                    "tls": None, "truncated": False, "elapsed": 0.1}
        page, issues, links = inspect_response("https://example.com", response)
        self.assertIn("content.mixed", {x["rule"] for x in issues})
        self.assertEqual(links, ["https://other.test/page"])

    def test_malformed_html_urls_do_not_discard_page(self):
        response = {"status": 200, "headers": [("Content-Type", "text/html")],
                    "body": b'<a href="http://[invalid">bad</a><form action="javascript:void(0)"></form><img src="http://[bad">',
                    "tls": None, "truncated": False, "elapsed": 0.1}
        page, _, links = inspect_response("https://example.com/", response)
        self.assertEqual(page["status"], 200)
        self.assertEqual(links, [])

    def test_authentication_is_bound_to_exact_origin(self):
        scope = Scope.from_dict({"targets": ["https://a.test", "https://b.test"], "allowed_origins": ["https://a.test", "https://b.test"], "delay": 0.1})
        response = {"status": 200, "headers": [], "body": b"", "tls": None, "truncated": False, "elapsed": 0.1}
        with patch("auditkit.scanner.fetch", return_value=response) as fetch:
            scan(scope, auth_headers={"https://a.test": {"Authorization": "Bearer secret"}})
        self.assertEqual(fetch.call_args_list[0].args[2], {"Authorization": "Bearer secret"})
        self.assertIsNone(fetch.call_args_list[1].args[2])


if __name__ == "__main__":
    unittest.main()
