"""Disposable test service: actual SQLite queries and contrasting output policies."""
from contextlib import closing, contextmanager
import html
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import sqlite3
import threading
from urllib.parse import parse_qs, urlsplit


class ActiveHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.requests.append({"path": self.path, "origin": self.headers.get("Origin"),
                                     "authorization": self.headers.get("Authorization")})
        p = urlsplit(self.path)
        args = parse_qs(p.query, keep_blank_values=True)
        value = args.get("id", args.get("q", ["1"]))[0]
        status, mime, extra = 200, "text/html; charset=utf-8", []
        if p.path.startswith("/sql/"):
            if p.path == "/sql/waf" and " AND " in value:
                status, body = 403, "blocked"
            elif p.path == "/sql/echo":
                body = "<p>Search: " + html.escape(value) + "</p>"
            else:
                with closing(sqlite3.connect(":memory:")) as connection:
                    connection.execute("CREATE TABLE items (id INTEGER, name TEXT)")
                    connection.execute("INSERT INTO items VALUES (1, 'apple')")
                    try:
                        if p.path == "/sql/numeric":
                            rows = connection.execute("SELECT name FROM items WHERE id=" + value).fetchall()
                        elif p.path == "/sql/two":
                            rows = connection.execute("SELECT name,id FROM items WHERE id=" + value).fetchall()
                        elif p.path == "/sql/three":
                            rows = connection.execute("SELECT name,id,id+10 FROM items WHERE id=" + value).fetchall()
                        elif p.path == "/sql/string":
                            rows = connection.execute("SELECT name FROM items WHERE name='" + value + "'").fetchall()
                        else:
                            rows = connection.execute("SELECT name FROM items WHERE id=?", (value,)).fetchall()
                        body = json.dumps(rows)
                    except sqlite3.Error:
                        body, status = "query error", 500
                if p.path == "/sql/dynamic":
                    body += str(len(self.server.requests))
        elif p.path == "/html/raw":
            body = "<main>" + value + "</main>"
        elif p.path == "/html/escaped":
            body = "<main>" + html.escape(value) + "</main>"
        elif p.path == "/html/attribute":
            body = '<input value="' + html.escape(value, quote=True) + '">'
        elif p.path == "/html/textarea":
            body = "<textarea>" + value + "</textarea>"
        elif p.path == "/html/script":
            body = "<script>let text=" + json.dumps(value) + ";</script>"
        elif p.path == "/html/json":
            body, mime = json.dumps({"value": value}), "application/json"
        elif p.path == "/truncated":
            body = "x" * 2048
        elif p.path == "/redirect":
            status, body = 302, "redirect"
            extra.append(("Location", "http://127.0.0.1:1/outside"))
        elif p.path.startswith("/cors/"):
            supplied = self.headers.get("Origin")
            body, mime = '{"test":"fixture-only"}', "application/json"
            if supplied:
                allow_origin = supplied
                if p.path == "/cors/strict":
                    allow_origin = "https://trusted.invalid"
                elif p.path == "/cors/wildcard":
                    allow_origin = "*"
                extra.append(("Access-Control-Allow-Origin", allow_origin))
                if p.path == "/cors/duplicate":
                    extra.append(("Access-Control-Allow-Origin", supplied))
                if p.path != "/cors/nocredentials":
                    extra.append(("Access-Control-Allow-Credentials", "true"))
        else:
            status, body = 404, "not found"
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(payload)))
        for key, val in extra:
            self.send_header(key, val)
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


@contextmanager
def active_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), ActiveHandler)
    server.requests = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server, f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


# Labels express expected probe behavior, not general security of each endpoint.
MATRIX = [
    ("sqli-union", "/sql/numeric?id=1", "id", "finding", "UNION canary: numeric, one column"),
    ("sqli-union", "/sql/string?id=apple", "id", "finding", "UNION canary: string, one column"),
    ("sqli-union", "/sql/two?id=1", "id", "finding", "UNION canary: two columns"),
    ("sqli-union", "/sql/three?id=1", "id", "finding", "UNION canary: three columns"),
    ("sqli-union", "/sql/protected?id=1", "id", "not-detected", "UNION: parameterized SQL"),
    ("sqli-union", "/sql/echo?id=1", "id", "not-detected", "UNION: reflection cannot assemble split canary"),
    ("sqli-boolean", "/sql/numeric?id=1", "id", "finding", "numeric SQLite injection"),
    ("sqli-boolean", "/sql/string?id=apple", "id", "finding", "string SQLite injection"),
    ("html-injection", "/html/raw?q=hello", "q", "finding", "unescaped HTML"),
    ("cors", "/cors/open", None, "finding", "arbitrary credentialed CORS"),
    ("sqli-boolean", "/sql/protected?id=1", "id", "not-detected", "parameterized SQL"),
    ("sqli-boolean", "/sql/echo?id=1", "id", "not-detected", "input reflection only"),
    ("html-injection", "/html/escaped?q=hello", "q", "not-detected", "HTML escaping"),
    ("html-injection", "/html/attribute?q=hello", "q", "not-detected", "escaped attribute"),
    ("html-injection", "/html/textarea?q=hello", "q", "not-detected", "inert textarea context"),
    ("html-injection", "/html/script?q=hello", "q", "not-detected", "marker string in script"),
    ("cors", "/cors/strict", None, "not-detected", "exact origin allowlist"),
    ("cors", "/cors/wildcard", None, "not-detected", "wildcard is not credentialed CORS"),
    ("cors", "/cors/duplicate", None, "not-detected", "duplicate invalid ACAO"),
    ("cors", "/cors/nocredentials", None, "not-detected", "no credentials permission"),
    ("sqli-boolean", "/sql/dynamic?id=1", "id", "inconclusive", "changing baseline"),
    ("sqli-boolean", "/sql/waf?id=1", "id", "inconclusive", "blocked probes are not SQLi proof"),
    ("html-injection", "/html/json?q=hello", "q", "inconclusive", "JSON is not HTML"),
    ("cors", "/truncated", None, "inconclusive", "truncated baseline"),
    ("cors", "/redirect", None, "inconclusive", "no redirect following"),
]


def matrix_plan(base):
    return [{"type": kind, "url": base + path, **({"parameter": parameter} if parameter else {})}
            for kind, path, parameter, _, _ in MATRIX]
