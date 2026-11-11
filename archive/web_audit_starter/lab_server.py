#!/usr/bin/env python3
"""Local-only mock site: a safe target for testing reporting and error handling."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'<!doctype html><html><head><title>Practice Lab</title></head><body><h1>Practice</h1><form method="post" action="/login"><input name="user"></form><script>console.log("lab")</script></body></html>'
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

if __name__ == "__main__":
    server = ThreadingHTTPServer(("127.0.0.1", 8765), Handler)
    print("Training server: http://127.0.0.1:8765")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
