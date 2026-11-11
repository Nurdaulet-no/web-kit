from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            body = b'<!doctype html><title>Local training lab</title><h1>Local training lab</h1><a href="/help">Help</a>'
            self.send_response(200)
        elif self.path == '/help':
            body = b'<h1>Practice inspecting HTTP responses</h1>'
            self.send_response(200)
        else:
            body = b'not found'
            self.send_response(404)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

if __name__ == '__main__':
    ThreadingHTTPServer(('127.0.0.1', 8765), Handler).serve_forever()
