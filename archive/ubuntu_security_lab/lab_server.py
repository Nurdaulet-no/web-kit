from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path not in ('/', '/health'):
            self.send_error(404)
            return
        body = (b'<html><head><title>Local Security Lab</title></head>'
                b'<body><h1>Local Security Lab</h1><p>Safe local training target.</p></body></html>')
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Security-Policy', "default-src 'self'")
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

if __name__ == '__main__':
    ThreadingHTTPServer(('127.0.0.1', 8765), Handler).serve_forever()
