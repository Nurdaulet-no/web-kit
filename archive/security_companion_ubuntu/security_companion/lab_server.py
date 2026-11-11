from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path not in ('/','/health'):
            self.send_error(404); return
        data= (b'<html><head><title>Local Classroom Lab</title></head><body><h1>Lab ready</h1><p>Local-only practice server.</p></body></html>' if self.path=='/' else b'OK')
        self.send_response(200); self.send_header('Content-Type','text/html; charset=utf-8' if self.path=='/' else 'text/plain'); self.send_header('Content-Length',str(len(data))); self.send_header('X-Content-Type-Options','nosniff'); self.end_headers(); self.wfile.write(data)
def serve():
    httpd=ThreadingHTTPServer(('127.0.0.1',8765),Handler)
    print('Lab: http://127.0.0.1:8765/ (Ctrl+C to stop)',flush=True)
    try: httpd.serve_forever()
    except KeyboardInterrupt: pass
    finally: httpd.server_close()
if __name__=='__main__': serve()
