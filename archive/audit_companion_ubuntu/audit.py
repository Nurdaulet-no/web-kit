#!/usr/bin/env python3
"""Training-first web audit companion. No active scanning of external hosts."""
import argparse
import datetime
import html
import http.server
import json
import pathlib
import shutil
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent
REPORTS = ROOT / 'reports'

class LabHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        route = parsed.path
        if route == '/':
            body = b'<h1>Training App</h1><p>Try /api/profile/101 using X-Lab-User: B</p>'
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
        elif route == '/api/profile/101':
            # Intentionally vulnerable LOCAL TRAINING ENDPOINT ONLY
            body = json.dumps({'owner':'A','private_note':'OWNED_BY_A_TEST_DATA','requester':self.headers.get('X-Lab-User', '-')}).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
        else:
            body = b'Not found'
            self.send_response(404)
            self.send_header('Content-Type', 'text/plain')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, fmt, *args):
        print('lab:', fmt % args)

def request(url, headers=None):
    req = urllib.request.Request(url, headers=headers or {'User-Agent': 'AuditCompanion/1.0'})
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, request, fp, code, msg, headers, newurl):
            return None
    opener = urllib.request.build_opener(NoRedirect())
    try:
        with opener.open(req, timeout=8) as response:
            return response.status, dict(response.headers.items()), response.read(32768).decode('utf-8', 'replace')
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers.items()), e.read(32768).decode('utf-8', 'replace')

def write_report(folder, title, lines, evidence=None):
    folder.mkdir(parents=True, exist_ok=True)
    (folder / 'report.md').write_text('# ' + title + '\n\n' + '\n'.join(lines) + '\n', encoding='utf-8')
    payload = {'title': title, 'date_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'observations':lines, 'evidence':evidence or {}}
    (folder / 'report.json').write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding='utf-8')
    sections = ''.join(f'<li>{html.escape(line)}</li>' for line in lines)
    ev = ''.join(f'<h2>{html.escape(k)}</h2><pre>{html.escape(str(v))}</pre>' for k,v in (evidence or {}).items())
    (folder/'report.html').write_text('<!doctype html><meta charset="utf-8"><title>Audit report</title><style>body{font:16px system-ui;max-width:900px;margin:48px auto;padding:0 20px}pre{background:#eee;padding:16px;white-space:pre-wrap;overflow-wrap:anywhere}</style><h1>'+html.escape(title)+'</h1><ul>'+sections+'</ul>'+ev, encoding='utf-8')
    print('Saved:', folder / 'report.html')

def doctor():
    for exe in ['python3','curl','java','nuclei','zaproxy','docker']:
        print(f'{exe:10}', shutil.which(exe) or 'NOT FOUND (optional except python3)')
    print('Burp is GUI/manual: check via your application launcher.')

def local_demo():
    base = 'http://127.0.0.1:8765'
    try:
        status_a, _, body_a = request(base + '/api/profile/101', {'X-Lab-User':'A'})
        status_b, _, body_b = request(base + '/api/profile/101', {'X-Lab-User':'B'})
    except (urllib.error.URLError, TimeoutError) as e:
        print('Start the lab in a second terminal first: python3 audit.py serve', file=sys.stderr)
        print(str(e), file=sys.stderr)
        return 2
    a, b = json.loads(body_a), json.loads(body_b)
    finding = status_a == 200 and status_b == 200 and b.get('owner') == 'A' and b.get('private_note') == a.get('private_note')
    lines = [f'Account A request: HTTP {status_a}', f'Account B request: HTTP {status_b}', 'Same private record returned to B: '+str(finding), 'This is a deliberately vulnerable local fixture, NOT a finding on a real website.', 'Never treat an HTTP 200 alone as proof of unauthorized access.']
    write_report(REPORTS/'lab', 'Local IDOR training demonstration',lines, {'A response':body_a,'B response':body_b})
    return 0 if finding else 1

def inspect(url):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password:
        print('For an external URL use an HTTPS URL without embedded credentials.', file=sys.stderr)
        return 2
    if parsed.port not in (None, 443):
        print('Use default HTTPS port for baseline external inspection.',file=sys.stderr)
        return 2
    try:
        code, hdr, body = request(url)
    except (urllib.error.URLError, TimeoutError) as e:
        print('Request failed:', e, file=sys.stderr)
        return 2
    normalized = {k.lower(): v for k,v in hdr.items()}
    checks = ['content-security-policy','strict-transport-security','x-content-type-options','referrer-policy']
    lines = [f'URL: {url}',f'HTTP status: {code}',f'HTML/text preview length: {len(body)}', 'A missing security header alone is not a critical vulnerability.']
    lines += [f'{name}: '+('present' if name in normalized else 'not observed') for name in checks]
    out = REPORTS/'external'
    # Avoid storing body by default: may contain personal data or secrets.
    write_report(out, 'Single-request passive HTTPS inspection', lines, {'HTTP headers': '\n'.join(f'{k}: {v}' for k,v in hdr.items() if k.lower() not in ('set-cookie', 'authorization'))})
    return 0

def main():
    p=argparse.ArgumentParser(description='Non-destructive audit companion and local training lab.')
    sub=p.add_subparsers(dest='cmd', required=True)
    sub.add_parser('doctor')
    sub.add_parser('serve')
    sub.add_parser('lab-demo')
    target=sub.add_parser('inspect', help='Exactly one GET, no redirects, no active scan')
    target.add_argument('url')
    args=p.parse_args()
    if args.cmd=='doctor': doctor(); return 0
    if args.cmd=='serve':
        print('LOCAL TRAINING LAB ONLY: http://127.0.0.1:8765')
        http.server.ThreadingHTTPServer(('127.0.0.1',8765), LabHandler).serve_forever()
        return 0
    if args.cmd=='lab-demo': return local_demo()
    if args.cmd=='inspect': return inspect(args.url)
    return 2

if __name__=='__main__': sys.exit(main())
