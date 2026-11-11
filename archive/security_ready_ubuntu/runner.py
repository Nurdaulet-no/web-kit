#!/usr/bin/env python3
"""Conservative security audit orchestration for a local lab and consented HTTP targets."""
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import time
from urllib.parse import urlsplit, urlunsplit
from urllib.request import Request, build_opener, HTTPHandler, HTTPSHandler
from urllib.error import HTTPError, URLError

ROOT = Path(__file__).resolve().parent
OUT = ROOT / 'reports'
LOCAL = 'http://127.0.0.1:8765/'

class NoRedirect(__import__('urllib.request', fromlist=['HTTPRedirectHandler']).HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None

def validate_target(target, local_only=False):
    p = urlsplit(target)
    if p.scheme not in ('http', 'https') or not p.hostname or p.username or p.password or p.fragment:
        raise ValueError('Expected http(s) URL with hostname, no credentials or fragment')
    if local_only and (p.hostname not in ('127.0.0.1', 'localhost') or p.port != 8765 or p.scheme != 'http'):
        raise ValueError('Local integrations only work on http://127.0.0.1:8765/')
    if not local_only and p.scheme != 'https' and p.hostname not in ('localhost', '127.0.0.1'):
        raise ValueError('Remote target must use HTTPS')
    return urlunsplit((p.scheme, p.netloc, p.path or '/', p.query, ''))

def doctor():
    for app in ('python3', 'curl', 'docker', 'nuclei', 'zaproxy', 'java'):
        print(f'{app:10} {shutil.which(app) or "NOT INSTALLED"}')
    print('Burp Suite: install and open manually; automation is not part of Community edition.')
    if shutil.which('docker'):
        r = subprocess.run(['docker', 'info'], capture_output=True, timeout=12)
        print('Docker daemon:', 'accessible' if r.returncode == 0 else 'not accessible (use sudo or fix Docker permissions)')

def request_once(url):
    opener = build_opener(HTTPHandler(), HTTPSHandler(), NoRedirect())
    req = Request(url, headers={'User-Agent': 'classroom-safe-audit/1.0', 'Accept': 'text/html,*/*;q=0.5'}, method='GET')
    start = time.monotonic()
    try:
        with opener.open(req, timeout=10) as r:
            status = r.status
            headers = dict(r.headers.items())
            body = r.read(65536)
    except HTTPError as e:
        status, headers, body = e.code, dict(e.headers.items()), e.read(65536)
    return {'url': url, 'status': status, 'seconds': round(time.monotonic() - start, 3),
            'headers': headers, 'sample_length_bytes': len(body), 'preview': body.decode('utf-8', errors='replace')[:4000]}

def analyse(data):
    h = {k.lower(): v for k,v in data['headers'].items()}
    notes = []
    for name in ('content-security-policy','x-content-type-options','referrer-policy'):
        if name not in h:
            notes.append(f'Missing {name} header (configuration review; not a proven vulnerability)')
    if data['url'].startswith('https://') and 'strict-transport-security' not in h:
        notes.append('Missing HSTS header (configuration review; not a proven vulnerability)')
    for k,v in data['headers'].items():
        if k.lower() == 'set-cookie' and 'secure' not in v.lower() and data['url'].startswith('https://'):
            notes.append('One observed cookie header lacks Secure attribute (verify cookie purpose)')
    return notes

def write_result(result, directory):
    directory.mkdir(parents=True, exist_ok=True)
    (directory/'result.json').write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding='utf8')
    txt = [f'# HTTP inspection: {result["url"]}', '',
           f'- HTTP status: {result["status"]}', f'- Response time: {result["seconds"]} s',
           f'- Bytes sampled: {result["sample_length_bytes"]}', '', '## Observations']
    txt += ['- '+n for n in result['notes']] or ['- No basic header observations.']
    txt += ['', '## Reminder', 'Findings are informational; they are not validated CVEs or CVSS scores.',
            'Do not reuse tokens or private data from responses.']
    (directory/'report.md').write_text('\n'.join(txt)+'\n', encoding='utf8')
    print('Saved:', directory/'report.md', 'and', directory/'result.json')

def external(command, destination, timeout=100):
    destination.parent.mkdir(parents=True, exist_ok=True)
    print('Running:', ' '.join(command))
    try:
        with destination.open('w', encoding='utf8') as out:
            done = subprocess.run(command, stdout=out, stderr=subprocess.STDOUT, timeout=timeout, check=False)
        print(f'Exit {done.returncode}; log: {destination}')
    except subprocess.TimeoutExpired:
        print('Timeout; subprocess stopped. Log:', destination)
    except OSError as e:
        print('Unable to run:', e)

def lab_integrations():
    target = validate_target(LOCAL, local_only=True)
    folder = OUT/'local'
    folder.mkdir(parents=True, exist_ok=True)
    try:
        data = request_once(target)
        data['notes'] = analyse(data)
        write_result(data, folder)
    except Exception as exc:
        print('Local server unavailable. Start with: python3 lab_server.py', exc)
        return 2
    if shutil.which('nuclei'):
        # Local-only technology fingerprint; not a vulnerability/exploitation scan.
        external(['nuclei','-u',target,'-tags','tech','-rl','1','-c','1','-timeout','5',
                  '-jsonl-export',str(folder/'nuclei-tech.jsonl')], folder/'nuclei.log', 100)
    else:
        print('SKIP Nuclei: not installed')
    if shutil.which('docker'):
        di = subprocess.run(['docker','info'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=12)
        if di.returncode == 0:
            # ZAP baseline: spider + passive checks, localhost only; no active scanner.
            external(['docker','run','--rm','--network','host',
                  '-v',f'{folder.resolve()}:/zap/wrk:rw','ghcr.io/zaproxy/zaproxy:stable',
                  'zap-baseline.py','-t',target,'-m','1','-r','zap.html','-J','zap.json','-I'],
                  folder/'zap.log', 180)
        else:
            print('SKIP ZAP: Docker daemon inaccessible')
    else:
        print('SKIP ZAP: Docker not installed')
    print('Burp Community: use Proxy > Open browser, visit the local lab and examine HTTP history.')
    return 0

def main(argv=None):
    parser = argparse.ArgumentParser(description='Non-destructive audit helper')
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('doctor')
    sub.add_parser('lab')
    a = sub.add_parser('inspect', help='Exactly ONE GET request; no redirects, no crawling')
    a.add_argument('url')
    a.add_argument('--authorized', action='store_true', help='Confirm authorization for this exact URL')
    args = parser.parse_args(argv)
    if args.command == 'doctor': doctor(); return 0
    if args.command == 'lab': return lab_integrations()
    if not args.authorized:
        parser.error('For an external URL specify --authorized after checking scope')
    try:
        target = validate_target(args.url)
        data = request_once(target)
        data['notes'] = analyse(data)
    except (ValueError, OSError, URLError, TimeoutError) as exc:
        print('Inspection failed:', exc, file=sys.stderr)
        return 2
    stamp = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    write_result(data, OUT/f'inspect-{stamp}')
    return 0

if __name__ == '__main__':
    sys.exit(main())
