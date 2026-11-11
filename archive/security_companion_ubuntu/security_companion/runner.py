#!/usr/bin/env python3
"""Bounded web assessment companion. Remote: single fetch only. Active checks: localhost only."""
import argparse, datetime as dt, html, json, os, pathlib, re, shutil, socket, subprocess, sys, time, urllib.error, urllib.parse, urllib.request
ROOT = pathlib.Path(__file__).resolve().parent

def local_target(url):
    p=urllib.parse.urlsplit(url)
    return p.scheme in ('http','https') and p.hostname in ('localhost','127.0.0.1','::1') and not p.username and not p.password

def inspect(url):
    p=urllib.parse.urlsplit(url)
    if p.scheme not in ('http','https') or not p.hostname or p.username or p.password:
        raise ValueError('Only http(s) URL without credentials supported')
    if p.port and not (1 <= p.port <= 65535):
        raise ValueError('Invalid port')
    req=urllib.request.Request(url,headers={'User-Agent':'Classroom-Audit-Companion/1.0','Accept':'text/html,*/*;q=0.5'})
    # Explicit no redirect: prevents a scoped site redirecting to different origin.
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self,*a,**kw): return None
    opener=urllib.request.build_opener(NoRedirect)
    started=time.monotonic()
    try:
        with opener.open(req,timeout=8) as resp:
            status=resp.status; headers=dict(resp.headers.items()); body=resp.read(8192)
    except urllib.error.HTTPError as ex:
        status=ex.code; headers=dict(ex.headers.items()); body=ex.read(8192)
    elapsed=round(time.monotonic()-started,3)
    h={k.lower():v for k,v in headers.items()}
    checks={
      'content_security_policy': 'content-security-policy' in h,
      'x_content_type_options': h.get('x-content-type-options','').lower()=='nosniff',
      'referrer_policy': 'referrer-policy' in h,
      'hsts_https_only': ('strict-transport-security' in h) if p.scheme=='https' else None,
      'cookie_http_only': [c.strip() for c in re.findall(r'(?im)^set-cookie:\s*([^\r\n]+)', '\n'.join(f'{k}: {v}' for k,v in headers.items()))],
    }
    return {'url':url,'timestamp_utc':dt.datetime.now(dt.timezone.utc).isoformat(), 'status':status,'seconds':elapsed,'headers':headers,'bytes_sampled':len(body),'sample_title':extract_title(body),'checks':checks, 'warnings':['Header absence is not proof of an exploitable vulnerability.']}

def extract_title(body):
    m=re.search(rb'<title[^>]*>(.*?)</title>',body,re.I|re.S)
    return html.unescape(re.sub(r'\s+',' ',m.group(1).decode('utf-8','replace')).strip())[:200] if m else None

def shell(cmd, timeout=90, cwd=None):
    try:
        p=subprocess.run(cmd,capture_output=True,text=True,timeout=timeout,cwd=cwd,check=False)
        return {'command':cmd,'returncode':p.returncode,'stdout':p.stdout[-50000:],'stderr':p.stderr[-12000:]}
    except (OSError,subprocess.TimeoutExpired) as e:
        return {'command':cmd,'error':str(e)}

def doctor():
    names=['python3','curl','nuclei','docker','zaproxy','burpsuite']
    return {name:shutil.which(name) for name in names}

def import_findings(path):
    out=[]
    if not path.exists(): return out
    for line in path.read_text(encoding='utf-8',errors='replace').splitlines():
        try:
            obj=json.loads(line)
            if not isinstance(obj,dict): continue
            info=obj.get('info',{}) or {}
            out.append({'tool':'Nuclei','title':str(info.get('name',obj.get('template-id','Untitled')))[:200], 'severity':str(info.get('severity','unknown')), 'location':str(obj.get('matched-at',''))[:300], 'verified':False})
        except json.JSONDecodeError: continue
    return out

def save_report(out,info,findings=None,runs=None):
    out.mkdir(parents=True,exist_ok=True)
    findings=findings or []; runs=runs or []
    doc={'inspection':info,'findings':findings,'runs':runs,'note':'Scanner matches are hypotheses until independently verified. No CVSS is inferred.'}
    (out/'report.json').write_text(json.dumps(doc,ensure_ascii=False,indent=2),encoding='utf-8')
    rows=''.join('<tr><td>'+html.escape(str(f.get('tool','')) )+'</td><td>'+html.escape(str(f.get('title','')))+'</td><td>'+html.escape(str(f.get('severity','')))+'</td><td>'+html.escape(str(f.get('location','')))+'</td><td>Not verified</td></tr>' for f in findings)
    checks=''.join('<li>'+html.escape(k)+': '+html.escape(str(v))+'</li>' for k,v in info.get('checks',{}).items())
    errs=''.join('<li>'+html.escape(' '.join(r.get('command',[])))+' — '+html.escape(str(r.get('returncode',r.get('error','unknown'))))+'</li>' for r in runs)
    page=f'''<!doctype html><html lang="ru"><meta charset="utf-8"><title>Web assessment report</title><style>body{{font:16px system-ui;max-width:1000px;margin:35px auto;padding:0 18px;color:#17202a}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ccd5df;padding:10px;text-align:left}}th{{background:#edf2f7}}.notice{{border-left:4px solid #7d8997;padding:12px;background:#f5f6f8}}</style><h1>Web assessment report</h1><p><b>URL:</b> {html.escape(info.get('url',''))}<br><b>HTTP:</b> {html.escape(str(info.get('status','')))}<br><b>Response time:</b> {html.escape(str(info.get('seconds','')))} s</p><h2>Configuration observations</h2><ul>{checks}</ul><h2>Findings ({len(findings)})</h2><table><tr><th>Source</th><th>Observation</th><th>Severity claimed</th><th>Location</th><th>Verification</th></tr>{rows}</table><h2>Tool runs</h2><ul>{errs}</ul><p class="notice">Warnings are not proof of exploitability. Do not assign CVSS 9+ without independently demonstrated impact.</p></html>'''
    (out/'report.html').write_text(page,encoding='utf-8')
    return out/'report.html'

def run_lab(url,out,do_nuclei,do_zap):
    if not local_target(url):
        raise ValueError('Active tool integrations are restricted to localhost/127.0.0.1/::1')
    info=inspect(url)
    runs=[]; findings=[]
    if do_nuclei:
        if not shutil.which('nuclei'):
            runs.append({'command':['nuclei'],'error':'not installed'})
        else:
            target=out/'nuclei.jsonl'; out.mkdir(parents=True,exist_ok=True)
            cmd=['nuclei','-u',url,'-tags','tech','-rl','1','-c','1','-timeout','5','-retries','0','-jsonl-export',str(target)]
            runs.append(shell(cmd,timeout=120)); findings+=import_findings(target)
    if do_zap:
        if not shutil.which('docker'):
            runs.append({'command':['docker'],'error':'not installed'})
        else:
            out.mkdir(parents=True,exist_ok=True)
            # Host networking only works on Linux (intended Ubuntu). Container receives path to local app.
            cmd=['docker','run','--rm','--network','host','-v',str(out.resolve())+':/zap/wrk/:rw','ghcr.io/zaproxy/zaproxy:stable','zap-baseline.py','-t',url,'-m','1','-J','zap.json','-r','zap.html','-I']
            runs.append(shell(cmd,timeout=180))
    return save_report(out,info,findings,runs)

def main():
    ap=argparse.ArgumentParser(description='Bounded audit companion: inspect any authorized URL; automated scanners only on localhost')
    sub=ap.add_subparsers(dest='command',required=True)
    sub.add_parser('doctor')
    p=sub.add_parser('inspect'); p.add_argument('url'); p.add_argument('--output',default='reports/inspect')
    p=sub.add_parser('lab'); p.add_argument('--url',default='http://127.0.0.1:8765/'); p.add_argument('--output',default='reports/lab'); p.add_argument('--nuclei',action='store_true'); p.add_argument('--zap',action='store_true')
    sub.add_parser('serve')
    a=ap.parse_args()
    if a.command=='doctor':
        for name,path in doctor().items(): print(f'{name:12s}: {path or "MISSING / optional"}')
        return 0
    if a.command=='serve':
        from lab_server import serve
        serve(); return 0
    try:
        out=ROOT/a.output
        report=run_lab(a.url,out,a.nuclei,a.zap) if a.command=='lab' else save_report(out,inspect(a.url))
        print('Report:',report); return 0
    except Exception as e:
        print(f'ERROR: {e}',file=sys.stderr); return 1
if __name__=='__main__': sys.exit(main())
