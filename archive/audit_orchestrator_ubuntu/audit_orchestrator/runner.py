#!/usr/bin/env python3
"""Low-impact, evidence-first web audit orchestrator. Python 3.9+ stdlib only."""
import argparse, datetime, hashlib, html, json, pathlib, shutil, subprocess, sys, time
import urllib.error, urllib.parse, urllib.request

ROOT=pathlib.Path(__file__).resolve().parent
TOOLS={'curl':'curl','nuclei':'nuclei','docker':'docker','zaproxy':'zaproxy','java':'java'}

def stamp(): return datetime.datetime.now(datetime.timezone.utc).isoformat()
def outdir(path):
    p=pathlib.Path(path);p.mkdir(parents=True,exist_ok=True);return p

def local_url(url):
    u=urllib.parse.urlsplit(url)
    return u.scheme=='http' and u.hostname in ('localhost','127.0.0.1','::1') and u.port==8765 and (u.username is None)

def fetch(url):
    u=urllib.parse.urlsplit(url)
    if u.scheme not in ('http','https') or not u.hostname or u.username or u.password:
        raise ValueError('Нужен HTTP(S) URL без учетных данных')
    if u.scheme!='https' and not local_url(url):
        raise ValueError('Внешний URL должен использовать HTTPS')
    req=urllib.request.Request(url,headers={'User-Agent':'Classroom-Audit-Inspector/1.0'},method='GET')
    opener=urllib.request.build_opener(NoRedirect)
    start=time.monotonic()
    try:
        with opener.open(req,timeout=10) as r:
            data=r.read(131072)
            return {'url':url,'timestamp':stamp(),'status':r.status,'elapsed_seconds':round(time.monotonic()-start,3),'headers':dict(r.headers.items()),'body_sha256_prefix':hashlib.sha256(data).hexdigest()[:16],'body_sample_bytes':len(data),'error':None}
    except urllib.error.HTTPError as ex:
        return {'url':url,'timestamp':stamp(),'status':ex.code,'elapsed_seconds':round(time.monotonic()-start,3),'headers':dict(ex.headers.items()),'body_sha256_prefix':None,'body_sample_bytes':0,'error':None}
    except (urllib.error.URLError,TimeoutError) as ex:
        return {'url':url,'timestamp':stamp(),'status':None,'elapsed_seconds':round(time.monotonic()-start,3),'headers':{},'body_sha256_prefix':None,'body_sample_bytes':0,'error':str(ex)}

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl): return None

def headers_review(d):
    h={k.lower():v for k,v in d['headers'].items()}
    checks=[]
    for key,title in [('content-security-policy','Content Security Policy'),('x-content-type-options','X-Content-Type-Options'),('referrer-policy','Referrer Policy')]:
        checks.append({'name':title,'status':'present' if key in h else 'review','note':'Наличие/отсутствие заголовка само по себе не подтверждает уязвимость'})
    if d['url'].startswith('https:'):
        checks.append({'name':'Strict Transport Security','status':'present' if 'strict-transport-security' in h else 'review','note':'Проверить использование HTTPS и HSTS'})
    return checks

def load_tool_report(path):
    p=pathlib.Path(path); raw=p.read_text(encoding='utf8')
    if p.suffix.lower()=='.jsonl':
        objects=[]
        for line in raw.splitlines():
            if line.strip(): objects.append(json.loads(line))
        return {'path':str(path),'kind':'jsonl','entries':len(objects),'items':objects[:100]}
    obj=json.loads(raw)
    if isinstance(obj,list): items=obj
    elif isinstance(obj,dict) and isinstance(obj.get('site'),list): items=obj['site']
    elif isinstance(obj,dict) and isinstance(obj.get('runs'),list): items=obj['runs']
    else: items=[obj]
    return {'path':str(path),'kind':'json','entries':len(items),'items':items[:100]}

def write_report(dest,info,imports=None,logs=None):
    dest=outdir(dest);imports=imports or [];logs=logs or []
    summary={'generated':stamp(),'inspection':info,'checks':headers_review(info) if info else [],'imported_reports':imports,'tool_logs':logs,'notice':'Предупреждения не эквивалентны подтвержденным CVSS. Проверять вручную и не эксплуатировать чужие данные.'}
    (dest/'report.json').write_text(json.dumps(summary,indent=2,ensure_ascii=False),encoding='utf8')
    lines=['# Отчет об аудите','',f'Дата: {summary["generated"]}','', '## HTTP-инспекция']
    if info:
        lines += [f'- URL: `{info["url"]}`', f'- Статус: {info["status"]}',f'- Время ответа: {info["elapsed_seconds"]} сек',f'- Ошибка: {info["error"] or "нет"}','','## Заголовки (не доказательство эксплуатации)']
        lines += [f'- {x["name"]}: {x["status"]}' for x in summary['checks']]
    lines += ['','## Импортированные результаты']
    lines += [f'- {x["path"]}: {x["entries"]} элементов' for x in imports] or ['- Нет']
    lines += ['','## Запуски локальных инструментов']
    lines += [f'- {x["tool"]}: код {x["returncode"]}, лог {x["log"]}' for x in logs] or ['- Нет']
    lines += ['','## Правила интерпретации','- Наличие заголовка, CVE или предупреждения не гарантирует CVSS 9+.','- Для доказательства приложи запрос, ответ, ожидаемое и фактическое поведение.','- Замаскируй cookies, API-ключи, токены и персональные данные.']
    (dest/'report.md').write_text('\n'.join(lines)+'\n',encoding='utf8')
    cells=''.join('<tr><td>'+html.escape(x['name'])+'</td><td>'+html.escape(x['status'])+'</td></tr>' for x in summary['checks'])
    imports_html=''.join('<li>'+html.escape(x['path'])+': '+str(x['entries'])+' элементов</li>' for x in imports)
    page='''<!doctype html><html lang="ru"><meta charset="utf-8"><title>Audit Report</title><style>body{max-width:900px;margin:40px auto;padding:0 20px;font:16px system-ui;color:#162333;line-height:1.6} table{border-collapse:collapse;width:100%}td,th{border:1px solid #ccc;padding:10px;text-align:left}code{background:#eee;padding:2px 5px}small{color:#666}</style><h1>Отчет об аудите</h1><p>'''+html.escape(summary['generated'])+'</p><h2>HTTP</h2><p>'+html.escape(info['url'] if info else 'Нет')+'</p><p>Статус: '+html.escape(str(info['status'] if info else 'не проверено'))+'</p><h2>Заголовки</h2><table><tr><th>Проверка</th><th>Результат</th></tr>'+cells+'</table><h2>Импортированные результаты</h2><ul>'+imports_html+'</ul><p><small>Не является подтверждением эксплуатации или гарантией CVSS.</small></p></html>'''
    (dest/'report.html').write_text(page,encoding='utf8')
    print('Отчёты:',dest/'report.md',dest/'report.html')

def execute(cmd,log_path,timeout=90):
    try:
        p=subprocess.run(cmd,capture_output=True,text=True,timeout=timeout,check=False)
        result=f'CMD: {cmd!r}\nEXIT: {p.returncode}\nSTDOUT:\n{p.stdout[:30000]}\nSTDERR:\n{p.stderr[:10000]}'
        log_path.write_text(result,encoding='utf8')
        return {'tool':cmd[0],'returncode':p.returncode,'log':str(log_path)}
    except (OSError,subprocess.TimeoutExpired) as ex:
        log_path.write_text(repr(ex),encoding='utf8')
        return {'tool':cmd[0],'returncode':'failed','log':str(log_path)}

def cli():
    parser=argparse.ArgumentParser(description='Учебный low-impact audit orchestrator')
    sub=parser.add_subparsers(dest='cmd',required=True)
    sub.add_parser('doctor');sub.add_parser('serve')
    p=sub.add_parser('inspect');p.add_argument('url');p.add_argument('--out',default='reports/target')
    p=sub.add_parser('lab');p.add_argument('--out',default='reports/lab');p.add_argument('--nuclei',action='store_true',help='Локальный tech fingerprint');p.add_argument('--zap',action='store_true',help='Локальный ZAP baseline через Docker')
    p=sub.add_parser('merge');p.add_argument('--report',action='append',required=True);p.add_argument('--out',default='reports/combined')
    args=parser.parse_args()
    if args.cmd=='doctor':
        for name,command in TOOLS.items():print(f'{name}: {shutil.which(command) or "не найден"}')
        print('Python:',sys.version.split()[0]);return
    if args.cmd=='serve':
        from lab_server import serve
        serve();return
    if args.cmd=='inspect':
        write_report(args.out,fetch(args.url));return
    if args.cmd=='merge':
        reports=[]
        for x in args.report:
            reports.append(load_tool_report(x))
        write_report(args.out,None,reports);return
    if args.cmd=='lab':
        url='http://127.0.0.1:8765/'
        target=outdir(args.out);logs=[]
        info=fetch(url)
        if info['error']: print('Сначала запусти в другом терминале: python3 runner.py serve');sys.exit(2)
        if args.nuclei:
            if shutil.which('nuclei'):
                logs.append(execute(['nuclei','-u',url,'-tags','tech','-rl','1','-c','1','-timeout','5','-jsonl-export',str(target/'nuclei.jsonl')],target/'nuclei.log',90))
            else:print('Nuclei не установлен — этап пропущен')
        if args.zap:
            if shutil.which('docker'):
                print('ZAP требует скачанного образа ghcr.io/zaproxy/zaproxy:stable и прав Docker')
                logs.append(execute(['docker','run','--rm','--network','host','-v',str(target.resolve())+':/zap/wrk:rw','ghcr.io/zaproxy/zaproxy:stable','zap-baseline.py','-t',url,'-m','1','-J','zap.json','-r','zap.html','-I'],target/'zap.log',120))
            else:print('Docker не установлен — ZAP этап пропущен')
        imports=[]
        for name in ['nuclei.jsonl','zap.json']:
            path=target/name
            if path.exists():
                try: imports.append(load_tool_report(path))
                except (ValueError,UnicodeError) as ex:print(name,'не разобран:',ex)
        write_report(target,info,imports,logs)

if __name__=='__main__':
    try:cli()
    except (ValueError,OSError) as ex:print('Ошибка:',ex,file=sys.stderr);sys.exit(1)
