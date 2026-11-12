"""Real external processes with deadlines, bounded logs and explicit coverage."""
from datetime import datetime, timezone
import base64
import ipaddress
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import tempfile
import time
from urllib.parse import urlsplit
import xml.etree.ElementTree as ET

from .reports import import_report, sanitize
from .scope import origin, public_url


ENGINES = ("nmap", "k6", "nuclei", "zap")


def inventory():
    return {name: (shutil.which("zap.sh") or shutil.which("zaproxy") if name == "zap" else shutil.which(name))
            for name in ENGINES}


def execute(command, timeout, on_tick=None, env_overrides=None):
    """No shell; terminate the whole process group on timeout, interrupt or log flood."""
    started = time.monotonic()
    env = {k: os.environ[k] for k in ("PATH", "HOME", "LANG", "SYSTEMROOT") if k in os.environ}
    env.update(env_overrides or {})
    with tempfile.TemporaryFile() as log:
        process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT,
                                   stdin=subprocess.DEVNULL, env=env, start_new_session=True)
        state, tick = "completed", started
        try:
            while process.poll() is None:
                if time.monotonic() - started > timeout:
                    state = "timeout"
                    break
                if os.fstat(log.fileno()).st_size > 2 * 1024 * 1024:
                    state = "output-limit"
                    break
                if on_tick and time.monotonic() - tick >= 5:
                    on_tick()
                    tick = time.monotonic()
                time.sleep(.1)
        except KeyboardInterrupt:
            state = "interrupted"
        finally:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait()
        if os.fstat(log.fileno()).st_size > 2 * 1024 * 1024:
            state = "output-limit"
        log.seek(0)
        output = log.read(2 * 1024 * 1024).decode("utf-8", "replace")
    return {"status": state, "exit_code": process.returncode,
            "duration_seconds": round(time.monotonic() - started, 3), "log": sanitize(output)}


def bounded_json(path):
    if not path.is_file() or path.stat().st_size > 20 * 1024 * 1024:
        raise ValueError("Нет результата движка или файл превышает 20 MiB")
    return json.loads(path.read_text(encoding="utf-8"))


class Captures:
    """Private, temporary HTTP responses for passive engines; removed after the run."""
    def __init__(self, directory):
        self.directory = Path(directory)
        self.entries = []
        self.bytes = 0
        self.limited = False
        self.raw = self.directory / "responses"
        self.raw.mkdir(mode=0o700)

    def __call__(self, url, response):
        if self.bytes + len(response["body"]) > 20 * 1024 * 1024:
            self.limited = True
            return
        self.bytes += len(response["body"])
        headers = response["headers"]
        raw = f"HTTP/1.1 {response['status']} Response\r\n".encode()
        raw += "".join(f"{k}: {v}\r\n" for k, v in headers).encode("utf-8") + b"\r\n" + response["body"]
        (self.raw / f"{len(self.entries):04d}.txt").write_bytes(raw)
        self.entries.append({"startedDateTime": datetime.now(timezone.utc).isoformat(),
            "time": response["elapsed"] * 1000,
            "request": {"method": "GET", "url": url, "httpVersion": "HTTP/1.1", "headers": [],
                        "queryString": [], "cookies": [], "headersSize": -1, "bodySize": 0},
            "response": {"status": response["status"], "statusText": "Response", "httpVersion": "HTTP/1.1",
                         "headers": [{"name": k, "value": v} for k, v in headers], "cookies": [],
                         "content": {"size": len(response["body"]), "mimeType": dict((k.lower(), v) for k, v in headers).get("content-type", "application/octet-stream"),
                                     "text": base64.b64encode(response["body"]).decode(), "encoding": "base64"},
                         "redirectURL": "", "headersSize": -1, "bodySize": len(response["body"])},
            "cache": {}, "timings": {"send": 0, "wait": response["elapsed"] * 1000, "receive": 0}})

    def har(self):
        path = self.directory / "capture.har"
        path.write_text(json.dumps({"log": {"version": "1.2", "creator": {"name": "WebAuditKit", "version": "1"}, "entries": self.entries}}), encoding="utf-8")
        return path


def nmap_scan(binary, scope, directory, tick, tls_enumeration=False):
    records, results = [], []
    for i, endpoint in enumerate(sorted(scope.allowed_origins)):
        p = urlsplit(endpoint)
        port = p.port or (443 if p.scheme == "https" else 80)
        # Resolve to ONE literal address: never feed Nmap target expressions from a URL.
        address = str(ipaddress.ip_address(socket.getaddrinfo(p.hostname, port, type=socket.SOCK_STREAM)[0][4][0]))
        path = directory / f"nmap-{i}.xml"
        args = [binary, "-sT", "-Pn", "-n", "--max-retries", "1", "--max-rate", "2",
                "--host-timeout", "90s", "-p", str(port), "-oX", str(path)]
        if ":" in address:
            args.append("-6")
        if p.scheme == "https":
            script_args = directory / "nmap-args.txt"
            script_args.write_text("tls.servername=" + json.dumps(p.hostname), encoding="utf-8")
            args += ["--script", "+ssl-cert" + (",+ssl-enum-ciphers" if tls_enumeration else ""),
                     "--script-timeout", "45s", "--script-args-file", str(script_args)]
        if i:
            time.sleep(scope.delay)
        run = execute(args + [address], 100, tick)
        results.append(run)
        if run["status"] != "completed" or run["exit_code"] != 0:
            return {"results": results, "ports": records, "status": "error"}
        if not path.is_file() or path.stat().st_size > 20 * 1024 * 1024:
            raise ValueError("Nmap не создал ограниченный XML-результат")
        root = ET.parse(path).getroot()
        if root.find("runstats/finished") is None or root.find("runstats/finished").get("exit") != "success":
            raise ValueError("Nmap завершился без подтверждения успешного выполнения")
        matched = False
        for node in root.findall("host/ports/port"):
            matched = True
            scripts = [{"id": x.get("id"), "output": x.get("output", "")} for x in node.findall("script")]
            records.append({"origin": endpoint, "address": address, "port": int(node.get("portid")),
                            "state": node.find("state").get("state"), "scripts": scripts})
            expected = {"ssl-cert"} | ({"ssl-enum-ciphers"} if tls_enumeration else set())
            returned = {x["id"] for x in scripts if "ERROR" not in x["output"]}
            if p.scheme == "https" and not expected.issubset(returned):
                return {"results": results, "ports": records, "status": "incomplete", "reason": "TLS-скрипт не вернул результат"}
        if not matched:
            return {"results": results, "ports": records, "status": "incomplete", "reason": "Нет записи проверенного порта"}
    return {"results": results, "ports": records, "status": "completed"}


def k6_script(scope, count, rps, headers, summary):
    config = {"targets": [{"url": x, "headers": (headers or {}).get(origin(x), {})} for x in scope.targets],
              "count": count, "interval": max(scope.delay, 1 / rps), "timeout": f"{scope.timeout}s", "summary": str(summary)}
    return '''import http from 'k6/http';
import exec from 'k6/execution';
import {sleep} from 'k6';
const cfg = ''' + json.dumps(config) + ''';
export const options = {vus:1, iterations:cfg.count, maxRedirects:0,
  discardResponseBodies:true, insecureSkipTLSVerify:false,
  thresholds:{http_req_failed:['rate<0.05']},
  summaryTrendStats:['avg','min','max','med','p(95)','p(99)'],
  systemTags:['status','method','name','error_code','tls_version']};
let failures=0;
export default function() {
  const target=cfg.targets[exec.scenario.iterationInTest % cfg.targets.length];
  const started=Date.now();
  const response=http.get(target.url, {headers:target.headers, redirects:0,
    timeout:cfg.timeout, tags:{name:'audit-target'}});
  failures=(response.status===0 || response.status>=500) ? failures+1 : 0;
  if(response.status===429 || response.status===503 || failures>=3) {
    exec.test.abort('SafetyStop: 429/503 or three consecutive failures');
  }
  sleep(Math.max(0,cfg.interval-(Date.now()-started)/1000));
}
export function handleSummary(data) {
  return {[cfg.summary]:JSON.stringify(data)};
}
'''


def k6_scan(binary, scope, directory, tick, count, rps, headers):
    summary = directory / "k6-summary.json"
    script = directory / "load.js"
    script.write_text(k6_script(scope, count, rps, headers, summary), encoding="utf-8")
    config = directory / "k6-config.json"
    config.write_text("{}", encoding="utf-8")
    args = [binary, "run", "--config", str(config), "--quiet", "--no-color", "--no-usage-report",
            "--include-system-env-vars=false", str(script)]
    result = execute(args, min(7200, count * (scope.timeout + max(scope.delay, 1 / rps)) + 30), tick)
    result["metrics"] = bounded_json(summary) if summary.exists() else {}
    result["requests"] = int(result["metrics"].get("metrics", {}).get("http_reqs", {}).get("values", {}).get("count", 0))
    if result["status"] == "completed":
        result["status"] = "completed" if result["exit_code"] == 0 and result["requests"] == count else "error"
    return result


def nuclei_scan(binary, captures, directory, tick):
    configured = os.environ.get("AUDIT_NUCLEI_TEMPLATES")
    candidates = [Path(configured)] if configured else [Path.home() / ".local/share/nuclei/nuclei-templates", Path.home() / "nuclei-templates"]
    templates = next((x.resolve() for x in candidates if x.is_dir()), None)
    if templates is None:
        return {"status": "incomplete", "reason": "Нет локальных шаблонов Nuclei; задайте AUDIT_NUCLEI_TEMPLATES", "findings": []}
    output = directory / "nuclei.jsonl"
    config = directory / "nuclei-config.yaml"
    config.write_text("{}", encoding="utf-8")
    args = [binary, "-config", str(config), "-passive", "-target", str(captures.raw), "-t", str(templates), "-pt", "http",
            "-ni", "-duc", "-dr", "-dashboard=false", "-c", "1", "-bs", "1", "-jsonl", "-omit-raw", "-o", str(output), "-nc"]
    isolated = {"NUCLEI_CONFIG_DIR": str(directory / "config"), "XDG_CONFIG_HOME": str(directory / "config"),
                "XDG_STATE_HOME": str(directory / "state"), "XDG_CACHE_HOME": str(directory / "cache"),
                "XDG_DATA_HOME": str(directory / "data")}
    result = execute(args, 300, tick, env_overrides=isolated)
    result["templates"] = str(templates)
    result["findings"] = import_report(output).get("findings", []) if output.exists() else []
    if result["status"] == "completed" and (result["exit_code"] != 0 or not output.exists()):
        result["status"] = "error"
    result["mode"] = "passive-recorded-http"
    return result


def zap_scan(binary, captures, directory, tick):
    report = directory / "zap.json"
    plan = {"env": {"parameters": {"failOnError": True, "failOnWarning": True}}, "jobs": [
        {"type": "import", "parameters": {"type": "har", "fileName": str(captures.har()), "sendRequests": False}},
        {"type": "passiveScan-wait", "parameters": {"maxDuration": 2}},
        {"type": "report", "parameters": {"template": "traditional-json", "reportDir": str(directory), "reportFile": "zap.json"}}]}
    path = directory / "zap-plan.yaml"
    path.write_text(json.dumps(plan), encoding="utf-8")
    result = execute([binary, "-cmd", "-dir", str(directory / "zap-home"), "-autorun", str(path)], 300, tick)
    result["findings"] = import_report(report).get("findings", []) if report.exists() else []
    if result["status"] == "completed" and (result["exit_code"] != 0 or not report.exists()):
        result["status"] = "error"
    result["mode"] = "passive-recorded-http"
    return result


def run_engine(name, scope, output, captures, events, count=10, rps=1, headers=None, tls_enumeration=False):
    binary = inventory()[name]
    record = {"engine": name, "started_utc": datetime.now(timezone.utc).isoformat()}
    if not binary:
        record.update(status="unavailable", reason="Исполняемый файл не найден в PATH", findings=[])
        directory = Path(output) / name
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        (directory / "engine.json").write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
        events.emit(f"{name}: unavailable")
        return record
    with tempfile.TemporaryDirectory(prefix="audit-engine-") as tmp:
        directory = Path(tmp)
        tick = lambda: events.emit(f"{name}: процесс выполняется")
        events.emit(f"Запуск {name}")
        try:
            version_args = [binary, "version" if name == "k6" else "-version" if name in ("nuclei", "zap") else "--version"]
            if name == "zap":
                version_args += ["-dir", str(directory / "version-home")]
            version = execute(version_args, 15)
            record["version"] = version["log"][:500]
            if version["status"] == "interrupted":
                result = {"status": "interrupted"}
            elif name == "nmap":
                result = nmap_scan(binary, scope, directory, tick, tls_enumeration)
            elif name == "k6":
                result = k6_scan(binary, scope, directory, tick, count, rps, headers)
            elif not captures.entries:
                result = {"status": "incomplete", "reason": "Нет HTTP-ответов для пассивного анализа"}
            elif name == "nuclei":
                result = nuclei_scan(binary, captures, directory, tick)
            else:
                result = zap_scan(binary, captures, directory, tick)
        except KeyboardInterrupt:
            result = {"status": "interrupted", "reason": "Остановлено пользователем"}
        except (OSError, ValueError, ET.ParseError, TypeError, KeyError) as exc:
            result = {"status": "error", "reason": type(exc).__name__}
        record.update(result)
    # Only normalized findings leave the private work directory.
    record = sanitize(record)
    record["completed_utc"] = datetime.now(timezone.utc).isoformat()
    directory = Path(output) / name
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    (directory / "engine.json").write_text(json.dumps(sanitize(record), ensure_ascii=False, indent=2), encoding="utf-8")
    events.emit(f"{name}: {record['status']}")
    return record
