#!/usr/bin/env python3
"""Low-impact, single-page, in-scope web audit. Python standard library only."""
import argparse
import datetime as dt
import hashlib
import html.parser
import json
import pathlib
import shutil
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

TOOLS = ["docker", "nuclei", "zap.sh", "java", "curl", "python3"]
SECURITY_HEADERS = ["content-security-policy", "strict-transport-security", "x-content-type-options", "referrer-policy", "permissions-policy"]
MAX_BYTES = 256 * 1024

class PageParser(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms = []
        self.scripts = 0
        self.title_text = []
        self.in_title = False
    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form":
            self.forms.append({"method": attrs.get("method", "GET").upper(), "action": attrs.get("action", "")[:160]})
        elif tag == "script":
            self.scripts += 1
        elif tag == "title":
            self.in_title = True
    def handle_endtag(self, tag):
        if tag == "title":
            self.in_title = False
    def handle_data(self, data):
        if self.in_title:
            self.title_text.append(data)

def validate_url(value, allow_http):
    p = urllib.parse.urlsplit(value)
    if p.scheme not in ({"http", "https"} if allow_http else {"https"}):
        raise ValueError("Use HTTPS, or add --allow-http for a local lab")
    if not p.hostname or p.username or p.password:
        raise ValueError("URL needs a hostname and must not include credentials")
    if p.port is not None and not (1 <= p.port <= 65535):
        raise ValueError("Invalid port")
    return p

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def get_page(url, timeout):
    opener = urllib.request.build_opener(NoRedirect)
    req = urllib.request.Request(url, headers={"User-Agent": "Classroom-Passive-Audit/1.0", "Accept": "text/html,application/xhtml+xml"}, method="GET")
    try:
        r = opener.open(req, timeout=timeout)
    except urllib.error.HTTPError as exc:
        r = exc
    with r:
        payload = r.read(MAX_BYTES + 1)
        headers = dict(r.headers.items())
        return {"status": r.status, "headers": headers, "body": payload[:MAX_BYTES], "truncated": len(payload) > MAX_BYTES}

def audit(url, timeout, allow_http):
    p = validate_url(url, allow_http)
    result = get_page(url, timeout)
    headers_l = {k.lower(): v for k, v in result["headers"].items()}
    # Avoid storing cookie values, authorization tokens or full response bodies.
    parser = PageParser()
    content_type = headers_l.get("content-type", "")
    if "html" in content_type.lower():
        parser.feed(result["body"].decode("utf-8", "replace"))
    cookies = [line for k, line in result["headers"].items() if k.lower() == "set-cookie"]
    findings = []
    for name in SECURITY_HEADERS:
        if name not in headers_l:
            if name == "strict-transport-security" and p.scheme != "https":
                continue
            findings.append({"name": "Missing header: " + name, "severity": "informational", "note": "Review applicability; missing headers alone do not establish a critical vulnerability."})
    if p.scheme == "http":
        findings.append({"name": "HTTP transport", "severity": "informational", "note": "Use HTTPS for real deployments."})
    return {
        "timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "target": f"{p.scheme}://{p.netloc}{p.path or '/'}", "status": result["status"],
        "redirect_location": headers_l.get("location", "")[:200],
        "content_type": content_type[:120],
        "server_header": headers_l.get("server", "")[:100],
        "title": "".join(parser.title_text).strip()[:120],
        "form_count": len(parser.forms), "forms": parser.forms[:20], "script_tag_count": parser.scripts,
        "set_cookie_present": bool(cookies),
        "security_headers": {name: ("present" if name in headers_l else "absent") for name in SECURITY_HEADERS},
        "body_sha256": hashlib.sha256(result["body"]).hexdigest(),
        "body_truncated": result["truncated"],
        "findings": findings,
        "limitations": "Exactly one GET to the provided URL, redirects disabled; passive configuration observations, not exploitation or CVSS verification."
    }

def write_report(data, out):
    directory = pathlib.Path(out)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "report.json").write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    lines = ["# Отчёт: базовый аудит", "", f"Цель: `{data['target']}`", f"Дата UTC: {data['timestamp_utc']}", f"HTTP: {data['status']}", f"Content-Type: {data['content_type']}", f"Заголовок страницы: {data['title']}", f"Формы: {data['form_count']}; script-теги: {data['script_tag_count']}", "", "## Проверка заголовков"]
    lines.extend(f"- `{k}`: {v}" for k, v in data["security_headers"].items())
    lines += ["", "## Наблюдения (не подтверждённые уязвимости)"]
    lines.extend("- " + f["name"] + " — " + f["note"] for f in data["findings"])
    lines += ["", "## Ограничение", data["limitations"], "", "## Дальнейшая ручная проверка", "Сверить области доступа на собственных тестовых аккаунтах; документировать ожидаемый и фактический результат."]
    (directory / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

def main():
    ap = argparse.ArgumentParser(description="Low-impact classroom passive audit")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("doctor", help="check whether popular tools are installed")
    scan = sub.add_parser("audit", help="exactly one GET request, no redirects or crawling")
    scan.add_argument("url")
    scan.add_argument("--allow-http", action="store_true", help="HTTP only for a local training lab")
    scan.add_argument("--timeout", type=float, default=8)
    scan.add_argument("--output", default="results")
    args = ap.parse_args()
    if args.cmd == "doctor":
        for name in TOOLS:
            print(f"{name:9} : {shutil.which(name) or 'not installed (optional)'}")
        return 0
    try:
        if not (1 <= args.timeout <= 30):
            raise ValueError("timeout must be between 1 and 30 seconds")
        data = audit(args.url, args.timeout, args.allow_http)
        write_report(data, args.output)
        print("Completed one GET. Reports:", pathlib.Path(args.output) / "report.md", "and report.json")
        print("HTTP status:", data["status"], "Findings (informational):", len(data["findings"]))
        return 0
    except (ValueError, urllib.error.URLError, TimeoutError, ssl.SSLError, OSError) as exc:
        print(f"Audit failed safely: {exc}", file=sys.stderr)
        return 2

if __name__ == "__main__":
    sys.exit(main())
