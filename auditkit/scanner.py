"""Bounded HTTP GET assessment. No form submission or attack payloads."""
from collections import deque
from datetime import datetime, timezone
import hashlib
from html.parser import HTMLParser
from http.client import HTTPConnection, HTTPSConnection, HTTPException
from http.cookies import SimpleCookie, CookieError
import ssl
import time
from urllib.parse import urljoin, urlsplit, urlunsplit

from .scope import canonical_url, origin, public_url


def resolve_url(base, reference):
    """Ignore malformed or non-HTTP references without losing the whole page."""
    try:
        return canonical_url(urljoin(base, reference))
    except ValueError:
        return None


class PageParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links, self.forms, self.resources = [], [], []
        self.current_form = None
        self.title = ""
        self.in_title = False
        self.base_href = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "base" and self.base_href is None:
            self.base_href = attrs.get("href")
        if tag == "a" and attrs.get("href"):
            self.links.append(attrs["href"])
        if tag in ("script", "img", "iframe", "link", "audio", "video", "source"):
            ref = attrs.get("href" if tag == "link" else "src")
            if ref:
                self.resources.append(ref)
        if tag == "form":
            self.current_form = {"method": attrs.get("method", "GET").upper(), "action": attrs.get("action", ""), "password": False}
            self.forms.append(self.current_form)
        if tag == "input" and self.current_form is not None and attrs.get("type", "").lower() == "password":
            self.current_form["password"] = True
        if tag == "title":
            self.in_title = True

    def handle_endtag(self, tag):
        if tag == "title":
            self.in_title = False
        if tag == "form":
            self.current_form = None

    def handle_data(self, data):
        if self.in_title:
            self.title = (self.title + data)[:200]


def finding(rule, title, url, evidence, recommendation, severity="info"):
    return {"rule": rule, "title": title, "url": public_url(url), "severity": severity,
            "confidence": "observed", "evidence": evidence, "recommendation": recommendation}


def fetch(url, scope, headers=None):
    """Direct connection; verified TLS; no environment proxies or automatic redirects."""
    if not scope.permits(url):
        raise ValueError("Запрос за пределами scope")
    p = urlsplit(url)
    connection = (HTTPSConnection(p.hostname, p.port, timeout=scope.timeout, context=ssl.create_default_context())
                  if p.scheme == "https" else HTTPConnection(p.hostname, p.port, timeout=scope.timeout))
    started = time.monotonic()
    try:
        connection.connect()
        tls = None
        if p.scheme == "https":
            cert = connection.sock.getpeercert()
            cipher = connection.sock.cipher()
            tls = {"version": connection.sock.version(), "cipher": cipher[0] if cipher else None,
                   "expires": cert.get("notAfter"), "verified": True}
        request_headers = {"User-Agent": "WebAuditKit/1.0", "Accept": "text/html,application/xhtml+xml,*/*;q=0.5", "Accept-Encoding": "identity"}
        request_headers.update(headers or {})
        connection.request("GET", urlunsplit(("", "", p.path or "/", p.query, "")), headers=request_headers)
        response = connection.getresponse()
        # Bound retained body size. Socket timeout applies to network operations.
        chunks, size = [], 0
        deadline = time.monotonic() + scope.timeout
        while size <= scope.max_bytes:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Body read deadline exceeded")
            # read1 returns after one buffered/socket read, allowing a deadline
            # even when the peer keeps sending small chunks.
            sock = connection.sock
            if sock is not None:
                sock.settimeout(remaining)
            chunk = response.read1(min(65536, scope.max_bytes + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        body = b"".join(chunks)
        return {"status": response.status, "headers": response.getheaders(), "body": body[:scope.max_bytes],
                "truncated": len(body) > scope.max_bytes, "tls": tls,
                "elapsed": round(time.monotonic() - started, 3)}
    finally:
        connection.close()


def inspect_response(url, response):
    pairs = response["headers"]
    headers = {k.lower(): v for k, v in pairs}
    issues = []

    def add(rule, title, evidence, recommendation, severity="info"):
        issues.append(finding(rule, title, url, evidence, recommendation, severity))

    if urlsplit(url).scheme == "http":
        add("transport.http", "Ответ получен по незашифрованному HTTP", f"HTTP {response['status']}", "Используйте HTTPS; проверьте перенаправление HTTP → HTTPS.", "low")
    is_html = "html" in headers.get("content-type", "").lower()
    if is_html and 200 <= response["status"] < 300:
        checks = {
            "content-security-policy": "Настройте CSP с учётом ресурсов приложения.",
            "x-content-type-options": "Добавьте X-Content-Type-Options: nosniff.",
            "referrer-policy": "Выберите Referrer-Policy для приложения.",
            "permissions-policy": "Ограничьте ненужные возможности браузера через Permissions-Policy.",
        }
        for name, advice in checks.items():
            if name not in headers:
                add("header." + name, "Отсутствует " + name, "Заголовок отсутствует в ответе HTML", advice)
        csp = headers.get("content-security-policy", "")
        if "frame-ancestors" not in csp.lower() and "x-frame-options" not in headers:
            add("header.framing", "Не обнаружена политика встраивания страницы", "Нет frame-ancestors и X-Frame-Options", "Ограничьте встраивание, если оно не требуется.")
    if urlsplit(url).scheme == "https" and 200 <= response["status"] < 400:
        if "strict-transport-security" not in headers:
            add("header.hsts", "Отсутствует HSTS", "Нет Strict-Transport-Security", "После проверки HTTPS настройте Strict-Transport-Security.")
    if headers.get("x-content-type-options", "nosniff").lower().strip() != "nosniff":
        add("header.nosniff", "Некорректный X-Content-Type-Options", headers["x-content-type-options"], "Используйте значение nosniff.")
    cookies = []
    for key, value in pairs:
        if key.lower() != "set-cookie":
            continue
        jar = SimpleCookie()
        try:
            jar.load(value)
        except CookieError:
            pass
        if not jar:
            add("cookie.parse", "Не удалось разобрать Set-Cookie", "Значение скрыто", "Проверьте синтаксис заголовка вручную.")
        for name, cookie in jar.items():
            flags = {"name": name, "secure": bool(cookie["secure"]), "httponly": bool(cookie["httponly"]), "samesite": cookie["samesite"] or None}
            cookies.append(flags)
            for flag in ("secure", "httponly", "samesite"):
                if not flags[flag]:
                    add("cookie." + flag, f"Cookie {name}: отсутствует {flag}", flags,
                        "Проверьте назначение cookie и задайте подходящие атрибуты; HttpOnly нужен для cookies, недоступных JavaScript.", "low" if flag == "secure" else "info")
    parser = PageParser()
    if is_html and headers.get("content-encoding", "identity").lower() == "identity":
        parser.feed(response["body"].decode("utf-8", "replace"))
    base = (resolve_url(url, parser.base_href) if parser.base_href is not None else None) or url
    forms = []
    for form in parser.forms:
        action = resolve_url(base, form["action"]) if form["action"] else url
        if action is None:
            forms.append({**form, "action": "[invalid or non-HTTP action]"})
            continue
        forms.append({**form, "action": public_url(action)})
        if form["password"] and (urlsplit(url).scheme != "https" or urlsplit(action).scheme != "https"):
            add("form.password_http", "Форма пароля использует HTTP", {"action": public_url(action)}, "Страница и обработчик пароля должны использовать HTTPS.", "medium")
        if form["password"] and form["method"] == "GET":
            add("form.password_get", "Форма пароля отправляется методом GET", {"action": public_url(action)}, "Передавайте пароль в теле POST по HTTPS.", "medium")
    resources = [resolve_url(base, x) for x in parser.resources]
    mixed = [public_url(x) for x in resources if x and urlsplit(x).scheme == "http"]
    if urlsplit(url).scheme == "https" and mixed:
        add("content.mixed", "HTML содержит ресурсы по HTTP", mixed[:20], "Переведите ресурсы на HTTPS; проверьте поведение браузера.", "low")
    tls = response["tls"]
    if tls and tls.get("expires"):
        days = int((ssl.cert_time_to_seconds(tls["expires"]) - time.time()) / 86400)
        tls["days_remaining"] = days
        if days < 30:
            add("tls.expiry", "Сертификат истекает менее чем через 30 дней", {"days_remaining": days}, "Проверьте автоматическое продление сертификата.", "low")
    # Only selected, non-secret headers are retained; never store cookie values or body.
    retained = {k: v for k, v in headers.items() if k in {
        "content-type", "content-security-policy", "strict-transport-security", "x-content-type-options",
        "referrer-policy", "permissions-policy", "x-frame-options", "server", "x-powered-by"}}
    page = {"url": public_url(url), "status": response["status"], "elapsed_seconds": response["elapsed"],
            "title": parser.title.strip(), "headers": retained, "cookies": cookies, "forms": forms,
            "tls": tls, "body_bytes": len(response["body"]), "body_truncated": response["truncated"],
            "body_sha256": hashlib.sha256(response["body"]).hexdigest()}
    links = [resolved for x in parser.links if (resolved := resolve_url(base, x))]
    if response["status"] in (301, 302, 303, 307, 308) and headers.get("location"):
        redirect = resolve_url(url, headers["location"])
        page["redirect"] = public_url(redirect) if redirect else "[invalid or non-HTTP redirect]"
        if redirect:
            links.insert(0, redirect)
    return page, issues, links


def scan(scope, crawl=False, auth_headers=None, on_event=None, on_response=None):
    from .events import Events
    events = Events(on_event)
    progress_total = scope.max_pages if crawl else len(set(scope.targets))
    events.emit("Начало HTTP/TLS-аудита", total=progress_total)
    queue, queued, visited = deque(scope.targets), set(scope.targets), set()
    pages, issues, errors = [], [], []
    started = datetime.now(timezone.utc).isoformat()
    last_start = None
    try:
        while queue and len(visited) < scope.max_pages:
            url = queue.popleft()
            if url in visited:
                continue
            if last_start is not None:
                time.sleep(max(0, scope.delay - (time.monotonic() - last_start)))
            visited.add(url)
            last_start = time.monotonic()
            events.emit("GET", len(visited) - 1, progress_total, url=public_url(url))
            try:
                response = fetch(url, scope, (auth_headers or {}).get(origin(url)))
                if on_response:
                    on_response(url, response)
                page, findings, links = inspect_response(url, response)
                pages.append(page)
                issues.extend(findings)
                events.emit(f"HTTP {page['status']}; замечаний: {len(findings)}", len(visited), progress_total, url=public_url(url), elapsed_seconds=page["elapsed_seconds"])
                if crawl:
                    for link in links:
                        try:
                            link = canonical_url(link)
                            # Query links may trigger actions or unbounded URL combinations.
                            if urlsplit(link).query or not scope.permits(link) or link in queued:
                                continue
                        except ValueError:
                            continue
                        if len(queued) < scope.max_pages:
                            queue.append(link)
                            queued.add(link)
            except (OSError, HTTPException, ValueError) as exc:
                events.emit(type(exc).__name__, len(visited), progress_total, url=public_url(url), level="error")
                # Exception text can contain reflected URLs/secrets; retain only type.
                errors.append({"url": public_url(url), "type": type(exc).__name__, "message": "Запрос не выполнен; проверьте DNS, соединение, TLS и формат ответа."})
    except KeyboardInterrupt:
        errors.append({"type": "Interrupted", "message": "Остановлено пользователем; сохранён частичный результат."})
    events.emit("Аудит завершён" if not errors else "Аудит завершён с ошибками", len(visited), max(1, len(visited)), finished=True)
    return {"timeline": events.items, "completed_utc": datetime.now(timezone.utc).isoformat(), "schema_version": 1, "generated_utc": started, "mode": "crawl" if crawl else "targets",
            "scope": {"targets": [public_url(x) for x in scope.targets], "allowed_origins": sorted(scope.allowed_origins),
                      "exclude_paths": scope.exclude_paths, "max_pages": scope.max_pages, "delay": scope.delay},
            "requests": len(visited), "pages": pages, "findings": issues, "errors": errors,
            "limitations": ["Проверка конфигурации и доступного HTML; бизнес-логика и эксплуатация не проверяются.",
                            "TLS: проверка доверия, hostname и срока сертификата текущего соединения; не перебор шифров.",
                            "Cookies не сохраняются между запросами. JavaScript не выполняется. Формы не отправляются.",
                            "Наличие замечаний не подтверждает эксплуатацию; отсутствие замечаний не доказывает безопасность."]}
