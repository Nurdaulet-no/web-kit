"""Explicit, bounded active verification with fixed non-destructive probes."""
from datetime import datetime, timezone
import hashlib
from html.parser import HTMLParser
from http.client import HTTPException
import secrets
import time
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .reports import empty_report
from .scanner import fetch, finding
from .scope import canonical_url, origin, public_url


CHECK_TYPES = {"sqli-boolean": 6, "sqli-union": 8, "html-injection": 3, "cors": 3}


def validate_plan(data, scope):
    if not isinstance(data, dict) or set(data) != {"checks"}:
        raise ValueError("Plan должен содержать только список checks")
    checks = data["checks"]
    if not isinstance(checks, list) or not 1 <= len(checks) <= 100:
        raise ValueError("В checks должно быть от 1 до 100 проверок")
    normalized = []
    for item in checks:
        if not isinstance(item, dict) or item.get("type") not in CHECK_TYPES:
            raise ValueError("Неизвестный тип проверки в plan")
        required = {"type", "url"} | ({"parameter"} if item["type"] != "cors" else set())
        if set(item) != required:
            raise ValueError("Поля проверки: " + ", ".join(sorted(required)))
        url = canonical_url(item["url"])
        if not scope.permits(url):
            raise ValueError("Проверка вне scope: " + public_url(url))
        if item["type"] != "cors":
            parameter = item["parameter"]
            if not isinstance(parameter, str) or not parameter or any(ord(c) < 32 for c in parameter):
                raise ValueError("Нужен корректный parameter")
            pairs = parse_qsl(urlsplit(url).query, keep_blank_values=True, max_num_fields=100)
            values = [v for k, v in pairs if k == parameter]
            if len(values) != 1:
                raise ValueError("Параметр должен присутствовать в URL ровно один раз")
        normalized.append({**item, "url": url})
    return normalized


def mutate(url, parameter, value):
    p = urlsplit(url)
    pairs = parse_qsl(p.query, keep_blank_values=True, max_num_fields=100)
    return urlunsplit((p.scheme, p.netloc, p.path, urlencode([(k, value if k == parameter else v) for k, v in pairs]), ""))


def response_digest(response):
    return hashlib.sha256(response["body"]).hexdigest()


def content_type(response):
    return dict((k.lower(), v) for k, v in response["headers"]).get("content-type", "").split(";")[0].strip().lower()


def usable(response):
    encoding = dict((k.lower(), v) for k, v in response["headers"]).get("content-encoding", "identity").lower()
    return 200 <= response["status"] < 300 and not response["truncated"] and encoding == "identity"


class ProbeParser(HTMLParser):
    """Only count marker elements outside inert/raw-text contexts."""
    INERT = {"script", "style", "textarea", "title", "xmp", "iframe", "noembed", "noframes", "plaintext", "template", "noscript"}

    def __init__(self, marker):
        super().__init__()
        self.marker, self.inert, self.found = marker, [], False

    def handle_starttag(self, tag, attrs):
        if tag in self.INERT:
            self.inert.append(tag)
        if not self.inert and tag == "span" and dict(attrs).get("data-audit-probe") == self.marker:
            self.found = True

    def handle_endtag(self, tag):
        if self.inert and tag == self.inert[-1]:
            self.inert.pop()


class Runner:
    def __init__(self, scope, headers, data, max_requests):
        self.scope, self.headers, self.data = scope, headers or {}, data
        self.max_requests = max_requests
        self.last_start = None
        self.trace = []
        self.events = None

    def get(self, url, extra=None, probe="baseline"):
        if not self.scope.permits(url):
            raise ValueError("Проверка вне scope")
        if self.data["requests"] >= self.max_requests:
            raise ValueError("Исчерпан бюджет запросов")
        if self.last_start is not None:
            time.sleep(max(0, self.scope.delay - (time.monotonic() - self.last_start)))
        self.last_start = time.monotonic()
        self.data["requests"] += 1
        if self.events:
            self.events.emit("GET: " + probe, self.data["requests"] - 1, self.max_requests, url=public_url(url))
        headers = {k: v for k, v in self.headers.get(origin(url), {}).items()
                   if not extra or k.lower() not in {x.lower() for x in extra}}
        headers.update(extra or {})
        record = {"url": public_url(url), "method": "GET", "probe": probe}
        self.trace.append(record)
        try:
            response = fetch(url, self.scope, headers)
            record.update({"status": response["status"], "body_bytes": len(response["body"]),
                           "body_sha256": response_digest(response), "truncated": response["truncated"]})
            if self.events:
                self.events.emit(f"HTTP {response['status']}", self.data["requests"], self.max_requests, url=public_url(url), elapsed_seconds=response["elapsed"])
            return response
        except (OSError, HTTPException, ValueError) as exc:
            record["error"] = type(exc).__name__
            raise


def result(status, reason, issue=None):
    return {"status": status, "reason": reason}, issue


def sql_boolean(check, runner):
    url, parameter = check["url"], check["parameter"]
    original = next(v for k, v in parse_qsl(urlsplit(url).query, keep_blank_values=True) if k == parameter)
    baseline = runner.get(url)
    repeat = runner.get(url, probe="baseline-repeat")
    if not all(usable(x) for x in (baseline, repeat)) or content_type(baseline) != content_type(repeat):
        return result("inconclusive", "Baseline не является полным успешным ответом одинакового типа")
    if response_digest(baseline) != response_digest(repeat):
        return result("inconclusive", "Baseline нестабилен; сравнение не даёт достоверного вывода")
    responses = []
    numeric = original.isascii() and original.isdigit() and bool(original)
    predicates = []
    for _ in range(2):
        number = secrets.randbelow(900000) + 100000
        true = f" AND {number}={number}" if numeric else f"' AND '{number}'='{number}"
        false = f" AND {number}={number + 1}" if numeric else f"' AND '{number}'='{number + 1}"
        predicates.append({"true_suffix": true, "false_suffix": false})
        responses.append((runner.get(mutate(url, parameter, original + true), probe="sql-true"),
                          runner.get(mutate(url, parameter, original + false), probe="sql-false")))
    all_responses = [x for pair in responses for x in pair]
    if not all(usable(x) and content_type(x) == content_type(baseline) for x in all_responses):
        return result("inconclusive", "Изменение HTTP-статуса, усечение или кодирование ответа не считается SQLi")
    base_hash = response_digest(baseline)
    true_hashes = [response_digest(pair[0]) for pair in responses]
    false_hashes = [response_digest(pair[1]) for pair in responses]
    if all(x == base_hash for x in true_hashes) and false_hashes[0] == false_hashes[1] and false_hashes[0] != base_hash:
        issue = finding("active.sqli-boolean", "Признаки SQL-инъекции: повторяемая зависимость от логического условия", url,
                        {"parameter": parameter, "predicates": predicates, "baseline_sha256": base_hash,
                         "true_sha256": true_hashes, "false_sha256": false_hashes,
                         "interpretation": "Два разных истинных условия сохраняют baseline; ложные дают другой стабильный ответ. Исполнение SQL сервером не наблюдалось напрямую."},
                        "Используйте параметризованные запросы; подтвердите источник различий по серверным логам и коду.", "high")
        issue["confidence"] = "strong-differential-evidence"
        return result("finding", "Повторяемое true/false-различие; данные БД не извлекались", issue)
    return result("not-detected", "Строгая схема baseline=true и false≠baseline не воспроизвелась")


def html_injection(check, runner):
    url, parameter = check["url"], check["parameter"]
    baseline = runner.get(url)
    if not usable(baseline) or content_type(baseline) != "text/html":
        return result("inconclusive", "Нужен полный успешный ответ text/html")
    markers = []
    for _ in range(2):
        marker = "audit" + secrets.token_hex(10)
        payload = f'<span data-audit-probe="{marker}">{marker}</span>'
        response = runner.get(mutate(url, parameter, payload), probe="html-marker:" + marker)
        if not usable(response) or content_type(response) != "text/html":
            return result("inconclusive", "Ответ на маркер не является полным успешным HTML")
        parser = ProbeParser(marker)
        parser.feed(response["body"].decode("utf-8", "replace"))
        markers.append({"marker": marker, "element_found": parser.found, "body_sha256": response_digest(response)})
    if all(x["element_found"] for x in markers):
        issue = finding("active.html-injection", "Подтверждено внедрение HTML-разметки через query-параметр", url,
                        {"parameter": parameter, "markers": markers, "element": "span[data-audit-probe]",
                         "interpretation": "Маркер распознан как HTML-элемент вне инертных контекстов. JavaScript не исполнялся; это не подтверждение XSS."},
                        "Экранируйте вывод по HTML-контексту и используйте безопасные шаблоны.", "medium")
        issue["confidence"] = "verified-html-structure"
        return result("finding", "Два независимых маркера стали HTML-элементами", issue)
    return result("not-detected", "Маркеры не стали HTML-элементами вне инертного контекста")


def sql_union(check, runner):
    """Compute a split constant via UNION; never request tables or stored values."""
    url, parameter = check["url"], check["parameter"]
    original = next(v for k, v in parse_qsl(urlsplit(url).query, keep_blank_values=True) if k == parameter)
    baseline = runner.get(url)
    if not usable(baseline):
        return result("inconclusive", "Нужен полный успешный baseline")
    closing_quote = "" if original.isascii() and original.isdigit() else "'"

    def attempt(columns, dialect):
        marker = "audit" + secrets.token_hex(12)
        left, right = marker[:14], marker[14:]
        expression = f"'{left}'||'{right}'" if dialect == "pipes" else f"CONCAT('{left}','{right}')"
        suffix = closing_quote + " UNION SELECT " + ",".join([expression] + ["NULL"] * (columns - 1)) + " -- "
        value = original + suffix
        if marker in value or marker.encode() in baseline["body"]:
            raise ValueError("Canary должен отсутствовать в запросе и baseline")
        response = runner.get(mutate(url, parameter, value), probe=f"sql-union:{columns}:{dialect}")
        matched = usable(response) and content_type(response) == content_type(baseline) and marker.encode() in response["body"]
        return matched, {"marker": marker, "suffix": suffix, "body_sha256": response_digest(response)}

    for columns in (1, 2, 3):
        for dialect in ("pipes", "concat"):
            matched, first = attempt(columns, dialect)
            if not matched:
                continue
            matched_again, second = attempt(columns, dialect)
            if not matched_again:
                return result("inconclusive", "SQL-canary появился однократно; независимый повтор не подтвердил результат")
            issue = finding("active.sqli-union", "Подтверждено вычисление двух SQL-canary через UNION SELECT", url,
                            {"parameter": parameter, "columns": columns, "dialect": dialect, "canaries": [first, second],
                             "interpretation": "В ответах появились два собранных маркера, отсутствовавших целиком во входе. SELECT содержит только константы и NULL; сохранённые значения БД не запрашивались."},
                            "Замените конкатенацию SQL параметризованными запросами; проверьте права учётной записи БД.", "high")
            issue["confidence"] = "verified-sql-canary"
            return result("finding", "Воспроизведено вычисление двух констант через SQL-инъекцию", issue)
    return result("not-detected", "SQL-canary не найден: проверены 1–3 столбца, первый столбец с маркером, два синтаксиса конкатенации")


def cors(check, runner):
    url = check["url"]
    baseline = runner.get(url)
    if not usable(baseline):
        return result("inconclusive", "Baseline не является полным успешным ответом")
    observations = []
    for _ in range(2):
        test_origin = "https://audit-" + secrets.token_hex(10) + ".invalid"
        response = runner.get(url, {"Origin": test_origin}, probe="cors-origin:" + test_origin)
        if not usable(response):
            return result("inconclusive", "Ответ Origin-проверки не является полным успешным ответом")
        headers = {}
        for key, value in response["headers"]:
            headers.setdefault(key.lower(), []).append(value.strip())
        # Duplicate CORS headers are invalid in browsers; do not report them as readable.
        reflected = headers.get("access-control-allow-origin") == [test_origin]
        credentialed = headers.get("access-control-allow-credentials") == ["true"]
        observations.append({"origin": test_origin, "allow_origin": headers.get("access-control-allow-origin", []),
                             "allow_credentials": headers.get("access-control-allow-credentials", []),
                             "policy_allows_credentials": reflected and credentialed})
    if all(x["policy_allows_credentials"] for x in observations):
        issue = finding("active.cors", "CORS отражает произвольный Origin и разрешает credentials", url,
                        {"observations": observations, "interpretation": "Подтверждено поведение CORS-заголовков. Доступ браузера к приватным данным не проверен; учитывайте SameSite и назначение API."},
                        "Сопоставляйте Origin с точным списком доверенных источников; credentials разрешайте только при необходимости.", "medium")
        issue["confidence"] = "verified-header-policy"
        return result("finding", "Два случайных Origin приняты с credentials", issue)
    return result("not-detected", "Произвольные Origin не приняты одновременно с credentials")


def verify(scope, checks, max_requests=50, auth_headers=None, on_event=None):
    from .events import Events
    events = Events(on_event)
    if isinstance(max_requests, bool) or not isinstance(max_requests, int) or not 1 <= max_requests <= 5000:
        raise ValueError("max_requests: целое число 1–5000")
    # Revalidate before sending any request, even for non-CLI callers.
    checks = validate_plan({"checks": checks}, scope)
    data = empty_report()
    data.update({"mode": "active-verification", "requests": 0, "active_results": [],
                 "scope": {"allowed_origins": sorted(scope.allowed_origins), "exclude_paths": scope.exclude_paths,
                           "max_requests": max_requests, "delay": scope.delay, "timeout": scope.timeout, "max_bytes": scope.max_bytes},
                 "limitations": ["Только явно заданные URL/параметры и фиксированные GET-пробы; автоматического обнаружения всех точек ввода нет.",
                                 "Нет извлечения данных БД, команд ОС, записи файлов, отправки форм и исполнения JavaScript.",
                                 "SQLi оценивается по повторяемым ответам; HTML-инъекция и CORS не доказывают XSS или утечку данных."]})
    runner = Runner(scope, auth_headers, data, max_requests)
    runner.events = events
    dispatch = {"sqli-boolean": sql_boolean, "sqli-union": sql_union, "html-injection": html_injection, "cors": cors}
    stopped = False
    events.emit("Начало активных проверок", total=max_requests)
    for index, check in enumerate(checks):
        events.emit(check["type"], data["requests"], max_requests, url=public_url(check["url"]))
        entry = {"index": index, "type": check["type"], "url": public_url(check["url"])}
        if "parameter" in check:
            entry["parameter"] = check["parameter"]
        runner.trace = []
        if stopped:
            outcome = {"status": "interrupted", "reason": "Пропущено после остановки пользователем"}
        elif data["requests"] + CHECK_TYPES[check["type"]] > max_requests:
            outcome = {"status": "skipped-budget", "reason": "Недостаточно бюджета для полной проверки"}
        else:
            try:
                outcome, issue = dispatch[check["type"]](check, runner)
                if issue:
                    data["findings"].append(issue)
            except KeyboardInterrupt:
                outcome = {"status": "interrupted", "reason": "Остановлено пользователем"}
                stopped = True
            except (OSError, HTTPException, ValueError) as exc:
                outcome = {"status": "error", "reason": "Запрос не выполнен", "error_type": type(exc).__name__}
        entry.update(outcome)
        entry["requests"] = runner.trace
        data["active_results"].append(entry)
        events.emit(outcome["status"], data["requests"], max_requests, url=entry["url"])
        if outcome["status"] in ("inconclusive", "skipped-budget", "interrupted", "error"):
            data["errors"].append({"check_index": index, "type": outcome["status"], "url": entry["url"], "message": outcome["reason"]})
    events.emit("Проверки завершены", len(checks), len(checks), finished=True)
    data["timeline"] = events.items
    data["completed_utc"] = datetime.now(timezone.utc).isoformat()
    return data
