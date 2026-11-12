"""One command interface for scanning, importing and documenting findings."""
import argparse
import json
from pathlib import Path
import shutil
import ssl
import sys

from . import __version__
from .active import validate_plan, verify
from .reports import add_evidence, empty_report, load_json, merge_reports, write_report
from .scanner import scan
from .pipeline import run_pipeline
from .safe import ports, load_test, review_code
from .security import run_security_check
from .tui import TerminalUI
from .scope import Scope, canonical_url, origin


def read_headers(path, scope):
    if not path:
        return {}
    data = load_json(path)
    if not isinstance(data, dict):
        raise ValueError("Файл headers: объект {origin: {header: value}}")
    result = {}
    forbidden = {"host", "content-length", "transfer-encoding", "connection", "accept-encoding"}
    for host, headers in data.items():
        normalized = canonical_url(host)
        if normalized != origin(normalized) + "/" or origin(normalized) not in scope.allowed_origins:
            raise ValueError("Origin в headers должен точно входить в allowed_origins")
        if not isinstance(headers, dict):
            raise ValueError("Headers должен быть объектом")
        for key, value in headers.items():
            if not isinstance(key, str) or not isinstance(value, str) or key.lower() in forbidden:
                raise ValueError("Недопустимый HTTP-заголовок")
            import re
            if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", key) or any(ord(c) < 32 or ord(c) > 255 or ord(c) == 127 for c in value):
                raise ValueError("Недопустимые символы в HTTP-заголовке")
        result[origin(normalized)] = headers
    return result


def prompt_url():
    print("Web Audit Kit — оркестратор проверок (production)")
    print("Введите URL своего сайта или сайта, который вам разрешено проверять.")
    while True:
        value = input("URL: ").strip()
        try:
            if not value:
                raise ValueError("Введите адрес сайта")
            # A bare hostname uses HTTPS; explicit schemes still pass strict validation.
            if "://" not in value:
                value = "https://" + value
            url = canonical_url(value)
            Scope.from_dict({"targets": [url], "allowed_origins": [origin(url)]})
            return url
        except ValueError as exc:
            print(f"Некорректный URL: {exc}. Попробуйте ещё раз.")


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        try:
            argv = ["run", "--url", prompt_url(), "--authorized"]
        except (EOFError, KeyboardInterrupt):
            print("\nЗапуск отменён.")
            return 2
    parser = argparse.ArgumentParser(description="Web Audit Kit — единая система аудита веб-конфигурации")
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("doctor", help="Проверить окружение")
    check = commands.add_parser("check-scope", help="Проверить настройки без сетевых запросов")
    check.add_argument("scope")
    run = commands.add_parser("scan", help="Проверить реальные HTTP/HTTPS-цели")
    run.add_argument("--scope", required=True, help="JSON с целями и точными разрешёнными origins")
    run.add_argument("--authorized", action="store_true", required=True, help="Подтверждаю разрешение на проверку целей")
    run.add_argument("--crawl", action="store_true", help="Обход ссылок и редиректов внутри scope; только GET, без query-ссылок")
    run.add_argument("--headers-file", help="Приватный JSON {origin: {header: value}} для сессий")
    run.add_argument("--out", help="Папка отчёта (по умолчанию новый каталог с датой)")
    run.add_argument("--fail-on", choices=["low", "medium", "high", "critical"], help="Код 1 при замечаниях указанной серьёзности и выше")
    active = commands.add_parser("verify", help="SQLi boolean/UNION-canary, HTML-инъекция и CORS по явному плану")
    active.add_argument("--scope", required=True)
    active.add_argument("--plan", required=True, help="JSON с типами проверок, URL и параметрами")
    active.add_argument("--authorized", action="store_true", required=True, help="Подтверждаю разрешение на активные проверки")
    active.add_argument("--headers-file")
    active.add_argument("--max-requests", type=int, default=50, help="Общий бюджет GET, включая baseline и повторы (1–5000)")
    active.add_argument("--out")
    active.add_argument("--fail-on", choices=["low", "medium", "high", "critical"])
    plan = commands.add_parser("check-plan", help="Проверить scope и активный план без сети")
    plan.add_argument("--scope", required=True)
    plan.add_argument("--plan", required=True)
    merge = commands.add_parser("merge", help="Объединить отчёты Web Audit Kit, Nuclei и ZAP")
    merge.add_argument("--report", action="append", required=True)
    merge.add_argument("--out", required=True)
    evidence = commands.add_parser("evidence", help="Добавить ручные доказательства в единый отчёт")
    evidence.add_argument("--report", help="Исходный report.json; без него создаётся новый отчёт")
    evidence.add_argument("--title", required=True)
    evidence.add_argument("--expected", required=True)
    evidence.add_argument("--observed", required=True)
    evidence.add_argument("--request")
    evidence.add_argument("--response")
    evidence.add_argument("--out", required=True)
    network = []
    for name, help_text in (("ports", "TCP connect только к host:port из allowed_origins"),
                            ("load", "Ограниченный последовательный нагрузочный GET-тест")):
        command = commands.add_parser(name, help=help_text)
        command.add_argument("--scope", required=True)
        command.add_argument("--authorized", action="store_true", required=True)
        network.append(command)
    network[1].add_argument("--requests", type=int, default=10)
    network[1].add_argument("--rps", type=float, default=1.0)
    network[1].add_argument("--headers-file")
    code = commands.add_parser("code", help="Локальный эвристический анализ Python и конфигов")
    code.add_argument("--path", required=True)
    security = commands.add_parser("security", help="Проверки безопасности: зависимости, RCE, конфигурация")
    security.add_argument("--scope", required=True)
    security.add_argument("--code-path", required=True)
    security.add_argument("--authorized", action="store_true", required=True)
    security.add_argument("--out")
    security.add_argument("--fail-on", choices=["low", "medium", "high", "critical"])
    security.add_argument("--ui", choices=["auto", "on", "off"], default="auto")
    attack = commands.add_parser("attack", help="Экспериментальная команда — не подключена")
    attack.add_argument("--scope", required=True)
    attack.add_argument("--authorized", action="store_true", required=True)
    attack.add_argument("--load", type=int, required=True, help="Уровень нагрузки для атаки")
    attack.add_argument("--duration", type=int, default=300, help="Длительность атаки в секундах")
    attack.add_argument("--out")
    attack.add_argument("--fail-on", choices=["low", "medium", "high", "critical"])
    rce = commands.add_parser("rce", help="Экспериментальная команда — не подключена; анализ кода: security")
    rce.add_argument("--scope", required=True)
    rce.add_argument("--authorized", action="store_true", required=True)
    rce.add_argument("--code-path", required=True)
    rce.add_argument("--out")
    rce.add_argument("--fail-on", choices=["low", "medium", "high", "critical"])
    sequence = commands.add_parser("run", help="Последовательно scan → ports → load → общий отчёт")
    target = sequence.add_mutually_exclusive_group(required=True)
    target.add_argument("--url", help="URL сайта; scope создаётся автоматически для его точного origin")
    target.add_argument("--scope", help="Готовый JSON scope вместо --url")
    sequence.add_argument("--authorized", action="store_true", required=True)
    sequence.add_argument("--profile", choices=["production", "basic"], default="production", help="production: реальные внешние движки; basic: встроенные проверки")
    sequence.add_argument("--tls-enumeration", action="store_true", help="Дополнительно Nmap ssl-enum-ciphers: много TLS-соединений")
    sequence.add_argument("--requests", type=int, default=10, help="Бюджет GET только для нагрузочного этапа")
    sequence.add_argument("--rps", type=float, default=1.0)
    sequence.add_argument("--headers-file")
    sequence.add_argument("--code-path", help="Дополнительно проверить локальный каталог кода")
    for command in (run, active, *network, code, sequence):
        command.add_argument("--ui", choices=["auto", "on", "off"], default="auto",
                             help="Закреплённый прогресс и живой лог; при перенаправлении — строки")
        if command not in (run, active):
            command.add_argument("--out")
            command.add_argument("--fail-on", choices=["low", "medium", "high", "critical"])
    args = parser.parse_args(argv)
    try:
        if args.command == "doctor":
            print(f"Web Audit Kit {__version__} | Python {sys.version.split()[0]} | {ssl.OPENSSL_VERSION}")
            print("Встроенные HTTP/TLS-проверки: готовы, сторонние зависимости не нужны.")
            for tool in ("nmap", "k6", "nuclei", "zap.sh", "zaproxy", "docker", "curl"):
                print(f"{tool}: {shutil.which(tool) or 'не установлен'}")
            print("Профиль production требует nmap, k6, nuclei и zap.sh/zaproxy; отсутствие движка отмечается в отчёте с кодом 2.")
            return 0
        if args.command == "check-scope":
            scope = Scope.from_dict(load_json(args.scope))
            print(f"Scope корректен: целей {len(scope.targets)}, origins {len(scope.allowed_origins)}, максимум запросов {scope.max_pages}")
            return 0
        if args.command == "check-plan":
            scope = Scope.from_dict(load_json(args.scope))
            checks = validate_plan(load_json(args.plan), scope)
            from .active import CHECK_TYPES
            print(f"Plan корректен: проверок {len(checks)}, полный бюджет не более {sum(CHECK_TYPES[x['type']] for x in checks)} GET")
            return 0
        if args.command in ("attack", "rce"):
            raise ValueError("Эта экспериментальная команда не подключена. Для локального анализа используйте code или security; для ограниченного нагрузочного теста — load.")
        if args.command in ("scan", "verify", "ports", "load", "code", "run", "security"):
            from datetime import datetime, timezone
            output = args.out or "reports/" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
            if args.command == "run" and args.url:
                url = canonical_url(args.url)
                scope = Scope.from_dict({"targets": [url], "allowed_origins": [origin(url)], "max_pages": 100 if args.profile == "production" else 10})
            else:
                scope = None if args.command == "code" else Scope.from_dict(load_json(args.scope))
            headers = read_headers(getattr(args, "headers_file", None), scope)
            checks = validate_plan(load_json(args.plan), scope) if args.command == "verify" else None
            with TerminalUI(args.ui) as ui:
                if args.command == "run":
                    data = run_pipeline(scope, output, args.requests, args.rps, headers, args.code_path, on_event=ui, profile=args.profile, tls_enumeration=args.tls_enumeration)
                elif args.command == "scan":
                    data = scan(scope, args.crawl, headers, on_event=ui)
                elif args.command == "verify":
                    data = verify(scope, checks, args.max_requests, headers, on_event=ui)
                elif args.command == "ports":
                    data = ports(scope, on_event=ui)
                elif args.command == "load":
                    data = load_test(scope, args.requests, args.rps, headers, on_event=ui)
                elif args.command == "code":
                    data = review_code(args.path, on_event=ui)
                elif args.command == "security":
                    data = run_security_check(scope, args.code_path, on_event=ui)
        elif args.command == "merge":
            data, output = merge_reports(args.report), args.out
        else:
            data = load_json(args.report) if args.report else empty_report()
            if not isinstance(data, dict) or data.get("schema_version") != 1:
                raise ValueError("Нужен report.json Web Audit Kit")
            data = add_evidence(data, args.title, args.expected, args.observed, args.request, args.response)
            output = args.out
        data = write_report(data, output)
        print(f"Отчёт: {Path(output) / 'report.html'} (также JSON и Markdown)")
        print(f"Страниц: {data['summary']['pages']}; замечаний: {data['summary']['findings']}; ошибок: {data['summary']['errors']}")
        if args.command == "verify":
            from collections import Counter
            print("Проверки:", dict(Counter(x["status"] for x in data["active_results"])), "GET:", data["requests"])
        if data.get("coverage"):
            from collections import Counter
            print("Движки:", dict(Counter(x["status"] for x in data["coverage"])))
            print("Непроверенные области:", "; ".join(data.get("coverage_gaps", [])))
        if data.get("errors"):
            return 2
        if args.command in ("scan", "verify", "ports", "load", "code", "run", "security") and args.fail_on:
            rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
            if any(rank.get(x.get("severity"), 0) >= rank[args.fail_on] for x in data["findings"]):
                return 1
        return 0
    except (ValueError, OSError, TypeError, KeyError, AttributeError) as exc:
        print(f"Ошибка: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
