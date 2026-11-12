"""Explicit-scope TCP inventory, bounded GET load sampling and offline review."""
from datetime import datetime, timezone
from http.client import HTTPException
import ast
import errno
import math
from pathlib import Path
import re
import socket
import time
from urllib.parse import urlsplit

from .events import Events
from .reports import empty_report
from .scanner import fetch, finding
from .scope import origin, public_url


def finish(data, events):
    events.emit("Завершено" if not data["errors"] else "Завершено с ошибками", finished=True)
    data["timeline"] = events.items
    data["completed_utc"] = datetime.now(timezone.utc).isoformat()
    return data


def ports(scope, on_event=None):
    """Connect only to host:port pairs explicitly present in allowed_origins."""
    data, events = empty_report(), Events(on_event)
    endpoints = sorted({(urlsplit(x).hostname, urlsplit(x).port or (443 if x.startswith("https:") else 80))
                        for x in scope.allowed_origins})
    if len(endpoints) > 1000:
        raise ValueError("Не более 1000 явных TCP endpoints за запуск")
    data.update(mode="tcp-inventory", ports=[], requests=0,
                scope={"allowed_origins": sorted(scope.allowed_origins)},
                limitations=["TCP connect без баннеров; открытый порт сам по себе не является уязвимостью."])
    try:
        for index, (host, port) in enumerate(endpoints):
            if index:
                time.sleep(scope.delay)
            events.emit(f"TCP {host}:{port}", index, len(endpoints))
            data["requests"] += 1
            state = "open"
            try:
                with socket.create_connection((host, port), timeout=scope.timeout):
                    pass
            except OSError as exc:
                state = "closed" if exc.errno == errno.ECONNREFUSED else "unknown"
                if state == "unknown":
                    data["errors"].append({"type": type(exc).__name__, "host": host, "port": port})
            data["ports"].append({"host": host, "port": port, "state": state})
            events.emit(f"TCP {host}:{port}: {state}", index + 1, len(endpoints))
    except KeyboardInterrupt:
        data["errors"].append({"type": "Interrupted"})
    return finish(data, events)


def validate_load(scope, count=10, rps=1.0):
    if isinstance(count, bool) or not isinstance(count, int) or not 1 <= count <= min(1000, scope.max_pages):
        raise ValueError("requests: целое число от 1 до min(1000, scope.max_pages)")
    if isinstance(rps, bool) or not isinstance(rps, (float, int)) or not math.isfinite(rps) or not 0.1 <= rps <= 10:
        raise ValueError("rps: число от 0.1 до 10")
    # Validate the full target list before any request, including direct API callers.
    if not scope.targets or any(not scope.permits(x) for x in scope.targets):
        raise ValueError("Цель вне scope")


def load_test(scope, count=10, rps=1.0, auth_headers=None, on_event=None):
    validate_load(scope, count, rps)
    data, events = empty_report(), Events(on_event)
    interval = max(scope.delay, 1 / rps)
    data.update(mode="load-test", requests=0, samples=[],
                scope={"targets": [public_url(x) for x in scope.targets], "allowed_origins": sorted(scope.allowed_origins)},
                load={"planned_requests": count, "max_rps": 1 / interval, "concurrency": 1},
                limitations=["Ограниченная последовательная выборка GET; не определяет предельную пропускную способность.",
                             "Без редиректов, отправки форм и сохранения cookies; GET должен быть безопасным для выбранных маршрутов."])
    last, failures = None, 0
    started = time.monotonic()
    try:
        for index in range(count):
            url = scope.targets[index % len(scope.targets)]
            if last is not None:
                time.sleep(max(0, interval - (time.monotonic() - last)))
            events.emit("Нагрузочный GET", index, count, url=public_url(url))
            last = time.monotonic()
            data["requests"] += 1
            sample = {"url": public_url(url), "timestamp": datetime.now(timezone.utc).isoformat()}
            try:
                response = fetch(url, scope, (auth_headers or {}).get(origin(url)))
                sample.update(status=response["status"], elapsed_seconds=response["elapsed"], body_truncated=response["truncated"])
                failures = failures + 1 if response["status"] >= 500 else 0
                stop = response["status"] in (429, 503) or failures >= 3
            except (OSError, HTTPException, ValueError) as exc:
                sample["error"] = type(exc).__name__
                data["errors"].append({"type": type(exc).__name__, "url": public_url(url)})
                failures += 1
                stop = failures >= 3
            data["samples"].append(sample)
            events.emit(f"GET: {sample.get('status', sample.get('error'))}", index + 1, count,
                        url=public_url(url), elapsed_seconds=sample.get("elapsed_seconds"))
            if stop:
                data["errors"].append({"type": "SafetyStop", "message": "Остановка: 429/503 или три последовательных сбоя."})
                break
    except KeyboardInterrupt:
        data["errors"].append({"type": "Interrupted"})
    elapsed = time.monotonic() - started
    latencies = sorted(x["elapsed_seconds"] for x in data["samples"] if "elapsed_seconds" in x)
    data["load"].update(duration_seconds=round(elapsed, 3),
                        achieved_rps=round(data["requests"] / max(elapsed, 0.001), 3),
                        http_errors=sum(x.get("status", 0) >= 400 for x in data["samples"]),
                        transport_errors=sum("error" in x for x in data["samples"]),
                        p50_seconds=latencies[math.ceil(len(latencies) * .5) - 1] if latencies else None,
                        p95_seconds=latencies[math.ceil(len(latencies) * .95) - 1] if latencies else None)
    return finish(data, events)


# Heuristics deliberately report rule names/line numbers, never source or secrets.
CONFIG_RULES = [
    ("debug", r"(?im)^\s*(?:DEBUG\s*=\s*(?:True|1)|debug\s*[:=]\s*true)\b", "Режим debug включён", "Отключите debug в production.", "medium"),
    ("tls_verify", r"(?i)\bverify\s*=\s*False\b|\bssl_verify\s*[:=]\s*false\b", "Отключена проверка TLS", "Включите проверку доверия и имени TLS-сертификата.", "medium"),
    ("secret", r'''(?im)^\s*["']?(?:SECRET_KEY|API_KEY|PASSWORD|ACCESS_TOKEN)["']?\s*[:=]\s*["'][^"'\n]{8,}["']''', "Возможный секрет в коде/конфиге", "Проверьте вручную; перенесите секрет в хранилище и замените при раскрытии.", "medium"),
]


def review_code(root, on_event=None):
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("code: нужен локальный каталог, не symlink")
    root = root.resolve()
    data, events = empty_report(), Events(on_event)
    data.update(mode="code-review", files_reviewed=0, checklist_sources=["https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
                                   "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html"],
                limitations=["Эвристики конфигурации и Python AST; не полный SAST и не подтверждение соответствия OWASP.",
                             "До 500 файлов, каждый до 1 MiB; symlinks и каталоги зависимостей пропускаются."])
    ignored = {".git", ".venv", "venv", "node_modules", "__pycache__", "reports", "archive", "risks"}
    suffixes = {".py", ".json", ".yaml", ".yml", ".toml", ".ini", ".conf", ".env"}
    import os
    files = []
    for directory, folders, names in os.walk(root, followlinks=False):
        folders[:] = sorted(x for x in folders if x not in ignored and not (Path(directory) / x).is_symlink())
        for name in sorted(names):
            path = Path(directory) / name
            if (path.suffix in suffixes or name == ".env") and not path.is_symlink():
                files.append(path)
                if len(files) > 500:
                    break
        if len(files) > 500:
            data["errors"].append({"type": "FileLimit", "message": "Лимит 500 файлов; анализ неполный."})
            files = files[:500]
            break
    try:
        for index, path in enumerate(files):
            relative = path.relative_to(root).as_posix()
            events.emit("Анализ " + relative, index, len(files))
            try:
                # Bound the read even if the file grows between stat and read.
                with path.open("rb") as stream:
                    raw = stream.read(1024 * 1024 + 1)
                if len(raw) > 1024 * 1024:
                    data["errors"].append({"type": "FileSizeLimit", "file": relative})
                    continue
                text = raw.decode("utf-8")
                matches = [(rule, text.count("\n", 0, m.start()) + 1, title, advice, severity)
                           for rule, pattern, title, advice, severity in CONFIG_RULES for m in re.finditer(pattern, text)]
                if path.suffix == ".py":
                    tree = ast.parse(text)
                    for node in ast.walk(tree):
                        if isinstance(node, ast.Call):
                            name = node.func.id if isinstance(node.func, ast.Name) else getattr(node.func, "attr", "")
                            if name in ("eval", "exec") or any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True for k in node.keywords):
                                matches.append(("dynamic_execution", node.lineno, "Динамическое выполнение или shell=True", "Проверьте поток недоверенного ввода; используйте явные аргументы и безопасный разбор.", "medium"))
                for rule, line, title, advice, severity in matches:
                    item = finding("code." + rule, title, "", {"file": relative, "line": line}, advice, severity)
                    item["confidence"] = "heuristic-review-required"
                    data["findings"].append(item)
                data["files_reviewed"] += 1
            except (OSError, UnicodeError, SyntaxError) as exc:
                data["errors"].append({"type": type(exc).__name__, "file": relative})
    except KeyboardInterrupt:
        data["errors"].append({"type": "Interrupted"})
    return finish(data, events)
