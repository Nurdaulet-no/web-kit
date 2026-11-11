"""Production-oriented orchestration; incomplete coverage is never reported as success."""
from datetime import datetime, timezone
from pathlib import Path
import tempfile

from .engines import Captures, ENGINES, run_engine
from .events import Events
from .reports import empty_report, write_report
from .safe import review_code, validate_load
from .scanner import scan, finding
from .scope import public_url


def run_production(scope, output, count, rps, headers, code_path, on_event, tls_enumeration):
    validate_load(scope, count, rps)
    if len(scope.allowed_origins) > 1000:
        raise ValueError("Не более 1000 origins за запуск")
    if code_path is not None and (Path(code_path).is_symlink() or not Path(code_path).is_dir()):
        raise ValueError("code-path: нужен локальный каталог, не symlink")
    data = empty_report()
    data.update(mode="production-orchestrator", requests=0, engines=[], coverage=[], runs=[],
                scope={"targets": [public_url(x) for x in scope.targets], "allowed_origins": sorted(scope.allowed_origins)},
                coverage_gaps=["Авторизованные роли и бизнес-логика не проверены автоматически.",
                               "Нет браузерного исполнения JavaScript и импорта API-схемы.",
                               "Nuclei/ZAP анализируют полученные ответы пассивно; активные CVE-проверки не выполняются.",
                               "Предельная производительность не измеряется: k6 использует один VU и заданный бюджет."],
                limitations=["Название профиля production задаёт ограничения запуска, а не сертификацию полноты аудита.",
                             "Количество HTTP-запросов учитывается сканером и k6; пакеты/соединения Nmap отдельно не подсчитываются.",
                             "Пассивные движки видят только ограниченные max_bytes части полученных ответов."])
    if not code_path:
        data["coverage_gaps"].append("Исходники и конфигурация не переданы; SAST, зависимости и контейнеры не проверены.")
    else:
        data["coverage_gaps"].append("Локальный анализ ограничен эвристиками; полный SAST, зависимости и контейнеры не проверены.")
    total = 1 + len(ENGINES) + (1 if code_path else 0)
    step = 0
    def progress(event):
        mapped = dict(event)
        fraction = 1 if event.get("finished") else min(.99, event.get("completed", 0) / max(1, event.get("total", 1)))
        mapped.update(completed=step + fraction, total=total, finished=False)
        if on_event:
            on_event(mapped)
    events = Events(progress)
    def collect(result):
        data["requests"] += result.get("requests", 0)
        data["findings"].extend(result.get("findings", []))
        data["errors"].extend(result.get("errors", []))
        data["runs"].append({k: v for k, v in result.items() if k not in ("findings", "pages", "timeline")})
    with tempfile.TemporaryDirectory(prefix="audit-capture-") as tmp:
        captures = Captures(tmp)
        events.emit("Обход HTML внутри scope и сбор ответов")
        result = scan(scope, crawl=True, auth_headers=headers, on_event=events.callback, on_response=captures)
        collect(result)
        data["pages"] = result["pages"]
        # Keep native scanner events as well as orchestration events in the durable timeline.
        events.items.extend(result.get("timeline", []))
        write_report(result, Path(output) / "scan")
        data["coverage"].append({"engine": "http-tls-crawler", "status": "error" if result["errors"] else "completed",
                                 "pages": len(result["pages"]), "budget": scope.max_pages})
        stop_network = bool(result["errors"])
        interrupted = any(x.get("type") == "Interrupted" for x in result["errors"])
        step += 1
        for name in ENGINES:
            if interrupted or (stop_network and name in ("nmap", "k6")):
                record = {"engine": name, "status": "skipped", "reason": "Предыдущий сетевой этап завершился ошибкой или был прерван"}
            else:
                record = run_engine(name, scope, output, captures, events, count, rps, headers, tls_enumeration)
            data["engines"].append(record)
            data["coverage"].append({k: record[k] for k in ("engine", "status", "reason", "mode", "version") if k in record})
            data["findings"].extend(record.get("findings", []))
            if name == "nmap":
                data["ports"] = record.get("ports", [])
                for port in data["ports"]:
                    for script in port.get("scripts", []):
                        if script["id"] == "ssl-enum-ciphers" and any(x in script["output"] for x in ("TLSv1.0:", "TLSv1.1:", "SSLv3:")):
                            issue = finding("nmap.tls.legacy", "Nmap обнаружил устаревшую версию TLS/SSL", port["origin"], script["output"],
                                            "Отключите устаревшие протоколы после проверки совместимости клиентов.", "medium")
                            data["findings"].append(issue)
            if name == "k6":
                data["requests"] += record.get("requests", 0)
                metrics = record.get("metrics", {}).get("metrics", {})
                data["load"] = {"engine": "k6", "concurrency": 1, "planned_requests": count, "requests": record.get("requests", 0),
                                "response_time_ms": metrics.get("http_req_duration", {}).get("values", {}),
                                "failed_requests": metrics.get("http_req_failed", {}).get("values", {}),
                                "max_rps": 1 / max(scope.delay, 1 / rps)}
            if record["status"] != "completed":
                data["errors"].append({"type": "EngineIncomplete", "engine": name, "status": record["status"], "message": record.get("reason", "Движок не завершил проверку")})
            if record["status"] == "interrupted" or any(x.get("status") == "interrupted" for x in record.get("results", [])):
                interrupted = True
            events.emit(f"Этап {name}: {record['status']}", finished=True)
            step += 1
        if captures.limited:
            data["errors"].append({"type": "CaptureLimit", "message": "Пассивные движки получили неполный набор ответов: лимит 20 MiB."})
        if code_path and not interrupted:
            result = review_code(code_path, on_event=progress)
            collect(result)
            data["files_reviewed"] = result["files_reviewed"]
            write_report(result, Path(output) / "code")
            events.items.extend(result.get("timeline", []))
            data["coverage"].append({"engine": "code-heuristics", "status": "error" if result["errors"] else "completed"})
        elif code_path:
            data["coverage"].append({"engine": "code-heuristics", "status": "skipped"})
    # Exact duplicates are merged, but corroborating results from different rules retain provenance.
    import json
    unique = {}
    for item in data["findings"]:
        key = json.dumps([item.get("rule"), item.get("url"), item.get("evidence")], sort_keys=True)
        unique.setdefault(key, item)
    data["findings"] = list(unique.values())
    data["execution_status"] = "incomplete" if data["errors"] else "completed"
    data["completed_utc"] = datetime.now(timezone.utc).isoformat()
    data["timeline"] = sorted(events.items, key=lambda x: x.get("timestamp", ""))
    event = {"timestamp": data["completed_utc"], "message": f"Запуск: {data['execution_status']}; проверьте покрытие",
             "completed": total, "total": total, "finished": True}
    data["timeline"].append(event)
    if on_event:
        on_event(event)
    return data
