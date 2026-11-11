"""Sequential safe checks with one progress bar and combined report."""
from datetime import datetime, timezone
from pathlib import Path

from .reports import empty_report, write_report
from .safe import load_test, ports, review_code, validate_load
from .scanner import scan


def run_pipeline(scope, output, count=10, rps=1.0, headers=None, code_path=None, on_event=None, profile="basic", tls_enumeration=False):
    if profile == "production":
        from .production import run_production
        return run_production(scope, output, count, rps, headers, code_path, on_event, tls_enumeration)
    if profile != "basic":
        raise ValueError("Неизвестный профиль")
    # Complete preflight before starting the first network operation.
    validate_load(scope, count, rps)
    if code_path is not None:
        path = Path(code_path)
        if path.is_symlink() or not path.is_dir():
            raise ValueError("code-path: нужен локальный каталог, не symlink")
    stages = [
        ("scan", lambda callback: scan(scope, auth_headers=headers, on_event=callback)),
        ("ports", lambda callback: ports(scope, on_event=callback)),
        ("load", lambda callback: load_test(scope, count, rps, headers, on_event=callback)),
    ]
    if code_path is not None:
        stages.append(("code", lambda callback: review_code(code_path, on_event=callback)))
    data = empty_report()
    data.update(mode="safe-pipeline", requests=0, timeline=[], runs=[],
                scope={"targets": scope.targets, "allowed_origins": sorted(scope.allowed_origins)},
                limitations=["Последовательные scan → ports → load; при ошибке этапа последующие этапы пропускаются.",
                             "TCP-проверка ограничена портами allowed_origins; load ограничен scope и заданным бюджетом."])
    for index, (name, execute) in enumerate(stages):
        def progress(event):
            event = dict(event)
            fraction = 1 if event.get("finished") else min(.99, event["completed"] / max(1, event["total"]))
            event.update(message=f"[{name}] {event['message']}", stage=name,
                         completed=index + fraction, total=len(stages), finished=False)
            data["timeline"].append(event)
            if on_event:
                on_event(event)
        result = execute(progress)
        write_report(result, Path(output) / name)
        data["runs"].append({k: v for k, v in result.items() if k not in ("pages", "findings", "timeline", "samples", "ports")})
        data["requests"] += result.get("requests", 0)
        for key in ("pages", "findings", "errors", "samples", "ports"):
            data.setdefault(key, []).extend(result.get(key, []))
        for key in ("load", "files_reviewed", "checklist_sources"):
            if key in result:
                data[key] = result[key]
        if result.get("errors"):
            data["skipped_stages"] = [x[0] for x in stages[index + 1:]]
            break
    event = {"timestamp": datetime.now(timezone.utc).isoformat(),
             "message": "Запуск завершён с ошибками" if data["errors"] else "Все этапы завершены",
             "completed": len(stages), "total": len(stages), "finished": True}
    data["completed_utc"] = event["timestamp"]
    data["timeline"].append(event)
    if on_event:
        on_event(event)
    return data
