"""Common report schema, offline imports and evidence records."""
from datetime import datetime, timezone
import html
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

from .scope import public_url


SECRET_KEYS = re.compile(r"(?i)^(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|api[-_]?key|access[-_]?token|refresh[-_]?token|session[-_]?token|secret|password)$")
SECRET_LINES = re.compile(r"(?im)^((?:authorization|proxy-authorization|cookie|set-cookie|x-api-key)\s*:\s*).*$")
SECRET_JSON = re.compile(r'(?i)("(?:access_token|refresh_token|api_key|secret|password|session_token)"\s*:\s*)"[^"\n]*"')
URL = re.compile(r"https?://[^\s<>\"']+")


def sanitize(value):
    if isinstance(value, dict):
        return {str(k): "[REDACTED]" if SECRET_KEYS.match(str(k)) else sanitize(v) for k, v in value.items()}
    if isinstance(value, list):
        return [sanitize(x) for x in value]
    if isinstance(value, str):
        value = SECRET_LINES.sub(lambda m: m.group(1) + "[REDACTED]", value)
        value = SECRET_JSON.sub(lambda m: m.group(1) + '"[REDACTED]"', value)
        def clean_url(match):
            try:
                # Remove userinfo as well as query values from imported URL strings.
                from urllib.parse import urlsplit, urlunsplit
                p = urlsplit(match.group())
                return public_url(urlunsplit((p.scheme, p.netloc.rsplit("@", 1)[-1], p.path, p.query, "")))
            except ValueError:
                return "[REDACTED URL]"
        return URL.sub(clean_url, value)
    return value


def execution_outcome(data):
    if (data.get("errors") or data.get("skipped_stages") or
            any(row.get("status") != "completed" for row in data.get("coverage", [])) or
            data.get("execution_status") in ("incomplete", "error", "interrupted")):
        return "incomplete"
    return "completed" if data.get("mode") or data.get("coverage") else "recorded"


def group_findings(findings):
    groups = {}
    ranks = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for item in findings:
        url = str(item.get("url", ""))
        try:
            parsed = urlsplit(url)
            site = f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else "Локальный анализ"
        except ValueError:
            site = "Импортированный результат"
        key = tuple(str(item.get(name, "")) for name in ("rule", "title", "severity", "confidence", "recommendation")) + (site,)
        if key not in groups:
            groups[key] = {name: item.get(name, "") for name in ("rule", "title", "severity", "confidence", "recommendation")}
            groups[key].update(site=site, occurrences=0, urls=[], evidence_samples=[])
        group = groups[key]
        group["occurrences"] += 1
        if url and url not in group["urls"]:
            group["urls"].append(url)
        evidence = item.get("evidence")
        if len(group["evidence_samples"]) < 3 and evidence not in group["evidence_samples"]:
            group["evidence_samples"].append(evidence)
    return sorted(groups.values(), key=lambda group: (ranks.get(group["severity"], 4), group["title"], group["site"]))


def write_report(data, output):
    directory = Path(output)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    data = sanitize(data)
    data["execution_status"] = execution_outcome(data)
    data["finding_groups"] = group_findings(data.get("findings", []))
    data["summary"] = {"pages": len(data.get("pages", [])), "findings": len(data.get("findings", [])),
                       "errors": len(data.get("errors", [])), "active_checks": len(data.get("active_results", [])),
                       "finding_groups": len(data["finding_groups"])}
    serialized = json.dumps(data, indent=2, ensure_ascii=False)
    (directory / "report.json").write_text(serialized + "\n", encoding="utf-8")
    lines = ["# Web Audit Kit", "", f"Дата UTC: {data.get('generated_utc', '')}", "",
             f"Страниц: {data['summary']['pages']}; замечаний: {data['summary']['findings']}; ошибок: {data['summary']['errors']}", ""]
    cards = []
    active_rows = []
    if data.get("active_results"):
        lines.extend(["## Активные проверки", ""])
        for check in data["active_results"]:
            label = f"{check.get('type', '')}: {check.get('status', '')} — {check.get('url', '')} — {check.get('reason', '')}"
            lines.extend(["- " + label, ""])
            active_rows.append("<tr>" + "".join("<td>" + html.escape(str(check.get(k, ""))) + "</td>" for k in ("type", "status", "url", "reason")) + "</tr>")
    from .dashboard import human_value
    for item in data["finding_groups"]:
        evidence = json.dumps(item["evidence_samples"], ensure_ascii=False, indent=2)
        lines.extend([f"## [{item.get('severity', 'info')}] {item.get('title', '')}", "",
                      "Сервис: " + item["site"], "", f"Наблюдений: {item['occurrences']}; URL: {len(item['urls'])}", "", "Статус: " + item.get("confidence", "unverified"), "",
                      "Доказательства:", "", "    " + evidence.replace("\n", "\n    "), "",
                      "Рекомендация: " + str(item.get("recommendation", "")), ""])
        level = item['severity'] if item['severity'] in ('critical', 'high', 'medium', 'low', 'info') else 'info'
        cards.append(f'<article class="finding {level}"><h2>' + html.escape(f"[{level}] {item['title']}") +
                     "</h2><p>" + html.escape(item["site"]) + f" · Наблюдений: {item['occurrences']} · URL: {len(item['urls'])}</p>" +
                     "<p>Статус доказательства: " + html.escape(item.get("confidence", "unverified")) + "</p>" +
                     "<p><strong>Что исправить:</strong> " + html.escape(str(item.get("recommendation", ""))) + "</p>" +
                     "<details><summary>Доказательства и затронутые URL</summary>" + human_value(item["evidence_samples"]) +
                     "<ul>" + "".join("<li>" + html.escape(url) + "</li>" for url in item["urls"]) + "</ul></details></article>")
    lines.extend(["## Выполнение", "", data["execution_status"], "", "## Ошибки", ""])
    lines.extend("- " + str(row.get("engine", row.get("type", ""))) + ": " + str(row.get("message", "")) for row in data.get("errors", []))
    lines.extend(["", "## Ограничения и пробелы покрытия", ""])
    lines.extend("- " + str(value) for value in data.get("coverage_gaps", []) + data.get("limitations", []))
    lines.extend(["", "Полные наблюдения и технические данные: report.json", ""])
    (directory / "report.md").write_text("\n".join(lines), encoding="utf-8")
    from .dashboard import render_dashboard
    page = render_dashboard(data, cards, active_rows, "")
    (directory / "report.html").write_text(page, encoding="utf-8")
    return data


def empty_report():
    return {"schema_version": 1, "generated_utc": datetime.now(timezone.utc).isoformat(),
            "pages": [], "findings": [], "errors": [], "imports": [], "evidence": []}


def load_json(path):
    path = Path(path)
    if path.stat().st_size > 20 * 1024 * 1024:
        raise ValueError("Файл превышает 20 MiB: " + str(path))
    return json.loads(path.read_text(encoding="utf-8"))


def import_report(path):
    path = Path(path)
    if path.stat().st_size > 20 * 1024 * 1024:
        raise ValueError("Файл превышает 20 MiB")
    if path.suffix.lower() == ".jsonl":
        objects = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    else:
        obj = load_json(path)
        if isinstance(obj, dict) and obj.get("schema_version") == 1:
            return obj
        if isinstance(obj, dict) and isinstance(obj.get("site"), list):
            records = []
            for site in obj["site"]:
                for alert in site.get("alerts", []):
                    for instance in alert.get("instances") or [{"uri": site.get("@name", "")}]:
                        records.append({"rule": "zap." + str(alert.get("pluginid", "unknown")),
                                        "title": alert.get("alert", alert.get("name", "ZAP alert")),
                                        "url": instance.get("uri", ""), "severity": {"0": "info", "1": "low", "2": "medium", "3": "high"}.get(str(alert.get("riskcode")), "info"),
                                        "confidence": "unverified-tool-alert", "evidence": instance.get("evidence", ""),
                                        "recommendation": alert.get("solution", "Проверьте вручную.")})
            return {"findings": sanitize(records)}
        objects = obj if isinstance(obj, list) else [obj]
    records = []
    for item in objects:
        if not isinstance(item, dict) or "template-id" not in item:
            raise ValueError("Ожидается отчёт Web Audit Kit, Nuclei JSON/JSONL или ZAP JSON")
        info = item.get("info", {})
        records.append({"rule": "nuclei." + str(item["template-id"]), "title": info.get("name", item["template-id"]),
                        "url": item.get("matched-at", item.get("host", "")), "severity": info.get("severity", "info"),
                        "confidence": "unverified-tool-alert", "evidence": {"matcher": item.get("matcher-name"), "type": item.get("type")},
                        "recommendation": info.get("remediation", "Проверьте результат вручную по шаблону " + str(item["template-id"]))})
    return {"findings": sanitize(records)}


def merge_reports(paths):
    result = empty_report()
    seen = set()
    for path in paths:
        imported = import_report(path)
        result["imports"].append(str(path))
        for key in ("pages", "errors", "evidence", "active_results", "timeline", "samples", "ports", "coverage", "engines", "coverage_gaps"):
            result.setdefault(key, []).extend(imported.get(key, []))
        # Preserve scope and request information for each imported native run.
        if "scope" in imported or "mode" in imported:
            result.setdefault("runs", []).append({k: imported[k] for k in ("generated_utc", "scope", "mode", "requests", "limitations", "load", "files_reviewed") if k in imported})
        for item in imported.get("findings", []):
            identity = json.dumps([item.get("rule"), item.get("url"), item.get("evidence")], sort_keys=True)
            if identity not in seen:
                result["findings"].append(item)
                seen.add(identity)
    result["timeline"] = sorted(result.get("timeline", []), key=lambda x: x.get("timestamp", ""))
    if result.get("coverage"):
        result["execution_status"] = "incomplete" if result["errors"] or any(x.get("status") != "completed" for x in result["coverage"]) else "completed"
        result["coverage_gaps"] = list(dict.fromkeys(result.get("coverage_gaps", [])))
    return result


def add_evidence(data, title, expected, observed, request=None, response=None):
    record = {"title": title, "expected": expected, "observed": observed,
              "status": "manual-evidence-not-automatically-verified"}
    for key, path in (("request", request), ("response", response)):
        if path:
            with Path(path).open("r", encoding="utf-8", errors="replace") as stream:
                record[key] = stream.read(30000)
    data.setdefault("evidence", []).append(sanitize(record))
    return data
