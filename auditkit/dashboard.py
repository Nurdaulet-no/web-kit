"""Offline dashboard prioritizing findings, execution failures and remediation."""
from collections import Counter
import html


def esc(value):
    return html.escape(str(value))


def human_value(value):
    if isinstance(value, dict):
        return "<dl>" + "".join("<dt>" + esc(key) + "</dt><dd>" + human_value(item) + "</dd>" for key, item in value.items()) + "</dl>"
    if isinstance(value, list):
        return "<ul>" + "".join("<li>" + human_value(item) + "</li>" for item in value) + "</ul>"
    if value is True:
        return "Да"
    if value is False:
        return "Нет"
    if value is None:
        return "Не указано"
    return esc(value)


def render_dashboard(data, cards, active_rows, details_json=""):
    groups = data.get("finding_groups", [])
    severity = ("critical", "high", "medium", "low", "info")
    counts = Counter(item.get("severity", "info") for item in groups)
    maximum = max([counts[level] for level in severity] + [1])
    bars = "".join(f'<div class="bar-row"><span>{level}</span><div class="track"><div class="bar {level}" style="width:{100 * counts[level] / maximum:.2f}%"></div></div><b>{counts[level]}</b></div>' for level in severity)
    status = data.get("execution_status", "recorded")
    title = {"completed": "Проверка завершена", "incomplete": "Проверка завершена не полностью",
             "recorded": "Результаты сохранены"}.get(status, "Проверьте состояние запуска")
    explanation = ("Все запланированные этапы выполнены. Результаты и ограничения приведены ниже."
                   if status == "completed" else "Часть проверок не завершена. Устраните ошибки этапов; сохранённые наблюдения доступны ниже."
                   if status == "incomplete" else "Импортированные наблюдения и доказательства; новый скан не выполнялся.")
    summary = data["summary"]
    metrics = "".join(f'<div class="metric"><strong>{esc(value)}</strong><span>{label}</span></div>' for label, value in (
        ("Группы замечаний", summary.get("finding_groups", len(groups))),
        ("Наблюдения на страницах", summary["findings"]), ("Проверено страниц", summary["pages"]),
        ("Ошибки выполнения", summary["errors"])))
    errors = ""
    if data.get("errors"):
        errors = '<section class="error-panel"><h2>Что помешало завершению</h2><ul>' + "".join(
            "<li><strong>" + esc(row.get("engine", row.get("type", "Ошибка"))) + "</strong>: " +
            esc(row.get("message", row.get("status", "Нет диагностики"))) + "</li>" for row in data["errors"]) + "</ul></section>"
    extras = ""
    if data.get("coverage"):
        labels = {"completed": "Выполнен", "error": "Ошибка", "output-limit": "Лимит журнала",
                  "timeout": "Таймаут", "unavailable": "Не установлен", "skipped": "Пропущен", "incomplete": "Не завершён"}
        rows = "".join("<tr><td>" + esc(row.get("engine", "")) + "</td><td>" +
                       esc(labels.get(row.get("status"), row.get("status", ""))) + "</td><td>" +
                       esc(row.get("reason", "—")) + "</td></tr>" for row in data["coverage"])
        extras += '<section><h2>Выполнение движков</h2><table><tr><th>Движок</th><th>Результат</th><th>Диагностика</th></tr>' + rows + "</table></section>"
    limits = data.get("coverage_gaps", []) + data.get("limitations", [])
    if limits:
        extras += '<details><summary>Пробелы покрытия и ограничения</summary><ul>' + "".join("<li>" + esc(value) + "</li>" for value in dict.fromkeys(limits)) + "</ul></details>"
    load = data.get("load")
    if load:
        extras += '<details><summary>Измерения нагрузки</summary>' + human_value(load) + "</details>"
    if data.get("ports"):
        rows = "".join("<tr>" + "".join("<td>" + esc(row.get(key, "—")) + "</td>" for key in ("origin", "port", "status")) + "</tr>" for row in data["ports"])
        extras += '<details><summary>Результаты TCP-проверок</summary><table><tr><th>Сервис</th><th>Порт</th><th>Статус</th></tr>' + rows + "</table></details>"
    if "files_reviewed" in data:
        extras += "<p>Проанализировано локальных файлов: " + esc(data["files_reviewed"]) + "</p>"
    timeline = "".join("<li><time>" + esc(row.get("timestamp", "")) + "</time> " + esc(row.get("message", "")) + "</li>" for row in data.get("timeline", [])[-100:])
    active = ('<details><summary>Результаты активных проверок</summary><table><tr><th>Тип</th><th>Результат</th><th>URL</th><th>Причина</th></tr>' +
              "".join(active_rows) + "</table></details>") if active_rows else ""
    return """<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>Web Audit Kit — результаты проверки</title><style>
:root{color-scheme:light;--ink:#172338;--muted:#52647a;--line:#dce4ef}*{box-sizing:border-box}body{font:15px/1.6 system-ui,sans-serif;background:#edf2f8;color:var(--ink);margin:0}main{max-width:1100px;margin:auto;padding:36px 24px}header{background:#14243b;color:#fff;padding:32px;border-radius:20px}h1{font-size:30px;line-height:1.2;margin:12px 0}h2{font-size:20px;margin-top:0}.eyebrow{letter-spacing:.12em;font-size:12px;color:#94b9ed}.meta{color:#c7d7ed}.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin:24px 0}.metric,section,article,details{background:white;border:1px solid var(--line);border-radius:14px;padding:24px;margin:16px 0}.metric{margin:0;display:flex;flex-direction:column}.metric strong{font-size:32px}.metric span,time{color:var(--muted)}.bar-row{display:grid;grid-template-columns:65px 1fr 30px;align-items:center;gap:12px;margin:12px 0}.track{background:#eef2f7;border-radius:8px;overflow:hidden}.bar{height:12px;background:var(--severity)}.critical{--severity:#a51545}.high{--severity:#d03939}.medium{--severity:#c17a08}.low{--severity:#16817f}.info{--severity:#5279af}.finding{border-left:5px solid var(--severity)}.error-panel{border-left:5px solid #d03939}.incomplete{border:3px solid #c17a08}p,td,li,dd{overflow-wrap:anywhere}table{width:100%;border-collapse:collapse;table-layout:fixed}td,th{padding:10px;border-bottom:1px solid var(--line);text-align:left}ul,ol{padding-left:24px}li{padding:5px 0}summary{cursor:pointer;font-weight:600}dt{font-weight:600}dd{margin:0 0 8px 16px}.note{font-size:13px;color:var(--muted)}a{color:#2866ac}article details{background:#f7f9fc;padding:16px}.badge{display:inline-block;padding:4px 12px;border:1px solid #8394ac;border-radius:20px}
@media(max-width:720px){.metrics{grid-template-columns:1fr 1fr}main{padding:16px}header{padding:20px}}@media print{@page{margin:15mm}body{background:white;font-size:11px}main{padding:0}header{background:white;color:#172338;border:1px solid #ddd}.meta,.eyebrow{color:#52647a}.metrics{grid-template-columns:repeat(4,1fr)}article,.metric{break-inside:avoid}.bar{print-color-adjust:exact;-webkit-print-color-adjust:exact}}
</style></head><body><main>""" + '<header class="' + ("incomplete" if status == "incomplete" else "") + '"><div class="eyebrow">WEB AUDIT KIT</div><h1>' + esc(title) + "</h1><p>" + esc(explanation) + '</p><p class="meta">UTC: ' + esc(data.get("generated_utc", "")) + " · " + esc(data.get("mode", "import")) + "</p></header>" + \
        '<div class="metrics">' + metrics + "</div>" + errors + \
        '<section><h2>Приоритет исправлений</h2><p>Повторения одного правила на страницах сгруппированы. Число наблюдений не равно числу независимых уязвимостей.</p>' + bars + "</section>" + \
        '<h2>Замечания и действия</h2>' + ("".join(cards) or "<section>Замечаний не зарегистрировано. Это не подтверждает отсутствие уязвимостей.</section>") + \
        extras + active + '<details><summary>Таймлайн — последние 100 событий</summary><ol>' + timeline + "</ol></details>" + \
        '<p class="note">HTTP 200 означает получение ответа, а не успешную проверку безопасности. Полные наблюдения и журналы сохранены отдельно: <a href="report.json">report.json</a>. Для печати: Ctrl+P.</p></main></body></html>'
