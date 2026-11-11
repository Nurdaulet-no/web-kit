"""Offline report dashboard: CSS charts, severity cards, timeline and print layout."""
from collections import Counter
import html
import json


def esc(value):
    return html.escape(str(value))


def render_dashboard(data, cards, active_rows, details_json):
    counts = Counter(x.get("severity", "info") for x in data.get("findings", []))
    severity = ("critical", "high", "medium", "low", "info")
    maximum = max([counts[x] for x in severity] + [1])
    bars = "".join(f'<div class="bar-row"><span>{level}</span><div class="track"><div class="bar {level}" style="width:{100 * counts[level] / maximum:.2f}%"></div></div><b>{counts[level]}</b></div>' for level in severity)
    summary = data["summary"]
    metrics = "".join(f'<div class="metric"><strong>{esc(value)}</strong><span>{label}</span></div>' for label, value in (
        ("Замечания", summary["findings"]), ("Страницы", summary["pages"]),
        ("Ошибки выполнения", summary["errors"]), ("Запросы / соединения", data.get("requests", "—"))))
    samples = data.get("samples", []) or data.get("pages", [])
    latencies = [x for x in samples if isinstance(x.get("elapsed_seconds"), (int, float))]
    maximum_latency = max([x["elapsed_seconds"] for x in latencies] + [.001])
    timing = "".join(f'<div class="latency"><span>{esc(x.get("url", ""))}</span><meter min="0" max="{maximum_latency}" value="{x["elapsed_seconds"]}">{x["elapsed_seconds"]}</meter><b>{x["elapsed_seconds"]:.3f} s</b></div>' for x in latencies)
    timeline = "".join('<li><time>' + esc(x.get("timestamp", "")) + '</time><strong>' + esc(x.get("message", "")) + '</strong><span>' + esc(x.get("url", "")) + '</span></li>' for x in data.get("timeline", []))
    extras = ""
    if data.get("coverage"):
        rows = "".join("<tr>" + "".join("<td>" + esc(x.get(k, "—")) + "</td>" for k in ("engine", "status", "reason")) + "</tr>" for x in data["coverage"])
        gaps = "".join("<li>" + esc(x) + "</li>" for x in data.get("coverage_gaps", []))
        extras += '<section><h2>Выполнение движков и пробелы покрытия</h2><p>Статус: <strong>' + esc(data.get("execution_status", "unknown")) + '</strong>. completed означает завершение этапа, а не безопасность приложения.</p><table><tr><th>Движок</th><th>Статус</th><th>Причина</th></tr>' + rows + '</table><h3>Не проверено</h3><ul>' + gaps + '</ul></section>' 
    for key, title in (("load", "Производительность"), ("ports", "TCP-порты")):
        if key in data:
            extras += f'<section><h2>{title}</h2><pre>{esc(json.dumps(data[key], ensure_ascii=False, indent=2))}</pre></section>'
    if "files_reviewed" in data:
        extras += f'<section><h2>Код и конфигурация</h2><p>Проанализировано файлов: {esc(data["files_reviewed"])}</p><p>Эвристические замечания требуют ручной проверки.</p></section>'
    for index, item in enumerate(data.get("findings", [])):
        level = item.get("severity", "info")
        level = level if level in severity else "info"
        cards[index] = cards[index].replace('<article>', f'<article class="finding {level}">', 1)
    return '''<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>Web Audit Kit — отчёт</title><style>
:root{color-scheme:light;--ink:#172338;--muted:#52647a;--line:#dce4ef}*{box-sizing:border-box}body{font:15px/1.6 system-ui,sans-serif;background:#edf2f8;color:var(--ink);margin:0}main{max-width:1200px;margin:auto;padding:36px 24px}header{background:#14243b;color:#fff;padding:32px;border-radius:20px}h1{font-size:34px;margin:0}h2{font-size:20px;margin-top:0}.eyebrow{letter-spacing:.15em;font-size:12px;color:#94b9ed}.meta{color:#c7d7ed}.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin:24px 0}.metric,section,article,details{background:white;border:1px solid var(--line);border-radius:14px;padding:24px;margin:16px 0}.metric{margin:0;display:flex;flex-direction:column}.metric strong{font-size:32px}.metric span,time{color:var(--muted)}.grid{display:grid;grid-template-columns:1fr 1fr;gap:20px}.bar-row{display:grid;grid-template-columns:65px 1fr 25px;align-items:center;gap:12px;margin:14px 0}.track{background:#eef2f7;border-radius:8px;overflow:hidden}.bar{height:16px;min-width:0}.critical{--severity:#a51545}.high{--severity:#d03939}.medium{--severity:#c17a08}.low{--severity:#16817f}.info{--severity:#5279af}.bar{background:var(--severity)}.finding{border-left:5px solid var(--severity)}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f2f5fa;padding:16px;font-size:12px}p,td,li{overflow-wrap:anywhere}table{width:100%;border-collapse:collapse;table-layout:fixed}td,th{padding:10px;border:1px solid var(--line);text-align:left}.latency{display:grid;grid-template-columns:1fr 90px;gap:8px;margin:14px 0}.latency span{grid-column:1/-1;overflow-wrap:anywhere;font-size:12px}meter{width:100%}ol{padding-left:20px}li{padding:10px 0}li time,li strong,li span{display:block}li time{font-size:12px}summary{cursor:pointer;font-weight:600}.print-note{font-size:13px;color:var(--muted)}@media(max-width:720px){.metrics,.grid{grid-template-columns:1fr}main{padding:16px}header{padding:20px}}@media print{@page{margin:15mm}body{background:#fff;font-size:11px}main{padding:0;max-width:none}header{background:white;color:#172338;border:1px solid #ddd}.meta,.eyebrow{color:#52647a}.metrics{grid-template-columns:repeat(4,1fr)}.grid{display:block}article,.metric,li{break-inside:avoid}section,article,details{box-shadow:none}.print-note{display:none}.bar{print-color-adjust:exact;-webkit-print-color-adjust:exact}}
</style></head><body><main><header><div class="eyebrow">WEB AUDIT KIT / SECURITY & PERFORMANCE</div><h1>Результаты аудита</h1>''' + f'<p class="meta">UTC: {esc(data.get("generated_utc", ""))} · Режим: {esc(data.get("mode", "combined"))}</p></header>' + \
        '<p class="print-note">Для PDF: Ctrl+P → «Сохранить как PDF». Отчёт работает без сети. 100% выполнения не означает отсутствие уязвимостей.</p>' + \
        '<div class="metrics">' + metrics + '</div><div class="grid"><section><h2>Уровни критичности / Severity</h2>' + bars + \
        '</section><section><h2>Время ответа</h2>' + (timing or '<p>Нет измерений.</p>') + '</section></div>' + extras + \
        ('<section><h2>Активные проверки</h2><table><tr><th>Тип</th><th>Результат</th><th>URL</th><th>Причина</th></tr>' + ''.join(active_rows) + '</table></section>' if active_rows else '') + \
        '<h2>Замечания и рекомендации</h2>' + (''.join(cards) or '<section>Замечаний нет. Проверьте ошибки и полноту проверки.</section>') + \
        '<section><h2>Таймлайн</h2>' + ('<ol>' + timeline + '</ol>' if timeline else '<p>Источник не содержит событий.</p>') + '</section>' + \
        '<details open><summary>Область, страницы, ошибки и ограничения</summary><pre>' + esc(details_json) + '</pre></details></main></body></html>'
