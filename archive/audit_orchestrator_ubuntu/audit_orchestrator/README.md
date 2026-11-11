# Audit Orchestrator for Ubuntu

Это **evidence-first** учебный оркестратор, не автоматический эксплойтер и не DDoS-инструмент. Внешний HTTPS URL проверяется **одним GET без редиректов**. Автозапуск Nuclei и ZAP разрешён скриптом **только на встроенной лаборатории 127.0.0.1:8765**. Burp Community — ручной инструмент; его автоматическое сканирование не входит в Community.

## Начало работы (Python 3.9+)

```bash
cd audit_orchestrator
python3 -m unittest -v
python3 runner.py doctor
```

Терминал 1:

```bash
python3 runner.py serve
```

Терминал 2:

```bash
python3 runner.py lab
```

Если Nuclei уже установлен:

```bash
python3 runner.py lab --nuclei
```

Если Docker установлен, образ `ghcr.io/zaproxy/zaproxy:stable` уже загружен и Docker доступен пользователю:

```bash
python3 runner.py lab --zap
```

Для целевого сайта, когда его предоставит преподаватель:

```bash
python3 runner.py inspect https://example.com/ --out reports/classroom
```

Отчёты: `report.json`, `report.md`, `report.html`. Импортируй готовые JSON/JSONL отчёты разрешённых внешних инструментов командой:

```bash
python3 runner.py merge --report path/to/nuclei.jsonl --report path/to/zap.json --out reports/merged
```

## Установка и запуск отдельных инструментов

- ZAP: https://www.zaproxy.org/download/ ; Docker: https://www.zaproxy.org/docs/docker/baseline-scan/
- Nuclei: https://docs.projectdiscovery.io/opensource/nuclei/install ; https://github.com/projectdiscovery/nuclei
- Burp Community: https://portswigger.net/burp/communitydownload ; Proxy -> Open browser -> HTTP history, затем Repeater для своих тестовых запросов.

Не запускай ZAP Baseline одновременно с запущенным браузерным прокси на одном порту. Не смешивай cookies, токены и реальные персональные данные с отчётами. Алерты Nuclei/ZAP нужно вручную подтверждать; высокая оценка CVSS не гарантируется.
