#!/usr/bin/env python3
"""Offline evidence pack generator. Does not make network requests or execute payloads."""
import argparse
import base64
import html
import json
import mimetypes
import re
from datetime import datetime, timezone
from pathlib import Path

MAX_TEXT = 30000
SECRET_HEADERS = re.compile(r'(?im)^((?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|api-key)\s*:\s*).*$')
SECRET_JSON = re.compile(r'(?i)("(?:access_token|refresh_token|api_key|secret|password|session_token)"\s*:\s*)"[^"]*"')

def sanitize(value):
    value = SECRET_HEADERS.sub(lambda m: m.group(1) + '[REDACTED]', value)
    value = SECRET_JSON.sub(lambda m: m.group(1) + '"[REDACTED]"', value)
    return value[:MAX_TEXT]

def read_text(name):
    return sanitize(Path(name).read_text(encoding='utf-8', errors='replace')) if name else '(не приложено)'

def img_data(name):
    if not name:
        return ''
    p = Path(name)
    if p.stat().st_size > 4_000_000:
        raise ValueError('Screenshot must be <= 4 MB')
    mime, _ = mimetypes.guess_type(p.name)
    if mime not in ('image/png','image/jpeg','image/webp'):
        raise ValueError('Screenshot must be PNG/JPEG/WebP')
    return f'data:{mime};base64,{base64.b64encode(p.read_bytes()).decode()}'

def generate(title, expected, observed, request_file, response_file, screenshot_file, out):
    request, response = read_text(request_file), read_text(response_file)
    screenshot = img_data(screenshot_file)
    now = datetime.now(timezone.utc).isoformat(timespec='seconds')
    def esc(s): return html.escape(s, quote=True)
    photo = f'<h2>Визуальное подтверждение</h2><img alt="Приложенный скриншот" src="{screenshot}">' if screenshot else '<p>Скриншот не приложен.</p>'
    doc = f'''<!doctype html><html lang="ru"><meta charset="utf-8"><title>{esc(title)}</title>
<style>body{{font:16px system-ui,sans-serif;max-width:1100px;margin:3rem auto;padding:0 1rem;line-height:1.5}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#f2f3f5;padding:1rem;border-radius:8px}}.columns{{display:grid;grid-template-columns:1fr 1fr;gap:1rem}}img{{max-width:100%;border:1px solid #ddd}}small{{color:#555}}@media(max-width:700px){{.columns{{grid-template-columns:1fr}}}}</style>
<h1>{esc(title)}</h1><small>Отчёт создан {esc(now)} (UTC). Это свидетельства наблюдения, не автоматическая оценка CVSS.</small>
<h2>Ожидаемое поведение</h2><p>{esc(expected)}</p><h2>Фактический результат</h2><p>{esc(observed)}</p>
<div class="columns"><section><h2>HTTP-запрос</h2><pre>{esc(request)}</pre></section><section><h2>HTTP-ответ</h2><pre>{esc(response)}</pre></section></div>{photo}
<h2>Проверка доказательств</h2><p>Повторить тест на своём тестовом аккаунте; исключить случайные сбои, сохранить точное время и проверить, что не затронуты чужие данные. Оценку CVSS выставить отдельно по подтверждённым последствиям.</p>
<p><strong>Внимание:</strong> автоматическая маскировка секретов неполная. Перед отправкой отчёта вручную проверьте текст и скриншот на токены и персональные данные.</p></html>'''
    target = Path(out)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(doc, encoding='utf-8')
    print('Отчёт создан:', target)

def main():
    p = argparse.ArgumentParser(description='Create a standalone HTML evidence report without network activity')
    p.add_argument('--title', required=True)
    p.add_argument('--expected', required=True)
    p.add_argument('--observed', required=True)
    p.add_argument('--request')
    p.add_argument('--response')
    p.add_argument('--screenshot')
    p.add_argument('--out', default='reports/evidence.html')
    a = p.parse_args()
    generate(a.title, a.expected, a.observed, a.request, a.response, a.screenshot, a.out)
if __name__ == '__main__':
    main()
