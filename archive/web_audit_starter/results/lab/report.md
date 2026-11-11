# Отчёт: базовый аудит

Цель: `http://127.0.0.1:8765/`
Дата UTC: 2026-11-10T23:31:33.969728+00:00
HTTP: 200
Content-Type: text/html; charset=utf-8
Заголовок страницы: Practice Lab
Формы: 1; script-теги: 1

## Проверка заголовков
- `content-security-policy`: absent
- `strict-transport-security`: absent
- `x-content-type-options`: present
- `referrer-policy`: absent
- `permissions-policy`: absent

## Наблюдения (не подтверждённые уязвимости)
- Missing header: content-security-policy — Review applicability; missing headers alone do not establish a critical vulnerability.
- Missing header: referrer-policy — Review applicability; missing headers alone do not establish a critical vulnerability.
- Missing header: permissions-policy — Review applicability; missing headers alone do not establish a critical vulnerability.
- HTTP transport — Use HTTPS for real deployments.

## Ограничение
Exactly one GET to the provided URL, redirects disabled; passive configuration observations, not exploitation or CVSS verification.

## Дальнейшая ручная проверка
Сверить области доступа на собственных тестовых аккаунтах; документировать ожидаемый и фактический результат.
