# Web Audit Kit

Дата UTC: 2026-11-11T17:55:10.256388+00:00

Страниц: 1; замечаний: 5; ошибок: 0

## [info] Отсутствует content-security-policy

URL: https://httpbin.org/

Статус: observed

Доказательства:

    "Заголовок отсутствует в ответе HTML"

Рекомендация: Настройте CSP с учётом ресурсов приложения.

## [info] Отсутствует referrer-policy

URL: https://httpbin.org/

Статус: observed

Доказательства:

    "Заголовок отсутствует в ответе HTML"

Рекомендация: Выберите Referrer-Policy для приложения.

## [info] Отсутствует permissions-policy

URL: https://httpbin.org/

Статус: observed

Доказательства:

    "Заголовок отсутствует в ответе HTML"

Рекомендация: Ограничьте ненужные возможности браузера через Permissions-Policy.

## [info] Не обнаружена политика встраивания страницы

URL: https://httpbin.org/

Статус: observed

Доказательства:

    "Нет frame-ancestors и X-Frame-Options"

Рекомендация: Ограничьте встраивание, если оно не требуется.

## [info] Отсутствует HSTS

URL: https://httpbin.org/

Статус: observed

Доказательства:

    "Нет Strict-Transport-Security"

Рекомендация: После проверки HTTPS настройте Strict-Transport-Security.

## Область, страницы, ошибки и ограничения

    {
      "timeline": [
        {
          "timestamp": "2026-11-11T17:55:10.256199+00:00",
          "message": "Начало HTTP/TLS-аудита",
          "completed": 0,
          "total": 1
        },
        {
          "timestamp": "2026-11-11T17:55:10.256411+00:00",
          "message": "GET",
          "completed": 0,
          "total": 1,
          "url": "https://httpbin.org/"
        },
        {
          "timestamp": "2026-11-11T17:55:10.392159+00:00",
          "message": "HTTP 200; замечаний: 5",
          "completed": 1,
          "total": 1,
          "url": "https://httpbin.org/",
          "elapsed_seconds": 0.097
        },
        {
          "timestamp": "2026-11-11T17:55:10.392282+00:00",
          "message": "Аудит завершён",
          "completed": 1,
          "total": 1,
          "finished": true
        }
      ],
      "completed_utc": "2026-11-11T17:55:10.392330+00:00",
      "schema_version": 1,
      "generated_utc": "2026-11-11T17:55:10.256388+00:00",
      "mode": "targets",
      "scope": {
        "targets": [
          "https://httpbin.org/"
        ],
        "allowed_origins": [
          "https://httpbin.org"
        ],
        "exclude_paths": [
          "/logout",
          "/signout",
          "/delete",
          "/remove"
        ],
        "max_pages": 10,
        "delay": 1.0
      },
      "requests": 1,
      "pages": [
        {
          "url": "https://httpbin.org/",
          "status": 200,
          "elapsed_seconds": 0.097,
          "title": "httpbin.org",
          "headers": {
            "content-type": "text/html; charset=utf-8",
            "x-content-type-options": "nosniff"
          },
          "cookies": [],
          "forms": [],
          "tls": {
            "version": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "expires": "Feb  3 19:21:39 2027 GMT",
            "verified": true,
            "days_remaining": 84
          },
          "body_bytes": 8632,
          "body_truncated": false,
          "body_sha256": "a62840d9a4902533eeb17816f28685d6d2ec3356916bb1fc899b4858c1ec8240"
        }
      ],
      "errors": [],
      "limitations": [
        "Проверка конфигурации и доступного HTML; бизнес-логика и эксплуатация не проверяются.",
        "TLS: проверка доверия, hostname и срока сертификата текущего соединения; не перебор шифров.",
        "Cookies не сохраняются между запросами. JavaScript не выполняется. Формы не отправляются.",
        "Наличие замечаний не подтверждает эксплуатацию; отсутствие замечаний не доказывает безопасность."
      ],
      "summary": {
        "pages": 1,
        "findings": 5,
        "errors": 0,
        "active_checks": 0
      }
    }
