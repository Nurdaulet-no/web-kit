# Web Audit Kit

Дата UTC: 2026-11-11T17:55:33.397103+00:00

Страниц: 2; замечаний: 10; ошибок: 0

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

## [info] Отсутствует content-security-policy

URL: https://httpbin.org/forms/post

Статус: observed

Доказательства:

    "Заголовок отсутствует в ответе HTML"

Рекомендация: Настройте CSP с учётом ресурсов приложения.

## [info] Отсутствует referrer-policy

URL: https://httpbin.org/forms/post

Статус: observed

Доказательства:

    "Заголовок отсутствует в ответе HTML"

Рекомендация: Выберите Referrer-Policy для приложения.

## [info] Отсутствует permissions-policy

URL: https://httpbin.org/forms/post

Статус: observed

Доказательства:

    "Заголовок отсутствует в ответе HTML"

Рекомендация: Ограничьте ненужные возможности браузера через Permissions-Policy.

## [info] Не обнаружена политика встраивания страницы

URL: https://httpbin.org/forms/post

Статус: observed

Доказательства:

    "Нет frame-ancestors и X-Frame-Options"

Рекомендация: Ограничьте встраивание, если оно не требуется.

## [info] Отсутствует HSTS

URL: https://httpbin.org/forms/post

Статус: observed

Доказательства:

    "Нет Strict-Transport-Security"

Рекомендация: После проверки HTTPS настройте Strict-Transport-Security.

## Область, страницы, ошибки и ограничения

    {
      "timeline": [
        {
          "timestamp": "2026-11-11T17:55:33.397055+00:00",
          "message": "Начало HTTP/TLS-аудита",
          "completed": 0,
          "total": 10
        },
        {
          "timestamp": "2026-11-11T17:55:33.397120+00:00",
          "message": "GET",
          "completed": 0,
          "total": 10,
          "url": "https://httpbin.org/"
        },
        {
          "timestamp": "2026-11-11T17:55:33.527580+00:00",
          "message": "HTTP 200; замечаний: 5",
          "completed": 1,
          "total": 10,
          "url": "https://httpbin.org/",
          "elapsed_seconds": 0.091
        },
        {
          "timestamp": "2026-11-11T17:55:34.397310+00:00",
          "message": "GET",
          "completed": 1,
          "total": 10,
          "url": "https://httpbin.org/forms/post"
        },
        {
          "timestamp": "2026-11-11T17:55:34.537838+00:00",
          "message": "HTTP 200; замечаний: 5",
          "completed": 2,
          "total": 10,
          "url": "https://httpbin.org/forms/post",
          "elapsed_seconds": 0.107
        },
        {
          "timestamp": "2026-11-11T17:55:34.537950+00:00",
          "message": "Аудит завершён",
          "completed": 2,
          "total": 2,
          "finished": true
        }
      ],
      "completed_utc": "2026-11-11T17:55:34.537979+00:00",
      "schema_version": 1,
      "generated_utc": "2026-11-11T17:55:33.397103+00:00",
      "mode": "crawl",
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
      "requests": 2,
      "pages": [
        {
          "url": "https://httpbin.org/",
          "status": 200,
          "elapsed_seconds": 0.091,
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
        },
        {
          "url": "https://httpbin.org/forms/post",
          "status": 200,
          "elapsed_seconds": 0.107,
          "title": "",
          "headers": {
            "content-type": "text/html; charset=utf-8",
            "x-content-type-options": "nosniff"
          },
          "cookies": [],
          "forms": [
            {
              "method": "POST",
              "action": "https://httpbin.org/post",
              "password": "[REDACTED]"
            }
          ],
          "tls": {
            "version": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "expires": "Feb  3 19:21:39 2027 GMT",
            "verified": true,
            "days_remaining": 84
          },
          "body_bytes": 1397,
          "body_truncated": false,
          "body_sha256": "d9cd9adbe7554d4e82a597d722dccdcea70c8dd918836670e3f9687531f54d74"
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
        "pages": 2,
        "findings": 10,
        "errors": 0,
        "active_checks": 0
      }
    }
