# Web Audit Kit

Дата UTC: 2026-11-11T17:55:10.256167+00:00

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
      "schema_version": 1,
      "generated_utc": "2026-11-11T17:55:10.256167+00:00",
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
      "imports": [],
      "evidence": [],
      "mode": "safe-pipeline",
      "requests": 12,
      "timeline": [
        {
          "timestamp": "2026-11-11T17:55:10.256199+00:00",
          "message": "[scan] Начало HTTP/TLS-аудита",
          "completed": 0.0,
          "total": 3,
          "stage": "scan",
          "finished": false
        },
        {
          "timestamp": "2026-11-11T17:55:10.256411+00:00",
          "message": "[scan] GET",
          "completed": 0.0,
          "total": 3,
          "url": "https://httpbin.org/",
          "stage": "scan",
          "finished": false
        },
        {
          "timestamp": "2026-11-11T17:55:10.392159+00:00",
          "message": "[scan] HTTP 200; замечаний: 5",
          "completed": 0.99,
          "total": 3,
          "url": "https://httpbin.org/",
          "elapsed_seconds": 0.097,
          "stage": "scan",
          "finished": false
        },
        {
          "timestamp": "2026-11-11T17:55:10.392282+00:00",
          "message": "[scan] Аудит завершён",
          "completed": 1,
          "total": 3,
          "finished": false,
          "stage": "scan"
        },
        {
          "timestamp": "2026-11-11T17:55:10.394075+00:00",
          "message": "[ports] TCP httpbin.org:443",
          "completed": 1.0,
          "total": 3,
          "stage": "ports",
          "finished": false
        },
        {
          "timestamp": "2026-11-11T17:55:10.424568+00:00",
          "message": "[ports] TCP httpbin.org:443: open",
          "completed": 1.99,
          "total": 3,
          "stage": "ports",
          "finished": false
        },
        {
          "timestamp": "2026-11-11T17:55:10.424687+00:00",
          "message": "[ports] Завершено",
          "completed": 2,
          "total": 3,
          "finished": false,
          "stage": "ports"
        },
        {
          "timestamp": "2026-11-11T17:55:10.425766+00:00",
          "message": "[load] Нагрузочный GET",
          "completed": 2.0,
          "total": 3,
          "url": "https://httpbin.org/",
          "stage": "load",
          "finished": false
        },
        {
          "timestamp": "2026-11-11T17:55:10.553114+00:00",
          "message": "[load] GET: 200",
          "completed": 2.1,
          "total": 3,
          "url": "https://httpbin.org/",
          "elapsed_seconds": 0.097,
          "stage": "load",
          "finished": false
        },
        {
          "timestamp": "2026-11-11T17:55:11.425987+00:00",
          "message": "[load] Нагрузочный GET",
          "completed": 2.1,
          "total": 3,
          "url": "https://httpbin.org/",
          "stage": "load",
          "finished": false
        },
        {
          "timestamp": "2026-11-11T17:55:11.557403+00:00",
          "message": "[load] GET: 200",
          "completed": 2.2,
          "total": 3,
          "url": "https://httpbin.org/",
          "elapsed_seconds": 0.1,
          "stage": "load",
          "finished": false
        },
        {
          "timestamp": "2026-11-11T17:55:12.426306+00:00",
          "message": "[load] Нагрузочный GET",
          "completed": 2.2,
          "total": 3,
          "url": "https://httpbin.org/",
          "stage": "load",
          "finished": false
        },
        {
          "timestamp": "2026-11-11T17:55:12.547770+00:00",
          "message": "[load] GET: 200",
          "completed": 2.3,
          "total": 3,
          "url": "https://httpbin.org/",
          "elapsed_seconds": 0.09,
          "stage": "load",
          "finished": false
        },
        {
          "timestamp": "2026-11-11T17:55:13.426589+00:00",
          "message": "[load] Нагрузочный GET",
          "completed": 2.3,
          "total": 3,
          "url": "https://httpbin.org/",
          "stage": "load",
          "finished": false
        },
        {
          "timestamp": "2026-11-11T17:55:13.558666+00:00",
          "message": "[load] GET: 200",
          "completed": 2.4,
          "total": 3,
          "url": "https://httpbin.org/",
          "elapsed_seconds": 0.101,
          "stage": "load",
          "finished": false
        },
        {
          "timestamp": "2026-11-11T17:55:14.426942+00:00",
          "message": "[load] Нагрузочный GET",
          "completed": 2.4,
          "total": 3,
          "url": "https://httpbin.org/",
          "stage": "load",
          "finished": false
        },
        {
          "timestamp": "2026-11-11T17:55:14.556277+00:00",
          "message": "[load] GET: 200",
          "completed": 2.5,
          "total": 3,
          "url": "https://httpbin.org/",
          "elapsed_seconds": 0.098,
          "stage": "load",
          "finished": false
        },
        {
          "timestamp": "2026-11-11T17:55:15.427274+00:00",
          "message": "[load] Нагрузочный GET",
          "completed": 2.5,
          "total": 3,
          "url": "https://httpbin.org/",
          "stage": "load",
          "finished": false
        },
        {
          "timestamp": "2026-11-11T17:55:15.556708+00:00",
          "message": "[load] GET: 200",
          "completed": 2.6,
          "total": 3,
          "url": "https://httpbin.org/",
          "elapsed_seconds": 0.098,
          "stage": "load",
          "finished": false
        },
        {
          "timestamp": "2026-11-11T17:55:16.427598+00:00",
          "message": "[load] Нагрузочный GET",
          "completed": 2.6,
          "total": 3,
          "url": "https://httpbin.org/",
          "stage": "load",
          "finished": false
        },
        {
          "timestamp": "2026-11-11T17:55:16.556541+00:00",
          "message": "[load] GET: 200",
          "completed": 2.7,
          "total": 3,
          "url": "https://httpbin.org/",
          "elapsed_seconds": 0.098,
          "stage": "load",
          "finished": false
        },
        {
          "timestamp": "2026-11-11T17:55:17.427962+00:00",
          "message": "[load] Нагрузочный GET",
          "completed": 2.7,
          "total": 3,
          "url": "https://httpbin.org/",
          "stage": "load",
          "finished": false
        },
        {
          "timestamp": "2026-11-11T17:55:17.546634+00:00",
          "message": "[load] GET: 200",
          "completed": 2.8,
          "total": 3,
          "url": "https://httpbin.org/",
          "elapsed_seconds": 0.088,
          "stage": "load",
          "finished": false
        },
        {
          "timestamp": "2026-11-11T17:55:18.428301+00:00",
          "message": "[load] Нагрузочный GET",
          "completed": 2.8,
          "total": 3,
          "url": "https://httpbin.org/",
          "stage": "load",
          "finished": false
        },
        {
          "timestamp": "2026-11-11T17:55:18.549823+00:00",
          "message": "[load] GET: 200",
          "completed": 2.9,
          "total": 3,
          "url": "https://httpbin.org/",
          "elapsed_seconds": 0.091,
          "stage": "load",
          "finished": false
        },
        {
          "timestamp": "2026-11-11T17:55:19.428616+00:00",
          "message": "[load] Нагрузочный GET",
          "completed": 2.9,
          "total": 3,
          "url": "https://httpbin.org/",
          "stage": "load",
          "finished": false
        },
        {
          "timestamp": "2026-11-11T17:55:19.548417+00:00",
          "message": "[load] GET: 200",
          "completed": 2.99,
          "total": 3,
          "url": "https://httpbin.org/",
          "elapsed_seconds": 0.088,
          "stage": "load",
          "finished": false
        },
        {
          "timestamp": "2026-11-11T17:55:19.548587+00:00",
          "message": "[load] Завершено",
          "completed": 3,
          "total": 3,
          "finished": false,
          "stage": "load"
        },
        {
          "timestamp": "2026-11-11T17:55:19.550330+00:00",
          "message": "Все этапы завершены",
          "completed": 3,
          "total": 3,
          "finished": true
        }
      ],
      "runs": [
        {
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
          "errors": [],
          "limitations": [
            "Проверка конфигурации и доступного HTML; бизнес-логика и эксплуатация не проверяются.",
            "TLS: проверка доверия, hostname и срока сертификата текущего соединения; не перебор шифров.",
            "Cookies не сохраняются между запросами. JavaScript не выполняется. Формы не отправляются.",
            "Наличие замечаний не подтверждает эксплуатацию; отсутствие замечаний не доказывает безопасность."
          ]
        },
        {
          "schema_version": 1,
          "generated_utc": "2026-11-11T17:55:10.394046+00:00",
          "errors": [],
          "imports": [],
          "evidence": [],
          "mode": "tcp-inventory",
          "requests": 1,
          "scope": {
            "allowed_origins": [
              "https://httpbin.org"
            ]
          },
          "limitations": [
            "TCP connect без баннеров; открытый порт сам по себе не является уязвимостью."
          ],
          "completed_utc": "2026-11-11T17:55:10.424723+00:00"
        },
        {
          "schema_version": 1,
          "generated_utc": "2026-11-11T17:55:10.425729+00:00",
          "errors": [],
          "imports": [],
          "evidence": [],
          "mode": "load-test",
          "requests": 10,
          "scope": {
            "targets": [
              "https://httpbin.org/"
            ],
            "allowed_origins": [
              "https://httpbin.org"
            ]
          },
          "load": {
            "planned_requests": 10,
            "max_rps": 1.0,
            "concurrency": 1,
            "duration_seconds": 9.123,
            "achieved_rps": 1.096,
            "http_errors": 0,
            "transport_errors": 0,
            "p50_seconds": 0.097,
            "p95_seconds": 0.101
          },
          "limitations": [
            "Ограниченная последовательная выборка GET; не определяет предельную пропускную способность.",
            "Без редиректов, отправки форм и сохранения cookies; GET должен быть безопасным для выбранных маршрутов."
          ],
          "completed_utc": "2026-11-11T17:55:19.548624+00:00"
        }
      ],
      "scope": {
        "targets": [
          "https://httpbin.org/"
        ],
        "allowed_origins": [
          "https://httpbin.org"
        ]
      },
      "limitations": [
        "Последовательные scan → ports → load; при ошибке этапа последующие этапы пропускаются.",
        "TCP-проверка ограничена портами allowed_origins; load ограничен scope и заданным бюджетом."
      ],
      "samples": [
        {
          "url": "https://httpbin.org/",
          "timestamp": "2026-11-11T17:55:10.425844+00:00",
          "status": 200,
          "elapsed_seconds": 0.097,
          "body_truncated": false
        },
        {
          "url": "https://httpbin.org/",
          "timestamp": "2026-11-11T17:55:11.426149+00:00",
          "status": 200,
          "elapsed_seconds": 0.1,
          "body_truncated": false
        },
        {
          "url": "https://httpbin.org/",
          "timestamp": "2026-11-11T17:55:12.426468+00:00",
          "status": 200,
          "elapsed_seconds": 0.09,
          "body_truncated": false
        },
        {
          "url": "https://httpbin.org/",
          "timestamp": "2026-11-11T17:55:13.426756+00:00",
          "status": 200,
          "elapsed_seconds": 0.101,
          "body_truncated": false
        },
        {
          "url": "https://httpbin.org/",
          "timestamp": "2026-11-11T17:55:14.427108+00:00",
          "status": 200,
          "elapsed_seconds": 0.098,
          "body_truncated": false
        },
        {
          "url": "https://httpbin.org/",
          "timestamp": "2026-11-11T17:55:15.427438+00:00",
          "status": 200,
          "elapsed_seconds": 0.098,
          "body_truncated": false
        },
        {
          "url": "https://httpbin.org/",
          "timestamp": "2026-11-11T17:55:16.427783+00:00",
          "status": 200,
          "elapsed_seconds": 0.098,
          "body_truncated": false
        },
        {
          "url": "https://httpbin.org/",
          "timestamp": "2026-11-11T17:55:17.428122+00:00",
          "status": 200,
          "elapsed_seconds": 0.088,
          "body_truncated": false
        },
        {
          "url": "https://httpbin.org/",
          "timestamp": "2026-11-11T17:55:18.428459+00:00",
          "status": 200,
          "elapsed_seconds": 0.091,
          "body_truncated": false
        },
        {
          "url": "https://httpbin.org/",
          "timestamp": "2026-11-11T17:55:19.428770+00:00",
          "status": 200,
          "elapsed_seconds": 0.088,
          "body_truncated": false
        }
      ],
      "ports": [
        {
          "host": "httpbin.org",
          "port": 443,
          "state": "open"
        }
      ],
      "load": {
        "planned_requests": 10,
        "max_rps": 1.0,
        "concurrency": 1,
        "duration_seconds": 9.123,
        "achieved_rps": 1.096,
        "http_errors": 0,
        "transport_errors": 0,
        "p50_seconds": 0.097,
        "p95_seconds": 0.101
      },
      "completed_utc": "2026-11-11T17:55:19.550330+00:00",
      "summary": {
        "pages": 1,
        "findings": 5,
        "errors": 0,
        "active_checks": 0
      }
    }
