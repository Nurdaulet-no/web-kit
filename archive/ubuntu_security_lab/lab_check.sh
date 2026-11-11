#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")"
mkdir -p reports
HOST='http://127.0.0.1:8765/'
case "${1:-help}" in
  doctor)
    for x in python3 curl zaproxy nuclei docker; do
      if command -v "$x" >/dev/null 2>&1; then printf 'OK %-10s %s\n' "$x" "$(command -v "$x")"; else printf 'MISSING %s\n' "$x"; fi
    done
    echo 'Burp Suite: проверить запуск вручную через меню приложений'
    ;;
  serve)
    exec python3 lab_server.py
    ;;
  basic)
    curl --fail --silent --show-error --max-time 5 --dump-header reports/headers.txt --output reports/home.html "$HOST"
    echo 'Saved reports/headers.txt and reports/home.html'
    ;;
  nuclei)
    command -v nuclei >/dev/null || { echo 'Install Nuclei first'; exit 1; }
    # Only local target, minimal technology-identification templates.
    nuclei -u "$HOST" -tags tech -rl 1 -c 1 -timeout 5 -jsonl-export reports/nuclei-local.jsonl
    ;;
  zap)
    command -v docker >/dev/null || { echo 'Install Docker first'; exit 1; }
    docker info >/dev/null 2>&1 || { echo 'Docker daemon inaccessible; see README'; exit 1; }
    mkdir -p reports
    chmod 777 reports
    docker run --rm --network host -v "$PWD/reports:/zap/wrk:rw" ghcr.io/zaproxy/zaproxy:stable \
      zap-baseline.py -t "$HOST" -m 1 -r zap-report.html -J zap-report.json -I
    ;;
  *)
    echo 'Commands: ./lab_check.sh doctor | serve | basic | nuclei | zap'
    echo 'All scanning commands are fixed to the local server at 127.0.0.1:8765.'
    ;;
esac
