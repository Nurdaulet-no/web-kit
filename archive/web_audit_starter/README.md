# Classroom black-box audit starter

A zero-dependency Python 3.9+ toolkit to practice safe, low-impact passive web assessment. **No automated exploitation, brute force, flooding, crawler or destructive actions.** The audit makes exactly one GET request to the provided URL and never follows redirects.

## Today: verify that everything works

```bash
python3 --version
python3 audit.py doctor
python3 -m unittest -v test_audit.py
```

In terminal 1, run the local mock site:

```bash
python3 lab_server.py
```

In terminal 2, audit the mock site:

```bash
python3 audit.py audit http://127.0.0.1:8765/ --allow-http --output results/lab
```

Open `results/lab/report.md` and `results/lab/report.json`.

## Tomorrow: instructor-provided URL

Get the scope/authorization conditions in writing, verify domain and stop conditions, then:

```bash
python3 audit.py audit https://YOUR-INSTRUCTOR-LAB.example/ --output results/classroom
```

This gathers response status, selected headers, HTML title, counts of forms/scripts, redirects (without following them), and information-only observations. The report does **not** assert CVSS scores or automatically verify vulnerabilities.

## Manual triage checklist

1. Inspect browser DevTools Network and map features you can access normally.
2. In Burp Suite Community / ZAP, use passive interception only on the authorised host and observe requests for normal application actions.
3. If you have two instructor-owned test accounts, compare whether access controls correctly isolate their own data; don't touch other users' records.
4. Confirm every scanner alert manually; save redacted request/response evidence.
5. Assess impact and exploitability with CVSS only after you have reliable evidence.

Useful official repos:
- OWASP ZAP: https://github.com/zaproxy/zaproxy
- Nuclei: https://github.com/projectdiscovery/nuclei
- Nuclei templates: https://github.com/projectdiscovery/nuclei-templates
- TruffleHog: https://github.com/trufflesecurity/trufflehog
- SQLmap: https://github.com/sqlmapproject/sqlmap
- Autorize: https://github.com/PortSwigger/autorize

`doctor` only checks installation availability; it never launches other tools. Potentially intrusive scans must be separately evaluated, scoped, and authorized. This starter deliberately does not chain them into an attack.

## Troubleshooting

- `python3` not found: install Python 3.9+; on Windows use `py -3` instead.
- `Connection refused`: start `lab_server.py` in the other terminal first.
- `HTTP 301/302`: the tool reports the Location but never follows the redirect; only inspect a new URL after confirming it is in scope.
- `SSL error`: check the provided hostname and lab certificate; do not disable verification for arbitrary remote hosts.
- Error `timeout`: the program exits safely rather than retrying repeatedly.

## Evidence template

For each observation: URL/path, preconditions, expected outcome, actual outcome, redacted screenshot, response code, affected asset, scope notes, plausible impact, mitigation, validation status. **A missing header is not a CVSS 9+ vulnerability.**
