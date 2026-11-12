# Web Audit Kit

A command-line toolkit for configuration audits, scoped active checks, and orchestration of external security engines against real web applications. Requires Python 3.9+. Built-in checks use the Python standard library; the external-engine profile requires separately installed tools.

Start with `audit.py` or `python3 -m auditkit`. Seven earlier implementations are preserved in `archive/`; the main application does not depend on them.

## Integrated local security review

Reviewed additions from `my-project-final/my-project` are integrated into the root
application. Run commands from this repository root. Files unique to the imported
copy are preserved in `risks/incoming-only/`; differing versions are preserved in
`risks/conflicting-versions/`. `risks/manifest.json` records original paths, retained
paths and SHA-256 hashes. Identical files remain in the main project; the redundant
`my-project-final/` folder has been removed. Archived `cli.py`, `cli_temp.py`, and
`security.py` have syntax errors and are not the runnable application. Alternative dependency implementations
(`dependency_check_v2.py` and `dependency_check_final.py`) were consolidated into
`auditkit/dependency_check.py`. Attack/system-capture modules were not integrated.
The inactive `attack.py` and `distributed_attack.py` modules are archived under
`risks/legacy-runtime/`; the unused `attack` and `rce` CLI commands were removed.
The runnable package contains no simulated takeover results.

```bash
python3 audit.py security --scope examples/scope.json --code-path ./my-app --authorized --ui off --out reports/local-security
```

`security` combines the existing bounded local Python/configuration review with
project-specific dependency checks. It does not send requests to scope targets.
It runs installed `pip-audit` against each `requirements.txt`, and installed `npm audit`
in each directory with a `package.json` and an existing `package-lock.json` or
`npm-shrinkwrap.json`. These tools contact their configured advisory services;
their network requests are not included in the report's `requests` counter.
No packages are installed by the wrapper and no automatic fixes are requested;
pip-audit may resolve requirements and invoke its own package tooling, so use trusted
project manifests. Tools are limited to 60 seconds per manifest and 2 MiB of process
output. At most 100 manifests are processed; symlinks and dependency/archive/import
directories are skipped. Missing tools, unsupported manifests, invalid output, and
timeouts are reported as coverage errors (exit code 2), not clean results.

Dependency findings remain `unverified-tool-alert`. `pip-audit` does not supply
severity in its JSON result, so its findings use `info` with an explicit unknown
severity annotation; `--fail-on` cannot use them as high-severity findings. npm
`moderate` maps to `medium`. Local execution-risk matches are heuristics, not proof
of RCE or system compromise. No manifests means dependency checking was not
applicable, as recorded in `limitations`.

Scope JSON now accepts optional `allowed_ports`, for example `[443, 8443]`. It is an
additional restriction and never grants access to extra origins. Every configured
origin must use a permitted port; omitted HTTPS/HTTP ports mean 443/80. Omitting
`allowed_ports` or using `[]` preserves previous behavior.

Validation commands:

```bash
python3 -m compileall -q auditkit tests
python3 -m unittest discover -s tests -v
```

Tests use local HTTP fixtures; dependency-tool results are mocked. They do not
establish that external audit engines or advisory services are installed/available.
`risks/` is an inactive archive, excluded from local review and dependency traversal.
Tests for the removed standalone `coding_agent.py` are preserved separately in
`risks/orphaned-tests/` and are not part of the application's test suite.
Protocol references: [pip-audit](https://github.com/pypa/pip-audit) and
[npm audit](https://docs.npmjs.com/cli/v11/commands/npm-audit/).

## Start with one command

```bash
python3 audit.py
```

Enter a website address at the `URL:` prompt and press Enter. A bare domain automatically gets an `https://` prefix. Invalid input can be entered again; Ctrl+C cancels the prompt.

The default `production` profile launches installed external engines as real processes. Reports are saved as `report.html`, `report.json`, and `report.md` in a new `reports/<UTC-timestamp>/` directory. The final output shows the path, and the terminal interface displays overall progress.

The profile name describes execution settings and limits. It does not promise a complete penetration test or establish that the toolkit is suitable for every production environment.

Stages run in this order:

1. Built-in HTTP/TLS analysis and HTML crawling within explicitly allowed origins.
2. **Nmap:** TCP connect checks on ports from `allowed_origins`; HTTPS certificate inspection with `ssl-cert`. One IP address is selected for each hostname and recorded in the report. Adjacent addresses and address ranges are not scanned.
3. **k6:** bounded real GET requests using one virtual user and 10 iterations by default. Redirects are disabled, and cookies do not persist between iterations. TLS verification stays enabled; the minimum request interval follows the scope's `delay` setting.
4. **Nuclei:** passive HTTP templates applied to temporarily stored responses. This adapter does not run active CVE probes, headless checks, fuzzing, or OAST interactions.
5. **ZAP:** recorded HAR import (the default import behavior), passive scanning, and JSON report import through the Automation Framework. The plan contains no requestor, spider or active-scan jobs.
6. With `--code-path`, local heuristic source/configuration review.

k6 aborts on HTTP 429/503 or three consecutive network failures/HTTP 5xx responses. The `http_req_failed rate<0.05` threshold is evaluated at the end. Threshold failures, incomplete request counts, and interruptions are recorded as errors. k6 discards response bodies but reads them until completion or timeout: the built-in scanner's `max_bytes` setting does not limit k6 network reads. This profile does not measure maximum throughput or multi-user scenarios.

External network processes have timeouts. Combined stdout/stderr is limited to 2 MiB; exceeding that limit stops the process. Stopping a process terminates its process group. Private HAR files, response bodies, session settings, and the generated k6 script live in temporary directories and are removed after the run. Up to 20 MiB of response bodies is retained for passive engines; exceeding this limit marks execution as incomplete. Each engine's `engine.json` contains normalized results, metrics, a bounded sanitized log, and version information.

The HTML report includes an **engine execution and coverage gaps** table. `completed` means that a stage finished, not that the application is secure. Missing engines are `unavailable`, failures are `error`, and unfinished or omitted work is `incomplete`/`skipped`. Such runs save their results and return exit code 2.

The terminal always prints a final result: completed (0), completed with findings
above `--fail-on` (1), or incomplete (2). Non-completed engine coverage cannot be
reported as success, even if an engine omitted its error record. Failure summaries
include the process exit code and a short diagnostic rather than only a status name.

HTML groups repeated findings by rule, title, origin, severity, evidence status and
recommendation. It shows the number of groups separately from the number of page
observations. A missing header on 100 pages is one group with 100 observations.
Recommendations are visible; evidence and affected URLs can be expanded. Full
observations and engine logs remain in `report.json`; they are not embedded as a
large JSON block in HTML. HTTP 200 indicates a response, not a successful security
assessment. Historical reports retain their actual execution status when re-rendered.

Recorded responses use a corrected Content-Length: Python's HTTP client has already
removed chunk framing, so Transfer-Encoding and Trailer are not copied into the
reconstructed responses. This also handles bodies truncated by the capture budget.

An HTTP/TLS crawl failure blocks subsequent network stages; passive engines may still analyze responses already collected. Ctrl+C stops subsequent stages. Findings from external engines retain `unverified-tool-alert` status until manually confirmed.

### External-engine requirements

```bash
python3 audit.py doctor
```

To complete all configured stages, the following executables must be available in `PATH`:

- `nmap`
- `k6`
- `nuclei`
- Either `zap.sh` or `zaproxy`

Docker images are not launched automatically. Installed executables are detected automatically; software and templates are not installed during an audit. `doctor` checks executable availability, not whether each engine's environment works correctly.

Nuclei requires local templates installed in advance. The toolkit checks `~/.local/share/nuclei/nuclei-templates` and `~/nuclei-templates`. Set `AUDIT_NUCLEI_TEMPLATES` for another directory. Execution configuration is isolated; template updates and cloud upload are not enabled.

ZAP requires the Automation Framework, Import/Export, Passive Scan, and Report Generation add-ons. Incompatible versions or missing add-ons cause a stage error.

Set `AUDIT_ZAP_BIN` to select a specific installed ZAP executable. The standard
`/snap/bin/zaproxy` installation uses its bundled `zap.sh` and Java directly for
headless execution, avoiding the desktop launcher. Each run uses a private home,
a loopback proxy on an OS-assigned port, and disables update checks and telemetry.
The HAR plan defines contexts for recorded origins. It omits the optional
`sendRequests` field for compatibility with older Import/Export versions, whose
default is to import recorded responses without resending them.

Adapter references:
[Nmap ssl-cert](https://nmap.org/nsedoc/scripts/ssl-cert.html),
[k6 options](https://grafana.com/docs/k6/latest/using-k6/k6-options/reference/),
[Nuclei passive scanning](https://docs.projectdiscovery.io/opensource/nuclei/running#passive-scan),
[ZAP HAR import](https://www.zaproxy.org/docs/desktop/addons/import-export/automation/).

### Advanced run options

The interactive entry point remains `python3 audit.py`. For automation:

```bash
python3 audit.py run --url "https://your-site.kz/" --authorized --out reports/my-site
python3 audit.py run --scope scope.local.json --authorized --headers-file headers.local.json --out reports/my-site
python3 audit.py run --url "https://your-site.kz/" --authorized --code-path ./my-app
```

`--url` creates a scope using the URL's exact origin, `max_pages=100`, `delay=1`, and `timeout=10`. Subdomains and additional origins are not added automatically. `--scope` uses the supplied JSON settings without changing them.

`--requests` and `--rps` control only the k6 budget/rate; the HTTP crawl and Nmap connections are accounted for separately. The final `requests` counter includes the HTTP crawl and k6 requests, but not Nmap's TCP packets or TLS connections.

Extended TLS cipher enumeration is an explicit option:

```bash
python3 audit.py run --url "https://your-site.kz/" --authorized --tls-enumeration
```

The [ssl-enum-ciphers](https://nmap.org/nsedoc/scripts/ssl-enum-ciphers.html) script establishes many TLS connections and is classified by Nmap as intrusive. It has a timeout, but `--max-rate` does not guarantee a connection-rate limit for NSE scripts. It is disabled by default.

To use the earlier built-in sequence:

```bash
python3 audit.py run --url "https://your-site.kz/" --authorized --profile basic
```

The `basic` profile runs `scan → ports → load`, without external engines or link crawling. Its `--url` option creates a scope with `max_pages=10`.

Authenticated business logic, role comparisons, browser JavaScript execution, OpenAPI import, and active CVE verification are not implemented in the orchestrator. These gaps remain listed in the report even when every configured engine completes successfully.

## Quick start with an explicit scope

```bash
python3 audit.py doctor
cp examples/scope.json scope.local.json
```

In `scope.local.json`, replace `https://example.com/` with a website you own or are authorized to test. Set `allowed_origins` to the exact permitted combinations of scheme, hostname, and port. For example, `https://app.example.org` and `https://app.example.org:8443` are different origins. Subdomains, HTTP variants, and redirect destinations are not automatically authorized.

```bash
python3 audit.py check-scope scope.local.json
python3 audit.py scan --scope scope.local.json --authorized
```

The scanner makes real requests to the specified targets. By default, `scan` checks each URL in `targets` without crawling links or following redirects. A new `reports/<UTC-timestamp>/` directory contains `report.html`, `report.json`, and `report.md`.

Use `--out reports/my-site` to select a directory. Existing report files in that directory are overwritten.

For bounded link and redirect crawling:

```bash
python3 audit.py scan --scope scope.local.json --authorized --crawl --out reports/my-site
```

Crawling sends GET requests only within `allowed_origins`, honors `exclude_paths`, and uses a shared `max_pages` budget, including failed requests. Links containing query strings are not crawled; explicit `targets` may contain query strings. Add specific pages to `targets` when needed.

Some applications change state on GET requests: exclude those paths before enabling crawling. `exclude_paths` matches case-insensitive substrings after URL decoding. The example excludes `/logout`, `/signout`, `/delete`, and `/remove`.

## Built-in checks

- HTTP status codes, response times, redirects, and available HTML.
- TLS certificate trust using the system trust store, hostname matching, expiration, and the negotiated TLS version/cipher.
- CSP, HSTS, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, and page embedding policies.
- Each Set-Cookie header separately: Secure, HttpOnly, and SameSite attributes; cookie values are not retained in the built-in report.
- Password forms using HTTP or GET, and HTTP resources referenced by HTTPS pages.
- Page/form inventory and SHA-256 hashes of retained response content.
- Combined reports and manually supplied evidence for further review.

Findings include a URL, observation, severity, and recommendation. A missing header alone does not establish exploitability. This toolkit audits web configuration and selected vectors; it is not a complete penetration test.

The separate `verify` command checks SQL injection, HTML injection, and CORS using an explicit plan. It does not automatically test RCE, IDOR, business logic, or credential guessing. The built-in scanner does not execute JavaScript, submit forms, or carry response cookies between requests. Its TLS check inspects the current connection rather than enumerating every supported cipher.

HTML is parsed as UTF-8; pages using other encodings may be interpreted incorrectly.

## Active checks and SQL injection reproduction

`verify` sends modified requests to the actual server. Specify exact URLs and parameters in a separate plan. The entire plan is validated before the first request, and every request is checked against the scope. Links are not crawled.

```bash
cp examples/active-plan.json active-plan.local.json
# Replace example.com and the routes with your actual authorized input points.
python3 audit.py check-plan --scope scope.local.json --plan active-plan.local.json
python3 audit.py verify --scope scope.local.json --plan active-plan.local.json \
  --authorized --max-requests 50 --out reports/active
```

The example contains four checks with a combined upper budget of 20 GET requests. Remove any checks you do not need. Each item in `checks` uses this format:

```json
{
  "type": "sqli-union",
  "url": "https://app.example.org/item?id=1",
  "parameter": "id"
}
```

`parameter` is required for SQLi/HTML checks and must appear exactly once in the URL's query string. For `cors`, specify only `type` and `url`.

| Type | Action and detection criterion | Maximum GET requests |
|---|---|---|
| `sqli-union` | UNION SELECT computes two independent markers from separate fragments. The full marker is absent from the input, so simple reflection does not confirm it. | 8 |
| `sqli-boolean` | Two baseline requests and two independent true/false pairs; true responses match the baseline, while false responses differ consistently. | 6 |
| `html-injection` | Two unique harmless span markers are recognized as HTML elements outside script/textarea and other inert contexts. | 3 |
| `cors` | Two random Origin values are reflected exactly, with a single Access-Control-Allow-Origin header and credentials=true. | 3 |

`sqli-union` tries 1–3 columns, a marker in the first column, and concatenation using `||` or `CONCAT`. SELECT expressions contain only string constants and NULL: no table/file reads, command execution, or database modifications. A successful computation is repeated with a new marker.

Real SQLite injection is covered by integration tests; other database systems are outside the test matrix. Supporting an expression does not imply support for every SQL query context.

`sqli-boolean` requires exact response-body matches without removing arbitrary fragments. Dynamic baselines, status changes, compression, and truncation do not count as confirmation. Response differences are a strong signal, not direct observation of SQL execution.

HTML injection is not equivalent to XSS: JavaScript is not executed. CORS headers alone do not prove that a browser can read private data; API behavior, cookies, and SameSite settings also need review.

`--max-requests` sets the total active-run budget, independently of `scan`'s `max_pages`. It includes baselines, failures, and retries. A check starts only if its full upper budget remains; otherwise it is marked `skipped-budget`, and the run returns exit code 2.

`delay`, `timeout`, `max_bytes`, allowed origins, and excluded paths come from the same scope. `--headers-file` and `--fail-on` are supported.

Reports include every check's outcome, reasons for inconclusive results, request sequences, statuses, and body hashes. Original query values and response bodies are not recorded in the built-in active report. Keep the private plan separately for reproduction; the report retains parameter names and generated probe suffixes.

The toolkit does not guess input points without explicit URLs and parameters. POST/JSON checks, blind timing checks, WAF bypasses, and exploit chains to an operating-system shell are not implemented.

Methodology:
[OWASP SQL Injection](https://owasp.github.io/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection),
[OWASP CORS](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing/),
[SQLite SELECT](https://www.sqlite.org/lang_select.html),
[SQLite expressions](https://www.sqlite.org/lang_expr.html).

## Scope and request limits

Settings are stored in a JSON scope file. `check-scope` validates it without network access.

| Field | Purpose | Default |
|---|---|---|
| `targets` | Explicit starting HTTP(S) URLs | Required |
| `allowed_origins` | Exact permitted origins without paths | Required |
| `exclude_paths` | Excluded path substrings | logout, signout, delete, remove |
| `max_pages` | Total request limit, 1–1000 | 10 |
| `delay` | Minimum interval between request starts, 0.1–60 seconds | 1 |
| `timeout` | Network-operation timeout, 1–60 seconds | 10 |
| `max_bytes` | Retained response-body limit, 1024–2097152 bytes | 262144 |

The table lists scope-file defaults. `run --url` uses `max_pages=100` for `production` and `max_pages=10` for `basic`.

Built-in requests are sequential. They do not use system proxies, disable TLS verification, or cross origins without explicit permission. Scope permits origins rather than fixed IP addresses, so DNS load balancing is allowed. Response bodies are not stored in the built-in report; the production profile temporarily captures responses for passive engines as described above.

## Testing with a session

Create a private `headers.local.json` file, for example:

```json
{
  "https://app.example.org": {
    "Authorization": "Bearer YOUR_TEST_TOKEN"
  }
}
```

```bash
chmod 600 headers.local.json
python3 audit.py scan --scope scope.local.json --authorized --headers-file headers.local.json
```

Each header set is sent only to its exact origin. You can use `Cookie` instead of Authorization. Supply a test session with the intended permissions. Private `*.local.json` files are excluded from Git.

## Importing Nuclei and ZAP reports

Merge existing Nuclei JSON/JSONL and ZAP JSON results with native reports:

```bash
python3 audit.py merge --report reports/my-site/report.json --report nuclei.jsonl --report zap.json --out reports/combined
```

`merge` is an offline import command and does not launch external scanners. External alerts are marked `unverified-tool-alert`. Findings with the same rule, URL, and evidence are deduplicated.

Keep original external JSON files separately: import preserves core finding fields rather than every scanner-specific field. Burp is used separately for manual investigation.

## Manual evidence

```bash
python3 audit.py evidence --report reports/my-site/report.json \
  --title "Access check for a test record" \
  --expected "The second test account is denied access" \
  --observed "Describe the actual result" \
  --request request.txt --response response.txt --out reports/with-evidence
```

Without `--report`, this creates a standalone package using the same format. Each attachment is read up to 30,000 characters. A manual record does not automatically become a confirmed vulnerability or receive a fabricated CVSS score.

The built-in report omits cookie values, masks known sensitive headers and JSON fields, and redacts URL query values. Arbitrary text, page titles, CSP values, URL paths, and manual attachments may still contain private information. Review reports before sharing; masking does not guarantee complete sanitization.

## Automation and validation

```bash
python3 -m unittest discover -s tests -v
python3 audit.py scan --scope scope.local.json --authorized --fail-on medium
```

Exit codes:

- `0`: execution completed.
- `1`: findings meet or exceed the `--fail-on` threshold.
- `2`: an error occurred or execution was incomplete.

For built-in scans, individual target errors are recorded while other targets continue. Ctrl+C during scanning saves a partial report with exit code 2. The production orchestrator applies its stage-stopping rules described above.

Tests use local servers and mocked responses, not public websites. External-engine integration tests launch real Nmap and k6 processes when both executables are available; they are skipped otherwise.

Run the reproducible active-module benchmark:

```bash
python3 -m tests.benchmark_active --out validation/active-benchmark
```

The matrix includes real SQLite queries with concatenation and parameterization, escaped/unescaped HTML, input reflection, CORS policies, dynamic pages, request blocking, truncation, and redirects. `benchmark.json` records each scenario's expected/actual outcome, request count, and duration.

This is a small internal regression matrix, not an independent assessment of detection quality on arbitrary websites.

## Live terminal interface

`run`, `scan`, `verify`, `ports`, `load`, and `code` default to `--ui auto`. In an interactive terminal, progress from 0–100% and a progress bar stay at the top, with a bounded live event log below.

The interface uses the Python standard library; Rich/Textual installation is not required. It restores the screen and cursor on exit and errors. In pipes/CI, events are written as ordinary lines to stderr. `--ui off` disables output; `--ui on` explicitly enables it, retaining plain text when no TTY is available.

Event timestamps use UTC. Ctrl+C saves a partial report with exit code 2. A 100% progress indication means execution ended, including runs with errors; inspect the errors separately. Crawl progress is measured against the page budget and reaches 100% when the queue is exhausted.

```bash
python3 audit.py scan --scope scope.local.json --authorized --ui on --out reports/site
```

## HTML dashboard and PDF

Every report-producing command saves a standalone `report.html` with metric cards, a color-coded severity chart, response-time measurements, findings/recommendations, and an event timeline. Depending on the command, the report also includes load metrics, TCP inventory, code-review results, or engine execution and coverage gaps.

JSON and Markdown reports remain available. Additional data uses fields such as `timeline`, `samples`, `ports`, `load`, and `files_reviewed`. Imported older reports may not include timelines or response times.

Open the HTML report in a browser and use **Ctrl+P → Save as PDF**. A print stylesheet is included. Direct generation of `report.pdf` without a browser is not implemented. Charts and styles do not require network access, JavaScript, or a CDN.

## Standalone bounded checks

`scan` analyzes HTTP headers, cookie attributes, HTML, and the current TLS connection. For manual header review, see the [OWASP Secure Headers Project](https://owasp.org/projects/secure-headers-project).

The commands below run independently and do not invoke the active `verify` scenarios.

### TCP inventory

```bash
python3 audit.py ports --scope scope.local.json --authorized --out reports/ports
```

Only unique host:port pairs from `allowed_origins` are checked, up to 1,000 pairs. To include another port, add its exact origin, such as `https://app.example.org:8443`. Ranges and neighboring ports are not enumerated automatically.

Checks use sequential TCP connections without sending application data or reading banners, honoring scope `delay` and `timeout` settings. Results are `open`, `closed` (connection refused), or `unknown` (timeout, DNS, or other errors). `unknown` makes the run incomplete and returns exit code 2. An open port is not automatically classified as a vulnerability.

### GET load sampling

```bash
python3 audit.py load --scope scope.local.json --authorized \
  --requests 10 --rps 2 --out reports/load
```

This standalone command uses the built-in sampler, not k6. It cycles through `targets`, sends GET requests without following redirects, and does not carry cookies between requests. Use `--headers-file` for a test session.

`--requests` must be between 1 and min(1000, scope `max_pages`); `--rps` must be 0.1–10. The effective interval is at least scope `delay`: with `delay=1`, requests start no faster than once per second even with `--rps 10`.

One request runs at a time. HTTP 429/503 or three consecutive network failures/HTTP 5xx responses stop the run, save partial results, and return exit code 2. Other HTTP 4xx/5xx responses are counted in metrics; they are not security findings for `--fail-on` by themselves.

Reports include actual request count, duration, achieved rate, p50/p95 latency of completed network responses (including HTTP errors), and transport/HTTP error counts. This is a bounded performance sample, not a measurement of maximum server capacity.

Response times include TLS, headers, and reading the body up to `max_bytes`; truncation is recorded in `samples`.

### Local source and configuration review

```bash
python3 audit.py code --path ./my-app --out reports/code --fail-on medium
```

This command uses no network access and does not execute the reviewed code. It applies heuristics for debug mode, disabled TLS verification, and possible secrets in string-valued settings. Python AST checks identify `eval`/`exec` calls and calls using `shell=True`.

Reports retain filenames, line numbers, and rule identifiers; source lines and detected secret values are not copied. Findings use `heuristic-review-required` status and need manual data-flow/context review. This is a limited checklist, not a full SAST engine or OWASP compliance certification.

Up to 500 Python/JSON/YAML/TOML/INI/CONF/ENV files are reviewed, each limited to 1 MiB. Symbolic links, `.git`, `node_modules`, virtual environments, `archive`, and `reports` are skipped. Limit violations and read/parse errors are recorded with exit code 2.

Combine results using:

```bash
python3 audit.py merge --report reports/site/report.json \
  --report reports/load/report.json --report reports/ports/report.json \
  --report reports/code/report.json --out reports/combined
```
