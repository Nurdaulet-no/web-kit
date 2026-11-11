# Ubuntu Local Web Security Lab

Runs a harmless HTTP training server bound to `127.0.0.1:8765`. All automated checks target this local server only.

## Start

Terminal 1: `./lab_check.sh serve`

Terminal 2:

- `./lab_check.sh doctor` – check installed executables
- `./lab_check.sh basic` – save response headers and HTML
- `./lab_check.sh nuclei` – low-rate technology-detection templates (if Nuclei installed)
- `./lab_check.sh zap` – ZAP baseline passive scan via Docker (if Docker installed and running)

Reports are saved under `reports/`. ZAP baseline performs a short crawl; it does not run active vulnerability attacks. The script intentionally does not accept a remote URL, avoiding accidental scans of unrelated sites. For Burp Suite, open its embedded browser and navigate to `http://127.0.0.1:8765/`, then inspect Proxy > HTTP history.

### Notes

Docker is optional. Install it following https://docs.docker.com/engine/install/ubuntu/ if needed. If using Docker with the lab, the `--network host` flag allows its container to access the host-bound local service under Linux. `zap` may exit with warnings from findings, so `-I` allows it to produce a report without treating warnings as failure. ZAP may still fail for other reasons. `chmod 777 reports` is used only for this disposable lab folder to allow container writes; do not reuse this approach on sensitive folders.
