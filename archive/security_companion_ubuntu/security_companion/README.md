# Security Companion (Ubuntu)

This package is a bounded classroom web-assessment helper. Remote URLs: **one HTTP GET**, no redirects or crawling. Automated Nuclei/ZAP runs: **local loopback only**. It does **not** exploit vulnerabilities, attempt DoS, or guarantee CVSS 9+.

## Setup

```bash
sudo apt update
sudo apt install -y python3 curl unzip
unzip security_companion_ubuntu.zip
cd security_companion
python3 runner.py doctor
python3 -m unittest discover -s tests -v
```

Optional, installed separately according to vendor instructions: Nuclei, Docker with `ghcr.io/zaproxy/zaproxy:stable`, and Burp Suite Community. Check Docker security: membership in the `docker` group grants root-equivalent privileges.

## Practice in two terminals

Terminal A:
```bash
python3 runner.py serve
```
Terminal B:
```bash
python3 runner.py lab
xdg-open reports/lab/report.html
```
When Nuclei and Docker are installed, optionally add `--nuclei --zap`; both run only on localhost, sequentially, with rate/time bounds. ZAP baseline may return warning exit codes. Inspect logs rather than assuming an error means an exploitable vulnerability.

## Tomorrow (authorized target)

```bash
python3 runner.py inspect https://YOUR-ASSIGNED-HOST/ --output reports/classroom
xdg-open reports/classroom/report.html
```

This does a single, bounded request. Use Burp Community's embedded browser to inspect authorized functionality manually. Document two-account access-control experiments only with your own test records. Never include unredacted cookies, tokens, or third-party personal data in reports. A missing security header is not itself a critical vulnerability.

## Files

- `runner.py`: tool checks, bounded inspection, local integration, HTML/JSON reports
- `lab_server.py`: localhost training site
- `tests/test_runner.py`: self-tests

## Troubleshooting

- `nuclei missing`: install the official ProjectDiscovery Nuclei release and confirm `nuclei -version`.
- `docker missing`: install Docker from official docs and verify `sudo docker version`.
- `permission denied` from Docker: configure rootful Docker securely; do not blindly add yourself to docker group.
- `Address already in use`: stop the prior lab process using port 8765.
- ZAP Docker image may need to be pulled separately, and network=host is Linux-specific.

Official references: https://github.com/projectdiscovery/nuclei ; https://www.zaproxy.org/docs/docker/baseline-scan/ ; https://portswigger.net/burp/communitydownload
