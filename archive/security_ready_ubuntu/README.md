# Ubuntu classroom security starter

A conservative launchpad for a consented web application assessment. **Not a critical vulnerability scanner, DDoS utility, or exploit framework.** No program can guarantee a CVSS 9+ finding.

## Ubuntu dependencies

```bash
sudo apt update
sudo apt install -y python3 python3-venv curl git jq unzip openjdk-21-jre docker.io
python3 runner.py doctor
```

Optional external tools (review official installation instructions and security implications):
- Burp Suite Community: https://portswigger.net/burp/downloads
- Nuclei: https://github.com/projectdiscovery/nuclei/releases
- ZAP: https://www.zaproxy.org/download/ ; ZAP baseline Docker image: `sudo docker pull ghcr.io/zaproxy/zaproxy:stable`

`runner.py lab` requires Docker daemon access for ZAP; avoid adding yourself to the privileged Docker group unless you understand the implications. If necessary, use `sudo python3 runner.py lab` after reviewing the script. Burp is opened manually; it cannot be automatically used as a vulnerability scanner in the Community Edition.

## Practice today

In terminal A:

```bash
cd security_ready_ubuntu
python3 lab_server.py
```

In terminal B:

```bash
cd security_ready_ubuntu
python3 -m unittest -v
python3 runner.py doctor
python3 runner.py lab
```

Local results are under `reports/local/`. If Nuclei/Docker aren't installed, the runner skips them and logs why. Nuclei only uses `tech` templates, limited to one request/second and one concurrent worker; templates are maintained by a third party, so review them first. ZAP only uses baseline (short spider + passive alerts) locally. Burp Suite: open Proxy > Open browser, browse `http://127.0.0.1:8765/` then inspect Proxy > HTTP history.

## Tomorrow: provided URL

1. Obtain the **exact scope and restrictions** from the instructor. Do not assume related subdomains or infrastructure are in scope.
2. Inspect once with `python3 runner.py inspect https://TARGET/ --authorized`.
3. Open Burp's built-in browser and explore only supplied in-scope features manually. Create two test accounts if permitted. Use two clearly separated sessions for access-control checks.
4. Review reports and record the evidence; independently verify findings before claiming CVSS severity.

The external inspect command uses **one** HTTP GET, at most 64 KiB of body, **no redirects or crawling**. It does not run Nuclei or ZAP against external targets. Do not put session tokens or credentials in URLs or reports; the `result.json` may contain cookies and response snippets, so keep it private.

## Troubleshooting

- `Connection refused`: start `python3 lab_server.py` first.
- `nuclei: missing`: install from official releases; otherwise it is skipped.
- `Docker daemon inaccessible`: `sudo systemctl enable --now docker`; check `sudo docker info`, or use `sudo python3 runner.py lab` after reviewing the program.
- `Port already in use`: stop the old lab server.
- `zaproxy` not installed: the runner uses Docker ZAP baseline locally, not desktop ZAP.
- `Burp Community`: browser/manual, not an automatic active scanner.
