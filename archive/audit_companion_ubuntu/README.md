# Audit Companion Ubuntu — quick start

Requires Python 3.9+ only. Designed for passive external inspection and a **local-only** demo of an access-control bug. It is not an exploitation platform or a guarantee of any CVSS score.

```bash
python3 audit.py doctor
# Terminal 1
python3 audit.py serve
# Terminal 2
python3 audit.py lab-demo
# Open reports/lab/report.html in your browser
```

The lab intentionally returns the private test record belonging to account A when account B asks for it. This is fabricated test data; it shows how to explain an IDOR finding by comparing authorization contexts. The local server only listens on 127.0.0.1. In a real challenge, verify authorization requirements using only your own test accounts, then compare actual responses. Redact personal data and tokens before reporting.

Tomorrow, if your instructor authorizes checking the exact website:

```bash
python3 audit.py inspect https://example.com/
# Open reports/external/report.html
```

This sends one HTTPS GET and does not follow redirects or crawl. It does not automatically run active scans against the external URL.

## Optional third-party tools

- ZAP: https://www.zaproxy.org/download/ — use the GUI for passive HTTP history inspection. Do not enable active scan by default.
- Burp Community: https://portswigger.net/burp/communitydownload — use the built-in browser, Proxy history, and Repeater for manual verification.
- Nuclei: https://github.com/projectdiscovery/nuclei — study the help and templates on localhost first. Not every template is passive. Do not run the entire template collection against an external site.

`python3 audit.py doctor` tells you which CLIs exist on your machine. Burp typically installs as a GUI app.

## Reading the evidence

`reports/lab/report.html` will contain the A/B responses in a clear side-by-side narrative. You should explain the expected response (B denied) vs observed response (B sees A private test content). This is a **local training example**, not proof of vulnerability on your instructor's site.
