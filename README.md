# takeover-watch

A Python tool that detects potential **subdomain takeover** vulnerabilities by
combining Certificate Transparency log data with DNS resolution checks.

## What it does

1. Queries [crt.sh](https://crt.sh) to enumerate all subdomains that have ever
   had an SSL certificate issued for the target domain.
2. Resolves the CNAME record for each subdomain.
3. Flags any subdomain whose CNAME target returns `NXDOMAIN` — a strong
   indicator of a dangling DNS record that could potentially be hijacked by
   an attacker if the pointed-to service allows unclaimed hostname
   registration (e.g. an unclaimed S3 bucket, GitHub Pages site, or Heroku app).

This maps to **OWASP A05:2021 – Security Misconfiguration**: a dangling DNS
record is a leftover configuration that was never cleaned up after the
resource it pointed to was deleted.

## Why this matters

Subdomain takeovers let an attacker serve their own content under a
trusted, legitimate-looking domain — which can be used for phishing,
credential theft, or reputational damage — without ever breaching the
target's actual infrastructure.

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/takeover-watch.git
cd takeover-watch
python -m venv venv
venv\Scripts\activate      # Windows
# source venv/bin/activate   # macOS/Linux
pip install -r requirements.txt
```

## Usage

```bash
python takeover_watch.py example.com
```

Example output:

```
[*] Querying crt.sh for subdomains of 'example.com'...
[*] Found 42 unique subdomain(s) via crt.sh.
[*] Checking CNAME records for 42 subdomain(s)...

[1/42] Checking api.example.com ... CNAME -> api-gateway.aws.com (resolved OK)
[2/42] Checking old.example.com ... NXDOMAIN  <-- POTENTIAL TAKEOVER
...

============================================================
SUMMARY
============================================================
Total subdomains checked : 42
CNAME resolved OK        : 38
No CNAME record          : 2
Errors / timeouts        : 1
Potential takeovers      : 1
```

## Responsible use

This tool only performs **passive reconnaissance** — public Certificate
Transparency lookups and standard DNS queries, the same kind of requests a
browser makes automatically. It does not exploit, claim, or modify any
infrastructure.

That said:
- Only run this against domains you own or are explicitly authorized to test.
- If you find a genuine dangling CNAME on a third party's domain, do not
  attempt to claim it. Report it responsibly to the domain owner instead.

## Built with

- Python 3
- [dnspython](https://www.dnspython.org/)
- [requests](https://requests.readthedocs.io/)
- [crt.sh](https://crt.sh) Certificate Transparency search

## Author

Built as part of independent security research and coursework in
penetration testing / offensive security.
