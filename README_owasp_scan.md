# owasp_scan.py

A lightweight, passive/light-active web vulnerability scanner that checks a
target site against several categories from the **OWASP Top 10 (2021)**.

This is a reconnaissance tool, not an exploitation tool — it works the same
way as tools like `securityheaders.com`, Nikto, or OWASP ZAP's baseline scan:
it sends normal-looking HTTP requests and inspects the responses (headers,
cookies, status codes) for common misconfigurations. It does not attempt to
exploit, modify, or damage anything.

## What it checks

| OWASP Category | What's tested |
|---|---|
| **A01 – Broken Access Control** | Common admin/management paths reachable without auth, directory listing |
| **A02 – Cryptographic Failures** | HTTPS enforcement, TLS version, certificate validity |
| **A03 – Injection** | Safe, non-destructive reflected-input probe (checks if input is echoed back unescaped) |
| **A05 – Security Misconfiguration** | Missing hardening headers (CSP, HSTS, X-Frame-Options, etc.), exposed sensitive files (`.git/config`, `.env`, backups) |
| **A06 – Vulnerable and Outdated Components** | Server/technology version banners exposed in response headers |
| **A07 – Identification and Authentication Failures** | Missing `Secure` / `HttpOnly` / `SameSite` cookie flags |
| **A08 – Software and Data Integrity Failures** | External `<script>` tags missing Subresource Integrity (SRI) |

### Not tested, and why
- **A04 – Insecure Design**: requires understanding business logic; not something a scanner can check externally
- **A09 – Security Logging and Monitoring Failures**: not observable from outside the target system
- **A10 – Server-Side Request Forgery**: safe detection requires an out-of-band callback server, which is out of scope for this tool

Being upfront about what's out of scope is intentional — no automated scanner
can honestly claim full coverage of all 10 categories, and claiming otherwise
would be misleading.

## Installation

```bash
pip install requests
```

## Usage

```bash
python owasp_scan.py https://example.com
```

### Options

| Flag | Description |
|---|---|
| `--dorks` | Also print a categorized Google dork recon list scoped to this domain |
| `--delay SECONDS` | Time to wait between requests (default: 1.0s) — more considerate to the target's server |
| `--verbose` | Check the fuller list of sensitive file paths instead of the small default set |
| `--contact EMAIL` | Contact info included in the scanner's User-Agent, so the target can identify and reach you if they notice the scan |

Example with all options:

```bash
python owasp_scan.py https://example.com --delay 1.5 --verbose --contact you@email.com
```

## Sample output

```
[*] [A05] Checking security headers...
    [+] Strict-Transport-Security: present
[*] [A02] Checking TLS/HTTPS configuration...
    [+] TLS version negotiated: TLSv1.3
...

======================================================================
OWASP TOP 10 SCAN REPORT - https://example.com
======================================================================

[A05] Security Misconfiguration - 2 finding(s)
    - Missing header 'Content-Security-Policy' - Restricts sources of scripts/content (mitigates XSS)
    - Potentially exposed sensitive file: https://example.com/.env (HTTP 200)
...

TOTAL FINDINGS: 4
```

## Responsible use

- Only run this against domains you own or are explicitly authorized to test (e.g. a program you're enrolled in on HackerOne/Bugcrowd, with the target in scope).
- Findings are **indicators**, not confirmed vulnerabilities — each one should be manually verified before being reported or acted on.
- This tool identifies itself honestly via its User-Agent rather than disguising its traffic. Legitimate security testing should always be identifiable and traceable back to the tester.

## Built with

- Python 3
- [requests](https://requests.readthedocs.io/)
- Python's built-in `ssl` / `socket` modules for TLS checks
