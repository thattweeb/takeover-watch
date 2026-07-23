import sys
import time
import re
import argparse
import ssl
import socket
from urllib.parse import urlparse, urljoin

import requests
from requests.exceptions import RequestException

REQUEST_TIMEOUT = 10
DEFAULT_DELAY = 1.0  # seconds between requests -- polite default, avoids hammering the target
USER_AGENT = "owasp-scan/1.0 (+authorized security research; contact: {contact})"

# Smaller, high-value default list -- run with --verbose for the fuller list
SENSITIVE_PATHS_DEFAULT = [
    ".git/config",
    ".env",
    ".DS_Store",
]

SENSITIVE_PATHS_VERBOSE = SENSITIVE_PATHS_DEFAULT + [
    "wp-config.php.bak",
    "config.php.bak",
    "backup.zip",
    ".svn/entries",
    "web.config",
    "phpinfo.php",
]

SECURITY_HEADERS = {
    "Strict-Transport-Security": "Enforces HTTPS connections (protects against protocol downgrade attacks)",
    "Content-Security-Policy": "Restricts sources of scripts/content (mitigates XSS)",
    "X-Content-Type-Options": "Prevents MIME-sniffing (should be 'nosniff')",
    "X-Frame-Options": "Prevents clickjacking via iframe embedding",
    "Referrer-Policy": "Controls how much referrer info is leaked to other sites",
    "Permissions-Policy": "Restricts access to browser features (camera, geolocation, etc.)",
}

REFLECTED_XSS_PROBE = "owasptest<script>alert(1)</script>"


def make_session(contact: str):
    s = requests.Session()
    s.headers.update({"User-Agent": USER_AGENT.format(contact=contact)})
    return s


def normalize_url(target: str) -> str:
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    return target.rstrip("/")


def check_a05_security_headers(session, base_url, findings):
    """A05:2021 - Security Misconfiguration (missing hardening headers)."""
    print("[*] [A05] Checking security headers...")
    try:
        resp = session.get(base_url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
    except RequestException as e:
        findings["A05"].append(f"Could not fetch base URL to check headers: {e}")
        return

    for header, description in SECURITY_HEADERS.items():
        if header not in resp.headers:
            findings["A05"].append(f"Missing header '{header}' - {description}")
        else:
            print(f"    [+] {header}: present")

    server_banner = resp.headers.get("Server")
    powered_by = resp.headers.get("X-Powered-By")
    if server_banner:
        findings["A06"].append(f"Server banner exposed: '{server_banner}' (version disclosure)")
    if powered_by:
        findings["A06"].append(f"X-Powered-By header exposed: '{powered_by}' (version disclosure)")


def check_a05_sensitive_paths(session, base_url, findings, delay, verbose):
    """A05:2021 - Security Misconfiguration (exposed sensitive files)."""
    paths = SENSITIVE_PATHS_VERBOSE if verbose else SENSITIVE_PATHS_DEFAULT
    print(f"[*] [A05] Checking for exposed sensitive files ({len(paths)} checked)...")
    for path in paths:
        url = urljoin(base_url + "/", path)
        try:
            resp = session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=False)
            if resp.status_code == 200 and len(resp.content) > 0:
                findings["A05"].append(f"Potentially exposed sensitive file: {url} (HTTP 200)")
                print(f"    [!] Exposed: {url}")
            else:
                print(f"    [ok] {path} -> HTTP {resp.status_code}")
        except RequestException:
            print(f"    [!] Could not reach {url}")
        time.sleep(delay)


def check_a02_tls(base_url, findings):
    """A02:2021 - Cryptographic Failures (TLS/HTTPS enforcement)."""
    print("[*] [A02] Checking TLS/HTTPS configuration...")
    parsed = urlparse(base_url)
    hostname = parsed.hostname

    if parsed.scheme != "https":
        findings["A02"].append("Site is not served over HTTPS by default")
        return

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=REQUEST_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                version = ssock.version()
                print(f"    [+] TLS version negotiated: {version}")
                if version in ("TLSv1", "TLSv1.1"):
                    findings["A02"].append(f"Outdated TLS version in use: {version}")
                not_after = cert.get("notAfter", "unknown")
                print(f"    [+] Certificate expires: {not_after}")
    except ssl.SSLCertVerificationError as e:
        findings["A02"].append(f"TLS certificate verification failed: {e}")
    except (socket.timeout, socket.gaierror, ConnectionRefusedError) as e:
        findings["A02"].append(f"Could not establish TLS connection: {e}")
    except Exception as e:
        findings["A02"].append(f"Unexpected TLS check error: {e}")


def check_a01_common_admin_paths(session, base_url, findings, delay):
    """A01:2021 - Broken Access Control (common admin/exposed paths, directory listing)."""
    print("[*] [A01] Checking common admin/restricted paths for exposure...")
    admin_paths = ["admin/", "administrator/", "wp-admin/", "manager/html", "console/"]
    for path in admin_paths:
        url = urljoin(base_url + "/", path)
        try:
            resp = session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=False)
            if resp.status_code == 200:
                findings["A01"].append(
                    f"Admin/management path reachable without redirect to login: {url} (HTTP 200)"
                )
            print(f"    [ok] {path} -> HTTP {resp.status_code}")
        except RequestException:
            pass
        time.sleep(delay)

    # Basic directory listing check on base URL
    try:
        resp = session.get(base_url, timeout=REQUEST_TIMEOUT)
        if "Index of /" in resp.text:
            findings["A01"].append(f"Directory listing appears enabled at {base_url}")
    except RequestException:
        pass


def check_a03_reflected_input(session, base_url, findings):
    """A03:2021 - Injection (basic reflected-input / XSS indicator, non-destructive)."""
    print("[*] [A03] Checking for naive reflected-input handling (safe probe only)...")
    test_url = f"{base_url}/?q={REFLECTED_XSS_PROBE}"
    try:
        resp = session.get(test_url, timeout=REQUEST_TIMEOUT)
        if REFLECTED_XSS_PROBE in resp.text:
            findings["A03"].append(
                "Input appears to be reflected back unescaped in the response "
                "(possible reflected XSS - needs manual confirmation)"
            )
        else:
            print("    [ok] Test probe not reflected unescaped")
    except RequestException as e:
        print(f"    [!] Could not run reflection probe: {e}")


def check_a07_cookie_flags(session, base_url, findings):
    """A07:2021 - Identification and Authentication Failures (cookie security flags)."""
    print("[*] [A07] Checking cookie security attributes...")
    try:
        resp = session.get(base_url, timeout=REQUEST_TIMEOUT)
        if not resp.cookies:
            print("    [ok] No cookies set on base response")
            return
        for cookie in resp.cookies:
            issues = []
            if not cookie.secure:
                issues.append("missing 'Secure' flag")
            has_httponly = "httponly" in [k.lower() for k in cookie._rest.keys()]
            if not has_httponly:
                issues.append("missing 'HttpOnly' flag")
            samesite = cookie._rest.get("SameSite") or cookie._rest.get("samesite")
            if not samesite:
                issues.append("missing 'SameSite' attribute")
            if issues:
                findings["A07"].append(f"Cookie '{cookie.name}': {', '.join(issues)}")
    except RequestException as e:
        print(f"    [!] Could not check cookies: {e}")


def check_a08_sri(session, base_url, findings):
    """A08:2021 - Software and Data Integrity Failures (missing Subresource Integrity)."""
    print("[*] [A08] Checking external scripts for Subresource Integrity (SRI)...")
    try:
        resp = session.get(base_url, timeout=REQUEST_TIMEOUT)
        text = resp.text
        script_count = text.count("<script")
        sri_count = text.count("integrity=")
        external_script_count = text.count("src=\"http")
        if external_script_count > 0 and sri_count == 0:
            findings["A08"].append(
                f"Found {external_script_count} externally-sourced <script> tag(s) "
                "with no 'integrity' (SRI) attribute detected"
            )
    except RequestException as e:
        print(f"    [!] Could not check SRI: {e}")


DORK_TEMPLATES = {
    "Exposed sensitive files": [
        'site:{domain} filetype:env',
        'site:{domain} filetype:sql',
        'site:{domain} filetype:log',
        'site:{domain} filetype:bak',
        'site:{domain} ext:config',
        'site:{domain} intitle:"index of" "parent directory"',
    ],
    "Exposed credentials / config": [
        'site:{domain} "api_key" filetype:json',
        'site:{domain} "aws_access_key_id"',
        'site:{domain} inurl:wp-config.php.bak',
    ],
    "Admin / login panels": [
        'site:{domain} inurl:admin',
        'site:{domain} inurl:login intitle:"admin"',
        'site:{domain} inurl:phpmyadmin',
    ],
    "Exposed documents (possible info leak)": [
        'site:{domain} filetype:pdf "confidential"',
        'site:{domain} filetype:xls "internal"',
        'site:{domain} filetype:doc "password"',
    ],
    "Error messages / stack traces": [
        'site:{domain} "sql syntax near"',
        'site:{domain} "warning: mysql"',
        'site:{domain} "fatal error" "on line"',
    ],
    "Exposed source control / backups": [
        'site:{domain} inurl:.git',
        'site:{domain} inurl:.svn',
        'site:{domain} ext:zip OR ext:tar.gz',
    ],
    "Subdomain discovery": [
        'site:*.{domain} -site:www.{domain}',
    ],
}


def generate_dorks(domain: str):
    """
    Print a categorized list of Google dork queries scoped to a single
    domain, for use during AUTHORIZED bug bounty recon (i.e. only against
    domains explicitly listed in a program's scope on HackerOne, Bugcrowd,
    etc.). These queries only surface what's already publicly indexed by
    Google about the target -- they don't scan or send requests to it.
    """
    print("\n" + "=" * 70)
    print(f"GOOGLE DORK RECON LIST - {domain}")
    print("=" * 70)
    print(
        "\nOnly use these against domains explicitly listed in scope for a\n"
        "bug bounty program you are enrolled in (HackerOne, Bugcrowd, etc.),\n"
        "or domains you own. Copy each line into Google manually -- Google\n"
        "rate-limits/CAPTCHAs automated dork queries, so these are meant to\n"
        "be run a handful at a time in a browser, not scripted at scale.\n"
    )
    for category, templates in DORK_TEMPLATES.items():
        print(f"\n[{category}]")
        for t in templates:
            print(f"    {t.format(domain=domain)}")
    print("\n" + "-" * 70)
    print(
        "For a much larger, continuously updated library, see the Google\n"
        "Hacking Database (GHDB): https://www.exploit-db.com/google-hacking-database"
    )
    print("=" * 70)


def check_a04_rate_limiting(session, base_url, findings, delay):
    """
    A04:2021 - Insecure Design (partial signal only).
    Sends a handful of quick requests and checks whether anything throttles
    (HTTP 429 or similar). Absence of any rate limiting is a recognized
    insecure-design pattern (no abuse-prevention safeguard), but this is a
    weak signal, not proof -- real insecure-design review needs a human
    looking at actual business logic.
    """
    print("[*] [A04] Checking for basic rate-limiting behavior (weak signal only)...")
    statuses = []
    for i in range(5):
        try:
            resp = session.get(base_url, timeout=REQUEST_TIMEOUT)
            statuses.append(resp.status_code)
        except RequestException:
            statuses.append(None)
        time.sleep(0.2)  # deliberately quick burst to see if anything throttles

    if 429 in statuses or 503 in statuses:
        print("    [+] Server responded with a throttling status during burst - rate limiting appears present")
    else:
        findings["A04"].append(
            "No rate-limiting response (429/503) observed across 5 quick requests -- "
            "weak signal only, does not confirm absence of protection elsewhere (e.g. WAF/CDN layer)"
        )
    time.sleep(delay)


def check_a10_ssrf_surface(session, base_url, findings):
    """
    A10:2021 - Server-Side Request Forgery (surface detection only, no exploitation attempt).
    Looks for URL-accepting parameter names commonly associated with SSRF in
    the page's own links/forms. This does NOT send any probe or attempt to
    trigger an outbound request from the target -- it only flags parameter
    names worth a human manually reviewing for SSRF risk.
    """
    print("[*] [A10] Checking for SSRF-prone parameter names in page content (heuristic only)...")
    ssrf_param_indicators = ["url=", "redirect=", "callback=", "fetch=", "target=", "dest=", "path=", "uri=", "webhook="]
    try:
        resp = session.get(base_url, timeout=REQUEST_TIMEOUT)
        text = resp.text.lower()
        found = [p for p in ssrf_param_indicators if p in text]
        if found:
            findings["A10"].append(
                f"Parameter name(s) commonly associated with SSRF found in page content: "
                f"{', '.join(found)} -- manual review recommended, this is NOT confirmed SSRF"
            )
        else:
            print("    [ok] No obviously SSRF-prone parameter names found in page content")
    except RequestException as e:
        print(f"    [!] Could not check for SSRF surface indicators: {e}")


CSRF_TOKEN_NAME_PATTERNS = [
    "csrf", "authenticity_token", "_token", "xsrf", "anti-forgery", "requestverificationtoken",
]


def check_csrf_tokens(session, base_url, findings):
    """
    A01:2021 - Broken Access Control (CSRF was folded into this category in
    the 2021 OWASP Top 10, since most modern frameworks now handle it by
    default).

    Passive check: fetches the page HTML and looks for <form> tags using
    POST that do NOT appear to include a hidden CSRF token field. This does
    NOT submit any form or trigger any state change -- it only inspects the
    page's own markup.
    """
    print("[*] [A01] Checking forms for CSRF token presence...")
    try:
        resp = session.get(base_url, timeout=REQUEST_TIMEOUT)
    except RequestException as e:
        print(f"    [!] Could not fetch page to check forms: {e}")
        return

    forms = re.findall(r"<form[^>]*>.*?</form>", resp.text, re.IGNORECASE | re.DOTALL)
    if not forms:
        print("    [ok] No <form> tags found on this page")
        return

    post_forms = [f for f in forms if re.search(r'method\s*=\s*["\']?post', f, re.IGNORECASE)]
    if not post_forms:
        print(f"    [ok] {len(forms)} form(s) found, none use POST (GET forms are not CSRF-relevant)")
        return

    unprotected_count = 0
    for i, form in enumerate(post_forms, start=1):
        has_token = any(pattern in form.lower() for pattern in CSRF_TOKEN_NAME_PATTERNS)
        if has_token:
            print(f"    [+] POST form #{i}: CSRF token field detected")
        else:
            unprotected_count += 1
            print(f"    [!] POST form #{i}: no CSRF token field detected")

    if unprotected_count:
        findings["A01"].append(
            f"{unprotected_count} of {len(post_forms)} POST form(s) on the page show no "
            "recognizable CSRF token field -- verify manually, some frameworks handle "
            "CSRF protection via cookies/headers instead of a visible form field"
        )


def print_report(target, findings):
    categories = {
        "A01": "Broken Access Control",
        "A02": "Cryptographic Failures",
        "A03": "Injection",
        "A04": "Insecure Design (partial - weak signal only)",
        "A05": "Security Misconfiguration",
        "A06": "Vulnerable and Outdated Components",
        "A07": "Identification and Authentication Failures",
        "A08": "Software and Data Integrity Failures",
        "A10": "Server-Side Request Forgery (surface heuristic only, not confirmed)",
    }
    not_tested = {
        "A09": "Security Logging and Monitoring Failures - not observable from outside the system",
    }

    print("\n" + "=" * 70)
    print(f"OWASP TOP 10 SCAN REPORT - {target}")
    print("=" * 70)

    total_findings = 0
    for code, name in categories.items():
        items = findings.get(code, [])
        total_findings += len(items)
        print(f"\n[{code}] {name} - {len(items)} finding(s)")
        for item in items:
            print(f"    - {item}")
        if not items:
            print("    (no issues detected by these checks)")

    print("\n" + "-" * 70)
    print("NOT TESTED (cannot be safely/meaningfully checked externally):")
    for code, reason in not_tested.items():
        print(f"    [{code}] {reason}")

    print("\n" + "=" * 70)
    print(f"TOTAL FINDINGS: {total_findings}")
    print("=" * 70)
    print(
        "\nNote: these are indicators, not confirmed vulnerabilities. Each "
        "finding should be manually verified before being reported or acted "
        "on. Only test domains you own or are explicitly authorized to assess."
    )


def main():
    parser = argparse.ArgumentParser(
        description="Passive/light-active scanner mapping findings to OWASP Top 10 (2021) categories."
    )
    parser.add_argument("target", help="Target URL or domain, e.g. https://example.com")
    parser.add_argument(
        "--dorks",
        action="store_true",
        help="Also print a categorized Google dork recon list scoped to this domain "
             "(only for domains you own or that are in-scope for a bug bounty program)",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=DEFAULT_DELAY,
        help=f"Seconds to wait between requests (default: {DEFAULT_DELAY}). "
             "Higher values are more considerate to the target's server.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Check the fuller list of sensitive file paths instead of the small default set",
    )
    parser.add_argument(
        "--contact",
        default="see-profile",
        help="Contact info (email/handle) included in the User-Agent so the target "
             "can identify and reach you if they notice the scan -- standard practice "
             "for legitimate, authorized security testing.",
    )
    args = parser.parse_args()

    base_url = normalize_url(args.target)
    domain_only = urlparse(base_url).hostname
    print(f"[*] Starting OWASP Top 10 scan against: {base_url}")
    print(f"[*] Request delay: {args.delay}s | Sensitive path list: "
          f"{'verbose' if args.verbose else 'default'}\n")

    session = make_session(args.contact)
    findings = {code: [] for code in ["A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A10"]}

    try:
        check_a05_security_headers(session, base_url, findings)
        check_a02_tls(base_url, findings)
        check_a01_common_admin_paths(session, base_url, findings, args.delay)
        check_csrf_tokens(session, base_url, findings)
        check_a05_sensitive_paths(session, base_url, findings, args.delay, args.verbose)
        check_a03_reflected_input(session, base_url, findings)
        check_a04_rate_limiting(session, base_url, findings, args.delay)
        check_a07_cookie_flags(session, base_url, findings)
        check_a08_sri(session, base_url, findings)
        check_a10_ssrf_surface(session, base_url, findings)
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
        sys.exit(1)

    print_report(base_url, findings)

    if args.dorks:
        generate_dorks(domain_only)


if __name__ == "__main__":
    main()
