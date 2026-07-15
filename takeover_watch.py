#!/usr/bin/env python3
"""
takeover_watch.py

Enumerates subdomains for a given domain via crt.sh (Certificate Transparency
logs) and checks each one's CNAME record for dangling references (NXDOMAIN),
which can indicate a potential subdomain takeover vulnerability.

Usage:
    python takeover_watch.py example.com

Requirements:
    pip install dnspython requests
"""

import sys
import time
import json
import argparse

import requests
import dns.resolver
import dns.exception


CRTSH_URL = "https://crt.sh/?q={domain}&output=json"
REQUEST_TIMEOUT = 30
DNS_TIMEOUT = 5


def fetch_subdomains(domain: str) -> set:
    """
    Query crt.sh for certificate transparency records matching the domain
    and return a deduplicated set of subdomains found in the certificate
    common names / SANs.
    """
    url = CRTSH_URL.format(domain=domain)
    print(f"[*] Querying crt.sh for subdomains of '{domain}'...")

    try:
        resp = requests.get(url, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
    except requests.exceptions.Timeout:
        print("[!] Request to crt.sh timed out.")
        return set()
    except requests.exceptions.ConnectionError as e:
        print(f"[!] Could not connect to crt.sh: {e}")
        return set()
    except requests.exceptions.HTTPError as e:
        print(f"[!] crt.sh returned an HTTP error: {e}")
        return set()
    except requests.exceptions.RequestException as e:
        print(f"[!] Unexpected error querying crt.sh: {e}")
        return set()

    if not resp.text.strip():
        print("[!] crt.sh returned an empty response.")
        return set()

    try:
        data = resp.json()
    except json.JSONDecodeError:
        print("[!] Failed to parse crt.sh response as JSON. "
              "The service may be rate-limiting or temporarily down.")
        return set()

    subdomains = set()
    for entry in data:
        name_value = entry.get("name_value", "")
        # name_value can contain multiple newline-separated names
        for name in name_value.split("\n"):
            name = name.strip().lower()
            if name and "*" not in name:  # skip wildcard entries
                subdomains.add(name)

    print(f"[*] Found {len(subdomains)} unique subdomain(s) via crt.sh.")
    return subdomains


def check_cname(subdomain: str, resolver: dns.resolver.Resolver) -> str:
    """
    Attempt to resolve the CNAME record for a subdomain.
    Returns a status string: 'NXDOMAIN', 'NO_CNAME', 'RESOLVED:<target>',
    'TIMEOUT', or 'ERROR:<message>'.
    """
    try:
        answer = resolver.resolve(subdomain, "CNAME")
        target = str(answer[0].target).rstrip(".")
        return f"RESOLVED:{target}"
    except dns.resolver.NXDOMAIN:
        return "NXDOMAIN"
    except dns.resolver.NoAnswer:
        # No CNAME record exists (might have A/AAAA directly instead) - not a takeover signal
        return "NO_CNAME"
    except dns.resolver.NoNameservers:
        return "ERROR:No nameservers available to answer the query"
    except dns.exception.Timeout:
        return "TIMEOUT"
    except Exception as e:
        return f"ERROR:{e}"


def main():
    parser = argparse.ArgumentParser(
        description="Check subdomains of a domain for potential takeover "
                    "vulnerabilities via dangling CNAME records."
    )
    parser.add_argument("domain", help="Target domain, e.g. example.com")
    parser.add_argument(
        "--delay",
        type=float,
        default=0.1,
        help="Delay in seconds between DNS queries (default: 0.1)",
    )
    args = parser.parse_args()

    domain = args.domain.strip().lower()
    if not domain:
        print("[!] Please provide a valid domain.")
        sys.exit(1)

    subdomains = fetch_subdomains(domain)
    if not subdomains:
        print("[!] No subdomains to check. Exiting.")
        sys.exit(0)

    resolver = dns.resolver.Resolver()
    # On some Windows setups dnspython fails to correctly read the system's
    # configured DNS servers, causing every query to time out even though
    # the OS itself resolves fine. Forcing well-known public resolvers here
    # avoids that issue.
    resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_TIMEOUT

    print(f"[*] Checking CNAME records for {len(subdomains)} subdomain(s)...\n")

    sorted_subs = sorted(subdomains)
    total = len(sorted_subs)
    potential_takeovers = []
    resolved_count = 0
    no_cname_count = 0
    error_count = 0

    for i, sub in enumerate(sorted_subs, start=1):
        print(f"[{i}/{total}] Checking {sub} ...", end=" ")
        result = check_cname(sub, resolver)

        if result == "NXDOMAIN":
            print("NXDOMAIN  <-- POTENTIAL TAKEOVER")
            potential_takeovers.append(sub)
        elif result == "NO_CNAME":
            print("no CNAME record")
            no_cname_count += 1
        elif result == "TIMEOUT":
            print("DNS query timed out")
            error_count += 1
        elif result.startswith("RESOLVED:"):
            target = result.split(":", 1)[1]
            print(f"CNAME -> {target} (resolved OK)")
            resolved_count += 1
        elif result.startswith("ERROR:"):
            msg = result.split(":", 1)[1]
            print(f"error: {msg}")
            error_count += 1
        else:
            print(f"unexpected result: {result}")
            error_count += 1

        if args.delay > 0:
            time.sleep(args.delay)

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"Total subdomains checked : {total}")
    print(f"CNAME resolved OK        : {resolved_count}")
    print(f"No CNAME record          : {no_cname_count}")
    print(f"Errors / timeouts        : {error_count}")
    print(f"Potential takeovers      : {len(potential_takeovers)}")

    if potential_takeovers:
        print("\n[!] Subdomains with dangling CNAME (NXDOMAIN) - investigate further:")
        for sub in potential_takeovers:
            print(f"    - {sub}")
        print(
            "\nNote: NXDOMAIN on a CNAME target means the record points to a "
            "hostname that doesn't exist. If that hostname belongs to a cloud "
            "service (S3, Azure, GitHub Pages, Heroku, etc.) that anyone can "
            "register, this may be exploitable. Always verify manually and "
            "only test on domains you own or are authorized to assess."
        )
    else:
        print("\n[+] No obviously dangling CNAME records found.")


if __name__ == "__main__":
    main()
