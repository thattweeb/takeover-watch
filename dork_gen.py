#!/usr/bin/env python3
"""
dork_gen.py

Generates a categorized list of Google dork queries scoped to a single
domain, for use during AUTHORIZED security research / bug bounty recon
(i.e. only against domains explicitly listed in scope for a program you're
enrolled in on HackerOne, Bugcrowd, etc., or domains you own).

This tool does NOT send any requests to the target domain. It only prints
ready-to-use search queries -- you copy/paste them into Google yourself.
Google indexes what's already publicly accessible about a domain; these
queries just help you search that index more precisely.

Usage:
    python dork_gen.py example.com
    python dork_gen.py example.com --category files
    python dork_gen.py example.com --list-categories
"""

import argparse


DORK_TEMPLATES = {
    "files": {
        "label": "Exposed sensitive files",
        "queries": [
            'site:{domain} filetype:env',
            'site:{domain} filetype:sql',
            'site:{domain} filetype:log',
            'site:{domain} filetype:bak',
            'site:{domain} ext:config',
            'site:{domain} intitle:"index of" "parent directory"',
        ],
    },
    "credentials": {
        "label": "Exposed credentials / config",
        "queries": [
            'site:{domain} "api_key" filetype:json',
            'site:{domain} "aws_access_key_id"',
            'site:{domain} inurl:wp-config.php.bak',
        ],
    },
    "admin": {
        "label": "Admin / login panels",
        "queries": [
            'site:{domain} inurl:admin',
            'site:{domain} inurl:login intitle:"admin"',
            'site:{domain} inurl:phpmyadmin',
        ],
    },
    "documents": {
        "label": "Exposed documents (possible info leak)",
        "queries": [
            'site:{domain} filetype:pdf "confidential"',
            'site:{domain} filetype:xls "internal"',
            'site:{domain} filetype:doc "password"',
        ],
    },
    "errors": {
        "label": "Error messages / stack traces",
        "queries": [
            'site:{domain} "sql syntax near"',
            'site:{domain} "warning: mysql"',
            'site:{domain} "fatal error" "on line"',
        ],
    },
    "source_control": {
        "label": "Exposed source control / backups",
        "queries": [
            'site:{domain} inurl:.git',
            'site:{domain} inurl:.svn',
            'site:{domain} ext:zip OR ext:tar.gz',
        ],
    },
    "subdomains": {
        "label": "Subdomain discovery",
        "queries": [
            'site:*.{domain} -site:www.{domain}',
        ],
    },
}


def list_categories():
    print("Available categories:")
    for key, data in DORK_TEMPLATES.items():
        print(f"  {key:<15} - {data['label']}")


def generate_dorks(domain: str, category: str = None):
    print("\n" + "=" * 70)
    print(f"GOOGLE DORK RECON LIST - {domain}")
    print("=" * 70)
    print(
        "\nOnly use these against domains explicitly listed in scope for a\n"
        "bug bounty program you are enrolled in (HackerOne, Bugcrowd, etc.),\n"
        "or domains you own. Copy each line into Google manually -- Google\n"
        "rate-limits/CAPTCHAs automated dork queries, so run these a handful\n"
        "at a time in a browser, not scripted at scale.\n"
    )

    categories_to_show = DORK_TEMPLATES
    if category:
        if category not in DORK_TEMPLATES:
            print(f"[!] Unknown category '{category}'.")
            list_categories()
            return
        categories_to_show = {category: DORK_TEMPLATES[category]}

    for key, data in categories_to_show.items():
        print(f"\n[{data['label']}]")
        for q in data["queries"]:
            print(f"    {q.format(domain=domain)}")

    print("\n" + "-" * 70)
    print(
        "For a much larger, continuously updated library, see the Google\n"
        "Hacking Database (GHDB): https://www.exploit-db.com/google-hacking-database"
    )
    print("=" * 70)


def main():
    parser = argparse.ArgumentParser(
        description="Generate domain-scoped Google dork queries for authorized security recon."
    )
    parser.add_argument(
        "domain",
        nargs="?",
        help="Target domain, e.g. example.com (no https://)",
    )
    parser.add_argument(
        "--category",
        help="Only show dorks from one category (see --list-categories for options)",
    )
    parser.add_argument(
        "--list-categories",
        action="store_true",
        help="List available dork categories and exit",
    )
    args = parser.parse_args()

    if args.list_categories:
        list_categories()
        return

    if not args.domain:
        parser.error("domain is required unless using --list-categories")

    generate_dorks(args.domain, args.category)


if __name__ == "__main__":
    main()
