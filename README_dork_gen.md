# dork_gen.py

Generates a categorized list of **Google dork queries** scoped to a single
domain, for use during authorized security research / bug bounty
reconnaissance (e.g. HackerOne, Bugcrowd programs, or domains you own).

## What it does

Google dorks are advanced search operators (`site:`, `filetype:`, `inurl:`,
etc.) that let you search more precisely within what Google has already
indexed publicly about a domain. This tool doesn't invent a new technique —
it just organizes the standard, widely-used dork categories and inserts your
target domain automatically, so you don't have to rewrite each query by hand
every time you pick a new target.

**This tool sends no requests to the target domain at all.** It only prints
search query strings for you to copy and paste into Google yourself. Only
Google sees what you search — the target site's server logs are never
touched by running this script.

## Categories included

| Category key | What it finds |
|---|---|
| `files` | Exposed sensitive files (`.env`, `.sql`, `.log`, `.bak`, directory listings) |
| `credentials` | Exposed API keys, AWS credentials, leftover config backups |
| `admin` | Admin/login panels indexed by Google |
| `documents` | Exposed PDFs/docs/spreadsheets that may contain internal info |
| `errors` | Indexed error messages / stack traces (info disclosure) |
| `source_control` | Exposed `.git`, `.svn`, or backup archives |
| `subdomains` | Subdomain discovery via indexed pages |

## Installation

No external dependencies — uses only Python's built-in `argparse`.

```bash
# nothing to install
```

## Usage

```bash
# Full list, all categories
python dork_gen.py example.com

# Just one category
python dork_gen.py example.com --category admin

# See available category keys
python dork_gen.py --list-categories
```

## Sample output

```
======================================================================
GOOGLE DORK RECON LIST - example.com
======================================================================

[Admin / login panels]
    site:example.com inurl:admin
    site:example.com inurl:login intitle:"admin"
    site:example.com inurl:phpmyadmin
```

## Responsible use

- Only run these queries against domains explicitly listed in scope for a bug bounty program you're enrolled in, or domains you own.
- Google actively rate-limits and CAPTCHAs automated dork queries — run these manually in a browser a handful at a time, not scripted at scale.
- For a much larger, continuously updated library of dorks, see the [Google Hacking Database (GHDB)](https://www.exploit-db.com/google-hacking-database), maintained by Offensive Security/Exploit-DB.

## Built with

- Python 3 (standard library only)
