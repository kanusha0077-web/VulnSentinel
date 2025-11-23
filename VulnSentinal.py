#!/usr/bin/env python3
# VulnSentinal - Consolidated vulnerability and exploit intelligence assistant
# Originally inspired by Exploit Eye by Jolanda de Koff (BullsEye0)

import os
import re
import json
import time
import sys
from datetime import datetime, timedelta

import requests

# Color constants
RED = "\033[1;31m"
BLUE = "\033[1;34m"
BOLD = "\033[1m"
RESET = "\033[0m"

HTTP_TIMEOUT = 30
MAX_RESULTS_LIMIT = 100

NVD_API_KEY = os.getenv("NVD_API_KEY")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")


def banner():
    print(f"""
{RED}{BOLD}
██╗   ██╗██╗   ██╗██╗     ███╗   ██╗███████╗███████╗███████╗███████╗███████╗
██║   ██║██║   ██║██║     ████╗  ██║██╔════╝██╔════╝██╔════╝██╔════╝██╔════╝
██║   ██║██║   ██║██║     ██╔██╗ ██║███████╗███████╗█████╗  ███████╗█████╗  
╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║╚════██║╚════██║██╔══╝  ╚════██║██╔══╝  
 ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║███████║███████║███████╗███████║███████╗
  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚══════╝╚══════╝╚══════╝╚══════╝╚══════╝
{RESET}
                    {BOLD}VulnSentinal v1.0 - Threat Insight Console{RESET}

        Aggregate CVE intelligence, exploit references, and security tooling
    """)


def menu():
    print(f"\n{BLUE}{'=' * 72}{RESET}")
    print(f"{BLUE}[1]{RESET} Recent High-Risk Alerts (time-windowed CVEs)")
    print(f"{BLUE}[2]{RESET} Threat Surface Lookup (keyword-based CVE search)")
    print(f"{BLUE}[3]{RESET} Vendor Footprint Scan (vendor/product CVE search)")
    print(f"{BLUE}[4]{RESET} Advisory Deep Dive (by CVE identifier)")
    print(f"{BLUE}[5]{RESET} Exploit Intelligence Gateway (Exploit-DB search)")
    print(f"{BLUE}[6]{RESET} Offensive Toolkit Discovery (GitHub repos)")
    print(f"{BLUE}[7]{RESET} About / Usage Guide")
    print(f"{BLUE}[0]{RESET} Exit")
    print(f"{BLUE}{'=' * 72}{RESET}")


def show_about():
    print(f"\n{BOLD}VulnSentinal - Threat Intelligence Assistant{RESET}\n")
    print("This console helps you:")
    print("  • Track recent high-impact CVEs")
    print("  • Search vulnerabilities by keyword, vendor, or specific CVE ID")
    print("  • Jump directly to Exploit-DB search results")
    print("  • Discover PoC / offensive tooling on GitHub\n")
    print("Environment variables (optional but recommended):")
    print("  • NVD_API_KEY    – NVD API key for better reliability & quota")
    print("  • GITHUB_TOKEN   – GitHub token to avoid public rate limits\n")
    print("Tip: Use this as a reconnaissance and research aid,")
    print("     not as an automated exploitation platform.\n")


def http_get(url, params=None, headers=None, timeout=HTTP_TIMEOUT, retries=1):
    """Wrapper around requests.get with basic error handling and optional retries."""
    base_headers = {
        "User-Agent": "VulnSentinal/1.0 (https://example.com)"
    }
    if headers:
        base_headers.update(headers)

    attempt = 0
    while True:
        attempt += 1
        try:
            resp = requests.get(url, params=params, headers=base_headers, timeout=timeout)
        except requests.exceptions.RequestException as e:
            print(f"{RED}[!] HTTP error contacting {url}: {e}{RESET}")
            if attempt > retries:
                return None
            print("[*] Retrying...")
            time.sleep(1)
            continue

        if resp.status_code == 200:
            return resp
        elif resp.status_code in (403, 429):
            print(f"{RED}[!] Remote service refused the request (status {resp.status_code}).{RESET}")
            if "github.com" in url.lower():
                print("[!] GitHub likely rate-limited you – consider setting GITHUB_TOKEN.")
            elif "nvd.nist.gov" in url.lower():
                print("[!] NVD API may be rate-limiting – consider an NVD_API_KEY.")
            return None
        elif 500 <= resp.status_code < 600 and attempt <= retries:
            print(f"[!] Server error {resp.status_code}, retrying...")
            time.sleep(1)
            continue
        else:
            print(f"{RED}[!] HTTP error {resp.status_code} from {url}{RESET}")
            return None


def extract_cvss(metrics):
    """Return (score, severity, vector) from NVD metrics dict."""
    score = "N/A"
    severity = "N/A"
    vector = "N/A"

    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV3", "cvssMetricV2"):
        metric_list = metrics.get(key)
        if metric_list:
            cvss_data = metric_list[0].get("cvssData", {})
            score = cvss_data.get("baseScore", "N/A")
            severity = cvss_data.get("baseSeverity", "N/A") or severity
            vector = cvss_data.get("vectorString", "N/A")
            break

    return score, severity, vector


def get_english_description(descriptions, max_len=300):
    text = "N/A"
    for desc in descriptions or []:
        if desc.get("lang") == "en":
            text = desc.get("value", "N/A")
            break
    if isinstance(text, str) and len(text) > max_len:
        return text[:max_len] + "..."
    return text


CVE_REGEX = re.compile(r"^CVE-\d{4}-\d{4,7}$")


def validate_cve_id(cve_id):
    return bool(CVE_REGEX.match(cve_id))


def clamp_results(value, default=20):
    try:
        v = int(value)
    except (TypeError, ValueError):
        return default
    return max(1, min(v, MAX_RESULTS_LIMIT))


def prompt_export_json(data, default_filename):
    if not data:
        return
    choice = input("\n[?] Save raw results to JSON file? [y/N]: ").strip().lower()
    if choice != "y":
        return
    filename = input(f"[+] Filename (default: {default_filename}): ").strip() or default_filename
    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        print(f"[✓] Saved results to {filename}")
    except Exception as e:
        print(f"{RED}[!] Failed to write file: {e}{RESET}")


def get_latest_cves(days=7, severity="CRITICAL"):
    print(f"\n[*] Gathering recent alerts from last {days} day(s) with severity: {severity}...")
    try:
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)

        pub_start = start_date.strftime("%Y-%m-%dT00:00:00.000")
        pub_end = end_date.strftime("%Y-%m-%dT23:59:59.999")

        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

        params = {
            "pubStartDate": pub_start,
            "pubEndDate": pub_end,
            "cvssV3Severity": severity.upper(),
        }
        if NVD_API_KEY:
            params["apiKey"] = NVD_API_KEY

        resp = http_get(url, params=params)
        if not resp:
            return

        data = resp.json()
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            print("[!] No CVEs returned for that window/severity.")
            return

        print(f"\n[✓] Retrieved {len(vulns)} CVEs "
              f"(Total available: {data.get('totalResults', 'N/A')}).\n")

        for idx, wrapper in enumerate(vulns, start=1):
            vuln = wrapper.get("cve", {})
            cve_id = vuln.get("id", "N/A")
            description = get_english_description(vuln.get("descriptions"), max_len=200)
            metrics = vuln.get("metrics", {})
            score, sev, _ = extract_cvss(metrics)
            published = vuln.get("published", "N/A")

            print("*" * 72)
            print(f"[{idx}] {cve_id}")
            print(f"[+] CVSS: {score} ({sev})")
            print(f"[+] Published: {published[:10]}")
            print(f"[+] Summary: {description}")
            print(f"[+] NVD Detail: https://nvd.nist.gov/vuln/detail/{cve_id}")
            print()

            time.sleep(0.05)

        print("*" * 72)
        prompt_export_json(data, "vulnsentinal_recent_cves.json")

    except Exception as e:
        print(f"{RED}[!] Error while fetching recent CVEs: {e}{RESET}")


def search_cve_keyword(keyword, max_results=20):
    max_results = clamp_results(max_results)
    print(f"\n[*] Threat surface lookup for: {keyword}")
    print(f"[*] Max results this page: {max_results}")

    try:
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

        params = {
            "keywordSearch": keyword,
            "resultsPerPage": max_results,
        }
        if NVD_API_KEY:
            params["apiKey"] = NVD_API_KEY

        resp = http_get(url, params=params)
        if not resp:
            return

        data = resp.json()
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            print(f"[!] No CVEs found matching: {keyword}")
            return

        total = data.get("totalResults", 0)
        print(f"\n[✓] Showing {len(vulns)} result(s) (total reported by NVD: {total}).\n")
        if total > len(vulns):
            print("[!] NVD reports more results than returned in this page. "
                  "Refine your keyword or increase resultsPerPage (up to 100).\n")

        for idx, wrapper in enumerate(vulns, start=1):
            vuln = wrapper.get("cve", {})
            cve_id = vuln.get("id", "N/A")
            description = get_english_description(vuln.get("descriptions"), max_len=260)
            metrics = vuln.get("metrics", {})
            score, sev, _ = extract_cvss(metrics)
            published = vuln.get("published", "N/A")

            print("*" * 72)
            print(f"[{idx}] {cve_id}")
            print(f"[+] CVSS: {score} ({sev})")
            print(f"[+] Published: {published[:10]}")
            print(f"[+] Summary: {description}")
            print(f"[+] NVD: https://nvd.nist.gov/vuln/detail/{cve_id}")
            print(f"[+] Exploit-DB (search by CVE): https://www.exploit-db.com/search?cve={cve_id}")
            print()
            time.sleep(0.05)

        print("*" * 72)
        prompt_export_json(data, "vulnsentinal_keyword_search.json")

    except Exception as e:
        print(f"{RED}[!] Error during keyword search: {e}{RESET}")


def search_exploitdb(keyword):
    print(f"\n[*] Opening exploit intelligence view for: {keyword}")
    try:
        url = "https://www.exploit-db.com/search"
        params = {"q": keyword}

        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
        }

        resp = http_get(url, params=params, headers=headers)
        if not resp:
            return

        print("[✓] Search endpoint reached.")
        print(f"[+] Results URL (open in browser): {resp.url}")
        print("\n[!] For richer local enumeration, you can also use:")
        print(f"    searchsploit {keyword}")

    except Exception as e:
        print(f"{RED}[!] Error while contacting Exploit-DB: {e}{RESET}")


def search_github(keyword, max_results=20):
    max_results = clamp_results(max_results)
    print(f"\n[*] Offensive toolkit discovery for: {keyword}")
    print(f"[*] Max repositories to display: {max_results}")

    try:
        url = "https://api.github.com/search/repositories"

        params = {
            "q": f"{keyword} exploit OR poc OR vulnerability",
            "sort": "stars",
            "order": "desc",
            "per_page": max_results
        }

        headers = {
            "Accept": "application/vnd.github.v3+json",
        }
        if GITHUB_TOKEN:
            headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"

        resp = http_get(url, params=params, headers=headers)
        if not resp:
            return

        data = resp.json()
        items = data.get("items", [])
        if not items:
            print(f"[!] No GitHub repositories found matching: {keyword}")
            return

        total = data.get("total_count", 0)
        print(f"\n[✓] Showing {len(items)} repository result(s) "
              f"(GitHub reports total: {total}).\n")

        for idx, repo in enumerate(items, start=1):
            full_name = repo.get("full_name", "N/A")
            stars = repo.get("stargazers_count", 0)
            language = repo.get("language", "N/A")
            desc = repo.get("description") or "No description"
            if len(desc) > 150:
                desc = desc[:150] + "..."
            url_html = repo.get("html_url", "N/A")
            updated = repo.get("updated_at", "N/A")

            print("*" * 72)
            print(f"[{idx}] {full_name}")
            print(f"[+] Stars: {stars}")
            print(f"[+] Language: {language}")
            print(f"[+] Description: {desc}")
            print(f"[+] URL: {url_html}")
            print(f"[+] Last Updated: {updated[:10]}")
            print()
            time.sleep(0.05)

        print("*" * 72)
        print(f"\n[!] Direct GitHub search URL:")
        print(f"    https://github.com/search?q={keyword}+exploit\n")

        prompt_export_json(data, "vulnsentinal_github_search.json")

    except Exception as e:
        print(f"{RED}[!] Error during GitHub search: {e}{RESET}")


def get_cve_details(cve_id):
    print(f"\n[*] Advisory deep dive for: {cve_id}")
    if not validate_cve_id(cve_id):
        print(f"{RED}[!] '{cve_id}' does not look like a valid CVE identifier (e.g., CVE-2025-1234).{RESET}")
        return

    try:
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {"cveId": cve_id}
        if NVD_API_KEY:
            params["apiKey"] = NVD_API_KEY

        resp = http_get(url, params=params)
        if not resp:
            return

        data = resp.json()
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            print(f"[!] CVE not found in NVD: {cve_id}")
            return

        vuln = vulns[0].get("cve", {})
        descriptions = vuln.get("descriptions", [])
        description = get_english_description(descriptions, max_len=800)
        metrics = vuln.get("metrics", {})
        score, severity, vector = extract_cvss(metrics)

        published = vuln.get("published", "N/A")
        modified = vuln.get("lastModified", "N/A")
        refs = vuln.get("references", [])

        print("\n" + "=" * 72)
        print(f"{BOLD}CVE Advisory: {cve_id}{RESET}")
        print("=" * 72)
        print(f"\n[+] CVSS Base Score: {score}")
        print(f"[+] Severity: {severity}")
        print(f"[+] Vector: {vector}")
        print(f"[+] Published: {published}")
        print(f"[+] Last Modified: {modified}")

        print(f"\n[+] Description:\n    {description}\n")

        if refs:
            print("[+] Selected references:")
            for ref in refs[:8]:
                print(f"    - {ref.get('url', 'N/A')}")

        print(f"\n[+] Quick links:")
        print(f"    - NVD:       https://nvd.nist.gov/vuln/detail/{cve_id}")
        print(f"    - Exploit-DB search: https://www.exploit-db.com/search?cve={cve_id}")
        print(f"    - GitHub PoCs:       https://github.com/search?q={cve_id}&type=repositories")

        print("=" * 72)
        prompt_export_json(data, f"vulnsentinal_{cve_id}.json")

    except Exception as e:
        print(f"{RED}[!] Error while fetching CVE details: {e}{RESET}")


def main():
    banner()

    while True:
        try:
            menu()
            choice = input(f"\n{BLUE}[+]{RESET} Select action: ").strip()

            if choice == "1":
                days_raw = input("\n[+] Look back how many days? (default 7): ").strip()
                days = int(days_raw) if days_raw else 7
                if days < 1:
                    days = 1
                severity_raw = input("[+] Minimum severity [CRITICAL/HIGH/MEDIUM/LOW] (default CRITICAL): ").strip().upper()
                if severity_raw not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                    severity_raw = "CRITICAL"
                get_latest_cves(days=days, severity=severity_raw)

            elif choice == "2":
                keyword = input("\n[+] Enter keyword for threat lookup: ").strip()
                if keyword:
                    max_raw = input("[+] Max results (default 20, max 100): ").strip()
                    max_results = clamp_results(max_raw or 20)
                    search_cve_keyword(keyword, max_results)

            elif choice == "3":
                vendor = input("\n[+] Enter vendor/product identifier: ").strip()
                if vendor:
                    max_raw = input("[+] Max results (default 20, max 100): ").strip()
                    max_results = clamp_results(max_raw or 20)
                    search_cve_keyword(vendor, max_results)

            elif choice == "4":
                cve_id = input("\n[+] Enter CVE ID (e.g., CVE-2025-1234): ").strip().upper()
                if cve_id:
                    get_cve_details(cve_id)

            elif choice == "5":
                keyword = input("\n[+] Exploit-DB search term: ").strip()
                if keyword:
                    search_exploitdb(keyword)

            elif choice == "6":
                keyword = input("\n[+] GitHub search term (product, CVE, etc.): ").strip()
                if keyword:
                    max_raw = input("[+] Max repositories (default 20, max 100): ").strip()
                    max_results = clamp_results(max_raw or 20)
                    search_github(keyword, max_results)

            elif choice == "7":
                show_about()

            elif choice == "0":
                print(f"\n{BLUE}[*] Exiting VulnSentinal. Stay sharp.{RESET}\n")
                sys.exit(0)

            else:
                print(f"\n{RED}[-] Invalid menu selection.{RESET}")

        except KeyboardInterrupt:
            print(f"\n\n{BLUE}[*] Interrupted. Exiting VulnSentinal.{RESET}\n")
            sys.exit(0)
        except ValueError:
            print(f"\n{RED}[-] Invalid numeric input.{RESET}")
        except Exception as e:
            print(f"\n{RED}[!] Unexpected error: {e}{RESET}")


if __name__ == "__main__":
    main()
