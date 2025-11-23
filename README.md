# VulnSentinal

VulnSentinal is a terminal-based **threat intelligence console** that helps you quickly pivot across:

- CVE data from the National Vulnerability Database (NVD)
- Exploit references on Exploit-DB
- Proof-of-concept / offensive tooling on GitHub

It does **not** exploit anything by itself. It’s a research and reconnaissance assistant designed for:

- Security researchers
- Penetration testers
- Blue teams tracking exposure
- Curious practitioners learning how vulnerabilities are surfaced and weaponized

---

## Features

### 1. Recent High-Risk Alerts
Track newly published vulnerabilities within a configurable time window and minimum severity:

- Time window: last _N_ days (default from config)
- Severity: CRITICAL / HIGH / MEDIUM / LOW
- Output includes:
  - CVE ID
  - CVSS score & severity
  - Publication date
  - Short English description
  - Direct NVD link

### 2. Threat Surface Lookup (Keyword CVE Search)
Search CVEs by keyword (product, technology, vulnerability type, etc.):

- Uses NVD’s `keywordSearch`
- Shows:
  - CVE ID
  - CVSS score/severity
  - Description snippet
  - NVD link
  - Exploit-DB search link for that CVE ID

### 3. Vendor Footprint Scan (Vendor/Product Search)
Same engine as keyword search, but semantically oriented toward a vendor/product:

- You might search `microsoft`, `cisco`, `wordpress`, etc.
- Great for footprinting a vendor’s vulnerability history.

### 4. Advisory Deep Dive (CVE Details)
Given an ID like `CVE-2025-1234`, VulnSentinal:

- Validates the CVE format
- Fetches full CVE record from NVD
- Extracts:
  - CVSS score, severity, and vector
  - Published and last-modified timestamps
  - Long English description
  - Up to 8 key references
- Provides quick links to:
  - NVD detail page
  - Exploit-DB search by CVE
  - GitHub PoC search by CVE

### 5. Exploit Intelligence Gateway (Exploit-DB Search)
Given a keyword (e.g., product, technique):

- Hits Exploit-DB search endpoint
- Prints the full URL so you can open it in your browser
- Reminds you that `searchsploit <keyword>` is also an option locally

### 6. Offensive Toolkit Discovery (GitHub Search)
Search GitHub for repositories that likely contain exploits, PoCs, or tooling:

- Query format: `<keyword> exploit OR poc OR vulnerability`
- Sorted by stars, descending
- For each repo:
  - `owner/name`
  - Stars
  - Language
  - Short description
  - URL
  - Last updated date

### 7. JSON Export
For NVD and GitHub-backed options, you can optionally export the raw JSON response to a file, useful for:

- Offline analysis
- Feeding into other tools
- Archiving snapshots of exposure

---

## Data Sources

- **NVD** API: https://services.nvd.nist.gov/
- **Exploit-DB** search interface: https://www.exploit-db.com/
- **GitHub** search API: https://docs.github.com/en/rest/search

All requests identify themselves with a dedicated User-Agent string.

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/vulnsentinal.git
cd vulnsentinal
```

2. Create and activate a virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate   # Linux/macOS
# On Windows:
# venv\Scripts\activate

3. Install dependencies
pip install -r requirements.txt

Configuration

VulnSentinal can be configured with:

Environment variables (highest precedence)

A TOML config file vulnsentinal.toml in the working directory

Internal default values

Environment variables

NVD_API_KEY – optional, but recommended for higher rate limits and reliability

GITHUB_TOKEN – optional, but helps avoid anonymous GitHub rate limits

Example:

export NVD_API_KEY="your-nvd-key"
export GITHUB_TOKEN="ghp_yourgithubtoken"

TOML config file

Copy the example file and adjust:

cp vulnsentinal.toml.example vulnsentinal.toml


vulnsentinal.toml:

[api]
nvd_api_key = "YOUR_NVD_API_KEY"
github_token = "YOUR_GITHUB_TOKEN"

[defaults]
days_lookback = 7
min_severity = "CRITICAL"
max_results = 20


Environment variables override anything defined in this file.

Usage

Run the console:

python vulnsentinal.py


You’ll see a menu like:

[1] Recent High-Risk Alerts (time-windowed CVEs)
[2] Threat Surface Lookup (keyword-based CVE search)
[3] Vendor Footprint Scan (vendor/product CVE search)
[4] Advisory Deep Dive (by CVE identifier)
[5] Exploit Intelligence Gateway (Exploit-DB search)
[6] Offensive Toolkit Discovery (GitHub repos)
[7] About / Usage Guide
[0] Exit

Examples

Recent high-risk alerts (menu 1)

Choose 1

Enter days (e.g., 7)

Enter minimum severity (e.g., CRITICAL)

Keyword-based CVE search (menu 2)

Choose 2

Keyword: apache

Max results: 30

Vendor scan (menu 3)

Choose 3

Vendor/product: cisco

Max results: 50

Specific CVE deep dive (menu 4)

Choose 4

CVE ID: CVE-2025-1234

Exploit-DB search (menu 5)

Choose 5

Term: windows privilege escalation

GitHub offensive toolkit search (menu 6)

Choose 6

Term: CVE-2021-44228

Max repos: 25

JSON Export

After most NVD and GitHub-based queries, VulnSentinal will ask:

[?] Save raw results to JSON file? [y/N]:


If you choose y, it will:

Ask for a filename (with a sensible default)

Save the raw JSON from the API to that file

This is useful if you want to:

Feed results into other analysis tools

Store snapshots of vulnerabilities for a given date range

Build your own dashboards

Requirements

See requirements.txt:

requests

toml (for Python < 3.11; Python 3.11+ can use tomllib from stdlib)

Python 3.8+ is recommended.

Notes & Limitations

All network calls depend on upstream APIs — if NVD, Exploit-DB, or GitHub change their interfaces or rate limit you, behavior may change.

This tool is for research & reconnaissance, not for autonomous exploitation.

Use it only in environments and against targets where you are legally authorized to perform security assessments.

Contributing

Fork the repository

Create a feature branch

Make changes with clear commit messages

Open a pull request with a focused description
