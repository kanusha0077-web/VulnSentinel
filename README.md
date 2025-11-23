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
