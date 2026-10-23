# BountyReport 🎯

[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-Zero-brightgreen)](#)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)](#)
[![Bug Bounty](https://img.shields.io/badge/Bug%20Bounty-Ready-red)](#)
[![GitHub Stars](https://img.shields.io/github/stars/Venu-exe/bountyreport?style=social)](https://github.com/Venu-exe/bountyreport/stargazers)

> **Zero-dependency, pure-Python bug bounty submission report generator.**  
> Turn raw findings into polished, platform-ready markdown for **HackerOne, Bugcrowd, Intigriti, YesWeHack**, and generic programs — in seconds.

<p align="center">
  <img src="https://img.shields.io/badge/CVSS-3.1%20Calculator-blue" />
  <img src="https://img.shields.io/badge/Templates-27-orange" />
  <img src="https://img.shields.io/badge/Platforms-5-purple" />
</p>

---

## 📑 Table of Contents

- [Why BountyReport?](#-why-bountyreport)
- [Features](#-features)
- [Demo](#-demo)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Usage](#-usage)
- [Vulnerability Templates](#-vulnerability-templates)
- [CVSS 3.1 Calculator](#-cvss-31-calculator)
- [JSON Input Format](#-json-input-format)
- [Platform Formats](#-platform-formats)
- [CLI Reference](#-cli-reference)
- [Roadmap](#-roadmap)
- [Contributing](#-contributing)
- [License](#-license)
- [Author](#-author)

---

## 💡 Why BountyReport?

Writing a good bug bounty report is half the battle. A clear, well-structured submission with a correct CVSS score and a reproducible PoC is what separates **triaged** from **informative/duplicate**. BountyReport removes the boilerplate so you can focus on the bug.

- ⚡ **Fast** — generate a full report in under 30 seconds
- 🎯 **Accurate** — built-in CVSS 3.1 calculator (no more manual scoring mistakes)
- 🧩 **Templated** — 27 vulnerability types with pre-filled impact & remediation
- 🌐 **Multi-platform** — HackerOne, Bugcrowd, Intigriti, YesWeHack, Generic
- 🪶 **Zero deps** — pure Python 3, runs anywhere
- 🤖 **Automatable** — JSON input + `--quick` mode for CI/pipelines

---

## ✨ Features

| Feature | Description |
|---|---|
| 🧙 Interactive Wizard | Step-by-step guided report creation |
| 📐 CVSS 3.1 Calculator | Vector string in/out, auto severity rating |
| 🧩 27 Vuln Templates | XSS, IDOR, SSRF, SQLi, RCE, and more |
| 🏷️ 5 Platform Formats | H1, Bugcrowd, Intigriti, YesWeHack, Generic |
| 📄 JSON Input | Batch/automated report generation |
| ⚡ Quick Mode | One-liner reports from CLI flags |
| 📋 PoC Scaffolding | HTTP request/response + curl blocks |
| 🎨 Colorized CLI | Clean, readable terminal output |
| 📊 Severity Auto-Rating | Critical / High / Medium / Low / None |
| 🔁 Template Overrides | Apply template, then override any field |

---

## 🎬 Demo

```bash
$ python3 bountyreport.py -t xss -p hackerone --quick \
    --target example.com \
    --url "https://example.com/search" \
    --param q \
    --title "Reflected XSS in search"

  ✓ Report saved ./reports/report_example.com_20261023_173517.md
```

Generated report preview:

```markdown
# Reflected XSS in search

## Summary
A Cross-Site Scripting (XSS) was found.

## Severity
**Medium** — CVSS 3.1: `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` (Score: 6.1)

## Steps to Reproduce
1. Navigate to https://example.com/search
2. Inject payload: <script>alert(document.domain)</script>
3. Observe script execution in browser.

## Impact
An attacker can execute arbitrary JavaScript in a victim's browser...

## Suggested Fix
Context-aware output encoding, strict Content-Security-Policy...
```

---

## 📦 Installation

### Requirements
- Python **3.8+**
- No external dependencies

### Clone & Run

```bash
git clone https://github.com/Venu-exe/bountyreport.git
cd bountyreport
python3 bountyreport.py --help
```

### Optional: make it a global command

```bash
chmod +x bountyreport.py
sudo ln -s "$(pwd)/bountyreport.py" /usr/local/bin/bountyreport
bountyreport --help
```

---

## 🚀 Quick Start

```bash
# 1. Interactive wizard (recommended for first use)
python3 bountyreport.py

# 2. Quick report from a template
python3 bountyreport.py -t idor -p bugcrowd --quick \
  --target api.example.com \
  --url "https://api.example.com/users/123" \
  --param id \
  --title "IDOR in user profile endpoint"

# 3. Score a CVSS vector
python3 bountyreport.py --cvss "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"

# 4. From a JSON file
python3 bountyreport.py --file finding.json -o ./reports

# 5. Browse templates / platforms
python3 bountyreport.py --list-vulns
python3 bountyreport.py --list-platforms
```

---

## 📖 Usage

### Interactive Wizard

```bash
python3 bountyreport.py
```

Walks you through:
1. Target & platform selection
2. Vulnerability type (with template)
3. CVSS vector (template default or custom)
4. Summary, steps, impact, remediation
5. Proof of Concept (request/response/curl)
6. References

Output is written to `./reports/` by default (override with `-o`).

### Quick Mode

```bash
python3 bountyreport.py -t <type> -p <platform> --quick [options]
```

| Flag | Description |
|---|---|
| `-t, --type` | Vulnerability type (see `--list-vulns`) |
| `-p, --platform` | Target platform (default: `hackerone`) |
| `--target` | Target domain/program |
| `--url` | Full target URL |
| `--endpoint` | Endpoint/path (default: `/`) |
| `--param` | Parameter/field name (default: `q`) |
| `--title` | Report title |
| `--summary` | Summary paragraph |
| `-o, --output` | Output directory (default: `./reports`) |
| `--out` | Output filename |

### From JSON

```bash
python3 bountyreport.py --file finding.json -o ./reports
```

Accepts a single object or an array of findings. See [JSON Input Format](#-json-input-format).

---

## 🧩 Vulnerability Templates

27 built-in templates, each with a default CVSS vector, impact, remediation, and steps-to-reproduce scaffold.

| Key | Vulnerability |
|---|---|
| `xss` | Cross-Site Scripting (Reflected) |
| `stored_xss` | Stored XSS |
| `idor` | Insecure Direct Object Reference |
| `ssrf` | Server-Side Request Forgery |
| `sqli` | SQL Injection |
| `rce` | Remote Code Execution |
| `lfi` | Local File Inclusion |
| `open_redirect` | Open Redirect |
| `cors` | CORS Misconfiguration |
| `csrf` | Cross-Site Request Forgery |
| `auth_bypass` | Authentication Bypass |
| `info_disclosure` | Information Disclosure |
| `subdomain_takeover` | Subdomain Takeover |
| `race_condition` | Race Condition |
| `mass_assignment` | Mass Assignment |
| `jwt` | JWT Vulnerability |
| `xxe` | XML External Entity |
| `ssti` | Server-Side Template Injection |
| `file_upload` | Unrestricted File Upload |
| `business_logic` | Business Logic Flaw |
| `privilege_escalation` | Privilege Escalation |
| `rate_limit` | Missing Rate Limiting |
| `cache_poisoning` | Web Cache Poisoning |
| `http_smuggling` | HTTP Request Smuggling |
| `prototype_pollution` | Prototype Pollution |
| `nosql_injection` | NoSQL Injection |
| `command_injection` | Command Injection |

List them anytime: `python3 bountyreport.py --list-vulns`

---

## 📐 CVSS 3.1 Calculator

Standalone CVSS 3.1 base score calculator — no network, no dependencies.

```bash
# From a vector string
python3 bountyreport.py --cvss "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
# → Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N
# → Score:  6.1 (Medium)

# Interactive
python3 bountyreport.py   # choose CVSS in wizard
```

Supports all 8 base metrics: `AV`, `AC`, `PR`, `UI`, `S`, `C`, `I`, `A`.  
Severity rating follows FIRST's official scale:

| Score | Severity |
|---|---|
| 0.0 | None |
| 0.1 – 3.9 | Low |
| 4.0 – 6.9 | Medium |
| 7.0 – 8.9 | High |
| 9.0 – 10.0 | Critical |

---

## 📄 JSON Input Format

Single finding or array of findings:

```json
[
  {
    "vuln_type": "idor",
    "platform": "bugcrowd",
    "target": "api.example.com",
    "url": "https://api.example.com/users/123",
    "endpoint": "/users/{id}",
    "param": "id",
    "title": "IDOR in user profile endpoint",
    "summary": "User A can view User B's profile by changing the id parameter.",
    "poc_curl": "curl -s 'https://api.example.com/users/456' -H 'Authorization: Bearer TOKEN_A'"
  }
]
```

**Supported fields:** `title`, `vuln_type`, `platform`, `target`, `endpoint`, `param`, `url`, `cvss_vector`, `cvss_score`, `severity`, `summary`, `steps`, `poc_request`, `poc_response`, `poc_curl`, `impact`, `remediation`, `references`.

When `vuln_type` is provided, the template fills empty fields (impact, remediation, steps, CVSS) automatically; your explicit values always take precedence.

---

## 🏷️ Platform Formats

| Platform | Sections |
|---|---|
| `hackerone` | Summary, Severity, Steps to Reproduce, PoC, Impact, Suggested Fix, References |
| `bugcrowd` | Target, Vulnerability Type, Severity, Steps, PoC, Impact, Remediation |
| `intigriti` | Description, Severity, Steps to reproduce, Impact, Remediation, HTTP Request |
| `yeswehack` | Severity, CVSS Vector, Details, Steps, Impact, Remediation |
| `generic` | Flat markdown with all fields |

Select with `-p` / `--platform`.

---

## 📋 CLI Reference

```
usage: bountyreport.py [-h] [-t TYPE] [-p PLATFORM] [--file FILE] [--cvss CVSS]
                       [--list-vulns] [--list-platforms] [-o OUTPUT] [--quick]
                       [--title TITLE] [--url URL] [--target TARGET]
                       [--endpoint ENDPOINT] [--param PARAM] [--summary SUMMARY]
                       [--out OUT]

BountyReport — bug bounty submission report generator

options:
  -t, --type        Vulnerability type (see --list-vulns)
  -p, --platform    Target platform (default: hackerone)
  --file            JSON file with finding(s)
  --cvss            Compute CVSS score for a vector string
  --list-vulns      List vulnerability templates
  --list-platforms  List supported platforms
  -o, --output      Output directory (default: ./reports)
  --quick           Skip interactive prompts, use defaults
  --title           Report title
  --url             Target URL
  --target          Target domain/program
  --endpoint        Endpoint/path (default: /)
  --param           Parameter/field (default: q)
  --summary         Summary paragraph
  --out             Output filename
```

---

## 🗺️ Roadmap

- [ ] CVSS 4.0 support
- [ ] HTML / PDF export
- [ ] Screenshot embedding
- [ ] HackerOne API auto-submission
- [ ] Template customization via config file
- [ ] Report dedup / similarity check

Have an idea? [Open an issue](https://github.com/Venu-exe/bountyreport/issues)!

---

## 🤝 Contributing

Contributions are welcome! 🎉

1. Fork the repo
2. Create a feature branch: `git checkout -b feat/my-feature`
3. Commit changes: `git commit -m "feat: add my feature"`
4. Push: `git push origin feat/my-feature`
5. Open a Pull Request

Please keep the **zero-dependency** philosophy (pure Python stdlib only).

---

## 📄 License

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for details.

---

## 👤 Author

**Venu-exe** — bug bounty hunter & security tooling developer.

- GitHub: [@Venu-exe](https://github.com/Venu-exe)
- Portfolio: [Venu-exe.github.io](https://Venu-exe.github.io)

If this tool saved you time, consider ⭐ starring the repo!

---

<p align="center">
  <b>Built for hunters, by a hunter. 🎯 Happy hunting!</b>
</p>
"""