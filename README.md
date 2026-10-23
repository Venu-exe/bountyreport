# BountyReport 🎯

Zero-dependency, pure-Python bug bounty submission report generator. Turns your findings into platform-ready markdown for HackerOne, Bugcrowd, Intigriti, YesWeHack, and generic programs.

## Features

- 🧙 Interactive wizard
- 📐 CVSS 3.1 base score calculator (vector in/out)
- 🧩 27 vulnerability templates (XSS, IDOR, SSRF, SQLi, RCE, ...)
- 🏷️ Platform formats: HackerOne, Bugcrowd, Intigriti, YesWeHack, Generic
- 📄 JSON file input for automation/CI
- ⚡ Quick mode for scripting
- 📋 PoC scaffolding (HTTP request/response, curl)

## Install

```bash
git clone https://github.com/Venu-exe/bountyreport.git
cd bountyreport
python3 bountyreport.py --help
```

No dependencies required — pure Python 3.

## Usage

```bash
# Interactive wizard
python3 bountyreport.py

# Quick report from a template
python3 bountyreport.py -t xss -p hackerone --quick --target example.com --url "https://example.com/search" --param q

# Score a CVSS vector
python3 bountyreport.py --cvss "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"

# From JSON
python3 bountyreport.py --file finding.json -o ./reports

# List templates / platforms
python3 bountyreport.py --list-vulns
python3 bountyreport.py --list-platforms
```

## JSON format

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
    "summary": "User A can view User B profile by changing id.",
    "poc_curl": "curl -s 'https://api.example.com/users/456' -H 'Authorization: Bearer TOKEN_A'"
  }
]
```

## License

MIT
EOF
echo done