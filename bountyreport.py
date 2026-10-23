#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║  BountyReport — Bug Bounty Submission Report Generator       ║
║  Zero dependencies. Pure Python. Built for hunters.         ║
╚══════════════════════════════════════════════════════════════╝

Features:
  • Interactive wizard for building submission-ready reports
  • CVSS 3.1 base score calculator (vector string in/out)
  • Vulnerability templates (XSS, IDOR, SSRF, SQLi, RCE, ...)
  • Platform formats: HackerOne, Bugcrowd, Intigriti, YesWeHack, Generic
  • JSON file input for automation / CI
  • Multi-finding report support
  • PoC scaffolding (HTTP request/response, curl, steps)
  • Severity auto-rating from CVSS

Usage:
  python3 bountyreport.py                      Interactive wizard
  python3 bountyreport.py --file finding.json  From JSON
  python3 bountyreport.py --cvss "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
  python3 bountyreport.py --list-vulns
  python3 bountyreport.py --list-platforms
  python3 bountyreport.py -t xss -p hackerone --quick

Author: Built for bug bounty hunters 🎯
"""

import os
import sys
import json
import math
import argparse
import textwrap
from datetime import datetime
from typing import Dict, List, Optional, Tuple

# ============================================================
# COLORS & UI
# ============================================================
class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    GRAY = "\033[90m"

    @staticmethod
    def disable():
        for a in ["RESET","BOLD","DIM","RED","GREEN","YELLOW","BLUE","MAGENTA","CYAN","WHITE","GRAY"]:
            setattr(C, a, "")

if not sys.stdout.isatty():
    C.disable()


def banner():
    print(f"""{C.CYAN}{C.BOLD}
╔══════════════════════════════════════════════════════════════╗
║  BountyReport — Bug Bounty Submission Report Generator       ║
║  Zero deps · Pure Python · Built for hunters 🎯              ║
╚══════════════════════════════════════════════════════════════╝{C.RESET}""")


def section(title):
    print(f"\n{C.MAGENTA}{C.BOLD}═══ {title} ═══{C.RESET}")


def ask(prompt, default=None, choices=None):
    suffix = ""
    if default is not None:
        suffix = f" [{default}]"
    if choices:
        suffix += f" ({'/'.join(choices)})"
    while True:
        val = input(f"{C.CYAN}{prompt}{suffix}: {C.RESET}").strip()
        if val == "" and default is not None:
            val = str(default)
        if choices and val not in choices:
            print(f"{C.RED}Choose one of: {', '.join(choices)}{C.RESET}")
            continue
        if val == "" and default is None:
            print(f"{C.RED}Required.{C.RESET}")
            continue
        return val


def ask_multiline(prompt):
    print(f"{C.CYAN}{prompt} (end with a line containing only 'EOF'):{C.RESET}")
    lines = []
    while True:
        line = input()
        if line.strip() == "EOF":
            break
        lines.append(line)
    return "\n".join(lines).strip()


def found(msg, detail="", good=True):
    color = C.GREEN if good else C.RED
    print(f"  {color}✓{C.RESET} {msg}" + (f" {C.DIM}{detail}{C.RESET}" if detail else ""))


# ============================================================
# CVSS 3.1 CALCULATOR
# ============================================================
CVSS_METRICS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
    "AC": {"L": 0.77, "H": 0.44},
    "PR_U": {"N": 0.85, "L": 0.62, "H": 0.27},   # scope unchanged
    "PR_C": {"N": 0.85, "L": 0.68, "H": 0.50},   # scope changed
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"N": 0.00, "L": 0.22, "H": 0.56},
    "I": {"N": 0.00, "L": 0.22, "H": 0.56},
    "A": {"N": 0.00, "L": 0.22, "H": 0.56},
}

METRIC_NAMES = {
    "AV": "Attack Vector", "AC": "Attack Complexity", "PR": "Privileges Required",
    "UI": "User Interaction", "S": "Scope", "C": "Confidentiality",
    "I": "Integrity", "A": "Availability",
}
METRIC_OPTIONS = {
    "AV": [("N", "Network"), ("A", "Adjacent"), ("L", "Local"), ("P", "Physical")],
    "AC": [("L", "Low"), ("H", "High")],
    "PR": [("N", "None"), ("L", "Low"), ("H", "High")],
    "UI": [("N", "None"), ("R", "Required")],
    "S": [("U", "Unchanged"), ("C", "Changed")],
    "CIA": [("N", "None"), ("L", "Low"), ("H", "High")],
}


def parse_cvss_vector(vec: str) -> Optional[Dict[str, str]]:
    vec = vec.strip()
    if vec.upper().startswith("CVSS:3.1/"):
        vec = vec[len("CVSS:3.1/"):]
    elif vec.upper().startswith("CVSS:3.0/"):
        vec = vec[len("CVSS:3.0/"):]
    parts = vec.split("/")
    out = {}
    for p in parts:
        if ":" in p:
            k, v = p.split(":", 1)
            out[k.upper()] = v.upper()
    required = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
    if not required.issubset(out.keys()):
        return None
    return out


def cvss_base_score(vec: str) -> Tuple[float, str]:
    """Return (score, normalized_vector_string)."""
    m = parse_cvss_vector(vec)
    if not m:
        raise ValueError("Invalid CVSS vector")
    av = CVSS_METRICS["AV"][m["AV"]]
    ac = CVSS_METRICS["AC"][m["AC"]]
    pr_table = CVSS_METRICS["PR_C"] if m["S"] == "C" else CVSS_METRICS["PR_U"]
    pr = pr_table[m["PR"]]
    ui = CVSS_METRICS["UI"][m["UI"]]
    c = CVSS_METRICS["C"][m["C"]]
    i = CVSS_METRICS["I"][m["I"]]
    a = CVSS_METRICS["A"][m["A"]]

    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if m["S"] == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
        if impact < 0:
            impact = 0.0
    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        base = 0.0
    elif m["S"] == "U":
        base = min(impact + exploitability, 10.0)
    else:
        base = min(1.08 * (impact + exploitability), 10.0)

    # round up to one decimal
    base = math.ceil(round(base, 9) * 10) / 10.0
    vec_norm = "CVSS:3.1/AV:{}/AC:{}/PR:{}/UI:{}/S:{}/C:{}/I:{}/A:{}".format(
        m["AV"], m["AC"], m["PR"], m["UI"], m["S"], m["C"], m["I"], m["A"])
    return base, vec_norm


def cvss_severity(score: float) -> str:
    if score == 0.0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


def interactive_cvss() -> Tuple[float, str]:
    section("CVSS 3.1 Calculator")
    vals = {}
    for key, opts in [("AV", METRIC_OPTIONS["AV"]), ("AC", METRIC_OPTIONS["AC"]),
                      ("PR", METRIC_OPTIONS["PR"]), ("UI", METRIC_OPTIONS["UI"]),
                      ("S", METRIC_OPTIONS["S"])]:
        print(f"  {METRIC_NAMES[key]}:")
        for code, name in opts:
            print(f"    {C.GRAY}{code}{C.RESET} = {name}")
        vals[key] = ask(f"  {key}", default=opts[0][0], choices=[o[0] for o in opts])
    print(f"  Confidentiality / Integrity / Availability:")
    for code, name in METRIC_OPTIONS["CIA"]:
        print(f"    {C.GRAY}{code}{C.RESET} = {name}")
    for k in ("C", "I", "A"):
        vals[k] = ask(f"  {k}", default="H", choices=[o[0] for o in METRIC_OPTIONS["CIA"]])
    vec = "CVSS:3.1/AV:{}/AC:{}/PR:{}/UI:{}/S:{}/C:{}/I:{}/A:{}".format(
        vals["AV"], vals["AC"], vals["PR"], vals["UI"], vals["S"], vals["C"], vals["I"], vals["A"])
    score, norm = cvss_base_score(vec)
    sev = cvss_severity(score)
    print(f"\n  {C.BOLD}Vector:{C.RESET} {norm}")
    print(f"  {C.BOLD}Score:{C.RESET}  {C.YELLOW}{score}{C.RESET}  ({sev})")
    return score, norm


# ============================================================
# VULNERABILITY TEMPLATES
# ============================================================
VULNS: Dict[str, dict] = {
    "xss": {
        "name": "Cross-Site Scripting (XSS)",
        "title": "Reflected XSS in {param} parameter on {endpoint}",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "impact": ("An attacker can execute arbitrary JavaScript in a victim's browser, leading to "
                   "session hijacking, credential theft, phishing, or actions performed on behalf of the user."),
        "remediation": ("Context-aware output encoding, strict Content-Security-Policy, input validation, "
                        "and use of safe templating APIs. Avoid reflecting user input unencoded."),
        "steps": ("1. Navigate to {url}\n2. Inject payload: {payload}\n3. Observe script execution in browser.\n"
                  "4. Confirm impact (e.g., cookie exfiltration / DOM change)."),
        "payload": "<script>alert(document.domain)</script>",
    },
    "stored_xss": {
        "name": "Stored Cross-Site Scripting (XSS)",
        "title": "Stored XSS in {field} field rendered on {page}",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N",
        "impact": "Stored payload executes for every visitor, enabling mass account takeover and wormable spread.",
        "remediation": "Output encode on render, sanitize on input, enforce CSP, validate content type.",
        "steps": "1. Submit payload in {field}.\n2. View {page} as another user.\n3. Payload executes.",
        "payload": "<img src=x onerror=alert(document.domain)>",
    },
    "idor": {
        "name": "Insecure Direct Object Reference (IDOR)",
        "title": "IDOR allows access to other users' {object} via {param}",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
        "impact": ("Unauthorized read/modification of other users' data, leading to privacy breach and "
                   "potential account takeover or data manipulation."),
        "remediation": ("Enforce object-level authorization checks on every request; use indirect references; "
                        "validate ownership server-side."),
        "steps": ("1. Authenticate as User A, capture request to {endpoint}.\n"
                  "2. Change {param} to User B's identifier.\n3. Observe User B's data returned without authorization."),
    },
    "ssrf": {
        "name": "Server-Side Request Forgery (SSRF)",
        "title": "SSRF via {param} parameter allows internal network access",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N",
        "impact": ("Attacker can make the server issue requests to internal services, cloud metadata, "
                   "or localhost, potentially leaking credentials or pivoting into internal network."),
        "remediation": ("Strict allowlist of destinations, block private IP ranges and metadata IPs, "
                        "disable unnecessary URL schemes, use a hardened HTTP client."),
        "steps": ("1. Send request with {param}=http://169.254.169.254/latest/meta-data/\n"
                  "2. Observe metadata response.\n3. Demonstrate internal port scanning / data exfil."),
    },
    "sqli": {
        "name": "SQL Injection",
        "title": "SQL injection in {param} parameter on {endpoint}",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "impact": "Full database compromise: data exfiltration, authentication bypass, and possible RCE.",
        "remediation": "Parameterized queries / prepared statements, ORM, least-privilege DB account, WAF as defense-in-depth.",
        "steps": "1. Send payload {payload} in {param}.\n2. Observe SQL error / boolean difference / time delay.\n3. Extract data via sqlmap or manual.",
        "payload": "' OR '1'='1",
    },
    "rce": {
        "name": "Remote Code Execution (RCE)",
        "title": "RCE via {vector} on {endpoint}",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "impact": "Full server compromise; attacker can run arbitrary commands, pivot, and exfiltrate data.",
        "remediation": "Avoid eval/exec, sanitize inputs, sandbox, patch dependencies, principle of least privilege.",
        "steps": "1. Trigger {vector} with payload {payload}.\n2. Confirm command output in response.\n3. Demonstrate safe PoC (id/hostname).",
        "payload": "; id",
    },
    "lfi": {
        "name": "Local File Inclusion (LFI)",
        "title": "LFI via {param} allows reading arbitrary files",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "impact": "Disclosure of sensitive files (config, secrets, source code, /etc/passwd).",
        "remediation": "Whitelist allowed files, avoid user input in file paths, chroot/jail, disable wrappers.",
        "steps": "1. Request {endpoint}?{param}=../../../../etc/passwd\n2. Observe file contents in response.",
    },
    "open_redirect": {
        "name": "Open Redirect",
        "title": "Open redirect via {param} parameter",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "impact": "Phishing facilitation, OAuth token theft via redirect_uri abuse, reputation damage.",
        "remediation": "Validate redirect targets against allowlist; use relative paths; reject external hosts.",
        "steps": "1. Visit {url}?{param}=https://evil.com\n2. Observe 302 to evil.com.",
    },
    "cors": {
        "name": "CORS Misconfiguration",
        "title": "CORS reflects arbitrary Origin with credentials",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N",
        "impact": "Cross-origin data theft from authenticated users; account data exfiltration.",
        "remediation": "Strict allowlist of origins; never reflect Origin with credentials; validate exact match.",
        "steps": "1. Send Origin: https://evil.com with credentials.\n2. Observe ACAO: https://evil.com and ACAC: true.\n3. Build PoC HTML to exfil data.",
    },
    "csrf": {
        "name": "Cross-Site Request Forgery (CSRF)",
        "title": "CSRF on {action} endpoint lacks token validation",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
        "impact": "Attacker can force authenticated users to perform unwanted state-changing actions.",
        "remediation": "Anti-CSRF tokens, SameSite cookies, Origin/Referer validation, re-auth for sensitive ops.",
        "steps": "1. Craft HTML form auto-submitting to {endpoint}.\n2. Host and have victim visit.\n3. Confirm action performed.",
    },
    "auth_bypass": {
        "name": "Authentication Bypass",
        "title": "Authentication bypass on {endpoint}",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "impact": "Unauthenticated access to protected functionality/data.",
        "remediation": "Enforce auth middleware on all routes; deny by default; test authorization matrix.",
        "steps": "1. Access {endpoint} without credentials.\n2. Observe protected data/actions returned.",
    },
    "info_disclosure": {
        "name": "Information Disclosure",
        "title": "Sensitive information disclosed via {source}",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "impact": "Leakage of internal data, secrets, or PII enabling further attacks.",
        "remediation": "Remove debug endpoints, restrict error messages, audit responses, use generic errors.",
        "steps": "1. Request {url}.\n2. Observe sensitive data in response.",
    },
    "subdomain_takeover": {
        "name": "Subdomain Takeover",
        "title": "Subdomain takeover of {subdomain}",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "impact": "Attacker hosts content on victim's subdomain, enabling phishing, cookie theft, CSP bypass.",
        "remediation": "Remove dangling DNS records; claim resources before deletion; monitor DNS.",
        "steps": "1. Identify dangling CNAME to {service}.\n2. Claim the resource on {service}.\n3. Serve proof content.",
    },
    "race_condition": {
        "name": "Race Condition",
        "title": "Race condition in {action} allows {impact_short}",
        "cvss": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N",
        "impact": "Double-spend, duplicate rewards, or bypass of limits via concurrent requests.",
        "remediation": "Atomic operations, DB transactions, idempotency keys, locking.",
        "steps": "1. Send N concurrent requests to {endpoint}.\n2. Observe duplicate success.\n3. Demonstrate impact (e.g., double credit).",
    },
    "mass_assignment": {
        "name": "Mass Assignment",
        "title": "Mass assignment allows setting {field} on {endpoint}",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N",
        "impact": "Privilege escalation or modification of protected fields (role, balance, verified).",
        "remediation": "Allowlist updatable fields; reject unknown params; use DTOs.",
        "steps": "1. Add {field}=value to request body.\n2. Observe field persisted/changed.",
    },
    "jwt": {
        "name": "JWT Vulnerability",
        "title": "JWT {issue} allows token forgery",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "impact": "Authentication bypass / privilege escalation via forged tokens.",
        "remediation": "Enforce algorithm server-side; validate signature; rotate secrets; reject none alg.",
        "steps": "1. Modify token header/payload.\n2. Re-sign or use alg:none.\n3. Access protected resource.",
    },
    "xxe": {
        "name": "XML External Entity (XXE)",
        "title": "XXE in {endpoint} allows file read / SSRF",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
        "impact": "Local file disclosure, SSRF, potential DoS via billion laughs.",
        "remediation": "Disable external entities; use safe parsers; validate XML.",
        "steps": "1. Submit XML with external entity.\n2. Observe file contents / internal request.",
    },
    "ssti": {
        "name": "Server-Side Template Injection (SSTI)",
        "title": "SSTI in {param} leads to RCE",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "impact": "Remote code execution on server.",
        "remediation": "Use sandboxed templates; avoid user input in templates; escape.",
        "steps": "1. Inject {{7*7}} → 49.\n2. Escalate to RCE payload.\n3. Demonstrate command output.",
    },
    "file_upload": {
        "name": "Unrestricted File Upload",
        "title": "Unrestricted file upload leads to RCE",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "impact": "Upload of executable leading to RCE or stored XSS.",
        "remediation": "Validate type/extension/content; store outside webroot; randomize names.",
        "steps": "1. Upload webshell with allowed extension.\n2. Access uploaded file.\n3. Execute command.",
    },
    "business_logic": {
        "name": "Business Logic Flaw",
        "title": "Business logic flaw in {flow} allows {impact_short}",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N",
        "impact": "Abuse of intended functionality for financial/privilege gain.",
        "remediation": "Server-side validation of business rules; state machines; audit logs.",
        "steps": "1. Perform normal flow.\n2. Manipulate step/parameter.\n3. Observe unintended outcome.",
    },
    "privilege_escalation": {
        "name": "Privilege Escalation",
        "title": "Vertical privilege escalation to {role}",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "impact": "Low-privilege user gains admin/higher privileges.",
        "remediation": "Enforce RBAC server-side; deny by default; test authorization matrix.",
        "steps": "1. Authenticate as low-priv user.\n2. Invoke admin endpoint / modify role param.\n3. Confirm elevated access.",
    },
    "rate_limit": {
        "name": "Missing Rate Limiting",
        "title": "Missing rate limiting on {endpoint} allows brute force",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "impact": "Brute-force of OTP/passwords, credential stuffing, resource exhaustion.",
        "remediation": "Implement rate limits per IP/user; account lockout; CAPTCHA.",
        "steps": "1. Send many requests to {endpoint}.\n2. Observe no throttling.",
    },
    "cache_poisoning": {
        "name": "Web Cache Poisoning",
        "title": "Cache poisoning via unkeyed {header}",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "impact": "Serve malicious content to other users via poisoned cache.",
        "remediation": "Include inputs in cache key or sanitize; vary headers appropriately.",
        "steps": "1. Send malicious {header}.\n2. Confirm cached response served to others.",
    },
    "http_smuggling": {
        "name": "HTTP Request Smuggling",
        "title": "HTTP request smuggling via CL/TE desync",
        "cvss": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N",
        "impact": "Bypass security controls, poison caches, hijack requests.",
        "remediation": "Normalize parsing; use HTTP/2; disable connection reuse inconsistencies.",
        "steps": "1. Send smuggled request.\n2. Observe desync effect.",
    },
    "prototype_pollution": {
        "name": "Prototype Pollution",
        "title": "Prototype pollution via {param}",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "impact": "Client-side XSS, auth bypass, or server-side RCE depending on context.",
        "remediation": "Freeze prototypes; validate input; avoid deep merge of untrusted data.",
        "steps": "1. Inject __proto__ payload.\n2. Observe property pollution.",
    },
    "nosql_injection": {
        "name": "NoSQL Injection",
        "title": "NoSQL injection in {param}",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "impact": "Authentication bypass, data exfiltration from NoSQL DB.",
        "remediation": "Validate/sanitize input; use typed queries; avoid $where.",
        "steps": "1. Send {$ne: null} payload.\n2. Observe auth bypass / data leak.",
    },
    "command_injection": {
        "name": "Command Injection",
        "title": "Command injection in {param}",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "impact": "Arbitrary OS command execution.",
        "remediation": "Avoid shell calls; use safe APIs; strict allowlist; input validation.",
        "steps": "1. Inject ;id in {param}.\n2. Observe command output.",
        "payload": "; id",
    },
}


PLATFORMS = ["hackerone", "bugcrowd", "intigriti", "yeswehack", "generic"]


def list_vulns():
    print(f"\n{C.BOLD}Available vulnerability templates ({len(VULNS)}):{C.RESET}")
    for k, v in sorted(VULNS.items()):
        print(f"  {C.CYAN}{k:22}{C.RESET} {v['name']}")


def list_platforms():
    print(f"\n{C.BOLD}Supported platforms:{C.RESET}")
    for p in PLATFORMS:
        print(f"  {C.CYAN}{p}{C.RESET}")


# ============================================================
# REPORT BUILDER
# ============================================================
class Finding:
    def __init__(self):
        self.title = ""
        self.vuln_type = ""
        self.platform = "hackerone"
        self.target = ""
        self.endpoint = ""
        self.param = ""
        self.url = ""
        self.cvss_vector = ""
        self.cvss_score = 0.0
        self.severity = ""
        self.summary = ""
        self.steps = ""
        self.poc_request = ""
        self.poc_response = ""
        self.poc_curl = ""
        self.impact = ""
        self.remediation = ""
        self.references = ""
        self.extra = {}

    def apply_template(self, vtype: str):
        t = VULNS.get(vtype)
        if not t:
            return
        self.vuln_type = vtype
        if not self.cvss_vector:
            self.cvss_vector = t["cvss"]
        if not self.impact:
            self.impact = t["impact"]
        if not self.remediation:
            self.remediation = t["remediation"]
        if not self.steps:
            self.steps = t["steps"]
        if not self.title:
            self.title = t["title"]

    def fmt(self, s: str) -> str:
        mapping = {
            "param": self.param or "{param}",
            "endpoint": self.endpoint or "{endpoint}",
            "url": self.url or "{url}",
            "field": self.param or "{field}",
            "page": self.endpoint or "{page}",
            "object": "object",
            "source": self.url or "{source}",
            "subdomain": self.target or "{subdomain}",
            "service": "service",
            "vector": self.param or "{vector}",
            "payload": VULNS.get(self.vuln_type, {}).get("payload", "{payload}"),
            "action": self.endpoint or "{action}",
            "flow": self.endpoint or "{flow}",
            "role": "admin",
            "header": "X-Forwarded-Host",
            "impact_short": "unauthorized action",
            "issue": "algorithm confusion",
        }
        try:
            return s.format(**mapping)
        except (KeyError, ValueError):
            return s

    def compute_cvss(self):
        if self.cvss_vector:
            try:
                score, norm = cvss_base_score(self.cvss_vector)
                self.cvss_score = score
                self.cvss_vector = norm
                self.severity = cvss_severity(score)
            except ValueError:
                pass

    def to_markdown(self) -> str:
        self.compute_cvss()
        title = self.fmt(self.title) if self.title else (VULNS.get(self.vuln_type, {}).get("name", "Finding"))
        steps = self.fmt(self.steps)
        impact = self.fmt(self.impact)
        remediation = self.fmt(self.remediation)
        p = self.platform.lower()

        lines = []
        if p == "hackerone":
            lines.append(f"# {title}\n")
            lines.append("## Summary\n")
            lines.append(self.summary or "_Describe the vulnerability and where it occurs._\n")
            lines.append("## Severity\n")
            lines.append(f"**{self.severity}** — CVSS 3.1: `{self.cvss_vector}` (Score: {self.cvss_score})\n")
            lines.append("## Steps to Reproduce\n")
            lines.append(steps + "\n")
            if self.url:
                lines.append(f"**Target:** `{self.url}`\n")
            if self.poc_request:
                lines.append("## Proof of Concept\n")
                lines.append("**Request:**\n```http\n" + self.poc_request.strip() + "\n```\n")
            if self.poc_response:
                lines.append("**Response:**\n```http\n" + self.poc_response.strip() + "\n```\n")
            if self.poc_curl:
                lines.append("**curl:**\n```bash\n" + self.poc_curl.strip() + "\n```\n")
            lines.append("## Impact\n")
            lines.append(impact + "\n")
            if self.remediation:
                lines.append("## Suggested Fix\n")
                lines.append(remediation + "\n")
            if self.references:
                lines.append("## References\n")
                lines.append(self.references + "\n")
        elif p == "bugcrowd":
            lines.append(f"# {title}\n")
            lines.append("## Target\n")
            lines.append(f"- **URL:** {self.url or 'N/A'}\n- **Endpoint:** {self.endpoint or 'N/A'}\n")
            lines.append("## Vulnerability Type\n")
            lines.append(f"{VULNS.get(self.vuln_type, {}).get('name', self.vuln_type)}\n")
            lines.append("## Severity\n")
            lines.append(f"**{self.severity}** (CVSS 3.1 {self.cvss_score}: `{self.cvss_vector}`)\n")
            lines.append("## Steps to Reproduce\n")
            lines.append(steps + "\n")
            if self.poc_request or self.poc_curl:
                lines.append("## Proof of Concept\n")
                if self.poc_curl:
                    lines.append("```bash\n" + self.poc_curl.strip() + "\n```\n")
                if self.poc_request:
                    lines.append("```http\n" + self.poc_request.strip() + "\n```\n")
                if self.poc_response:
                    lines.append("Response:\n```http\n" + self.poc_response.strip() + "\n```\n")
            lines.append("## Impact\n")
            lines.append(impact + "\n")
            lines.append("## Remediation\n")
            lines.append(remediation + "\n")
        elif p == "intigriti":
            lines.append(f"# {title}\n")
            lines.append("## Description\n")
            lines.append(self.summary or "_Describe the vulnerability._\n")
            lines.append("## Severity\n")
            lines.append(f"**{self.severity}** — CVSS 3.1 `{self.cvss_vector}` ({self.cvss_score})\n")
            lines.append("## Steps to reproduce\n")
            lines.append(steps + "\n")
            lines.append("## Impact\n")
            lines.append(impact + "\n")
            lines.append("## Root cause / Remediation\n")
            lines.append(remediation + "\n")
            if self.poc_request:
                lines.append("## HTTP Request\n```\n" + self.poc_request.strip() + "\n```\n")
        elif p == "yeswehack":
            lines.append(f"# {title}\n")
            lines.append(f"**Severity:** {self.severity} (CVSS {self.cvss_score})\n")
            lines.append(f"**CVSS Vector:** `{self.cvss_vector}`\n")
            lines.append("## Vulnerability details\n")
            lines.append(self.summary or "_Details._\n")
            lines.append("## Steps to reproduce\n")
            lines.append(steps + "\n")
            lines.append("## Impact\n")
            lines.append(impact + "\n")
            lines.append("## Remediation\n")
            lines.append(remediation + "\n")
        else:
            lines.append(f"# {title}\n")
            lines.append(f"- **Platform:** {p}\n- **Severity:** {self.severity} (CVSS {self.cvss_score})\n")
            lines.append(f"- **Vector:** `{self.cvss_vector}`\n")
            lines.append("\n## Summary\n" + (self.summary or "") + "\n")
            lines.append("\n## Steps to Reproduce\n" + steps + "\n")
            lines.append("\n## Impact\n" + impact + "\n")
            lines.append("\n## Remediation\n" + remediation + "\n")
            if self.poc_request:
                lines.append("\n## PoC Request\n```\n" + self.poc_request.strip() + "\n```\n")
            if self.poc_response:
                lines.append("\n## PoC Response\n```\n" + self.poc_response.strip() + "\n```\n")

        lines.append(f"\n---\n*Generated by BountyReport on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*")
        return "\n".join(lines)


def interactive_wizard() -> Finding:
    banner()
    f = Finding()
    section("Target & Platform")
    f.target = ask("Target (domain/program)", default="example.com")
    f.platform = ask("Platform", default="hackerone", choices=PLATFORMS)
    f.url = ask("Target URL (full)", default=f"https://{f.target}")

    section("Vulnerability")
    print(f"  {C.GRAY}Type --list-vulns for all. Common: xss, idor, ssrf, sqli, rce, lfi, open_redirect, cors, csrf{C.RESET}")
    vtype = ask("Vuln type", default="xss")
    if vtype not in VULNS:
        print(f"{C.YELLOW}Unknown type; continuing with generic.{C.RESET}")
    else:
        f.apply_template(vtype)
    f.title = ask("Title", default=f.title or "Finding")
    f.endpoint = ask("Endpoint/path", default="/")
    f.param = ask("Parameter/field", default="q")

    section("CVSS")
    print(f"  Template vector: {C.GRAY}{f.cvss_vector}{C.RESET}")
    use = ask("Use template CVSS vector?", default="y", choices=["y", "n"])
    if use == "n":
        f.cvss_vector = ask("CVSS vector (e.g. AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)")
    else:
        custom = ask("Override vector? (blank to keep)", default="")
        if custom:
            f.cvss_vector = custom
    score, norm = cvss_base_score(f.cvss_vector) if f.cvss_vector else (0.0, "")
    f.cvss_vector = norm or f.cvss_vector
    f.cvss_score = score
    f.severity = cvss_severity(score)
    found(f"CVSS {score} ({f.severity})", norm)

    section("Content")
    f.summary = ask("Summary (one paragraph)", default=f"A {VULNS.get(f.vuln_type,{}).get('name','vulnerability')} was found.")
    default_steps = f.fmt(f.steps)
    print(f"  {C.GRAY}Default steps:{C.RESET}\n{textwrap.indent(default_steps, '    ')}")
    edit = ask("Edit steps? (y/n)", default="n", choices=["y", "n"])
    if edit == "y":
        f.steps = ask_multiline("Steps to Reproduce")
    f.impact = ask("Impact", default=f.fmt(f.impact))
    f.remediation = ask("Remediation", default=f.fmt(f.remediation))

    section("Proof of Concept")
    want_poc = ask("Add PoC? (y/n)", default="y", choices=["y", "n"])
    if want_poc == "y":
        print(f"  {C.GRAY}Paste request, then EOF:{C.RESET}")
        f.poc_request = ask_multiline("Request")
        print(f"  {C.GRAY}Paste response (optional), then EOF:{C.RESET}")
        r = ask_multiline("Response")
        if r:
            f.poc_response = r
        c = ask("curl command (optional)", default="")
        if c:
            f.poc_curl = c

    section("References")
    f.references = ask("References (optional)", default="")
    return f


def from_json(path: str) -> List[Finding]:
    with open(path) as fh:
        data = json.load(fh)
    items = data if isinstance(data, list) else [data]
    out = []
    for d in items:
        f = Finding()
        for k, v in d.items():
            if hasattr(f, k):
                setattr(f, k, v)
        if f.vuln_type:
            f.apply_template(f.vuln_type)
            # keep user overrides: re-apply only empty fields already handled in apply_template
        out.append(f)
    return out


def write_report(findings: List[Finding], outdir: str, filename: str = None) -> str:
    os.makedirs(outdir, exist_ok=True)
    if len(findings) == 1:
        f = findings[0]
        f.compute_cvss()
        content = f.to_markdown()
        safe = re_safe(f.target or "report")
        name = filename or f"report_{safe}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    else:
        parts = []
        for i, f in enumerate(findings, 1):
            f.compute_cvss()
            parts.append(f"## Finding {i}\n\n" + f.to_markdown())
        content = "# Bug Bounty Report\n\n" + "\n\n---\n\n".join(parts)
        name = filename or f"report_multi_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    path = os.path.join(outdir, name)
    with open(path, "w") as fh:
        fh.write(content)
    return path


def re_safe(s):
    import re
    return re.sub(r"[^\w\-.]", "_", s)


def main():
    parser = argparse.ArgumentParser(description="BountyReport — bug bounty submission report generator")
    parser.add_argument("-t", "--type", help="Vulnerability type (use --list-vulns)")
    parser.add_argument("-p", "--platform", default="hackerone", choices=PLATFORMS, help="Target platform")
    parser.add_argument("--file", help="JSON file with finding(s)")
    parser.add_argument("--cvss", help="Compute CVSS score for a vector string")
    parser.add_argument("--list-vulns", action="store_true", help="List vulnerability templates")
    parser.add_argument("--list-platforms", action="store_true", help="List platforms")
    parser.add_argument("-o", "--output", default="./reports", help="Output directory")
    parser.add_argument("--quick", action="store_true", help="Skip interactive prompts, use defaults")
    parser.add_argument("--title", help="Report title")
    parser.add_argument("--url", help="Target URL")
    parser.add_argument("--target", help="Target domain")
    parser.add_argument("--endpoint", default="/")
    parser.add_argument("--param", default="q")
    parser.add_argument("--summary", default="")
    parser.add_argument("--out", help="Output filename")
    args = parser.parse_args()

    if args.list_vulns:
        list_vulns()
        return
    if args.list_platforms:
        list_platforms()
        return
    if args.cvss:
        try:
            score, norm = cvss_base_score(args.cvss)
            print(f"Vector: {norm}")
            print(f"Score:  {score} ({cvss_severity(score)})")
        except ValueError as e:
            print(f"Error: {e}")
            sys.exit(1)
        return

    if args.file:
        findings = from_json(args.file)
        path = write_report(findings, args.output, args.out)
        found("Report saved", path)
        return

    if args.quick and args.type:
        f = Finding()
        f.vuln_type = args.type
        f.apply_template(args.type)
        f.platform = args.platform
        f.target = args.target or "example.com"
        f.url = args.url or f"https://{f.target}"
        f.title = args.title or f.title
        f.endpoint = args.endpoint
        f.param = args.param
        f.summary = args.summary or f.summary
        path = write_report([f], args.output, args.out)
        found("Report saved", path)
        return

    # interactive
    f = interactive_wizard()
    path = write_report([f], args.output, args.out)
    print()
    found("Report saved", path, True)
    print(f"  {C.DIM}Open it, fill placeholders, submit. Good luck! 🎯{C.RESET}")


if __name__ == "__main__":
    main()